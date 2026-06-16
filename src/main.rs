mod api;
mod config;
mod db;
mod fanout;

use anyhow::Result;
use api::AppState;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use config::{ClusterConfig, Config};
use fanout::UseridAutoSubscription;
use rmqtt::context::ServerContext;
use rmqtt::net::Builder;
use rmqtt::server::MqttServer;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".into());
    let cfg = Config::load(&cfg_path)?;

    let token = cfg.api.token.clone().unwrap_or_else(|| {
        let t = random_token();
        log::warn!("api.token not set, generated token for this run: {t}");
        t
    });

    let db = db::open(&cfg.db.url).await?;
    let auth_cache_ttl = std::env::var("AUTH_CACHE_TTL_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(300);
    let auth_cache = Arc::new(api::AuthCache::new(Duration::from_secs(auth_cache_ttl)));
    {
        let auth_cache = auth_cache.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                auth_cache.sweep();
            }
        });
    }
    let state = AppState {
        db: db.clone(),
        token: Arc::new(token),
        acl: Arc::new(cfg.acl.clone()),
        auth_cache,
    };

    let mgmt_listener = tokio::net::TcpListener::bind(cfg.api.addr).await?;
    let mgmt = api::management_router(state.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(mgmt_listener, mgmt).await {
            log::error!("management api server failed: {e}");
        }
    });
    log::info!("management api listening on {}", cfg.api.addr);

    let auth_listener = tokio::net::TcpListener::bind(cfg.api.internal_auth_addr).await?;
    let auth = api::auth_router(state.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(auth_listener, auth).await {
            log::error!("internal auth server failed: {e}");
        }
    });
    log::info!("internal auth endpoint listening on {}", cfg.api.internal_auth_addr);

    let mut scx_builder = ServerContext::new()
        .node_id(cfg.cluster.node_id)
        .busy_check_enable(cfg.mqtt.busy_check)
        .plugins_config_map_add(
            "rmqtt-auth-http",
            auth_http_plugin_config(&cfg.api.internal_auth_addr, cfg.acl.enabled),
        );
    if cfg.cluster.enabled {
        scx_builder = scx_builder
            .plugins_config_map_add("rmqtt-cluster-raft", cluster_raft_plugin_config(&cfg.cluster));
    }
    let scx = scx_builder.build().await;

    rmqtt_auth_http::register(&scx, true, true).await?;

    if cfg.cluster.enabled {
        log::info!(
            "starting cluster node {} grpc {} raft {}",
            cfg.cluster.node_id,
            cfg.cluster.grpc_laddr,
            cfg.cluster.raft_laddr
        );
        scx.node.start_grpc_server(scx.clone(), cfg.cluster.grpc_laddr, true, false);
        let mut attempt: u32 = 0;
        loop {
            match rmqtt_cluster_raft::register(&scx, true, true).await {
                Ok(()) => break,
                Err(e) if attempt < cfg.cluster.join_max_retries => {
                    attempt += 1;
                    let backoff = Duration::from_secs(cfg.cluster.join_retry_secs);
                    log::warn!(
                        "cluster registration attempt {attempt}/{} failed: {e}; retrying in {}s",
                        cfg.cluster.join_max_retries,
                        backoff.as_secs()
                    );
                    tokio::time::sleep(backoff).await;
                }
                Err(e) => return Err(e),
            }
        }
    }

    if cfg.fanout.auto_subscribe {
        *scx.extends.auto_subscription_mut().await =
            Box::new(UseridAutoSubscription::new(db.clone(), &cfg.fanout, &cfg.acl));
    }

    let expiry = Duration::from_secs(cfg.mqtt.message_expiry_secs);
    log::info!(
        "starting mqtt broker: tcp {} ws {} message expiry {}s",
        cfg.mqtt.tcp_addr,
        cfg.mqtt.ws_addr,
        expiry.as_secs()
    );

    MqttServer::new(scx)
        .listener(
            Builder::new()
                .name("external/tcp")
                .laddr(cfg.mqtt.tcp_addr)
                .allow_anonymous(false)
                .message_expiry_interval(expiry)
                .max_mqueue_len(cfg.mqtt.max_mqueue_len)
                .max_inflight(std::num::NonZeroU16::new(cfg.mqtt.max_inflight).unwrap_or(std::num::NonZeroU16::MAX))
                .bind()?
                .tcp()?,
        )
        .listener(
            Builder::new()
                .name("external/ws")
                .laddr(cfg.mqtt.ws_addr)
                .allow_anonymous(false)
                .message_expiry_interval(expiry)
                .max_mqueue_len(cfg.mqtt.max_mqueue_len)
                .max_inflight(std::num::NonZeroU16::new(cfg.mqtt.max_inflight).unwrap_or(std::num::NonZeroU16::MAX))
                .bind()?
                .ws()?,
        )
        .build()
        .run()
        .await?;
    Ok(())
}

fn auth_http_plugin_config(auth_addr: &SocketAddr, acl_enabled: bool) -> String {
    let mut cfg = format!(
        r#"
http_timeout = "5s"
deny_if_error = true
disconnect_if_pub_rejected = true
http_auth_req.url = "http://{auth_addr}/mqtt/auth"
http_auth_req.method = "post"
http_auth_req.headers = {{ content-type = "application/x-www-form-urlencoded" }}
http_auth_req.params = {{ clientid = "%c", username = "%u", password = "%P" }}
"#
    );
    if acl_enabled {
        cfg.push_str(&format!(
            r#"
http_acl_req.url = "http://{auth_addr}/mqtt/acl"
http_acl_req.method = "post"
http_acl_req.headers = {{ content-type = "application/x-www-form-urlencoded" }}
http_acl_req.params = {{ access = "%A", username = "%u", topic = "%t" }}
"#
        ));
    }
    cfg
}

fn cluster_raft_plugin_config(cluster: &ClusterConfig) -> String {
    let grpc_addrs = toml_string_array(&cluster.node_grpc_addrs);
    let raft_addrs = toml_string_array(&cluster.raft_peer_addrs);
    format!(
        r#"
worker_threads = 6
message_type = 198
node_grpc_addrs = {grpc_addrs}
raft_peer_addrs = {raft_addrs}
laddr = "{raft_laddr}"
leader_id = {leader_id}
verify_addr = true
try_lock_timeout = "10s"
health.exit_on_node_unavailable = false
raft.check_quorum = true
raft.pre_vote = true
"#,
        raft_laddr = cluster.raft_laddr,
        leader_id = cluster.leader_id,
    )
}

fn toml_string_array(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| format!("\"{s}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

fn random_token() -> String {
    let mut buf = [0u8; 24];
    OsRng.fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

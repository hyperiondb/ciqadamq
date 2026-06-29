mod api;
mod config;
mod db;
mod fanout;
mod msgstore;
mod topic;
mod vault;

use anyhow::Result;
use api::AppState;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use config::{ClusterConfig, Config};
use fanout::UseridAutoSubscription;
use rmqtt::context::ServerContext;
use rmqtt::net::Builder;
use rmqtt::server::MqttServer;
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
    let cfg_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".into());
    let cfg = Config::load(&cfg_path)?;

    let mut token = cfg.api.token.clone().unwrap_or_else(|| {
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
    let user_cache = Arc::new(api::UserCache::new(Duration::from_secs(auth_cache_ttl)));
    {
        let auth_cache = auth_cache.clone();
        let user_cache = user_cache.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                auth_cache.sweep();
                user_cache.sweep();
            }
        });
    }
    let api_port = cfg.api.addr.port();
    let my_id = cfg.cluster.node_id;
    let peers: Vec<String> = cfg
        .cluster
        .node_grpc_addrs
        .iter()
        .filter_map(|entry| {
            let (id, hostport) = entry.split_once('@')?;
            if id.parse::<u64>().ok()? == my_id {
                return None;
            }
            let host = hostport.split(':').next()?;
            Some(format!("http://{host}:{api_port}"))
        })
        .collect();
    let hash_concurrency: usize = std::env::var("AUTH_HASH_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(4)
        });
    let auth_disabled = std::env::var("AUTH_DISABLED")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if auth_disabled {
        log::warn!(
            "AUTH_DISABLED set: MQTT auth and ACL are bypassed, all clients allowed as superuser (testing only)"
        );
    }
    let mut pepper: Option<Arc<[u8]>> = std::env::var("AUTH_PEPPER")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|s| Arc::from(s.into_bytes()));

    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap_or_default();
    let vault = vault::VaultClient::from_env(http.clone());
    if let Some(vault) = &vault {
        match vault.get_value("ciqada/api-token").await {
            Ok(Some(v)) => {
                token = v;
                log::info!("api token loaded from vault");
            }
            Ok(None) => {
                log::warn!("vault secret 'ciqada/api-token' not found; using env/config api token")
            }
            Err(e) => log::warn!("vault api-token fetch failed ({e}); using env/config api token"),
        }
        match vault.get_value("ciqada/pepper").await {
            Ok(Some(v)) => {
                pepper = Some(Arc::from(v.into_bytes()));
                log::info!("auth pepper loaded from vault");
            }
            Ok(None) => {
                log::warn!("vault secret 'ciqada/pepper' not found; using env pepper if set")
            }
            Err(e) => log::warn!("vault pepper fetch failed ({e}); using env pepper if set"),
        }
    }
    if pepper.is_some() {
        log::info!("fast password verifier enabled (argon2 used on first auth and as fallback)");
    }

    let state = AppState {
        db: db.clone(),
        token: Arc::new(RwLock::new(api::TokenPair {
            current: token,
            previous: None,
            refreshed_at: None,
        })),
        acl: Arc::new(cfg.acl.clone()),
        auth_cache,
        users: user_cache,
        peers: Arc::new(peers),
        http: http.clone(),
        auth_sem: Arc::new(tokio::sync::Semaphore::new(hash_concurrency)),
        auth_disabled,
        pepper,
        vault,
        cluster: Arc::new(cfg.cluster.clone()),
        scx: Arc::new(std::sync::OnceLock::new()),
    };
    {
        let state = state.clone();
        tokio::spawn(async move {
            api::catch_up(state).await;
        });
    }

    let mgmt_listener = tokio::net::TcpListener::bind(cfg.api.addr).await?;
    let mgmt = api::management_router(state.clone());
    tokio::spawn(async move {
        if let Err(e) = axum::serve(mgmt_listener, mgmt).await {
            log::error!("management api server failed: {e}");
        }
    });
    log::info!("management api listening on {}", cfg.api.addr);

    let mut scx_builder = ServerContext::new()
        .node_id(cfg.cluster.node_id)
        .busy_check_enable(cfg.mqtt.busy_check);
    if cfg.cluster.enabled {
        scx_builder = scx_builder.plugins_config_map_add(
            "rmqtt-cluster-raft",
            cluster_raft_plugin_config(&cfg.cluster),
        );
    }
    let scx = scx_builder.build().await;
    let _ = state.scx.set(scx.clone());

    let _auth_reg = api::register_auth_hooks(&scx, state.clone()).await;

    if cfg.cluster.enabled {
        log::info!(
            "starting cluster node {} grpc {} raft {}",
            cfg.cluster.node_id,
            cfg.cluster.grpc_laddr,
            cfg.cluster.raft_laddr
        );
        scx.node
            .start_grpc_server(scx.clone(), cfg.cluster.grpc_laddr, true, false);
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
        *scx.extends.auto_subscription_mut().await = Box::new(UseridAutoSubscription::new(
            db.clone(),
            &cfg.fanout,
            &cfg.acl,
        ));
    }

    let mut shutdown_flush: Option<msgstore::RedbMessageStore> = None;
    if cfg.mqtt.persist_messages {
        if let Some(path) = cfg.db.url.strip_prefix("redb://") {
            let msg_path = std::path::Path::new(path)
                .parent()
                .map(|d| d.join("messages.redb"))
                .unwrap_or_else(|| std::path::PathBuf::from("messages.redb"));
            match msgstore::RedbMessageStore::open(&msg_path, cfg.cluster.node_id) {
                Ok(store) => {
                    let flush_secs: u64 = std::env::var("MSG_FLUSH_SECS")
                        .ok()
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(5);
                    if flush_secs > 0 {
                        shutdown_flush = Some(store.clone());
                        let flusher = store.clone();
                        tokio::spawn(async move {
                            let mut tick = tokio::time::interval(Duration::from_secs(flush_secs));
                            loop {
                                tick.tick().await;
                                flusher.flush().await;
                            }
                        });
                        log::info!("message persistence enabled (redb, flush every {flush_secs}s)");
                    } else {
                        log::info!(
                            "message store in-memory only (MSG_FLUSH_SECS=0, no disk flush)"
                        );
                    }
                    *scx.extends.message_mgr_mut().await = Box::new(store);
                }
                Err(e) => log::error!("message persistence init failed: {e:#}"),
            }
        } else {
            log::warn!("mqtt.persist_messages set but db.url is not redb; persistence disabled");
        }
    }

    let expiry = Duration::from_secs(cfg.mqtt.message_expiry_secs);
    log::info!(
        "starting mqtt broker: tcp {} ws {} message expiry {}s",
        cfg.mqtt.tcp_addr,
        cfg.mqtt.ws_addr,
        expiry.as_secs()
    );

    if let Some(secs) = std::env::var("PROFILE_SECS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    {
        log::info!(
            "PROFILE_SECS={secs}: broker will exit cleanly after {secs}s so the profiler can write its output"
        );
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(secs)).await;
            std::process::exit(0);
        });
    }

    let server = MqttServer::new(scx)
        .listener(
            Builder::new()
                .name("external/tcp")
                .laddr(cfg.mqtt.tcp_addr)
                .allow_anonymous(false)
                .nodelay(true)
                .message_expiry_interval(expiry)
                .max_mqueue_len(cfg.mqtt.max_mqueue_len)
                .max_inflight(
                    std::num::NonZeroU16::new(cfg.mqtt.max_inflight)
                        .unwrap_or(std::num::NonZeroU16::MAX),
                )
                .bind()?
                .tcp()?,
        )
        .listener(
            Builder::new()
                .name("external/ws")
                .laddr(cfg.mqtt.ws_addr)
                .allow_anonymous(false)
                .nodelay(true)
                .message_expiry_interval(expiry)
                .max_mqueue_len(cfg.mqtt.max_mqueue_len)
                .max_inflight(
                    std::num::NonZeroU16::new(cfg.mqtt.max_inflight)
                        .unwrap_or(std::num::NonZeroU16::MAX),
                )
                .bind()?
                .ws()?,
        )
        .build();

    tokio::select! {
        res = server.run() => res?,
        _ = shutdown_signal() => {
            if let Some(store) = &shutdown_flush {
                log::info!("shutdown signal received, flushing message store before exit");
                store.flush().await;
            } else {
                log::info!("shutdown signal received");
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn cluster_raft_plugin_config(cluster: &ClusterConfig) -> String {
    let grpc_addrs = toml_string_array(&cluster.node_grpc_addrs);
    let raft_addrs = toml_string_array(&cluster.raft_peer_addrs);
    let worker_threads: usize = std::env::var("RAFT_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n > 0)
        .unwrap_or(6);
    format!(
        r#"
worker_threads = {worker_threads}
message_type = 198
node_grpc_addrs = {grpc_addrs}
raft_peer_addrs = {raft_addrs}
laddr = "{raft_laddr}"
leader_id = {leader_id}
verify_addr = true
try_lock_timeout = "3s"
health.exit_on_node_unavailable = false
raft.check_quorum = true
raft.pre_vote = true
raft.election_tick = 30
raft.heartbeat_tick = 3
raft.proposal_batch_size = 250
raft.proposal_batch_timeout = "20ms"
raft.grpc_breaker_threshold = 50
raft.grpc_breaker_retry_interval = "500ms"
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

use anyhow::{Context, Result};
use serde::Deserialize;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct Config {
    pub mqtt: MqttConfig,
    pub api: ApiConfig,
    pub db: DbConfig,
    pub fanout: FanoutConfig,
    pub acl: AclConfig,
    pub cluster: ClusterConfig,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct MqttConfig {
    pub tcp_addr: SocketAddr,
    pub ws_addr: SocketAddr,
    pub message_expiry_secs: u64,
    pub max_mqueue_len: usize,
    pub max_inflight: u16,
    pub busy_check: bool,
    pub persist_messages: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ApiConfig {
    pub addr: SocketAddr,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct DbConfig {
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct FanoutConfig {
    pub auto_subscribe: bool,
    pub qos: u8,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ClusterConfig {
    pub enabled: bool,
    pub node_id: u64,
    pub grpc_laddr: SocketAddr,
    pub raft_laddr: String,
    pub node_grpc_addrs: Vec<String>,
    pub raft_peer_addrs: Vec<String>,
    pub leader_id: u64,
    pub join_max_retries: u32,
    pub join_retry_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct AclConfig {
    pub enabled: bool,
    pub publish_topics: Vec<String>,
    pub fanout_prefixes: Vec<String>,
    pub admin_prefixes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            mqtt: MqttConfig::default(),
            api: ApiConfig::default(),
            db: DbConfig::default(),
            fanout: FanoutConfig::default(),
            acl: AclConfig::default(),
            cluster: ClusterConfig::default(),
        }
    }
}

impl Default for ClusterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            node_id: 1,
            grpc_laddr: "0.0.0.0:5363".parse().unwrap(),
            raft_laddr: "0.0.0.0:6003".into(),
            node_grpc_addrs: Vec::new(),
            raft_peer_addrs: Vec::new(),
            leader_id: 1,
            join_max_retries: 10,
            join_retry_secs: 5,
        }
    }
}

impl Default for MqttConfig {
    fn default() -> Self {
        Self {
            tcp_addr: "0.0.0.0:1883".parse().unwrap(),
            ws_addr: "0.0.0.0:8083".parse().unwrap(),
            message_expiry_secs: 20 * 60,
            max_mqueue_len: 1000,
            max_inflight: 65535,
            busy_check: false,
            persist_messages: false,
        }
    }
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            addr: "0.0.0.0:8090".parse().unwrap(),
            token: None,
        }
    }
}

impl Default for DbConfig {
    fn default() -> Self {
        Self {
            url: "redb://data/users.redb".into(),
        }
    }
}

impl Default for FanoutConfig {
    fn default() -> Self {
        Self {
            auto_subscribe: false,
            qos: 1,
        }
    }
}

impl Default for AclConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            publish_topics: vec!["chatsync".into(), "updates".into()],
            fanout_prefixes: vec!["fanout".into()],
            admin_prefixes: vec!["adminfanout".into()],
        }
    }
}

impl Config {
    pub fn load(path: &str) -> Result<Self> {
        let mut cfg: Config = if Path::new(path).exists() {
            let raw = std::fs::read_to_string(path).with_context(|| format!("reading {path}"))?;
            toml::from_str(&raw).with_context(|| format!("parsing {path}"))?
        } else {
            log::warn!("config file {path} not found, using defaults");
            Config::default()
        };
        if let Ok(token) = std::env::var("API_TOKEN") {
            cfg.api.token = Some(token);
        }
        if let Ok(url) = std::env::var("DB_URL") {
            cfg.db.url = url;
        }
        if let Ok(id) = std::env::var("NODE_ID") {
            cfg.cluster.node_id = id.parse().context("NODE_ID must be a positive integer")?;
        }
        Ok(cfg)
    }
}

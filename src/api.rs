use crate::config::{AclConfig, ClusterConfig};
use crate::db::{self, NewUser, UserRecord, UserStore};
use async_trait::async_trait;
use axum::extract::{Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rmqtt::acl::{Action, AuthInfo, Permission, Rule, Topic};
use rmqtt::codec::v5::SubscribeAckReason;
use rmqtt::context::ServerContext;
use rmqtt::hook::{Handler, HookResult, Parameter, Register, ReturnType, Type};
use rmqtt::types::{AuthResult, ConnectInfo, PublishAclResult, SubscribeAclResult};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn UserStore>,
    pub token: Arc<RwLock<TokenPair>>,
    pub acl: Arc<AclConfig>,
    pub auth_cache: Arc<AuthCache>,
    pub users: Arc<UserCache>,
    pub peers: Arc<Vec<String>>,
    pub http: reqwest::Client,
    pub auth_sem: Arc<tokio::sync::Semaphore>,
    pub auth_disabled: bool,
    pub pepper: Option<Arc<[u8]>>,
    pub vault: Option<crate::vault::VaultClient>,
    pub cluster: Arc<ClusterConfig>,
    pub scx: Arc<OnceLock<ServerContext>>,
}

#[derive(Clone, Default)]
pub struct TokenPair {
    pub current: String,
    pub previous: Option<String>,
    pub refreshed_at: Option<Instant>,
}

impl AppState {
    pub fn token_matches(&self, presented: &str) -> bool {
        let guard = self.token.read().unwrap();
        presented == guard.current || guard.previous.as_deref() == Some(presented)
    }

    pub fn current_token(&self) -> String {
        self.token.read().unwrap().current.clone()
    }

    pub async fn refresh_token(&self) {
        let Some(vault) = &self.vault else {
            return;
        };
        {
            let mut guard = self.token.write().unwrap();
            match guard.refreshed_at {
                Some(at) if at.elapsed() < Duration::from_secs(5) => return,
                _ => guard.refreshed_at = Some(Instant::now()),
            }
        }
        if let Ok(Some(new)) = vault.get_value("ciqada/api-token").await {
            let mut guard = self.token.write().unwrap();
            if guard.current != new {
                log::info!("ciqada api token refreshed from vault");
                guard.previous = Some(std::mem::replace(&mut guard.current, new));
            }
        }
    }
}

pub struct AuthCache {
    map: RwLock<HashMap<[u8; 32], (bool, Instant)>>,
    ttl: Duration,
}

impl AuthCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    fn get(&self, key: &[u8; 32]) -> Option<bool> {
        let guard = self.map.read().ok()?;
        let (superuser, expiry) = *guard.get(key)?;
        if expiry > Instant::now() {
            Some(superuser)
        } else {
            None
        }
    }

    fn insert(&self, key: [u8; 32], superuser: bool) {
        if self.ttl.is_zero() {
            return;
        }
        if let Ok(mut guard) = self.map.write() {
            guard.insert(key, (superuser, Instant::now() + self.ttl));
        }
    }

    pub fn purge_user(&self, _username: &str) {
        if let Ok(mut guard) = self.map.write() {
            guard.clear();
        }
    }

    pub fn sweep(&self) {
        let now = Instant::now();
        if let Ok(mut guard) = self.map.write() {
            guard.retain(|_, (_, expiry)| *expiry > now);
        }
    }
}

pub struct UserCache {
    map: RwLock<HashMap<String, (UserRecord, Instant)>>,
    ttl: Duration,
}

impl UserCache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            map: RwLock::new(HashMap::new()),
            ttl,
        }
    }

    fn get(&self, username: &str) -> Option<UserRecord> {
        let guard = self.map.read().ok()?;
        let (record, expiry) = guard.get(username)?;
        if *expiry > Instant::now() {
            Some(record.clone())
        } else {
            None
        }
    }

    fn insert(&self, username: String, record: UserRecord) {
        if self.ttl.is_zero() {
            return;
        }
        if let Ok(mut guard) = self.map.write() {
            guard.insert(username, (record, Instant::now() + self.ttl));
        }
    }

    pub fn purge(&self, username: &str) {
        if let Ok(mut guard) = self.map.write() {
            guard.remove(username);
        }
    }

    pub fn sweep(&self) {
        let now = Instant::now();
        if let Ok(mut guard) = self.map.write() {
            guard.retain(|_, (_, expiry)| *expiry > now);
        }
    }
}

#[derive(Deserialize)]
struct CreateUser {
    username: String,
    userid: String,
    password: String,
    #[serde(default)]
    superuser: bool,
    #[serde(default)]
    admin: bool,
}

pub fn management_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/users", get(list_users).post(create_user))
        .route(
            "/api/v1/users/{username}",
            axum::routing::delete(delete_user),
        )
        .route("/internal/replicate", post(replicate))
        .route("/internal/users-full", get(users_full))
        .route("/api/v1/cluster", get(cluster_status))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}

async fn require_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t.to_string());
    let authorized = match &presented {
        Some(token) if state.token_matches(token) => true,
        Some(token) => {
            state.refresh_token().await;
            state.token_matches(token)
        }
        None => false,
    };
    if authorized {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid or missing bearer token"})),
        )
            .into_response()
    }
}

fn valid_segment(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn valid_username(s: &str) -> bool {
    !s.is_empty() && s.len() <= 128 && s.chars().all(|c| c.is_ascii_graphic())
}

async fn create_user(State(state): State<AppState>, Json(req): Json<CreateUser>) -> Response {
    if !valid_username(&req.username) {
        return bad_request("username must be 1-128 printable ascii chars without spaces");
    }
    if !valid_segment(&req.userid) {
        return bad_request("userid must be 1-64 chars of [A-Za-z0-9_-]");
    }
    if req.password.is_empty() || req.password.len() > 512 {
        return bad_request("password must be 1-512 bytes");
    }
    let password = req.password;
    let verifier = state
        .pepper
        .as_ref()
        .map(|p| db::compute_verifier(p, &req.username, &password));
    let _permit = state.auth_sem.clone().acquire_owned().await;
    let hash = match tokio::task::spawn_blocking(move || db::hash_password(&password)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e.into()),
    };
    let user = NewUser {
        username: req.username.clone(),
        userid: req.userid.clone(),
        password_hash: hash.clone(),
        superuser: req.superuser,
        admin: req.admin,
    };
    match state.db.insert_user(user).await {
        Ok(true) => {
            if let Some(v) = &verifier {
                let _ = state.db.set_verifier(&req.username, v).await;
            }
            let rec = UserRecord {
                username: req.username.clone(),
                userid: req.userid.clone(),
                password_hash: hash,
                superuser: req.superuser,
                admin: req.admin,
            };
            fanout(&state, &ReplOp::Upsert { user: rec }).await;
            (
                StatusCode::CREATED,
                Json(json!({"username": req.username, "userid": req.userid})),
            )
                .into_response()
        }
        Ok(false) => (
            StatusCode::CONFLICT,
            Json(json!({"error": "user already exists"})),
        )
            .into_response(),
        Err(e) => internal_error(e),
    }
}

async fn delete_user(State(state): State<AppState>, Path(username): Path<String>) -> Response {
    match state.db.delete_user(&username).await {
        Ok(true) => {
            state.auth_cache.purge_user(&username);
            state.users.purge(&username);
            fanout(
                &state,
                &ReplOp::Delete {
                    username: username.clone(),
                },
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "user not found"})),
        )
            .into_response(),
        Err(e) => internal_error(e),
    }
}

async fn list_users(State(state): State<AppState>) -> Response {
    match state.db.list_users().await {
        Ok(users) => {
            let users: Vec<_> = users
                .into_iter()
                .map(|u| {
                    json!({
                        "username": u.username,
                        "userid": u.userid,
                        "superuser": u.superuser,
                        "admin": u.admin
                    })
                })
                .collect();
            Json(json!({"users": users})).into_response()
        }
        Err(e) => internal_error(e),
    }
}

fn auth_key(username: &str, password: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(username.as_bytes());
    h.update(b"\x00");
    h.update(password.as_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&h.finalize());
    hash
}

async fn lookup_user(state: &AppState, username: &str) -> Result<Option<UserRecord>, Response> {
    if let Some(record) = state.users.get(username) {
        return Ok(Some(record));
    }
    match state.db.get_user(username).await {
        Ok(Some(record)) => {
            state.users.insert(username.to_string(), record.clone());
            Ok(Some(record))
        }
        Ok(None) => Ok(None),
        Err(e) => Err(internal_error(e)),
    }
}

pub async fn register_auth_hooks(scx: &ServerContext, state: AppState) -> Box<dyn Register> {
    let register = scx.extends.hook_mgr().register();
    register
        .add(
            Type::ClientAuthenticate,
            Box::new(MqttAuth {
                state: state.clone(),
            }),
        )
        .await;
    register
        .add(
            Type::ClientSubscribeCheckAcl,
            Box::new(MqttAuth {
                state: state.clone(),
            }),
        )
        .await;
    register
        .add(Type::MessagePublishCheckAcl, Box::new(MqttAuth { state }))
        .await;
    register.start().await;
    register
}

struct MqttAuth {
    state: AppState,
}

impl MqttAuth {
    async fn authenticate(&self, connect_info: &ConnectInfo) -> ReturnType {
        if self.state.auth_disabled {
            return (
                false,
                Some(HookResult::AuthResult(AuthResult::Allow(true, None))),
            );
        }
        let username = connect_info.username().map(|u| u.to_string());
        let password = connect_info
            .password()
            .and_then(|p| std::str::from_utf8(p).ok().map(|s| s.to_string()));
        let (Some(username), Some(password)) = (username, password) else {
            return deny_auth();
        };
        if username.is_empty() || password.is_empty() {
            return deny_auth();
        }
        let record = match lookup_user(&self.state, &username).await {
            Ok(Some(r)) => r,
            Ok(None) => return deny_auth(),
            Err(_) => {
                return (
                    false,
                    Some(HookResult::AuthResult(AuthResult::NotAuthorized)),
                );
            }
        };
        let key = auth_key(&username, &password);
        let mut verified = self.state.auth_cache.get(&key).is_some();
        if !verified {
            if let Some(pepper) = &self.state.pepper {
                if let Ok(Some(v)) = self.state.db.get_verifier(&username).await {
                    if db::verify_fast(pepper, &username, &password, &v) {
                        self.state.auth_cache.insert(key.clone(), record.superuser);
                        verified = true;
                    }
                }
            }
        }
        if !verified {
            let _permit = self.state.auth_sem.clone().acquire_owned().await;
            let hash = record.password_hash.clone();
            let pw = password.clone();
            if let Ok(true) =
                tokio::task::spawn_blocking(move || db::verify_password(&hash, &pw)).await
            {
                self.state.auth_cache.insert(key, record.superuser);
                if let Some(pepper) = &self.state.pepper {
                    let v = db::compute_verifier(pepper, &username, &password);
                    let _ = self.state.db.set_verifier(&username, &v).await;
                }
                verified = true;
            }
        }
        if !verified {
            return deny_auth();
        }
        let auth_info = build_auth_info(&record, &self.state.acl, connect_info);
        (
            false,
            Some(HookResult::AuthResult(AuthResult::Allow(
                record.superuser,
                Some(auth_info),
            ))),
        )
    }
}

#[async_trait]
impl Handler for MqttAuth {
    async fn hook(&self, param: &Parameter, acc: Option<HookResult>) -> ReturnType {
        match param {
            Parameter::ClientAuthenticate(connect_info) => self.authenticate(connect_info).await,
            Parameter::ClientSubscribeCheckAcl(session, subscribe) => {
                if !self.state.acl.enabled {
                    return (
                        false,
                        Some(HookResult::SubscribeAclResult(
                            SubscribeAclResult::new_success(subscribe.opts.qos(), None),
                        )),
                    );
                }
                if let Some(auth_info) = &session.auth_info {
                    if let Some(res) = auth_info.subscribe_acl(subscribe).await {
                        return res;
                    }
                }
                (
                    false,
                    Some(HookResult::SubscribeAclResult(
                        SubscribeAclResult::new_failure(SubscribeAckReason::NotAuthorized),
                    )),
                )
            }
            Parameter::MessagePublishCheckAcl(session, publish) => {
                if !self.state.acl.enabled {
                    return (
                        false,
                        Some(HookResult::PublishAclResult(PublishAclResult::allow())),
                    );
                }
                if let Some(auth_info) = &session.auth_info {
                    if let Some(res) = auth_info.publish_acl(publish, true).await {
                        return res;
                    }
                }
                (
                    false,
                    Some(HookResult::PublishAclResult(PublishAclResult::rejected(
                        true, None,
                    ))),
                )
            }
            _ => (true, acc),
        }
    }
}

fn deny_auth() -> ReturnType {
    (
        false,
        Some(HookResult::AuthResult(AuthResult::BadUsernameOrPassword)),
    )
}

fn build_auth_info(record: &UserRecord, acl: &AclConfig, ci: &ConnectInfo) -> AuthInfo {
    if record.superuser {
        return AuthInfo {
            superuser: true,
            expire_at: None,
            rules: Vec::new(),
        };
    }
    let mut filters: Vec<String> = vec![format!("+/{}/#", record.userid)];
    for p in &acl.fanout_prefixes {
        filters.push(format!("{p}/#"));
    }
    if record.admin {
        for p in &acl.admin_prefixes {
            filters.push(format!("{p}/#"));
        }
    }
    let mut rules = Vec::new();
    for f in filters {
        if let Ok(topic) = Topic::try_from((f.as_str(), ci)) {
            rules.push(Rule {
                permission: Permission::Allow,
                action: Action::Subscribe,
                qos: None,
                retain: None,
                topic,
            });
        }
    }
    for t in &acl.publish_topics {
        if let Ok(topic) = Topic::try_from((format!("eq {t}").as_str(), ci)) {
            rules.push(Rule {
                permission: Permission::Allow,
                action: Action::Publish,
                qos: None,
                retain: None,
                topic,
            });
        }
    }
    AuthInfo {
        superuser: false,
        expire_at: None,
        rules,
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "lowercase")]
enum ReplOp {
    Upsert { user: UserRecord },
    Delete { username: String },
}

async fn fanout(state: &AppState, op: &ReplOp) {
    if state.peers.is_empty() {
        return;
    }
    let body = match serde_json::to_value(op) {
        Ok(v) => v,
        Err(e) => {
            log::warn!("replicate encode failed: {e}");
            return;
        }
    };
    let mut set = tokio::task::JoinSet::new();
    for base in state.peers.iter() {
        let http = state.http.clone();
        let token = state.current_token();
        let url = format!("{base}/internal/replicate");
        let body = body.clone();
        set.spawn(async move {
            match http.post(&url).bearer_auth(&token).json(&body).send().await {
                Ok(r) if r.status().is_success() => {}
                Ok(r) => log::warn!("replicate to {url} returned {}", r.status()),
                Err(e) => log::warn!("replicate to {url} failed: {e}"),
            }
        });
    }
    while set.join_next().await.is_some() {}
}

async fn replicate(State(state): State<AppState>, Json(op): Json<ReplOp>) -> Response {
    let username = match op {
        ReplOp::Upsert { user } => {
            let username = user.username.clone();
            let nu = NewUser {
                username: user.username,
                userid: user.userid,
                password_hash: user.password_hash,
                superuser: user.superuser,
                admin: user.admin,
            };
            if let Err(e) = state.db.upsert_user(nu).await {
                return internal_error(e);
            }
            username
        }
        ReplOp::Delete { username } => {
            if let Err(e) = state.db.delete_user(&username).await {
                return internal_error(e);
            }
            username
        }
    };
    state.auth_cache.purge_user(&username);
    state.users.purge(&username);
    StatusCode::NO_CONTENT.into_response()
}

async fn users_full(State(state): State<AppState>) -> Response {
    match state.db.list_users().await {
        Ok(users) => Json(users).into_response(),
        Err(e) => internal_error(e),
    }
}

pub async fn catch_up(state: AppState) {
    if state.peers.is_empty() {
        return;
    }
    for _ in 0..30 {
        for base in state.peers.iter() {
            let url = format!("{base}/internal/users-full");
            if let Ok(resp) = state
                .http
                .get(&url)
                .bearer_auth(state.current_token())
                .send()
                .await
            {
                if resp.status().is_success() {
                    if let Ok(users) = resp.json::<Vec<UserRecord>>().await {
                        let users: Vec<NewUser> = users
                            .into_iter()
                            .map(|u| NewUser {
                                username: u.username,
                                userid: u.userid,
                                password_hash: u.password_hash,
                                superuser: u.superuser,
                                admin: u.admin,
                            })
                            .collect();
                        if let Err(e) = state.db.upsert_many(users).await {
                            log::warn!("user snapshot apply failed: {e}");
                        }
                        log::info!("user snapshot synced from {base}");
                        return;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
    log::warn!("user snapshot catch-up: no peer responded yet");
}

async fn cluster_status(State(state): State<AppState>) -> Response {
    let cfg = &state.cluster;
    let mut body = json!({
        "node_id": cfg.node_id,
        "enabled": cfg.enabled,
        "leader_id": cfg.leader_id,
        "node_grpc_addrs": cfg.node_grpc_addrs,
        "raft_peer_addrs": cfg.raft_peer_addrs,
    });
    match state.scx.get() {
        Some(scx) => match scx.extends.shared().await.check_health().await {
            Ok(health) => body["health"] = health.to_json(),
            Err(e) => body["health_error"] = json!(e.to_string()),
        },
        None => body["health"] = json!("broker initializing"),
    }
    Json(body).into_response()
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
}

fn internal_error(e: anyhow::Error) -> Response {
    log::error!("internal error: {e:#}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({"error": "internal error"})),
    )
        .into_response()
}

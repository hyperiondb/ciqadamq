use crate::config::AclConfig;
use crate::db::{self, NewUser, UserRecord, UserStore};
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderName, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Form, Json, Router};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

const X_SUPERUSER: HeaderName = HeaderName::from_static("x-superuser");
const X_CACHE: HeaderName = HeaderName::from_static("x-cache");

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<dyn UserStore>,
    pub token: Arc<String>,
    pub acl: Arc<AclConfig>,
    pub auth_cache: Arc<AuthCache>,
}

pub struct AuthCache {
    map: RwLock<HashMap<(String, [u8; 32]), (bool, Instant)>>,
    ttl: Duration,
}

impl AuthCache {
    pub fn new(ttl: Duration) -> Self {
        Self { map: RwLock::new(HashMap::new()), ttl }
    }

    fn get(&self, key: &(String, [u8; 32])) -> Option<bool> {
        let guard = self.map.read().ok()?;
        let (superuser, expiry) = *guard.get(key)?;
        if expiry > Instant::now() {
            Some(superuser)
        } else {
            None
        }
    }

    fn insert(&self, key: (String, [u8; 32]), superuser: bool) {
        if self.ttl.is_zero() {
            return;
        }
        if let Ok(mut guard) = self.map.write() {
            guard.insert(key, (superuser, Instant::now() + self.ttl));
        }
    }

    fn purge_user(&self, username: &str) {
        if let Ok(mut guard) = self.map.write() {
            guard.retain(|(u, _), _| u != username);
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

#[derive(Deserialize)]
struct AuthReq {
    username: Option<String>,
    password: Option<String>,
}

#[derive(Deserialize)]
struct AclReq {
    access: Option<String>,
    username: Option<String>,
    topic: Option<String>,
}

pub fn management_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/users/{username}", axum::routing::delete(delete_user))
        .route_layer(middleware::from_fn_with_state(state.clone(), require_token))
        .route("/health", get(|| async { "ok" }))
        .with_state(state)
}

pub fn auth_router(state: AppState) -> Router {
    Router::new()
        .route("/mqtt/auth", post(mqtt_auth))
        .route("/mqtt/acl", post(mqtt_acl))
        .with_state(state)
}

async fn require_token(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| t == state.token.as_str())
        .unwrap_or(false);
    if authorized {
        next.run(req).await
    } else {
        (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid or missing bearer token"}))).into_response()
    }
}

fn valid_segment(s: &str) -> bool {
    !s.is_empty() && s.len() <= 64 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
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
    let hash = match tokio::task::spawn_blocking(move || db::hash_password(&password)).await {
        Ok(Ok(h)) => h,
        Ok(Err(e)) => return internal_error(e),
        Err(e) => return internal_error(e.into()),
    };
    let user = NewUser {
        username: req.username.clone(),
        userid: req.userid.clone(),
        password_hash: hash,
        superuser: req.superuser,
        admin: req.admin,
    };
    match state.db.insert_user(user).await {
        Ok(true) => (
            StatusCode::CREATED,
            Json(json!({"username": req.username, "userid": req.userid})),
        )
            .into_response(),
        Ok(false) => (StatusCode::CONFLICT, Json(json!({"error": "user already exists"}))).into_response(),
        Err(e) => internal_error(e),
    }
}

async fn delete_user(State(state): State<AppState>, Path(username): Path<String>) -> Response {
    match state.db.delete_user(&username).await {
        Ok(true) => {
            state.auth_cache.purge_user(&username);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => (StatusCode::NOT_FOUND, Json(json!({"error": "user not found"}))).into_response(),
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

fn auth_key(username: &str, password: &str) -> (String, [u8; 32]) {
    let mut hash = [0u8; 32];
    hash.copy_from_slice(Sha256::digest(password.as_bytes()).as_slice());
    (username.to_string(), hash)
}

fn allow_response(superuser: bool) -> Response {
    if superuser {
        (StatusCode::OK, [(X_SUPERUSER, "true")], "allow").into_response()
    } else {
        (StatusCode::OK, "allow").into_response()
    }
}

async fn mqtt_auth(State(state): State<AppState>, Form(req): Form<AuthReq>) -> Response {
    let (Some(username), Some(password)) = (req.username, req.password) else {
        return (StatusCode::OK, "deny").into_response();
    };
    if username.is_empty() || password.is_empty() {
        return (StatusCode::OK, "deny").into_response();
    }
    let key = auth_key(&username, &password);
    if let Some(superuser) = state.auth_cache.get(&key) {
        return allow_response(superuser);
    }
    let record = match state.db.get_user(&username).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::OK, "deny").into_response(),
        Err(e) => return internal_error(e),
    };
    let superuser = record.superuser;
    let verified =
        tokio::task::spawn_blocking(move || db::verify_password(&record.password_hash, &password)).await;
    match verified {
        Ok(true) => {
            state.auth_cache.insert(key, superuser);
            allow_response(superuser)
        }
        Ok(false) => (StatusCode::OK, "deny").into_response(),
        Err(e) => internal_error(e.into()),
    }
}

async fn mqtt_acl(State(state): State<AppState>, Form(req): Form<AclReq>) -> Response {
    if !state.acl.enabled {
        return (StatusCode::OK, "ignore").into_response();
    }
    let (Some(access), Some(username), Some(topic)) = (req.access, req.username, req.topic) else {
        return (StatusCode::OK, "deny").into_response();
    };
    let record = match state.db.get_user(&username).await {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::OK, "deny").into_response(),
        Err(e) => return internal_error(e),
    };
    let allowed = match access.as_str() {
        "1" => record.superuser || subscribe_allowed(&state.acl, &record, &topic),
        "2" => record.superuser || publish_allowed(&state.acl, &topic),
        _ => false,
    };
    let verdict = if allowed { "allow" } else { "deny" };
    if access == "2" {
        (StatusCode::OK, [(X_CACHE, "-1")], verdict).into_response()
    } else {
        (StatusCode::OK, verdict).into_response()
    }
}

fn subscribe_allowed(acl: &AclConfig, user: &UserRecord, topic_filter: &str) -> bool {
    let mut parts = topic_filter.split('/');
    let first = parts.next().unwrap_or("");
    if acl.fanout_prefixes.iter().any(|p| p == first) {
        return true;
    }
    if user.admin && acl.admin_prefixes.iter().any(|p| p == first) {
        return true;
    }
    matches!(parts.next(), Some(second) if second == user.userid)
}

fn publish_allowed(acl: &AclConfig, topic: &str) -> bool {
    acl.publish_topics.iter().any(|t| t == topic)
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({"error": msg}))).into_response()
}

fn internal_error(e: anyhow::Error) -> Response {
    log::error!("internal error: {e:#}");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": "internal error"}))).into_response()
}

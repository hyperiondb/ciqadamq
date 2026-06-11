use anyhow::{anyhow, Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use async_trait::async_trait;
use rusqlite::{params, Connection, OptionalExtension};
use sqlx::postgres::PgPoolOptions;
use sqlx::{PgPool, Row};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct UserRecord {
    pub username: String,
    pub userid: String,
    pub password_hash: String,
    pub superuser: bool,
    pub admin: bool,
}

#[derive(Debug, Clone)]
pub struct NewUser {
    pub username: String,
    pub userid: String,
    pub password_hash: String,
    pub superuser: bool,
    pub admin: bool,
}

#[async_trait]
pub trait UserStore: Send + Sync {
    async fn insert_user(&self, user: NewUser) -> Result<bool>;
    async fn delete_user(&self, username: &str) -> Result<bool>;
    async fn list_users(&self) -> Result<Vec<UserRecord>>;
    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>>;
}

pub async fn open(url: &str) -> Result<Arc<dyn UserStore>> {
    if let Some(path) = url.strip_prefix("sqlite://") {
        Ok(Arc::new(SqliteStore::open(Path::new(path))?))
    } else if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        Ok(Arc::new(PgStore::connect(url).await?))
    } else {
        Err(anyhow!("unsupported db url scheme: {url}"))
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    Ok(Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("password hashing failed: {e}"))?
        .to_string())
}

pub fn verify_password(stored_hash: &str, password: &str) -> bool {
    PasswordHash::new(stored_hash)
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub struct SqliteStore {
    conn: Arc<Mutex<Connection>>,
}

impl SqliteStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                userid TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                superuser INTEGER NOT NULL DEFAULT 0,
                admin INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL
            );",
        )?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    async fn run<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T> + Send + 'static,
    {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            f(&conn)
        })
        .await?
    }
}

#[async_trait]
impl UserStore for SqliteStore {
    async fn insert_user(&self, user: NewUser) -> Result<bool> {
        self.run(move |conn| {
            let n = conn.execute(
                "INSERT OR IGNORE INTO users (username, userid, password_hash, superuser, admin, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![user.username, user.userid, user.password_hash, user.superuser, user.admin, now_secs()],
            )?;
            Ok(n > 0)
        })
        .await
    }

    async fn delete_user(&self, username: &str) -> Result<bool> {
        let username = username.to_owned();
        self.run(move |conn| {
            let n = conn.execute("DELETE FROM users WHERE username = ?1", params![username])?;
            Ok(n > 0)
        })
        .await
    }

    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        self.run(|conn| {
            let mut stmt = conn.prepare(
                "SELECT username, userid, password_hash, superuser, admin FROM users ORDER BY username",
            )?;
            let rows = stmt.query_map([], row_to_record)?;
            let mut out = Vec::new();
            for row in rows {
                out.push(row?);
            }
            Ok(out)
        })
        .await
    }

    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>> {
        let name = username.to_owned();
        self.run(move |conn| {
            let rec = conn
                .query_row(
                    "SELECT username, userid, password_hash, superuser, admin FROM users WHERE username = ?1",
                    params![name],
                    row_to_record,
                )
                .optional()?;
            Ok(rec)
        })
        .await
    }
}

fn row_to_record(r: &rusqlite::Row) -> rusqlite::Result<UserRecord> {
    Ok(UserRecord {
        username: r.get(0)?,
        userid: r.get(1)?,
        password_hash: r.get(2)?,
        superuser: r.get(3)?,
        admin: r.get(4)?,
    })
}

pub struct PgStore {
    pool: PgPool,
}

impl PgStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let mut last_err = None;
        let mut pool = None;
        for attempt in 1..=30 {
            match PgPoolOptions::new().max_connections(8).connect(url).await {
                Ok(p) => {
                    pool = Some(p);
                    break;
                }
                Err(e) => {
                    if attempt % 5 == 0 {
                        log::warn!("postgres not ready (attempt {attempt}): {e}");
                    }
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
        let pool = pool.ok_or_else(|| {
            anyhow!("could not connect to postgres after 30 attempts: {:?}", last_err)
        })?;
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                userid TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                superuser BOOLEAN NOT NULL DEFAULT FALSE,
                admin BOOLEAN NOT NULL DEFAULT FALSE,
                created_at BIGINT NOT NULL
            )",
        )
        .execute(&pool)
        .await
        .context("creating users table")?;
        Ok(Self { pool })
    }
}

fn pg_row_to_record(r: &sqlx::postgres::PgRow) -> UserRecord {
    UserRecord {
        username: r.get(0),
        userid: r.get(1),
        password_hash: r.get(2),
        superuser: r.get(3),
        admin: r.get(4),
    }
}

#[async_trait]
impl UserStore for PgStore {
    async fn insert_user(&self, user: NewUser) -> Result<bool> {
        let res = sqlx::query(
            "INSERT INTO users (username, userid, password_hash, superuser, admin, created_at)
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (username) DO NOTHING",
        )
        .bind(&user.username)
        .bind(&user.userid)
        .bind(&user.password_hash)
        .bind(user.superuser)
        .bind(user.admin)
        .bind(now_secs())
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_user(&self, username: &str) -> Result<bool> {
        let res = sqlx::query("DELETE FROM users WHERE username = $1")
            .bind(username)
            .execute(&self.pool)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        let rows = sqlx::query(
            "SELECT username, userid, password_hash, superuser, admin FROM users ORDER BY username",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(pg_row_to_record).collect())
    }

    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>> {
        let row = sqlx::query(
            "SELECT username, userid, password_hash, superuser, admin FROM users WHERE username = $1",
        )
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(pg_row_to_record))
    }
}

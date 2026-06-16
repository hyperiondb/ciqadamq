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
use tokio::sync::{Mutex as TokioMutex, RwLock};

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

fn expand_multi_host(url: &str) -> Vec<String> {
    let Some(scheme_end) = url.find("://") else {
        return vec![url.to_string()];
    };
    let (scheme, rest) = url.split_at(scheme_end + 3);
    let authority_end = rest.find('/').unwrap_or(rest.len());
    let (authority, path) = rest.split_at(authority_end);
    let (userinfo, hosts) = match authority.rfind('@') {
        Some(i) => (&authority[..=i], &authority[i + 1..]),
        None => ("", authority),
    };
    hosts
        .split(',')
        .filter(|h| !h.is_empty())
        .map(|h| format!("{scheme}{userinfo}{h}{path}"))
        .collect()
}

pub struct PgStore {
    urls: Vec<String>,
    pool: RwLock<PgPool>,
    refresh_lock: TokioMutex<()>,
}

impl PgStore {
    pub async fn connect(url: &str) -> Result<Self> {
        let urls = expand_multi_host(url);
        let pool = Self::discover(&urls, 30).await?;
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
        Ok(Self {
            urls,
            pool: RwLock::new(pool),
            refresh_lock: TokioMutex::new(()),
        })
    }

    async fn probe(url: &str) -> Result<PgPool, sqlx::Error> {
        let pool = PgPoolOptions::new()
            .max_connections(32)
            .acquire_timeout(Duration::from_secs(5))
            .connect(url)
            .await?;
        let standby: bool = sqlx::query_scalar("SELECT pg_is_in_recovery()")
            .fetch_one(&pool)
            .await?;
        if standby {
            pool.close().await;
            return Err(sqlx::Error::Configuration(
                "node is a read-only standby".into(),
            ));
        }
        Ok(pool)
    }

    async fn discover(urls: &[String], attempts: u32) -> Result<PgPool> {
        let mut last_err = None;
        for attempt in 1..=attempts {
            for url in urls {
                match Self::probe(url).await {
                    Ok(pool) => return Ok(pool),
                    Err(e) => last_err = Some(e),
                }
            }
            if attempt % 5 == 0 {
                if let Some(e) = &last_err {
                    log::warn!("no writable postgres yet (attempt {attempt}): {e}");
                }
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Err(anyhow!(
            "could not connect to a writable postgres after {attempts} attempts: {:?}",
            last_err
        ))
    }

    async fn pool(&self) -> PgPool {
        self.pool.read().await.clone()
    }

    fn should_failover(e: &sqlx::Error) -> bool {
        match e {
            sqlx::Error::Io(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => true,
            sqlx::Error::Database(db) => {
                matches!(db.code().as_deref(), Some("25006" | "57P01" | "57P02" | "57P03"))
            }
            _ => false,
        }
    }

    async fn refresh(&self) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        let current = self.pool().await;
        if let Ok(false) = sqlx::query_scalar::<_, bool>("SELECT pg_is_in_recovery()")
            .fetch_one(&current)
            .await
        {
            return Ok(());
        }
        let new_pool = Self::discover(&self.urls, 3).await?;
        let old = {
            let mut guard = self.pool.write().await;
            std::mem::replace(&mut *guard, new_pool)
        };
        old.close().await;
        log::info!("postgres primary changed, reconnected");
        Ok(())
    }

    async fn with_failover<T, F, Fut>(&self, op: F) -> Result<T>
    where
        F: Fn(PgPool) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<T, sqlx::Error>>,
    {
        let pool = self.pool().await;
        match op(pool).await {
            Ok(v) => Ok(v),
            Err(e) if Self::should_failover(&e) => {
                log::warn!("postgres query failed ({e}), probing for writable primary");
                self.refresh().await?;
                let pool = self.pool().await;
                Ok(op(pool).await?)
            }
            Err(e) => Err(e.into()),
        }
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
        let created_at = now_secs();
        let res = self
            .with_failover(|pool| {
                let user = user.clone();
                async move {
                    sqlx::query(
                        "INSERT INTO users (username, userid, password_hash, superuser, admin, created_at)
                         VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (username) DO NOTHING",
                    )
                    .bind(user.username)
                    .bind(user.userid)
                    .bind(user.password_hash)
                    .bind(user.superuser)
                    .bind(user.admin)
                    .bind(created_at)
                    .execute(&pool)
                    .await
                }
            })
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn delete_user(&self, username: &str) -> Result<bool> {
        let username = username.to_owned();
        let res = self
            .with_failover(|pool| {
                let username = username.clone();
                async move {
                    sqlx::query("DELETE FROM users WHERE username = $1")
                        .bind(username)
                        .execute(&pool)
                        .await
                }
            })
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        let rows = self
            .with_failover(|pool| async move {
                sqlx::query(
                    "SELECT username, userid, password_hash, superuser, admin FROM users ORDER BY username",
                )
                .fetch_all(&pool)
                .await
            })
            .await?;
        Ok(rows.iter().map(pg_row_to_record).collect())
    }

    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>> {
        let username = username.to_owned();
        let row = self
            .with_failover(|pool| {
                let username = username.clone();
                async move {
                    sqlx::query(
                        "SELECT username, userid, password_hash, superuser, admin FROM users WHERE username = $1",
                    )
                    .bind(username)
                    .fetch_optional(&pool)
                    .await
                }
            })
            .await?;
        Ok(row.as_ref().map(pg_row_to_record))
    }
}

#[cfg(test)]
mod multi_host_tests {
    use super::expand_multi_host;

    #[test]
    fn expands_multi_host_url() {
        assert_eq!(
            expand_multi_host("postgres://u:p@10.0.0.1:5432,10.0.0.2:5432/db"),
            vec![
                "postgres://u:p@10.0.0.1:5432/db",
                "postgres://u:p@10.0.0.2:5432/db",
            ]
        );
    }

    #[test]
    fn single_host_unchanged() {
        assert_eq!(
            expand_multi_host("postgres://u:p@paradedb:5432/db"),
            vec!["postgres://u:p@paradedb:5432/db"]
        );
    }

    #[test]
    fn no_userinfo() {
        assert_eq!(
            expand_multi_host("postgres://h1:5432,h2:5432/db"),
            vec!["postgres://h1:5432/db", "postgres://h2:5432/db"]
        );
    }
}

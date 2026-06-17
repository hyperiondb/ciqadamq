use anyhow::{anyhow, Context, Result};
use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use async_trait::async_trait;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    async fn upsert_user(&self, user: NewUser) -> Result<()>;
    async fn upsert_many(&self, users: Vec<NewUser>) -> Result<()>;
    async fn delete_user(&self, username: &str) -> Result<bool>;
    async fn list_users(&self) -> Result<Vec<UserRecord>>;
    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>>;
}

pub async fn open(url: &str) -> Result<Arc<dyn UserStore>> {
    let path = url
        .strip_prefix("redb://")
        .ok_or_else(|| anyhow!("unsupported db url (expected redb://<path>): {url}"))?;
    Ok(Arc::new(RedbStore::open(Path::new(path))?))
}

fn env_u32(key: &str, default: u32) -> u32 {
    std::env::var(key).ok().and_then(|s| s.parse().ok()).unwrap_or(default)
}

pub fn hash_password(password: &str) -> Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(
        env_u32("ARGON2_M_COST", 9216),
        env_u32("ARGON2_T_COST", 2),
        env_u32("ARGON2_P_COST", 1),
        None,
    )
    .map_err(|e| anyhow!("argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    Ok(argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("password hashing failed: {e}"))?
        .to_string())
}

pub fn verify_password(stored_hash: &str, password: &str) -> bool {
    PasswordHash::new(stored_hash)
        .map(|parsed| Argon2::default().verify_password(password.as_bytes(), &parsed).is_ok())
        .unwrap_or(false)
}

const USERS_TABLE: TableDefinition<&str, &[u8]> = TableDefinition::new("users");

pub struct RedbStore {
    db: Arc<Database>,
}

impl RedbStore {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let db = Database::create(path).context("opening redb database")?;
        let wtx = db.begin_write()?;
        {
            wtx.open_table(USERS_TABLE)?;
        }
        wtx.commit()?;
        Ok(Self { db: Arc::new(db) })
    }

    async fn run<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Database) -> Result<T> + Send + 'static,
    {
        let db = self.db.clone();
        tokio::task::spawn_blocking(move || f(&db)).await?
    }
}

#[async_trait]
impl UserStore for RedbStore {
    async fn insert_user(&self, user: NewUser) -> Result<bool> {
        self.run(move |db| {
            let rec = UserRecord {
                username: user.username,
                userid: user.userid,
                password_hash: user.password_hash,
                superuser: user.superuser,
                admin: user.admin,
            };
            let bytes = bincode::serialize(&rec).map_err(|e| anyhow!("encode user: {e}"))?;
            let wtx = db.begin_write()?;
            let inserted = {
                let mut t = wtx.open_table(USERS_TABLE)?;
                if t.get(rec.username.as_str())?.is_some() {
                    false
                } else {
                    t.insert(rec.username.as_str(), bytes.as_slice())?;
                    true
                }
            };
            wtx.commit()?;
            Ok(inserted)
        })
        .await
    }

    async fn upsert_user(&self, user: NewUser) -> Result<()> {
        self.run(move |db| {
            let rec = UserRecord {
                username: user.username,
                userid: user.userid,
                password_hash: user.password_hash,
                superuser: user.superuser,
                admin: user.admin,
            };
            let bytes = bincode::serialize(&rec).map_err(|e| anyhow!("encode user: {e}"))?;
            let wtx = db.begin_write()?;
            {
                let mut t = wtx.open_table(USERS_TABLE)?;
                t.insert(rec.username.as_str(), bytes.as_slice())?;
            }
            wtx.commit()?;
            Ok(())
        })
        .await
    }

    async fn upsert_many(&self, users: Vec<NewUser>) -> Result<()> {
        if users.is_empty() {
            return Ok(());
        }
        self.run(move |db| {
            let wtx = db.begin_write()?;
            {
                let mut t = wtx.open_table(USERS_TABLE)?;
                for user in users {
                    let rec = UserRecord {
                        username: user.username,
                        userid: user.userid,
                        password_hash: user.password_hash,
                        superuser: user.superuser,
                        admin: user.admin,
                    };
                    let bytes = bincode::serialize(&rec).map_err(|e| anyhow!("encode user: {e}"))?;
                    t.insert(rec.username.as_str(), bytes.as_slice())?;
                }
            }
            wtx.commit()?;
            Ok(())
        })
        .await
    }

    async fn delete_user(&self, username: &str) -> Result<bool> {
        let username = username.to_owned();
        self.run(move |db| {
            let wtx = db.begin_write()?;
            let existed = {
                let mut t = wtx.open_table(USERS_TABLE)?;
                t.remove(username.as_str())?.is_some()
            };
            wtx.commit()?;
            Ok(existed)
        })
        .await
    }

    async fn list_users(&self) -> Result<Vec<UserRecord>> {
        self.run(|db| {
            let rtx = db.begin_read()?;
            let t = rtx.open_table(USERS_TABLE)?;
            let mut out = Vec::new();
            for item in t.iter()? {
                let (_, v) = item?;
                let rec: UserRecord =
                    bincode::deserialize(v.value()).map_err(|e| anyhow!("decode user: {e}"))?;
                out.push(rec);
            }
            out.sort_by(|a, b| a.username.cmp(&b.username));
            Ok(out)
        })
        .await
    }

    async fn get_user(&self, username: &str) -> Result<Option<UserRecord>> {
        let username = username.to_owned();
        self.run(move |db| {
            let rtx = db.begin_read()?;
            let t = rtx.open_table(USERS_TABLE)?;
            match t.get(username.as_str())? {
                Some(v) => Ok(Some(
                    bincode::deserialize(v.value()).map_err(|e| anyhow!("decode user: {e}"))?,
                )),
                None => Ok(None),
            }
        })
        .await
    }
}

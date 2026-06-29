use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct SecretValue {
    #[serde(default)]
    value: Option<String>,
}

#[derive(Clone)]
pub struct VaultClient {
    http: reqwest::Client,
    addr: String,
}

impl VaultClient {
    pub fn from_env(http: reqwest::Client) -> Option<Self> {
        let addr = std::env::var("VAULT_ADDR").ok().filter(|s| !s.is_empty())?;
        Some(Self {
            http,
            addr: addr.trim_end_matches('/').to_string(),
        })
    }

    pub async fn get_value(&self, name: &str) -> anyhow::Result<Option<String>> {
        let url = format!("{}/v1/secrets/{}", self.addr, encode_name(name));
        let resp = self.http.get(&url).send().await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let secret: SecretValue = resp.error_for_status()?.json().await?;
        Ok(secret.value)
    }
}

fn encode_name(name: &str) -> String {
    name.replace('%', "%25").replace('/', "%2F")
}

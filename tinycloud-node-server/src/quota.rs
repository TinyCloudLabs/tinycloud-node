use rocket::data::ByteUnit;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tinycloud_auth::resource::SpaceId;
use tokio::sync::RwLock;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuotaInfo {
    pub storage_limit_bytes: u64,
}

pub struct QuotaCache {
    overrides: Arc<RwLock<HashMap<String, u64>>>,
    default_limit: Option<ByteUnit>,
    billing_url: Option<String>,
    client: Option<reqwest::Client>,
}

impl QuotaCache {
    pub fn new(default_limit: Option<ByteUnit>, billing_url: Option<String>) -> Self {
        let client = billing_url.as_ref().map(|_| reqwest::Client::new());
        Self {
            overrides: Arc::new(RwLock::new(HashMap::new())),
            default_limit,
            billing_url,
            client,
        }
    }

    /// Get the effective storage limit for a space.
    /// Priority: cache override → lazy-load from billing sidecar → env default → None
    pub async fn get_limit(&self, space_id: &SpaceId) -> Option<ByteUnit> {
        let key = space_id.to_string();

        // Check cache first
        {
            let overrides = self.overrides.read().await;
            if let Some(&limit) = overrides.get(&key) {
                return Some(ByteUnit::Byte(limit));
            }
        }

        // Try lazy-load from billing sidecar
        if let (Some(url), Some(client)) = (&self.billing_url, &self.client) {
            match client.get(format!("{}/api/quota/{}", url, key)).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(info) = resp.json::<QuotaInfo>().await {
                        // Cache the result
                        let mut overrides = self.overrides.write().await;
                        overrides.insert(key, info.storage_limit_bytes);
                        return Some(ByteUnit::Byte(info.storage_limit_bytes));
                    }
                }
                _ => {
                    tracing::debug!("billing sidecar unavailable for space {}, using default", key);
                }
            }
        }

        // Fall back to env default
        self.default_limit
    }

    pub async fn set_limit(&self, space_id: &SpaceId, limit_bytes: u64) {
        let mut overrides = self.overrides.write().await;
        overrides.insert(space_id.to_string(), limit_bytes);
    }

    pub async fn remove_limit(&self, space_id: &SpaceId) -> bool {
        let mut overrides = self.overrides.write().await;
        overrides.remove(&space_id.to_string()).is_some()
    }

    pub async fn get_override(&self, space_id: &SpaceId) -> Option<u64> {
        let overrides = self.overrides.read().await;
        overrides.get(&space_id.to_string()).copied()
    }

    pub async fn list_overrides(&self) -> HashMap<String, u64> {
        let overrides = self.overrides.read().await;
        overrides.clone()
    }

    pub fn default_limit(&self) -> Option<ByteUnit> {
        self.default_limit
    }
}

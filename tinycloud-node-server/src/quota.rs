use rocket::data::ByteUnit;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tinycloud_auth::resource::SpaceId;
use tokio::sync::RwLock;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct QuotaInfo {
    pub storage_limit_bytes: u64,
}

/// How long a remote quota answer is served without triggering a background
/// refresh. Matches the billing sidecar's own usage-cache TTL.
const FRESH_TTL: Duration = Duration::from_secs(60);
/// After a failed fetch with no known value, wait this long before retrying
/// so an unavailable quota service is not hammered once per write.
const FAILURE_BACKOFF: Duration = Duration::from_secs(30);
/// Budget for the single blocking fetch on first sight of a space. Writes to
/// already-seen spaces never wait on the quota service (stale-while-revalidate),
/// so this is the worst-case latency the quota system can add to a write.
const FETCH_TIMEOUT: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug)]
struct RemoteEntry {
    /// `None` = the last fetch failed and no prior value is known (negative
    /// cache); serve the env default until `FAILURE_BACKOFF` elapses.
    limit_bytes: Option<u64>,
    fetched_at: Instant,
    /// Set by `remove_limit` (billing invalidation after a plan change): the
    /// value is served one more time while a refresh runs in the background.
    stale: bool,
    /// The most recent failed refresh of an already-known value. This keeps
    /// stale writes from repeatedly retrying an unavailable quota service.
    last_failure: Option<Instant>,
}

#[allow(clippy::unnecessary_map_or)] // Keep D1's no-failure-or-backoff-elapsed policy explicit.
fn should_spawn_refresh(
    stale: bool,
    fetched_at_elapsed: Duration,
    last_failure_elapsed: Option<Duration>,
) -> bool {
    (stale && last_failure_elapsed.map_or(true, |elapsed| elapsed >= FAILURE_BACKOFF))
        || (!stale && fetched_at_elapsed >= FRESH_TTL)
}

pub struct QuotaCache {
    /// Admin-set overrides (`PUT /admin/quota/<space>`). Checked before the
    /// quota service and never expired. NOTE: these are in-memory only and
    /// do not survive a node restart — re-apply after deploys, or use the
    /// billing sidecar for durable limits.
    overrides: Arc<RwLock<HashMap<String, u64>>>,
    /// Values learned from the quota service, with freshness metadata.
    remote: Arc<RwLock<HashMap<String, RemoteEntry>>>,
    /// Spaces with a background refresh currently in flight (dedupe guard).
    inflight: Arc<RwLock<HashSet<String>>>,
    default_limit: Option<ByteUnit>,
    quota_url: Option<String>,
    client: Option<reqwest::Client>,
}

impl QuotaCache {
    pub fn new(default_limit: Option<ByteUnit>, quota_url: Option<String>) -> Self {
        let client = quota_url.as_ref().map(|_| {
            reqwest::Client::builder()
                .timeout(FETCH_TIMEOUT)
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .expect("failed to build quota reqwest client")
        });
        Self {
            overrides: Arc::new(RwLock::new(HashMap::new())),
            remote: Arc::new(RwLock::new(HashMap::new())),
            inflight: Arc::new(RwLock::new(HashSet::new())),
            default_limit,
            quota_url,
            client,
        }
    }

    /// Get the effective storage limit for a space.
    ///
    /// Priority: admin override → remote quota service → env default → None.
    ///
    /// The remote lookup never blocks a write for a space that has been seen
    /// before: fresh values are served directly, stale values are served
    /// while a refresh runs in the background, and fetch failures fall back
    /// to the env default (fail-open — a billing hiccup must not deny
    /// writes). Only the very first write to a space performs one bounded
    /// (`FETCH_TIMEOUT`) synchronous fetch, so paid limits above the env
    /// default apply from the first byte.
    pub async fn get_limit(&self, space_id: &SpaceId) -> Option<ByteUnit> {
        let key = space_id.to_string();

        {
            let overrides = self.overrides.read().await;
            if let Some(&limit) = overrides.get(&key) {
                return Some(ByteUnit::Byte(limit));
            }
        }

        if self.quota_url.is_none() || self.client.is_none() {
            return self.default_limit;
        }

        let entry = { self.remote.read().await.get(&key).copied() };
        match entry {
            Some(RemoteEntry {
                limit_bytes: Some(limit),
                fetched_at,
                stale,
                last_failure,
            }) => {
                if should_spawn_refresh(
                    stale,
                    fetched_at.elapsed(),
                    last_failure.map(|failure| failure.elapsed()),
                ) {
                    self.spawn_refresh(key);
                }
                Some(ByteUnit::Byte(limit))
            }
            Some(RemoteEntry {
                limit_bytes: None,
                fetched_at,
                ..
            }) => {
                if fetched_at.elapsed() >= FAILURE_BACKOFF {
                    self.spawn_refresh(key);
                }
                self.default_limit
            }
            None => match self.fetch_and_record(&key).await {
                Some(limit) => Some(ByteUnit::Byte(limit)),
                None => self.default_limit,
            },
        }
    }

    /// Fetch the limit from the quota service and record the outcome
    /// (success or negative entry) in the remote cache.
    async fn fetch_and_record(&self, key: &str) -> Option<u64> {
        let fetched = fetch_remote(self.client.as_ref()?, self.quota_url.as_deref()?, key).await;
        record_fetch(&self.remote, key, fetched).await;
        fetched
    }

    /// Refresh a space's remote entry in the background, deduplicating
    /// concurrent refreshes for the same space.
    fn spawn_refresh(&self, key: String) {
        let (Some(client), Some(url)) = (self.client.clone(), self.quota_url.clone()) else {
            return;
        };
        let remote = self.remote.clone();
        let inflight = self.inflight.clone();
        tokio::spawn(async move {
            {
                let mut guard = inflight.write().await;
                if !guard.insert(key.clone()) {
                    return; // refresh already in flight
                }
            }
            let fetched = fetch_remote(&client, &url, &key).await;
            record_fetch(&remote, &key, fetched).await;
            inflight.write().await.remove(&key);
        });
    }

    /// Set an admin override. In-memory only: overrides are lost on restart.
    pub async fn set_limit(&self, space_id: &SpaceId, limit_bytes: u64) {
        let mut overrides = self.overrides.write().await;
        overrides.insert(space_id.to_string(), limit_bytes);
    }

    /// Remove an admin override and mark any remote-cached value stale so the
    /// next write triggers a background refresh (the billing sidecar calls
    /// this after a plan change). Returns true if an override or a cached
    /// remote value existed.
    pub async fn remove_limit(&self, space_id: &SpaceId) -> bool {
        let key = space_id.to_string();
        let had_override = self.overrides.write().await.remove(&key).is_some();
        let mut remote = self.remote.write().await;
        let had_remote = match remote.get_mut(&key) {
            Some(entry) => {
                entry.stale = true;
                true
            }
            None => false,
        };
        had_override || had_remote
    }

    pub async fn get_override(&self, space_id: &SpaceId) -> Option<u64> {
        let overrides = self.overrides.read().await;
        overrides.get(&space_id.to_string()).copied()
    }

    /// The last limit learned from the quota service, if any (stale or not).
    /// Local read only — safe for the admin endpoint the quota service calls
    /// back into (no recursion).
    pub async fn get_cached_remote(&self, space_id: &SpaceId) -> Option<u64> {
        self.remote
            .read()
            .await
            .get(&space_id.to_string())
            .and_then(|e| e.limit_bytes)
    }

    pub async fn list_overrides(&self) -> HashMap<String, u64> {
        let overrides = self.overrides.read().await;
        overrides.clone()
    }

    pub fn default_limit(&self) -> Option<ByteUnit> {
        self.default_limit
    }

    pub fn quota_url(&self) -> Option<&str> {
        self.quota_url.as_deref()
    }

    #[cfg(test)]
    async fn seed_remote(&self, key: &str, limit_bytes: Option<u64>, stale: bool) {
        self.remote.write().await.insert(
            key.to_string(),
            RemoteEntry {
                limit_bytes,
                fetched_at: Instant::now(),
                stale,
                last_failure: None,
            },
        );
    }

    #[cfg(test)]
    async fn remote_entry(&self, key: &str) -> Option<(Option<u64>, bool)> {
        self.remote
            .read()
            .await
            .get(key)
            .map(|e| (e.limit_bytes, e.stale))
    }
}

async fn fetch_remote(client: &reqwest::Client, url: &str, key: &str) -> Option<u64> {
    match client
        .get(format!("{}/api/quota/{}", url, key))
        .send()
        .await
    {
        Ok(resp) if resp.status().is_success() => match resp.json::<QuotaInfo>().await {
            Ok(info) => Some(info.storage_limit_bytes),
            Err(e) => {
                tracing::warn!("quota service returned invalid body for space {key}: {e}");
                None
            }
        },
        Ok(resp) => {
            tracing::warn!(
                "quota service returned {} for space {key}, using fallback",
                resp.status()
            );
            None
        }
        Err(e) => {
            tracing::debug!("quota service unavailable for space {key} ({e}), using fallback");
            None
        }
    }
}

/// Record a fetch outcome. A failure never erases a previously known limit:
/// the old value stays (marked refreshed-at-now, still stale) so writes keep
/// using the last-known limit rather than snapping to the env default.
async fn record_fetch(
    remote: &Arc<RwLock<HashMap<String, RemoteEntry>>>,
    key: &str,
    fetched: Option<u64>,
) {
    let mut guard = remote.write().await;
    match (fetched, guard.get(key).and_then(|e| e.limit_bytes)) {
        (Some(limit), _) => {
            guard.insert(
                key.to_string(),
                RemoteEntry {
                    limit_bytes: Some(limit),
                    fetched_at: Instant::now(),
                    stale: false,
                    last_failure: None,
                },
            );
        }
        (None, Some(previous)) => {
            guard.insert(
                key.to_string(),
                RemoteEntry {
                    limit_bytes: Some(previous),
                    fetched_at: Instant::now(),
                    stale: true,
                    last_failure: Some(Instant::now()),
                },
            );
        }
        (None, None) => {
            guard.insert(
                key.to_string(),
                RemoteEntry {
                    limit_bytes: None,
                    fetched_at: Instant::now(),
                    stale: false,
                    last_failure: None,
                },
            );
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use tokio::io::AsyncWriteExt;

    fn space(n: u8) -> SpaceId {
        format!("tinycloud:pkh:eip155:1:0x7BD63AA37326a64d458559F44432103e3d6eEDE9:s{n}")
            .parse()
            .expect("valid space id")
    }

    // Unroutable per RFC 5737 (TEST-NET-1): connects fail fast and never
    // succeed, exercising the failure paths without a live service.
    const DEAD_URL: &str = "http://192.0.2.1:1";

    #[tokio::test]
    async fn first_sight_http_success_is_parsed_and_cached() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local listener");
        let quota_url = format!(
            "http://{}",
            listener.local_addr().expect("listener address")
        );
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept quota request");
            let body = r#"{"storage_limit_bytes":500}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write quota response");
            stream.shutdown().await.expect("close quota response");
            listener
        });

        let cache = QuotaCache::new(Some(ByteUnit::Byte(100)), Some(quota_url));
        let sid = space(1);
        let key = sid.to_string();

        assert_eq!(cache.get_limit(&sid).await, Some(ByteUnit::Byte(500)));
        let listener = server.await.expect("quota server task");
        assert_eq!(cache.remote_entry(&key).await, Some((Some(500), false)));
        assert_eq!(cache.get_limit(&sid).await, Some(ByteUnit::Byte(500)));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "the fresh cached entry must avoid a second network request",
        );
    }

    #[tokio::test]
    async fn refresh_decision_respects_failure_backoff_and_invalidation() {
        assert!(!should_spawn_refresh(
            true,
            Duration::from_secs(0),
            Some(FAILURE_BACKOFF - Duration::from_millis(1)),
        ));
        assert!(should_spawn_refresh(
            true,
            Duration::from_secs(0),
            Some(FAILURE_BACKOFF),
        ));
        assert!(should_spawn_refresh(true, Duration::from_secs(0), None));
        assert!(!should_spawn_refresh(false, Duration::from_secs(0), None));
    }

    #[tokio::test]
    async fn recent_failed_stale_refresh_does_not_spawn() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind local listener");
        let cache = QuotaCache::new(
            Some(ByteUnit::Byte(100)),
            Some(format!(
                "http://{}",
                listener.local_addr().expect("listener address")
            )),
        );
        let sid = space(1);
        let key = sid.to_string();
        cache.seed_remote(&key, Some(500), false).await;
        record_fetch(&cache.remote, &key, None).await;

        assert_eq!(cache.get_limit(&sid).await, Some(ByteUnit::Byte(500)));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "a recent failed refresh must suppress another background fetch",
        );
    }

    #[tokio::test]
    async fn override_beats_remote_and_default() {
        let cache = QuotaCache::new(Some(ByteUnit::Byte(100)), Some(DEAD_URL.into()));
        let sid = space(1);
        cache.seed_remote(&sid.to_string(), Some(200), false).await;
        cache.set_limit(&sid, 300).await;
        assert_eq!(cache.get_limit(&sid).await, Some(ByteUnit::Byte(300)));
    }

    #[tokio::test]
    async fn no_quota_url_falls_back_to_default() {
        let cache = QuotaCache::new(Some(ByteUnit::Byte(100)), None);
        assert_eq!(cache.get_limit(&space(1)).await, Some(ByteUnit::Byte(100)));
    }

    #[tokio::test]
    async fn fresh_remote_value_served_directly() {
        let cache = QuotaCache::new(Some(ByteUnit::Byte(100)), Some(DEAD_URL.into()));
        let sid = space(1);
        cache.seed_remote(&sid.to_string(), Some(500), false).await;
        assert_eq!(cache.get_limit(&sid).await, Some(ByteUnit::Byte(500)));
    }

    #[tokio::test]
    async fn stale_remote_value_still_served_not_blocked() {
        let cache = QuotaCache::new(Some(ByteUnit::Byte(100)), Some(DEAD_URL.into()));
        let sid = space(1);
        cache.seed_remote(&sid.to_string(), Some(500), true).await;
        // Stale value is served immediately; the refresh happens off-path.
        assert_eq!(cache.get_limit(&sid).await, Some(ByteUnit::Byte(500)));
    }

    #[tokio::test]
    async fn first_sight_fetch_failure_falls_open_and_negative_caches() {
        let cache = QuotaCache::new(Some(ByteUnit::Byte(100)), Some(DEAD_URL.into()));
        let sid = space(1);
        assert_eq!(cache.get_limit(&sid).await, Some(ByteUnit::Byte(100)));
        // Failure recorded as a negative entry: subsequent writes inside the
        // backoff window use the default without re-fetching.
        let entry = cache.remote_entry(&sid.to_string()).await;
        assert_eq!(entry, Some((None, false)));
        assert_eq!(cache.get_limit(&sid).await, Some(ByteUnit::Byte(100)));
    }

    #[tokio::test]
    async fn failed_refresh_keeps_last_known_limit() {
        let cache = QuotaCache::new(Some(ByteUnit::Byte(100)), Some(DEAD_URL.into()));
        let sid = space(1);
        let key = sid.to_string();
        cache.seed_remote(&key, Some(500), false).await;
        // Simulate a refresh failing after a value was known.
        record_fetch(&cache.remote, &key, None).await;
        assert_eq!(cache.remote_entry(&key).await, Some((Some(500), true)));
        assert_eq!(cache.get_limit(&sid).await, Some(ByteUnit::Byte(500)));
    }

    #[tokio::test]
    async fn remove_limit_drops_override_and_marks_remote_stale() {
        let cache = QuotaCache::new(Some(ByteUnit::Byte(100)), Some(DEAD_URL.into()));
        let sid = space(1);
        let key = sid.to_string();
        cache.set_limit(&sid, 300).await;
        cache.seed_remote(&key, Some(500), false).await;
        assert!(cache.remove_limit(&sid).await);
        assert_eq!(cache.get_override(&sid).await, None);
        assert_eq!(cache.remote_entry(&key).await, Some((Some(500), true)));
        // Nothing left to remove except the (kept) stale remote entry.
        assert!(cache.remove_limit(&sid).await);
    }

    #[tokio::test]
    async fn remove_limit_on_unknown_space_is_false() {
        let cache = QuotaCache::new(None, Some(DEAD_URL.into()));
        assert!(!cache.remove_limit(&space(9)).await);
    }
}

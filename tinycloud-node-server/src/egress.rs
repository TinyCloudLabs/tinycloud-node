//! Outbound webhook destination policy. This does not enable network DID resolution.
use crate::{config::Config, BlockConfig};
use reqwest::{
    dns::{Addrs, Resolve, Resolving},
    header::{HeaderMap, HeaderName, HeaderValue, InvalidHeaderName, InvalidHeaderValue},
    redirect, Client, Url,
};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    sync::{Mutex, RwLock, RwLockReadGuard},
    time::Instant,
};

const DNS_TIMEOUT: Duration = Duration::from_secs(1);
const REFRESH_INTERVAL: Duration = Duration::from_secs(600);

/// Fail-closed destination and internal-endpoint resolution errors.
#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("destination DNS lookup failed")]
    Dns,
    #[error("destination DNS lookup timed out")]
    DnsTimeout,
    #[error("destination has no permitted address")]
    Forbidden,
    #[error("internal endpoint deny-set is unavailable")]
    Unavailable,
    #[error("invalid configured internal endpoint")]
    InvalidEndpoint,
}

impl EgressError {
    /// Temporary failures may be retried without permitting a network connection.
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Dns | Self::DnsTimeout | Self::Unavailable)
    }
}

#[async_trait::async_trait]
pub(crate) trait LookupHost: Send + Sync {
    async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, EgressError>;
}

struct SystemLookup;
#[async_trait::async_trait]
impl LookupHost for SystemLookup {
    async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>, EgressError> {
        tokio::net::lookup_host((host, 0))
            .await
            .map(|addresses| addresses.map(|address| address.ip()).collect())
            .map_err(|_| EgressError::Dns)
    }
}

struct DenySet {
    addresses: Arc<HashSet<IpAddr>>,
    refreshed: Option<Instant>,
    healthy: bool,
}

/// Shared policy for callback registration and every delivery attempt.
/// Internal endpoint lookup failure or stale state denies all destinations.
pub struct EgressPolicy {
    lookup: Arc<dyn LookupHost>,
    internal_hosts: Vec<String>,
    deny: RwLock<DenySet>,
    refresh_lock: Mutex<()>,
    #[cfg(test)]
    allow_loopback: bool,
    #[cfg(test)]
    roots: Vec<reqwest::Certificate>,
}

impl EgressPolicy {
    /// Gather operator-configured service hosts; SQLite has no network host.
    /// Credentials and paths are neither retained nor included in errors.
    pub fn from_config(config: &Config, quota_url: Option<&str>) -> Result<Self, EgressError> {
        let mut hosts = Vec::new();
        if let Some(database) = config.storage.database.as_deref() {
            if !database.starts_with("sqlite:") {
                hosts.push(endpoint_host(database)?);
            }
        }
        if let Some(url) = quota_url {
            hosts.push(endpoint_host(url)?);
        }
        if let Some(allowlist) = &config.spaces.allowlist {
            hosts.push(endpoint_host(&allowlist.0)?);
        }
        if let BlockConfig::A(s3) = &config.storage.blocks {
            if let Some(endpoint) = &s3.endpoint {
                hosts.push(endpoint_host(&endpoint.to_string())?);
            }
        }
        hosts.sort_unstable();
        hosts.dedup();
        Ok(Self::new(hosts, Arc::new(SystemLookup)))
    }

    fn new(internal_hosts: Vec<String>, lookup: Arc<dyn LookupHost>) -> Self {
        let healthy = internal_hosts.is_empty();
        Self {
            lookup,
            internal_hosts,
            deny: RwLock::new(DenySet {
                addresses: Arc::new(HashSet::new()),
                refreshed: healthy.then(Instant::now),
                healthy,
            }),
            refresh_lock: Mutex::new(()),
            #[cfg(test)]
            allow_loopback: false,
            #[cfg(test)]
            roots: Vec::new(),
        }
    }

    async fn lookup_bounded(&self, host: &str) -> Result<Vec<IpAddr>, EgressError> {
        if let Ok(ip) = host.trim_matches(['[', ']']).parse() {
            return Ok(vec![ip]);
        }
        tokio::time::timeout(DNS_TIMEOUT, self.lookup.lookup(host))
            .await
            .map_err(|_| EgressError::DnsTimeout)?
    }

    /// Atomically replace the deny-set only after every host resolves.
    /// On failure retain the last set but close all webhook egress until recovery.
    pub async fn refresh(&self) -> Result<(), EgressError> {
        let _guard = self.refresh_lock.lock().await;
        self.refresh_locked().await
    }

    async fn refresh_locked(&self) -> Result<(), EgressError> {
        // Exclusive state access closes egress while DNS is in progress. Keep
        // the prior state intact until completion so cancellation is harmless.
        let mut deny = self.deny.write().await;
        let results = futures::future::join_all(
            self.internal_hosts
                .iter()
                .map(|host| self.lookup_bounded(host)),
        )
        .await;
        let mut addresses = HashSet::new();
        let mut success = true;
        for result in results {
            match result {
                Ok(ips) if !ips.is_empty() => {
                    for ip in ips {
                        addresses.insert(ip);
                        for v4 in embedded_v4(ip) {
                            addresses.insert(IpAddr::V4(v4));
                        }
                    }
                }
                _ => success = false,
            }
        }
        deny.refreshed = Some(Instant::now());
        if success {
            deny.addresses = Arc::new(addresses);
            deny.healthy = true;
            Ok(())
        } else {
            deny.healthy = false;
            Err(EgressError::Unavailable)
        }
    }

    fn stale(&self, deny: &DenySet) -> bool {
        !self.internal_hosts.is_empty()
            && deny
                .refreshed
                .is_none_or(|at| at.elapsed() >= REFRESH_INTERVAL)
    }

    async fn read_state(&self) -> Result<RwLockReadGuard<'_, DenySet>, EgressError> {
        tokio::time::timeout(DNS_TIMEOUT, self.deny.read())
            .await
            .map_err(|_| EgressError::Unavailable)
    }

    async fn ensure_fresh(&self) -> Result<(), EgressError> {
        if self.internal_hosts.is_empty() {
            return Ok(());
        }
        let stale = {
            let state = self.read_state().await?;
            self.stale(&state)
        };
        if stale {
            let _guard = tokio::time::timeout(DNS_TIMEOUT, self.refresh_lock.lock())
                .await
                .map_err(|_| EgressError::Unavailable)?;
            let stale = {
                let state = self.read_state().await?;
                self.stale(&state)
            };
            if stale {
                self.refresh_locked().await?;
            }
        }
        if !self.read_state().await?.healthy {
            return Err(EgressError::Unavailable);
        }
        Ok(())
    }

    async fn send_lease(&self) -> Result<RwLockReadGuard<'_, DenySet>, EgressError> {
        loop {
            self.ensure_fresh().await?;
            let lease = self.read_state().await?;
            if !lease.healthy {
                return Err(EgressError::Unavailable);
            }
            if !self.stale(&lease) {
                return Ok(lease);
            }
            // A refresh may have completed, failed or expired between checks.
            drop(lease);
        }
    }

    fn permits_ip(&self, ip: IpAddr, denied: &HashSet<IpAddr>) -> bool {
        if denied.contains(&ip) || embedded_v4(ip).any(|v4| denied.contains(&IpAddr::V4(v4))) {
            return false;
        }
        let forbidden = Self::forbidden(ip).is_some();
        #[cfg(test)]
        let forbidden = forbidden && !(self.allow_loopback && ip.is_loopback());
        !forbidden
    }

    async fn permitted(
        &self,
        ips: impl Iterator<Item = IpAddr>,
        port: u16,
    ) -> Result<Vec<SocketAddr>, EgressError> {
        let deny = self.send_lease().await?;
        let mut addresses = Vec::new();
        for ip in ips {
            let address = SocketAddr::new(ip, port);
            if self.permits_ip(ip, &deny.addresses) && !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            Err(EgressError::Forbidden)
        } else {
            Ok(addresses)
        }
    }

    /// Resolve once, filter each address, and bind the result to this URL's host.
    /// Literal hosts are checked here because reqwest bypasses DNS for them.
    pub async fn resolve_url(&self, url: &Url) -> Result<VettedDestination, EgressError> {
        self.ensure_fresh().await?;
        let host = url.host_str().ok_or(EgressError::Forbidden)?;
        let port = url.port_or_known_default().ok_or(EgressError::Forbidden)?;
        let addresses = if let Ok(ip) = host.trim_matches(['[', ']']).parse() {
            self.permitted(std::iter::once(ip), port).await?
        } else {
            let ips = self.lookup_bounded(host).await?;
            self.permitted(ips.into_iter(), port).await?
        };
        Ok(VettedDestination {
            url: url.clone(),
            addresses: addresses.into(),
        })
    }

    /// Return the special-use class, recursively checking embedded IPv4.
    pub fn forbidden(ip: IpAddr) -> Option<&'static str> {
        match ip {
            IpAddr::V4(ip) => {
                let [a, b, c, _] = ip.octets();
                match (a, b, c) {
                    (0, _, _) => Some("this_network"),
                    (10, _, _) | (172, 16..=31, _) | (192, 168, _) => Some("private"),
                    (100, 64..=127, _) => Some("cgnat"),
                    (127, _, _) => Some("loopback"),
                    (169, 254, _) => Some("link_local"),
                    (192, 0, 0) => Some("ietf"),
                    (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => Some("documentation"),
                    (198, 18..=19, _) => Some("benchmark"),
                    (192, 88, 99) => Some("6to4_relay"),
                    (224..=239, _, _) => Some("multicast"),
                    (240..=255, _, _) => Some("reserved"),
                    _ => None,
                }
            }
            IpAddr::V6(ip) => {
                let s = ip.segments();
                if ip.is_unspecified() {
                    return Some("unspecified");
                }
                if ip.is_loopback() {
                    return Some("loopback");
                }
                if s[0] & 0xffc0 == 0xfe80 {
                    return Some("link_local");
                }
                if s[0] & 0xffc0 == 0xfec0 {
                    return Some("site_local");
                }
                if s[0] & 0xfe00 == 0xfc00 {
                    return Some("unique_local");
                }
                if ip.is_multicast() {
                    return Some("multicast");
                }
                if s[0] == 0x2001 && s[1] == 0xdb8 {
                    return Some("documentation");
                }
                if s[..4] == [0x100, 0, 0, 0] {
                    return Some("discard");
                }
                if s[0] == 0x2001 && s[1] == 0 {
                    return Some("teredo");
                }
                embedded_v4(IpAddr::V6(ip)).find_map(|v4| Self::forbidden(IpAddr::V4(v4)))
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(
        hosts: Vec<String>,
        lookup: Arc<dyn LookupHost>,
        allow_loopback: bool,
    ) -> Self {
        let mut policy = Self::new(hosts, lookup);
        policy.allow_loopback = allow_loopback;
        policy
    }

    #[cfg(test)]
    pub(crate) fn test_loopback() -> Arc<Self> {
        Arc::new(Self::for_test(Vec::new(), Arc::new(SystemLookup), true))
    }

    #[cfg(test)]
    pub(crate) fn permits_test_http(&self) -> bool {
        self.allow_loopback
    }

    #[cfg(test)]
    pub(crate) fn with_test_root(mut self, root: reqwest::Certificate) -> Self {
        self.roots.push(root);
        self
    }
}

fn endpoint_host(value: &str) -> Result<String, EgressError> {
    let url = Url::parse(value).map_err(|_| EgressError::InvalidEndpoint)?;
    url.host_str()
        .filter(|host| !host.is_empty())
        .map(|host| host.trim_matches(['[', ']']).to_owned())
        .ok_or(EgressError::InvalidEndpoint)
}

// RFC 6052 layouts. Local-use NAT64 can use /48, /56, /64 or /96 within
// 64:ff9b:1::/48; reject if any canonical interpretation carries a denied v4.
// Check the u octet and zero suffix for the shorter layouts, not just the tail.
fn embedded_v4(ip: IpAddr) -> impl Iterator<Item = Ipv4Addr> {
    let mut values = [None; 4];
    if let IpAddr::V6(ip) = ip {
        let s = ip.segments();
        let b = ip.octets();
        if s[..6] == [0, 0, 0, 0, 0, 0]
            || s[..6] == [0, 0, 0, 0, 0, 0xffff]
            || s[..6] == [0x64, 0xff9b, 0, 0, 0, 0]
        {
            values[0] = Some(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
        } else if s[0] == 0x2002 {
            values[0] = Some(Ipv4Addr::new(b[2], b[3], b[4], b[5]));
        } else if s[..3] == [0x64, 0xff9b, 1] {
            if b[8] == 0 && b[11..].iter().all(|byte| *byte == 0) {
                values[0] = Some(Ipv4Addr::new(b[6], b[7], b[9], b[10]));
            }
            if b[8] == 0 && b[12..].iter().all(|byte| *byte == 0) {
                values[1] = Some(Ipv4Addr::new(b[7], b[9], b[10], b[11]));
            }
            if b[8] == 0 && b[13..].iter().all(|byte| *byte == 0) {
                values[2] = Some(Ipv4Addr::new(b[9], b[10], b[11], b[12]));
            }
            values[3] = Some(Ipv4Addr::new(b[12], b[13], b[14], b[15]));
        }
    }
    values.into_iter().flatten()
}

/// A single lookup's vetted addresses. No caller can insert unvetted addresses.
pub struct VettedDestination {
    url: Url,
    addresses: Arc<[SocketAddr]>,
}

impl VettedDestination {
    /// The immutable URL whose addresses were vetted by this lookup.
    pub fn url(&self) -> &Url {
        &self.url
    }

    #[cfg(test)]
    pub(crate) fn is_loopback(&self) -> bool {
        self.addresses
            .iter()
            .all(|address| address.ip().is_loopback())
    }
}

/// Resolver for the sealed sender's lease-bound address snapshot. It never
/// performs a second DNS lookup or reacquires the policy lock.
struct PolicyResolver {
    host: String,
    addresses: Arc<[SocketAddr]>,
    policy: Arc<EgressPolicy>,
    denied: Arc<HashSet<IpAddr>>,
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: hyper::client::connect::dns::Name) -> Resolving {
        let policy = self.policy.clone();
        let addresses = self.addresses.clone();
        let denied = self.denied.clone();
        let matches = name.as_str() == self.host;
        Box::pin(async move {
            if !matches {
                return Err(
                    Box::new(EgressError::Forbidden) as Box<dyn std::error::Error + Send + Sync>
                );
            }
            let mut vetted = (0..addresses.len())
                .map(move |index| addresses[index])
                .filter(move |address| policy.permits_ip(address.ip(), &denied));
            let first = vetted.next().ok_or(EgressError::Forbidden)?;
            Ok(Box::new(std::iter::once(first).chain(vetted)) as Addrs)
        })
    }
}

/// A failed sealed send retains the destination/transport distinction.
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    #[error(transparent)]
    Policy(#[from] EgressError),
    #[error(transparent)]
    Transport(#[from] reqwest::Error),
    #[error("invalid request header name: {0}")]
    HeaderName(#[from] InvalidHeaderName),
    #[error("invalid request header value: {0}")]
    HeaderValue(#[from] InvalidHeaderValue),
    #[error("outbound request timed out")]
    Timeout,
}

impl SendError {
    /// Only a proven forbidden destination is a terminal policy rejection.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Policy(error) => error.is_retryable(),
            _ => true,
        }
    }
}

/// A target-bound POST request. No raw client, URL setter, redirect policy or
/// proxy override is exposed; even literal hosts are rechecked at `send`.
pub struct EgressRequest {
    policy: Arc<EgressPolicy>,
    destination: VettedDestination,
    timeout: Duration,
    headers: HeaderMap,
    body: Option<reqwest::Body>,
    error: Option<SendError>,
}

/// Prepare a POST to exactly the URL carried by the vetted destination.
/// The actual connection is permitted only under a fresh, healthy read lease.
pub fn post(
    policy: Arc<EgressPolicy>,
    destination: VettedDestination,
    timeout: Duration,
) -> EgressRequest {
    EgressRequest {
        policy,
        destination,
        timeout,
        headers: HeaderMap::new(),
        body: None,
        error: None,
    }
}

impl EgressRequest {
    /// Set a header without exposing or changing the target URL.
    pub fn header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if self.error.is_none() {
            match HeaderName::from_bytes(name.as_bytes()) {
                Ok(name) => match HeaderValue::from_str(value.as_ref()) {
                    Ok(value) => {
                        self.headers.insert(name, value);
                    }
                    Err(error) => self.error = Some(error.into()),
                },
                Err(error) => self.error = Some(error.into()),
            }
        }
        self
    }

    /// Move the original body bytes into the request.
    pub fn body(mut self, body: impl Into<reqwest::Body>) -> Self {
        if self.error.is_none() {
            self.body = Some(body.into());
        }
        self
    }

    /// Recheck the bound destination and keep refresh from invalidating it
    /// until the connection/request completes. Cancellation releases the lease.
    pub async fn send(self) -> Result<reqwest::Response, SendError> {
        let timeout = self.timeout;
        let started = Instant::now();
        tokio::time::timeout(timeout, self.send_under_lease(started))
            .await
            .map_err(|_| SendError::Timeout)?
    }

    async fn send_under_lease(self, started: Instant) -> Result<reqwest::Response, SendError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let lease = self.policy.send_lease().await?;
        if !self
            .destination
            .addresses
            .iter()
            .any(|address| self.policy.permits_ip(address.ip(), &lease.addresses))
        {
            return Err(EgressError::Forbidden.into());
        }
        let host = self
            .destination
            .url
            .host_str()
            .ok_or(EgressError::Forbidden)?
            .to_owned();
        #[cfg(not(test))]
        let https_only = true;
        #[cfg(test)]
        let https_only = !(self.policy.allow_loopback && self.destination.is_loopback());
        let builder = Client::builder()
            .no_proxy()
            .https_only(https_only)
            .redirect(redirect::Policy::none())
            .connect_timeout(Duration::from_secs(2))
            .timeout(self.timeout);
        #[cfg(test)]
        let builder = self
            .policy
            .roots
            .iter()
            .cloned()
            .fold(builder, |builder, root| builder.add_root_certificate(root));
        let client = builder
            .dns_resolver(Arc::new(PolicyResolver {
                host,
                addresses: self.destination.addresses,
                policy: self.policy.clone(),
                denied: lease.addresses.clone(),
            }))
            .build()?;
        let mut request = client.post(self.destination.url).headers(self.headers);
        if let Some(body) = self.body {
            request = request.body(body);
        }
        let result = request
            .timeout(self.timeout.saturating_sub(started.elapsed()))
            .send()
            .await;
        drop(lease);
        result.map_err(SendError::Transport)
    }
}

/// Refresh the service deny-set every ten minutes and stop with Rocket.
pub async fn run_refresh(policy: Arc<EgressPolicy>, shutdown: rocket::Shutdown) {
    let mut interval =
        tokio::time::interval_at(Instant::now() + REFRESH_INTERVAL, REFRESH_INTERVAL);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = interval.tick() => {
                if policy.refresh().await.is_err() {
                    tracing::warn!("webhook egress closed: internal endpoint refresh failed");
                }
            }
            _ = &mut shutdown => break,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;

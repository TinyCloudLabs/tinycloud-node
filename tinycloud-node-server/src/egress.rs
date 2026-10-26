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

    fn permits_ip_in(&self, ip: IpAddr, denied: &HashSet<IpAddr>, scope: AddressScope) -> bool {
        if denied.contains(&ip) || embedded_v4(ip).any(|v4| denied.contains(&IpAddr::V4(v4))) {
            return false;
        }
        let forbidden = Self::forbidden(ip)
            .is_some_and(|class| scope == AddressScope::PublicOnly || !is_private_class(class));
        #[cfg(test)]
        let forbidden = forbidden && !(self.allow_loopback && ip.is_loopback());
        !forbidden
    }

    async fn permitted(
        &self,
        ips: impl Iterator<Item = IpAddr>,
        port: u16,
        scope: AddressScope,
    ) -> Result<Vec<SocketAddr>, EgressError> {
        let deny = self.send_lease().await?;
        let mut addresses = Vec::new();
        for ip in ips {
            let address = SocketAddr::new(ip, port);
            if self.permits_ip_in(ip, &deny.addresses, scope) && !addresses.contains(&address) {
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
        self.resolve_url_scoped(url, AddressScope::PublicOnly).await
    }

    /// As [`Self::resolve_url`], with the address scope the destination is
    /// vetted under. The scope is bound to the result and applied again at
    /// connect time; the internal-endpoint deny-set applies under every scope.
    pub async fn resolve_url_scoped(
        &self,
        url: &Url,
        scope: AddressScope,
    ) -> Result<VettedDestination, EgressError> {
        self.ensure_fresh().await?;
        let host = url.host_str().ok_or(EgressError::Forbidden)?;
        let port = url.port_or_known_default().ok_or(EgressError::Forbidden)?;
        let addresses = if let Ok(ip) = host.trim_matches(['[', ']']).parse() {
            self.permitted(std::iter::once(ip), port, scope).await?
        } else {
            let ips = self.lookup_bounded(host).await?;
            self.permitted(ips.into_iter(), port, scope).await?
        };
        Ok(VettedDestination {
            url: url.clone(),
            addresses: addresses.into(),
            scope,
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

/// Which special-use addresses a destination may use. Every scope refuses
/// unspecified, multicast, reserved, documentation and similar classes and the
/// operator's internal endpoints.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddressScope {
    /// Public addresses only.
    PublicOnly,
    /// Public addresses and the private, loopback, link-local and CGNAT
    /// classes, for an operator-configured destination on a private network.
    AllowPrivate,
}

impl AddressScope {
    /// Whether an address is allowed under this scope, before any
    /// internal-endpoint deny-set. For configuration checks without a lookup
    /// policy; every connection is vetted again by the policy.
    pub fn permits(self, ip: IpAddr) -> bool {
        EgressPolicy::forbidden(ip)
            .is_none_or(|class| self == Self::AllowPrivate && is_private_class(class))
    }
}

fn is_private_class(class: &str) -> bool {
    matches!(
        class,
        "private" | "loopback" | "link_local" | "cgnat" | "unique_local" | "site_local"
    )
}

/// A single lookup's vetted addresses. No caller can insert unvetted addresses.
pub struct VettedDestination {
    url: Url,
    addresses: Arc<[SocketAddr]>,
    scope: AddressScope,
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
    scope: AddressScope,
    policy: Arc<EgressPolicy>,
    denied: Arc<HashSet<IpAddr>>,
}

impl Resolve for PolicyResolver {
    fn resolve(&self, name: hyper::client::connect::dns::Name) -> Resolving {
        let policy = self.policy.clone();
        let addresses = self.addresses.clone();
        let denied = self.denied.clone();
        let scope = self.scope;
        let matches = name.as_str() == self.host;
        Box::pin(async move {
            if !matches {
                return Err(
                    Box::new(EgressError::Forbidden) as Box<dyn std::error::Error + Send + Sync>
                );
            }
            let mut vetted = (0..addresses.len())
                .map(move |index| addresses[index])
                .filter(move |address| policy.permits_ip_in(address.ip(), &denied, scope));
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
        let (client, url) = pinned_client(
            &self.policy,
            self.destination,
            &lease.addresses,
            self.timeout,
        )?;
        let mut request = client.post(url).headers(self.headers);
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

/// The one place a client is built for a vetted destination: no proxy, no
/// redirects, `https` only, a two-second connect bound, and a resolver that
/// answers only with the addresses vetted by the destination's single lookup,
/// so the socket connects to a vetted address and TLS verifies the URL's host
/// name. The caller holds the read lease the deny-set was taken from.
fn pinned_client(
    policy: &Arc<EgressPolicy>,
    destination: VettedDestination,
    denied: &Arc<HashSet<IpAddr>>,
    timeout: Duration,
) -> Result<(Client, Url), SendError> {
    if !destination
        .addresses
        .iter()
        .any(|address| policy.permits_ip_in(address.ip(), denied, destination.scope))
    {
        return Err(EgressError::Forbidden.into());
    }
    let host = destination
        .url
        .host_str()
        .ok_or(EgressError::Forbidden)?
        .to_owned();
    #[cfg(not(test))]
    let https_only = true;
    #[cfg(test)]
    let https_only = !(policy.allow_loopback && destination.is_loopback());
    let builder = Client::builder()
        .no_proxy()
        .https_only(https_only)
        .redirect(redirect::Policy::none())
        .connect_timeout(Duration::from_secs(2))
        .timeout(timeout);
    #[cfg(test)]
    let builder = policy
        .roots
        .iter()
        .cloned()
        .fold(builder, |builder, root| builder.add_root_certificate(root));
    let client = builder
        .dns_resolver(Arc::new(PolicyResolver {
            host,
            addresses: destination.addresses,
            scope: destination.scope,
            policy: policy.clone(),
            denied: denied.clone(),
        }))
        .build()?;
    Ok((client, destination.url))
}

/// A failed bounded GET. Transport errors carry no URL.
#[derive(Debug, thiserror::Error)]
pub enum GetError {
    #[error(transparent)]
    Policy(#[from] EgressError),
    #[error("outbound request failed")]
    Transport(reqwest::Error),
    #[error("invalid request header")]
    Header,
    #[error("outbound request timed out")]
    Timeout,
    #[error("response body exceeds the byte cap")]
    BodyTooLarge,
}

impl From<SendError> for GetError {
    fn from(error: SendError) -> Self {
        match error {
            SendError::Policy(error) => Self::Policy(error),
            SendError::Transport(error) => Self::Transport(error.without_url()),
            SendError::HeaderName(_) | SendError::HeaderValue(_) => Self::Header,
            SendError::Timeout => Self::Timeout,
        }
    }
}

/// A bounded GET response. The body is read only for a success status.
pub struct GetResponse {
    pub status: reqwest::StatusCode,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}

/// A target-bound GET request: one attempt, no body, the same pinned,
/// redirect-free, proxy-free client as [`post`]. One deadline covers the
/// connection, the response headers and the whole body, and the body is read
/// chunk by chunk against a hard byte cap, never buffered past it.
pub struct EgressGet {
    policy: Arc<EgressPolicy>,
    destination: VettedDestination,
    timeout: Duration,
    max_body_bytes: usize,
    headers: HeaderMap,
    error: Option<GetError>,
}

/// Prepare a GET to exactly the URL carried by the vetted destination. The
/// response body is refused as soon as it exceeds `max_body_bytes`.
pub fn get(
    policy: Arc<EgressPolicy>,
    destination: VettedDestination,
    timeout: Duration,
    max_body_bytes: usize,
) -> EgressGet {
    EgressGet {
        policy,
        destination,
        timeout,
        max_body_bytes,
        headers: HeaderMap::new(),
        error: None,
    }
}

impl EgressGet {
    /// Set a header without exposing or changing the target URL.
    pub fn header(mut self, name: &'static str, value: impl AsRef<str>) -> Self {
        if self.error.is_none() {
            match (
                HeaderName::from_bytes(name.as_bytes()),
                HeaderValue::from_str(value.as_ref()),
            ) {
                (Ok(name), Ok(value)) => {
                    self.headers.insert(name, value);
                }
                _ => self.error = Some(GetError::Header),
            }
        }
        self
    }

    /// Recheck the bound destination and keep refresh from invalidating it
    /// until the response headers arrive. Cancellation releases the lease.
    pub async fn send(self) -> Result<GetResponse, GetError> {
        let deadline = Instant::now() + self.timeout;
        tokio::time::timeout_at(deadline, self.fetch(deadline))
            .await
            .map_err(|_| GetError::Timeout)?
    }

    async fn fetch(self, deadline: Instant) -> Result<GetResponse, GetError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let cap = self.max_body_bytes;
        let lease = self.policy.send_lease().await?;
        let (client, url) = pinned_client(
            &self.policy,
            self.destination,
            &lease.addresses,
            self.timeout,
        )?;
        let sent = client
            .get(url)
            .headers(self.headers)
            .timeout(deadline.saturating_duration_since(Instant::now()))
            .send()
            .await;
        drop(lease);
        let mut response = sent.map_err(|error| GetError::Transport(error.without_url()))?;
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        if status.is_success() {
            if response
                .content_length()
                .is_some_and(|length| length > cap as u64)
            {
                return Err(GetError::BodyTooLarge);
            }
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| GetError::Transport(error.without_url()))?
            {
                if chunk.len() > cap - body.len() {
                    return Err(GetError::BodyTooLarge);
                }
                body.extend_from_slice(&chunk);
            }
        }
        Ok(GetResponse {
            status,
            headers,
            body,
        })
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

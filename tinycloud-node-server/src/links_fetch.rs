//! Reads one record from the links API for a delivery authorization.
//!
//! The API origin is operator configuration (`share_email.links_origin`); a
//! link never names it. One `GET {origin}/v1/links/{id}`, no authentication,
//! no query, no redirects, no proxy, no retries, no cache. The request goes
//! through [`EgressPolicy`]: the host is resolved once, the answer is vetted,
//! and the socket connects to a vetted address while TLS verifies the
//! configured host name. The body is capped while it streams.

use crate::egress::{self, AddressScope, EgressPolicy, GetError};
use crate::links_read_auth::{ClockSkew, ReadSigner, READ_AUTH_HEADER};
use reqwest::{StatusCode, Url};
use std::{net::IpAddr, sync::Arc, time::Duration};
use time::OffsetDateTime;

/// `MAX_LINK_BODY_BYTES` (contract §3): the one limit on a sealed body, 64 KiB,
/// the same for every link type.
pub const MAX_LINK_BODY_BYTES: usize = 65_536;
/// The `X-Link-Record` header cap. It is checked after the response headers
/// have arrived, not while they stream: reqwest 0.11 has no response-header
/// size setting, so the bound on the header block while it streams is hyper's
/// own header limit, and the one deadline bounds the time. The body cap, in
/// contrast, is enforced chunk by chunk while the body streams.
pub const MAX_LINK_RECORD_HEADER_BYTES: usize = 2_048;
/// One deadline for connecting, the response headers and the whole body.
pub const LINK_TOTAL_TIMEOUT: Duration = Duration::from_secs(5);

/// A link id: 26 characters of `[a-z2-7]`. The only value that is ever placed
/// in the request path.
#[derive(Clone, PartialEq, Eq)]
pub struct LinkId(String);

impl LinkId {
    pub fn parse(value: &str) -> Option<Self> {
        (value.len() == 26
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte)))
        .then(|| Self(value.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The configured API origin: exactly `https://host[:port]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinksOrigin {
    url: Url,
}

/// Answers with a host's addresses at a port, or `None` when it cannot.
pub type HostResolver<'a> = dyn Fn(&str, u16) -> Option<Vec<IpAddr>> + 'a;

impl LinksOrigin {
    /// Parse the configured value. It must be the canonical origin string and
    /// nothing else: `https`, a host, an optional non-default port, and no
    /// userinfo, path, query or fragment.
    pub fn parse(value: &str) -> Result<Self, &'static str> {
        const INVALID: &str = "share email links_origin must be exactly https://host[:port]";
        let url = Url::parse(value).map_err(|_| INVALID)?;
        if url.scheme() != "https"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.port() == Some(0)
            || url
                .host_str()
                .is_none_or(|host| host.is_empty() || host.ends_with('.'))
            || url.origin().ascii_serialization() != value
        {
            return Err(INVALID);
        }
        Ok(Self { url })
    }

    /// Parse and check the host against the address scope without any
    /// lookup: an IP literal in a refused class and `localhost` names fail.
    /// `lookup` answers with the host's addresses (`None` when it cannot);
    /// when given, every answer must be permitted. A failed lookup is not an
    /// error here: the fetch vets the addresses again on every request.
    pub fn validate(
        value: &str,
        allow_private: bool,
        lookup: Option<&HostResolver<'_>>,
    ) -> Result<Self, &'static str> {
        const PRIVATE: &str = "share email links_origin is a private, loopback, link-local or CGNAT address; set links_origin_allow_private to use one";
        let origin = Self::parse(value)?;
        let scope = if allow_private {
            AddressScope::AllowPrivate
        } else {
            AddressScope::PublicOnly
        };
        let host = origin.url.host_str().ok_or(PRIVATE)?;
        if let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() {
            if !scope.permits(ip) {
                return Err(PRIVATE);
            }
        } else {
            if !allow_private && (host == "localhost" || host.ends_with(".localhost")) {
                return Err(PRIVATE);
            }
            if let Some(lookup) = lookup {
                let port = origin.url.port_or_known_default().unwrap_or(443);
                if let Some(addresses) = lookup(host, port) {
                    if addresses.iter().any(|ip| !scope.permits(*ip)) {
                        return Err(PRIVATE);
                    }
                }
            }
        }
        Ok(origin)
    }

    fn record_url(&self, id: &LinkId) -> Option<Url> {
        self.url.join(&format!("v1/links/{}", id.as_str())).ok()
    }

    /// The API instance as the contract writes its audience: the origin,
    /// `https://host[:port]`.
    pub(crate) fn audience(&self) -> String {
        self.url.origin().ascii_serialization()
    }
}

/// What a successful read returns: the raw `X-Link-Record` header value and
/// the sealed body bytes.
pub struct FetchedLink {
    pub record_header: String,
    pub body: Vec<u8>,
}

/// Why a read produced no record. None carries the id, the URL or any text
/// from the API.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkFetchError {
    /// The API answered `404`: unknown, expired, deleted or already read.
    NotFound,
    /// The API could not be used: connection failure, timeout, `429`, `5xx`,
    /// any other status, or a response over a byte cap. Fail closed.
    Unavailable,
    /// A `200` without exactly one readable `X-Link-Record` header.
    RecordHeaderInvalid,
}

#[async_trait::async_trait]
pub trait LinkRecordFetcher: Send + Sync {
    async fn fetch(&self, id: &LinkId) -> Result<FetchedLink, LinkFetchError>;
}

/// The production fetcher: [`egress::get`] against the configured origin.
pub struct ApiLinkFetcher {
    policy: Arc<EgressPolicy>,
    origin: LinksOrigin,
    scope: AddressScope,
    total_timeout: Duration,
    /// Signs each read with the node identity key when present.
    signer: Option<ReadSigner>,
    skew: ClockSkew,
    clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
}

impl ApiLinkFetcher {
    pub fn new(policy: Arc<EgressPolicy>, origin: LinksOrigin, allow_private: bool) -> Self {
        Self {
            policy,
            origin,
            scope: if allow_private {
                AddressScope::AllowPrivate
            } else {
                AddressScope::PublicOnly
            },
            total_timeout: LINK_TOTAL_TIMEOUT,
            signer: None,
            skew: ClockSkew::default(),
            clock: Arc::new(OffsetDateTime::now_utc),
        }
    }

    /// Sign every read with the node identity key (contract section 4.11).
    pub fn with_read_signer(mut self, signer: ReadSigner) -> Self {
        self.signer = Some(signer);
        self
    }

    #[cfg(test)]
    pub(crate) fn with_total_timeout(mut self, timeout: Duration) -> Self {
        self.total_timeout = timeout;
        self
    }

    #[cfg(test)]
    pub(crate) fn with_clock(
        mut self,
        clock: Arc<dyn Fn() -> OffsetDateTime + Send + Sync>,
    ) -> Self {
        self.clock = clock;
        self
    }

    /// The `TinyCloud-Read-Auth` value for a `GET` of `url`, only when a
    /// signer is set and `url` is at the configured origin (scheme, host and
    /// port) over `https`. Any other URL gets none.
    pub(crate) fn read_auth_value(&self, url: &Url) -> Option<String> {
        let signer = self.signer.as_ref()?;
        let configured = self.origin.url.origin();
        if url.origin() != configured || url.scheme() != "https" {
            return None;
        }
        Some(signer.header_value(&self.origin.audience(), url.path(), (self.clock)()))
    }
}

#[async_trait::async_trait]
impl LinkRecordFetcher for ApiLinkFetcher {
    async fn fetch(&self, id: &LinkId) -> Result<FetchedLink, LinkFetchError> {
        let url = self
            .origin
            .record_url(id)
            .ok_or(LinkFetchError::Unavailable)?;
        let destination = self
            .policy
            .resolve_url_scoped(&url, self.scope)
            .await
            .map_err(|_| LinkFetchError::Unavailable)?;
        let mut request = egress::get(
            self.policy.clone(),
            destination,
            self.total_timeout,
            MAX_LINK_BODY_BYTES,
        )
        .header("accept", "application/octet-stream")
        .header("accept-encoding", "identity");
        // The signature goes only to the configured origin; no redirect is
        // followed, so a response cannot move the request elsewhere.
        if let Some(value) = self.read_auth_value(&url) {
            request = request.header(READ_AUTH_HEADER, value);
        }
        let response = request.send().await.map_err(|error| match error {
            GetError::Policy(_)
            | GetError::Transport(_)
            | GetError::Header
            | GetError::Timeout
            | GetError::BodyTooLarge => LinkFetchError::Unavailable,
        })?;
        // Any response carries the API's clock in `Date`.
        self.skew.observe(
            response
                .headers
                .get("date")
                .and_then(|value| value.to_str().ok()),
            (self.clock)(),
            std::time::Instant::now(),
        );
        match response.status {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Err(LinkFetchError::NotFound),
            _ => return Err(LinkFetchError::Unavailable),
        }
        let mut values = response.headers.get_all("x-link-record").iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return Err(LinkFetchError::RecordHeaderInvalid);
        };
        if value.len() > MAX_LINK_RECORD_HEADER_BYTES {
            return Err(LinkFetchError::Unavailable);
        }
        let record_header = value
            .to_str()
            .map_err(|_| LinkFetchError::RecordHeaderInvalid)?
            .to_owned();
        Ok(FetchedLink {
            record_header,
            body: response.body,
        })
    }
}

#[cfg(test)]
mod tests;

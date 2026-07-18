//! `tinycloud node link` — LAN HTTPS via the tinycloud.link name+cert service.
//!
//! Overview
//!
//! When link is enabled, the node claims a name at `<name>.local.tinycloud.link`
//! that resolves to its private LAN IPs and requests a real TLS cert for that
//! FQDN from the link service. `serve` then starts a small TLS terminator
//! bound to a LAN address that proxies raw bytes to the loopback public API
//! port, so LAN clients get a browser-trusted HTTPS URL without touching the
//! existing localhost-only Rocket listener.
//!
//! Trust boundary
//!
//! `link enable`/`link renew`/`link disable` link the KeyProvider library
//! in-process the same way `node key backup` does (see
//! `docs/specs/node-control-plane-v1.md` §3.7). Secret key material stays in
//! memory only long enough to derive the node's `did:key` and Ed25519 signing
//! keypair to sign the canonical service payloads; it is never sent over the
//! control API and never written unencrypted.
pub mod client;
pub mod csr;
pub mod ip;
pub mod payload;
pub mod state;

pub mod commands;
pub mod proxy;

/// Domain the link service issues certs under.
pub const DOMAIN_SUFFIX: &str = "local.tinycloud.link";

/// Default service base URL. Overridable per-node via CLI or a link config
/// field.
pub const DEFAULT_SERVICE_URL: &str = "https://api.tinycloud.link";

/// Default bind address for the LAN TLS terminator.
pub const DEFAULT_BIND_ADDR: &str = "0.0.0.0:8443";

/// Number of days before cert expiry at which the auto-renew task will renew.
pub const RENEW_WINDOW_DAYS: i64 = 30;

/// Fatal errors returned by the link module. Errors surface up to the CLI /
/// serve loop; there is no graceful fallback path.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    #[error("failed to sign canonical payload: {0}")]
    Signing(String),

    #[error("failed to enumerate LAN interfaces: {0}")]
    Interface(String),

    #[error("no private-range LAN IPs were found on this host")]
    NoLanIps,

    #[error("failed to generate CSR: {0}")]
    Csr(String),

    #[error("link service HTTP call failed: {0}")]
    Http(String),

    #[error("name `{name}` is already claimed by a different subject at the link service")]
    NameConflict { name: String, body: String },

    #[error("link service rate-limited the request{retry_after:?}")]
    RateLimited {
        retry_after: Option<String>,
        body: String,
    },

    #[error("link service returned unexpected status {status}: {body}")]
    UnexpectedStatus { status: u16, body: String },
}

/// The client-facing FQDN a link-managed node is reachable at over LAN.
pub fn local_url(name: &str, bind_port: u16) -> String {
    let host = csr::fqdn_for_name(name);
    if bind_port == 443 {
        format!("https://{host}")
    } else {
        format!("https://{host}:{bind_port}")
    }
}

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

    #[error(
        "link service rejected `{name}` for a stale sequence — local state has fallen behind the service's record: {body}"
    )]
    StaleSequence { name: String, body: String },

    #[error(
        "link service rate-limited the request{}",
        retry_after
            .as_deref()
            .map(|value| format!(" (retry after {value}s)"))
            .unwrap_or_default()
    )]
    RateLimited {
        retry_after: Option<String>,
        body: String,
    },

    #[error("link service returned unexpected status {status}: {body}")]
    UnexpectedStatus { status: u16, body: String },

    #[error("{0}")]
    InvalidName(String),
}

/// Client-side mirror of `validateNameLabel` in
/// `tinycloud-link/src/names.ts`: lowercases and checks the DNS-label shape
/// the service enforces. Catching this locally avoids two failure modes: a
/// wasted round trip for an obviously-bad name, and a mixed-case name
/// producing a CSR whose CN/SAN (built from the as-typed name) don't match
/// what the service actually stores (it lowercases before persisting) —
/// which `assertCsrMatchesDomain` in `names.ts` then rejects.
///
/// This intentionally does not port the service's reserved-name list; an
/// attempt to claim a reserved name still fails, just remotely instead of
/// locally.
pub fn normalize_name_label(name: &str) -> Result<String, LinkError> {
    let lower = name.to_ascii_lowercase();
    if lower.len() < 3 || lower.len() > 32 {
        return Err(LinkError::InvalidName(format!(
            "name `{name}` must be 3-32 characters"
        )));
    }
    let bytes = lower.as_bytes();
    let is_label_char = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
    let valid_shape = bytes.iter().all(|&b| is_label_char(b))
        && bytes.first().is_some_and(|&b| b != b'-')
        && bytes.last().is_some_and(|&b| b != b'-');
    if !valid_shape {
        return Err(LinkError::InvalidName(format!(
            "name `{name}` must be a dns-safe label (lowercase letters, digits, hyphens; cannot start or end with a hyphen)"
        )));
    }
    if lower.starts_with("xn--") {
        return Err(LinkError::InvalidName(format!(
            "name `{name}` must not be a punycode (\"xn--\") label"
        )));
    }
    Ok(lower)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rate_limited_display_includes_retry_after_cleanly() {
        let err = LinkError::RateLimited {
            retry_after: Some("120".to_string()),
            body: "slow down".to_string(),
        };
        assert_eq!(
            err.to_string(),
            "link service rate-limited the request (retry after 120s)"
        );
    }

    #[test]
    fn rate_limited_display_omits_suffix_when_retry_after_is_absent() {
        let err = LinkError::RateLimited {
            retry_after: None,
            body: "slow down".to_string(),
        };
        assert_eq!(err.to_string(), "link service rate-limited the request");
    }

    #[test]
    fn normalize_name_label_lowercases_valid_names() {
        assert_eq!(normalize_name_label("MyNode").unwrap(), "mynode");
        assert_eq!(normalize_name_label("living-room").unwrap(), "living-room");
    }

    #[test]
    fn normalize_name_label_rejects_bad_length() {
        assert!(normalize_name_label("ab").is_err());
        assert!(normalize_name_label(&"a".repeat(33)).is_err());
    }

    #[test]
    fn normalize_name_label_rejects_bad_shape() {
        assert!(normalize_name_label("-leading").is_err());
        assert!(normalize_name_label("trailing-").is_err());
        assert!(normalize_name_label("has_underscore").is_err());
        assert!(normalize_name_label("has a space").is_err());
    }

    #[test]
    fn normalize_name_label_rejects_punycode_prefix() {
        assert!(normalize_name_label("xn--abc").is_err());
    }
}

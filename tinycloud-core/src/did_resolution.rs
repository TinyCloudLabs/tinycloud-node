//! Node UCAN issuer resolution policy. DID syntax and identity comparisons are unaffected.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    env,
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex, OnceLock,
    },
    time::{Duration, Instant},
};
use tinycloud_auth::share_email_evidence;
use tinycloud_auth::ssi::{
    dids::{
        resolution::{self, Options, Output},
        AnyDidMethod, DIDResolver, DID, DIDURL,
    },
    jwk::{Algorithm, Params, JWK},
    ucan::{Ucan, UcanRevocation},
};

/// The only issuer DID methods the node resolves. Each derives verification material without
/// network access. Every other method is refused before any lookup, whatever the configuration.
/// `did:web` credential issuers are configured in `tinycloud-node-server/src/issuer_set.rs` and
/// are not resolved through this module.
pub const ALLOWED_DID_METHODS: &[&str] = &["key", "pkh", "jwk"];
/// `did:key` is limited to Ed25519: base58btc multibase `z` over the `0xed 0x01` multicodec.
const ED25519_DID_KEY_PREFIX: &str = "z6Mk";
/// Length of an Ed25519 `did:key` identifier, checked before any decoding.
const ED25519_DID_KEY_ID_LEN: usize = 48;
/// `did:pkh` is limited to the EVM (`eip155`) namespace.
const PKH_EVM_NAMESPACE_PREFIX: &str = "eip155:";
/// Longest `did:pkh:eip155` identifier: namespace, u64 chain id (<= 20 digits), `0x`, 40 hex.
const PKH_EVM_ID_MAX_LEN: usize = 70;
static REFUSED_TOTAL: AtomicU64 = AtomicU64::new(0);
static REFUSAL_OBSERVER: OnceLock<fn(&str, &str)> = OnceLock::new();

/// Process-lifetime refusal count. Public status reads never acquire a lock.
pub fn refused_total() -> u64 {
    REFUSED_TOTAL.load(Ordering::Relaxed)
}

/// Register the server's metrics hook. Refusals are observed even with telemetry disabled.
pub fn set_refusal_observer(observer: fn(&str, &str)) {
    let _ = REFUSAL_OBSERVER.set(observer);
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum UcanVerifyError {
    #[error("did_method_disabled: DID method `{method}` is not resolvable on this node")]
    MethodDisabled { method: String },
    #[error("did_url_query_rejected: issuer DID URL must not carry a query")]
    QueryRejected,
    #[error("did_resolution_timeout")]
    Timeout,
    #[error("invalid signature")]
    Invalid,
}

/// Defence in depth for callers resolving a DID directly. `inner` is consulted only after
/// the method and namespace checks pass.
pub struct NodeDidResolver<R> {
    inner: R,
}
impl NodeDidResolver<AnyDidMethod> {
    pub fn current() -> Self {
        Self {
            inner: AnyDidMethod::default(),
        }
    }
}
impl<R> NodeDidResolver<R> {
    /// Wrap `inner` as the lookup backend. Refusal runs before `inner` is consulted.
    pub fn new(inner: R) -> Self {
        Self { inner }
    }
    fn check(&self, issuer: &DIDURL) -> Result<(), UcanVerifyError> {
        if issuer.query().is_some() {
            refused(issuer.did(), "query_rejected");
            return Err(UcanVerifyError::QueryRejected);
        }
        check_method(issuer.did())
    }
}
impl<R: DIDResolver> DIDResolver for NodeDidResolver<R> {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<Output<Vec<u8>>, resolution::Error> {
        check_method(did).map_err(resolution::Error::internal)?;
        self.inner.resolve_representation(did, options).await
    }
}

/// Admit a DID only when its method is allow-listed and its key type or namespace is allowed.
/// Runs before any lookup.
fn check_method(did: &DID) -> Result<(), UcanVerifyError> {
    let method = did.method_name();
    if !ALLOWED_DID_METHODS.contains(&method) || !namespace_allowed(did) {
        refused(did, "method_disabled");
        return Err(UcanVerifyError::MethodDisabled {
            method: method.to_owned(),
        });
    }
    Ok(())
}

/// Admit an identifier only when its key type or namespace is allowed. Length bounds run
/// before any decoding.
fn namespace_allowed(did: &DID) -> bool {
    let id = did.method_specific_id();
    match did.method_name() {
        "key" => {
            id.len() == ED25519_DID_KEY_ID_LEN
                && id.starts_with(ED25519_DID_KEY_PREFIX)
                && share_email_evidence::did_key_public_key(did.as_str()).is_ok()
        }
        "pkh" => id.len() <= PKH_EVM_ID_MAX_LEN && id.starts_with(PKH_EVM_NAMESPACE_PREFIX),
        "jwk" => jwk_is_ed25519(id),
        _ => false,
    }
}

/// Longest `did:jwk` identifier that can carry a canonical Ed25519 JWK:
/// `{"crv":"Ed25519","kty":"OKP","x":"<43 chars>"}` is 79 bytes, which is
/// 106 unpadded base64url characters. Longer identifiers are refused before decoding.
const ED25519_DID_JWK_ID_LEN_MAX: usize = 106;

#[cfg(test)]
thread_local! {
    static JWK_DECODE_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Decodes a `did:jwk` identifier as the SSI resolver does (unpadded base64url, then JWK JSON).
/// Admits only an OKP `Ed25519` key, the same key type as `did:key`.
fn jwk_is_ed25519(id: &str) -> bool {
    if id.len() > ED25519_DID_JWK_ID_LEN_MAX {
        return false;
    }
    #[cfg(test)]
    JWK_DECODE_ATTEMPTS.with(|c| c.set(c.get() + 1));
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(id) else {
        return false;
    };
    match serde_json::from_slice::<JWK>(&bytes) {
        Ok(jwk) => matches!(
            &jwk.params,
            Params::OKP(okp) if okp.curve == "Ed25519" && okp.public_key.0.len() == 32
        ),
        Err(_) => false,
    }
}

/// The single production entry point for node UCAN signature verification.
pub async fn verify_ucan_signature<F, A>(ucan: &Ucan<F, A>) -> Result<(), UcanVerifyError>
where
    F: for<'de> Deserialize<'de> + Serialize,
    A: for<'de> Deserialize<'de> + Serialize,
{
    verify_ucan_signature_with(ucan, AnyDidMethod::default()).await
}

/// Verify a UCAN against an explicit lookup backend. Refusal runs before `inner` is consulted.
pub async fn verify_ucan_signature_with<F, A, R>(
    ucan: &Ucan<F, A>,
    inner: R,
) -> Result<(), UcanVerifyError>
where
    F: for<'de> Deserialize<'de> + Serialize,
    A: for<'de> Deserialize<'de> + Serialize,
    R: DIDResolver,
{
    let resolver = NodeDidResolver { inner };
    resolver.check(&ucan.payload().issuer)?;
    tokio::time::timeout(did_resolution_timeout(), ucan.verify_signature(&resolver))
        .await
        .map_err(|_| UcanVerifyError::Timeout)?
        .map_err(|_| UcanVerifyError::Invalid)
}

/// Equivalent entry point for the SSI revocation format (node revocations use UCANs).
pub async fn verify_ucan_revocation_signature(
    revocation: &UcanRevocation,
    algorithm: Algorithm,
    jwk: Option<&JWK>,
) -> Result<(), UcanVerifyError> {
    verify_ucan_revocation_signature_with(revocation, algorithm, jwk, AnyDidMethod::default()).await
}

/// Revocation counterpart of [`verify_ucan_signature_with`].
pub async fn verify_ucan_revocation_signature_with<R: DIDResolver>(
    revocation: &UcanRevocation,
    algorithm: Algorithm,
    jwk: Option<&JWK>,
    inner: R,
) -> Result<(), UcanVerifyError> {
    let resolver = NodeDidResolver { inner };
    resolver.check(&revocation.issuer)?;
    tokio::time::timeout(
        did_resolution_timeout(),
        revocation.verify_signature(&resolver, algorithm, jwk),
    )
    .await
    .map_err(|_| UcanVerifyError::Timeout)?
    .map_err(|_| UcanVerifyError::Invalid)
}

const WARN_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
const MAX_WARN_HOSTS: usize = 1024;
#[derive(Default)]
struct RefusalLimiter {
    hosts: HashMap<(String, String), Instant>,
    emitted: VecDeque<Instant>,
    suppressed: u64,
}
impl RefusalLimiter {
    fn observe(&mut self, method: &str, host: &str, now: Instant) -> Option<u64> {
        while self
            .emitted
            .front()
            .is_some_and(|last| now.duration_since(*last) >= WARN_WINDOW)
        {
            self.emitted.pop_front();
        }
        let key = (method.to_owned(), host.to_owned());
        if self.emitted.len() >= 10
            || self
                .hosts
                .get(&key)
                .is_some_and(|last| now.duration_since(*last) < WARN_WINDOW)
        {
            self.suppressed = self.suppressed.saturating_add(1);
            return None;
        }
        if self.hosts.len() >= MAX_WARN_HOSTS {
            // Preserve the current minute to keep the per-host limit even at capacity.
            self.hosts
                .retain(|_, last| now.duration_since(*last) < WARN_WINDOW);
        }
        self.hosts.insert(key, now);
        self.emitted.push_back(now);
        Some(std::mem::take(&mut self.suppressed))
    }
}

fn sanitized_host(did: &DID) -> String {
    let id = did.method_specific_id();
    let host = match did.method_name() {
        "web" => id
            .split(':')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase(),
        "tz" => id
            .split(':')
            .next()
            .filter(|_| id.contains(':'))
            .unwrap_or("mainnet")
            .to_ascii_lowercase(),
        _ => return String::new(),
    };
    host.split("%3a")
        .next()
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-'))
        .take(253)
        .collect()
}

fn refused(did: &DID, reason: &str) {
    REFUSED_TOTAL.fetch_add(1, Ordering::Relaxed);
    // Unknown method names are caller-controlled: keep metric cardinality and logs bounded.
    let method = match did.method_name() {
        "key" | "pkh" | "jwk" | "web" | "tz" | "ion" | "ethr" => did.method_name(),
        _ => "unknown",
    };
    if let Some(observer) = REFUSAL_OBSERVER.get() {
        observer(method, reason);
    }
    static LIMITER: OnceLock<Mutex<RefusalLimiter>> = OnceLock::new();
    let host = sanitized_host(did);
    let suppressed = LIMITER
        .get_or_init(Mutex::default)
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .observe(method, &host, Instant::now());
    if let Some(suppressed) = suppressed {
        tracing::warn!(target: "tinycloud::did_resolution", event = "did_resolution_refused", method, host, reason, suppressed);
    }
}

pub const DID_RESOLUTION_TIMEOUT_ENV: &str = "TINYCLOUD_DID_RESOLUTION_TIMEOUT_MS";
const DEFAULT_DID_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(3);

pub fn did_resolution_timeout() -> Duration {
    env::var(DID_RESOLUTION_TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(Duration::from_millis)
        .unwrap_or(DEFAULT_DID_RESOLUTION_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    #[test]
    fn refusal_limiter_counts_suppression_and_bounds_global_warnings() {
        let mut limiter = RefusalLimiter::default();
        let counter = prometheus::IntCounter::new("refusals", "test").unwrap();
        let now = Instant::now();
        let mut emitted = 0;
        for _ in 0..100 {
            counter.inc();
            emitted += usize::from(limiter.observe("web", "localhost", now).is_some());
        }
        assert_eq!(counter.get(), 100);
        assert_eq!(emitted, 1);
        assert_eq!(
            limiter.observe("web", "localhost", now + WARN_WINDOW),
            Some(99)
        );
        for n in 0..9 {
            assert!(limiter
                .observe("web", &n.to_string(), now + WARN_WINDOW)
                .is_some());
        }
        assert_eq!(limiter.observe("tz", "mainnet", now + WARN_WINDOW), None);
        assert_eq!(
            limiter.observe("tz", "mainnet", now + WARN_WINDOW * 2),
            Some(1)
        );
        assert!(limiter.hosts.len() <= MAX_WARN_HOSTS);
    }

    #[test]
    fn refusal_hosts_exclude_ports_paths_and_query_values() {
        for (input, expected) in [
            ("did:web:EXAMPLE.com%3A1234:private:path", "example.com"),
            ("did:web:localhost%3a1234:private", "localhost"),
            ("did:web:x%2Fsecret:private", "x2fsecret"),
            ("did:tz:mainnet:tz1address", "mainnet"),
            ("did:tz:tz1address", "mainnet"),
            ("did:key:private", ""),
        ] {
            let did = DID::new(input.as_bytes()).unwrap();
            assert_eq!(sanitized_host(did), expected);
        }
        let did = format!("did:web:{}:private", "a".repeat(300));
        assert_eq!(sanitized_host(DID::new(did.as_bytes()).unwrap()).len(), 253);
    }

    fn admitted(did: &str) -> bool {
        namespace_allowed(DID::new(did.as_bytes()).unwrap())
    }

    #[test]
    fn did_key_is_admitted_only_at_the_ed25519_identifier_length() {
        let key = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";
        assert_eq!(key.len(), ED25519_DID_KEY_ID_LEN);
        assert!(admitted(&format!("did:key:{key}")));
        assert!(!admitted(&format!("did:key:{}", &key[..47])));
        assert!(!admitted(&format!("did:key:{key}1")));
        // Right length and prefix, but not an Ed25519 multicodec encoding.
        assert!(!admitted(&format!("did:key:z6Mk{}", "1".repeat(44))));
        // Oversized: refused by length before any base58 decode.
        assert!(!admitted(&format!("did:key:z6Mk{}", "1".repeat(65_532))));
    }

    /// Canonical `did:jwk` for an OKP Ed25519 key whose `x` is `key_len` bytes.
    fn jwk_did(key_len: usize) -> String {
        let x = URL_SAFE_NO_PAD.encode(vec![7u8; key_len]);
        let json = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
        format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(json))
    }

    #[test]
    fn did_jwk_identifier_is_capped_at_the_canonical_ed25519_length() {
        let canonical = jwk_did(32);
        let id = canonical.strip_prefix("did:jwk:").unwrap();
        assert_eq!(id.len(), ED25519_DID_JWK_ID_LEN_MAX);
        assert!(admitted(&canonical));
        // One extra space: still valid JSON for the same key, but 107 characters.
        let json = format!(
            r#"{{"crv":"Ed25519", "kty":"OKP","x":"{}"}}"#,
            URL_SAFE_NO_PAD.encode([7u8; 32])
        );
        let padded = format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(json));
        assert_eq!(padded.len() - "did:jwk:".len(), 107);
        assert!(!admitted(&padded));
    }

    #[test]
    fn did_jwk_is_admitted_only_with_a_32_byte_ed25519_key() {
        assert!(admitted(&jwk_did(32)));
        // Shorter key: fits the cap, so only the 32-byte check refuses it.
        assert!(!admitted(&jwk_did(31)));
        assert!(!admitted(&jwk_did(0)));
    }

    #[test]
    fn oversized_did_jwk_is_refused_without_decoding() {
        let before = JWK_DECODE_ATTEMPTS.with(std::cell::Cell::get);
        let oversized = format!("did:jwk:{}", "A".repeat(400_000));
        assert!(!admitted(&oversized));
        assert_eq!(JWK_DECODE_ATTEMPTS.with(std::cell::Cell::get), before);
        // Positive control: a canonical key does reach the decoder.
        assert!(admitted(&jwk_did(32)));
        assert_eq!(JWK_DECODE_ATTEMPTS.with(std::cell::Cell::get), before + 1);
    }

    #[test]
    fn did_pkh_is_admitted_only_as_bounded_evm() {
        assert!(admitted(
            "did:pkh:eip155:1:0x0000000000000000000000000000000000000001"
        ));
        // Longest valid identifier: a 20-digit chain id.
        assert!(admitted(&format!(
            "did:pkh:eip155:{}:0x{}",
            "1".repeat(20),
            "0".repeat(40)
        )));
        assert!(!admitted(&format!(
            "did:pkh:eip155:{}:0x{}",
            "1".repeat(21),
            "0".repeat(40)
        )));
        assert!(!admitted("did:pkh:solana:local:abc"));
        assert!(!admitted(&format!(
            "did:pkh:eip155:1:{}",
            "0".repeat(65_536)
        )));
    }

    #[test]
    fn did_jwk_is_admitted_only_as_ed25519_okp() {
        use base64::Engine as _;
        let jwk_did = |json: &str| format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(json));
        assert!(admitted(&jwk_did(
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
        )));
        assert!(!admitted(&jwk_did(
            r#"{"kty":"OKP","crv":"X25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}"#
        )));
        assert!(!admitted(&jwk_did(
            r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#
        )));
    }

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn restore_env(previous: Option<std::ffi::OsString>) {
        match previous {
            Some(value) => env::set_var(DID_RESOLUTION_TIMEOUT_ENV, value),
            None => env::remove_var(DID_RESOLUTION_TIMEOUT_ENV),
        }
    }

    #[test]
    fn uses_default_timeout_when_env_is_missing() {
        let _guard = env_lock().lock().unwrap();
        let previous = env::var_os(DID_RESOLUTION_TIMEOUT_ENV);

        env::remove_var(DID_RESOLUTION_TIMEOUT_ENV);
        assert_eq!(did_resolution_timeout(), Duration::from_secs(3));

        restore_env(previous);
    }

    #[test]
    fn uses_timeout_from_env_milliseconds() {
        let _guard = env_lock().lock().unwrap();
        let previous = env::var_os(DID_RESOLUTION_TIMEOUT_ENV);

        env::set_var(DID_RESOLUTION_TIMEOUT_ENV, "1250");
        assert_eq!(did_resolution_timeout(), Duration::from_millis(1250));

        restore_env(previous);
    }

    #[test]
    fn invalid_env_uses_default_timeout() {
        let _guard = env_lock().lock().unwrap();
        let previous = env::var_os(DID_RESOLUTION_TIMEOUT_ENV);

        env::set_var(DID_RESOLUTION_TIMEOUT_ENV, "invalid");
        assert_eq!(did_resolution_timeout(), Duration::from_secs(3));

        env::set_var(DID_RESOLUTION_TIMEOUT_ENV, "0");
        assert_eq!(did_resolution_timeout(), Duration::from_secs(3));

        restore_env(previous);
    }
}

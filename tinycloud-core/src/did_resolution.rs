//! Node UCAN issuer resolution policy. DID syntax and identity comparisons are unaffected.
//!
//! The node verifies a signature only when it can derive the signer's key offline. A DID is
//! accepted when its method is `key`, `pkh` or `jwk` and its identifier names a key type or
//! account namespace the node verifies; every other DID is refused before any resolution
//! (TC-1500). No setting enables another method.
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
use tinycloud_auth::ssi::{
    dids::{
        resolution::{self, Options, Output},
        AnyDidMethod, DIDResolver, DID, DIDURL,
    },
    jwk::{Algorithm, Params, JWK},
    multicodec::MultiEncoded,
    ucan::{Ucan, UcanRevocation},
};

/// The DID methods whose verification material the node derives without network access.
pub const OFFLINE_DID_METHODS: &[&str] = &["key", "pkh", "jwk"];
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
    #[error("did_unverifiable: this `did:{method}` identifier is malformed or names a key type this node cannot verify")]
    Unverifiable { method: String },
    #[error("did_url_query_rejected: issuer DID URL must not carry a query")]
    QueryRejected,
    #[error("did_resolution_timeout")]
    Timeout,
    #[error("invalid signature")]
    Invalid,
}

/// Why [`check_verifiable`] refuses a DID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unverifiable {
    /// The method is not one of [`OFFLINE_DID_METHODS`].
    MethodDisabled,
    /// The method is offline, but the identifier is malformed, too long, or names a key type
    /// or account namespace the node cannot verify.
    Identifier,
}

/// Whether the node can verify a signature by `did` offline:
///
/// - `did:key`: base58btc multibase over an Ed25519 (`0xed 0x01`), secp256k1 (`0xe7 0x01`) or
///   P-256 (`0x80 0x24`) public key, compressed for the two elliptic curves. The identifier
///   length is checked before the base58 decode.
/// - `did:jwk`: an Ed25519 OKP key or a secp256k1 or P-256 EC key, public only, in an identifier
///   of at most [`MAX_DID_JWK_ID_LEN`] characters, checked before decoding.
/// - `did:pkh`: CAIP-10 accounts in the `eip155`, `solana` and `bip122` (Bitcoin and Dogecoin
///   mainnet) namespaces.
///
/// Keys are checked to be valid points on their curve. Runs no lookup and allocates at most a
/// bounded decode.
pub fn check_verifiable(did: &DID) -> Result<(), Unverifiable> {
    let id = did.method_specific_id();
    let verifiable = match did.method_name() {
        "key" => did_key_verifiable(id),
        "jwk" => did_jwk_verifiable(id),
        "pkh" => did_pkh_verifiable(id),
        _ => return Err(Unverifiable::MethodDisabled),
    };
    if verifiable {
        Ok(())
    } else {
        Err(Unverifiable::Identifier)
    }
}

/// Characters in a `did:key` identifier: 48 for Ed25519 (34 bytes), 49 for a compressed
/// secp256k1 or P-256 key (35 bytes).
const DID_KEY_ID_LENS: [usize; 2] = [48, 49];

fn did_key_verifiable(id: &str) -> bool {
    // M1: base58 decoding is quadratic, so the length is checked first.
    if !DID_KEY_ID_LENS.contains(&id.len()) || !id.starts_with('z') {
        return false;
    }
    #[cfg(test)]
    tests::count_decode();
    let Ok((_, bytes)) = tinycloud_auth::ipld_core::cid::multibase::decode(id) else {
        return false;
    };
    let supported = match bytes.as_slice() {
        [0xed, 0x01, key @ ..] => key.len() == 32,
        [0xe7, 0x01, key @ ..] | [0x80, 0x24, key @ ..] => key.len() == 33,
        _ => false,
    };
    supported
        && MultiEncoded::new(&bytes)
            .ok()
            .is_some_and(|encoded| JWK::from_multicodec(encoded).is_ok())
}

/// Longest `did:jwk` identifier decoded: 192 bytes of JWK JSON. A public EC key with `crv`,
/// `kty`, `x` and `y` is 160 characters; the rest leaves room for short members such as `alg`.
pub const MAX_DID_JWK_ID_LEN: usize = 256;

fn did_jwk_verifiable(id: &str) -> bool {
    // N1: the identifier is bounded before decoding, so no member can be oversized.
    if id.len() > MAX_DID_JWK_ID_LEN {
        return false;
    }
    #[cfg(test)]
    tests::count_decode();
    let Ok(bytes) = URL_SAFE_NO_PAD.decode(id) else {
        return false;
    };
    let Ok(jwk) = serde_json::from_slice::<JWK>(&bytes) else {
        return false;
    };
    let supported = match &jwk.params {
        Params::OKP(okp) => okp.curve == "Ed25519" && okp.private_key.is_none(),
        Params::EC(ec) => {
            matches!(ec.curve.as_deref(), Some("secp256k1" | "P-256"))
                && ec.ecc_private_key.is_none()
        }
        _ => false,
    };
    // The multicodec round trip checks the key is a valid point of its curve.
    supported
        && jwk
            .to_multicodec()
            .ok()
            .is_some_and(|encoded| JWK::from_multicodec(&encoded).is_ok())
}

/// Longest `did:pkh` identifier parsed: namespace, a CAIP-2 reference of at most 32 characters
/// and an address.
const MAX_DID_PKH_ID_LEN: usize = 96;
const BIP122_BITCOIN_MAINNET: &str = "000000000019d6689c085ae165831e93";
const BIP122_DOGECOIN_MAINNET: &str = "1a91e3dace36e2be3bf030a65679fe82";

fn did_pkh_verifiable(id: &str) -> bool {
    if id.len() > MAX_DID_PKH_ID_LEN {
        return false;
    }
    #[cfg(test)]
    tests::count_decode();
    let mut parts = id.split(':');
    let (Some(namespace), Some(reference), Some(address), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if reference.is_empty()
        || reference.len() > 32
        || !reference
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return false;
    }
    match namespace {
        "eip155" => {
            reference.bytes().all(|b| b.is_ascii_digit())
                && address.len() == 42
                && address
                    .strip_prefix("0x")
                    .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
        }
        "solana" => (32..=44).contains(&address.len()) && base58_decoded_len(address) == Some(32),
        "bip122" => {
            matches!(reference, BIP122_BITCOIN_MAINNET | BIP122_DOGECOIN_MAINNET)
                && (25..=35).contains(&address.len())
                && base58_decoded_len(address).is_some()
        }
        _ => false,
    }
}

fn base58_decoded_len(value: &str) -> Option<usize> {
    tinycloud_auth::ipld_core::cid::multibase::Base::Base58Btc
        .decode(value)
        .ok()
        .map(|bytes| bytes.len())
}

/// Refuse a DID the node cannot verify offline, counting and logging the refusal.
fn check_did(did: &DID) -> Result<(), UcanVerifyError> {
    match check_verifiable(did) {
        Ok(()) => Ok(()),
        Err(Unverifiable::MethodDisabled) => {
            refused(did, "method_disabled");
            Err(UcanVerifyError::MethodDisabled {
                method: did.method_name().to_owned(),
            })
        }
        Err(Unverifiable::Identifier) => {
            refused(did, "unverifiable");
            Err(UcanVerifyError::Unverifiable {
                method: did.method_name().to_owned(),
            })
        }
    }
}

fn check_issuer(issuer: &DIDURL) -> Result<(), UcanVerifyError> {
    if issuer.query().is_some() {
        refused(issuer.did(), "query_rejected");
        return Err(UcanVerifyError::QueryRejected);
    }
    check_did(issuer.did())
}

/// Whether a grant may name `did` as its holder: a DID the node can verify offline, or a
/// Policy/v3 delegate (`did:tinycloud:policy:<64 lowercase hex>`), which holds a policy root
/// and never signs. Counted as a refusal with reason `holder_unverifiable` when it may not.
pub fn check_holder(did: &str) -> bool {
    if did
        .strip_prefix("did:tinycloud:policy:")
        .is_some_and(|digest| {
            digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        })
    {
        return true;
    }
    let Ok(parsed) = DID::new(did.as_bytes()) else {
        REFUSED_TOTAL.fetch_add(1, Ordering::Relaxed);
        if let Some(observer) = REFUSAL_OBSERVER.get() {
            observer("unknown", "holder_unverifiable");
        }
        return false;
    };
    if check_verifiable(parsed).is_ok() {
        return true;
    }
    refused(parsed, "holder_unverifiable");
    false
}

/// Defence in depth for callers resolving a DID directly: a DID the node cannot verify
/// offline is refused before the offline resolver is consulted.
pub struct NodeDidResolver;
impl DIDResolver for NodeDidResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: Options,
    ) -> Result<Output<Vec<u8>>, resolution::Error> {
        check_did(did).map_err(resolution::Error::internal)?;
        AnyDidMethod::default()
            .resolve_representation(did, options)
            .await
    }
}

/// The single production entry point for node UCAN signature verification.
pub async fn verify_ucan_signature<F, A>(ucan: &Ucan<F, A>) -> Result<(), UcanVerifyError>
where
    F: for<'de> Deserialize<'de> + Serialize,
    A: for<'de> Deserialize<'de> + Serialize,
{
    check_issuer(&ucan.payload().issuer)?;
    tokio::time::timeout(
        did_resolution_timeout(),
        ucan.verify_signature(&NodeDidResolver),
    )
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
    check_issuer(&revocation.issuer)?;
    tokio::time::timeout(
        did_resolution_timeout(),
        revocation.verify_signature(&NodeDidResolver, algorithm, jwk),
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
    use std::cell::Cell;
    use std::sync::{Mutex, OnceLock};
    use tinycloud_auth::{ipld_core::cid::multibase, resolver::DID_METHODS};

    thread_local! {
        static DECODES: Cell<usize> = const { Cell::new(0) };
    }

    /// Counts identifier decodes, so tests can prove a length cap refuses before decoding.
    pub(super) fn count_decode() {
        DECODES.with(|decodes| decodes.set(decodes.get() + 1));
    }

    /// The verdict for `did` and the identifier decodes it took.
    fn verdict(did: &str) -> (Result<(), Unverifiable>, usize) {
        let before = DECODES.with(Cell::get);
        let result = check_verifiable(DID::new(did.as_bytes()).unwrap());
        (result, DECODES.with(Cell::get) - before)
    }

    fn did_key(bytes: &[u8]) -> String {
        format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base58Btc, bytes)
        )
    }

    fn did_jwk(jwk: serde_json::Value) -> String {
        format!("did:jwk:{}", URL_SAFE_NO_PAD.encode(jwk.to_string()))
    }

    fn generated(key: &JWK, method: &str) -> String {
        DID_METHODS.generate(key, method).unwrap().to_string()
    }

    fn address(did: &str) -> &str {
        did.rsplit(':').next().unwrap()
    }

    /// A Tezos account; the node's ssi build cannot generate one.
    const TEZOS: &str = "did:pkh:tezos:NetXdQprcVkpaWU:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x";

    #[test]
    fn accepts_every_offline_key_type_and_account_namespace() {
        let ed = JWK::generate_ed25519().unwrap();
        let k1 = JWK::generate_secp256k1();
        let p256 = JWK::generate_p256();
        let mut accepted = vec![];
        for key in [&ed, &k1, &p256] {
            accepted.push(generated(key, "key"));
            accepted.push(generated(key, "jwk"));
        }
        let eip155 = generated(&k1, "pkh:eip155:1");
        accepted.push(eip155.clone());
        accepted.push(eip155.replace(":1:", ":137:").to_lowercase());
        accepted.push(generated(
            &k1,
            "pkh:bip122:000000000019d6689c085ae165831e93",
        ));
        accepted.push(format!(
            "did:pkh:bip122:{BIP122_DOGECOIN_MAINNET}:{}",
            address(&generated(&k1, "pkh:doge"))
        ));
        accepted.push(format!(
            "did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:{}",
            address(&generated(&ed, "pkh:sol"))
        ));
        assert!(accepted[0].starts_with("did:key:z6Mk"));
        assert!(accepted[2].starts_with("did:key:zQ3s"));
        assert!(accepted[4].starts_with("did:key:zDn"));
        for did in accepted {
            assert_eq!(verdict(&did).0, Ok(()), "{did}");
            assert!(check_holder(&did), "{did}");
        }
    }

    #[test]
    fn refuses_unverifiable_did_keys_with_lengths_checked_before_decoding() {
        let ed = JWK::generate_ed25519().unwrap();
        let Params::OKP(okp) = &ed.params else {
            unreachable!()
        };
        let x = &okp.public_key.0;
        // The production z2D… host keys: a one-byte 0xed prefix, not the 0xed 0x01 varint.
        let z2d = did_key(&[&[0xed][..], x].concat());
        assert!(z2d.starts_with("did:key:z2D"), "{z2d}");
        let p384 = did_key(&[&[0x81, 0x24, 0x02][..], &[7; 48]].concat());
        let oversized = format!("did:key:z{}", "1".repeat(10_000));
        let base64_multibase = format!(
            "did:key:{}",
            multibase::encode(multibase::Base::Base64Url, [&[0xed, 0x01][..], x].concat())
        );
        for did in [&z2d, &p384, &oversized, &base64_multibase] {
            assert_eq!(verdict(did), (Err(Unverifiable::Identifier), 0), "{did}");
        }
        // Within the length bounds: decoded once, then refused.
        let not_on_curve = (0u8..=255)
            .map(|b| [b; 32])
            .find(|y| ed25519_dalek::VerifyingKey::from_bytes(y).is_err())
            .unwrap();
        let secp256k1_x_out_of_range = [&[0xe7, 0x01, 0x02][..], &[0xff; 32]].concat();
        let ed25519_private = [&[0x80, 0x26][..], x].concat();
        for bytes in [
            [&[0xed, 0x01][..], &not_on_curve].concat(),
            secp256k1_x_out_of_range,
            ed25519_private,
        ] {
            let did = did_key(&bytes);
            if DID_KEY_ID_LENS.contains(&did.len().saturating_sub(8)) {
                assert_eq!(verdict(&did), (Err(Unverifiable::Identifier), 1), "{did}");
            } else {
                assert_eq!(verdict(&did), (Err(Unverifiable::Identifier), 0), "{did}");
            }
            assert!(!check_holder(&did), "{did}");
        }
        assert!(!check_holder(&z2d));
    }

    #[test]
    fn refuses_unverifiable_did_jwks_with_length_checked_before_decoding() {
        let ed = serde_json::to_value(JWK::generate_ed25519().unwrap()).unwrap();
        let p256 = serde_json::to_value(JWK::generate_p256().to_public()).unwrap();
        let mut off_curve = p256.clone();
        off_curve["y"] = serde_json::json!(URL_SAFE_NO_PAD.encode([0xff; 32]));
        let mut p384 = p256.clone();
        p384["crv"] = serde_json::json!("P-384");
        let mut x25519 =
            serde_json::to_value(JWK::generate_ed25519().unwrap().to_public()).unwrap();
        x25519["crv"] = serde_json::json!("X25519");
        // Ed25519 private key material, `d`, makes the DID malformed.
        for jwk in [ed, off_curve, p384, x25519] {
            let did = did_jwk(jwk);
            assert_eq!(verdict(&did), (Err(Unverifiable::Identifier), 1), "{did}");
            assert!(!check_holder(&did), "{did}");
        }
        let mut padded = serde_json::to_value(JWK::generate_p256().to_public()).unwrap();
        padded["kid"] = serde_json::json!("k".repeat(MAX_DID_JWK_ID_LEN));
        let did = did_jwk(padded);
        assert_eq!(verdict(&did), (Err(Unverifiable::Identifier), 0), "{did}");
    }

    #[test]
    fn refuses_unverifiable_did_pkh_accounts() {
        let k1 = JWK::generate_secp256k1();
        let ed = JWK::generate_ed25519().unwrap();
        let eip155 = generated(&k1, "pkh:eip155:1");
        let account = address(&eip155);
        for did in [
            TEZOS.to_owned(),
            generated(&k1, "pkh:eth"),
            generated(&ed, "pkh:sol"),
            generated(&k1, "pkh:btc"),
            format!("did:pkh:eip155:1:{}", &account[..41]),
            format!("did:pkh:eip155:1:{}g", &account[..41]),
            format!("did:pkh:eip155:mainnet:{account}"),
            format!("did:pkh:eip155:1:{account}:extra"),
            format!("did:pkh:eip155::{account}"),
            format!(
                "did:pkh:bip122:000000000933ea01ad0ee984209779ba:{}",
                address(&generated(&k1, "pkh:btc"))
            ),
            format!(
                "did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:{}",
                multibase::Base::Base58Btc.encode([1; 31])
            ),
        ] {
            assert_eq!(verdict(&did).0, Err(Unverifiable::Identifier), "{did}");
            assert!(!check_holder(&did), "{did}");
        }
        let long = format!(
            "did:pkh:eip155:{}:{account}",
            "1".repeat(MAX_DID_PKH_ID_LEN)
        );
        assert_eq!(verdict(&long), (Err(Unverifiable::Identifier), 0));
    }

    #[test]
    fn refuses_network_methods_and_exempts_only_policy_holders() {
        for did in [
            "did:web:example.com",
            "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
            "did:ion:EiClkZMDxPKqC9c-umQfTkR8vvZ9JPhl_xLDI9Nfk38w5w",
            "did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x",
        ] {
            assert_eq!(
                verdict(did),
                (Err(Unverifiable::MethodDisabled), 0),
                "{did}"
            );
            assert!(!check_holder(did), "{did}");
        }
        let digest = "0123456789abcdef".repeat(4);
        let policy = format!("did:tinycloud:policy:{digest}");
        assert_eq!(verdict(&policy).0, Err(Unverifiable::MethodDisabled));
        assert!(check_holder(&policy));
        for did in [
            format!("did:tinycloud:policy:{}", digest.to_uppercase()),
            format!("did:tinycloud:policy:{}", &digest[..63]),
            format!("did:tinycloud:policy:{digest}0"),
            format!("did:tinycloud:other:{digest}"),
            "not a did".into(),
        ] {
            assert!(!check_holder(&did), "{did}");
        }
    }

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

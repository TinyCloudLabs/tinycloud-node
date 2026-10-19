//! The pinned per-policy credential issuer set (TC-1452, G3).
//!
//! A verifier trusts an issuer only through an entry configured here: a
//! pinned Ed25519 key together with the credential types, profiles and
//! validity window the key may vouch for. Nothing in this module fetches or
//! resolves a DID; an unknown `(issuerDid, kid)` pair, or a DID method that is
//! not on the allow-list (`docs/principles.md`, principle 2), is simply absent.
//!
//! The entry shape and the set-load rules follow the held-credential profile
//! spec (tinycloud-dev `docs/specs/held-credential-profile-v1.md`, section 6).
//! A violation makes the whole set invalid and the node refuses to start.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::share_email_evidence::{IssuerKey, EDDSA};

/// Profiles the OpenCredentials witness issues today. The legacy single-issuer
/// configuration (`share_email.issuer_*`) becomes a one-entry set that admits
/// exactly these.
const LEGACY_PROFILES: &[&str] = &[
    "tinycloud.email-proof/v1",
    "tinycloud.email-domain-proof/v1",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IssuerSetError {
    #[error("issuer set entry {index}: alg must be EdDSA")]
    Alg { index: usize },
    #[error("issuer set entry {index}: issuerDid is not canonical or its DID method is not on the allow-list")]
    IssuerDid { index: usize },
    #[error("issuer set entry {index}: kid must be issuerDid#fragment")]
    Kid { index: usize },
    #[error("issuer set entry {index}: duplicate kid")]
    DuplicateKid { index: usize },
    #[error(
        "issuer set entry {index}: publicKey must be a canonical 32-byte Ed25519 key in base64url"
    )]
    PublicKey { index: usize },
    #[error("issuer set entry {index}: publicKey is a fixture or repeated-byte test key")]
    FixtureKey { index: usize },
    #[error("issuer set entry {index}: publicKey is already pinned by another entry")]
    DuplicatePublicKey { index: usize },
    #[error(
        "issuer set entry {index}: vcts and profiles must be non-empty lists of non-empty strings"
    )]
    Admission { index: usize },
    #[error("issuer set entry {index}: {field} must be an RFC 3339 UTC time ending in Z")]
    Time { index: usize, field: &'static str },
    #[error("issuer set entry {index}: retiredAt is after notAfter")]
    RetiredAfterNotAfter { index: usize },
    #[error(
        "issuer set entry {index}: notBefore is after notAfter, or retiredAt is before notBefore"
    )]
    EmptyWindow { index: usize },
}

/// One configured issuer, as written in configuration (camelCase, matching the
/// `tinycloud.credentials-issuers/v1` document).
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CredentialIssuerConfig {
    pub issuer_did: String,
    pub kid: String,
    pub alg: String,
    pub public_key: String,
    pub vcts: Vec<String>,
    pub profiles: Vec<String>,
    pub not_before: String,
    #[serde(default)]
    pub retired_at: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
}

/// A validated issuer-set entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerSetEntry {
    pub issuer_did: String,
    pub kid: String,
    pub alg: String,
    pub public_key: [u8; 32],
    pub vcts: Vec<String>,
    pub profiles: Vec<String>,
    pub not_before: OffsetDateTime,
    pub retired_at: Option<OffsetDateTime>,
    pub not_after: Option<OffsetDateTime>,
    /// The credential's JWT header must carry `typ` (exactly `vc+sd-jwt`).
    /// True for every explicitly configured entry (held-profile spec 3.1);
    /// false for the legacy single issuer, which keeps accepting a header
    /// without `typ` so credentials already issued under it still verify.
    pub require_typ: bool,
}

/// Why an entry cannot vouch for a credential at this moment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssuerWindowError {
    /// `now < notBefore`, or the credential was issued before `notBefore`.
    NotYetValid,
    /// `now >= notAfter`: the hard stop for a compromised key.
    Stopped,
    /// `iat >= retiredAt`: the key was rotated out before it issued this.
    Retired,
}

impl IssuerSetEntry {
    /// An entry admits a credential only for a `vct` and a profile it lists.
    pub fn admits(&self, vct: &str, profile: &str) -> bool {
        self.vcts.iter().any(|value| value == vct) && self.profiles.iter().any(|v| v == profile)
    }

    /// Checks that depend only on the clock. Run these before the signature.
    pub fn check_now(&self, now: OffsetDateTime) -> Result<(), IssuerWindowError> {
        if now < self.not_before {
            return Err(IssuerWindowError::NotYetValid);
        }
        if self.not_after.is_some_and(|stop| now >= stop) {
            return Err(IssuerWindowError::Stopped);
        }
        Ok(())
    }

    /// Checks on the signed `iat`. Run these only after the signature has
    /// verified. A credential issued before `retiredAt` keeps verifying until
    /// its own `exp`; one issued at or after it does not.
    pub fn check_issued_at(&self, iat: OffsetDateTime) -> Result<(), IssuerWindowError> {
        if iat < self.not_before {
            return Err(IssuerWindowError::NotYetValid);
        }
        if self.retired_at.is_some_and(|retired| iat >= retired) {
            return Err(IssuerWindowError::Retired);
        }
        Ok(())
    }

    /// The legacy single-issuer configuration as an entry: no time window, and
    /// only the profiles the witness issues today.
    fn from_legacy(key: &IssuerKey) -> Self {
        Self {
            issuer_did: key.issuer_did.clone(),
            kid: key.kid.clone(),
            alg: EDDSA.to_owned(),
            public_key: key.public_key,
            vcts: vec![key.vct.clone()],
            profiles: LEGACY_PROFILES.iter().map(|p| (*p).to_owned()).collect(),
            not_before: OffsetDateTime::UNIX_EPOCH,
            retired_at: None,
            not_after: None,
            require_typ: false,
        }
    }
}

/// The pinned set, keyed by the exact `(issuerDid, kid)` pair.
#[derive(Debug, Clone, Default)]
pub struct IssuerSet {
    entries: BTreeMap<(String, String), IssuerSetEntry>,
}

impl IssuerSet {
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Builds the set from configuration, applying every set-load rule. Any
    /// violation rejects the whole set.
    pub fn load(configured: &[CredentialIssuerConfig]) -> Result<Self, IssuerSetError> {
        let mut set = Self::default();
        for (index, config) in configured.iter().enumerate() {
            set.insert(index, parse_entry(index, config)?)?;
        }
        Ok(set)
    }

    /// Loads the set and adds the legacy single issuer as one more entry. A
    /// legacy `kid` that also appears in the explicit list is a duplicate.
    pub fn load_with_legacy(
        configured: &[CredentialIssuerConfig],
        legacy: Option<&IssuerKey>,
    ) -> Result<Self, IssuerSetError> {
        let mut set = Self::load(configured)?;
        if let Some(key) = legacy.filter(|key| key.enabled) {
            let entry = IssuerSetEntry::from_legacy(key);
            let index = configured.len();
            if !did_is_canonical(&entry.issuer_did) {
                return Err(IssuerSetError::IssuerDid { index });
            }
            if !kid_matches(&entry.kid, &entry.issuer_did) {
                return Err(IssuerSetError::Kid { index });
            }
            set.insert(index, entry)?;
        }
        Ok(set)
    }

    /// The legacy single issuer as a one-entry set.
    pub fn from_legacy(key: &IssuerKey) -> Self {
        let mut set = Self::default();
        if key.enabled {
            let entry = IssuerSetEntry::from_legacy(key);
            set.entries
                .insert((entry.issuer_did.clone(), entry.kid.clone()), entry);
        }
        set
    }

    fn insert(&mut self, index: usize, entry: IssuerSetEntry) -> Result<(), IssuerSetError> {
        // `kid` is unique across the whole set, whatever the issuer.
        if self
            .entries
            .values()
            .any(|existing| existing.kid == entry.kid)
        {
            return Err(IssuerSetError::DuplicateKid { index });
        }
        // One key under two kids would let the unsigned envelope pick the
        // more permissive entry for the same signature.
        if self
            .entries
            .values()
            .any(|existing| existing.public_key == entry.public_key)
        {
            return Err(IssuerSetError::DuplicatePublicKey { index });
        }
        self.entries
            .insert((entry.issuer_did.clone(), entry.kid.clone()), entry);
        Ok(())
    }

    /// The single lookup seam. Returns the full entry for the exact
    /// `(issuerDid, kid)` pair, never a bare key. A DID method that is not on
    /// the allow-list, an unknown issuer and a right issuer with a wrong `kid`
    /// all return `None`. It never touches the network; a future allow-listed
    /// `did:web` resolver (TC-1132) would be a second source behind this
    /// function.
    pub fn resolve_pinned_issuer(&self, did: &str, kid: &str) -> Option<&IssuerSetEntry> {
        if !did_method_allowed(did) {
            return None;
        }
        self.entries.get(&(did.to_owned(), kid.to_owned()))
    }
}

fn parse_entry(
    index: usize,
    config: &CredentialIssuerConfig,
) -> Result<IssuerSetEntry, IssuerSetError> {
    if config.alg != EDDSA {
        return Err(IssuerSetError::Alg { index });
    }
    if !did_is_canonical(&config.issuer_did) {
        return Err(IssuerSetError::IssuerDid { index });
    }
    if !kid_matches(&config.kid, &config.issuer_did) {
        return Err(IssuerSetError::Kid { index });
    }
    // The fixture seeds are public: a pasted fixture key would let anyone mint
    // credentials the node admits. Only the hermetic fixture build keeps them.
    if !crate::config::allows_hermetic_fixture()
        && crate::config::is_fixture_public_key(&config.public_key)
    {
        return Err(IssuerSetError::FixtureKey { index });
    }
    let public_key =
        canonical_ed25519_key(&config.public_key).ok_or(IssuerSetError::PublicKey { index })?;
    let non_empty = |values: &[String]| !values.is_empty() && values.iter().all(|v| !v.is_empty());
    if !non_empty(&config.vcts) || !non_empty(&config.profiles) {
        return Err(IssuerSetError::Admission { index });
    }
    let not_before = parse_utc(&config.not_before).ok_or(IssuerSetError::Time {
        index,
        field: "notBefore",
    })?;
    let retired_at = config
        .retired_at
        .as_deref()
        .map(|text| {
            parse_utc(text).ok_or(IssuerSetError::Time {
                index,
                field: "retiredAt",
            })
        })
        .transpose()?;
    let not_after = config
        .not_after
        .as_deref()
        .map(|text| {
            parse_utc(text).ok_or(IssuerSetError::Time {
                index,
                field: "notAfter",
            })
        })
        .transpose()?;
    if let (Some(retired), Some(stop)) = (retired_at, not_after) {
        if retired > stop {
            return Err(IssuerSetError::RetiredAfterNotAfter { index });
        }
    }
    if not_after.is_some_and(|stop| not_before > stop)
        || retired_at.is_some_and(|retired| retired < not_before)
    {
        return Err(IssuerSetError::EmptyWindow { index });
    }
    Ok(IssuerSetEntry {
        issuer_did: config.issuer_did.clone(),
        kid: config.kid.clone(),
        alg: config.alg.clone(),
        public_key,
        vcts: config.vcts.clone(),
        profiles: config.profiles.clone(),
        not_before,
        retired_at,
        not_after,
        require_typ: true,
    })
}

/// RFC 3339, UTC, written with a literal `Z`. Offsets such as `+00:00` and a
/// lowercase `z` are refused so one instant has one spelling.
fn parse_utc(text: &str) -> Option<OffsetDateTime> {
    if !text.ends_with('Z') {
        return None;
    }
    let parsed = OffsetDateTime::parse(text, &Rfc3339).ok()?;
    parsed.offset().is_utc().then_some(parsed)
}

/// `kid` is `issuerDid#fragment` with a non-empty fragment.
fn kid_matches(kid: &str, issuer_did: &str) -> bool {
    kid.strip_prefix(issuer_did)
        .and_then(|rest| rest.strip_prefix('#'))
        .is_some_and(|fragment| {
            !fragment.is_empty()
                && !fragment.contains('#')
                && !fragment
                    .chars()
                    .any(|c| c.is_whitespace() || c.is_control())
        })
}

/// An Ed25519 public key written as unpadded base64url that decodes to 32
/// bytes, re-encodes to the same text, and is the canonical encoding of a
/// valid, non-small-order curve point.
fn canonical_ed25519_key(text: &str) -> Option<[u8; 32]> {
    use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
    let bytes = decode_config(text, URL_SAFE_NO_PAD).ok()?;
    if encode_config(&bytes, URL_SAFE_NO_PAD) != text {
        return None;
    }
    let bytes: [u8; 32] = bytes.try_into().ok()?;
    let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()?;
    // dalek decompresses non-canonical y encodings; re-compressing exposes them.
    (key.to_bytes() == bytes && !key.is_weak()).then_some(bytes)
}

/// The DID methods an issuer may use (`docs/principles.md`, principle 2): only
/// `did:web`, for issuers TinyCloud lists, with the key pinned here. The other
/// allow-listed methods (`did:key`, `did:jwk`, `did:pkh`) identify subjects, not
/// issuers. Anything else is refused without a lookup.
pub fn did_method_allowed(did: &str) -> bool {
    did_is_canonical(did)
}

fn did_is_canonical(did: &str) -> bool {
    if did.is_empty() || did.contains(['#', '?', '/']) || did.chars().any(char::is_whitespace) {
        return false;
    }
    if let Some(host) = did.strip_prefix("did:web:") {
        // Lowercase host only: no port (`%3A`), no path (`:`), no query.
        return !host.is_empty()
            && host.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            });
    }
    // did:key and did:jwk are self-describing but the node has no option to
    // trust one as an issuer, and did:pkh is for subjects only (principle 2).
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{decode_config, encode_config, STANDARD, URL_SAFE_NO_PAD};

    const DID: &str = "did:web:issuer.credentials.org";

    pub(crate) fn key_text(seed: u8) -> String {
        let signing = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        encode_config(signing.verifying_key().to_bytes(), URL_SAFE_NO_PAD)
    }

    fn entry(did: &str, fragment: &str, seed: u8) -> CredentialIssuerConfig {
        CredentialIssuerConfig {
            issuer_did: did.into(),
            kid: format!("{did}#{fragment}"),
            alg: "EdDSA".into(),
            public_key: key_text(seed),
            vcts: vec!["opencredentials.email/v1".into()],
            profiles: vec!["tinycloud.email-held/v1".into()],
            not_before: "2026-10-01T00:00:00Z".into(),
            retired_at: None,
            not_after: None,
        }
    }

    fn time(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &Rfc3339).unwrap()
    }

    #[test]
    fn loads_a_valid_two_issuer_set_and_returns_the_full_entry() {
        let mut second = entry("did:web:acme.credentials.org", "issuing-1", 2);
        second.retired_at = Some("2027-01-01T00:00:00Z".into());
        second.not_after = Some("2028-01-01T00:00:00Z".into());
        let set = IssuerSet::load(&[entry(DID, "issuing-1", 1), second]).unwrap();
        assert_eq!(set.len(), 2);
        let found = set
            .resolve_pinned_issuer(DID, "did:web:issuer.credentials.org#issuing-1")
            .unwrap();
        assert!(found.require_typ);
        assert_eq!(found.vcts, ["opencredentials.email/v1"]);
        assert_eq!(found.profiles, ["tinycloud.email-held/v1"]);
        assert_eq!(found.not_before, time("2026-10-01T00:00:00Z"));
        assert!(found.retired_at.is_none() && found.not_after.is_none());
        let acme = set
            .resolve_pinned_issuer(
                "did:web:acme.credentials.org",
                "did:web:acme.credentials.org#issuing-1",
            )
            .unwrap();
        assert_eq!(acme.retired_at, Some(time("2027-01-01T00:00:00Z")));
        assert_eq!(acme.not_after, Some(time("2028-01-01T00:00:00Z")));
    }

    #[test]
    fn lookup_is_the_exact_pair_and_fails_closed() {
        let set = IssuerSet::load(&[
            entry(DID, "issuing-1", 1),
            entry("did:web:acme.credentials.org", "issuing-1", 2),
        ])
        .unwrap();
        // Right issuer, wrong kid.
        assert!(set
            .resolve_pinned_issuer(DID, "did:web:issuer.credentials.org#issuing-2")
            .is_none());
        // A kid that belongs to another issuer is not found under this one.
        assert!(set
            .resolve_pinned_issuer(DID, "did:web:acme.credentials.org#issuing-1")
            .is_none());
        // Unknown issuer.
        assert!(set
            .resolve_pinned_issuer(
                "did:web:other.credentials.org",
                "did:web:other.credentials.org#a"
            )
            .is_none());
        // No kid-only match.
        assert!(set
            .resolve_pinned_issuer("", "did:web:acme.credentials.org#issuing-1")
            .is_none());
    }

    #[test]
    fn dids_outside_the_allow_list_are_refused_at_load_and_at_lookup() {
        for bad in [
            "did:ethr:0xabc",
            "did:ion:abc",
            "did:tz:tz1abc",
            "did:pkh:solana:abc",
            "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd",
            "did:jwk:eyJ",
            "did:pkh:eip155:1:0xabc",
            "did:web:Issuer.Credentials.org",
            "did:web:issuer.credentials.org%3A8443",
            "did:web:issuer.credentials.org:path",
            "did:web:",
        ] {
            let result = IssuerSet::load(&[entry(bad, "k", 1)]);
            assert_eq!(
                result.unwrap_err(),
                IssuerSetError::IssuerDid { index: 0 },
                "{bad}"
            );
            assert!(!did_method_allowed(bad), "{bad}");
        }
        assert!(did_method_allowed(DID));
        let set = IssuerSet::load(&[entry(DID, "k", 1)]).unwrap();
        assert!(set
            .resolve_pinned_issuer("did:ethr:0xabc", "did:ethr:0xabc#k")
            .is_none());
    }

    #[test]
    fn refuses_a_non_eddsa_entry() {
        for alg in ["ES256K", "ES256", "eddsa", "Ed25519", ""] {
            let mut bad = entry(DID, "k", 1);
            bad.alg = alg.into();
            assert_eq!(
                IssuerSet::load(&[bad]).unwrap_err(),
                IssuerSetError::Alg { index: 0 }
            );
        }
    }

    #[test]
    fn refuses_a_duplicate_kid_even_under_another_issuer() {
        let a = entry(DID, "k", 1);
        assert_eq!(
            IssuerSet::load(&[a.clone(), a.clone()]).unwrap_err(),
            IssuerSetError::DuplicateKid { index: 1 }
        );
        // Same kid text under a different `issuerDid` cannot happen because
        // `kid` must start with its own issuer, so the pair duplicate is the
        // only reachable case; it is also refused through the legacy path.
        let legacy = IssuerKey::new(
            DID,
            "opencredentials.email/v1",
            1,
            format!("{DID}#k"),
            [0; 32],
        );
        assert_eq!(
            IssuerSet::load_with_legacy(&[a], Some(&legacy)).unwrap_err(),
            IssuerSetError::DuplicateKid { index: 1 }
        );
    }

    #[test]
    fn refuses_a_kid_that_is_not_issuer_did_hash_fragment() {
        for kid in [
            "did:web:issuer.credentials.org",
            "did:web:issuer.credentials.org#",
            "did:web:acme.credentials.org#k",
            "issuer.credentials.org#k",
            "did:web:issuer.credentials.org#a#b",
            "did:web:issuer.credentials.org#a b",
            "did:web:issuer.credentials.orgx#k",
        ] {
            let mut bad = entry(DID, "k", 1);
            bad.kid = kid.into();
            assert_eq!(
                IssuerSet::load(&[bad]).unwrap_err(),
                IssuerSetError::Kid { index: 0 },
                "{kid}"
            );
        }
    }

    #[test]
    fn refuses_retired_at_after_not_after_but_allows_equal() {
        let mut bad = entry(DID, "k", 1);
        bad.retired_at = Some("2027-01-02T00:00:00Z".into());
        bad.not_after = Some("2027-01-01T00:00:00Z".into());
        assert_eq!(
            IssuerSet::load(&[bad]).unwrap_err(),
            IssuerSetError::RetiredAfterNotAfter { index: 0 }
        );
        let mut equal = entry(DID, "k", 1);
        equal.retired_at = Some("2027-01-01T00:00:00Z".into());
        equal.not_after = Some("2027-01-01T00:00:00Z".into());
        assert!(IssuerSet::load(&[equal]).is_ok());
    }

    #[test]
    fn refuses_malformed_and_non_z_times() {
        for text in [
            "2026-10-01",
            "2026-10-01T00:00:00",
            "2026-10-01T00:00:00+00:00",
            "2026-10-01T02:00:00+02:00",
            "2026-10-01T00:00:00z",
            "yesterday",
            "",
        ] {
            let mut bad = entry(DID, "k", 1);
            bad.not_before = text.into();
            assert_eq!(
                IssuerSet::load(&[bad]).unwrap_err(),
                IssuerSetError::Time {
                    index: 0,
                    field: "notBefore"
                },
                "{text:?}"
            );
            let mut bad = entry(DID, "k", 1);
            bad.retired_at = Some(text.into());
            assert_eq!(
                IssuerSet::load(&[bad]).unwrap_err(),
                IssuerSetError::Time {
                    index: 0,
                    field: "retiredAt"
                },
                "{text:?}"
            );
            let mut bad = entry(DID, "k", 1);
            bad.not_after = Some(text.into());
            assert_eq!(
                IssuerSet::load(&[bad]).unwrap_err(),
                IssuerSetError::Time {
                    index: 0,
                    field: "notAfter"
                },
                "{text:?}"
            );
        }
    }

    #[test]
    fn refuses_non_canonical_or_invalid_ed25519_keys() {
        let valid = key_text(1);
        let bytes = decode_config(&valid, URL_SAFE_NO_PAD).unwrap();
        let padded = format!("{valid}=");
        let standard_alphabet = encode_config(&bytes, STANDARD);
        let short = encode_config(&bytes[..31], URL_SAFE_NO_PAD);
        let long = encode_config([&bytes[..], &[0u8]].concat(), URL_SAFE_NO_PAD);
        // y = p (2^255 - 19) encodes a non-canonical value for y = 0.
        let mut non_canonical = [0xffu8; 32];
        non_canonical[0] = 0xed;
        non_canonical[31] = 0x7f;
        // The identity point (0, 1) is a small-order key.
        let mut identity = [0u8; 32];
        identity[0] = 1;
        // y = 2 is not on the curve.
        let mut off_curve = [0u8; 32];
        off_curve[0] = 2;
        let mut candidates = vec![
            padded,
            standard_alphabet,
            short,
            long,
            encode_config(non_canonical, URL_SAFE_NO_PAD),
            encode_config(identity, URL_SAFE_NO_PAD),
            encode_config(off_curve, URL_SAFE_NO_PAD),
            String::new(),
            "not base64!".into(),
        ];
        // Non-zero padding bits in the final base64url character: the text
        // decodes to the same bytes but is not the canonical spelling.
        const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let last = valid.chars().last().unwrap();
        let value = ALPHABET.find(last).unwrap();
        assert_eq!(value & 0b11, 0, "a canonical 32-byte key ends in zero bits");
        let mut trailing = valid.clone();
        trailing.pop();
        trailing.push(ALPHABET.chars().nth(value | 1).unwrap());
        candidates.push(trailing);
        for key in candidates {
            let mut bad = entry(DID, "k", 1);
            bad.public_key = key.clone();
            assert_eq!(
                IssuerSet::load(&[bad]).unwrap_err(),
                IssuerSetError::PublicKey { index: 0 },
                "{key:?}"
            );
        }
        assert!(IssuerSet::load(&[entry(DID, "k", 1)]).is_ok());
    }

    #[test]
    fn refuses_empty_validity_windows() {
        let mut bad = entry(DID, "k", 1);
        bad.not_after = Some("2026-09-30T00:00:00Z".into());
        assert_eq!(
            IssuerSet::load(&[bad]).unwrap_err(),
            IssuerSetError::EmptyWindow { index: 0 }
        );
        let mut bad = entry(DID, "k", 1);
        bad.retired_at = Some("2026-09-30T00:00:00Z".into());
        assert_eq!(
            IssuerSet::load(&[bad]).unwrap_err(),
            IssuerSetError::EmptyWindow { index: 0 }
        );
        // Equal bounds are degenerate but not inverted.
        let mut edge = entry(DID, "k", 1);
        edge.not_after = Some("2026-10-01T00:00:00Z".into());
        edge.retired_at = Some("2026-10-01T00:00:00Z".into());
        assert!(IssuerSet::load(&[edge]).is_ok());
    }

    #[test]
    fn refuses_one_public_key_pinned_twice() {
        let a = entry(DID, "issuing-1", 1);
        let mut b = entry("did:web:acme.credentials.org", "issuing-1", 1);
        assert_eq!(
            IssuerSet::load(&[a.clone(), b.clone()]).unwrap_err(),
            IssuerSetError::DuplicatePublicKey { index: 1 }
        );
        b.issuer_did = DID.into();
        b.kid = format!("{DID}#issuing-2");
        assert_eq!(
            IssuerSet::load(&[a.clone(), b]).unwrap_err(),
            IssuerSetError::DuplicatePublicKey { index: 1 }
        );
        // Also against the legacy entry.
        let legacy = IssuerKey::new(
            "did:web:legacy.credentials.org",
            "opencredentials.email/v1",
            1,
            "did:web:legacy.credentials.org#controller",
            decode_config(&a.public_key, URL_SAFE_NO_PAD)
                .unwrap()
                .try_into()
                .unwrap(),
        );
        assert_eq!(
            IssuerSet::load_with_legacy(&[a], Some(&legacy)).unwrap_err(),
            IssuerSetError::DuplicatePublicKey { index: 1 }
        );
    }

    #[cfg(not(feature = "mounted-fixture"))]
    #[test]
    fn refuses_fixture_and_repeated_byte_keys_in_a_production_build() {
        for key in [
            "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY",
            "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI",
            &encode_config([0x43u8; 32], URL_SAFE_NO_PAD),
        ] {
            let mut bad = entry(DID, "k", 1);
            bad.public_key = key.into();
            assert_eq!(
                IssuerSet::load(&[bad]).unwrap_err(),
                IssuerSetError::FixtureKey { index: 0 },
                "{key}"
            );
        }
    }

    #[cfg(feature = "mounted-fixture")]
    #[test]
    fn accepts_the_frozen_fixture_key_only_in_the_hermetic_fixture_build() {
        let mut fixture = entry(DID, "k", 1);
        fixture.public_key = "Ivwpd5Lwtv_Av8_bftsMCqFOAlo2XsDjQuhuOCnLdLY".into();
        assert!(IssuerSet::load(&[fixture]).is_ok());
    }

    #[test]
    fn refuses_empty_admission_lists() {
        let mut bad = entry(DID, "k", 1);
        bad.vcts.clear();
        assert_eq!(
            IssuerSet::load(&[bad]).unwrap_err(),
            IssuerSetError::Admission { index: 0 }
        );
        let mut bad = entry(DID, "k", 1);
        bad.profiles = vec![String::new()];
        assert_eq!(
            IssuerSet::load(&[bad]).unwrap_err(),
            IssuerSetError::Admission { index: 0 }
        );
    }

    #[test]
    fn unknown_fields_and_null_required_fields_do_not_parse() {
        let base = serde_json::json!({
            "issuerDid": DID, "kid": format!("{DID}#k"), "alg": "EdDSA",
            "publicKey": key_text(1), "vcts": ["v"], "profiles": ["p"],
            "notBefore": "2026-10-01T00:00:00Z", "retiredAt": null, "notAfter": null
        });
        assert!(serde_json::from_value::<CredentialIssuerConfig>(base.clone()).is_ok());
        let mut extra = base.clone();
        extra["extra"] = serde_json::json!(1);
        assert!(serde_json::from_value::<CredentialIssuerConfig>(extra).is_err());
        let mut null_alg = base.clone();
        null_alg["alg"] = serde_json::Value::Null;
        assert!(serde_json::from_value::<CredentialIssuerConfig>(null_alg).is_err());
        let mut missing = base;
        missing.as_object_mut().unwrap().remove("notBefore");
        assert!(serde_json::from_value::<CredentialIssuerConfig>(missing).is_err());
    }

    #[test]
    fn validity_window_follows_the_spec() {
        let mut config = entry(DID, "k", 1);
        config.retired_at = Some("2027-01-01T00:00:00Z".into());
        config.not_after = Some("2028-01-01T00:00:00Z".into());
        let set = IssuerSet::load(&[config]).unwrap();
        let e = set.resolve_pinned_issuer(DID, &format!("{DID}#k")).unwrap();
        assert_eq!(
            e.check_now(time("2026-09-30T23:59:59Z")),
            Err(IssuerWindowError::NotYetValid)
        );
        assert_eq!(e.check_now(time("2026-10-01T00:00:00Z")), Ok(()));
        // Retired but not stopped: still usable for verifying.
        assert_eq!(e.check_now(time("2027-06-01T00:00:00Z")), Ok(()));
        assert_eq!(
            e.check_now(time("2028-01-01T00:00:00Z")),
            Err(IssuerWindowError::Stopped)
        );
        assert_eq!(
            e.check_issued_at(time("2026-09-30T23:59:59Z")),
            Err(IssuerWindowError::NotYetValid)
        );
        assert_eq!(e.check_issued_at(time("2026-12-31T23:59:59Z")), Ok(()));
        assert_eq!(
            e.check_issued_at(time("2027-01-01T00:00:00Z")),
            Err(IssuerWindowError::Retired)
        );
        assert!(e.admits("opencredentials.email/v1", "tinycloud.email-held/v1"));
        assert!(!e.admits("opencredentials.email/v1", "tinycloud.email-proof/v1"));
        assert!(!e.admits("other/v1", "tinycloud.email-held/v1"));
    }

    #[test]
    fn legacy_single_issuer_is_a_one_entry_set() {
        let key = IssuerKey::new(
            DID,
            "opencredentials.email/v1",
            1,
            format!("{DID}#controller"),
            [7; 32],
        );
        let set = IssuerSet::from_legacy(&key);
        let e = set
            .resolve_pinned_issuer(DID, &format!("{DID}#controller"))
            .unwrap();
        assert_eq!(e.public_key, [7; 32]);
        assert_eq!(e.check_now(time("2026-10-19T00:00:00Z")), Ok(()));
        assert_eq!(e.check_issued_at(time("2001-01-01T00:00:00Z")), Ok(()));
        assert!(!e.require_typ);
        assert!(e.admits("opencredentials.email/v1", "tinycloud.email-proof/v1"));
        assert!(e.admits(
            "opencredentials.email/v1",
            "tinycloud.email-domain-proof/v1"
        ));
        let mut disabled = key;
        disabled.enabled = false;
        assert!(IssuerSet::from_legacy(&disabled).is_empty());
    }
}

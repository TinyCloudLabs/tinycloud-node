//! Escrow of the TinyCloud at-rest root key (ARK), TC-887.
//!
//! The node makes one random 32-byte ARK inside the TEE. This crate splits it
//! 2-of-3 with Shamir over GF(256), seals each share with age to a holder
//! recipient pinned in the node's config, and describes the result as an
//! [`EscrowBundle`]. The bundle's fingerprint ([`Efp`]) is what operators pin
//! once a ceremony has proven every share. Two shares rebuild the ARK; one
//! share reveals nothing about it.
//!
//! Three operations need the ARK and therefore run only inside the TEE:
//! [`EscrowBundle::create`], [`EscrowBundle::test_unlock`] and
//! [`EscrowBundle::recover`]. Everything a holder's machine does (inspecting
//! a bundle, checking a decrypted share against its commitment, re-sealing it
//! to a TEE's per-boot recovery recipient) uses public data only.
//!
//! All derivations use length-prefixed fields: `lp(x) = u32 BE len ‖ x`.

#![forbid(unsafe_code)]

mod bundle;
mod piv;
mod recipients;
mod record;
mod recovery;
mod share;

use std::fmt;
use std::str::FromStr;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub use bundle::{EscrowBundle, EscrowShare, TestUnlock};
pub use recipients::{
    parse_recipient, validate_holders, HolderRecipient, RecipientKind, RecipientPolicy,
};
pub use record::VerificationRecord;
pub use recovery::{
    binding_digest, recovery_binding, validate_nonce, wrap_share, RecoveryIdentity, RecoveryInfo,
    MAX_WRAPPED_SHARE, RECOVERY_INFO_VERSION,
};
pub use share::SharePayload;

/// Shares needed to rebuild the ARK.
pub const THRESHOLD: u8 = 2;
/// Shares made, one per holder.
pub const HOLDERS: u8 = 3;

/// Errors from escrow operations. None of them carry key or share bytes.
#[derive(Debug, thiserror::Error)]
pub enum EscrowError {
    #[error("escrow holders: {0}")]
    Holders(String),
    #[error("recipient for holder {holder:?}: {reason}")]
    Recipient { holder: String, reason: String },
    #[error("escrow bundle: {0}")]
    Bundle(&'static str),
    #[error("share is malformed")]
    ShareFormat,
    #[error("share belongs to a different ARK or generation")]
    ShareMismatch,
    #[error("share {index} does not match its commitment in this bundle: the share may come from a different escrow (a re-split) of the same key; check the bundle's EFP")]
    Commitment { index: u8 },
    #[error("{what} is not valid: {reason}")]
    Json { what: &'static str, reason: String },
    #[error("{what} is version {found}, but this tool reads version {supported}; use the tool built from the release that matches the node")]
    Version {
        what: &'static str,
        found: u64,
        supported: u32,
    },
    #[error("two shares with index {index}")]
    DuplicateIndex { index: u8 },
    #[error("combined shares do not reproduce the escrowed key (canary mismatch)")]
    Canary,
    #[error("Shamir split/combine failed")]
    Shamir,
    #[error("age: {0}")]
    Age(String),
    #[error("verification record: {0}")]
    Record(&'static str),
    #[error("recovery binding: {0}")]
    Binding(&'static str),
}

/// The at-rest root key. Zeroized on drop; `Debug` never prints it.
#[derive(Clone)]
pub struct Ark(Zeroizing<[u8; 32]>);

impl Ark {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// A fresh key from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = Zeroizing::new([0u8; 32]);
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, bytes.as_mut());
        Self(bytes)
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Ark) -> bool {
        self.0.ct_eq(&*other.0).into()
    }

    /// HKDF-SHA256 with `salt = ark_id`. Every escrow-side key comes from here.
    pub(crate) fn derive(&self, ark_id: &ArkId, info: &[u8]) -> Zeroizing<[u8; 32]> {
        let hk = Hkdf::<Sha256>::new(Some(&ark_id.0), self.expose());
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(info, out.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        out
    }
}

impl fmt::Debug for Ark {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Ark(<redacted>)")
    }
}

/// Random 16-byte id of one ARK generation. Hex on the wire.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArkId(pub [u8; 16]);

impl ArkId {
    pub fn generate() -> Self {
        let mut id = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut id);
        Self(id)
    }
}

impl fmt::Display for ArkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for ArkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArkId({self})")
    }
}

impl FromStr for ArkId {
    type Err = EscrowError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(hex32::<16>(s).ok_or(EscrowError::Bundle(
            "ark_id must be 32 hex chars",
        ))?))
    }
}

impl serde::Serialize for ArkId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ArkId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// A public 32-byte digest (fingerprint, commitment, canary). Lowercase hex on
/// the wire; equality is constant-time.
#[derive(Clone, Copy, Eq)]
pub struct Digest32(pub [u8; 32]);

impl PartialEq for Digest32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl fmt::Display for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Digest32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl FromStr for Digest32 {
    type Err = EscrowError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(hex32::<32>(s).ok_or(EscrowError::Bundle(
            "digest must be 64 hex chars",
        ))?))
    }
}

impl serde::Serialize for Digest32 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for Digest32 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Escrow fingerprint: SHA-256 over the canonical encoding of a bundle,
/// including its recipients, commitments, ciphertext digests and canary.
/// This is the value pinned as `at_rest.escrow.verified_fp`.
pub type Efp = Digest32;

/// Lowercase-only hex of exactly `N` bytes.
fn hex32<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

pub(crate) fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("field shorter than 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Parse a versioned JSON document: read `version` first, so a newer format
/// is reported as such instead of as an unknown field; then parse strictly.
pub(crate) fn parse_versioned<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
    what: &'static str,
    supported: u32,
) -> Result<T, EscrowError> {
    let json_err = |e: serde_json::Error| EscrowError::Json {
        what,
        reason: e.to_string(),
    };
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(json_err)?;
    let found = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| EscrowError::Json {
            what,
            reason: "no numeric `version` field".into(),
        })?;
    if found != u64::from(supported) {
        return Err(EscrowError::Version {
            what,
            found,
            supported,
        });
    }
    serde_json::from_value(value).map_err(json_err)
}

const CANARY_INFO: &[u8] = b"tinycloud/at-rest/escrow-canary/v1";
const CANARY_FP_DOMAIN: &[u8] = b"tinycloud/at-rest/escrow-canary-fp/v1";

/// Public fingerprint of the ARK's canary key. A holder sees it in the bundle
/// before a test-unlock; the TEE reports it after rebuilding the ARK from
/// shares, so the two can be compared without the ARK leaving the TEE.
pub fn canary_fingerprint(ark: &Ark, ark_id: &ArkId, generation: u32) -> Digest32 {
    let mut info = Vec::new();
    lp(&mut info, CANARY_INFO);
    info.extend_from_slice(&generation.to_be_bytes());
    let canary = ark.derive(ark_id, &info);
    let mut pre = Vec::new();
    lp(&mut pre, CANARY_FP_DOMAIN);
    pre.extend_from_slice(ark_id.0.as_slice());
    pre.extend_from_slice(&generation.to_be_bytes());
    lp(&mut pre, canary.as_slice());
    Digest32(sha256(&pre))
}

#[cfg(test)]
pub(crate) mod test_support;

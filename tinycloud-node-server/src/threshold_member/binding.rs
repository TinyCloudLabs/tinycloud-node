//! The member-key binding to the attested CVM (D7.3): the quote's
//! `report_data` and the proof of possession, plus the owner-side check.

use ed25519_dalek::{Signature, VerifyingKey};
use sha2::{Digest, Sha256, Sha512};

use super::{is_canonical_urn, member_did, MAX_URN_BYTES};

/// Domain label of the quote `report_data` preimage. Literal, no NUL.
pub const ATTEST_LABEL: &[u8] = b"tinycloud/threshold-member/v1/attest";
/// Domain label of the proof-of-possession message. Literal, no NUL.
pub const POP_LABEL: &[u8] = b"tinycloud/threshold-member/v1/pop";

/// A binding input or check that failed. Carries no secret.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("network URN is not canonical")]
    NoncanonicalNetwork,
    #[error("member public key is not a valid Ed25519 key")]
    InvalidMemberKey,
    #[error("quote is malformed: {0}")]
    MalformedQuote(String),
    #[error("quote REPORTDATA does not match the recomputed binding")]
    ReportDataMismatch,
    #[error("proof-of-possession signature does not verify")]
    InvalidPop,
}

fn length_prefixed_urn(urn: &str) -> Result<Vec<u8>, BindingError> {
    if urn.len() > MAX_URN_BYTES || !is_canonical_urn(urn) {
        return Err(BindingError::NoncanonicalNetwork);
    }
    let mut out = Vec::with_capacity(4 + urn.len());
    out.extend_from_slice(&(urn.len() as u32).to_be_bytes());
    out.extend_from_slice(urn.as_bytes());
    Ok(out)
}

fn member_key(member_pk: &[u8; 32]) -> Result<VerifyingKey, BindingError> {
    let key = VerifyingKey::from_bytes(member_pk).map_err(|_| BindingError::InvalidMemberKey)?;
    if key.is_weak() {
        return Err(BindingError::InvalidMemberKey);
    }
    Ok(key)
}

/// `R = SHA-512("tinycloud/threshold-member/v1/attest" || u32be(len(U)) || U || P || C)`.
///
/// `urn` is `U`, the canonical network URN; `member_pk` is `P`, the raw
/// Ed25519 public key; `nonce` is `C`. A noncanonical URN or an invalid key
/// is refused.
pub fn report_data(
    urn: &str,
    member_pk: &[u8; 32],
    nonce: &[u8; 32],
) -> Result<[u8; 64], BindingError> {
    member_key(member_pk)?;
    let mut hash = Sha512::new();
    hash.update(ATTEST_LABEL);
    hash.update(length_prefixed_urn(urn)?);
    hash.update(member_pk);
    hash.update(nonce);
    Ok(hash.finalize().into())
}

/// `"tinycloud/threshold-member/v1/pop" || u32be(len(U)) || U || C || SHA-256(raw_quote)`,
/// the message the member key signs after obtaining the quote.
pub fn pop_message(urn: &str, nonce: &[u8; 32], raw_quote: &[u8]) -> Result<Vec<u8>, BindingError> {
    let mut out = POP_LABEL.to_vec();
    out.extend_from_slice(&length_prefixed_urn(urn)?);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&Sha256::digest(raw_quote));
    Ok(out)
}

/// The owner-side check of a member attestation answer, as a pure function.
///
/// Recomputes `R` from the verifier's own canonical `urn` and outstanding
/// `nonce`, compares it with the REPORTDATA parsed from the `raw_quote` bytes
/// (never the guest agent's JSON echo), and verifies `pop_sig` under
/// `member_pk` over the nonce and the SHA-256 of exactly these quote bytes.
/// Returns the member's `did:key`, the DID to certify.
///
/// Out of scope here, and required before admitting the member: the quote's
/// signature chain, TCB status, TD attributes and measurements, and the
/// event-log replay to RTMR3 (app id, compose hash, instance id). This
/// function only parses the quote layout.
pub fn verify_member_attestation(
    urn: &str,
    nonce: &[u8; 32],
    member_pk: &[u8; 32],
    raw_quote: &[u8],
    pop_sig: &[u8; 64],
) -> Result<String, BindingError> {
    let key = member_key(member_pk)?;
    let expected = report_data(urn, member_pk, nonce)?;
    let quoted = crate::dstack::quote_report_data(raw_quote)
        .map_err(|error| BindingError::MalformedQuote(error.to_string()))?;
    if quoted != expected.as_slice() {
        return Err(BindingError::ReportDataMismatch);
    }
    key.verify_strict(
        &pop_message(urn, nonce, raw_quote)?,
        &Signature::from_bytes(pop_sig),
    )
    .map_err(|_| BindingError::InvalidPop)?;
    Ok(member_did(member_pk))
}

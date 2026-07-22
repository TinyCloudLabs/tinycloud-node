//! Cryptographic primitives for the exact-email claim verifier.
//!
//! This module deliberately contains no HTTP, persistence, or authorization
//! decision.  It authenticates a credential/proof and returns bounded evidence
//! for the node authority kernel to evaluate.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{
    de::{MapAccess, Visitor},
    Deserialize,
};
use serde_json::{Map, Number, Value};
use std::{cmp::Ordering, collections::BTreeMap, fmt};
use thiserror::Error;

pub const EMAIL_VCT: &str = "opencredentials.email/v1";
pub const OPEN_CREDENTIALS_ISSUER_DID: &str = "did:web:issuer.credentials.org";
pub const EDDSA: &str = "EdDSA";
pub const SD_ALG: &str = "sha-256";
pub const HOLDER_BINDING_DOMAIN: &str = "xyz.tinycloud.share/email-claim-holder-binding/v1\0";
pub const HOLDER_BINDING_NAME: &str = "holderBinding";
pub const HOLDER_BINDING_TYPE: &str = "TinyCloudEmailClaimHolderBinding";
pub const MAX_CREDENTIAL_BYTES: usize = 65_536;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvidenceError {
    #[error("invalid evidence")]
    Invalid,
    #[error("untrusted issuer")]
    UntrustedIssuer,
    #[error("issuer key is ambiguous")]
    AmbiguousIssuerKey,
    #[error("issuer key is disabled")]
    DisabledIssuerKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("invalid holder proof")]
    InvalidHolderProof,
    #[error("credential is not active")]
    CredentialNotActive,
    #[error("credential is expired")]
    CredentialExpired,
    #[error("credential subject mismatch")]
    SubjectMismatch,
    #[error("email mismatch")]
    EmailMismatch,
    #[error("scope mismatch")]
    ScopeMismatch,
    #[error("holder equation mismatch")]
    HolderEquationMismatch,
    #[error("unsupported cryptography")]
    UnsupportedCryptography,
}

/// A single operator-authorized issuer key.  Trust is an exact tuple; a key
/// is never selected by issuer DID alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerKey {
    pub issuer_did: String,
    pub vct: String,
    pub key_version: u64,
    pub kid: String,
    pub public_key: [u8; 32],
    pub enabled: bool,
}

impl IssuerKey {
    pub fn new(
        issuer_did: impl Into<String>,
        vct: impl Into<String>,
        key_version: u64,
        kid: impl Into<String>,
        public_key: [u8; 32],
    ) -> Self {
        Self {
            issuer_did: issuer_did.into(),
            vct: vct.into(),
            key_version,
            kid: kid.into(),
            public_key,
            enabled: true,
        }
    }
}

/// In-memory representation of the operator's authenticated trust registry.
/// Production composition supplies this from configuration/attestation and
/// replaces it on rotation; it is not an authority or revocation database.
#[derive(Clone, Debug, Default)]
pub struct IssuerTrustRegistry {
    keys: BTreeMap<(String, String, String), IssuerKey>,
}

impl IssuerTrustRegistry {
    pub fn new(keys: impl IntoIterator<Item = IssuerKey>) -> Result<Self, EvidenceError> {
        let mut registry = Self::default();
        for key in keys {
            registry.insert(key)?;
        }
        Ok(registry)
    }

    pub fn insert(&mut self, key: IssuerKey) -> Result<(), EvidenceError> {
        if key.issuer_did.is_empty()
            || key.vct != EMAIL_VCT
            || key.kid.is_empty()
            || key.key_version == 0
            || key.kid.split('#').count() != 2
        {
            return Err(EvidenceError::Invalid);
        }
        let lookup = (key.issuer_did.clone(), key.vct.clone(), key.kid.clone());
        if let Some(previous) = self.keys.get(&lookup) {
            if key.key_version <= previous.key_version {
                return Err(EvidenceError::Invalid);
            }
        }
        self.keys.insert(lookup, key);
        Ok(())
    }

    pub fn remove(&mut self, issuer_did: &str, vct: &str, kid: &str) -> bool {
        self.keys
            .remove(&(issuer_did.to_owned(), vct.to_owned(), kid.to_owned()))
            .is_some()
    }

    pub fn disable(&mut self, issuer_did: &str, vct: &str, kid: &str) -> bool {
        self.keys
            .get_mut(&(issuer_did.to_owned(), vct.to_owned(), kid.to_owned()))
            .map(|key| key.enabled = false)
            .is_some()
    }

    /// Replace the active key in one explicit operation.  The old tuple is
    /// disabled before the new tuple is exposed, so a rotation can never
    /// create an ambiguous verification set.
    pub fn rotate(
        &mut self,
        issuer_did: &str,
        vct: &str,
        old_kid: &str,
        new_key: IssuerKey,
    ) -> Result<(), EvidenceError> {
        if new_key.issuer_did != issuer_did
            || new_key.vct != vct
            || new_key.key_version
                <= self
                    .keys
                    .get(&(issuer_did.to_owned(), vct.to_owned(), old_kid.to_owned()))
                    .ok_or(EvidenceError::UntrustedIssuer)?
                    .key_version
        {
            return Err(EvidenceError::Invalid);
        }
        self.disable(issuer_did, vct, old_kid);
        self.insert(new_key)
    }

    fn active_key(&self, issuer_did: &str, vct: &str) -> Result<&IssuerKey, EvidenceError> {
        let mut keys = self
            .keys
            .values()
            .filter(|key| key.issuer_did == issuer_did && key.vct == vct && key.enabled);
        let first = match keys.next() {
            Some(key) => key,
            None if self
                .keys
                .values()
                .any(|key| key.issuer_did == issuer_did && key.vct == vct) =>
            {
                return Err(EvidenceError::DisabledIssuerKey)
            }
            None => return Err(EvidenceError::UntrustedIssuer),
        };
        if keys.next().is_some() {
            return Err(EvidenceError::AmbiguousIssuerKey);
        }
        Ok(first)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialScope<'a> {
    pub share_cid: &'a str,
    pub share_id: &'a str,
    pub policy_cid: &'a str,
    pub node_audience: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerificationTime {
    pub evaluation_time: i64,
    pub clock_skew_seconds: i64,
    pub expected_expiry: Option<i64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedEmailEvidence {
    pub issuer_did: String,
    pub issuer_kid: String,
    pub credential_subject: String,
    pub disclosed_email: String,
    pub credential_digest: [u8; 32],
    pub expires_at: i64,
}

pub fn normalize_email(input: &str) -> Result<String, EvidenceError> {
    if !input.is_ascii() || input.len() > 254 {
        return Err(EvidenceError::Invalid);
    }
    let (local, domain) = input.split_once('@').ok_or(EvidenceError::Invalid)?;
    if local.is_empty()
        || local.len() > 64
        || domain.is_empty()
        || domain.len() > 253
        || input.matches('@').count() != 1
        || local.starts_with('.')
        || local.ends_with('.')
        || local.contains("..")
        || !local
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&byte))
    {
        return Err(EvidenceError::Invalid);
    }
    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(EvidenceError::Invalid);
        }
    }
    Ok(format!("{local}@{}", domain.to_ascii_lowercase()))
}

pub fn normalized_email_hash(input: &str) -> Result<String, EvidenceError> {
    Ok(URL_SAFE_NO_PAD.encode(sha256(normalize_email(input)?.as_bytes())))
}

pub fn verify_sd_jwt(
    credential: &[u8],
    registry: &IssuerTrustRegistry,
    expected_scope: &CredentialScope<'_>,
    expected_holder: &str,
    expected_email: &str,
    expected_issuer: &str,
    time: VerificationTime,
) -> Result<VerifiedEmailEvidence, EvidenceError> {
    if credential.is_empty() || credential.len() > MAX_CREDENTIAL_BYTES {
        return Err(EvidenceError::Invalid);
    }
    let credential_text = std::str::from_utf8(credential).map_err(|_| EvidenceError::Invalid)?;
    let parts: Vec<_> = credential_text.split('~').collect();
    if parts.len() != 3 || !parts[2].is_empty() || parts[1].is_empty() {
        return Err(EvidenceError::Invalid);
    }
    let jwt: Vec<_> = parts[0].split('.').collect();
    if jwt.len() != 3 || jwt.iter().any(|part| part.is_empty()) {
        return Err(EvidenceError::Invalid);
    }
    let header = decode_json(jwt[0])?;
    let header = exact_object(&header)?;
    if header.len() != 1 || header.get("alg").and_then(Value::as_str) != Some(EDDSA) {
        return Err(EvidenceError::UnsupportedCryptography);
    }
    let payload = decode_json(jwt[1])?;
    let payload = exact_object(&payload)?;
    let issuer = required_string(payload, "iss")?;
    let subject = required_string(payload, "sub")?;
    if subject != expected_holder {
        return Err(EvidenceError::SubjectMismatch);
    }
    let vct = required_string(payload, "vct")?;
    if vct != EMAIL_VCT {
        return Err(EvidenceError::Invalid);
    }
    if issuer != expected_issuer {
        return Err(EvidenceError::UntrustedIssuer);
    }
    let issuer_key = registry.active_key(issuer, vct)?;
    let signing_input = format!("{}.{}", jwt[0], jwt[1]);
    let signature = decode_exact_b64(jwt[2], 64)?;
    verify_ed25519(&issuer_key.public_key, signing_input.as_bytes(), &signature)?;

    let expected_claims = [
        "iss",
        "sub",
        "iat",
        "nbf",
        "exp",
        "jti",
        "vct",
        "tinycloud_share",
        "_sd_alg",
        "_sd",
    ];
    require_exact_keys(payload, &expected_claims)?;
    if required_string(payload, "_sd_alg")? != SD_ALG {
        return Err(EvidenceError::Invalid);
    }
    let scope = exact_object(
        payload
            .get("tinycloud_share")
            .ok_or(EvidenceError::Invalid)?,
    )?;
    require_exact_keys(
        scope,
        &["share_cid", "share_id", "policy_cid", "node_audience"],
    )?;
    if required_string(scope, "share_cid")? != expected_scope.share_cid
        || required_string(scope, "share_id")? != expected_scope.share_id
        || required_string(scope, "policy_cid")? != expected_scope.policy_cid
        || required_string(scope, "node_audience")? != expected_scope.node_audience
    {
        return Err(EvidenceError::ScopeMismatch);
    }
    let sd = payload
        .get("_sd")
        .and_then(Value::as_array)
        .ok_or(EvidenceError::Invalid)?;
    if sd.len() != 1 {
        return Err(EvidenceError::Invalid);
    }
    let disclosure = decode_json(parts[1])?;
    let disclosure = disclosure.as_array().ok_or(EvidenceError::Invalid)?;
    if disclosure.len() != 3
        || disclosure[0].as_str().is_none()
        || disclosure[1].as_str() != Some("email")
    {
        return Err(EvidenceError::Invalid);
    }
    let salt = disclosure[0].as_str().ok_or(EvidenceError::Invalid)?;
    let disclosed = disclosure[2].as_str().ok_or(EvidenceError::Invalid)?;
    let _ = decode_exact_b64(salt, 16)?;
    let digest = sha256(parts[1].as_bytes());
    if URL_SAFE_NO_PAD.encode(digest) != sd[0].as_str().ok_or(EvidenceError::Invalid)? {
        return Err(EvidenceError::Invalid);
    }
    let normalized_disclosed = normalize_email(disclosed)?;
    let normalized_expected = normalize_email(expected_email)?;
    if normalized_disclosed != normalized_expected {
        return Err(EvidenceError::EmailMismatch);
    }
    let iat = required_integer(payload, "iat")?;
    let nbf = required_integer(payload, "nbf")?;
    let exp = required_integer(payload, "exp")?;
    if iat < 0 || nbf < 0 || exp < 0 || iat > nbf || nbf >= exp {
        return Err(EvidenceError::Invalid);
    }
    let Some(latest_allowed) = time.evaluation_time.checked_add(time.clock_skew_seconds) else {
        return Err(EvidenceError::CredentialNotActive);
    };
    let Some(earliest_allowed_expiry) = time.evaluation_time.checked_sub(time.clock_skew_seconds)
    else {
        return Err(EvidenceError::CredentialNotActive);
    };
    if time.clock_skew_seconds < 0 || iat > latest_allowed || nbf > latest_allowed {
        return Err(EvidenceError::CredentialNotActive);
    }
    if exp <= earliest_allowed_expiry {
        return Err(EvidenceError::CredentialExpired);
    }
    if time.expected_expiry.is_some_and(|expected| expected != exp) {
        return Err(EvidenceError::CredentialExpired);
    }
    let _ = required_string(payload, "jti")?;
    Ok(VerifiedEmailEvidence {
        issuer_did: issuer.to_owned(),
        issuer_kid: issuer_key.kid.clone(),
        credential_subject: subject.to_owned(),
        disclosed_email: normalized_disclosed,
        credential_digest: sha256(credential),
        expires_at: exp,
    })
}

/// Verify a frozen `holderBinding` artifact and return its authenticated
/// message.  The caller binds the returned fields to its request and lets
/// #117 decide whether a policy session/read is authorized.
pub fn verify_holder_binding_artifact(
    artifact: &[u8],
    expected_holder: &str,
) -> Result<Value, EvidenceError> {
    let value = parse_strict_json(artifact)?;
    let object = exact_object(&value)?;
    require_exact_keys(
        object,
        &[
            "name",
            "domain",
            "signerDid",
            "message",
            "jcs",
            "messageDigest",
            "signedBytesDigest",
            "signatureDigest",
            "signature",
        ],
    )?;
    if required_string(object, "name")? != HOLDER_BINDING_NAME
        || required_string(object, "domain")? != HOLDER_BINDING_DOMAIN
        || required_string(object, "signerDid")? != expected_holder
    {
        return Err(EvidenceError::HolderEquationMismatch);
    }
    let signer = required_string(object, "signerDid")?;
    let public_key = did_key_public_key(signer)?;
    let message = object.get("message").ok_or(EvidenceError::Invalid)?;
    let canonical = jcs(message)?;
    if required_string(object, "jcs")?.as_bytes() != canonical.as_slice()
        || required_string(object, "messageDigest")? != URL_SAFE_NO_PAD.encode(sha256(&canonical))
    {
        return Err(EvidenceError::InvalidHolderProof);
    }
    let domain = required_string(object, "domain")?;
    let signed = [domain.as_bytes(), canonical.as_slice()].concat();
    if required_string(object, "signedBytesDigest")? != URL_SAFE_NO_PAD.encode(sha256(&signed)) {
        return Err(EvidenceError::InvalidHolderProof);
    }
    let signature = exact_object(object.get("signature").ok_or(EvidenceError::Invalid)?)?;
    require_exact_keys(signature, &["alg", "kid", "value"])?;
    if required_string(signature, "alg")? != EDDSA
        || required_string(signature, "kid")? != canonical_kid(signer)?
    {
        return Err(EvidenceError::InvalidHolderProof);
    }
    let signature_bytes = decode_exact_b64(required_string(signature, "value")?, 64)?;
    if required_string(object, "signatureDigest")?
        != URL_SAFE_NO_PAD.encode(sha256(&signature_bytes))
    {
        return Err(EvidenceError::InvalidHolderProof);
    }
    verify_ed25519(&public_key, &signed, &signature_bytes)?;
    Ok(message.clone())
}

pub fn enforce_holder_equation(values: [&str; 5]) -> Result<&str, EvidenceError> {
    let first = values[0];
    if values.iter().all(|value| *value == first) && did_key_public_key(first).is_ok() {
        Ok(first)
    } else {
        Err(EvidenceError::HolderEquationMismatch)
    }
}

fn verify_ed25519(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8],
) -> Result<(), EvidenceError> {
    if !canonical_signature_s(signature) {
        return Err(EvidenceError::InvalidSignature);
    }
    let key = crate::ssi::jwk::JWK {
        public_key_use: Some("sig".into()),
        key_operations: Some(vec!["verify".into()]),
        algorithm: Some(crate::ssi::jwk::Algorithm::EdDSA),
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        params: crate::ssi::jwk::Params::OKP(crate::ssi::jwk::OctetParams {
            curve: "Ed25519".into(),
            public_key: crate::ssi::jwk::Base64urlUInt(public_key.to_vec()),
            private_key: None,
        }),
    };
    crate::ssi::claims::jws::verify_bytes(
        crate::ssi::jwk::Algorithm::EdDSA,
        message,
        &key,
        signature,
    )
    .map_err(|_| EvidenceError::InvalidSignature)
}

/// Verify an Ed25519 signature for a caller-selected, already
/// domain-separated byte string. This reuses the same canonical signature and
/// SSI verification path as the holder-binding verifier.
pub fn verify_detached_ed25519(
    signer_did: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<(), EvidenceError> {
    let public_key = did_key_public_key(signer_did)?;
    verify_ed25519(&public_key, message, signature)
}

fn did_key_public_key(did: &str) -> Result<[u8; 32], EvidenceError> {
    let encoded = did
        .strip_prefix("did:key:z")
        .ok_or(EvidenceError::Invalid)?;
    let (_, bytes) = crate::ipld_core::cid::multibase::decode(format!("z{encoded}"))
        .map_err(|_| EvidenceError::Invalid)?;
    if bytes.len() != 34 || bytes[..2] != [0xed, 0x01] {
        return Err(EvidenceError::Invalid);
    }
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[2..]);
    Ok(key)
}

fn canonical_kid(did: &str) -> Result<String, EvidenceError> {
    let fragment = did.strip_prefix("did:key:").ok_or(EvidenceError::Invalid)?;
    Ok(format!("{did}#{fragment}"))
}

fn canonical_signature_s(signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];
    signature[32..].iter().rev().cmp(L.iter().rev()) == Ordering::Less
}

fn decode_exact_b64(value: &str, length: usize) -> Result<Vec<u8>, EvidenceError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| EvidenceError::Invalid)?;
    if bytes.len() != length || URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(EvidenceError::Invalid);
    }
    Ok(bytes)
}

fn decode_json(encoded: &str) -> Result<Value, EvidenceError> {
    let bytes = decode_b64(encoded)?;
    parse_strict_json(&bytes)
}

fn decode_b64(value: &str) -> Result<Vec<u8>, EvidenceError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| EvidenceError::Invalid)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != value {
        return Err(EvidenceError::Invalid);
    }
    Ok(bytes)
}

fn parse_strict_json(bytes: &[u8]) -> Result<Value, EvidenceError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue::deserialize(&mut deserializer)
        .map_err(|_| EvidenceError::Invalid)?
        .0;
    deserializer.end().map_err(|_| EvidenceError::Invalid)?;
    Ok(value)
}

struct StrictValue(Value);

impl<'de> serde::Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("strict JSON")
            }
            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }
            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }
            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(Number::from(value))))
            }
            fn visit_f64<E>(self, _: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Err(E::custom("fractional JSON is not accepted"))
            }
            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.into())))
            }
            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }
            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = seq.next_element::<StrictValue>()? {
                    values.push(value.0);
                }
                Ok(StrictValue(Value::Array(values)))
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some((key, value)) = map.next_entry::<String, StrictValue>()? {
                    if values.insert(key, value.0).is_some() {
                        return Err(serde::de::Error::custom("duplicate JSON member"));
                    }
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }
        deserializer.deserialize_any(StrictVisitor)
    }
}

fn exact_object(value: &Value) -> Result<&Map<String, Value>, EvidenceError> {
    value.as_object().ok_or(EvidenceError::Invalid)
}

fn require_exact_keys(object: &Map<String, Value>, expected: &[&str]) -> Result<(), EvidenceError> {
    if object.len() != expected.len() || object.keys().any(|key| !expected.contains(&key.as_str()))
    {
        return Err(EvidenceError::Invalid);
    }
    Ok(())
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a str, EvidenceError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .ok_or(EvidenceError::Invalid)
}

fn required_integer(object: &Map<String, Value>, key: &str) -> Result<i64, EvidenceError> {
    let number = object
        .get(key)
        .and_then(Value::as_number)
        .ok_or(EvidenceError::Invalid)?;
    let value = number.as_i64().ok_or(EvidenceError::Invalid)?;
    if value.unsigned_abs() > 9_007_199_254_740_991 {
        return Err(EvidenceError::Invalid);
    }
    Ok(value)
}

fn sha256(bytes: impl AsRef<[u8]>) -> [u8; 32] {
    crate::ssi::crypto::hashes::sha256::sha256(bytes.as_ref())
}

fn jcs(value: &Value) -> Result<Vec<u8>, EvidenceError> {
    let mut output = Vec::new();
    write_jcs(value, &mut output)?;
    Ok(output)
}

fn write_jcs(value: &Value, output: &mut Vec<u8>) -> Result<(), EvidenceError> {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(number) => {
            if number.as_i64().is_none()
                || number
                    .as_i64()
                    .is_some_and(|value| value.unsigned_abs() > 9_007_199_254_740_991)
            {
                return Err(EvidenceError::Invalid);
            }
            output.extend_from_slice(number.to_string().as_bytes());
        }
        Value::String(value) => output.extend_from_slice(
            serde_json::to_string(value)
                .map_err(|_| EvidenceError::Invalid)?
                .as_bytes(),
        ),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_jcs(value, output)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            let mut entries: Vec<_> = values.iter().collect();
            entries.sort_by(|(left, _), (right, _)| utf16_cmp(left, right));
            output.push(b'{');
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                output.extend_from_slice(
                    serde_json::to_string(key)
                        .map_err(|_| EvidenceError::Invalid)?
                        .as_bytes(),
                );
                output.push(b':');
                write_jcs(value, output)?;
            }
            output.push(b'}');
        }
    }
    Ok(())
}

fn utf16_cmp(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_normalization_preserves_local_and_only_lowercases_domain() {
        assert_eq!(
            normalize_email("Alice+Notes@EXAMPLE.COM").unwrap(),
            "Alice+Notes@example.com"
        );
        assert!(normalize_email(" Alice@example.com").is_err());
        assert!(normalize_email("a..b@example.com").is_err());
        assert!(normalize_email("a@example..com").is_err());
    }

    #[test]
    fn holder_kid_is_derived_from_the_did_key_fragment() {
        let did = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";
        assert_eq!(
            canonical_kid(did).unwrap(),
            format!("{did}#z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw")
        );
    }

    #[test]
    fn jcs_sorts_by_utf16_code_units() {
        let value = serde_json::json!({"\u{e000}": 1, "\u{10000}": 2});
        assert_eq!(
            String::from_utf8(jcs(&value).unwrap()).unwrap(),
            "{\"𐀀\":2,\"\":1}"
        );
    }

    #[test]
    fn issuer_rotation_and_trust_removal_are_fail_closed() {
        let issuer = OPEN_CREDENTIALS_ISSUER_DID;
        let kid_one = "did:web:issuer.credentials.org#email-signing-key-1";
        let kid_two = "did:web:issuer.credentials.org#email-signing-key-2";
        let mut registry =
            IssuerTrustRegistry::new([IssuerKey::new(issuer, EMAIL_VCT, 1, kid_one, [1; 32])])
                .unwrap();
        registry
            .rotate(
                issuer,
                EMAIL_VCT,
                kid_one,
                IssuerKey::new(issuer, EMAIL_VCT, 2, kid_two, [2; 32]),
            )
            .unwrap();
        assert_eq!(registry.active_key(issuer, EMAIL_VCT).unwrap().kid, kid_two);
        assert!(registry.disable(issuer, EMAIL_VCT, kid_two));
        assert_eq!(
            registry.active_key(issuer, EMAIL_VCT),
            Err(EvidenceError::DisabledIssuerKey)
        );
        assert!(registry.remove(issuer, EMAIL_VCT, kid_two));
        assert_eq!(
            registry.active_key(issuer, EMAIL_VCT),
            Err(EvidenceError::DisabledIssuerKey)
        );
        assert!(registry.remove(issuer, EMAIL_VCT, kid_one));
        assert_eq!(
            registry.active_key(issuer, EMAIL_VCT),
            Err(EvidenceError::UntrustedIssuer)
        );
    }
}

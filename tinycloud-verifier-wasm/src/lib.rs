extern crate alloc;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::str::FromStr;
use futures::executor::block_on;
use multibase::decode as multibase_decode;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudInvocation},
    cacaos::siwe_cacao::{SIWEPayloadConversionError, SiweCacao},
    identity::{did_principal_matches, principal_did},
    ipld_core::cid::{multibase::Base, Cid},
    multihash_codetable::{Code, MultihashDigest},
    resource::{ResourceId, SpaceId},
    siwe_recap::Capability as SiweRecapCapability,
    ssi::{
        claims::jws::verify_bytes,
        jwk::{Base64urlUInt, OctetParams, Params, JWK},
        ucan::TimeInvalid,
    },
};
use wasm_bindgen::prelude::*;

const RAW_CODEC: u64 = 0x55;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelegationKind {
    Cacao,
    Ucan,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityGrant {
    pub resource: String,
    pub action: String,
    #[serde(default)]
    pub caveats: BTreeMap<String, serde_json::Value>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationVerdict {
    pub ok: bool,
    pub kind: DelegationKind,
    pub issuer: String,
    pub audience: String,
    pub capabilities: Vec<CapabilityGrant>,
    pub proof_cids: Vec<String>,
    pub issued_at: Option<String>,
    pub not_before: Option<String>,
    pub expires_at: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationVerdict {
    pub authorized: bool,
    pub delegation: DelegationVerdict,
    pub expected_resource: String,
    pub expected_action: String,
    pub matched_capability: CapabilityGrant,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerificationErrorKind {
    Decode,
    InvalidSignature,
    InvalidTime,
    InvalidStatement,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationError {
    pub kind: VerificationErrorKind,
    pub message: String,
}

impl VerificationError {
    fn decode(message: impl Into<String>) -> Self {
        Self {
            kind: VerificationErrorKind::Decode,
            message: message.into(),
        }
    }

    fn invalid_signature(message: impl Into<String>) -> Self {
        Self {
            kind: VerificationErrorKind::InvalidSignature,
            message: message.into(),
        }
    }

    fn invalid_time(message: impl Into<String>) -> Self {
        Self {
            kind: VerificationErrorKind::InvalidTime,
            message: message.into(),
        }
    }

    fn invalid_statement(message: impl Into<String>) -> Self {
        Self {
            kind: VerificationErrorKind::InvalidStatement,
            message: message.into(),
        }
    }
}

fn js_value<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|error| error.to_string().into())
}

fn js_error(error: &VerificationError) -> JsValue {
    serde_wasm_bindgen::to_value(error).unwrap_or_else(|_| {
        JsValue::from_str(&format!("{}: {}", error.kind.as_str(), error.message))
    })
}

impl VerificationErrorKind {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Decode => "decode",
            Self::InvalidSignature => "invalid-signature",
            Self::InvalidTime => "invalid-time",
            Self::InvalidStatement => "invalid-statement",
        }
    }
}

fn canonical_principal_or_uri(value: &str) -> String {
    principal_did(value).unwrap_or_else(|_| value.split('#').next().unwrap_or(value).to_string())
}

fn offset_datetime_from_seconds(seconds: f64) -> Result<OffsetDateTime, VerificationError> {
    OffsetDateTime::from_unix_timestamp_nanos((seconds * 1_000_000_000.0) as i128)
        .map_err(|error| VerificationError::invalid_time(error.to_string()))
}

fn offset_datetime_to_rfc3339(datetime: &OffsetDateTime) -> String {
    datetime
        .format(&time::format_description::well_known::Rfc3339)
        .expect("RFC3339 formatting is infallible for OffsetDateTime")
}

fn numeric_date_to_rfc3339(seconds: f64) -> Result<String, VerificationError> {
    Ok(offset_datetime_to_rfc3339(&offset_datetime_from_seconds(
        seconds,
    )?))
}

fn time_to_rfc3339(time: &OffsetDateTime) -> String {
    offset_datetime_to_rfc3339(time)
}

fn cid_to_b58(cid: &Cid) -> String {
    cid.to_string_of_base(Base::Base58Btc)
        .expect("cid base58btc encoding should not fail")
}

fn resource_extends(granted: &str, required: &str) -> bool {
    let Ok(granted) = ResourceId::from_str(granted) else {
        return false;
    };
    let Ok(required) = ResourceId::from_str(required) else {
        return false;
    };
    required.extends(&granted).is_ok()
}

// TC-482: a capability's resource URI is not always a TinyCloud `tinycloud:`
// ResourceId. Every default (no-manifest) SDK sign-in requests an encryption
// network grant alongside kv/sql/duckdb/capabilities/hooks
// (NodeUserAuthorization.resolveSignInCapabilities's `rawAbilities` -
// packages/node-sdk/src/authorization/NodeUserAuthorization.ts), whose
// resource is a `urn:tinycloud:encryption:<ownerDid>:<network>` NetworkId
// URN, not a ResourceId.
//
// tinycloud-core's own capability extraction is infallible over resource
// shape: `Resource::from(UriString)` (tinycloud-core/src/types/resource.rs)
// tries ResourceId first and falls back to `Resource::Other(uri)` - an
// opaque, verbatim URI - rather than rejecting the delegation. That is the
// contract of record (tinycloud-core/src/util.rs's extract_siwe_cap /
// extract_ucan_caps both call it unconditionally, never erroring on
// resource shape). The WASM verifier's extract_recap_capabilities /
// extract_ucan_capabilities previously required every resource to parse as
// a ResourceId and threw `Decode: Incorrect Structure` otherwise, rejecting
// a session shape the Rust node accepts every day - failing every default
// full-permission sign-in against a WASM-verifying node with an opaque 500
// once cf-node's own error mapping is fixed. Mirror the Rust fallback
// exactly: canonicalize when the resource IS a TinyCloud ResourceId (which
// also gets EIP-55 checksum normalization "for free" from ResourceId's
// Display), and pass any other URI through unchanged otherwise. This does
// not affect resource_extends()/resource_path_contains() above: an
// unparseable-as-ResourceId resource still can never `extend` or contain a
// TinyCloud ResourceId, so a non-TinyCloud capability grant remains inert
// for every KV/SQL/etc containment check - it is carried through the
// verdict for callers that understand its own extension semantics (e.g. a
// caller matching NetworkId URNs directly), not silently authorized against
// TinyCloud resources.
fn canonicalize_capability_resource(resource: &str) -> String {
    ResourceId::from_str(resource)
        .map(|id| id.to_string())
        .unwrap_or_else(|_| resource.to_string())
}

fn verify_header_bytes(bytes: &[u8]) -> Result<TinyCloudDelegation, VerificationError> {
    TinyCloudDelegation::from_bytes(bytes)
        .map_err(|error| VerificationError::decode(error.to_string()))
}

fn verify_header_text(encoded: &str) -> Result<TinyCloudDelegation, VerificationError> {
    <TinyCloudDelegation as HeaderEncode>::decode(encoded)
        .map(|(delegation, _)| delegation)
        .map_err(|error| VerificationError::decode(error.to_string()))
}

fn extract_ucan_capabilities(
    capabilities: &tinycloud_auth::ucan_capabilities_object::Capabilities<serde_json::Value>,
) -> Result<Vec<CapabilityGrant>, VerificationError> {
    let mut grants = Vec::new();
    for (resource, abilities) in capabilities.abilities() {
        let resource = canonicalize_capability_resource(resource.as_str());
        for (action, caveat_collection) in abilities.iter() {
            let mut caveats = BTreeMap::new();
            for (index, note_bene) in caveat_collection.as_ref().iter().enumerate() {
                let value = serde_json::to_value(note_bene)
                    .map_err(|error| VerificationError::decode(error.to_string()))?;
                caveats.insert(index.to_string(), value);
            }
            grants.push(CapabilityGrant {
                resource: resource.clone(),
                action: action.to_string(),
                caveats,
            });
        }
    }
    Ok(grants)
}

fn extract_recap_capabilities(
    capability: SiweRecapCapability<serde_json::Value>,
) -> Result<(Vec<CapabilityGrant>, Vec<Cid>), VerificationError> {
    let (caps, proofs) = capability.into_inner();
    let mut grants = Vec::new();
    for (resource, abilities) in caps.into_inner() {
        let resource = canonicalize_capability_resource(resource.as_str());
        // Mirror extract_ucan_capabilities exactly: a ReCap ability's note-bene
        // collection is the caveat set. `Caveats<T>` deserialization already
        // normalizes the spec's mandatory-but-meaningless `[{}]` sentinel down
        // to an empty Vec (ucan-capabilities-object's caveats.rs), so an empty
        // `caveats` map here is a genuine absence of restriction, and any
        // non-empty map is a real, signed restriction that callers must not
        // discard.
        for (action, caveat_collection) in abilities.into_iter() {
            let mut caveats = BTreeMap::new();
            for (index, note_bene) in caveat_collection.into_inner().into_iter().enumerate() {
                let value = serde_json::to_value(note_bene)
                    .map_err(|error| VerificationError::decode(error.to_string()))?;
                caveats.insert(index.to_string(), value);
            }
            grants.push(CapabilityGrant {
                resource: resource.clone(),
                action: action.to_string(),
                caveats,
            });
        }
    }
    Ok((grants, proofs))
}

fn verify_ucan(
    ucan: &TinyCloudInvocation,
    now_seconds: f64,
) -> Result<DelegationVerdict, VerificationError> {
    verify_ucan_signature_offline(ucan)?;
    ucan.payload()
        .validate_time(Some(now_seconds))
        .map_err(|error| match error {
            TimeInvalid::TooEarly | TimeInvalid::TooLate => {
                VerificationError::invalid_time(error.to_string())
            }
        })?;

    Ok(DelegationVerdict {
        ok: true,
        kind: DelegationKind::Ucan,
        issuer: canonical_principal_or_uri(ucan.payload().issuer.as_str()),
        audience: canonical_principal_or_uri(ucan.payload().audience.as_str()),
        capabilities: extract_ucan_capabilities(&ucan.payload().attenuation)?,
        proof_cids: ucan.payload().proof.iter().map(cid_to_b58).collect(),
        issued_at: None,
        not_before: ucan
            .payload()
            .not_before
            .map(|ts| numeric_date_to_rfc3339(ts.as_seconds()))
            .transpose()?,
        expires_at: Some(numeric_date_to_rfc3339(
            ucan.payload().expiration.as_seconds(),
        )?),
    })
}

fn did_key_ed25519_jwk(did: &str) -> Result<JWK, VerificationError> {
    let did = canonical_principal_or_uri(did);
    let method_specific_id = did
        .strip_prefix("did:key:")
        .ok_or_else(|| VerificationError::invalid_signature("UCAN issuer must be did:key"))?;
    let (_base, data) = multibase_decode(method_specific_id)
        .map_err(|error| VerificationError::invalid_signature(error.to_string()))?;
    if data.len() != 34 || data[0] != 0xed || data[1] != 0x01 {
        return Err(VerificationError::invalid_signature(
            "UCAN issuer must be a did:key Ed25519 public key",
        ));
    }

    Ok(JWK {
        params: Params::OKP(OctetParams {
            curve: "Ed25519".to_string(),
            public_key: Base64urlUInt(data[2..].to_vec()),
            private_key: None,
        }),
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
    })
}

fn verify_ucan_signature_offline(ucan: &TinyCloudInvocation) -> Result<(), VerificationError> {
    let key = did_key_ed25519_jwk(ucan.payload().issuer.as_str())?;
    let encoded = ucan
        .encode()
        .map_err(|error| VerificationError::decode(error.to_string()))?;
    let signing_input = encoded
        .rsplit_once('.')
        .ok_or_else(|| VerificationError::decode("invalid UCAN JWT encoding"))?
        .0;

    verify_bytes(
        ucan.header().algorithm,
        signing_input.as_bytes(),
        &key,
        ucan.signature(),
    )
    .map_err(|error| VerificationError::invalid_signature(error.to_string()))
}

fn verify_cacao(
    cacao: &SiweCacao,
    now_seconds: f64,
) -> Result<DelegationVerdict, VerificationError> {
    let now = offset_datetime_from_seconds(now_seconds)?;
    block_on(cacao.verify())
        .map_err(|error| VerificationError::invalid_signature(error.to_string()))?;
    if !cacao.payload().valid_at(&now) {
        return Err(VerificationError::invalid_time(
            "CACAO validity window rejected the provided clock",
        ));
    }

    let message: tinycloud_auth::cacaos::siwe::Message = cacao
        .payload()
        .clone()
        .try_into()
        .map_err(|error: SIWEPayloadConversionError| {
            VerificationError::decode(error.to_string())
        })?;
    let maybe_recap = SiweRecapCapability::<serde_json::Value>::extract_and_verify(&message)
        .map_err(|error| VerificationError::invalid_statement(error.to_string()))?;
    let (capabilities, proofs) = match maybe_recap {
        Some(recap) => extract_recap_capabilities(recap)?,
        None => (Vec::new(), Vec::new()),
    };

    Ok(DelegationVerdict {
        ok: true,
        kind: DelegationKind::Cacao,
        issuer: canonical_principal_or_uri(cacao.payload().iss.as_str()),
        audience: canonical_principal_or_uri(cacao.payload().aud.as_str()),
        capabilities,
        proof_cids: proofs.iter().map(cid_to_b58).collect(),
        issued_at: Some(time_to_rfc3339(cacao.payload().iat.as_ref())),
        not_before: cacao
            .payload()
            .nbf
            .as_ref()
            .map(|ts| time_to_rfc3339(ts.as_ref())),
        expires_at: cacao
            .payload()
            .exp
            .as_ref()
            .map(|ts| time_to_rfc3339(ts.as_ref())),
    })
}

fn verify_delegation_inner(
    delegation: TinyCloudDelegation,
    now_seconds: f64,
) -> Result<DelegationVerdict, VerificationError> {
    match delegation {
        TinyCloudDelegation::Ucan(ucan) => verify_ucan(&ucan, now_seconds),
        TinyCloudDelegation::Cacao(cacao) => verify_cacao(&cacao, now_seconds),
    }
}

fn verify_invocation_inner(
    delegation: TinyCloudDelegation,
    expected_resource: &str,
    expected_action: &str,
    now_seconds: f64,
) -> Result<InvocationVerdict, VerificationError> {
    let verdict = verify_delegation_inner(delegation, now_seconds)?;
    let matched_capability = verdict
        .capabilities
        .iter()
        .find(|capability| {
            resource_path_contains(&capability.resource, expected_resource)
                && action_matches(&capability.action, expected_action)
        })
        .cloned()
        .ok_or_else(|| {
            VerificationError::invalid_statement(format!(
                "expected capability {expected_action} on {expected_resource} was not authorized"
            ))
        })?;

    Ok(InvocationVerdict {
        authorized: true,
        delegation: verdict,
        expected_resource: expected_resource.to_string(),
        expected_action: expected_action.to_string(),
        matched_capability,
    })
}

pub fn verify_delegation_bytes(
    bytes: &[u8],
    now_seconds: f64,
) -> Result<DelegationVerdict, VerificationError> {
    verify_delegation_inner(verify_header_bytes(bytes)?, now_seconds)
}

pub fn verify_delegation_text(
    encoded: &str,
    now_seconds: f64,
) -> Result<DelegationVerdict, VerificationError> {
    verify_delegation_inner(verify_header_text(encoded)?, now_seconds)
}

pub fn verify_invocation_bytes(
    bytes: &[u8],
    expected_resource: &str,
    expected_action: &str,
    now_seconds: f64,
) -> Result<InvocationVerdict, VerificationError> {
    verify_invocation_inner(
        verify_header_bytes(bytes)?,
        expected_resource,
        expected_action,
        now_seconds,
    )
}

pub fn extract_capabilities_bytes(
    bytes: &[u8],
    now_seconds: f64,
) -> Result<Vec<CapabilityGrant>, VerificationError> {
    Ok(verify_delegation_bytes(bytes, now_seconds)?.capabilities)
}

pub fn canonical_issuer_bytes(bytes: &[u8], now_seconds: f64) -> Result<String, VerificationError> {
    Ok(verify_delegation_bytes(bytes, now_seconds)?.issuer)
}

pub fn canonical_audience_bytes(
    bytes: &[u8],
    now_seconds: f64,
) -> Result<String, VerificationError> {
    Ok(verify_delegation_bytes(bytes, now_seconds)?.audience)
}

pub fn compute_proof_cid(data: &[u8]) -> String {
    let hash = Code::Blake3_256.digest(data);
    Cid::new_v1(RAW_CODEC, hash)
        .to_string_of_base(Base::Base58Btc)
        .expect("cid base58btc encoding should not fail")
}

pub fn resource_path_contains(granted_resource: &str, required_resource: &str) -> bool {
    resource_extends(granted_resource, required_resource)
}

pub fn action_matches(held: &str, required: &str) -> bool {
    tinycloud_auth::policy_capability::ability_matches(held, required)
}

/// TinyCloud-space root-authority check: does `delegator` match the DID that
/// owns `space_or_resource`'s space? Accepts either a bare `SpaceId` string
/// (`tinycloud:<suffix>:<name>`) or a full `ResourceId` string
/// (`tinycloud:<suffix>:<name>/<service>[/<path>]`) and extracts the space
/// either way.
///
/// This mirrors only the TinyCloud-space arm of core's `is_root_authority`
/// (`tinycloud-core/src/models/delegation.rs`) - the separate `NetworkId`
/// arm is deliberately out of scope for this export. Any non-TinyCloud
/// input, including a syntactically valid `NetworkId` URN
/// (`urn:tinycloud:encryption:...`), fails to parse as either `SpaceId` or
/// `ResourceId` here and returns `false`. Callers must not treat this as a
/// full port of `is_root_authority`.
pub fn space_root_authority_matches(space_or_resource: &str, delegator: &str) -> bool {
    if let Ok(space) = SpaceId::from_str(space_or_resource) {
        return did_principal_matches(space.did().as_str(), delegator);
    }
    if let Ok(resource) = ResourceId::from_str(space_or_resource) {
        return did_principal_matches(resource.space().did().as_str(), delegator);
    }
    false
}

#[wasm_bindgen(js_name = verifyDelegation)]
pub fn verify_delegation_wasm(bytes: &[u8], now_seconds: f64) -> Result<JsValue, JsValue> {
    match verify_delegation_bytes(bytes, now_seconds) {
        Ok(value) => js_value(&value),
        Err(error) => Err(js_error(&error)),
    }
}

#[wasm_bindgen(js_name = verifyInvocation)]
pub fn verify_invocation_wasm(
    bytes: &[u8],
    expected_resource: &str,
    expected_action: &str,
    now_seconds: f64,
) -> Result<JsValue, JsValue> {
    match verify_invocation_bytes(bytes, expected_resource, expected_action, now_seconds) {
        Ok(value) => js_value(&value),
        Err(error) => Err(js_error(&error)),
    }
}

#[wasm_bindgen(js_name = verifyDelegationText)]
pub fn verify_delegation_text_wasm(encoded: &str, now_seconds: f64) -> Result<JsValue, JsValue> {
    match verify_delegation_text(encoded, now_seconds) {
        Ok(value) => js_value(&value),
        Err(error) => Err(js_error(&error)),
    }
}

#[wasm_bindgen(js_name = extractCapabilities)]
pub fn extract_capabilities_wasm(bytes: &[u8], now_seconds: f64) -> Result<JsValue, JsValue> {
    match extract_capabilities_bytes(bytes, now_seconds) {
        Ok(value) => js_value(&value),
        Err(error) => Err(js_error(&error)),
    }
}

#[wasm_bindgen(js_name = canonicalIssuer)]
pub fn canonical_issuer_wasm(bytes: &[u8], now_seconds: f64) -> Result<String, JsValue> {
    canonical_issuer_bytes(bytes, now_seconds).map_err(|error| js_error(&error))
}

#[wasm_bindgen(js_name = canonicalAudience)]
pub fn canonical_audience_wasm(bytes: &[u8], now_seconds: f64) -> Result<String, JsValue> {
    canonical_audience_bytes(bytes, now_seconds).map_err(|error| js_error(&error))
}

#[wasm_bindgen(js_name = computeProofCid)]
pub fn compute_proof_cid_wasm(data: &[u8]) -> String {
    compute_proof_cid(data)
}

#[wasm_bindgen(js_name = resourcePathContains)]
pub fn resource_path_contains_wasm(granted_resource: String, required_resource: String) -> bool {
    resource_path_contains(&granted_resource, &required_resource)
}

#[wasm_bindgen(js_name = abilityMatches)]
pub fn action_matches_wasm(held: String, required: String) -> bool {
    action_matches(&held, &required)
}

#[wasm_bindgen(js_name = spaceRootAuthorityMatches)]
pub fn space_root_authority_matches_wasm(space_or_resource: String, delegator: String) -> bool {
    space_root_authority_matches(&space_or_resource, &delegator)
}

#[wasm_bindgen(js_name = didPrincipalMatches)]
pub fn did_principal_matches_wasm(a: String, b: String) -> bool {
    did_principal_matches(&a, &b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::FromHex;
    use serde::Deserialize;
    use std::iter::once;
    use tinycloud_auth::{
        authorization::{make_invocation_from_uris, InvocationOptions},
        cacaos::siwe_cacao::{Header as SiweHeader, Payload as SiwePayload},
        ipld_core::cid::multibase::Base as CidBase,
        resolver::DID_METHODS,
        ssi::jwk::JWK,
    };

    #[derive(Deserialize)]
    struct GoldenVectors {
        valid: Vec<GoldenVector>,
        invalid: Vec<GoldenVector>,
    }

    // Only the fields this offline verifier can actually evaluate are
    // deserialized; serde ignores the rest. The fixture also carries `nonce`,
    // `expected.status`, `expected.code` and `invalidReason`, which describe
    // node-level HTTP conformance outcomes (nonce replay, block digest
    // mismatch) that cannot be decided from a delegation alone — those belong
    // to the tc-bench node suite, not here. Deserializing them and never
    // asserting on them is exactly the unchecked-expectation pattern TC-381 is
    // about, so they are left out rather than silently carried.
    #[derive(Deserialize, Clone)]
    #[serde(rename_all = "camelCase")]
    struct GoldenVector {
        case: String,
        delegation_depth: usize,
        recap: Recap,
        operation: CapabilityOperation,
        proof_cids: Vec<String>,
        siwe: String,
        signature: String,
    }

    #[derive(Deserialize, Clone)]
    struct CapabilityOperation {
        path: String,
        action: String,
    }

    #[derive(Deserialize, Clone)]
    struct Recap {
        att: BTreeMap<String, BTreeMap<String, Vec<serde_json::Value>>>,
        prf: Vec<String>,
        statement: String,
        resource: String,
    }

    // TC-381: this used to `include_str!` five directories above the crate root,
    // into a sibling `tc-bench` checkout that only exists inside one particular
    // monorepo layout. That made this whole test target uncompilable in CI and
    // in a plain clone — and because `tinycloud-verifier-wasm` was absent from
    // the CI matrix, nothing ever noticed. The vectors are frozen, so the frozen
    // copy belongs beside the test that freezes them. Refresh by copying
    // `fixtures/golden-vectors.json` from the tc-bench repository.
    const GOLDEN_VECTORS: &str = include_str!("../tests/fixtures/golden-vectors.json");

    fn parse_golden() -> GoldenVectors {
        serde_json::from_str(GOLDEN_VECTORS).expect("golden vectors parse")
    }

    fn build_cacao(vector: &GoldenVector) -> SiweCacao {
        let message: tinycloud_auth::cacaos::siwe::Message =
            vector.siwe.parse().expect("siwe parses");
        let payload: SiwePayload = message.into();
        let signature = Vec::from_hex(vector.signature.trim_start_matches("0x"))
            .expect("hex signature")
            .try_into()
            .expect("65-byte signature");
        tinycloud_auth::cacaos::CACAO::new(payload, signature, SiweHeader)
    }

    fn mutate_signature(signature: &str) -> String {
        let mut chars: Vec<char> = signature.chars().collect();
        let last = chars.last_mut().expect("signature length");
        *last = if *last == '0' { '1' } else { '0' };
        chars.into_iter().collect()
    }

    #[test]
    fn verifiable_cacao_vectors_match_frozen_golden_vectors() {
        let golden = parse_golden();
        let now = OffsetDateTime::parse(
            "2025-01-01T00:00:00.000Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("frozen clock");

        for vector in &golden.valid {
            let cacao = build_cacao(vector);
            let raw = serde_ipld_dagcbor::to_vec(&cacao).expect("cacao encodes");
            let verdict = verify_delegation_bytes(&raw, now.unix_timestamp() as f64)
                .expect(vector.case.as_str());

            assert!(verdict.ok);
            assert_eq!(verdict.kind, DelegationKind::Cacao);
            assert_eq!(
                verdict.issuer,
                canonical_principal_or_uri(cacao.payload().iss.as_ref())
            );
            assert_eq!(
                verdict.audience,
                canonical_principal_or_uri(cacao.payload().aud.as_ref())
            );
            assert_eq!(verdict.capabilities.len(), 1, "{}", vector.case);
            assert_eq!(verdict.proof_cids, vector.proof_cids, "{}", vector.case);
            // The proof chain the verifier recovers must be exactly as deep as
            // the vector says it is, so a vector named "depth-8" cannot quietly
            // become a depth-1 delegation.
            assert_eq!(
                verdict.proof_cids.len(),
                vector.delegation_depth,
                "{}",
                vector.case
            );

            let capability = &verdict.capabilities[0];
            assert_eq!(
                capability.resource,
                *vector.recap.att.keys().next().expect("recap resource")
            );
            assert_eq!(capability.action, vector.operation.action);
            assert_eq!(vector.recap.prf, vector.proof_cids);
            assert!(vector.recap.statement.contains(&vector.operation.path));
            assert!(vector.recap.resource.starts_with("urn:recap:"));
        }
    }

    #[test]
    fn proof_cid_helper_matches_tc_bench_fixture() {
        let golden = parse_golden();
        for vector in &golden.valid {
            for (index, proof_cid) in vector.proof_cids.iter().enumerate() {
                let seed = format!("tc-bench-v1:{}:proof:{}", vector.case, index);
                assert_eq!(
                    compute_proof_cid(seed.as_bytes()),
                    proof_cid.as_str(),
                    "{}",
                    vector.case
                );
            }
        }
    }

    #[test]
    fn rejects_wrong_signature_and_expiry() {
        let golden = parse_golden();
        let valid = golden
            .valid
            .iter()
            .find(|vector| vector.case == "depth-1")
            .expect("depth-1 vector");
        let expired = golden
            .invalid
            .iter()
            .find(|vector| vector.case == "expired")
            .expect("expired vector");

        let cacao = build_cacao(valid);
        let raw = serde_ipld_dagcbor::to_vec(&cacao).expect("cacao encodes");
        let mut bad_signature = valid.signature.clone();
        bad_signature = mutate_signature(&bad_signature);
        let mut bad = valid.clone();
        bad.signature = bad_signature;
        let bad_cacao = build_cacao(&bad);
        let bad_raw = serde_ipld_dagcbor::to_vec(&bad_cacao).expect("bad cacao encodes");

        let now = OffsetDateTime::parse(
            "2025-01-01T00:00:00.000Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("frozen clock");
        let err = verify_delegation_bytes(&bad_raw, now.unix_timestamp() as f64)
            .expect_err("wrong signature");
        assert_eq!(err.kind, VerificationErrorKind::InvalidSignature);

        let expired_cacao = build_cacao(expired);
        let expired_raw =
            serde_ipld_dagcbor::to_vec(&expired_cacao).expect("expired cacao encodes");
        let err = verify_delegation_bytes(&expired_raw, now.unix_timestamp() as f64)
            .expect_err("expired");
        assert_eq!(err.kind, VerificationErrorKind::InvalidTime);

        let _ = raw;
    }

    #[test]
    fn resource_and_action_authorization_matches_core_semantics() {
        let golden = parse_golden();
        let vector = golden
            .valid
            .iter()
            .find(|vector| vector.case == "depth-1")
            .expect("depth-1 vector");
        let cacao = build_cacao(vector);
        let raw = serde_ipld_dagcbor::to_vec(&cacao).expect("cacao encodes");
        let now = OffsetDateTime::parse(
            "2025-01-01T00:00:00.000Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("frozen clock");
        let verdict = verify_delegation_bytes(&raw, now.unix_timestamp() as f64).expect("verdict");
        let grant = &verdict.capabilities[0];

        let requested_same = grant.resource.clone();
        assert!(resource_path_contains(&grant.resource, &requested_same));

        let widened_resource = format!("{}x", grant.resource);
        assert!(!resource_path_contains(&grant.resource, &widened_resource));
        assert!(action_matches(&grant.action, &grant.action));
        assert!(!action_matches(&grant.action, "tinycloud.kv/put"));

        let expected_resource = vector.recap.att.keys().next().expect("recap resource");
        let invocation_verdict = verify_invocation_bytes(
            &raw,
            expected_resource,
            &vector.operation.action,
            now.unix_timestamp() as f64,
        )
        .expect("invocation verdict");
        assert!(invocation_verdict.authorized);
        assert_eq!(invocation_verdict.expected_resource, *expected_resource);
        assert_eq!(invocation_verdict.expected_action, vector.operation.action);
        assert_eq!(
            invocation_verdict.matched_capability.resource,
            *expected_resource
        );
        assert_eq!(
            invocation_verdict.matched_capability.action,
            vector.operation.action
        );
    }

    #[test]
    fn bare_ucan_jwt_verifies_without_tokio() {
        let jwk = JWK::generate_ed25519().expect("jwk");
        let mut verification_method = DID_METHODS.generate(&jwk, "key").expect("did").to_string();
        let fragment = verification_method
            .rsplit_once(':')
            .expect("verification method fragment")
            .1
            .to_string();
        verification_method.push('#');
        verification_method.push_str(&fragment);

        let proof = Cid::new_v1(RAW_CODEC, Code::Blake3_256.digest(b"bare-ucan-proof"));
        let ucan = make_invocation_from_uris(
            once((
                "tinycloud:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:space/kv/path"
                    .parse()
                    .expect("resource uri"),
                once("tinycloud.kv/get".parse().expect("ability")),
            )),
            &proof,
            &jwk,
            &verification_method,
            4_102_444_800.0,
            InvocationOptions::default(),
        )
        .expect("ucan");

        let jwt = ucan.encode().expect("jwt");
        let verdict = verify_delegation_text(jwt.as_str(), 1_700_000_000.0).expect("ucan verdict");
        assert_eq!(verdict.kind, DelegationKind::Ucan);
        assert_eq!(verdict.capabilities.len(), 1);
        assert_eq!(
            verdict.proof_cids,
            vec![proof
                .to_string_of_base(CidBase::Base58Btc)
                .expect("cid base58btc")]
        );

        let wrong_jwk = JWK::generate_ed25519().expect("wrong jwk");
        let wrong_ucan = make_invocation_from_uris(
            once((
                "tinycloud:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:space/kv/path"
                    .parse()
                    .expect("resource uri"),
                once("tinycloud.kv/get".parse().expect("ability")),
            )),
            &proof,
            &wrong_jwk,
            &verification_method,
            4_102_444_800.0,
            InvocationOptions::default(),
        )
        .expect("wrong ucan");
        let wrong_jwt = wrong_ucan.encode().expect("wrong jwt");
        let err =
            verify_delegation_text(wrong_jwt.as_str(), 1_700_000_000.0).expect_err("tampered jwt");
        assert_eq!(err.kind, VerificationErrorKind::InvalidSignature);
    }

    #[test]
    fn invocation_verifier_rejects_unauthorized_action() {
        let golden = parse_golden();
        let vector = golden
            .invalid
            .iter()
            .find(|vector| vector.case == "wrong-ability")
            .expect("wrong-ability vector");
        let cacao = build_cacao(vector);
        let raw = serde_ipld_dagcbor::to_vec(&cacao).expect("cacao encodes");
        let expected_resource = vector.recap.att.keys().next().expect("recap resource");
        let err = verify_invocation_bytes(
            &raw,
            expected_resource,
            &vector.operation.action,
            1_700_000_000.0,
        )
        .expect_err("unauthorized action");
        assert_eq!(err.kind, VerificationErrorKind::InvalidStatement);
    }

    // Parity tests for the two authority-check exports added for the cf-node
    // security wave (TC-428/TC-437/TC-440). These pin `space_root_authority_matches`
    // to the TinyCloud-space arm of `is_root_authority`
    // (tinycloud-core/src/models/delegation.rs) so a future caller cannot
    // mistake it for the full check.

    const SPACE_OWNER_LOWER: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    const SPACE_OWNER_CHECKSUM: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";

    #[test]
    fn space_root_authority_matches_owner_in_lowercase_and_eip55_casing() {
        let space_id = format!("tinycloud:pkh:eip155:1:{SPACE_OWNER_CHECKSUM}:myspace");
        let resource_id = format!("tinycloud:pkh:eip155:1:{SPACE_OWNER_CHECKSUM}:myspace/kv/path");

        let delegator_lower = format!("did:pkh:eip155:1:{SPACE_OWNER_LOWER}");
        let delegator_checksum = format!("did:pkh:eip155:1:{SPACE_OWNER_CHECKSUM}");

        assert!(space_root_authority_matches(&space_id, &delegator_lower));
        assert!(space_root_authority_matches(&space_id, &delegator_checksum));
        assert!(space_root_authority_matches(&resource_id, &delegator_lower));
        assert!(space_root_authority_matches(
            &resource_id,
            &delegator_checksum
        ));
    }

    #[test]
    fn space_root_authority_matches_rejects_non_owner_did_key_issuer() {
        let space_id = format!("tinycloud:pkh:eip155:1:{SPACE_OWNER_CHECKSUM}:myspace");
        assert!(!space_root_authority_matches(
            &space_id,
            "did:key:z6MkExampleSessionIssuer"
        ));
    }

    #[test]
    fn space_root_authority_matches_rejects_valid_network_id_urn() {
        // A syntactically valid NetworkId URN (tinycloud-core's separate
        // is_root_authority arm, out of scope for this space-specific
        // export) must not parse as a SpaceId/ResourceId and must return
        // false rather than accidentally authorizing.
        let network_id = "urn:tinycloud:encryption:did:key:z6MkExampleAbcd:default";
        assert!(!space_root_authority_matches(
            network_id,
            "did:key:z6MkExampleAbcd"
        ));
    }

    #[test]
    fn space_root_authority_matches_rejects_unparseable_input() {
        assert!(!space_root_authority_matches(
            "not-a-tinycloud-resource",
            "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
        ));
    }

    // ReCap caveat preservation (cf-node security wave, R5). Before this,
    // extract_recap_capabilities() iterated only ability KEYS and hard-coded
    // an empty caveat map, so every signed CACAO reached cf-node's R5 gate
    // reporting no caveats - a signed, caveat-restricted capability was
    // silently upgraded to unrestricted authority in exactly the dimension
    // the caveat restricted. These tests pin both halves: a real note-bene
    // map survives, and the spec's mandatory `[{}]` "no restriction"
    // sentinel still reports as no caveats. The second half is what keeps
    // every legitimate first-party session working - treating `[{}]` as a
    // restriction would deny every ReCap session in the stack.

    const CAVEAT_TEST_RESOURCE: &str =
        "tinycloud:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:myspace/kv/restricted";

    /// Builds a ReCap carrying exactly the given note-bene collection for one
    /// ability, by round-tripping through siwe-recap's own `build_message` +
    /// `extract_and_verify` - i.e. through the real signable wire format and
    /// its statement check, not a hand-rolled fixture.
    fn recap_with_note_bene(
        note_bene: Vec<BTreeMap<String, serde_json::Value>>,
    ) -> SiweRecapCapability<serde_json::Value> {
        let golden = parse_golden();
        let vector = golden
            .valid
            .iter()
            .find(|vector| vector.case == "depth-1")
            .expect("depth-1 vector");
        let mut message: tinycloud_auth::cacaos::siwe::Message =
            vector.siwe.parse().expect("siwe parses");
        // Start from a clean slate so the only recap resource/statement in
        // the message is the one built below.
        message.statement = None;
        message.resources = Vec::new();

        let mut capability = SiweRecapCapability::<serde_json::Value>::new();
        capability
            .with_action_convert(CAVEAT_TEST_RESOURCE, "tinycloud.kv/get", note_bene)
            .expect("with_action_convert accepts a note-bene collection");

        let message = capability
            .build_message(message)
            .expect("build_message produces a signable SIWE message");

        SiweRecapCapability::<serde_json::Value>::extract_and_verify(&message)
            .expect("recap extracts and its statement verifies")
            .expect("recap is present")
    }

    fn restriction() -> BTreeMap<String, serde_json::Value> {
        [("maxContentLength".to_string(), serde_json::json!(1024))]
            .into_iter()
            .collect()
    }

    #[test]
    fn recap_capabilities_preserve_a_real_note_bene_restriction() {
        let recap = recap_with_note_bene(vec![restriction()]);
        let (grants, _proofs) = extract_recap_capabilities(recap).expect("extraction succeeds");

        assert_eq!(grants.len(), 1);
        let grant = &grants[0];
        assert_eq!(grant.action, "tinycloud.kv/get");
        assert!(
            !grant.caveats.is_empty(),
            "a signed ReCap restriction must not be erased into an unrestricted grant"
        );
        // Same indexed serialization the UCAN path uses: position -> map.
        assert_eq!(
            grant.caveats.get("0"),
            Some(&serde_json::json!({ "maxContentLength": 1024 }))
        );
    }

    #[test]
    fn recap_capabilities_preserve_multiple_note_bene_entries_by_index() {
        let second: BTreeMap<String, serde_json::Value> =
            [("prefix".to_string(), serde_json::json!("shared/"))]
                .into_iter()
                .collect();
        let recap = recap_with_note_bene(vec![restriction(), second]);
        let (grants, _proofs) = extract_recap_capabilities(recap).expect("extraction succeeds");

        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].caveats.len(), 2);
        assert_eq!(
            grants[0].caveats.get("1"),
            Some(&serde_json::json!({ "prefix": "shared/" }))
        );
    }

    #[test]
    fn recap_capabilities_report_no_caveats_for_the_empty_sentinel() {
        // `[{}]` is the spec's mandatory placeholder for "no restriction" and
        // is what every first-party session mints. It must NOT be reported as
        // a caveat, or cf-node's fail-closed R5 gate denies all real traffic.
        let recap = recap_with_note_bene(vec![BTreeMap::new()]);
        let (grants, _proofs) = extract_recap_capabilities(recap).expect("extraction succeeds");

        assert_eq!(grants.len(), 1);
        assert!(grants[0].caveats.is_empty());
    }

    // TC-482: default (no-manifest) SDK sign-ins request an encryption
    // network grant (NodeUserAuthorization.resolveSignInCapabilities's
    // `rawAbilities`) whose resource is a `urn:tinycloud:encryption:...`
    // NetworkId URN, not a TinyCloud `tinycloud:` ResourceId. Before this
    // fix, extract_recap_capabilities() required every capability resource
    // to parse as a ResourceId and threw `Decode: Incorrect Structure` on
    // this exact shape - rejecting a session the Rust node accepts (Rust's
    // own extraction, tinycloud-core/src/types/resource.rs's
    // `Resource::from(UriString)`, falls back to keeping the URI verbatim
    // instead of erroring). This pins the WASM verifier to the same
    // behavior: a non-tinycloud resource URI must not fail extraction, and
    // its grant must survive with the resource kept verbatim.
    #[test]
    fn recap_capabilities_accept_non_tinycloud_resource_uris() {
        const NETWORK_RESOURCE: &str =
            "urn:tinycloud:encryption:did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266:default";

        let golden = parse_golden();
        let vector = golden
            .valid
            .iter()
            .find(|vector| vector.case == "depth-1")
            .expect("depth-1 vector");
        let mut message: tinycloud_auth::cacaos::siwe::Message =
            vector.siwe.parse().expect("siwe parses");
        message.statement = None;
        message.resources = Vec::new();

        let mut capability = SiweRecapCapability::<serde_json::Value>::new();
        capability
            .with_action_convert(
                NETWORK_RESOURCE,
                "tinycloud.encryption/decrypt",
                vec![BTreeMap::new()],
            )
            .expect("with_action_convert accepts a raw, non-tinycloud resource URI");

        let message = capability
            .build_message(message)
            .expect("build_message produces a signable SIWE message");

        let recap = SiweRecapCapability::<serde_json::Value>::extract_and_verify(&message)
            .expect("recap extracts and its statement verifies")
            .expect("recap is present");

        let (grants, _proofs) = extract_recap_capabilities(recap)
            .expect("extraction must not fail on a non-tinycloud resource URI (TC-482 regression)");

        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0].resource, NETWORK_RESOURCE);
        assert_eq!(grants[0].action, "tinycloud.encryption/decrypt");
    }

    #[test]
    fn golden_vector_sessions_still_report_no_caveats() {
        // The same property end-to-end through real signed CACAOs: no frozen
        // golden vector may start reporting a caveat.
        let golden = parse_golden();
        let now = OffsetDateTime::parse(
            "2025-01-01T00:00:00.000Z",
            &time::format_description::well_known::Rfc3339,
        )
        .expect("frozen clock");

        for vector in &golden.valid {
            let cacao = build_cacao(vector);
            let raw = serde_ipld_dagcbor::to_vec(&cacao).expect("cacao encodes");
            let verdict = verify_delegation_bytes(&raw, now.unix_timestamp() as f64)
                .expect(vector.case.as_str());
            for grant in &verdict.capabilities {
                assert!(grant.caveats.is_empty(), "{}", vector.case);
            }
        }
    }

    #[test]
    fn ucan_and_recap_caveat_serialization_agree() {
        // Parity: the same note-bene collection must produce the same
        // CapabilityGrant.caveats map regardless of delegation kind, so
        // cf-node's single `hasCaveats` predicate is correct for both.
        let nb = restriction();
        let recap = recap_with_note_bene(vec![nb.clone()]);
        let (recap_grants, _) = extract_recap_capabilities(recap).expect("recap extraction");

        let mut ucan_capabilities =
            tinycloud_auth::ucan_capabilities_object::Capabilities::<serde_json::Value>::new();
        ucan_capabilities
            .with_action_convert(CAVEAT_TEST_RESOURCE, "tinycloud.kv/get", vec![nb])
            .expect("ucan with_action_convert");
        let ucan_grants = extract_ucan_capabilities(&ucan_capabilities).expect("ucan extraction");

        assert_eq!(recap_grants, ucan_grants);
    }

    #[test]
    fn did_principal_matches_strips_fragment_and_canonicalizes_eip55() {
        let a = format!("did:pkh:eip155:1:{SPACE_OWNER_LOWER}#controller");
        let b = format!("did:pkh:eip155:1:{SPACE_OWNER_CHECKSUM}");
        assert!(did_principal_matches(&a, &b));
        assert!(!did_principal_matches(&a, "did:key:z6MkExampleAbcd"));
    }
}

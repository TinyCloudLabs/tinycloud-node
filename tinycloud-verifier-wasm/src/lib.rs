extern crate alloc;

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::str::FromStr;
use futures::executor::block_on;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudInvocation},
    cacaos::siwe_cacao::{SIWEPayloadConversionError, SiweCacao},
    identity::principal_did,
    ipld_core::cid::{multibase::Base, Cid},
    multihash_codetable::{Code, MultihashDigest},
    resolver::DID_METHODS,
    resource::ResourceId,
    siwe_recap::Capability as SiweRecapCapability,
    ssi::ucan::TimeInvalid,
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
    serde_wasm_bindgen::to_value(error)
        .unwrap_or_else(|_| JsValue::from_str(&format!("{}: {}", error.kind.as_str(), error.message)))
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
    principal_did(value)
        .unwrap_or_else(|_| value.split('#').next().unwrap_or(value).to_string())
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
    Ok(offset_datetime_to_rfc3339(&offset_datetime_from_seconds(seconds)?))
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

fn verify_header_bytes(bytes: &[u8]) -> Result<TinyCloudDelegation, VerificationError> {
    TinyCloudDelegation::from_bytes(bytes).map_err(|error| VerificationError::decode(error.to_string()))
}

fn verify_header_text(encoded: &str) -> Result<TinyCloudDelegation, VerificationError> {
    <TinyCloudDelegation as HeaderEncode>::decode(encoded)
        .map(|(delegation, _)| delegation)
        .map_err(|error| VerificationError::decode(error.to_string()))
}

fn extract_ucan_capabilities(capabilities: &tinycloud_auth::ucan_capabilities_object::Capabilities<
    serde_json::Value,
>) -> Result<Vec<CapabilityGrant>, VerificationError> {
    let mut grants = Vec::new();
    for (resource, abilities) in capabilities.abilities() {
        let resource = ResourceId::from_str(resource.as_str())
            .map_err(|error| VerificationError::decode(error.to_string()))?
            .to_string();
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
        let resource = ResourceId::from_str(resource.as_str())
            .map_err(|error| VerificationError::decode(error.to_string()))?
            .to_string();
        for action in abilities.into_keys() {
            grants.push(CapabilityGrant {
                resource: resource.clone(),
                action: action.to_string(),
                caveats: BTreeMap::new(),
            });
        }
    }
    Ok((grants, proofs))
}

fn verify_ucan(
    ucan: &TinyCloudInvocation,
    now_seconds: f64,
) -> Result<DelegationVerdict, VerificationError> {
    block_on(ucan.verify_signature(&*DID_METHODS))
        .map_err(|error| VerificationError::invalid_signature(error.to_string()))?;
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
        .map_err(|error: SIWEPayloadConversionError| VerificationError::decode(error.to_string()))?;
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

pub fn extract_capabilities_bytes(
    bytes: &[u8],
    now_seconds: f64,
) -> Result<Vec<CapabilityGrant>, VerificationError> {
    Ok(verify_delegation_bytes(bytes, now_seconds)?.capabilities)
}

pub fn canonical_issuer_bytes(
    bytes: &[u8],
    now_seconds: f64,
) -> Result<String, VerificationError> {
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

#[wasm_bindgen(js_name = verifyDelegation)]
pub fn verify_delegation_wasm(bytes: &[u8], now_seconds: f64) -> Result<JsValue, JsValue> {
    match verify_delegation_bytes(bytes, now_seconds) {
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

    #[derive(Deserialize, Clone)]
    struct GoldenVector {
        case: String,
        delegationDepth: usize,
        recap: Recap,
        operation: CapabilityOperation,
        nonce: String,
        proofCids: Vec<String>,
        siwe: String,
        signature: String,
        expected: Expected,
        invalidReason: Option<String>,
    }

    #[derive(Deserialize, Clone)]
    struct CapabilityOperation {
        service: String,
        space: String,
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

    #[derive(Deserialize, Clone)]
    struct Expected {
        status: u32,
        code: String,
    }

    const GOLDEN_VECTORS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../../repositories/tc-bench/fixtures/golden-vectors.json"
    ));

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
        let now = OffsetDateTime::parse("2025-01-01T00:00:00.000Z", &time::format_description::well_known::Rfc3339)
            .expect("frozen clock");

        for vector in &golden.valid {
            let cacao = build_cacao(vector);
            let raw = serde_ipld_dagcbor::to_vec(&cacao).expect("cacao encodes");
            let verdict = verify_delegation_bytes(&raw, now.unix_timestamp() as f64)
                .expect(vector.case.as_str());

            assert!(verdict.ok);
            assert_eq!(verdict.kind, DelegationKind::Cacao);
            assert_eq!(verdict.issuer, canonical_principal_or_uri(cacao.payload().iss.as_ref()));
            assert_eq!(verdict.audience, canonical_principal_or_uri(cacao.payload().aud.as_ref()));
            assert_eq!(verdict.capabilities.len(), 1, "{}", vector.case);
            assert_eq!(verdict.proof_cids, vector.proofCids, "{}", vector.case);

            let capability = &verdict.capabilities[0];
            assert_eq!(capability.resource, *vector.recap.att.keys().next().expect("recap resource"));
            assert_eq!(capability.action, vector.operation.action);
            assert_eq!(vector.recap.prf, vector.proofCids);
            assert!(vector.recap.statement.contains(&vector.operation.path));
            assert!(vector.recap.resource.starts_with("urn:recap:"));
        }
    }

    #[test]
    fn proof_cid_helper_matches_tc_bench_fixture() {
        let golden = parse_golden();
        for vector in &golden.valid {
            for (index, proof_cid) in vector.proofCids.iter().enumerate() {
                let seed = format!("tc-bench-v1:{}:proof:{}", vector.case, index);
                assert_eq!(compute_proof_cid(seed.as_bytes()), proof_cid.as_str(), "{}", vector.case);
            }
        }
    }

    #[test]
    fn rejects_wrong_signature_and_expiry() {
        let golden = parse_golden();
        let valid = golden.valid.iter().find(|vector| vector.case == "depth-1").expect("depth-1 vector");
        let expired = golden.invalid.iter().find(|vector| vector.case == "expired").expect("expired vector");

        let cacao = build_cacao(valid);
        let raw = serde_ipld_dagcbor::to_vec(&cacao).expect("cacao encodes");
        let mut bad_signature = valid.signature.clone();
        bad_signature = mutate_signature(&bad_signature);
        let mut bad = valid.clone();
        bad.signature = bad_signature;
        let bad_cacao = build_cacao(&bad);
        let bad_raw = serde_ipld_dagcbor::to_vec(&bad_cacao).expect("bad cacao encodes");

        let now = OffsetDateTime::parse("2025-01-01T00:00:00.000Z", &time::format_description::well_known::Rfc3339)
            .expect("frozen clock");
        let err = verify_delegation_bytes(&bad_raw, now.unix_timestamp() as f64).expect_err("wrong signature");
        assert_eq!(err.kind, VerificationErrorKind::InvalidSignature);

        let expired_cacao = build_cacao(expired);
        let expired_raw = serde_ipld_dagcbor::to_vec(&expired_cacao).expect("expired cacao encodes");
        let err = verify_delegation_bytes(&expired_raw, now.unix_timestamp() as f64).expect_err("expired");
        assert_eq!(err.kind, VerificationErrorKind::InvalidTime);

        let _ = raw;
    }

    #[test]
    fn resource_and_action_authorization_matches_core_semantics() {
        let golden = parse_golden();
        let vector = golden.valid.iter().find(|vector| vector.case == "depth-1").expect("depth-1 vector");
        let cacao = build_cacao(vector);
        let raw = serde_ipld_dagcbor::to_vec(&cacao).expect("cacao encodes");
        let now = OffsetDateTime::parse("2025-01-01T00:00:00.000Z", &time::format_description::well_known::Rfc3339)
            .expect("frozen clock");
        let verdict = verify_delegation_bytes(&raw, now.unix_timestamp() as f64).expect("verdict");
        let grant = &verdict.capabilities[0];

        let requested_same = grant.resource.clone();
        assert!(resource_path_contains(&grant.resource, &requested_same));

        let widened_resource = format!("{}x", grant.resource);
        assert!(!resource_path_contains(&grant.resource, &widened_resource));
        assert!(action_matches(&grant.action, &grant.action));
        assert!(!action_matches(&grant.action, "tinycloud.kv/put"));
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
            vec![proof.to_string_of_base(CidBase::Base58Btc).expect("cid base58btc")]
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
        let err = verify_delegation_text(wrong_jwt.as_str(), 1_700_000_000.0).expect_err("tampered jwt");
        assert_eq!(err.kind, VerificationErrorKind::InvalidSignature);
    }
}

//! Pure recipient-DID delegation-bundle verification.
//!
//! This module deliberately has no storage, resolver, registry, or network
//! inputs. A successful result is derived from one complete, ordered bundle
//! after all signatures, CIDs, authority edges, attenuation, and time bounds
//! have been verified together.

use std::{collections::HashSet, str::FromStr};

use base64::{engine::general_purpose::URL_SAFE, engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, VerifyingKey};
use http::Uri;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;

use crate::{
    cacaos::{siwe::Message, siwe_cacao::SiweCacao},
    identity::parse_pkh_did,
    ipld_core::cid::{Cid, Version},
    multihash_codetable::{Code, MultihashDigest},
    resource::ResourceId,
    siwe_recap::Capability as SiweCapability,
    ssi::{jwk::Algorithm, ucan::Ucan},
    ucan_capabilities_object::{Capabilities, CapsInner},
};

const RAW_CODEC: u64 = 0x55;
const BLAKE3_256: u64 = 0x1e;
const MAX_ISSUER_PROOFS: usize = 8;
const DELEGATION_MODE_FACT: &str = "xyz.tinycloud.policy/delegationMode";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientDidDelegationRoutingV2 {
    pub origin: String,
    pub node_audience: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CacaoDelegationArtifactV2 {
    pub kind: CacaoKind,
    pub cid: String,
    pub encoding: CacaoEncoding,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum CacaoKind {
    #[serde(rename = "cacao")]
    Cacao,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum CacaoEncoding {
    #[serde(rename = "dag-cbor-base64url-pad")]
    DagCborBase64UrlPad,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UcanDelegationArtifactV2 {
    pub kind: UcanKind,
    pub cid: String,
    pub encoding: UcanEncoding,
    pub value: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum UcanKind {
    #[serde(rename = "ucan")]
    Ucan,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum UcanEncoding {
    #[serde(rename = "jwt")]
    Jwt,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DelegationArtifactV2 {
    Cacao(CacaoDelegationArtifactV2),
    Ucan(UcanDelegationArtifactV2),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RecipientDidDelegationBundleV2 {
    pub format: RecipientDidDelegationFormatV2,
    pub routing: RecipientDidDelegationRoutingV2,
    pub grant: UcanDelegationArtifactV2,
    pub issuer_proofs: Vec<DelegationArtifactV2>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum RecipientDidDelegationFormatV2 {
    #[serde(rename = "tinycloud-recipient-delegation-v2")]
    TinycloudRecipientDelegationV2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NativeVerifiedRecipientDidDelegationBundleV2 {
    pub verification: &'static str,
    pub owner_did: String,
    pub session_principal_did: String,
    pub session_verification_method: String,
    pub recipient_did: String,
    pub grant_cid: String,
    pub proof_cids: Vec<String>,
    pub scope: RecipientDidVerifiedScopeV2,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    pub expiry: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecipientDidVerifiedScopeV2 {
    pub space_id: String,
    pub resource: RecipientDidExactResourceV2,
    pub actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RecipientDidExactResourceV2 {
    pub kind: &'static str,
    pub path: String,
}

#[derive(Debug, thiserror::Error)]
#[error("recipient-DID delegation bundle rejected: {0}")]
pub struct RecipientDidVerificationError(String);

impl RecipientDidVerificationError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DelegationMode {
    Attenuable,
    Terminal,
}

#[derive(Clone, Debug, PartialEq)]
struct VerifiedCapability {
    resource: ResourceId,
    ability: String,
    caveats: Value,
}

#[derive(Clone, Debug)]
struct VerifiedDelegation {
    cid: Cid,
    delegator: String,
    issuer_verification_method: Option<String>,
    delegate: String,
    parents: Vec<Cid>,
    capabilities: Vec<VerifiedCapability>,
    not_before: Option<OffsetDateTime>,
    expiry: OffsetDateTime,
    mode: DelegationMode,
}

/// Verify one complete recipient-DID authority graph without network or DB I/O.
pub fn verify_recipient_did_delegation_bundle_v2(
    bundle: RecipientDidDelegationBundleV2,
    now_unix_seconds: u64,
) -> Result<NativeVerifiedRecipientDidDelegationBundleV2, RecipientDidVerificationError> {
    validate_routing(&bundle.routing)?;
    if bundle.issuer_proofs.is_empty() || bundle.issuer_proofs.len() > MAX_ISSUER_PROOFS {
        return Err(RecipientDidVerificationError::invalid(
            "issuerProofs must contain one Cacao root and at most seven intermediate UCANs",
        ));
    }

    let now_seconds = i64::try_from(now_unix_seconds)
        .map_err(|_| RecipientDidVerificationError::invalid("verification time is out of range"))?;
    let now = OffsetDateTime::from_unix_timestamp(now_seconds)
        .map_err(|_| RecipientDidVerificationError::invalid("verification time is out of range"))?;

    let mut proof_cids = Vec::with_capacity(bundle.issuer_proofs.len());
    let mut seen_cids = HashSet::with_capacity(bundle.issuer_proofs.len() + 1);
    let mut iter = bundle.issuer_proofs.into_iter();
    let root_artifact = iter
        .next()
        .ok_or_else(|| RecipientDidVerificationError::invalid("missing owner Cacao"))?;
    let root = match root_artifact {
        DelegationArtifactV2::Cacao(artifact) => verify_cacao_artifact(artifact, now)?,
        DelegationArtifactV2::Ucan(_) => {
            return Err(RecipientDidVerificationError::invalid(
                "issuerProofs must begin with the owner Cacao",
            ))
        }
    };
    if !root.parents.is_empty() {
        return Err(RecipientDidVerificationError::invalid(
            "owner Cacao must be an authority root without cited parents",
        ));
    }
    let owner_did = canonical_mainnet_pkh_did(&root.delegator)?;
    canonical_session_verification_method_from_principal(&root.delegate)?;
    validate_owner_capability_spaces(&root.capabilities, &owner_did)?;
    insert_unique_cid(&mut seen_cids, &root.cid)?;
    proof_cids.push(root.cid.to_string());

    let mut effective_not_before = root.not_before;
    let mut parent = root;
    for artifact in iter {
        let child = match artifact {
            DelegationArtifactV2::Ucan(artifact) => verify_ucan_artifact(artifact, now)?,
            DelegationArtifactV2::Cacao(_) => {
                return Err(RecipientDidVerificationError::invalid(
                    "only the first issuer proof may be a Cacao",
                ))
            }
        };
        validate_authority_edge(&parent, &child)?;
        canonical_session_principal(&child.delegate)?;
        insert_unique_cid(&mut seen_cids, &child.cid)?;
        proof_cids.push(child.cid.to_string());
        effective_not_before = max_time(effective_not_before, child.not_before);
        parent = child;
    }

    let grant = verify_ucan_artifact(bundle.grant, now)?;
    validate_authority_edge(&parent, &grant)?;
    insert_unique_cid(&mut seen_cids, &grant.cid)?;
    let recipient_did = canonical_mainnet_pkh_did(&grant.delegate)?;
    let session_verification_method = grant
        .issuer_verification_method
        .clone()
        .ok_or_else(|| RecipientDidVerificationError::invalid("grant issuer is not a DID URL"))?;
    let session_principal_did =
        canonical_session_verification_method(&session_verification_method)?;
    if session_principal_did != grant.delegator {
        return Err(RecipientDidVerificationError::invalid(
            "grant issuer DID URL does not identify its delegator principal",
        ));
    }
    effective_not_before = max_time(effective_not_before, grant.not_before);
    let scope = derive_exact_scope(&grant.capabilities, &owner_did)?;

    Ok(NativeVerifiedRecipientDidDelegationBundleV2 {
        verification: "tinycloud-native-authority-v1",
        owner_did,
        session_principal_did,
        session_verification_method,
        recipient_did,
        grant_cid: grant.cid.to_string(),
        proof_cids,
        scope,
        not_before: effective_not_before.map(canonical_millis),
        expiry: canonical_millis(grant.expiry),
    })
}

fn verify_cacao_artifact(
    artifact: CacaoDelegationArtifactV2,
    now: OffsetDateTime,
) -> Result<VerifiedDelegation, RecipientDidVerificationError> {
    let bytes = URL_SAFE.decode(&artifact.value).map_err(|_| {
        RecipientDidVerificationError::invalid("Cacao transport is not padded base64url")
    })?;
    if URL_SAFE.encode(&bytes) != artifact.value {
        return Err(RecipientDidVerificationError::invalid(
            "Cacao transport is not canonical padded base64url",
        ));
    }
    let cid = verify_artifact_cid(&artifact.cid, &bytes)?;
    let cacao: SiweCacao = serde_ipld_dagcbor::from_slice(&bytes)
        .map_err(|_| RecipientDidVerificationError::invalid("Cacao is not valid DAG-CBOR"))?;
    let canonical = serde_ipld_dagcbor::to_vec(&cacao).map_err(|_| {
        RecipientDidVerificationError::invalid("Cacao cannot be canonically encoded")
    })?;
    if canonical != bytes {
        return Err(RecipientDidVerificationError::invalid(
            "Cacao DAG-CBOR is not canonical for the current TinyCloud profile",
        ));
    }
    let message: Message =
        cacao.payload().clone().try_into().map_err(|_| {
            RecipientDidVerificationError::invalid("Cacao payload is not valid SIWE")
        })?;
    let signature: &[u8; 65] =
        cacao.signature().as_ref().try_into().map_err(|_| {
            RecipientDidVerificationError::invalid("Cacao signature length is invalid")
        })?;
    message.verify_eip191(signature).map_err(|_| {
        RecipientDidVerificationError::invalid("Cacao EIP-191 signature is invalid")
    })?;

    let issued_at = *cacao.payload().iat.as_ref();
    let not_before = cacao.payload().nbf.as_ref().map(|value| *value.as_ref());
    let expiry = cacao
        .payload()
        .exp
        .as_ref()
        .map(|value| *value.as_ref())
        .ok_or_else(|| RecipientDidVerificationError::invalid("owner Cacao must expire"))?;
    if not_before.is_some_and(|value| value >= expiry) || issued_at >= expiry {
        return Err(RecipientDidVerificationError::invalid(
            "owner Cacao has inconsistent temporal bounds",
        ));
    }
    if issued_at > now || not_before.is_some_and(|value| value > now) || expiry <= now {
        return Err(RecipientDidVerificationError::invalid(
            "owner Cacao is not valid at the requested verification time",
        ));
    }

    let recap = SiweCapability::<Value>::extract_and_verify(&message)
        .map_err(|_| RecipientDidVerificationError::invalid("SIWE ReCap statement is invalid"))?
        .ok_or_else(|| {
            RecipientDidVerificationError::invalid("owner Cacao has no SIWE ReCap authority")
        })?;
    let parents = recap.proof().to_vec();
    let capabilities = extract_capabilities_map(recap.abilities())?;
    if capabilities.is_empty() {
        return Err(RecipientDidVerificationError::invalid(
            "owner Cacao has no delegated capabilities",
        ));
    }

    let delegate_vm = cacao.payload().aud.as_str().to_owned();
    let delegate = canonical_session_verification_method(&delegate_vm)?;
    Ok(VerifiedDelegation {
        cid,
        delegator: canonical_mainnet_pkh_did(cacao.payload().iss.as_str())?,
        issuer_verification_method: None,
        delegate,
        parents,
        capabilities,
        not_before,
        expiry,
        mode: DelegationMode::Attenuable,
    })
}

fn verify_ucan_artifact(
    artifact: UcanDelegationArtifactV2,
    now: OffsetDateTime,
) -> Result<VerifiedDelegation, RecipientDidVerificationError> {
    let segments: Vec<&str> = artifact.value.split('.').collect();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(RecipientDidVerificationError::invalid(
            "UCAN must be a three-segment compact JWT",
        ));
    }
    let decoded: Vec<Vec<u8>> = segments
        .iter()
        .map(|segment| {
            if segment.contains('=') {
                return Err(RecipientDidVerificationError::invalid(
                    "UCAN JWT segments must be unpadded base64url",
                ));
            }
            let bytes = URL_SAFE_NO_PAD.decode(segment).map_err(|_| {
                RecipientDidVerificationError::invalid("UCAN JWT segment is invalid base64url")
            })?;
            if bytes.is_empty() || URL_SAFE_NO_PAD.encode(&bytes) != *segment {
                return Err(RecipientDidVerificationError::invalid(
                    "UCAN JWT segment is not canonical base64url",
                ));
            }
            Ok(bytes)
        })
        .collect::<Result<_, _>>()?;
    let cid = verify_artifact_cid(&artifact.cid, artifact.value.as_bytes())?;
    let ucan: Ucan<Value, Value> = Ucan::decode(&artifact.value)
        .map_err(|_| RecipientDidVerificationError::invalid("UCAN JWT payload is invalid"))?;
    if ucan.header().algorithm != Algorithm::EdDSA {
        return Err(RecipientDidVerificationError::invalid(
            "UCAN JWT algorithm must be EdDSA",
        ));
    }

    let issuer_verification_method = ucan.payload().issuer.to_string();
    let delegator = canonical_session_verification_method(&issuer_verification_method)?;
    let public_key = ed25519_key_from_did(&delegator)?;
    validate_ucan_header_jwk(&decoded[0], &public_key)?;
    let signature = Signature::from_slice(&decoded[2]).map_err(|_| {
        RecipientDidVerificationError::invalid("UCAN signature must be exactly 64 bytes")
    })?;
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    public_key
        .verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| RecipientDidVerificationError::invalid("UCAN Ed25519 signature is invalid"))?;

    let not_before = ucan
        .payload()
        .not_before
        .map(|value| numeric_date(value.as_seconds(), "not-before"))
        .transpose()?;
    let expiry = numeric_date(ucan.payload().expiration.as_seconds(), "expiry")?;
    if not_before.is_some_and(|value| value >= expiry) {
        return Err(RecipientDidVerificationError::invalid(
            "UCAN has inconsistent temporal bounds",
        ));
    }
    if not_before.is_some_and(|value| value > now) || expiry <= now {
        return Err(RecipientDidVerificationError::invalid(
            "UCAN is not valid at the requested verification time",
        ));
    }
    let capabilities = extract_capabilities(&ucan.payload().attenuation)?;
    if capabilities.is_empty() {
        return Err(RecipientDidVerificationError::invalid(
            "UCAN has no delegated capabilities",
        ));
    }

    Ok(VerifiedDelegation {
        cid,
        delegator,
        issuer_verification_method: Some(issuer_verification_method),
        delegate: ucan.payload().audience.to_string(),
        parents: ucan.payload().proof.clone(),
        capabilities,
        not_before,
        expiry,
        mode: delegation_mode(ucan.payload().facts.as_ref())?,
    })
}

fn validate_authority_edge(
    parent: &VerifiedDelegation,
    child: &VerifiedDelegation,
) -> Result<(), RecipientDidVerificationError> {
    if parent.mode != DelegationMode::Attenuable {
        return Err(RecipientDidVerificationError::invalid(
            "terminal delegation cannot authorize a child",
        ));
    }
    if child.parents.as_slice() != [parent.cid] {
        return Err(RecipientDidVerificationError::invalid(
            "each delegation must cite exactly its preceding transported parent",
        ));
    }
    if child.delegator != parent.delegate {
        return Err(RecipientDidVerificationError::invalid(
            "delegation issuer does not equal its parent's audience",
        ));
    }
    if child.expiry > parent.expiry {
        return Err(RecipientDidVerificationError::invalid(
            "child expiry broadens its parent",
        ));
    }
    if parent.not_before.is_some_and(|parent_nbf| {
        child
            .not_before
            .is_none_or(|child_nbf| child_nbf < parent_nbf)
    }) {
        return Err(RecipientDidVerificationError::invalid(
            "child not-before broadens its parent",
        ));
    }
    for child_capability in &child.capabilities {
        let authorized = parent.capabilities.iter().any(|parent_capability| {
            child_capability
                .resource
                .extends(&parent_capability.resource)
                .is_ok()
                && child_capability.ability == parent_capability.ability
                && child_capability.caveats == parent_capability.caveats
        });
        if !authorized {
            return Err(RecipientDidVerificationError::invalid(
                "child capability is not an exact caveat-preserving attenuation of its parent",
            ));
        }
    }
    Ok(())
}

fn extract_capabilities<C: Serialize>(
    capabilities: &Capabilities<C>,
) -> Result<Vec<VerifiedCapability>, RecipientDidVerificationError> {
    extract_capabilities_map(capabilities.abilities())
}

fn extract_capabilities_map<C: Serialize>(
    capabilities: &CapsInner<C>,
) -> Result<Vec<VerifiedCapability>, RecipientDidVerificationError> {
    let mut result = Vec::new();
    for (resource, abilities) in capabilities {
        let parsed: ResourceId = resource.as_str().parse().map_err(|_| {
            RecipientDidVerificationError::invalid("authority contains a non-TinyCloud resource")
        })?;
        if parsed.to_string() != resource.as_str()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(RecipientDidVerificationError::invalid(
                "authority resource is not a canonical TinyCloud resource",
            ));
        }
        for (ability, caveats) in abilities {
            let action = ability.to_string();
            validate_action_for_service(&action, parsed.service().as_str())?;
            result.push(VerifiedCapability {
                resource: parsed.clone(),
                ability: action,
                caveats: serde_json::to_value(caveats).map_err(|_| {
                    RecipientDidVerificationError::invalid("capability caveats are not JSON")
                })?,
            });
        }
    }
    Ok(result)
}

fn derive_exact_scope(
    capabilities: &[VerifiedCapability],
    owner_did: &str,
) -> Result<RecipientDidVerifiedScopeV2, RecipientDidVerificationError> {
    let first = capabilities.first().ok_or_else(|| {
        RecipientDidVerificationError::invalid("recipient grant has no capability")
    })?;
    if capabilities
        .iter()
        .any(|capability| capability.resource != first.resource)
    {
        return Err(RecipientDidVerificationError::invalid(
            "recipient grant must contain exactly one resource",
        ));
    }
    if first.resource.space().did().as_str() != owner_did {
        return Err(RecipientDidVerificationError::invalid(
            "recipient grant space is not owned by the Cacao signer",
        ));
    }
    let path = first
        .resource
        .path()
        .map(|path| path.as_str())
        .ok_or_else(|| {
            RecipientDidVerificationError::invalid("recipient grant path must be exact")
        })?;
    validate_exact_path(path)?;
    let empty_caveats = serde_json::json!([{}]);
    if capabilities
        .iter()
        .any(|capability| capability.caveats != empty_caveats)
    {
        return Err(RecipientDidVerificationError::invalid(
            "recipient grant caveats cannot be represented by the frozen exact scope",
        ));
    }
    let mut actions: Vec<String> = capabilities
        .iter()
        .map(|capability| capability.ability.clone())
        .collect();
    actions.sort();
    actions.dedup();
    if actions.len() != capabilities.len() {
        return Err(RecipientDidVerificationError::invalid(
            "recipient grant contains duplicate actions",
        ));
    }
    Ok(RecipientDidVerifiedScopeV2 {
        space_id: first.resource.space().to_string(),
        resource: RecipientDidExactResourceV2 {
            kind: "exact",
            path: path.to_owned(),
        },
        actions,
    })
}

fn validate_owner_capability_spaces(
    capabilities: &[VerifiedCapability],
    owner_did: &str,
) -> Result<(), RecipientDidVerificationError> {
    if capabilities
        .iter()
        .any(|capability| capability.resource.space().did().as_str() != owner_did)
    {
        return Err(RecipientDidVerificationError::invalid(
            "SIWE ReCap authority includes a space not owned by the Cacao signer",
        ));
    }
    Ok(())
}

fn verify_artifact_cid(
    claimed: &str,
    preimage: &[u8],
) -> Result<Cid, RecipientDidVerificationError> {
    let cid = Cid::from_str(claimed)
        .map_err(|_| RecipientDidVerificationError::invalid("artifact CID is invalid"))?;
    if cid.version() != Version::V1
        || cid.codec() != RAW_CODEC
        || cid.hash().code() != BLAKE3_256
        || cid.hash().size() != 32
        || cid.to_string() != claimed
    {
        return Err(RecipientDidVerificationError::invalid(
            "artifact CID is not canonical CIDv1/raw/blake3-256",
        ));
    }
    let expected = Cid::new_v1(RAW_CODEC, Code::Blake3_256.digest(preimage));
    if cid != expected {
        return Err(RecipientDidVerificationError::invalid(
            "artifact CID does not match its exact transported bytes",
        ));
    }
    Ok(cid)
}

fn insert_unique_cid(
    seen: &mut HashSet<Cid>,
    cid: &Cid,
) -> Result<(), RecipientDidVerificationError> {
    if !seen.insert(*cid) {
        return Err(RecipientDidVerificationError::invalid(
            "every transported artifact CID must occur exactly once",
        ));
    }
    Ok(())
}

fn validate_ucan_header_jwk(
    header_bytes: &[u8],
    public_key: &VerifyingKey,
) -> Result<(), RecipientDidVerificationError> {
    let header: Value = serde_json::from_slice(header_bytes).map_err(|_| {
        RecipientDidVerificationError::invalid("UCAN protected header is invalid JSON")
    })?;
    let jwk = header
        .get("jwk")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            RecipientDidVerificationError::invalid("UCAN protected header has no public JWK")
        })?;
    let expected_x = URL_SAFE_NO_PAD.encode(public_key.as_bytes());
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA")
        || header.get("typ").and_then(Value::as_str) != Some("JWT")
        || header.get("ucv").and_then(Value::as_str) != Some("0.10.0")
        || jwk.get("kty").and_then(Value::as_str) != Some("OKP")
        || jwk.get("crv").and_then(Value::as_str) != Some("Ed25519")
        || jwk.get("alg").and_then(Value::as_str) != Some("EdDSA")
        || jwk.get("x").and_then(Value::as_str) != Some(expected_x.as_str())
        || jwk.contains_key("d")
    {
        return Err(RecipientDidVerificationError::invalid(
            "UCAN protected header does not bind the canonical Ed25519 issuer key",
        ));
    }
    Ok(())
}

fn ed25519_key_from_did(did: &str) -> Result<VerifyingKey, RecipientDidVerificationError> {
    let identifier = did.strip_prefix("did:key:").ok_or_else(|| {
        RecipientDidVerificationError::invalid("session principal is not did:key")
    })?;
    let (base, bytes) = multibase::decode(identifier)
        .map_err(|_| RecipientDidVerificationError::invalid("did:key multibase is invalid"))?;
    if base != multibase::Base::Base58Btc
        || multibase::encode(multibase::Base::Base58Btc, &bytes) != identifier
        || bytes.len() != 34
        || bytes[..2] != [0xed, 0x01]
    {
        return Err(RecipientDidVerificationError::invalid(
            "did:key must use canonical base58btc Ed25519 multicodec 0xed01",
        ));
    }
    let key_bytes: [u8; 32] = bytes[2..]
        .try_into()
        .map_err(|_| RecipientDidVerificationError::invalid("did:key length is invalid"))?;
    let compressed = CompressedEdwardsY(key_bytes);
    let point = compressed.decompress().ok_or_else(|| {
        RecipientDidVerificationError::invalid("did:key point is not a canonical Edwards point")
    })?;
    if point.is_small_order()
        || !point.is_torsion_free()
        || point.compress().to_bytes() != key_bytes
    {
        return Err(RecipientDidVerificationError::invalid(
            "did:key point must be canonical, torsion-free, and non-small-order",
        ));
    }
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|_| RecipientDidVerificationError::invalid("did:key point is invalid"))?;
    if key.is_weak() {
        return Err(RecipientDidVerificationError::invalid(
            "did:key point is weak",
        ));
    }
    Ok(key)
}

fn canonical_session_principal(did: &str) -> Result<String, RecipientDidVerificationError> {
    ed25519_key_from_did(did)?;
    Ok(did.to_owned())
}

fn canonical_session_verification_method(
    did_url: &str,
) -> Result<String, RecipientDidVerificationError> {
    let (principal, fragment) = did_url.split_once('#').ok_or_else(|| {
        RecipientDidVerificationError::invalid(
            "session issuer must be a did:key verification-method URL",
        )
    })?;
    let identifier = principal
        .strip_prefix("did:key:")
        .ok_or_else(|| RecipientDidVerificationError::invalid("session issuer must use did:key"))?;
    if fragment != identifier || did_url.matches('#').count() != 1 {
        return Err(RecipientDidVerificationError::invalid(
            "session verification-method fragment must equal its did:key multibase",
        ));
    }
    canonical_session_principal(principal)
}

fn canonical_session_verification_method_from_principal(
    principal: &str,
) -> Result<String, RecipientDidVerificationError> {
    let identifier = principal.strip_prefix("did:key:").ok_or_else(|| {
        RecipientDidVerificationError::invalid("session audience must use did:key")
    })?;
    canonical_session_verification_method(&format!("{principal}#{identifier}"))
}

fn canonical_mainnet_pkh_did(did: &str) -> Result<String, RecipientDidVerificationError> {
    let parsed = parse_pkh_did(did)
        .map_err(|_| RecipientDidVerificationError::invalid("account DID is invalid"))?
        .ok_or_else(|| RecipientDidVerificationError::invalid("account must use did:pkh:eip155"))?;
    let canonical = format!("did:pkh:eip155:{}:{}", parsed.chain_id, parsed.address);
    if parsed.chain_id != 1 || canonical != did {
        return Err(RecipientDidVerificationError::invalid(
            "account DID must be the exact canonical chain-1 did:pkh",
        ));
    }
    Ok(canonical)
}

fn delegation_mode(
    facts: Option<&Vec<Value>>,
) -> Result<DelegationMode, RecipientDidVerificationError> {
    let mut mode = None;
    for fact in facts.into_iter().flatten() {
        let Some(value) = fact
            .as_object()
            .and_then(|object| object.get(DELEGATION_MODE_FACT))
        else {
            continue;
        };
        if mode.is_some() {
            return Err(RecipientDidVerificationError::invalid(
                "delegation mode fact must occur at most once",
            ));
        }
        mode = Some(match value.as_str() {
            Some("attenuable") => DelegationMode::Attenuable,
            Some("terminal") => DelegationMode::Terminal,
            _ => {
                return Err(RecipientDidVerificationError::invalid(
                    "delegation mode must be attenuable or terminal",
                ))
            }
        });
    }
    Ok(mode.unwrap_or(DelegationMode::Attenuable))
}

fn numeric_date(
    seconds: f64,
    label: &str,
) -> Result<OffsetDateTime, RecipientDidVerificationError> {
    if !seconds.is_finite() || seconds < 0.0 || seconds.fract() != 0.0 || seconds > i64::MAX as f64
    {
        return Err(RecipientDidVerificationError::invalid(format!(
            "UCAN {label} must be an integer epoch second",
        )));
    }
    OffsetDateTime::from_unix_timestamp(seconds as i64).map_err(|_| {
        RecipientDidVerificationError::invalid(format!("UCAN {label} is out of range"))
    })
}

fn max_time(left: Option<OffsetDateTime>, right: Option<OffsetDateTime>) -> Option<OffsetDateTime> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.max(right)),
        (Some(left), None) => Some(left),
        (None, right) => right,
    }
}

fn canonical_millis(value: OffsetDateTime) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        value.year(),
        value.month() as u8,
        value.day(),
        value.hour(),
        value.minute(),
        value.second(),
        value.millisecond(),
    )
}

fn validate_routing(
    routing: &RecipientDidDelegationRoutingV2,
) -> Result<(), RecipientDidVerificationError> {
    let uri: Uri = routing
        .origin
        .parse()
        .map_err(|_| RecipientDidVerificationError::invalid("routing origin is invalid"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| RecipientDidVerificationError::invalid("routing origin has no host"))?;
    let host = authority.host();
    if uri.scheme_str() != Some("https")
        || authority.port().is_some()
        || uri
            .path_and_query()
            .is_some_and(|value| value.as_str() != "/")
        || routing.origin != format!("https://{host}")
        || !is_canonical_dns_host(host)
        || routing.node_audience != format!("did:web:{host}")
    {
        return Err(RecipientDidVerificationError::invalid(
            "routing must be a canonical default-port HTTPS DNS origin and matching did:web audience",
        ));
    }
    Ok(())
}

fn is_canonical_dns_host(host: &str) -> bool {
    if host.len() > 253 || host.contains(':') || host.parse::<std::net::Ipv4Addr>().is_ok() {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

fn validate_action_for_service(
    action: &str,
    service: &str,
) -> Result<(), RecipientDidVerificationError> {
    let expected_prefix = format!("tinycloud.{service}/");
    let Some(name) = action.strip_prefix(&expected_prefix) else {
        return Err(RecipientDidVerificationError::invalid(
            "capability action namespace does not match its resource service",
        ));
    };
    if name.is_empty()
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'*')
        })
    {
        return Err(RecipientDidVerificationError::invalid(
            "capability action is not canonical",
        ));
    }
    Ok(())
}

fn validate_exact_path(path: &str) -> Result<(), RecipientDidVerificationError> {
    let lower = path.to_ascii_lowercase();
    if path.is_empty()
        || path
            .chars()
            .any(|character| character.is_control() || character == '\\')
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%2e")
        || path
            .split('/')
            .any(|segment| segment.is_empty() || segment == "." || segment == "..")
    {
        return Err(RecipientDidVerificationError::invalid(
            "recipient grant path is not canonical and exact",
        ));
    }
    Ok(())
}

//! Authenticated production inputs for the exact-email authority bridge.
//!
//! The operator record contains two exact Share signed-artifact wrappers: the
//! authority-material bundle and the signed Share policy. The adapter verifies
//! those wrappers, the embedded #117 parents, each status observation, and the
//! runtime attestation before exposing opaque authority ports.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{path::Path, sync::Arc};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::{
    ipld_core::cid::Cid,
    multihash_codetable::{Code, MultihashDigest},
};

use super::{
    ports::{
        AttestationEnrollmentProvider, AuthorityMaterialBundle, AuthorityMaterialProvider,
        FreshAuthenticatedStatusProvider, PortError,
    },
    types::{
        AuthorityMaterialHandle, Did, DidKey, NodeDelegationCid, PolicyCid, Sha256Digest,
        ShareDelegationCid,
    },
};
use crate::policy_authority::{AuthorityArtifactVerifier, VerifiedDelegation};
use crate::policy_capability::jcs;

const AUTHORITY_MATERIAL_DOMAIN: &[u8] = b"xyz.tinycloud.share/authority-material-bundle/v1\0";
const POLICY_DOMAIN: &[u8] = b"xyz.tinycloud.share/policy/v1\0";
const STATUS_DOMAIN: &[u8] = b"xyz.tinycloud.share/authority-status/v1\0";
const ATTESTATION_DOMAIN: &[u8] = b"xyz.tinycloud.share/enrollment-attestation/v1\0";

#[derive(Debug, thiserror::Error)]
pub enum AuthorityProviderError {
    #[error("authority material cannot be read")]
    Io,
    #[error("authority material schema is invalid")]
    Schema,
    #[error("authority material signature is invalid")]
    Signature,
    #[error("authority material artifact is invalid")]
    Artifact,
}

#[derive(Clone)]
struct LoadedMaterial {
    share_policy_cid: PolicyCid,
    share_delegation_cid: ShareDelegationCid,
    bundle: AuthorityMaterialBundle,
    statuses: Vec<(NodeDelegationCid, Vec<u8>)>,
    attestation: Vec<u8>,
}

#[derive(Clone)]
pub struct AuthenticatedAuthorityMaterialProvider {
    records: Arc<Vec<LoadedMaterial>>,
}

impl AuthenticatedAuthorityMaterialProvider {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, AuthorityProviderError> {
        let bytes = std::fs::read(path).map_err(|_| AuthorityProviderError::Io)?;
        Self::from_json(&bytes)
    }

    /// Reads `{ "records": [{ "authorityMaterial": <signed>, "policy": <signed> }] }`.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuthorityProviderError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| AuthorityProviderError::Schema)?;
        let values = match value {
            Value::Array(values) => values,
            Value::Object(mut object) if object.contains_key("records") => {
                match object.remove("records") {
                    Some(Value::Array(values)) => values,
                    _ => return Err(AuthorityProviderError::Schema),
                }
            }
            Value::Object(object)
                if object.contains_key("authorityMaterial") && object.contains_key("policy") =>
            {
                vec![Value::Object(object)]
            }
            _ => return Err(AuthorityProviderError::Schema),
        };
        if values.is_empty() {
            return Err(AuthorityProviderError::Schema);
        }
        Ok(Self {
            records: Arc::new(
                values
                    .into_iter()
                    .map(load_record)
                    .collect::<Result<_, _>>()?,
            ),
        })
    }

    fn record(
        &self,
        policy: &PolicyCid,
        delegation: &ShareDelegationCid,
        handle: &AuthorityMaterialHandle,
        digest: &Sha256Digest,
    ) -> Result<&LoadedMaterial, PortError> {
        self.records
            .iter()
            .find(|record| {
                &record.share_policy_cid == policy
                    && &record.share_delegation_cid == delegation
                    && &record.bundle.handle == handle
                    && &record.bundle.digest == digest
            })
            .ok_or(PortError::Denied)
    }

    pub fn status_provider(&self) -> AuthenticatedStatusProvider {
        AuthenticatedStatusProvider {
            records: Arc::clone(&self.records),
        }
    }

    pub fn attestation_provider(&self) -> AuthenticatedAttestationProvider {
        AuthenticatedAttestationProvider {
            records: Arc::clone(&self.records),
        }
    }
}

#[async_trait]
impl AuthorityMaterialProvider for AuthenticatedAuthorityMaterialProvider {
    async fn resolve(
        &self,
        policy: &PolicyCid,
        delegation: &ShareDelegationCid,
    ) -> Result<AuthorityMaterialBundle, PortError> {
        self.records
            .iter()
            .find(|record| {
                &record.share_policy_cid == policy && &record.share_delegation_cid == delegation
            })
            .map(|record| record.bundle.clone())
            .ok_or(PortError::Denied)
    }

    async fn resolve_exact(
        &self,
        policy: &PolicyCid,
        delegation: &ShareDelegationCid,
        handle: &AuthorityMaterialHandle,
        digest: &Sha256Digest,
    ) -> Result<AuthorityMaterialBundle, PortError> {
        Ok(self
            .record(policy, delegation, handle, digest)?
            .bundle
            .clone())
    }

    fn healthy(&self) -> bool {
        !self.records.is_empty()
    }
    fn healthy_at(&self, now: OffsetDateTime) -> bool {
        self.records
            .iter()
            .any(|record| record_is_current(record, now))
    }
}

#[derive(Clone)]
pub struct AuthenticatedStatusProvider {
    records: Arc<Vec<LoadedMaterial>>,
}

#[async_trait]
impl FreshAuthenticatedStatusProvider for AuthenticatedStatusProvider {
    async fn refresh(&self, delegation: &NodeDelegationCid) -> Result<Vec<u8>, PortError> {
        self.records
            .iter()
            .find_map(|record| {
                record
                    .statuses
                    .iter()
                    .find(|(cid, _)| cid == delegation)
                    .map(|(_, bytes)| bytes.clone())
            })
            .ok_or(PortError::Denied)
    }
    fn healthy(&self) -> bool {
        !self.records.is_empty()
    }
    fn healthy_at(&self, now: OffsetDateTime) -> bool {
        self.records
            .iter()
            .any(|record| record_is_current(record, now))
    }
}

#[derive(Clone)]
pub struct AuthenticatedAttestationProvider {
    records: Arc<Vec<LoadedMaterial>>,
}

#[async_trait]
impl AttestationEnrollmentProvider for AuthenticatedAttestationProvider {
    async fn attest(&self, audience: &Did, enforcer: &DidKey) -> Result<Vec<u8>, PortError> {
        self.records
            .iter()
            .find(|record| {
                serde_json::from_slice::<Value>(&record.attestation)
                    .ok()
                    .is_some_and(|value| {
                        value.get("nodeAudience").and_then(Value::as_str) == Some(audience.as_str())
                            && value.get("enforcerDid").and_then(Value::as_str)
                                == Some(enforcer.as_str())
                    })
            })
            .map(|record| record.attestation.clone())
            .ok_or(PortError::Denied)
    }
    fn healthy(&self) -> bool {
        !self.records.is_empty()
    }
    fn healthy_at(&self, now: OffsetDateTime) -> bool {
        self.records
            .iter()
            .any(|record| record_is_current(record, now))
    }
}

fn record_is_current(record: &LoadedMaterial, now: OffsetDateTime) -> bool {
    let statuses_current = record.statuses.len() == 2
        && record.statuses.iter().all(|(_, bytes)| {
            serde_json::from_slice::<Value>(bytes)
                .ok()
                .is_some_and(|value| {
                    value.get("state").and_then(Value::as_str) == Some("active")
                        && value
                            .get("freshUntil")
                            .and_then(Value::as_str)
                            .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
                            .is_some_and(|value| value > now)
                })
        });
    let attestation_current = serde_json::from_slice::<Value>(&record.attestation)
        .ok()
        .and_then(|value| {
            value
                .get("expiresAt")
                .and_then(Value::as_str)
                .map(str::to_owned)
        })
        .and_then(|value| OffsetDateTime::parse(&value, &Rfc3339).ok())
        .is_some_and(|value| value > now);
    statuses_current && attestation_current
}

fn load_record(value: Value) -> Result<LoadedMaterial, AuthorityProviderError> {
    let object = value.as_object().ok_or(AuthorityProviderError::Schema)?;
    exact_keys(object, &["authorityMaterial", "policy"])?;
    let (authority, sender_did) = verify_wrapper(
        object_field_from_map(object, "authorityMaterial")?,
        "authorityMaterial",
        AUTHORITY_MATERIAL_DOMAIN,
    )?;
    let (policy, policy_sender) = verify_wrapper(
        object_field_from_map(object, "policy")?,
        "policy",
        POLICY_DOMAIN,
    )?;
    if sender_did != policy_sender
        || string_field(&authority, "type")? != "TinyCloudShareAuthorityMaterial"
        || authority.get("version").and_then(Value::as_u64) != Some(1)
        || string_field(&authority, "senderDid")? != sender_did
    {
        return Err(AuthorityProviderError::Artifact);
    }
    let relationship = object_field(&authority, "relationship")?;
    exact_keys(
        relationship
            .as_object()
            .ok_or(AuthorityProviderError::Schema)?,
        &["policyOwnerDid", "senderDid", "authenticated"],
    )?;
    if relationship.get("authenticated") != Some(&Value::Bool(true))
        || relationship.get("senderDid").and_then(Value::as_str) != Some(sender_did.as_str())
        || relationship.get("policyOwnerDid") != authority.get("policyOwnerDid")
    {
        return Err(AuthorityProviderError::Artifact);
    }
    exact_keys(
        authority
            .as_object()
            .ok_or(AuthorityProviderError::Schema)?,
        &[
            "type",
            "version",
            "handle",
            "policyOwnerDid",
            "senderDid",
            "relationship",
            "mapping",
            "policyAuthorityBytes",
            "policyAuthorityCid",
            "policyEnforcementBytes",
            "policyEnforcementCid",
            "statusObservations",
            "enrollment",
            "attestation",
        ],
    )?;
    let mapping = object_field(&authority, "mapping")?;
    exact_keys(
        mapping.as_object().ok_or(AuthorityProviderError::Schema)?,
        &[
            "sharePolicyCid",
            "shareDelegationCid",
            "policyAuthorityCid",
            "policyEnforcementCid",
        ],
    )?;
    let share_policy_cid = PolicyCid::parse(string_field(mapping, "sharePolicyCid")?)
        .map_err(|_| AuthorityProviderError::Schema)?;
    let share_delegation_cid =
        ShareDelegationCid::parse(string_field(mapping, "shareDelegationCid")?)
            .map_err(|_| AuthorityProviderError::Schema)?;
    let policy_bytes = decode_bytes(&authority, "policyAuthorityBytes")?;
    let enforcement_bytes = decode_bytes(&authority, "policyEnforcementBytes")?;
    let policy_parent = AuthorityArtifactVerifier
        .verify(&policy_bytes)
        .map_err(|_| AuthorityProviderError::Artifact)?;
    let enforcement_parent = AuthorityArtifactVerifier
        .verify(&enforcement_bytes)
        .map_err(|_| AuthorityProviderError::Artifact)?;
    let policy_cid = parse_node_cid(mapping, "policyAuthorityCid")?;
    let enforcement_cid = parse_node_cid(mapping, "policyEnforcementCid")?;
    if policy_parent.artifact().delegation_cid != policy_cid.as_str()
        || enforcement_parent.artifact().delegation_cid != enforcement_cid.as_str()
        || policy_parent.artifact().issuer_did != enforcement_parent.artifact().issuer_did
        || string_field(&policy, "type")? != "TinyCloudSharePolicy"
        || policy.get("version").and_then(Value::as_u64) != Some(1)
        || string_field(&policy, "issuerDid")? != sender_did
    {
        return Err(AuthorityProviderError::Artifact);
    }
    let policy_state = jcs::canonicalize(&policy);
    if Cid::new_v1(0x55, Code::Sha2_256.digest(&policy_state)).to_string()
        != share_policy_cid.as_str()
    {
        return Err(AuthorityProviderError::Artifact);
    }
    let statuses = load_statuses(
        object_field(&authority, "statusObservations")?,
        &policy_cid,
        &enforcement_cid,
    )?;
    let enrollment = object_field(&authority, "enrollment")?;
    validate_enrollment(enrollment)?;
    let attestation = object_field(&authority, "attestation")?;
    validate_attestation(attestation, enrollment, &enforcement_parent)?;
    Ok(LoadedMaterial {
        share_policy_cid,
        share_delegation_cid,
        bundle: AuthorityMaterialBundle {
            handle: AuthorityMaterialHandle::parse(string_field(&authority, "handle")?)
                .map_err(|_| AuthorityProviderError::Schema)?,
            digest: Sha256Digest::from_bytes(Sha256::digest(jcs::canonicalize(&authority)).into()),
            policy_authority: policy_bytes,
            policy_enforcement: enforcement_bytes,
            policy_state,
            internal_policy_authority_cid: policy_cid,
            internal_policy_enforcement_cid: enforcement_cid.clone(),
            internal_delegation_cid: enforcement_cid,
        },
        statuses,
        attestation: serde_json::to_vec(attestation).map_err(|_| AuthorityProviderError::Schema)?,
    })
}

fn verify_wrapper(
    wrapper: &Value,
    name: &str,
    domain: &[u8],
) -> Result<(Value, String), AuthorityProviderError> {
    let object = wrapper.as_object().ok_or(AuthorityProviderError::Schema)?;
    exact_keys(
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
    if string_field(wrapper, "name")? != name
        || string_field(wrapper, "domain")?.as_bytes() != domain
    {
        return Err(AuthorityProviderError::Signature);
    }
    let signer = string_field(wrapper, "signerDid")?.to_owned();
    let message = object_field(wrapper, "message")?;
    let message_jcs = jcs::canonicalize(message);
    if string_field(wrapper, "jcs")?.as_bytes() != message_jcs.as_slice()
        || string_field(wrapper, "messageDigest")? != digest_b64(&message_jcs)
    {
        return Err(AuthorityProviderError::Artifact);
    }
    let mut signed = domain.to_vec();
    signed.extend_from_slice(&message_jcs);
    if string_field(wrapper, "signedBytesDigest")? != digest_b64(&signed) {
        return Err(AuthorityProviderError::Artifact);
    }
    let signature = object_field(wrapper, "signature")?;
    let signature_object = signature
        .as_object()
        .ok_or(AuthorityProviderError::Signature)?;
    exact_keys(signature_object, &["alg", "kid", "value"])?;
    let bytes = decode_signature(signature)?;
    if string_field(signature, "alg")? != "EdDSA"
        || string_field(signature, "kid")? != canonical_kid(&signer)
        || string_field(wrapper, "signatureDigest")? != digest_b64(&bytes)
    {
        return Err(AuthorityProviderError::Signature);
    }
    tinycloud_auth::share_email_evidence::verify_detached_ed25519(&signer, &signed, &bytes)
        .map_err(|_| AuthorityProviderError::Signature)?;
    Ok((message.clone(), signer))
}

fn load_statuses(
    value: &Value,
    policy_cid: &NodeDelegationCid,
    enforcement_cid: &NodeDelegationCid,
) -> Result<Vec<(NodeDelegationCid, Vec<u8>)>, AuthorityProviderError> {
    let values = value.as_array().ok_or(AuthorityProviderError::Schema)?;
    if values.len() != 2 {
        return Err(AuthorityProviderError::Schema);
    }
    let mut result = Vec::with_capacity(2);
    for status in values {
        let object = status.as_object().ok_or(AuthorityProviderError::Schema)?;
        exact_keys(
            object,
            &[
                "type",
                "version",
                "parentCid",
                "state",
                "sequence",
                "checkedAt",
                "freshUntil",
                "revokedAt",
                "signerKid",
                "signerVersion",
                "signature",
            ],
        )?;
        if string_field(status, "type")? != "TinyCloudShareAuthorityStatusObservation"
            || status.get("version").and_then(Value::as_u64) != Some(1)
            || string_field(status, "state")? != "active"
            || status.get("revokedAt") != Some(&Value::Null)
            || status.get("signerVersion").and_then(Value::as_u64) == Some(0)
        {
            return Err(AuthorityProviderError::Artifact);
        }
        let parent = NodeDelegationCid::parse(string_field(status, "parentCid")?)
            .map_err(|_| AuthorityProviderError::Schema)?;
        if (parent != *policy_cid && parent != *enforcement_cid)
            || result.iter().any(|(cid, _)| *cid == parent)
        {
            return Err(AuthorityProviderError::Artifact);
        }
        let checked = OffsetDateTime::parse(string_field(status, "checkedAt")?, &Rfc3339)
            .map_err(|_| AuthorityProviderError::Schema)?;
        let fresh = OffsetDateTime::parse(string_field(status, "freshUntil")?, &Rfc3339)
            .map_err(|_| AuthorityProviderError::Schema)?;
        if fresh <= checked || fresh - checked > time::Duration::seconds(300) {
            return Err(AuthorityProviderError::Artifact);
        }
        let signer_kid = string_field(status, "signerKid")?;
        let signer = signer_kid
            .split_once('#')
            .map(|(did, _)| did)
            .ok_or(AuthorityProviderError::Signature)?;
        let signature_object = object_field(status, "signature")?;
        if signer_kid != canonical_kid(signer)
            || string_field(status, "signerKid")? != string_field(signature_object, "kid")?
        {
            return Err(AuthorityProviderError::Signature);
        }
        let signature = decode_signature(signature_object)?;
        let mut unsigned = object.clone();
        unsigned.remove("signature");
        let mut signed = STATUS_DOMAIN.to_vec();
        signed.extend_from_slice(&jcs::canonicalize(&Value::Object(unsigned)));
        tinycloud_auth::share_email_evidence::verify_detached_ed25519(signer, &signed, &signature)
            .map_err(|_| AuthorityProviderError::Signature)?;
        result.push((
            parent,
            serde_json::to_vec(status).map_err(|_| AuthorityProviderError::Schema)?,
        ));
    }
    Ok(result)
}

fn validate_enrollment(value: &Value) -> Result<(), AuthorityProviderError> {
    let object = value.as_object().ok_or(AuthorityProviderError::Schema)?;
    exact_keys(
        object,
        &[
            "targetOrigin",
            "nodeAudience",
            "invitationKid",
            "invitationPublicKey",
            "keyVersion",
            "enabled",
        ],
    )?;
    if value.get("enabled") != Some(&Value::Bool(true))
        || value.get("keyVersion").and_then(Value::as_u64) == Some(0)
    {
        return Err(AuthorityProviderError::Artifact);
    }
    Ok(())
}

fn validate_attestation(
    value: &Value,
    enrollment: &Value,
    enforcement: &VerifiedDelegation,
) -> Result<(), AuthorityProviderError> {
    let object = value.as_object().ok_or(AuthorityProviderError::Schema)?;
    exact_keys(
        object,
        &[
            "type",
            "version",
            "targetOrigin",
            "nodeAudience",
            "enforcerDid",
            "enforcerKid",
            "publicKey",
            "keyVersion",
            "localSignerDid",
            "localSignerKid",
            "measurement",
            "measurementDigest",
            "expiresAt",
            "enrollmentDigest",
            "signature",
        ],
    )?;
    let target_origin = string_field(value, "targetOrigin")?;
    let node_audience = string_field(value, "nodeAudience")?;
    let enforcer_kid = string_field(value, "enforcerKid")?;
    let expires_at = OffsetDateTime::parse(string_field(value, "expiresAt")?, &Rfc3339)
        .map_err(|_| AuthorityProviderError::Schema)?;
    let enforcement_expires_at =
        OffsetDateTime::parse(&enforcement.artifact().expires_at, &Rfc3339)
            .map_err(|_| AuthorityProviderError::Artifact)?;
    let enforcement_not_before =
        OffsetDateTime::parse(&enforcement.artifact().not_before, &Rfc3339)
            .map_err(|_| AuthorityProviderError::Artifact)?;
    let binding = serde_json::json!({
        "targetOrigin": target_origin,
        "nodeAudience": node_audience,
        "enforcerDid": string_field(value, "enforcerDid")?,
        "enforcerKid": enforcer_kid,
        "keyVersion": value.get("keyVersion"),
    });
    let measurement_digest = URL_SAFE_NO_PAD
        .decode(string_field(value, "measurementDigest")?)
        .map_err(|_| AuthorityProviderError::Artifact)?;
    if string_field(value, "type")? != "TinyCloudShareEnrollmentRuntimeAttestation"
        || value.get("version").and_then(Value::as_u64) != Some(1)
        || value.get("targetOrigin") != enrollment.get("targetOrigin")
        || value.get("nodeAudience") != enrollment.get("nodeAudience")
        || value.get("keyVersion") != enrollment.get("keyVersion")
        || value.get("publicKey") != enrollment.get("invitationPublicKey")
        || !enforcer_kid.starts_with(&format!("{node_audience}#"))
        || string_field(value, "enrollmentDigest")? != digest_b64(&jcs::canonicalize(enrollment))
        || measurement_digest.len() != 32
        || expires_at <= enforcement_not_before
        || expires_at > enforcement_expires_at
    {
        return Err(AuthorityProviderError::Artifact);
    }
    let enforcer = string_field(value, "enforcerDid")?;
    if enforcer
        != enforcement
            .artifact()
            .fact_value("enforcerDid")
            .map_err(|_| AuthorityProviderError::Artifact)?
        || string_field(value, "localSignerDid")? != enforcer
        || string_field(value, "localSignerKid")? != canonical_kid(enforcer)
    {
        return Err(AuthorityProviderError::Artifact);
    }
    let expected_binding = enforcement
        .artifact()
        .fact_value("attestationBindingDigestHex")
        .map_err(|_| AuthorityProviderError::Artifact)?;
    if expected_binding != digest_b64(&jcs::canonicalize(&binding)) {
        return Err(AuthorityProviderError::Artifact);
    }
    let signature_object = object_field(value, "signature")?;
    let signature = decode_signature(signature_object)?;
    if string_field(signature_object, "kid")? != canonical_kid(enforcer) {
        return Err(AuthorityProviderError::Signature);
    }
    let mut unsigned = object.clone();
    unsigned.remove("signature");
    let mut signed = ATTESTATION_DOMAIN.to_vec();
    signed.extend_from_slice(&jcs::canonicalize(&Value::Object(unsigned)));
    tinycloud_auth::share_email_evidence::verify_detached_ed25519(enforcer, &signed, &signature)
        .map_err(|_| AuthorityProviderError::Signature)
}

fn exact_keys(
    object: &Map<String, Value>,
    expected: &[&str],
) -> Result<(), AuthorityProviderError> {
    if object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key)) {
        Ok(())
    } else {
        Err(AuthorityProviderError::Schema)
    }
}

fn object_field<'a>(value: &'a Value, key: &str) -> Result<&'a Value, AuthorityProviderError> {
    value
        .as_object()
        .and_then(|object| object.get(key))
        .ok_or(AuthorityProviderError::Schema)
}
fn object_field_from_map<'a>(
    object: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Value, AuthorityProviderError> {
    object.get(key).ok_or(AuthorityProviderError::Schema)
}
fn string_field<'a>(value: &'a Value, key: &str) -> Result<&'a str, AuthorityProviderError> {
    object_field(value, key)?
        .as_str()
        .filter(|value| !value.is_empty())
        .ok_or(AuthorityProviderError::Schema)
}
fn decode_bytes(value: &Value, key: &str) -> Result<Vec<u8>, AuthorityProviderError> {
    let encoded = string_field(value, key)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AuthorityProviderError::Schema)?;
    if URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(AuthorityProviderError::Schema);
    }
    Ok(bytes)
}
fn decode_signature(value: &Value) -> Result<Vec<u8>, AuthorityProviderError> {
    let encoded = string_field(value, "value")?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AuthorityProviderError::Signature)?;
    if bytes.len() != 64 || URL_SAFE_NO_PAD.encode(&bytes) != encoded {
        return Err(AuthorityProviderError::Signature);
    }
    Ok(bytes)
}
fn parse_node_cid(value: &Value, key: &str) -> Result<NodeDelegationCid, AuthorityProviderError> {
    NodeDelegationCid::parse(string_field(value, key)?).map_err(|_| AuthorityProviderError::Schema)
}
fn digest_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(bytes))
}
fn canonical_kid(did: &str) -> String {
    format!("{did}#{}", did.trim_start_matches("did:key:"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_or_unsigned_material_never_becomes_healthy() {
        assert!(AuthenticatedAuthorityMaterialProvider::from_json(br"{}").is_err());
        assert!(AuthenticatedAuthorityMaterialProvider::from_json(br"[]").is_err());
    }

    #[test]
    fn exact_share_authority_and_policy_artifacts_are_consumed() {
        let root = std::env::var_os("TINYCLOUD_EMAIL_CLAIM_VECTOR_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| {
                std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../../share/feat/email-claim-e1-e2e/test/vectors/email-claim-v1")
            });
        let positive: Value =
            serde_json::from_slice(&std::fs::read(root.join("positive.json")).unwrap()).unwrap();
        let scenario = &positive["scenarios"][0];
        let authority = scenario["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["name"] == "authorityMaterial")
            .unwrap();
        let policy = scenario["artifacts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["name"] == "policy")
            .unwrap();
        let record = serde_json::json!({"authorityMaterial": authority, "policy": policy});
        let provider_result = AuthenticatedAuthorityMaterialProvider::from_json(
            &serde_json::to_vec(&record).unwrap(),
        );
        if let Err(error) = &provider_result {
            panic!("{error:?}");
        }
        let provider = provider_result.unwrap();
        let digest =
            Sha256Digest::parse(scenario["authorityMaterialDigest"].as_str().unwrap()).unwrap();
        let handle =
            AuthorityMaterialHandle::parse(scenario["authorityMaterialHandle"].as_str().unwrap())
                .unwrap();
        let share_policy = PolicyCid::parse(scenario["policyCid"].as_str().unwrap()).unwrap();
        let share_delegation =
            ShareDelegationCid::parse(scenario["delegationCid"].as_str().unwrap()).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        assert!(runtime
            .block_on(provider.resolve_exact(&share_policy, &share_delegation, &handle, &digest))
            .is_ok());
    }
}

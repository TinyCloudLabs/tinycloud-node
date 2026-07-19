//! Authenticated production inputs for the exact-email authority bridge.
//!
//! The provider is intentionally file-backed rather than request-backed. The
//! file is an operator-delivered, owner-signed bundle containing the canonical
//! #117 artifacts and the Share-domain mapping. Every lookup rechecks the
//! typed Share identifiers; a handle or session field is never authority.

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Deserialize;
use serde_json::Value;
use std::{path::Path, sync::Arc};

use super::{
    ports::{
        AttestationEnrollmentProvider, AuthorityMaterialBundle, AuthorityMaterialProvider,
        FreshAuthenticatedStatusProvider, PortError,
    },
    types::{Did, DidKey, NodeDelegationCid, PolicyCid, ShareDelegationCid},
};
use crate::policy_authority::AuthorityArtifactVerifier;
use crate::policy_capability::jcs;

const AUTHORITY_MATERIAL_DOMAIN: &[u8] = b"xyz.tinycloud.share/authority-material-bundle/v1\0";

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
    status: Vec<u8>,
    attestation: Vec<u8>,
}

/// The production provider reads one or more operator-authenticated records.
/// A JSON array is accepted so key rotation can retain overlapping records;
/// each record is independently verified before it enters the resolver.
#[derive(Clone)]
pub struct AuthenticatedAuthorityMaterialProvider {
    records: Arc<Vec<LoadedMaterial>>,
}

impl AuthenticatedAuthorityMaterialProvider {
    pub fn from_path(path: impl AsRef<Path>) -> Result<Self, AuthorityProviderError> {
        let bytes = std::fs::read(path).map_err(|_| AuthorityProviderError::Io)?;
        Self::from_json(&bytes)
    }

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
            Value::Object(object) => vec![Value::Object(object)],
            _ => return Err(AuthorityProviderError::Schema),
        };
        if values.is_empty() {
            return Err(AuthorityProviderError::Schema);
        }
        let mut records = Vec::with_capacity(values.len());
        for value in values {
            records.push(load_record(value)?);
        }
        Ok(Self {
            records: Arc::new(records),
        })
    }

    fn record(
        &self,
        policy: &PolicyCid,
        delegation: &ShareDelegationCid,
    ) -> Result<&LoadedMaterial, PortError> {
        self.records
            .iter()
            .find(|record| {
                &record.share_policy_cid == policy && &record.share_delegation_cid == delegation
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
        Ok(self.record(policy, delegation)?.bundle.clone())
    }

    fn healthy(&self) -> bool {
        !self.records.is_empty()
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
            .find(|record| {
                record.bundle.internal_policy_authority_cid == *delegation
                    || record.bundle.internal_policy_enforcement_cid == *delegation
            })
            .map(|record| record.status.clone())
            .ok_or(PortError::Denied)
    }

    fn healthy(&self) -> bool {
        !self.records.is_empty()
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
                record.attestation_value().ok().is_some_and(|value| {
                    value.get("audience").and_then(Value::as_str) == Some(audience.as_str())
                        && value
                            .get("enforcerKid")
                            .and_then(Value::as_str)
                            .is_some_and(|kid| kid.starts_with(enforcer.as_str()))
                })
            })
            .map(|record| record.attestation.clone())
            .ok_or(PortError::Denied)
    }

    fn healthy(&self) -> bool {
        !self.records.is_empty()
    }
}

impl LoadedMaterial {
    fn attestation_value(&self) -> Result<Value, AuthorityProviderError> {
        serde_json::from_slice(&self.attestation).map_err(|_| AuthorityProviderError::Schema)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct SignatureEnvelope {
    alg: String,
    kid: String,
    value: String,
}

fn load_record(mut value: Value) -> Result<LoadedMaterial, AuthorityProviderError> {
    let object = value
        .as_object_mut()
        .ok_or(AuthorityProviderError::Schema)?;
    let signature_value = object
        .remove("signature")
        .ok_or(AuthorityProviderError::Signature)?;
    let signature: SignatureEnvelope =
        serde_json::from_value(signature_value).map_err(|_| AuthorityProviderError::Signature)?;
    if signature.alg != "EdDSA" || signature.kid.is_empty() {
        return Err(AuthorityProviderError::Signature);
    }
    let signed_bundle = Value::Object(object.clone());
    let bytes = jcs::canonicalize(&signed_bundle);
    let owner = signed_bundle
        .get("ownerDid")
        .and_then(Value::as_str)
        .ok_or(AuthorityProviderError::Schema)?;
    if signature.kid != format!("{}#{}", owner, owner.trim_start_matches("did:key:")) {
        return Err(AuthorityProviderError::Signature);
    }
    let mut signed = AUTHORITY_MATERIAL_DOMAIN.to_vec();
    signed.extend_from_slice(&bytes);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(signature.value.as_bytes())
        .map_err(|_| AuthorityProviderError::Signature)?;
    tinycloud_auth::share_email_evidence::verify_detached_ed25519(owner, &signed, &signature_bytes)
        .map_err(|_| AuthorityProviderError::Signature)?;

    let share_policy_cid = PolicyCid::parse(required_string(&signed_bundle, "sharePolicyCid")?)
        .map_err(|_| AuthorityProviderError::Schema)?;
    let share_delegation_cid =
        ShareDelegationCid::parse(required_string(&signed_bundle, "shareDelegationCid")?)
            .map_err(|_| AuthorityProviderError::Schema)?;
    for (field, expected) in [
        ("sharePolicyCid", share_policy_cid.as_str()),
        ("shareDelegationCid", share_delegation_cid.as_str()),
    ] {
        if signed_bundle
            .get("policyAuthority")
            .and_then(|value| value.get(field))
            .and_then(Value::as_str)
            .is_some_and(|value| value != expected)
        {
            return Err(AuthorityProviderError::Artifact);
        }
    }
    if signed_bundle
        .get("policyAuthority")
        .and_then(|value| value.get("ownerDid"))
        .and_then(Value::as_str)
        .is_some_and(|value| value != owner)
    {
        return Err(AuthorityProviderError::Artifact);
    }
    let policy_bytes = decode_bytes(&signed_bundle, "policyAuthorityBytes")?;
    let enforcement_bytes = decode_bytes(&signed_bundle, "policyEnforcementBytes")?;
    let policy = AuthorityArtifactVerifier
        .verify(&policy_bytes)
        .map_err(|_| AuthorityProviderError::Artifact)?;
    let enforcement = AuthorityArtifactVerifier
        .verify(&enforcement_bytes)
        .map_err(|_| AuthorityProviderError::Artifact)?;
    let policy_cid = node_cid(
        &signed_bundle,
        "internalPolicyAuthorityCid",
        "policyAuthorityCid",
    )?;
    let enforcement_cid = node_cid(
        &signed_bundle,
        "internalPolicyEnforcementCid",
        "policyEnforcementCid",
    )?;
    if policy.artifact().delegation_cid != policy_cid.as_str()
        || enforcement.artifact().delegation_cid != enforcement_cid.as_str()
        || policy
            .artifact()
            .fact_value("ownerDid")
            .map_err(|_| AuthorityProviderError::Artifact)?
            != owner
    {
        return Err(AuthorityProviderError::Artifact);
    }
    let policy_state = decode_bytes(&signed_bundle, "sharePolicyBytes")?;
    let internal_delegation_cid = signed_bundle
        .get("internalDelegationCid")
        .and_then(Value::as_str)
        .or_else(|| {
            signed_bundle
                .get("internalPolicyEnforcementCid")
                .and_then(Value::as_str)
        })
        .or_else(|| {
            signed_bundle
                .get("policyEnforcementCid")
                .and_then(Value::as_str)
        })
        .ok_or(AuthorityProviderError::Schema)
        .and_then(|value| {
            NodeDelegationCid::parse(value).map_err(|_| AuthorityProviderError::Schema)
        })?;
    let status = serde_json::to_vec(
        signed_bundle
            .get("status")
            .ok_or(AuthorityProviderError::Schema)?,
    )
    .map_err(|_| AuthorityProviderError::Schema)?;
    let attestation = serde_json::to_vec(
        signed_bundle
            .get("attestation")
            .ok_or(AuthorityProviderError::Schema)?,
    )
    .map_err(|_| AuthorityProviderError::Schema)?;
    Ok(LoadedMaterial {
        share_policy_cid: share_policy_cid.clone(),
        share_delegation_cid: share_delegation_cid.clone(),
        bundle: AuthorityMaterialBundle {
            policy_authority: policy_bytes,
            policy_enforcement: enforcement_bytes,
            policy_state,
            internal_policy_authority_cid: policy_cid,
            internal_policy_enforcement_cid: enforcement_cid,
            internal_delegation_cid,
        },
        status,
        attestation,
    })
}

fn required_string<'a>(value: &'a Value, key: &str) -> Result<&'a str, AuthorityProviderError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(AuthorityProviderError::Schema)
}

fn decode_bytes(value: &Value, key: &str) -> Result<Vec<u8>, AuthorityProviderError> {
    let encoded = required_string(value, key)?;
    URL_SAFE_NO_PAD
        .decode(encoded.as_bytes())
        .map_err(|_| AuthorityProviderError::Schema)
}

fn node_cid(
    value: &Value,
    preferred: &str,
    fallback: &str,
) -> Result<NodeDelegationCid, AuthorityProviderError> {
    for key in [preferred, fallback] {
        if let Some(raw) = value.get(key).and_then(Value::as_str) {
            if let Ok(cid) = NodeDelegationCid::parse(raw) {
                return Ok(cid);
            }
        }
    }
    Err(AuthorityProviderError::Schema)
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
    fn status_and_attestation_are_not_request_constructible() {
        let _ = std::mem::size_of::<AuthenticatedStatusProvider>();
        let _ = std::mem::size_of::<AuthenticatedAttestationProvider>();
    }
}

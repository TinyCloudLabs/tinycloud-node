//! Inline owner proof for space lifecycle operations; independent of delegation rows.
use crate::did_resolution::verify_ucan_signature;
use tinycloud_auth::{
    authorization::TinyCloudInvocation,
    identity::{canonicalize_did, principal_did},
};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OwnerProofError {
    #[error("authentication failed")]
    Invalid,
    #[error("not found")]
    NotOwner,
    #[error("host mismatch")]
    HostMismatch,
}

pub struct OwnerProof {
    pub owner_did: String,
    pub nonce: String,
    pub expires_at: i64,
    pub idempotency_key: String,
}

/// Verify before any resource-existence lookup. Proof-bearing session tokens
/// cannot authorize lifecycle operations even when their root is the owner.
pub async fn verify_owner(
    invocation: &TinyCloudInvocation,
    action: &str,
    exact_resource: &str,
    expected_owner: &str,
    idempotency_header: &str,
    now: i64,
) -> Result<OwnerProof, OwnerProofError> {
    verify_ucan_signature(invocation)
        .await
        .map_err(|_| OwnerProofError::Invalid)?;
    owner_fields(
        invocation,
        action,
        exact_resource,
        expected_owner,
        idempotency_header,
        now,
    )
}

/// Signature-bound host routing is checked before owner, nonce or state lookup.
pub async fn verify_owner_for_host(
    invocation: &TinyCloudInvocation,
    action: &str,
    exact_resource: &str,
    expected_owner: &str,
    idempotency_header: &str,
    expected_host: &str,
    now: i64,
) -> Result<OwnerProof, OwnerProofError> {
    verify_ucan_signature(invocation)
        .await
        .map_err(|_| OwnerProofError::Invalid)?;
    let mut hosts = invocation
        .payload()
        .facts
        .as_ref()
        .into_iter()
        .flatten()
        .filter_map(|fact| fact.get("hostId"));
    if hosts.next().and_then(serde_json::Value::as_str) != Some(expected_host)
        || hosts.next().is_some()
    {
        return Err(OwnerProofError::HostMismatch);
    }
    owner_fields(
        invocation,
        action,
        exact_resource,
        expected_owner,
        idempotency_header,
        now,
    )
}

fn owner_fields(
    invocation: &TinyCloudInvocation,
    action: &str,
    exact_resource: &str,
    expected_owner: &str,
    idempotency_header: &str,
    now: i64,
) -> Result<OwnerProof, OwnerProofError> {
    let payload = invocation.payload();
    let parsed_owner: tinycloud_auth::ssi::dids::DIDBuf = expected_owner
        .parse()
        .map_err(|_| OwnerProofError::Invalid)?;
    let owner = canonicalize_did(parsed_owner.as_str()).map_err(|_| OwnerProofError::Invalid)?;
    let signer = principal_did(payload.issuer.as_str()).map_err(|_| OwnerProofError::Invalid)?;
    if !owner.starts_with("did:pkh:")
        || !signer.starts_with("did:pkh:")
        || canonicalize_did(payload.audience.as_str()).map_err(|_| OwnerProofError::Invalid)?
            != signer
        || !payload.proof.is_empty()
    {
        return Err(OwnerProofError::Invalid);
    }
    if signer != owner {
        return Err(OwnerProofError::NotOwner);
    }
    let nbf = payload
        .not_before
        .ok_or(OwnerProofError::Invalid)?
        .as_seconds();
    let exp = payload.expiration.as_seconds();
    if !nbf.is_finite()
        || !exp.is_finite()
        || nbf > now as f64
        || exp <= now as f64
        || exp <= nbf
        || exp - nbf > 300.0
    {
        return Err(OwnerProofError::Invalid);
    }
    let nonce = payload.nonce.as_deref().ok_or(OwnerProofError::Invalid)?;
    if nonce.is_empty()
        || nonce.len() > 256
        || !nonce.is_ascii()
        || nonce.bytes().any(|b| b.is_ascii_control())
    {
        return Err(OwnerProofError::Invalid);
    }
    let mut capabilities =
        payload
            .attenuation
            .abilities()
            .iter()
            .flat_map(|(resource, abilities)| {
                abilities
                    .iter()
                    .map(move |(ability, caveats)| (resource, ability, caveats))
            });
    let (resource, ability, caveats) = capabilities.next().ok_or(OwnerProofError::Invalid)?;
    if capabilities.next().is_some()
        || if resource.as_str().starts_with("did:") {
            canonicalize_did(resource.as_str()).map_err(|_| OwnerProofError::Invalid)?
                != exact_resource
        } else if resource.as_str().starts_with("tinycloud:") {
            resource
                .as_str()
                .parse::<tinycloud_auth::resource::ResourceId>()
                .map_err(|_| OwnerProofError::Invalid)?
                .to_string()
                != exact_resource
        } else {
            crate::resource_purge_fence::ResourceTarget::parse(resource.as_str())
                .map_err(|_| OwnerProofError::Invalid)?
                .as_str()
                != exact_resource
        }
        || ability.as_ref() != action
        || caveats.as_ref().len() > 1
        || caveats.as_ref().iter().any(|caveat| !caveat.is_empty())
    {
        return Err(OwnerProofError::Invalid);
    }
    let facts = payload.facts.as_deref().ok_or(OwnerProofError::Invalid)?;
    let mut bindings = facts.iter().filter_map(|fact| fact.get("idempotency_key"));
    if bindings.next().and_then(serde_json::Value::as_str) != Some(idempotency_header)
        || bindings.next().is_some()
    {
        return Err(OwnerProofError::Invalid);
    }
    let idempotency =
        uuid::Uuid::parse_str(idempotency_header).map_err(|_| OwnerProofError::Invalid)?;
    Ok(OwnerProof {
        owner_did: owner,
        nonce: nonce.to_owned(),
        expires_at: exp.ceil() as i64,
        idempotency_key: idempotency.to_string(),
    })
}

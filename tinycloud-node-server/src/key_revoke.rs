use rocket::{http::Status, serde::json::Json, State};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation},
    identity::{canonicalize_did, principal_did},
    resource::SpaceId,
    siwe_recap::Capability as SiweRecap,
    ssi::dids::DID,
};
use tinycloud_core::{
    encryption_network::EncryptionService,
    models::key_revocation::{KeyRevokeError, KeyRevokeReceipt, KeyRevokeScope, VerifiedKeyRevoke},
};

use crate::TinyCloud;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct KeyRevokeRequest {
    target_did: String,
    scope: KeyRevokeScope,
    authorization: String,
}

const MALFORMED: (Status, &str) = (Status::BadRequest, "key_revocation_invalid_request");
const UNAUTHENTICATED: (Status, &str) = (Status::Unauthorized, "key_revocation_invalid_signature");

/// Parse the signed grant without allowing the unsigned request body to
/// broaden its scope or replace the principal named by its capability.
async fn verify_request(
    request: KeyRevokeRequest,
    node_did: &str,
) -> Result<VerifiedKeyRevoke, (Status, &'static str)> {
    let target_did = request.target_did;
    if target_did.len() > 255
        || target_did
            .bytes()
            .any(|byte| matches!(byte, b'#' | b'?' | b'/'))
        || DID::new(&target_did).is_err()
        || canonicalize_did(&target_did).ok().as_deref() != Some(&target_did)
    {
        return Err(MALFORMED);
    }
    if let KeyRevokeScope::Space { space_id } = &request.scope {
        if space_id.len() > 249
            || space_id
                .parse::<SpaceId>()
                .map_or(true, |space| space.to_string() != *space_id)
        {
            return Err(MALFORMED);
        }
    }
    if request.authorization.len() > 16_384 {
        return Err(MALFORMED);
    }
    let (authorization, bytes) =
        TinyCloudDelegation::decode(&request.authorization).map_err(|_| UNAUTHENTICATED)?;
    let expected_resource = format!("urn:tinycloud:key:{target_did}");
    let expected_caveat =
        json!({ "version": 1, "targetDid": &target_did, "scope": &request.scope });

    let (issuer, audience, nonce, not_before, valid_after, expires_at, proof_cids) =
        match authorization {
            TinyCloudDelegation::Ucan(ucan) => {
                if ucan.header().algorithm != tinycloud_auth::ssi::jwk::Algorithm::EdDSA
                    || !ucan.payload().issuer.as_str().starts_with("did:key:")
                {
                    return Err(UNAUTHENTICATED);
                }
                tinycloud_core::did_resolution::verify_ucan_signature(&ucan)
                    .await
                    .map_err(|_| UNAUTHENTICATED)?;
                let payload = ucan.payload();
                let attenuation =
                    serde_json::to_value(&payload.attenuation).map_err(|_| MALFORMED)?;
                if attenuation
                    != json!({(expected_resource): {"tinycloud.key/revoke": [expected_caveat]}})
                {
                    return Err(MALFORMED);
                }
                let nbf = payload.not_before.ok_or(MALFORMED)?.as_seconds();
                let exp = payload.expiration.as_seconds();
                (
                    payload.issuer.to_string(),
                    payload.audience.to_string(),
                    payload.nonce.clone().ok_or(MALFORMED)?,
                    signed_seconds(nbf)?,
                    None,
                    signed_seconds(exp)?,
                    payload
                        .proof
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                )
            }
            TinyCloudDelegation::Cacao(cacao) => {
                cacao.verify().await.map_err(|_| UNAUTHENTICATED)?;
                let payload = cacao.payload();
                if !payload.iss.to_string().starts_with("did:pkh:eip155:") {
                    return Err(UNAUTHENTICATED);
                }
                let message: tinycloud_auth::cacaos::siwe::Message =
                    payload.clone().try_into().map_err(|_| MALFORMED)?;
                let recap = SiweRecap::<Value>::extract_and_verify(&message)
                    .map_err(|_| MALFORMED)?
                    .ok_or(MALFORMED)?;
                let (capabilities, proofs) = recap.into_inner();
                let mut entries = capabilities.into_inner().into_iter();
                let (resource, abilities) = entries.next().ok_or(MALFORMED)?;
                if entries.next().is_some() || resource.as_str() != expected_resource {
                    return Err(MALFORMED);
                }
                let mut actions = abilities.into_iter();
                let (action, caveats) = actions.next().ok_or(MALFORMED)?;
                if actions.next().is_some() || action.to_string() != "tinycloud.key/revoke" {
                    return Err(MALFORMED);
                }
                let caveats = caveats.into_inner();
                if caveats.len() != 1
                    || serde_json::to_value(&caveats[0]).map_err(|_| MALFORMED)? != expected_caveat
                {
                    return Err(MALFORMED);
                }
                let issued = payload.iat.as_ref();
                let expiry = payload.exp.as_ref().ok_or(MALFORMED)?.as_ref();
                if expiry <= issued || *expiry - *issued > time::Duration::seconds(60) {
                    return Err(MALFORMED);
                }
                (
                    payload.iss.to_string(),
                    payload.aud.to_string(),
                    message.nonce,
                    ceil_second(issued)?,
                    payload
                        .nbf
                        .as_ref()
                        .map(|value| ceil_second(value.as_ref()))
                        .transpose()?,
                    expiry.unix_timestamp(),
                    proofs.iter().map(ToString::to_string).collect::<Vec<_>>(),
                )
            }
        };
    let issuer_did = principal_did(&issuer).map_err(|_| UNAUTHENTICATED)?;
    if audience != node_did
        || !(issuer_did.starts_with("did:key:") || issuer_did.starts_with("did:pkh:eip155:"))
    {
        return Err(UNAUTHENTICATED);
    }
    if nonce.is_empty()
        || nonce.len() > 128
        || expires_at
            .checked_sub(not_before)
            .is_none_or(|seconds| !(1..=60).contains(&seconds))
        || proof_cids.len() > 64
    {
        return Err(MALFORMED);
    }
    Ok(VerifiedKeyRevoke {
        target_did,
        issuer_did,
        scope: request.scope,
        nonce,
        authorization_hash: Sha256::digest(bytes).into(),
        proof_cids,
        not_before,
        valid_after,
        expires_at,
    })
}

fn signed_seconds(seconds: f64) -> Result<i64, (Status, &'static str)> {
    if seconds.is_finite()
        && seconds.fract() == 0.0
        && seconds >= i64::MIN as f64
        && seconds < i64::MAX as f64
    {
        Ok(seconds as i64)
    } else {
        Err(MALFORMED)
    }
}

fn ceil_second(timestamp: &time::OffsetDateTime) -> Result<i64, (Status, &'static str)> {
    let seconds = timestamp.unix_timestamp();
    if timestamp.nanosecond() == 0 {
        Ok(seconds)
    } else {
        seconds.checked_add(1).ok_or(MALFORMED)
    }
}

#[post("/keys/revoke", format = "json", data = "<request>")]
pub async fn revoke_key(
    request: Json<Value>,
    tinycloud: &State<TinyCloud>,
    encryption: &State<EncryptionService>,
) -> Result<Json<KeyRevokeReceipt>, (Status, String)> {
    let request: KeyRevokeRequest = serde_json::from_value(request.into_inner())
        .map_err(|_| (Status::BadRequest, MALFORMED.1.to_string()))?;
    let verified = verify_request(request, encryption.node_did())
        .await
        .map_err(|(status, message)| (status, message.to_string()))?;
    let receipt = tinycloud
        .revoke_key(verified)
        .await
        .map_err(|error| match error {
            KeyRevokeError::Forbidden => (Status::Forbidden, "key_revocation_forbidden".into()),
            KeyRevokeError::Conflict => (Status::Conflict, "key_revocation_conflict".into()),
            KeyRevokeError::Db {
                write_may_have_applied: false,
                ..
            } => (
                Status::ServiceUnavailable,
                "unavailable_retryable: key_revocation_unavailable".into(),
            ),
            KeyRevokeError::Db {
                write_may_have_applied: true,
                ..
            } => (
                Status::InternalServerError,
                "outcome_unknown: key_revocation_unavailable".into(),
            ),
        })?;
    Ok(Json(receipt))
}

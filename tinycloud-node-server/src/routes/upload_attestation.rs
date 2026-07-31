//! Owner/session-bound upload attestations for Share.
//!
//! This route is deliberately a small authorization adapter.  It does not
//! authorize an upload from the HTTP header shape: the normal invocation
//! verifier checks the signature, time window, delegation graph, and live
//! revocation state before this module mints anything.

use base64::{encode_config, URL_SAFE_NO_PAD};
use rocket::{
    data::{Data, ToByteUnit},
    http::Status,
    response::status::Custom,
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};
use tinycloud_auth::identity::did_principal_matches;
use tinycloud_core::{
    models::{delegation, invocation as invocation_model},
    policy_capability::jcs,
    sea_orm::EntityTrait,
    share_email::{
        invitation::{random_protocol_jti, Ed25519InvitationSigner, InvitationSigner},
        types::TargetOrigin,
    },
    types::Resource,
    util::{Capability, InvocationInfo},
};
use tokio::io::AsyncReadExt;

use crate::{
    authorization::AuthHeaderGetter,
    config::{Config, ShareEmailConfig},
    invocation_replay::InvocationReplayCache,
    share_v2,
};

const DOMAIN: &[u8] = b"xyz.tinycloud.share/upload-attestation/v1\0";
const MAX_UPLOAD_METADATA_BYTES: usize = 64 * 1024;
const MAX_UPLOAD_BYTES: u64 = share_v2::MAX_BODY_BYTES as u64;
const MAX_RETENTION_BYTES: usize = 1024;
const BASELINE_ABILITY: &str = "tinycloud.capabilities/read";

#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    error: ApiError,
}

#[derive(Debug, Serialize)]
pub struct ApiError {
    code: &'static str,
}

type ApiErrorResponse = Custom<Json<ApiErrorBody>>;

fn error(status: Status, code: &'static str) -> ApiErrorResponse {
    Custom(
        status,
        Json(ApiErrorBody {
            error: ApiError { code },
        }),
    )
}

/// The node-side signer is the same derived Ed25519 key advertised through
/// the existing Share trust bundle.  The private key is held only in memory.
pub struct UploadAttestationRuntime {
    conn: tinycloud_core::sea_orm::DatabaseConnection,
    signer: Arc<Ed25519InvitationSigner>,
    issuer: String,
    share_origin: String,
}

impl UploadAttestationRuntime {
    pub fn compose(
        conn: tinycloud_core::sea_orm::DatabaseConnection,
        key_setup: &tinycloud_core::keys::StaticSecret,
        config: &ShareEmailConfig,
    ) -> anyhow::Result<Self> {
        let share_origin = TargetOrigin::parse(config.return_origin.clone())?
            .as_str()
            .to_owned();
        let key = key_setup.derive_key(b"tinycloud/share-email/invitation-signing");
        let secret = tinycloud_core::libp2p::identity::ed25519::SecretKey::try_from_bytes(key)
            .map_err(|_| anyhow::anyhow!("invalid upload attestation signing key"))?;
        let keypair = tinycloud_core::libp2p::identity::ed25519::Keypair::from(secret);
        let signer = Ed25519InvitationSigner::new(config.node_signing_kid.clone(), keypair.into())?;
        Ok(Self {
            conn,
            signer: Arc::new(signer),
            issuer: config.node_audience.clone(),
            share_origin,
        })
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct UploadAttestationRequest {
    pub share_origin: String,
    pub encrypted_blob_cid: String,
    #[serde(alias = "sha256", alias = "encryptedBlobDigest")]
    pub encrypted_blob_sha256: String,
    pub byte_length: u64,
    pub delete_after: String,
    pub retention: Value,
    pub request_body_digest: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UploadAttestation {
    #[serde(rename = "type")]
    pub artifact_type: &'static str,
    pub version: u8,
    pub issuer: String,
    pub kid: String,
    pub owner_did: String,
    pub session_did: String,
    pub share_origin: String,
    pub encrypted_blob_cid: String,
    pub encrypted_blob_sha256: String,
    pub byte_length: u64,
    pub delete_after: String,
    pub retention: Value,
    pub issued_at: String,
    pub expires_at: String,
    pub jti: String,
    pub signature: String,
}

#[post("/share/upload/attestation", format = "json", data = "<data>")]
pub async fn mint_upload_attestation(
    data: Data<'_>,
    invocation: AuthHeaderGetter<InvocationInfo>,
    runtime: &State<Option<UploadAttestationRuntime>>,
    replay: &State<InvocationReplayCache>,
    config: &State<Config>,
) -> Result<Json<UploadAttestation>, ApiErrorResponse> {
    let runtime = runtime.inner().as_ref().ok_or(error(
        Status::ServiceUnavailable,
        "upload_authority_unavailable",
    ))?;
    let raw = read_body(data).await?;
    let body_value: Value = serde_json::from_slice(&raw)
        .map_err(|_| error(Status::BadRequest, "upload_attestation_invalid"))?;
    if jcs::canonicalize(&body_value) != raw {
        return Err(error(Status::BadRequest, "upload_attestation_invalid"));
    }
    let request: UploadAttestationRequest = serde_json::from_value(body_value.clone())
        .map_err(|_| error(Status::BadRequest, "upload_attestation_invalid"))?;
    let unsigned_request_digest = request_body_digest(&body_value)
        .ok_or(error(Status::BadRequest, "upload_attestation_invalid"))?;
    if request.request_body_digest != unsigned_request_digest {
        return Err(error(Status::BadRequest, "upload_attestation_invalid"));
    }

    let now = OffsetDateTime::now_utc();
    let auth = &invocation.0 .0;
    validate_request(&request, &runtime.share_origin, now)
        .map_err(|_| error(Status::BadRequest, "upload_attestation_invalid"))?;
    invocation_model::verify_and_authorize(&runtime.conn, auth, now)
        .await
        .map_err(|_| error(Status::Unauthorized, "upload_authorization_invalid"))?;
    if !has_baseline_scope(&auth.capabilities)
        || !invocation_body_digest_matches(auth, &request.request_body_digest)
    {
        return Err(error(Status::Forbidden, "upload_authorization_invalid"));
    }
    let max_lifetime = config.invocation.max_lifetime_secs;
    if auth.invocation.payload().expiration.as_seconds()
        > now.unix_timestamp() as f64 + max_lifetime as f64
    {
        return Err(error(Status::Unauthorized, "upload_authorization_invalid"));
    }
    replay
        .check_and_insert(&invocation.0, max_lifetime)
        .await
        .map_err(|_| error(Status::Unauthorized, "upload_authorization_invalid"))?;

    let owner_did = owner_did(&runtime.conn, auth)
        .await
        .ok_or(error(Status::Forbidden, "upload_authorization_invalid"))?;
    let session_did = auth.invoker.clone();

    let expires_at = now + Duration::seconds(120);
    let mut attestation = UploadAttestation {
        artifact_type: "TinyCloudShareUploadAttestation",
        version: 1,
        issuer: runtime.issuer.clone(),
        kid: runtime.signer.kid().to_owned(),
        owner_did,
        session_did,
        share_origin: runtime.share_origin.clone(),
        encrypted_blob_cid: request.encrypted_blob_cid,
        encrypted_blob_sha256: request.encrypted_blob_sha256,
        byte_length: request.byte_length,
        delete_after: request.delete_after,
        retention: request.retention,
        issued_at: timestamp(now),
        expires_at: timestamp(expires_at),
        jti: random_protocol_jti().as_str().to_owned(),
        signature: String::new(),
    };
    let unsigned = serde_json::to_value(&attestation)
        .map_err(|_| error(Status::InternalServerError, "upload_authority_unavailable"))?;
    let mut signed = DOMAIN.to_vec();
    signed.extend(jcs::canonicalize(&without_signature(&unsigned)));
    let signature = runtime
        .signer
        .sign(&signed)
        .map_err(|_| error(Status::ServiceUnavailable, "upload_authority_unavailable"))?;
    attestation.signature = encode_config(signature, URL_SAFE_NO_PAD);
    Ok(Json(attestation))
}

async fn read_body(data: Data<'_>) -> Result<Vec<u8>, ApiErrorResponse> {
    let mut bytes = Vec::new();
    data.open((MAX_UPLOAD_METADATA_BYTES + 1).bytes())
        .read_to_end(&mut bytes)
        .await
        .map_err(|_| error(Status::BadRequest, "upload_attestation_invalid"))?;
    if bytes.len() > MAX_UPLOAD_METADATA_BYTES {
        return Err(error(Status::PayloadTooLarge, "upload_attestation_invalid"));
    }
    Ok(bytes)
}

fn request_body_digest(value: &Value) -> Option<String> {
    let mut unsigned = value.as_object()?.clone();
    unsigned.remove("requestBodyDigest");
    Some(encode_config(
        Sha256::digest(jcs::canonicalize(&Value::Object(unsigned))),
        URL_SAFE_NO_PAD,
    ))
}

fn without_signature(value: &Value) -> Value {
    let mut object = value.as_object().cloned().unwrap_or_default();
    object.remove("signature");
    Value::Object(object)
}

fn has_baseline_scope(capabilities: &[Capability]) -> bool {
    capabilities.len() == 1
        && capabilities.iter().any(|capability| {
            capability.ability.as_ref().as_ref() == BASELINE_ABILITY
                && matches!(&capability.resource, Resource::TinyCloud(resource)
                    if resource.service().as_str() == "capabilities" && resource.path().is_none())
        })
}

fn invocation_body_digest_matches(invocation: &InvocationInfo, expected: &str) -> bool {
    invocation
        .invocation
        .payload()
        .facts
        .as_ref()
        .is_some_and(|facts| {
            facts.iter().any(|fact| {
                fact.as_object().is_some_and(|object| {
                    [
                        "requestBodyDigest",
                        "bodyDigest",
                        "xyz.tinycloud.share/requestBodyDigest",
                        "xyz.tinycloud.share/upload/bodyDigest",
                    ]
                    .iter()
                    .any(|key| object.get(*key).and_then(Value::as_str) == Some(expected))
                })
            })
        })
}

async fn owner_did(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    invocation: &InvocationInfo,
) -> Option<String> {
    let parent = invocation.parents.first()?;
    let row = delegation::Entity::find_by_id(tinycloud_core::hash::Hash::from(*parent))
        .one(conn)
        .await
        .ok()??;
    if !did_principal_matches(&row.delegatee, &invocation.invoker) {
        return None;
    }
    Some(row.delegator)
}

fn validate_request(
    request: &UploadAttestationRequest,
    expected_origin: &str,
    now: OffsetDateTime,
) -> Result<(), ()> {
    let origin = TargetOrigin::parse(request.share_origin.clone()).map_err(|_| ())?;
    if origin.as_str() != request.share_origin || request.share_origin != expected_origin {
        return Err(());
    }
    request
        .encrypted_blob_cid
        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
        .map_err(|_| ())?;
    let digest =
        base64::decode_config(&request.encrypted_blob_sha256, URL_SAFE_NO_PAD).map_err(|_| ())?;
    if digest.len() != 32
        || encode_config(&digest, URL_SAFE_NO_PAD) != request.encrypted_blob_sha256
        || request.byte_length > MAX_UPLOAD_BYTES
    {
        return Err(());
    }
    let delete_after = OffsetDateTime::parse(&request.delete_after, &Rfc3339).map_err(|_| ())?;
    if delete_after <= now || request.delete_after != timestamp(delete_after) {
        return Err(());
    }
    let retention = jcs::canonicalize(&request.retention);
    if request.retention.is_null() || retention.len() > MAX_RETENTION_BYTES {
        return Err(());
    }
    Ok(())
}

fn timestamp(value: OffsetDateTime) -> String {
    let format = time::format_description::parse(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z",
    )
    .expect("fixed timestamp format");
    value
        .to_offset(time::UtcOffset::UTC)
        .format(&format)
        .expect("timestamp formats")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tinycloud_auth::multihash_codetable::{Code, MultihashDigest};

    fn request(now: OffsetDateTime) -> UploadAttestationRequest {
        UploadAttestationRequest {
            share_origin: "https://share.tinycloud.xyz".to_owned(),
            encrypted_blob_cid: tinycloud_auth::ipld_core::cid::Cid::new_v1(
                0x55,
                Code::Sha2_256.digest(b"encrypted blob"),
            )
            .to_string(),
            encrypted_blob_sha256: encode_config(
                Sha256::digest(b"encrypted blob"),
                URL_SAFE_NO_PAD,
            ),
            byte_length: 15,
            delete_after: timestamp(now + Duration::hours(1)),
            retention: Value::String("until-delete".to_owned()),
            request_body_digest: "digest".to_owned(),
        }
    }

    #[test]
    fn body_digest_excludes_only_the_digest_field() {
        let value = json!({
            "byteLength": 4,
            "deleteAfter": "2030-01-01T00:00:00.000Z",
            "encryptedBlobCid": "bafybeigdyrzt4x3",
            "encryptedBlobSha256": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "requestBodyDigest": "ignored",
            "retention": "until-delete",
            "shareOrigin": "https://share.tinycloud.xyz"
        });
        let digest = request_body_digest(&value).expect("digest");
        let mut unsigned = value.as_object().unwrap().clone();
        unsigned.remove("requestBodyDigest");
        assert_eq!(
            digest,
            encode_config(
                Sha256::digest(jcs::canonicalize(&Value::Object(unsigned))),
                URL_SAFE_NO_PAD
            )
        );
    }

    #[test]
    fn signature_is_not_part_of_signed_attestation_bytes() {
        let value = json!({"signature": "redacted", "version": 1});
        assert_eq!(without_signature(&value), json!({"version": 1}));
    }

    #[test]
    fn request_validation_rejects_redirects_and_ambiguous_origins() {
        let now = OffsetDateTime::now_utc();
        for origin in [
            "https://share.tinycloud.xyz/redirect",
            "https://share.tinycloud.xyz?next=/",
            "https://share.tinycloud.xyz#fragment",
            "https://share.tinycloud.xyz:443",
        ] {
            let mut candidate = request(now);
            candidate.share_origin = origin.to_owned();
            assert!(validate_request(&candidate, "https://share.tinycloud.xyz", now).is_err());
        }
    }

    #[test]
    fn request_validation_rejects_bad_digest_size_and_delete_time() {
        let now = OffsetDateTime::now_utc();
        let mut candidate = request(now);
        candidate.encrypted_blob_sha256 = encode_config([0u8; 31], URL_SAFE_NO_PAD);
        assert!(validate_request(&candidate, "https://share.tinycloud.xyz", now).is_err());

        let mut candidate = request(now);
        candidate.byte_length = MAX_UPLOAD_BYTES + 1;
        assert!(validate_request(&candidate, "https://share.tinycloud.xyz", now).is_err());

        let mut candidate = request(now);
        candidate.delete_after = timestamp(now - Duration::seconds(1));
        assert!(validate_request(&candidate, "https://share.tinycloud.xyz", now).is_err());
    }
}

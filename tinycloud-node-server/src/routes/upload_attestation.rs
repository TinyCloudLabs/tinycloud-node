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
    models::{abilities, delegation, invocation as invocation_model},
    policy_capability::jcs,
    relationships::parent_delegations,
    sea_orm::{ColumnTrait, EntityTrait, QueryFilter},
    share_email::{
        invitation::{random_protocol_jti, Ed25519InvitationSigner, InvitationSigner},
        types::TargetOrigin,
    },
    types::Resource,
    util::{Capability, InvocationInfo},
    AdmittedInvocation,
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
const SEALED_BLOB_OVERHEAD_BYTES: u64 = 1 + 12 + 16;
const MAX_UPLOAD_BYTES: u64 = share_v2::MAX_BODY_BYTES as u64 + SEALED_BLOB_OVERHEAD_BYTES;
const MAX_RETENTION_BYTES: usize = 1024;
const BASELINE_ABILITY: &str = "tinycloud.capabilities/read";
const MAX_RETENTION_SECONDS: i64 = 8 * 24 * 60 * 60;

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
    pub authority_expires_at: String,
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
    let admitted = AdmittedInvocation::admit(invocation.0, config.invocation.max_lifetime_secs)
        .await
        .map_err(|_| error(Status::Unauthorized, "upload_authorization_invalid"))?;
    let auth = &admitted.invocation().0;
    if auth.invocation.payload().audience.to_string() != runtime.issuer {
        return Err(error(Status::Forbidden, "upload_authorization_invalid"));
    }
    validate_request(&request, &runtime.share_origin, now)
        .map_err(|_| error(Status::BadRequest, "upload_attestation_invalid"))?;
    invocation_model::authorize_admitted(&runtime.conn, auth, now)
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
        .check_and_insert(&admitted, max_lifetime)
        .await
        .map_err(|_| error(Status::Unauthorized, "upload_authorization_invalid"))?;

    let (owner_did, delegation_expiry) = owner_did_and_expiry(&runtime.conn, auth)
        .await
        .ok_or(error(Status::Forbidden, "upload_authorization_invalid"))?;
    let session_did = auth.invoker.clone();

    let invocation_expiry = OffsetDateTime::from_unix_timestamp_nanos(
        (auth.invocation.payload().expiration.as_seconds() * 1_000_000_000.0) as i128,
    )
    .map_err(|_| error(Status::Unauthorized, "upload_authorization_invalid"))?;
    let authority_expiry = delegation_expiry
        .map(|expiry| expiry.min(invocation_expiry))
        .unwrap_or(invocation_expiry);
    let expires_at = (now + Duration::seconds(120)).min(authority_expiry);
    if expires_at <= now {
        return Err(error(Status::Unauthorized, "upload_authorization_invalid"));
    }
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
        authority_expires_at: timestamp(authority_expiry),
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
    capabilities.iter().any(|capability| {
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
                    object.get("requestBodyDigest").and_then(Value::as_str) == Some(expected)
                })
            })
        })
}

async fn owner_did_and_expiry(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    invocation: &InvocationInfo,
) -> Option<(String, Option<OffsetDateTime>)> {
    // This route deliberately supports the ordinary one-parent session
    // invocation shape.  A multi-parent or cyclic/malformed chain fails
    // closed instead of attributing an intermediate delegator as owner.
    if invocation.parents.len() != 1 {
        return None;
    }
    let mut current = tinycloud_core::hash::Hash::from(*invocation.parents.first()?);
    let mut expected_delegatee = invocation.invoker.clone();
    let mut expiry: Option<OffsetDateTime> = None;
    for _ in 0..32 {
        let row = delegation::Entity::find_by_id(current)
            .one(conn)
            .await
            .ok()??;
        if !did_principal_matches(&row.delegatee, &expected_delegatee) {
            return None;
        }
        expiry = match (expiry, row.expiry) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(value), None) | (None, Some(value)) => Some(value),
            (None, None) => None,
        };
        let parents = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(current))
            .all(conn)
            .await
            .ok()?;
        if parents.is_empty() {
            if !has_baseline_ability(conn, current).await {
                return None;
            }
            return Some((row.delegator, expiry));
        }
        if parents.len() != 1 {
            return None;
        }
        expected_delegatee = row.delegator.clone();
        current = parents[0].parent;
    }
    None
}

async fn has_baseline_ability(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    delegation_id: tinycloud_core::hash::Hash,
) -> bool {
    abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(delegation_id))
        .all(conn)
        .await
        .ok()
        .is_some_and(|rows| {
            rows.iter().any(|row| {
                row.ability.as_ref().as_ref() == BASELINE_ABILITY
                    && matches!(&row.resource, Resource::TinyCloud(resource)
                    if resource.service().as_str() == "capabilities" && resource.path().is_none())
            })
        })
}

#[cfg(test)]
async fn debug_authorization_classification(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    invocation: &InvocationInfo,
) -> &'static str {
    let Some(parent) = invocation.parents.first() else {
        return "missing_parent";
    };
    let id = tinycloud_core::hash::Hash::from(*parent);
    let Some(row) = delegation::Entity::find_by_id(id)
        .one(conn)
        .await
        .ok()
        .flatten()
    else {
        return "delegation_missing";
    };
    if !did_principal_matches(&row.delegatee, &invocation.invoker) {
        return "invocation_signer_mismatch";
    }
    if !has_baseline_ability(conn, id).await {
        return "baseline_ability_missing";
    }
    "persisted_session_proof"
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
    if request.retention != Value::String("until-delete".to_owned())
        || retention.len() > MAX_RETENTION_BYTES
        || delete_after > now + Duration::seconds(MAX_RETENTION_SECONDS)
    {
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
    use rocket::local::asynchronous::Client;
    use serde_json::json;
    use tinycloud_auth::multihash_codetable::{Code, MultihashDigest};
    use tinycloud_core::sea_orm::Database;

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

    #[tokio::test]
    async fn mounted_route_requires_a_decodable_invocation_before_body_authorization() {
        let database = Database::connect("sqlite::memory:")
            .await
            .expect("in-memory database");
        let rocket = rocket::build()
            .mount("/", rocket::routes![mint_upload_attestation])
            .manage(None::<UploadAttestationRuntime>)
            .manage(InvocationReplayCache::new(database))
            .manage(Config::default());
        let client = Client::tracked(rocket).await.expect("Rocket client");

        let cases = [
            ("missing authorization", None, Status::Unauthorized),
            (
                "malformed authorization",
                Some("not-an-invocation"),
                Status::Unauthorized,
            ),
        ];
        for (name, authorization, expected) in cases {
            let mut request = client
                .post("/share/upload/attestation")
                .header(rocket::http::ContentType::JSON)
                .body("{}");
            if let Some(value) = authorization {
                request = request.header(rocket::http::Header::new("Authorization", value));
            }
            assert_eq!(request.dispatch().await.status(), expected, "{name}");
        }
    }

    #[tokio::test]
    async fn mounted_route_authorization_matrix_rejects_cryptographically_valid_but_unauthorized_invocations(
    ) {
        use rocket::http::{ContentType, Header, Status};
        use serde_json::Map;
        use tinycloud_auth::{
            resolver::DID_METHODS,
            ssi::{
                claims::jwt::NumericDate,
                dids::{DIDBuf, DIDURLBuf},
                jwk::{Algorithm, JWK},
                ucan::Payload,
            },
            ucan_capabilities_object::Capabilities,
        };
        use tinycloud_core::keys::StaticSecret;

        fn metadata(now: OffsetDateTime) -> Value {
            let unsigned = json!({
                "byteLength": 14,
                "deleteAfter": timestamp(now + Duration::hours(1)),
                "encryptedBlobCid": tinycloud_auth::ipld_core::cid::Cid::new_v1(
                    0x55,
                    Code::Sha2_256.digest(b"encrypted blob"),
                ).to_string(),
                "encryptedBlobSha256": encode_config(
                    Sha256::digest(b"encrypted blob"),
                    URL_SAFE_NO_PAD,
                ),
                "retention": "until-delete",
                "shareOrigin": "https://share.tinycloud.xyz",
            });
            let request_body_digest = request_body_digest(&unsigned).expect("request digest");
            let mut body = unsigned.as_object().cloned().expect("object");
            body.insert(
                "requestBodyDigest".to_owned(),
                Value::String(request_body_digest),
            );
            Value::Object(body)
        }

        async fn invocation(expiration: f64, audience: &str) -> String {
            let jwk = JWK::generate_ed25519().expect("test invocation key");
            let issuer = DID_METHODS
                .generate(&jwk, "key")
                .expect("test issuer")
                .to_string();
            Payload {
                issuer: issuer.parse::<DIDURLBuf>().expect("issuer vm"),
                audience: audience.parse::<DIDBuf>().expect("audience did"),
                not_before: None,
                expiration: NumericDate::try_from_seconds(expiration).expect("expiration"),
                nonce: Some(format!("urn:uuid:mounted-upload-{}", expiration as i64)),
                facts: Some(vec![json!({ "requestBodyDigest": "wrong" })]),
                proof: vec![],
                attenuation: Capabilities::<Map<String, Value>>::new(),
            }
            .sign(Algorithm::EdDSA, &jwk)
            .expect("signed invocation")
            .encode()
            .expect("encoded invocation")
        }

        let database = Database::connect("sqlite::memory:")
            .await
            .expect("authorization database");
        let signer_secret = StaticSecret::new(vec![7; 32]).expect("signing secret");
        let node_did = signer_secret.node_did();
        let mut config = Config::default();
        config.share_email.node_audience = node_did.clone();
        config.share_email.node_signing_kid = format!("{node_did}#invitation-key-1");
        let runtime = UploadAttestationRuntime::compose(
            database.clone(),
            &signer_secret,
            &config.share_email,
        )
        .expect("mounted runtime");
        let valid_audience = config.share_email.node_audience.clone();
        let replay_database = Database::connect("sqlite::memory:")
            .await
            .expect("replay database");
        let client = Client::tracked(
            rocket::build()
                .mount("/", rocket::routes![mint_upload_attestation])
                .manage(Some(runtime))
                .manage(InvocationReplayCache::new(replay_database))
                .manage(config),
        )
        .await
        .expect("Rocket client");
        let now = OffsetDateTime::now_utc();
        let cases = [
            (
                "missing proof",
                now.unix_timestamp() as f64 + 60.0,
                valid_audience.as_str(),
                Status::Forbidden,
            ),
            (
                "expired invocation",
                now.unix_timestamp() as f64 - 1.0,
                valid_audience.as_str(),
                Status::Unauthorized,
            ),
            (
                "wrong audience",
                now.unix_timestamp() as f64 + 60.0,
                "did:key:z6MktwtqAzuD5F77tAMBMwNs1KybZeff61EehV9xB1ZpXQG7",
                Status::Forbidden,
            ),
        ];
        for (name, expiration, audience, expected) in cases {
            let body = metadata(now);
            let response = client
                .post("/share/upload/attestation")
                .header(ContentType::JSON)
                .header(Header::new(
                    "Authorization",
                    invocation(expiration, audience).await,
                ))
                .body(jcs::canonicalize(&body))
                .dispatch()
                .await;
            assert_eq!(response.status(), expected, "{name}");
        }
    }

    #[tokio::test]
    async fn packed_session_invocation_gets_a_mounted_attestation_after_activation() {
        use rocket::http::{ContentType, Header, Status};
        use tinycloud_auth::{
            authorization::HeaderEncode,
            resolver::DID_METHODS,
            ssi::{
                claims::jwt::NumericDate,
                dids::{DIDBuf, DIDURLBuf},
                jwk::{Algorithm, JWK},
                ucan::Payload,
            },
            ucan_capabilities_object::Capabilities,
        };
        use tinycloud_core::{
            events::Delegation,
            keys::StaticSecret,
            migrations::Migrator,
            models::{abilities, actor, delegation},
            sea_orm::{ActiveModelTrait, Set},
            sea_orm_migration::MigratorTrait,
            types::{Ability, Resource},
        };

        let database = Database::connect("sqlite::memory:")
            .await
            .expect("authorization database");
        Migrator::up(&database, None)
            .await
            .expect("database schema");
        let signer_secret = StaticSecret::new(vec![7; 32]).expect("signing secret");
        let mut config = Config::default();
        config.share_email.node_audience = "did:web:node.example".to_owned();
        config.share_email.node_signing_kid =
            format!("{}#invitation-key-1", config.share_email.node_audience);
        let runtime = UploadAttestationRuntime::compose(
            database.clone(),
            &signer_secret,
            &config.share_email,
        )
        .expect("mounted runtime");
        let session_jwk = JWK::generate_ed25519().expect("session key");
        let session_vm = DID_METHODS
            .generate(&session_jwk, "key")
            .expect("session verification method")
            .to_string();
        let session_did = session_vm
            .split('#')
            .next()
            .expect("session DID")
            .to_owned();
        let owner_jwk = JWK::generate_ed25519().expect("owner key");
        let owner_vm = DID_METHODS
            .generate(&owner_jwk, "key")
            .expect("owner verification method")
            .to_string();
        let owner_did = owner_vm.split('#').next().expect("owner DID").to_owned();
        let space = format!("tinycloud:{owner_did}:documents");
        let capability_resource = format!("{space}/capabilities");
        let mut capabilities = Capabilities::<serde_json::Map<String, Value>>::new();
        capabilities.with_actions(
            capability_resource.parse().expect("capability resource"),
            std::iter::once((BASELINE_ABILITY.parse().expect("baseline ability"), [])),
        );
        let expiration = OffsetDateTime::now_utc() + Duration::hours(1);
        let delegation = Payload {
            issuer: owner_vm.parse::<DIDURLBuf>().expect("owner VM"),
            audience: session_did.parse::<DIDBuf>().expect("session DID"),
            not_before: None,
            expiration: NumericDate::try_from_seconds(expiration.unix_timestamp() as f64)
                .expect("delegation expiration"),
            nonce: Some("mounted-share-session-proof".into()),
            facts: Some(Vec::<Value>::new()),
            proof: Vec::new(),
            attenuation: capabilities,
        }
        .sign(Algorithm::EdDSA, &owner_jwk)
        .expect("signed session delegation");
        let delegation_header = delegation.encode().expect("encoded delegation");
        let persisted = Delegation::from_header_ser::<
            tinycloud_auth::authorization::TinyCloudDelegation,
        >(&delegation_header)
        .expect("decoded delegation");
        let delegation_id = persisted.content_hash();
        actor::ActiveModel {
            id: Set(owner_did.clone()),
        }
        .insert(&database)
        .await
        .expect("owner actor");
        actor::ActiveModel {
            id: Set(session_did.clone()),
        }
        .insert(&database)
        .await
        .expect("session actor");
        delegation::ActiveModel {
            id: Set(delegation_id),
            delegator: Set(owner_did),
            delegatee: Set(session_did.clone()),
            expiry: Set(Some(expiration)),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(persisted.serialized_bytes().to_vec()),
        }
        .insert(&database)
        .await
        .expect("persisted session delegation");
        abilities::ActiveModel {
            delegation: Set(delegation_id),
            resource: Set(capability_resource.parse::<Resource>().expect("capability")),
            ability: Set(Ability::try_from(BASELINE_ABILITY.to_owned()).expect("ability")),
            caveats: Set(Default::default()),
        }
        .insert(&database)
        .await
        .expect("persisted baseline ability");

        let body_without_digest = json!({
            "byteLength": 14,
            "deleteAfter": timestamp(OffsetDateTime::now_utc() + Duration::hours(1)),
            "encryptedBlobCid": tinycloud_auth::ipld_core::cid::Cid::new_v1(
                0x55,
                Code::Sha2_256.digest(b"encrypted blob"),
            ).to_string(),
            "encryptedBlobSha256": encode_config(Sha256::digest(b"encrypted blob"), URL_SAFE_NO_PAD),
            "retention": "until-delete",
            "shareOrigin": "https://share.tinycloud.xyz",
        });
        let digest = request_body_digest(&body_without_digest).expect("request digest");
        let mut body = body_without_digest
            .as_object()
            .expect("body object")
            .clone();
        body.insert("requestBodyDigest".into(), Value::String(digest.clone()));
        let invocation = tinycloud_auth::authorization::make_invocation(
            vec![(
                capability_resource.parse().expect("resource ID"),
                vec![BASELINE_ABILITY.parse().expect("baseline ability")],
            )],
            &delegation_id.to_cid(0x55),
            &session_jwk,
            &session_vm,
            (OffsetDateTime::now_utc() + Duration::seconds(60)).unix_timestamp() as f64,
            tinycloud_auth::authorization::InvocationOptions {
                facts: Some(vec![json!({ "requestBodyDigest": digest })]),
                ..Default::default()
            },
        )
        .expect("packed invocation shape");
        let mut target_payload = invocation.payload().clone();
        target_payload.audience = config
            .share_email
            .node_audience
            .parse::<DIDBuf>()
            .expect("node audience");
        let invocation = target_payload
            .sign(Algorithm::EdDSA, &session_jwk)
            .expect("target-bound invocation");
        let invocation_header = HeaderEncode::encode(&invocation).expect("encoded invocation");
        let decoded = InvocationInfo::try_from(
            tinycloud_auth::authorization::TinyCloudInvocation::decode(&invocation_header)
                .expect("decoded invocation"),
        )
        .expect("invocation info");
        assert_eq!(
            debug_authorization_classification(&database, &decoded).await,
            "persisted_session_proof"
        );
        assert!(has_baseline_scope(&decoded.capabilities));
        assert!(invocation_body_digest_matches(&decoded, &digest));
        assert!(invocation_model::authorize_admitted(
            &database,
            &decoded,
            OffsetDateTime::now_utc()
        )
        .await
        .is_ok());

        let replay_database = Database::connect("sqlite::memory:")
            .await
            .expect("replay database");
        Migrator::up(&replay_database, None)
            .await
            .expect("replay database schema");
        let client = Client::tracked(
            rocket::build()
                .mount("/", rocket::routes![mint_upload_attestation])
                .manage(Some(runtime))
                .manage(InvocationReplayCache::new(replay_database))
                .manage(config),
        )
        .await
        .expect("Rocket client");
        let response = client
            .post("/share/upload/attestation")
            .header(ContentType::JSON)
            .header(Header::new("Authorization", invocation_header))
            .body(jcs::canonicalize(&Value::Object(body)))
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::Ok);
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

        let mut candidate = request(now);
        candidate.delete_after = timestamp(now + Duration::seconds(MAX_RETENTION_SECONDS + 1));
        assert!(validate_request(&candidate, "https://share.tinycloud.xyz", now).is_err());

        let mut candidate = request(now);
        candidate.retention = Value::String("until-delete-extra".to_owned());
        assert!(validate_request(&candidate, "https://share.tinycloud.xyz", now).is_err());
    }
}

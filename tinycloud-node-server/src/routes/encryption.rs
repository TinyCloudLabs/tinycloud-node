//! HTTP routes for the encryption network module.
//!
//! Layout:
//! - `POST /encryption/networks`                                  — create + ceremony for a network
//! - `GET  /encryption/networks/<network_id>`                     — fetch authoritative descriptor
//! - `GET  /.well-known/encryption/network/<name>`                — public discovery record
//! - `POST /encryption/networks/<network_id>/decrypt`             — UCAN-style decrypt invocation
//! - `POST /encryption/networks/<network_id>/revoke`              — admin revoke (placeholder)
//! - `POST /encryption/networks/<network_id>/keys`                — create a named key (`key-admin/v1`)
//! - `GET  /encryption/networks/<network_id>/keys/<key_path..>`   — authenticated describe (`key-describe/v1`)
//! - `GET  /encryption/networks/<network_id>/keys/<key_path..>`   — public key read (no auth)
//! - `POST /encryption/networks/<network_id>/key-actions/block`   — block a key (`key-admin/v1`)
//! - `POST /encryption/networks/<network_id>/key-actions/unblock` — unblock a key (`key-admin/v1`)
//! - `POST /encryption/networks/<network_id>/key-actions/delete`  — delete a key or every key under `apps/<app id>/` (owner-signed)

use rocket::request::{FromRequest, Outcome, Request};
use rocket::{
    form::FromForm,
    http::{
        uri::{error::PathError, Origin},
        Status,
    },
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, path::PathBuf, time::Instant};

use super::public::{ClientIp, RateLimiter};
use crate::{authorization::AuthHeaderGetter, BlockStage, TinyCloud};
use tinycloud_core::encryption_network::{
    delete_auth::DeleteTarget,
    key_id::KeyLocation,
    keys::{KeyDescriptor, KeyPublic},
    CreateNetworkRequest, DecryptResponseBody, EncryptionService, EncryptionServiceError,
    NetworkDescriptor, NetworkId, Threshold, WellKnownRecord, KEY_BLOCK_ACTION, KEY_CREATE_ACTION,
    KEY_UNBLOCK_ACTION, NETWORK_CREATE_ACTION, NETWORK_REVOKE_ACTION,
};
use tinycloud_core::{events::Invocation, util::InvocationInfo, TxError, TxStoreError};

#[derive(Debug, Deserialize)]
pub struct CreateNetworkBody {
    pub name: String,
    #[serde(rename = "ownerDid")]
    pub owner_did: String,
    #[serde(default = "default_threshold")]
    pub threshold: Threshold,
}

fn default_threshold() -> Threshold {
    Threshold::one_of_one()
}

#[derive(Debug, Serialize)]
pub struct DescriptorView {
    pub descriptor: NetworkDescriptor,
}

#[derive(Debug, FromForm)]
pub struct WellKnownNetworkQuery {
    #[field(name = "ownerDid")]
    pub owner_did: Option<String>,
}

#[post("/encryption/networks", format = "json", data = "<body>")]
pub async fn create_network(
    authorization: AuthHeaderGetter<InvocationInfo>,
    body: Json<serde_json::Value>,
    service: &State<EncryptionService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<DescriptorView>, (Status, String)> {
    let invocation = authorization.0;
    let invocation_info = invocation.0.clone();
    verify_auth(
        "server.encryption.create.auth",
        invocation,
        tinycloud,
        service.node_did(),
    )
    .await?;

    let body_value = body.into_inner();
    let body: CreateNetworkBody = serde_json::from_value(body_value.clone())
        .map_err(|err| (Status::BadRequest, err.to_string()))?;
    let network_id = NetworkId::new(body.owner_did.clone(), body.name.clone())
        .map_err(|err| (Status::BadRequest, err.to_string()))?;
    let admin_start = Instant::now();
    let admin_result = service
        .verify_network_admin_authorized(
            &network_id,
            NETWORK_CREATE_ACTION,
            &invocation_info,
            &body_value,
        )
        .await;
    crate::prometheus::observe_span(
        "server.encryption.verify_admin",
        if admin_result.is_ok() { "ok" } else { "error" },
        admin_start.elapsed(),
    );
    admin_result.map_err(map_service_err)?;
    let req = CreateNetworkRequest {
        name: body.name,
        owner_did: body.owner_did,
        threshold: body.threshold,
    };
    let create_start = Instant::now();
    let create_result = service.create_one_of_one_network(req).await;
    crate::prometheus::observe_span(
        "server.encryption.create_network",
        if create_result.is_ok() { "ok" } else { "error" },
        create_start.elapsed(),
    );
    let descriptor = create_result.map_err(map_service_err)?;
    Ok(Json(DescriptorView { descriptor }))
}

#[get("/encryption/networks/<network_id>")]
pub async fn get_network(
    network_id: &str,
    service: &State<EncryptionService>,
) -> Result<Json<DescriptorView>, (Status, String)> {
    let net: NetworkId =
        network_id
            .parse()
            .map_err(|e: tinycloud_core::encryption_network::NetworkIdError| {
                (Status::BadRequest, e.to_string())
            })?;
    let start = Instant::now();
    let result = service.get_network(&net).await;
    crate::prometheus::observe_span(
        "server.encryption.get_network",
        if result.is_ok() { "ok" } else { "error" },
        start.elapsed(),
    );
    let descriptor = result.map_err(map_service_err)?;
    Ok(Json(DescriptorView { descriptor }))
}

/// Discovery record published as `.well-known/encryption/network/<name>`.
/// Authoritative state still lives in the node DB; this endpoint just renders a
/// cache-friendly view of the active network for the given name.
#[get("/.well-known/encryption/network/<name>?<query..>")]
pub async fn well_known_network(
    name: &str,
    query: WellKnownNetworkQuery,
    service: &State<EncryptionService>,
) -> Result<Json<WellKnownRecord>, (Status, String)> {
    // V1 supports owner-qualified discovery when the caller has it, and a
    // name-only fallback for single-owner nodes.
    let start = Instant::now();
    let result = service
        .get_network_by_name(name, query.owner_did.as_deref())
        .await;
    crate::prometheus::observe_span(
        "server.encryption.get_network_by_name",
        if result.is_ok() { "ok" } else { "error" },
        start.elapsed(),
    );
    let descriptor = result.map_err(map_service_err)?;
    Ok(Json(WellKnownRecord::from(&descriptor)))
}

#[post(
    "/encryption/networks/<network_id>/decrypt",
    format = "json",
    data = "<body>"
)]
pub async fn decrypt(
    network_id: &str,
    authorization: AuthHeaderGetter<InvocationInfo>,
    body: Json<serde_json::Value>,
    service: &State<EncryptionService>,
    tinycloud: &State<TinyCloud>,
    policy_v3: &State<crate::policy_v3::PolicyV3Runtime>,
) -> Result<Json<DecryptResponseBody>, (Status, String)> {
    let invocation = authorization.0;
    let invocation_info = invocation.0.clone();
    verify_auth(
        "server.encryption.decrypt.auth",
        invocation,
        tinycloud,
        service.node_did(),
    )
    .await?;
    // Same policy gate as `/invoke`: a policy-session chain must still be
    // live (roots, session, descendants) to decrypt through this route.
    policy_v3
        .authorize_invocation(tinycloud, &invocation_info, time::OffsetDateTime::now_utc())
        .await
        .map_err(|error| (Status::Forbidden, error.to_string()))?;

    let net: NetworkId =
        network_id
            .parse()
            .map_err(|e: tinycloud_core::encryption_network::NetworkIdError| {
                (Status::BadRequest, e.to_string())
            })?;
    let body = body.into_inner();
    if body.get("keyPath").is_some() {
        return Err((
            Status::BadRequest,
            "key_path_invalid: keyPath is not accepted on the network decrypt route; use /invoke with a key capability"
                .to_string(),
        ));
    }
    let target = tinycloud_core::encryption_network::DecryptTarget::Root(net.clone());
    let decrypt_start = Instant::now();
    let decrypt_result = service
        .decrypt_authorized(&target, &invocation_info, &body)
        .await;
    crate::prometheus::observe_span(
        "server.encryption.decrypt_authorized",
        if decrypt_result.is_ok() {
            "ok"
        } else {
            "error"
        },
        decrypt_start.elapsed(),
    );
    let verified = decrypt_result.map_err(map_service_err)?;
    Ok(Json(verified.response))
}

#[post("/encryption/networks/<network_id>/revoke")]
pub async fn revoke_network(
    network_id: &str,
    authorization: AuthHeaderGetter<InvocationInfo>,
    service: &State<EncryptionService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Status, (Status, String)> {
    let invocation = authorization.0;
    let invocation_info = invocation.0.clone();
    verify_auth(
        "server.encryption.revoke.auth",
        invocation,
        tinycloud,
        service.node_did(),
    )
    .await?;

    let net: NetworkId =
        network_id
            .parse()
            .map_err(|e: tinycloud_core::encryption_network::NetworkIdError| {
                (Status::BadRequest, e.to_string())
            })?;
    let body = serde_json::json!({});
    let admin_start = Instant::now();
    let admin_result = service
        .verify_network_admin_authorized(&net, NETWORK_REVOKE_ACTION, &invocation_info, &body)
        .await;
    crate::prometheus::observe_span(
        "server.encryption.verify_revoke_admin",
        if admin_result.is_ok() { "ok" } else { "error" },
        admin_start.elapsed(),
    );
    admin_result.map_err(map_service_err)?;
    let revoke_start = Instant::now();
    let revoke_result = service.revoke_network(&net).await;
    crate::prometheus::observe_span(
        "server.encryption.revoke_network",
        if revoke_result.is_ok() { "ok" } else { "error" },
        revoke_start.elapsed(),
    );
    revoke_result.map_err(map_service_err)?;
    Ok(Status::NoContent)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateKeyBody {
    #[serde(rename = "keyPath")]
    pub key_path: String,
    #[serde(default)]
    pub deletable: bool,
}

#[derive(Debug, Deserialize)]
pub struct KeyPathBody {
    #[serde(rename = "keyPath")]
    pub key_path: String,
}

/// Full key descriptor, returned by create, block, unblock and the
/// authenticated describe GET.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyDescriptorView {
    network_id: String,
    key_path: String,
    alg: String,
    key_version: i64,
    public_encryption_key: String,
    kind: String,
    state: &'static str,
    created_at: String,
    updated_at: String,
}

impl From<KeyDescriptor> for KeyDescriptorView {
    fn from(descriptor: KeyDescriptor) -> Self {
        Self {
            network_id: descriptor.network_id,
            key_path: descriptor.key_path,
            alg: descriptor.alg,
            key_version: descriptor.key_version,
            public_encryption_key: base64::encode(&descriptor.public_encryption_key),
            kind: descriptor.kind,
            state: descriptor.state.as_str(),
            created_at: descriptor.created_at,
            updated_at: descriptor.updated_at,
        }
    }
}

/// Public-only view served by the unauthenticated GET.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyPublicView {
    network_id: String,
    key_path: String,
    alg: String,
    key_version: i64,
    public_encryption_key: String,
}

impl From<KeyPublic> for KeyPublicView {
    fn from(public: KeyPublic) -> Self {
        Self {
            network_id: public.network_id,
            key_path: public.key_path,
            alg: public.alg,
            key_version: public.key_version,
            public_encryption_key: base64::encode(&public.public_encryption_key),
        }
    }
}

/// Parses the network id and key path. The network id must be in canonical form,
/// and any key path the grammar rejects is refused.
fn key_location(
    network_id: &str,
    key_path: &str,
) -> Result<(NetworkId, KeyLocation), (Status, String)> {
    let network = network_id
        .parse::<NetworkId>()
        .map_err(|err| (Status::BadRequest, err.to_string()))?;
    if network.to_string() != network_id {
        return Err((
            Status::BadRequest,
            "network id is not in canonical form".to_string(),
        ));
    }
    let location = KeyLocation::new(&network, key_path)
        .map_err(|err| map_service_err(EncryptionServiceError::KeyPathInvalid(err.to_string())))?;
    Ok((network, location))
}

/// Raw key path: the request path after `/networks/<network_id>/keys/`. Rocket's
/// decoded segments drop empty segments (and a `PathBuf` conversion would
/// normalize dot segments), so the key path is taken from the raw request path
/// and checked against the key grammar as received. Rocket
/// decodes the `<network_id>` parameter, so a percent-escape in the network id
/// breaks the raw prefix match; the detail then names the escape. Percent-escapes
/// in the key path are refused outright.
fn raw_key_path(origin: &Origin<'_>, network_id: &str) -> Result<String, (Status, String)> {
    let path = origin.path().as_str();
    let Some(raw) = path.strip_prefix(&format!("/encryption/networks/{network_id}/keys/")) else {
        return Err(if path.contains('%') {
            percent_refused()
        } else {
            map_service_err(EncryptionServiceError::KeyPathInvalid(
                "key path is not present in the request".to_string(),
            ))
        });
    };
    if raw.contains('%') {
        return Err(percent_refused());
    }
    Ok(raw.to_string())
}

fn percent_refused() -> (Status, String) {
    map_service_err(EncryptionServiceError::KeyPathInvalid(
        "percent-encoding is not accepted in key route URLs (send the network id and key path unencoded)".to_string(),
    ))
}

#[post(
    "/encryption/networks/<network_id>/keys",
    format = "json",
    data = "<body>"
)]
pub async fn create_encryption_key(
    network_id: &str,
    authorization: AuthHeaderGetter<InvocationInfo>,
    body: Json<serde_json::Value>,
    service: &State<EncryptionService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KeyDescriptorView>, (Status, String)> {
    let invocation = authorization.0;
    let invocation_info = invocation.0.clone();
    verify_auth(
        "server.encryption.key_create.auth",
        invocation,
        tinycloud,
        service.node_did(),
    )
    .await?;

    let body_value = body.into_inner();
    let body: CreateKeyBody = serde_json::from_value(body_value.clone()).map_err(|err| {
        (
            Status::BadRequest,
            format!("request body is malformed: {err}"),
        )
    })?;
    let (network, location) = key_location(network_id, &body.key_path)?;
    service
        .verify_key_admin_authorized(
            &network,
            &location,
            KEY_CREATE_ACTION,
            &invocation_info,
            &body_value,
        )
        .await
        .map_err(map_key_service_err)?;
    let descriptor = service
        .create_key(&location, body.deletable)
        .await
        .map_err(map_key_service_err)?;
    Ok(Json(descriptor.into()))
}

/// Authenticated describe. Accepts a `decrypt`, `key.create`, `key.block` or
/// `key.unblock` capability on the exact key. Ranked ahead of the public GET,
/// which handles requests without an `Authorization` header.
#[get("/encryption/networks/<network_id>/keys/<key_path..>", rank = 1)]
pub async fn describe_encryption_key(
    network_id: &str,
    key_path: Result<PathBuf, PathError>,
    origin: &Origin<'_>,
    authorization: AuthHeaderGetter<InvocationInfo>,
    service: &State<EncryptionService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KeyDescriptorView>, (Status, String)> {
    let invocation = authorization.0;
    let invocation_info = invocation.0.clone();
    verify_auth(
        "server.encryption.key_describe.auth",
        invocation,
        tinycloud,
        service.node_did(),
    )
    .await?;

    // Routing guard only; the key path is read from the raw request path.
    let _ = key_path;
    let key_path = raw_key_path(origin, network_id)?;
    let (network, location) = key_location(network_id, &key_path)?;
    service
        .verify_key_describe_authorized(&network, &location, &invocation_info)
        .await
        .map_err(map_key_service_err)?;
    let descriptor = service
        .describe_key(&location)
        .await
        .map_err(map_key_service_err)?;
    Ok(Json(descriptor.into()))
}

/// Unauthenticated public key read, rate-limited per client IP like the other
/// public routes. Returns the same shape for missing, blocked and active keys.
#[get("/encryption/networks/<network_id>/keys/<key_path..>", rank = 2)]
pub async fn public_encryption_key(
    network_id: &str,
    key_path: Result<PathBuf, PathError>,
    origin: &Origin<'_>,
    client_ip: ClientIp,
    rate_limiter: &State<RateLimiter>,
    service: &State<EncryptionService>,
) -> Result<Json<KeyPublicView>, (Status, String)> {
    rate_limiter
        .check(client_ip.0)
        .map_err(|status| (status, "Rate limit exceeded".to_string()))?;
    // Routing guard only; the key path is read from the raw request path.
    let _ = key_path;
    let key_path = raw_key_path(origin, network_id)?;
    let (_, location) = key_location(network_id, &key_path)?;
    let public = service
        .public_key(&location)
        .await
        .map_err(map_service_err)?;
    Ok(Json(public.into()))
}

#[post(
    "/encryption/networks/<network_id>/key-actions/block",
    format = "json",
    data = "<body>"
)]
pub async fn block_encryption_key(
    network_id: &str,
    authorization: AuthHeaderGetter<InvocationInfo>,
    body: Json<serde_json::Value>,
    service: &State<EncryptionService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KeyDescriptorView>, (Status, String)> {
    let invocation = authorization.0;
    let invocation_info = invocation.0.clone();
    verify_auth(
        "server.encryption.key_block.auth",
        invocation,
        tinycloud,
        service.node_did(),
    )
    .await?;

    let body_value = body.into_inner();
    let body: KeyPathBody = serde_json::from_value(body_value.clone()).map_err(|err| {
        (
            Status::BadRequest,
            format!("request body is malformed: {err}"),
        )
    })?;
    let (network, location) = key_location(network_id, &body.key_path)?;
    service
        .verify_key_admin_authorized(
            &network,
            &location,
            KEY_BLOCK_ACTION,
            &invocation_info,
            &body_value,
        )
        .await
        .map_err(map_key_service_err)?;
    let descriptor = service
        .block_key(&location)
        .await
        .map_err(map_key_service_err)?;
    Ok(Json(descriptor.into()))
}

#[post(
    "/encryption/networks/<network_id>/key-actions/unblock",
    format = "json",
    data = "<body>"
)]
pub async fn unblock_encryption_key(
    network_id: &str,
    authorization: AuthHeaderGetter<InvocationInfo>,
    body: Json<serde_json::Value>,
    service: &State<EncryptionService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<KeyDescriptorView>, (Status, String)> {
    let invocation = authorization.0;
    let invocation_info = invocation.0.clone();
    verify_auth(
        "server.encryption.key_unblock.auth",
        invocation,
        tinycloud,
        service.node_did(),
    )
    .await?;

    let body_value = body.into_inner();
    let body: KeyPathBody = serde_json::from_value(body_value.clone()).map_err(|err| {
        (
            Status::BadRequest,
            format!("request body is malformed: {err}"),
        )
    })?;
    let (network, location) = key_location(network_id, &body.key_path)?;
    service
        .verify_key_admin_authorized(
            &network,
            &location,
            KEY_UNBLOCK_ACTION,
            &invocation_info,
            &body_value,
        )
        .await
        .map_err(map_key_service_err)?;
    let descriptor = service
        .unblock_key(&location)
        .await
        .map_err(map_key_service_err)?;
    Ok(Json(descriptor.into()))
}

/// The raw `Authorization` header. The delete route verifies the owner's
/// credential itself, so it takes the header as sent.
pub struct RawAuthorization(String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for RawAuthorization {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.headers().get_one("Authorization") {
            Some(value) => Outcome::Success(Self(value.to_string())),
            None => Outcome::Error((Status::Unauthorized, ())),
        }
    }
}

/// The keys an owner-signed delete touched.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyDeleteView {
    key_path: String,
    state: &'static str,
    deleted: Vec<String>,
    already_deleted: Vec<String>,
    count: usize,
}

/// Deletes one key (`keyPath` without a trailing `/`) or every key under
/// `apps/<app id>/` (`keyPath` with one). The caller is the network owner and
/// signs the request itself: a UCAN invocation for a `did:key` owner, a SIWE
/// CACAO for a `did:pkh` owner. Neither is stored as a delegation.
#[post(
    "/encryption/networks/<network_id>/key-actions/delete",
    format = "json",
    data = "<body>"
)]
pub async fn delete_encryption_key(
    network_id: &str,
    authorization: RawAuthorization,
    body: Json<serde_json::Value>,
    service: &State<EncryptionService>,
) -> Result<Json<KeyDeleteView>, (Status, String)> {
    let body_value = body.into_inner();
    let body: KeyPathBody = serde_json::from_value(body_value.clone()).map_err(|err| {
        (
            Status::BadRequest,
            format!("request body is malformed: {err}"),
        )
    })?;
    let network = network_id
        .parse::<NetworkId>()
        .map_err(|err| (Status::BadRequest, err.to_string()))?;
    if network.to_string() != network_id {
        return Err((
            Status::BadRequest,
            "network id is not in canonical form".to_string(),
        ));
    }
    let target = DeleteTarget::parse(&network, &body.key_path).map_err(map_key_service_err)?;
    let verified = service
        .authorize_owner_delete(&authorization.0, &network, &target, &body_value)
        .await
        .map_err(map_key_service_err)?;
    let outcome = service
        .delete_keys(&network, &target, &verified)
        .await
        .map_err(map_key_service_err)?;
    Ok(Json(KeyDeleteView {
        key_path: outcome.key_path,
        state: "deleted",
        count: outcome.deleted.len(),
        deleted: outcome.deleted,
        already_deleted: outcome.already_deleted,
    }))
}

async fn verify_auth(
    span: &'static str,
    invocation: Invocation,
    tinycloud: &State<TinyCloud>,
    node_did: &str,
) -> Result<(), (Status, String)> {
    if invocation.0.invocation.payload().audience != node_did {
        return Err((
            Status::Unauthorized,
            EncryptionServiceError::AudienceMismatch.to_string(),
        ));
    }
    let start = Instant::now();
    let result = tinycloud
        .invoke::<BlockStage>(invocation, HashMap::new())
        .await
        .map(|_| ())
        // Infrastructure failures are not authorization failures (TC-1317):
        // a read-audit or transient database failure is retryable, and must
        // not tell the client its credentials were refused.
        .map_err(|err| match &err {
            TxStoreError::Tx(TxError::ReadAudit(error)) => {
                super::read_audit_failure(tinycloud_core::failure_diagnostic::Service::Other, error)
            }
            TxStoreError::Tx(TxError::Db(error) | TxError::EpochInsert(error)) => {
                super::database_failure(
                    tinycloud_core::failure_diagnostic::Service::Other,
                    error,
                    false,
                    err.to_string(),
                )
            }
            _ => (Status::Unauthorized, err.to_string()),
        });
    crate::prometheus::observe_span(
        span,
        if result.is_ok() { "ok" } else { "error" },
        start.elapsed(),
    );
    result
}

/// Error mapper for the key routes that take a JSON body. A malformed body or
/// invocation fact is a request-body error; every other error uses
/// `map_service_err`.
fn map_key_service_err(err: EncryptionServiceError) -> (Status, String) {
    match err {
        EncryptionServiceError::InvalidBody(detail) => (
            Status::BadRequest,
            format!("request body is malformed: {detail}"),
        ),
        other => map_service_err(other),
    }
}

fn map_service_err(err: EncryptionServiceError) -> (Status, String) {
    let status = match err {
        EncryptionServiceError::NetworkNotFound => Status::NotFound,
        EncryptionServiceError::NetworkAlreadyExists => Status::Conflict,
        EncryptionServiceError::Db(_) => Status::InternalServerError,
        EncryptionServiceError::Backend(_) => Status::InternalServerError,
        EncryptionServiceError::Signing(_) => Status::InternalServerError,
        EncryptionServiceError::AudienceMismatch
        | EncryptionServiceError::TargetNodeMismatch
        | EncryptionServiceError::OwnerMismatch
        | EncryptionServiceError::NetworkMismatch
        | EncryptionServiceError::Unauthorized
        | EncryptionServiceError::NetworkRevoked
        | EncryptionServiceError::NonceReplay
        | EncryptionServiceError::Expired
        | EncryptionServiceError::NotYetValid
        | EncryptionServiceError::SignatureInvalid(_)
        | EncryptionServiceError::WrongInvocationType
        | EncryptionServiceError::AlgKeyVersionMismatch
        | EncryptionServiceError::HashMismatch(_) => Status::Unauthorized,
        EncryptionServiceError::NetworkNotActive(_) => Status::Conflict,
        EncryptionServiceError::KeyExists => Status::Conflict,
        EncryptionServiceError::KeyNotDeletable => Status::Conflict,
        EncryptionServiceError::KeyNotFound => Status::NotFound,
        EncryptionServiceError::KeyDeleted
        | EncryptionServiceError::KeyBlocked
        | EncryptionServiceError::KeyLimitExceeded
        | EncryptionServiceError::KeyUnwrapFailed(_)
        | EncryptionServiceError::OwnerOnly(_) => Status::Forbidden,
        EncryptionServiceError::CorruptKeyRow
        | EncryptionServiceError::StrayAppKeyRows(_)
        | EncryptionServiceError::DeletionLedger(_) => Status::InternalServerError,
        EncryptionServiceError::KeyPathInvalid(_) => Status::BadRequest,
        EncryptionServiceError::InvalidBody(_)
        | EncryptionServiceError::InvalidReceiverPublicKey
        | EncryptionServiceError::Base64(_) => Status::BadRequest,
    };
    (status, err.to_string())
}

#[cfg(feature = "dstack")]
pub fn _docs() {}

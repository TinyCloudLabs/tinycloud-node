//! HTTP routes for the encryption network module.
//!
//! Layout:
//! - `POST /encryption/networks`                      — create + ceremony for a network
//! - `GET  /encryption/networks/<network_id>`         — fetch authoritative descriptor
//! - `GET  /.well-known/encryption/network/<name>`    — public discovery record
//! - `POST /encryption/networks/<network_id>/decrypt` — UCAN-style decrypt invocation
//! - `POST /encryption/networks/<network_id>/revoke`  — admin revoke (placeholder)

use rocket::{form::FromForm, http::Status, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, time::Instant};

use crate::{authorization::AuthHeaderGetter, BlockStage, TinyCloud};
use tinycloud_core::encryption_network::{
    CreateNetworkRequest, DecryptResponseBody, EncryptionService, EncryptionServiceError,
    NetworkDescriptor, NetworkId, Threshold, WellKnownRecord, NETWORK_CREATE_ACTION,
    NETWORK_REVOKE_ACTION,
};
use tinycloud_core::{events::Invocation, util::InvocationInfo};

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

    let net: NetworkId =
        network_id
            .parse()
            .map_err(|e: tinycloud_core::encryption_network::NetworkIdError| {
                (Status::BadRequest, e.to_string())
            })?;
    let body = body.into_inner();
    let decrypt_start = Instant::now();
    let decrypt_result = service
        .decrypt_authorized(&net, &invocation_info, &body)
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
        .map_err(|err| (Status::Unauthorized, err.to_string()));
    crate::prometheus::observe_span(
        span,
        if result.is_ok() { "ok" } else { "error" },
        start.elapsed(),
    );
    result
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
        EncryptionServiceError::InvalidBody(_) | EncryptionServiceError::Base64(_) => {
            Status::BadRequest
        }
    };
    (status, err.to_string())
}

#[cfg(feature = "dstack")]
pub fn _docs() {}

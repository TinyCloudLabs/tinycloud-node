//! HTTP routes for the encryption network module.
//!
//! Layout:
//! - `POST /encryption/networks`                      — create + ceremony for a network
//! - `GET  /encryption/networks/<network_id>`         — fetch authoritative descriptor
//! - `GET  /.well-known/encryption/network/<name>`    — public discovery record
//! - `POST /encryption/networks/<network_id>/decrypt` — UCAN-style decrypt invocation
//! - `POST /encryption/networks/<network_id>/revoke`  — admin revoke (placeholder)

use rocket::{http::Status, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

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
    pub principal: String,
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

#[post("/encryption/networks", format = "json", data = "<body>")]
pub async fn create_network(
    authorization: AuthHeaderGetter<InvocationInfo>,
    body: Json<serde_json::Value>,
    service: &State<EncryptionService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<DescriptorView>, (Status, String)> {
    let invocation = authorization.0;
    let invocation_info = invocation.0.clone();
    verify_auth(invocation, tinycloud, service.node_did()).await?;

    let body_value = body.into_inner();
    let body: CreateNetworkBody = serde_json::from_value(body_value.clone())
        .map_err(|err| (Status::BadRequest, err.to_string()))?;
    let network_id = NetworkId::new(body.principal.clone(), body.name.clone())
        .map_err(|err| (Status::BadRequest, err.to_string()))?;
    service
        .verify_network_admin_authorized(
            &network_id,
            NETWORK_CREATE_ACTION,
            &invocation_info,
            &body_value,
        )
        .await
        .map_err(map_service_err)?;
    let req = CreateNetworkRequest {
        name: body.name,
        principal: body.principal,
        threshold: body.threshold,
    };
    let descriptor = service
        .create_one_of_one_network(req)
        .await
        .map_err(map_service_err)?;
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
    let descriptor = service.get_network(&net).await.map_err(map_service_err)?;
    Ok(Json(DescriptorView { descriptor }))
}

/// Discovery record published as `.well-known/encryption/network/<name>`.
/// Authoritative state still lives in the node DB; this endpoint just renders a
/// cache-friendly view of the active network for the given name.
#[get("/.well-known/encryption/network/<name>?<principal>")]
pub async fn well_known_network(
    name: &str,
    principal: Option<&str>,
    service: &State<EncryptionService>,
) -> Result<Json<WellKnownRecord>, (Status, String)> {
    // V1 supports principal-qualified discovery when the caller has it, and a
    // name-only fallback for single-principal nodes.
    let descriptor = service
        .get_network_by_name(name, principal)
        .await
        .map_err(map_service_err)?;
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
    verify_auth(invocation, tinycloud, service.node_did()).await?;

    let net: NetworkId =
        network_id
            .parse()
            .map_err(|e: tinycloud_core::encryption_network::NetworkIdError| {
                (Status::BadRequest, e.to_string())
            })?;
    let body = body.into_inner();
    let verified = service
        .decrypt_authorized(&net, &invocation_info, &body)
        .await
        .map_err(map_service_err)?;
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
    verify_auth(invocation, tinycloud, service.node_did()).await?;

    let net: NetworkId =
        network_id
            .parse()
            .map_err(|e: tinycloud_core::encryption_network::NetworkIdError| {
                (Status::BadRequest, e.to_string())
            })?;
    let body = serde_json::json!({});
    service
        .verify_network_admin_authorized(&net, NETWORK_REVOKE_ACTION, &invocation_info, &body)
        .await
        .map_err(map_service_err)?;
    service
        .revoke_network(&net)
        .await
        .map_err(map_service_err)?;
    Ok(Status::NoContent)
}

async fn verify_auth(
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
    tinycloud
        .invoke::<BlockStage>(invocation, HashMap::new())
        .await
        .map(|_| ())
        .map_err(|err| (Status::Unauthorized, err.to_string()))
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
        | EncryptionServiceError::PrincipalMismatch
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

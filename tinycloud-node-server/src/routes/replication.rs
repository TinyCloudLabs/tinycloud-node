use crate::{
    authorization::{AuthHeaderGetter, ReplicationSessionToken},
    BlockStage, TinyCloud,
};
use rocket::{http::Status, serde::json::Json, State};
use tinycloud_auth::resource::{Path as ResourcePath, Service, SpaceId};
use tinycloud_core::{
    events::Delegation,
    replication::{
        AuthReplicationApplyResponse, AuthReplicationExportRequest, AuthReplicationExportResponse,
        AuthReplicationReconcileRequest, KvReplicationError, ReplicationExportRequest,
        ReplicationExportResponse, ReplicationReconcileRequest, ReplicationRouteStatus,
        ReplicationScope, ReplicationService, ReplicationSessionError,
        ReplicationSessionOpenRequest, ReplicationSessionOpenResponse, ReplicationSessionRecord,
        ReplicationSessionSummary, SqlReplicationApplyResponse, SqlReplicationExportRequest,
        SqlReplicationExportResponse, SqlReplicationReconcileRequest,
    },
    sql::{SqlError, SqlService},
    types::Resource,
    util::{Capability, DelegationInfo},
    TxError,
};

#[get("/replication/info")]
pub async fn replication_info(
    replication: &State<ReplicationService>,
) -> Json<ReplicationRouteStatus> {
    Json(ReplicationRouteStatus {
        protocol_ready: true,
        requires_auth: true,
        endpoints: vec![
            "GET /replication/info",
            "POST /replication/session/open",
            "POST /replication/auth/export",
            "POST /replication/auth/reconcile",
            "POST /replication/export",
            "POST /replication/reconcile",
            "POST /replication/sql/export",
            "POST /replication/sql/reconcile",
        ],
        capabilities: replication.status().clone().into(),
        ..ReplicationRouteStatus::default()
    })
}

#[post("/replication/session/open", format = "json", data = "<request>")]
pub async fn replication_session_open(
    request: Json<ReplicationSessionOpenRequest>,
    auth: Option<AuthHeaderGetter<DelegationInfo>>,
    tinycloud: &State<TinyCloud>,
    replication: &State<ReplicationService>,
) -> Result<Json<ReplicationSessionOpenResponse>, (Status, String)> {
    let auth = auth.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Authorization delegation for replication session".to_string(),
        )
    })?;
    let scope = request_scope(&request)?;
    let delegation = auth.0;
    let requested_resource = requested_resource(&request.space_id, &scope)?;
    ensure_sync_scope(&delegation.0.capabilities, &requested_resource, &scope)?;
    let requester_did = delegation.0.delegate.clone();
    let delegation_hash = delegation.hash();

    import_supporting_delegations(request.supporting_delegations.as_deref(), tinycloud).await?;
    verify_replication_delegation(delegation, tinycloud).await?;
    ensure_replication_delegation_active(delegation_hash, tinycloud).await?;

    let (session_token, record) = replication.open_session(
        requester_did,
        request.space_id.clone(),
        scope,
        Some(delegation_hash),
    );
    let summary = ReplicationSessionSummary::from_record(&record);

    Ok(Json(ReplicationSessionOpenResponse {
        session_token,
        space_id: summary.space_id,
        service: summary.service,
        prefix: summary.prefix,
        db_name: summary.db_name,
        expires_at: summary.expires_at,
    }))
}

#[post("/replication/auth/export", format = "json", data = "<request>")]
pub async fn auth_replication_export(
    request: Json<AuthReplicationExportRequest>,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<AuthReplicationExportResponse>, (Status, String)> {
    ensure_peer_serving_enabled(replication)?;
    let scope = auth_request_scope(&request)?;
    let session = authorize_export_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;

    tinycloud
        .export_auth_replication(&request)
        .await
        .map(Json)
        .map_err(map_replication_error)
}

#[post("/replication/auth/reconcile", format = "json", data = "<request>")]
pub async fn auth_reconcile(
    request: Json<AuthReplicationReconcileRequest>,
    peer_token: Option<ReplicationSessionToken>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<AuthReplicationApplyResponse>, (Status, String)> {
    let _scope = auth_reconcile_scope(&request)?;
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Replication-Session for auth replication reconcile".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let export = reqwest::Client::new()
        .post(format!("{peer_url}/replication/auth/export"))
        .header("Replication-Session", peer_token.0)
        .json(&AuthReplicationExportRequest {
            space_id: request.space_id.clone(),
            service: request.service.clone(),
            prefix: request.prefix.clone(),
            db_name: request.db_name.clone(),
            supporting_delegations: request.supporting_delegations.clone(),
        })
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer auth export failed", export).await);
    }

    let export = export
        .json::<AuthReplicationExportResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    let mut applied = tinycloud
        .apply_auth_replication(&export)
        .await
        .map_err(map_auth_tx_error)?;
    applied.peer_url = Some(request.peer_url.clone());
    applied.service = request.service.clone();
    applied.prefix = request.prefix.clone();
    applied.db_name = request.db_name.clone();
    Ok(Json(applied))
}

#[post("/replication/export", format = "json", data = "<request>")]
pub async fn replication_export(
    request: Json<ReplicationExportRequest>,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<ReplicationExportResponse>, (Status, String)> {
    ensure_peer_serving_enabled(replication)?;
    let scope = ReplicationScope::Kv {
        prefix: request.prefix.clone(),
    };
    let session = authorize_export_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;

    tinycloud
        .export_kv_replication(&request)
        .await
        .map(Json)
        .map_err(map_replication_error)
}

#[post("/replication/reconcile", format = "json", data = "<request>")]
pub async fn reconcile(
    request: Json<ReplicationReconcileRequest>,
    peer_token: Option<ReplicationSessionToken>,
    staging: &State<BlockStage>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<tinycloud_core::replication::ReplicationApplyResponse>, (Status, String)> {
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Replication-Session for replication reconcile".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let mut export_request = reqwest::Client::new()
        .post(format!("{peer_url}/replication/export"))
        .json(&ReplicationExportRequest {
            space_id: request.space_id.clone(),
            prefix: request.prefix.clone(),
            since_seq: request.since_seq,
            limit: request.limit,
        });

    export_request = export_request.header("Replication-Session", peer_token.0);

    let export = export_request
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer export failed", export).await);
    }

    let export = export
        .json::<ReplicationExportResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    let mut applied = tinycloud
        .apply_kv_replication(&export, staging.inner())
        .await
        .map_err(map_replication_error)?;
    applied.peer_url = Some(request.peer_url.clone());
    Ok(Json(applied))
}

#[post("/replication/sql/export", format = "json", data = "<request>")]
pub async fn sql_replication_export(
    request: Json<SqlReplicationExportRequest>,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
    sql_service: &State<SqlService>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<SqlReplicationExportResponse>, (Status, String)> {
    ensure_peer_serving_enabled(replication)?;
    let scope = ReplicationScope::Sql {
        db_name: request.db_name.clone(),
    };
    let session = authorize_export_scope(&request.space_id, &scope, token, replication)?;
    ensure_replication_session_active(&session, tinycloud).await?;

    let space_id: SpaceId = request.space_id.parse().map_err(|_| {
        (
            Status::BadRequest,
            format!("invalid space id: {}", request.space_id),
        )
    })?;
    let snapshot = sql_service
        .export(&space_id, &request.db_name)
        .await
        .map_err(map_sql_error)?;

    Ok(Json(SqlReplicationExportResponse {
        space_id: request.space_id.clone(),
        db_name: request.db_name.clone(),
        snapshot,
    }))
}

#[post("/replication/sql/reconcile", format = "json", data = "<request>")]
pub async fn sql_reconcile(
    request: Json<SqlReplicationReconcileRequest>,
    peer_token: Option<ReplicationSessionToken>,
    sql_service: &State<SqlService>,
) -> Result<Json<SqlReplicationApplyResponse>, (Status, String)> {
    let space_id: SpaceId = request.space_id.parse().map_err(|_| {
        (
            Status::BadRequest,
            format!("invalid space id: {}", request.space_id),
        )
    })?;
    let peer_token = peer_token.ok_or_else(|| {
        (
            Status::Unauthorized,
            "missing Replication-Session for replication reconcile".to_string(),
        )
    })?;
    let peer_url = request.peer_url.trim_end_matches('/');
    let mut export_request = reqwest::Client::new()
        .post(format!("{peer_url}/replication/sql/export"))
        .json(&SqlReplicationExportRequest {
            space_id: request.space_id.clone(),
            db_name: request.db_name.clone(),
        });

    export_request = export_request.header("Replication-Session", peer_token.0);

    let export = export_request
        .send()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    if !export.status().is_success() {
        return Err(map_peer_error("peer sql export failed", export).await);
    }

    let export = export
        .json::<SqlReplicationExportResponse>()
        .await
        .map_err(|error| (Status::BadGateway, error.to_string()))?;

    sql_service
        .import(&space_id, &export.db_name, &export.snapshot)
        .await
        .map_err(map_sql_error)?;

    Ok(Json(SqlReplicationApplyResponse {
        space_id: export.space_id,
        db_name: export.db_name,
        peer_url: Some(request.peer_url.clone()),
        snapshot_bytes: export.snapshot.len(),
    }))
}

async fn verify_replication_delegation(
    delegation: Delegation,
    tinycloud: &State<TinyCloud>,
) -> Result<(), (Status, String)> {
    tinycloud
        .delegate(delegation)
        .await
        .map_err(|error| match error {
            TxError::SpaceNotFound => (Status::NotFound, error.to_string()),
            TxError::Db(tinycloud_core::sea_orm::DbErr::ConnectionAcquire(_)) => {
                (Status::InternalServerError, error.to_string())
            }
            _ => (Status::Unauthorized, error.to_string()),
        })?;
    Ok(())
}

async fn import_supporting_delegations(
    supporting_delegations: Option<&[String]>,
    tinycloud: &State<TinyCloud>,
) -> Result<(), (Status, String)> {
    let Some(supporting_delegations) = supporting_delegations else {
        return Ok(());
    };

    for delegation_header in supporting_delegations {
        let delegation = Delegation::from_header_ser::<
            tinycloud_auth::authorization::TinyCloudDelegation,
        >(delegation_header)
        .map_err(|error| (Status::BadRequest, error.to_string()))?;
        verify_replication_delegation(delegation, tinycloud).await?;
    }

    Ok(())
}

fn authorize_export_scope(
    space_id: &str,
    scope: &ReplicationScope,
    token: Option<ReplicationSessionToken>,
    replication: &State<ReplicationService>,
) -> Result<ReplicationSessionRecord, (Status, String)> {
    let session = replication
        .require_session(
            token.as_ref().map(|value| value.0.as_str()),
            space_id,
            scope,
        )
        .map_err(map_replication_session_error)?;

    Ok(session)
}

async fn ensure_replication_session_active(
    session: &ReplicationSessionRecord,
    tinycloud: &State<TinyCloud>,
) -> Result<(), (Status, String)> {
    let active = tinycloud
        .replication_session_delegation_active(session.delegation_hash)
        .await
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;

    if active {
        Ok(())
    } else {
        Err((
            Status::Unauthorized,
            "replication session delegation is no longer active".to_string(),
        ))
    }
}

async fn ensure_replication_delegation_active(
    delegation_hash: tinycloud_core::hash::Hash,
    tinycloud: &State<TinyCloud>,
) -> Result<(), (Status, String)> {
    let active = tinycloud
        .replication_session_delegation_active(Some(delegation_hash))
        .await
        .map_err(|error| (Status::InternalServerError, error.to_string()))?;

    if active {
        Ok(())
    } else {
        Err((
            Status::Unauthorized,
            "replication delegation is no longer active".to_string(),
        ))
    }
}

fn request_scope(
    request: &ReplicationSessionOpenRequest,
) -> Result<ReplicationScope, (Status, String)> {
    match request.service.as_str() {
        "auth" => Ok(ReplicationScope::Auth),
        "kv" => Ok(ReplicationScope::Kv {
            prefix: request.prefix.clone(),
        }),
        "sql" => Ok(ReplicationScope::Sql {
            db_name: request.db_name.clone().ok_or_else(|| {
                (
                    Status::BadRequest,
                    "dbName is required for sql replication sessions".to_string(),
                )
            })?,
        }),
        other => Err((
            Status::BadRequest,
            format!("unsupported replication service: {other}"),
        )),
    }
}

fn auth_request_scope(
    request: &AuthReplicationExportRequest,
) -> Result<ReplicationScope, (Status, String)> {
    auth_scope_from_parts(
        request.service.as_str(),
        request.prefix.as_deref(),
        request.db_name.as_deref(),
    )
}

fn auth_reconcile_scope(
    request: &AuthReplicationReconcileRequest,
) -> Result<ReplicationScope, (Status, String)> {
    auth_scope_from_parts(
        request.service.as_str(),
        request.prefix.as_deref(),
        request.db_name.as_deref(),
    )
}

fn auth_scope_from_parts(
    service: &str,
    prefix: Option<&str>,
    db_name: Option<&str>,
) -> Result<ReplicationScope, (Status, String)> {
    match service {
        "kv" => Ok(ReplicationScope::Kv {
            prefix: prefix.map(|value| value.to_string()),
        }),
        "sql" => Ok(ReplicationScope::Sql {
            db_name: db_name.map(|value| value.to_string()).ok_or_else(|| {
                (
                    Status::BadRequest,
                    "dbName is required for auth replication scope".to_string(),
                )
            })?,
        }),
        other => Err((
            Status::BadRequest,
            format!("unsupported auth replication service: {other}"),
        )),
    }
}

fn ensure_sync_scope(
    capabilities: &[Capability],
    requested_resource: &Resource,
    requested_scope: &ReplicationScope,
) -> Result<(), (Status, String)> {
    let allowed = capabilities.iter().any(|capability| {
        capability.ability.as_ref().as_ref() == "tinycloud.space/sync"
            && (requested_resource.extends(&capability.resource)
                || capability_matches_scope(
                    &capability.resource,
                    requested_resource,
                    requested_scope,
                ))
    });

    if allowed {
        Ok(())
    } else {
        Err((
            Status::Forbidden,
            "authorization does not grant tinycloud.space/sync for requested scope".to_string(),
        ))
    }
}

fn capability_matches_scope(
    capability_resource: &Resource,
    requested_resource: &Resource,
    requested_scope: &ReplicationScope,
) -> bool {
    let Some(requested) = requested_resource.tinycloud_resource() else {
        return false;
    };
    let Some(capability) = capability_resource.tinycloud_resource() else {
        return false;
    };

    if requested.space() != capability.space() {
        return false;
    }

    if capability.service().as_str() != "space" {
        return false;
    }

    scope_matches_space_resource(capability.path().map(|path| path.as_str()), requested_scope)
}

fn scope_matches_space_resource(
    delegated_path: Option<&str>,
    requested_scope: &ReplicationScope,
) -> bool {
    let Some(delegated_path) = delegated_path.map(normalize_scope_value) else {
        return true;
    };

    if delegated_path.is_empty() {
        return true;
    }

    match requested_scope {
        ReplicationScope::Auth => delegated_path == "auth",
        ReplicationScope::Kv { prefix } => match delegated_path {
            "kv" => true,
            _ => delegated_path
                .strip_prefix("kv/")
                .map(|delegated_prefix| {
                    scope_path_is_subset(prefix.as_deref(), Some(delegated_prefix))
                })
                .unwrap_or(false),
        },
        ReplicationScope::Sql { db_name } => match delegated_path {
            "sql" => true,
            _ => delegated_path
                .strip_prefix("sql/")
                .map(|delegated_db| {
                    normalize_scope_value(delegated_db) == normalize_scope_value(db_name)
                })
                .unwrap_or(false),
        },
    }
}

fn scope_path_is_subset(requested: Option<&str>, delegated: Option<&str>) -> bool {
    match (
        requested
            .map(normalize_scope_value)
            .filter(|value| !value.is_empty()),
        delegated
            .map(normalize_scope_value)
            .filter(|value| !value.is_empty()),
    ) {
        (_, None) => true,
        (None, Some(_)) => false,
        (Some(requested), Some(delegated)) => {
            requested == delegated || requested.starts_with(&format!("{delegated}/"))
        }
    }
}

fn normalize_scope_value(value: &str) -> &str {
    value.trim_matches('/')
}

fn requested_resource(
    space_id: &str,
    scope: &ReplicationScope,
) -> Result<Resource, (Status, String)> {
    let space_id: SpaceId = space_id
        .parse()
        .map_err(|_| (Status::BadRequest, format!("invalid space id: {space_id}")))?;
    let service: Service = match scope {
        ReplicationScope::Auth => "space".parse(),
        _ => scope.service().parse(),
    }
    .map_err(|error| (Status::BadRequest, format!("invalid service: {error}")))?;
    let path = match scope {
        ReplicationScope::Auth => Some(
            "auth"
                .parse::<ResourcePath>()
                .map_err(|error| (Status::BadRequest, format!("invalid auth scope: {error}")))?,
        ),
        ReplicationScope::Kv { prefix } => normalized_path(prefix.as_deref())?,
        ReplicationScope::Sql { db_name } => Some(
            normalize_required_db_name(db_name)?
                .parse::<ResourcePath>()
                .map_err(|error| (Status::BadRequest, format!("invalid sql db scope: {error}")))?,
        ),
    };

    Ok(Resource::from(
        space_id.to_resource(service, path, None, None),
    ))
}

fn normalized_path(value: Option<&str>) -> Result<Option<ResourcePath>, (Status, String)> {
    match value
        .map(|value| value.trim_matches('/'))
        .filter(|value| !value.is_empty())
    {
        Some(value) => value.parse::<ResourcePath>().map(Some).map_err(|error| {
            (
                Status::BadRequest,
                format!("invalid replication scope: {error}"),
            )
        }),
        None => Ok(None),
    }
}

fn normalize_required_db_name(value: &str) -> Result<String, (Status, String)> {
    let value = value.trim_matches('/');
    if value.is_empty() {
        return Err((
            Status::BadRequest,
            "dbName is required for sql replication sessions".to_string(),
        ));
    }
    Ok(value.to_string())
}

fn ensure_peer_serving_enabled(
    replication: &State<ReplicationService>,
) -> Result<(), (Status, String)> {
    let status = replication.status();
    if !status.enabled {
        return Err((
            Status::ServiceUnavailable,
            "replication export is disabled on this node".to_string(),
        ));
    }

    if status.roles_enabled.contains(&"host") {
        return Ok(());
    }

    if status.roles_enabled.contains(&"replica") && status.peer_serving {
        return Ok(());
    }

    if status.roles_enabled.contains(&"replica") {
        return Err((
            Status::Forbidden,
            "replication export requires peerServing on replica nodes".to_string(),
        ));
    }

    Err((
        Status::Forbidden,
        "replication export is not enabled for this node role".to_string(),
    ))
}

fn map_replication_error(error: KvReplicationError) -> (Status, String) {
    let status = match error {
        KvReplicationError::InvalidHashEncoding { .. }
        | KvReplicationError::InvalidInvocation { .. }
        | KvReplicationError::InvalidInvocationUtf8 { .. }
        | KvReplicationError::InvalidPath(_)
        | KvReplicationError::InvalidSpaceId(_)
        | KvReplicationError::UnsupportedInvocation { .. } => Status::BadRequest,
        KvReplicationError::MissingBlock { .. }
        | KvReplicationError::MissingDeletedWrite { .. } => Status::FailedDependency,
        KvReplicationError::Db(_)
        | KvReplicationError::Encryption(_)
        | KvReplicationError::Encoding(_)
        | KvReplicationError::Io(_)
        | KvReplicationError::StoreRead(_)
        | KvReplicationError::StoreWrite(_)
        | KvReplicationError::Stage(_)
        | KvReplicationError::Tx(_) => Status::InternalServerError,
    };
    (status, error.to_string())
}

fn map_replication_session_error(error: ReplicationSessionError) -> (Status, String) {
    let status = match error {
        ReplicationSessionError::MissingToken | ReplicationSessionError::InvalidToken => {
            Status::Unauthorized
        }
        ReplicationSessionError::ScopeMismatch => Status::Forbidden,
    };
    (status, error.to_string())
}

fn map_auth_tx_error<B, K>(error: TxError<B, K>) -> (Status, String)
where
    B: tinycloud_core::storage::StorageSetup,
    K: tinycloud_core::keys::Secrets,
{
    match error {
        TxError::SpaceNotFound => (Status::NotFound, error.to_string()),
        TxError::Db(tinycloud_core::sea_orm::DbErr::ConnectionAcquire(_)) => {
            (Status::InternalServerError, error.to_string())
        }
        TxError::Db(_) => (Status::InternalServerError, error.to_string()),
        _ => (Status::Unauthorized, error.to_string()),
    }
}

fn map_sql_error(error: SqlError) -> (Status, String) {
    let status = match error {
        SqlError::DatabaseNotFound => Status::NotFound,
        SqlError::PermissionDenied(_) | SqlError::ReadOnlyViolation => Status::Forbidden,
        SqlError::ResponseTooLarge(_) => Status::PayloadTooLarge,
        SqlError::QuotaExceeded => Status::TooManyRequests,
        SqlError::InvalidStatement(_)
        | SqlError::SchemaError(_)
        | SqlError::ParseError(_)
        | SqlError::Sqlite(_) => Status::BadRequest,
        SqlError::Internal(_) => Status::InternalServerError,
    };
    (status, error.to_string())
}

async fn map_peer_error(prefix: &str, response: reqwest::Response) -> (Status, String) {
    let peer_status = response.status();
    let body = response
        .text()
        .await
        .unwrap_or_else(|_| "<no response body>".to_string());
    (
        Status::BadGateway,
        format!("{prefix} with status {peer_status}: {body}"),
    )
}

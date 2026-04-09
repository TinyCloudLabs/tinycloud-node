use anyhow::Result;
use rocket::{data::ToByteUnit, http::Status, serde::json::Json, State};
use serde::Serialize;
use std::collections::HashMap;
use tokio::io::AsyncReadExt;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info_span, Instrument};

use crate::{
    auth_guards::{DataIn, DataOut, InvOut, ObjectHeaders},
    authorization::AuthHeaderGetter,
    config::Config,
    quota::QuotaCache,
    routes::public::is_public_space,
    tracing::TracingSpan,
    BlockStage, BlockStores, TinyCloud,
};
use tinycloud_core::{
    duckdb::{DuckDbCaveats, DuckDbError, DuckDbRequest, DuckDbResponse, DuckDbService},
    events::Invocation,
    replication::{ReplicationService, ReplicationStatus},
    sea_orm::DbErr,
    sql::{SqlCaveats, SqlError, SqlRequest, SqlService},
    storage::{ImmutableReadStore, ImmutableStaging},
    types::Resource,
    util::{DelegationInfo, InvocationInfo},
    InvocationOutcome, TransactResult, TxError, TxStoreError,
};

pub mod admin;
pub mod attestation;
pub mod public;
pub mod replication;
pub mod util;
use util::LimitedReader;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeServices {
    pub kv: bool,
    pub delegation: bool,
    pub sharing: bool,
    pub sql: bool,
    pub duckdb: bool,
}

#[derive(Serialize)]
pub struct NodeInfo {
    pub protocol: u32,
    pub version: String,
    pub features: Vec<&'static str>,
    #[serde(rename = "rolesSupported")]
    pub roles_supported: Vec<&'static str>,
    #[serde(rename = "rolesEnabled")]
    pub roles_enabled: Vec<&'static str>,
    pub services: NodeServices,
    pub replication: ReplicationStatus,
    #[serde(rename = "inTEE")]
    pub in_tee: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_url: Option<String>,
}

fn build_info(
    tee: &State<Option<crate::tee::TeeContext>>,
    quota_cache: &State<QuotaCache>,
    replication: &State<ReplicationService>,
) -> NodeInfo {
    #[allow(unused_mut)]
    let mut features = vec![
        "kv",
        "delegation",
        "sharing",
        "sql",
        "duckdb",
        "replication",
    ];
    #[cfg(feature = "dstack")]
    features.push("tee");
    NodeInfo {
        protocol: tinycloud_auth::protocol::PROTOCOL_VERSION,
        version: env!("CARGO_PKG_VERSION").to_string(),
        features,
        roles_supported: replication.status().roles_supported.clone(),
        roles_enabled: replication.status().roles_enabled.clone(),
        services: NodeServices {
            kv: true,
            delegation: true,
            sharing: true,
            sql: true,
            duckdb: true,
        },
        replication: replication.status().clone(),
        in_tee: tee.inner().is_some(),
        quota_url: quota_cache.quota_url().map(|s| s.to_string()),
    }
}

#[get("/info")]
pub fn info(
    tee: &State<Option<crate::tee::TeeContext>>,
    quota_cache: &State<QuotaCache>,
    replication: &State<ReplicationService>,
) -> Json<NodeInfo> {
    Json(build_info(tee, quota_cache, replication))
}

#[get("/version")]
pub fn version(
    tee: &State<Option<crate::tee::TeeContext>>,
    quota_cache: &State<QuotaCache>,
    replication: &State<ReplicationService>,
) -> Json<NodeInfo> {
    Json(build_info(tee, quota_cache, replication))
}

#[allow(clippy::let_unit_value)]
pub mod util_routes {
    use super::*;

    #[options("/<_s..>")]
    pub async fn cors(_s: std::path::PathBuf) {}

    #[get("/healthz")]
    pub async fn healthcheck(s: &State<TinyCloud>) -> Status {
        if s.check_db_connection().await.is_ok() {
            Status::Ok
        } else {
            Status::InternalServerError
        }
    }
}

#[get("/peer/generate/<space>")]
pub async fn open_host_key(
    s: &State<TinyCloud>,
    space: &str,
) -> Result<String, (Status, &'static str)> {
    s.stage_key(
        &space
            .parse()
            .map_err(|_| (Status::BadRequest, "Invalid space ID"))?,
    )
    .await
    .map_err(|_| {
        (
            Status::InternalServerError,
            "Failed to stage keypair for space",
        )
    })
}

#[derive(Serialize)]
pub struct DelegateResponse {
    pub cid: String,
    pub activated: Vec<String>,
    pub skipped: Vec<String>,
}

#[post("/delegate")]
pub async fn delegate(
    d: AuthHeaderGetter<DelegationInfo>,
    req_span: TracingSpan,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<DelegateResponse>, (Status, String)> {
    let action_label = "delegation";
    let span = info_span!(parent: &req_span.0, "delegate", action = %action_label);
    // Instrumenting async block to handle yielding properly
    async move {
        let timer = crate::prometheus::AUTHORIZED_INVOKE_HISTOGRAM
            .with_label_values(&["delegate"])
            .start_timer();
        let res = tinycloud
            .delegate(d.0)
            .await
            .map_err(|e| {
                (
                    match e {
                        TxError::SpaceNotFound => Status::NotFound,
                        TxError::Db(DbErr::ConnectionAcquire(_)) => Status::InternalServerError,
                        _ => Status::Unauthorized,
                    },
                    e.to_string(),
                )
            })
            .and_then(|result: TransactResult| {
                let activated: Vec<String> = result.commits.keys().map(|s| s.to_string()).collect();
                let skipped: Vec<String> = result
                    .skipped_spaces
                    .iter()
                    .map(|s| s.to_string())
                    .collect();

                // Get CID from the first committed event, or fall back to
                // the delegation CID when all spaces were skipped
                let cid = result
                    .commits
                    .into_values()
                    .next()
                    .and_then(|c| c.committed_events.into_iter().next())
                    .or_else(|| result.delegation_cids.into_iter().next())
                    .map(|h| h.to_cid(0x55).to_string())
                    .ok_or_else(|| {
                        (Status::Unauthorized, "Delegation not committed".to_string())
                    })?;

                Ok(Json(DelegateResponse {
                    cid,
                    activated,
                    skipped,
                }))
            });
        timer.observe_duration();
        res
    }
    .instrument(span)
    .await
}

#[post("/invoke", data = "<data>")]
#[allow(clippy::too_many_arguments)]
pub async fn invoke(
    i: AuthHeaderGetter<InvocationInfo>,
    req_span: TracingSpan,
    headers: ObjectHeaders,
    data: DataIn<'_>,
    staging: &State<BlockStage>,
    tinycloud: &State<TinyCloud>,
    config: &State<Config>,
    quota_cache: &State<QuotaCache>,
    sql_service: &State<SqlService>,
    duckdb_service: &State<DuckDbService>,
) -> Result<DataOut<<BlockStores as ImmutableReadStore>::Readable>, (Status, String)> {
    let action_label = "invocation";
    let span = info_span!(parent: &req_span.0, "invoke", action = %action_label);
    // Instrumenting async block to handle yielding properly
    async move {
        let timer = crate::prometheus::AUTHORIZED_INVOKE_HISTOGRAM
            .with_label_values(&["invoke"])
            .start_timer();

        // Check for SQL capabilities
        let sql_caps: Vec<_> = i
            .0
             .0
            .capabilities
            .iter()
            .filter_map(|c| match (&c.resource, c.ability.as_ref().as_ref()) {
                (Resource::TinyCloud(r), ability)
                    if r.service().as_str() == "sql" && ability.starts_with("tinycloud.sql/") =>
                {
                    Some((
                        r.space().clone(),
                        r.path().map(|p| p.to_string()),
                        ability.to_string(),
                    ))
                }
                _ => None,
            })
            .collect();

        if !sql_caps.is_empty() {
            let result = handle_sql_invoke(i, data, tinycloud, sql_service, &sql_caps).await;
            timer.observe_duration();
            return result;
        }

        // Check for DuckDB capabilities
        let duckdb_caps: Vec<_> =
            i.0 .0
                .capabilities
                .iter()
                .filter_map(|c| match (&c.resource, c.ability.as_ref().as_ref()) {
                    (Resource::TinyCloud(r), ability)
                        if r.service().as_str() == "duckdb"
                            && ability.starts_with("tinycloud.duckdb/") =>
                    {
                        Some((
                            r.space().clone(),
                            r.path().map(|p| p.to_string()),
                            ability.to_string(),
                        ))
                    }
                    _ => None,
                })
                .collect();

        if !duckdb_caps.is_empty() {
            let arrow_format = headers.0 .0.iter().any(|(k, v)| {
                k.eq_ignore_ascii_case("accept")
                    && v.contains("application/vnd.apache.arrow.stream")
            });
            let result = handle_duckdb_invoke(
                i,
                data,
                tinycloud,
                duckdb_service,
                &duckdb_caps,
                arrow_format,
            )
            .await;
            timer.observe_duration();
            return result;
        }

        let mut put_iter = i.0 .0.capabilities.iter().filter_map(|c| {
            match (&c.resource, c.ability.as_ref().as_ref()) {
                (Resource::TinyCloud(r), "tinycloud.kv/put")
                    if r.service().as_str() == "kv" && r.path().is_some() =>
                {
                    Some((r.space(), r.path()))
                }
                _ => None,
            }
        });

        let inputs = match (data, put_iter.next(), put_iter.next()) {
            (DataIn::None | DataIn::One(_), None, _) => HashMap::new(),
            (DataIn::One(d), Some((space, Some(path))), None) => {
                let mut stage = staging
                    .stage(space)
                    .await
                    .map_err(|e| (Status::InternalServerError, e.to_string()))?;
                let open_data = d.open(1u8.gigabytes()).compat();

                // Use public space storage limit if applicable, otherwise per-space quota
                let effective_limit = if is_public_space(space) {
                    Some(config.public_spaces.storage_limit)
                } else {
                    quota_cache.get_limit(space).await
                };

                if let Some(limit) = effective_limit {
                    let current_size = tinycloud
                        .store_size(space)
                        .await
                        .map_err(|e| (Status::InternalServerError, e.to_string()))?
                        .ok_or_else(|| (Status::NotFound, "space not found".to_string()))?;
                    // get the remaining allocated space for the given space storage
                    match limit.as_u64().checked_sub(current_size) {
                        // the current size is already equal or greater than the limit
                        None | Some(0) => {
                            return Err((
                                Status::new(402),
                                format!(
                                    "Storage quota exceeded. Used: {} bytes, Limit: {} bytes",
                                    current_size,
                                    limit.as_u64()
                                ),
                            ))
                        }
                        Some(remaining) => {
                            futures::io::copy(LimitedReader::new(open_data, remaining), &mut stage)
                                .await
                                .map_err(|e| {
                                    if e.to_string().contains("storage limit") {
                                        (
                                            Status::PayloadTooLarge,
                                            format!(
                                                "Write exceeds remaining storage. Used: {} bytes, Limit: {} bytes",
                                                current_size,
                                                limit.as_u64()
                                            ),
                                        )
                                    } else {
                                        (Status::InternalServerError, e.to_string())
                                    }
                                })?;
                        }
                    }
                } else {
                    // no limit on storage, just use the data as is
                    futures::io::copy(open_data, &mut stage)
                        .await
                        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
                };

                let mut inputs = HashMap::new();
                inputs.insert((space.clone(), path.clone()), (headers.0, stage));
                inputs
            }
            (DataIn::Many(_), Some(_), Some(_)) => {
                return Err((
                    Status::BadRequest,
                    "Multipart not yet supported".to_string(),
                ));
            }
            _ => {
                return Err((Status::BadRequest, "Invalid inputs".to_string()));
            }
        };
        let res = tinycloud
            .invoke::<BlockStage>(i.0, inputs)
            .await
            .map(
                |(_, mut outcomes)| match (outcomes.pop(), outcomes.pop(), outcomes.drain(..)) {
                    (None, None, _) => DataOut::None,
                    (Some(o), None, _) => DataOut::One(InvOut(o)),
                    (Some(o), Some(next), rest) => {
                        let mut v = vec![InvOut(o), InvOut(next)];
                        v.extend(rest.map(InvOut));
                        DataOut::Many(v)
                    }
                    _ => unreachable!(),
                },
            )
            .map_err(|e| {
                (
                    match e {
                        TxStoreError::Tx(TxError::SpaceNotFound) => Status::NotFound,
                        TxStoreError::Tx(TxError::Db(DbErr::ConnectionAcquire(_))) => {
                            Status::InternalServerError
                        }
                        _ => Status::Unauthorized,
                    },
                    e.to_string(),
                )
            });

        timer.observe_duration();
        res
    }
    .instrument(span)
    .await
}

/// Verify authorization by invoking with empty inputs.
///
/// Shared by SQL and DuckDB invoke handlers. The caller must extract caveats
/// from `i` before calling this, since the invocation tuple is consumed here.
async fn verify_auth(
    invocation: Invocation,
    tinycloud: &State<TinyCloud>,
) -> Result<(), (Status, String)> {
    tinycloud
        .invoke::<BlockStage>(invocation, HashMap::new())
        .await
        .map_err(|e| {
            (
                match e {
                    TxStoreError::Tx(TxError::SpaceNotFound) => Status::NotFound,
                    TxStoreError::Tx(TxError::Db(DbErr::ConnectionAcquire(_))) => {
                        Status::InternalServerError
                    }
                    _ => Status::Unauthorized,
                },
                e.to_string(),
            )
        })?;
    Ok(())
}

/// Read the request body as a JSON string.
async fn read_json_body(data: DataIn<'_>) -> Result<String, (Status, String)> {
    match data {
        DataIn::One(d) => {
            let mut buf = Vec::new();
            let mut reader = d.open(1u8.megabytes());
            reader
                .read_to_end(&mut buf)
                .await
                .map_err(|e| (Status::BadRequest, e.to_string()))?;
            String::from_utf8(buf).map_err(|e| (Status::BadRequest, e.to_string()))
        }
        _ => Err((Status::BadRequest, "Expected JSON body".to_string())),
    }
}

async fn handle_sql_invoke(
    i: AuthHeaderGetter<InvocationInfo>,
    data: DataIn<'_>,
    tinycloud: &State<TinyCloud>,
    sql_service: &State<SqlService>,
    sql_caps: &[(tinycloud_auth::resource::SpaceId, Option<String>, String)],
) -> Result<DataOut<<BlockStores as ImmutableReadStore>::Readable>, (Status, String)> {
    // Extract caveats from the invocation facts before consuming i
    let caveats: Option<SqlCaveats> =
        i.0 .0
            .invocation
            .payload()
            .facts
            .as_ref()
            .and_then(|facts| {
                facts.iter().find_map(|fact| {
                    fact.as_object()
                        .and_then(|obj| obj.get("sqlCaveats"))
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                })
            });

    verify_auth(i.0, tinycloud).await?;
    let body_str = read_json_body(data).await?;

    let (space, path, ability) = &sql_caps[0];
    let db_name = SqlService::db_name_from_path(path.as_deref());

    let sql_request: SqlRequest =
        serde_json::from_str(&body_str).map_err(|e| (Status::BadRequest, e.to_string()))?;

    // Handle export specially
    if matches!(sql_request, SqlRequest::Export) {
        let data = sql_service
            .export(space, &db_name)
            .await
            .map_err(|e| (sql_error_to_status(&e), e.to_string()))?;
        return Ok(DataOut::One(InvOut(InvocationOutcome::SqlExport(data))));
    }

    let response = sql_service
        .execute(space, &db_name, sql_request, caveats, ability.clone())
        .await
        .map_err(|e| (sql_error_to_status(&e), e.to_string()))?;

    let json =
        serde_json::to_value(response).map_err(|e| (Status::InternalServerError, e.to_string()))?;

    Ok(DataOut::One(InvOut(InvocationOutcome::SqlResult(json))))
}

fn sql_error_to_status(err: &SqlError) -> Status {
    match err {
        SqlError::Sqlite(_) => Status::BadRequest,
        SqlError::PermissionDenied(_) => Status::Forbidden,
        SqlError::DatabaseNotFound => Status::NotFound,
        SqlError::ResponseTooLarge(_) => Status::new(413),
        SqlError::QuotaExceeded => Status::new(429),
        SqlError::InvalidStatement(_) => Status::BadRequest,
        SqlError::SchemaError(_) => Status::BadRequest,
        SqlError::ReadOnlyViolation => Status::Forbidden,
        SqlError::ParseError(_) => Status::BadRequest,
        SqlError::Internal(_) => Status::InternalServerError,
    }
}

async fn handle_duckdb_invoke(
    i: AuthHeaderGetter<InvocationInfo>,
    data: DataIn<'_>,
    tinycloud: &State<TinyCloud>,
    duckdb_service: &State<DuckDbService>,
    duckdb_caps: &[(tinycloud_auth::resource::SpaceId, Option<String>, String)],
    arrow_format: bool,
) -> Result<DataOut<<BlockStores as ImmutableReadStore>::Readable>, (Status, String)> {
    // SECURITY TODO: Extract caveats from delegation chain, not invocation facts. See PR review [H3].
    // Extract caveats from the invocation facts before consuming i
    let caveats: Option<DuckDbCaveats> =
        i.0 .0
            .invocation
            .payload()
            .facts
            .as_ref()
            .and_then(|facts| {
                facts.iter().find_map(|fact| {
                    fact.as_object()
                        .and_then(|obj| obj.get("duckdbCaveats"))
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                })
            });

    verify_auth(i.0, tinycloud).await?;

    let (space, path, ability) = &duckdb_caps[0];
    let db_name = DuckDbService::db_name_from_path(path.as_deref());

    // Handle import: binary body with application/octet-stream
    if ability == "tinycloud.duckdb/import" {
        let body_bytes = match data {
            DataIn::One(d) => {
                let mut buf = Vec::new();
                let mut reader = d.open(100u8.megabytes());
                reader
                    .read_to_end(&mut buf)
                    .await
                    .map_err(|e| (Status::BadRequest, e.to_string()))?;
                buf
            }
            _ => {
                return Err((
                    Status::BadRequest,
                    "Expected binary body for import".to_string(),
                ));
            }
        };

        duckdb_service
            .import_db(space, &db_name, &body_bytes)
            .await
            .map_err(|e| (duckdb_error_to_status(&e), e.to_string()))?;

        let json = serde_json::json!({"imported": true});
        return Ok(DataOut::One(InvOut(InvocationOutcome::DuckDbResult(json))));
    }

    let body_str = read_json_body(data).await?;

    let duckdb_request: DuckDbRequest =
        serde_json::from_str(&body_str).map_err(|e| (Status::BadRequest, e.to_string()))?;

    // Handle export specially
    if matches!(duckdb_request, DuckDbRequest::Export) {
        if caveats.is_some() {
            return Err((
                Status::Forbidden,
                "Export not allowed with active caveats".into(),
            ));
        }
        let data = duckdb_service
            .export(space, &db_name)
            .await
            .map_err(|e| (duckdb_error_to_status(&e), e.to_string()))?;
        return Ok(DataOut::One(InvOut(InvocationOutcome::DuckDbExport(data))));
    }

    let response = duckdb_service
        .execute(
            space,
            &db_name,
            duckdb_request,
            caveats,
            ability.clone(),
            arrow_format,
        )
        .await
        .map_err(|e| (duckdb_error_to_status(&e), e.to_string()))?;

    match response {
        DuckDbResponse::Arrow(data) => {
            Ok(DataOut::One(InvOut(InvocationOutcome::DuckDbArrow(data))))
        }
        other => {
            let json = serde_json::to_value(other)
                .map_err(|e| (Status::InternalServerError, e.to_string()))?;
            Ok(DataOut::One(InvOut(InvocationOutcome::DuckDbResult(json))))
        }
    }
}

fn duckdb_error_to_status(err: &DuckDbError) -> Status {
    match err {
        DuckDbError::DuckDb(_) => Status::BadRequest,
        DuckDbError::InvalidStatement(_) => Status::BadRequest,
        DuckDbError::SchemaError(_) => Status::BadRequest,
        DuckDbError::ParseError(_) => Status::BadRequest,
        DuckDbError::PermissionDenied(_) => Status::Forbidden,
        DuckDbError::ReadOnlyViolation => Status::Forbidden,
        DuckDbError::DatabaseNotFound => Status::NotFound,
        DuckDbError::ResponseTooLarge(_) => Status::new(413),
        DuckDbError::QuotaExceeded => Status::new(429),
        DuckDbError::IngestError(_) => Status::InternalServerError,
        DuckDbError::ExportError(_) => Status::InternalServerError,
        DuckDbError::ImportError(_) => Status::InternalServerError,
        DuckDbError::Internal(_) => Status::InternalServerError,
    }
}

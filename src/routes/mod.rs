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
    tracing::TracingSpan,
    BlockStage, BlockStores, TinyCloud,
};
use tinycloud_core::{
    sea_orm::DbErr,
    sql::{SqlCaveats, SqlError, SqlRequest, SqlService},
    storage::{ImmutableReadStore, ImmutableStaging},
    types::Resource,
    util::{DelegationInfo, InvocationInfo},
    InvocationOutcome, TxError, TxStoreError,
};

pub mod util;
use util::LimitedReader;

#[derive(Serialize)]
pub struct VersionInfo {
    pub protocol: u32,
    pub version: String,
    pub features: Vec<&'static str>,
}

#[get("/version")]
pub fn version() -> Json<VersionInfo> {
    Json(VersionInfo {
        protocol: tinycloud_lib::protocol::PROTOCOL_VERSION,
        version: env!("CARGO_PKG_VERSION").to_string(),
        features: vec!["kv", "delegation", "sharing", "sql"],
    })
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

#[post("/delegate")]
pub async fn delegate(
    d: AuthHeaderGetter<DelegationInfo>,
    req_span: TracingSpan,
    tinycloud: &State<TinyCloud>,
) -> Result<String, (Status, String)> {
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
            .and_then(|c| {
                c.into_iter()
                    .next()
                    .and_then(|(_, c)| c.committed_events.into_iter().next())
                    .ok_or_else(|| (Status::Unauthorized, "Delegation not committed".to_string()))
            })
            .map(|h| h.to_cid(0x55).to_string());
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
    sql_service: &State<SqlService>,
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

                if let Some(limit) = config.storage.limit {
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
                                Status::PayloadTooLarge,
                                "The data storage limit has been reached".into(),
                            ))
                        }
                        Some(remaining) => {
                            futures::io::copy(LimitedReader::new(open_data, remaining), &mut stage)
                                .await
                                .map_err(|e| (Status::InternalServerError, e.to_string()))?;
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

async fn handle_sql_invoke(
    i: AuthHeaderGetter<InvocationInfo>,
    data: DataIn<'_>,
    tinycloud: &State<TinyCloud>,
    sql_service: &State<SqlService>,
    sql_caps: &[(tinycloud_lib::resource::SpaceId, Option<String>, String)],
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

    // Verify authorization by invoking with empty inputs
    // SQL capabilities don't match KV patterns, so invoke just verifies auth
    tinycloud
        .invoke::<BlockStage>(i.0, HashMap::new())
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

    // Read the request body as JSON
    let body_str = match data {
        DataIn::One(d) => {
            let mut buf = Vec::new();
            let mut reader = d.open(1u8.megabytes());
            reader
                .read_to_end(&mut buf)
                .await
                .map_err(|e| (Status::BadRequest, e.to_string()))?;
            String::from_utf8(buf).map_err(|e| (Status::BadRequest, e.to_string()))?
        }
        _ => {
            return Err((Status::BadRequest, "Expected JSON body".to_string()));
        }
    };

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

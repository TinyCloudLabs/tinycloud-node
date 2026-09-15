//! Native publication commands share /invoke admission and the existing SQL catalog.
use super::*;
use tinycloud_core::sql::{publication, SqlExecutionResult, SqlResponse, SqlValue};

pub(super) fn command(
    request: &SqlRequest,
    path: Option<&str>,
    ability: &str,
    caveats: &Option<SqlCaveats>,
) -> Result<Option<serde_json::Value>, (Status, String)> {
    let params = match request {
        SqlRequest::ExecuteStatement { name, params } if name == publication::STATEMENT => params,
        SqlRequest::Execute {
            sql,
            params,
            schema,
        } if sql == publication::STATEMENT => {
            if schema.is_some() {
                return Err((Status::BadRequest, "publication_schema_forbidden".into()));
            }
            params
        }
        _ => return Ok(None),
    };
    if path != Some(publication::SQL_PATH)
        || !tinycloud_core::policy_capability::ability_matches(ability, "tinycloud.sql/write")
        || caveats.is_some()
    {
        return Err((Status::Forbidden, "publication_authority_required".into()));
    }
    let [SqlValue::Text(raw)] = params.as_slice() else {
        return Err((Status::BadRequest, "publication_invalid_command".into()));
    };
    let command: serde_json::Value = serde_json::from_str(raw)
        .map_err(|_| (Status::BadRequest, "publication_invalid_command".into()))?;
    if command["contractVersion"] != 3
        || !matches!(
            command["operation"].as_str(),
            Some(
                "capabilities"
                    | "activate"
                    | "reserve"
                    | "stage"
                    | "publish"
                    | "inspect"
                    | "delete"
                    | "purge"
                    | "freeze_legacy"
                    | "unfreeze_legacy"
                    | "legacy_freeze_status"
            )
        )
    {
        return Err((Status::BadRequest, "publication_invalid_command".into()));
    }
    if matches!(
        command["operation"].as_str(),
        Some("freeze_legacy" | "unfreeze_legacy")
    ) && expected_generation(&command).is_none()
    {
        return Err((
            Status::BadRequest,
            "legacy_freeze_invalid_expected_generation".into(),
        ));
    }
    Ok(Some(command))
}
fn expected_generation(command: &serde_json::Value) -> Option<i64> {
    command["expectedGeneration"]
        .as_i64()
        .filter(|generation| *generation >= 0 && *generation < i64::MAX)
}
/// Publication does not reinterpret a delegated table/column/statement caveat as unrestricted SQL.
pub(super) async fn require_unconstrained_chain(
    tinycloud: &TinyCloud,
    parents: &[tinycloud_auth::authorization::Cid],
) -> Result<(), (Status, String)> {
    use tinycloud_core::{hash::Hash, models::abilities, relationships::parent_delegations};
    let conn = tinycloud
        .readable()
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    let mut frontier: Vec<Hash> = parents.iter().copied().map(Hash::from).collect();
    let mut visited = HashSet::new();
    while !frontier.is_empty() {
        let batch: Vec<_> = frontier.drain(..).filter(|h| visited.insert(*h)).collect();
        if batch.is_empty() {
            break;
        }
        let rows = abilities::Entity::find()
            .filter(abilities::Column::Delegation.is_in(batch.clone()))
            .all(&conn)
            .await
            .map_err(|e| (Status::InternalServerError, e.to_string()))?;
        for row in rows {
            if row
                .resource
                .tinycloud_resource()
                .is_some_and(|resource| resource.service().as_str() == "sql")
                && !row.caveats.0.is_empty()
            {
                return Err((
                    Status::Forbidden,
                    "publication_unconstrained_authority_required".into(),
                ));
            }
        }
        let links = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.is_in(batch))
            .all(&conn)
            .await
            .map_err(|e| (Status::InternalServerError, e.to_string()))?;
        for link in links {
            if !visited.contains(&link.parent) {
                frontier.push(link.parent);
            }
        }
    }
    Ok(())
}

fn bad(code: &str) -> SqlError {
    SqlError::InvalidStatement(code.into())
}
fn internal(error: impl std::fmt::Display) -> SqlError {
    SqlError::Internal(error.to_string())
}
fn receipt(value: serde_json::Value) -> SqlExecutionResult {
    SqlExecutionResult {
        response: SqlResponse::Query(tinycloud_core::sql::QueryResponse {
            columns: vec!["receipt".into()],
            rows: vec![vec![SqlValue::Text(value.to_string())]],
            row_count: 1,
        }),
        write_targets: vec![],
    }
}
async fn verify(
    tinycloud: &TinyCloud,
    space: &SpaceId,
    key: &str,
    revision: &str,
) -> Result<bool, SqlError> {
    let path: Path = key.parse().map_err(internal)?;
    let Some((_, _, content)) = tinycloud.kv_get(space, &path).await.map_err(internal)? else {
        return Ok(false);
    };
    let mut reader = Box::pin(content).take((publication::ENVELOPE_LIMIT + 1) as u64);
    let mut bytes = Vec::new();
    FuturesAsyncReadExt::read_to_end(&mut reader, &mut bytes)
        .await
        .map_err(internal)?;
    if bytes.len() > publication::ENVELOPE_LIMIT {
        return Err(bad("publication_capacity"));
    }
    let raw = std::str::from_utf8(&bytes).map_err(|_| bad("publication_snapshot_invalid"))?;
    if publication::digest(raw) != revision {
        return Err(bad("publication_digest_mismatch"));
    }
    Ok(true)
}
// Serialize the SQL/KV publication sequence as one native operation on this node.
lazy_static::lazy_static! {static ref PUBLICATION_LOCKS:std::sync::Mutex<HashMap<String,std::sync::Weak<tokio::sync::Mutex<()>>>>=std::sync::Mutex::new(HashMap::new());}
fn protocol_lock(space: &SpaceId) -> std::sync::Arc<tokio::sync::Mutex<()>> {
    let mut locks = PUBLICATION_LOCKS.lock().unwrap();
    locks.retain(|_, lock| lock.strong_count() > 0);
    let key = space.to_string();
    if let Some(lock) = locks.get(&key).and_then(std::sync::Weak::upgrade) {
        return lock;
    }
    let lock = std::sync::Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, std::sync::Arc::downgrade(&lock));
    lock
}
pub(super) async fn execute(
    tinycloud: &TinyCloud,
    sql: &SqlService,
    staging: &BlockStage,
    space: &SpaceId,
    mut command: serde_json::Value,
) -> Result<SqlExecutionResult, SqlError> {
    let _guard = protocol_lock(space).lock_owned().await;
    let operation = command["operation"]
        .as_str()
        .ok_or_else(|| bad("publication_invalid_command"))?
        .to_owned();
    if matches!(operation.as_str(), "freeze_legacy" | "unfreeze_legacy") {
        let expected = expected_generation(&command)
            .ok_or_else(|| bad("legacy_freeze_invalid_expected_generation"))?;
        let status = tinycloud
            .set_legacy_meeting_write_freeze(space, operation == "freeze_legacy", expected)
            .await
            .map_err(|error| match error {
                tinycloud_core::meeting_legacy_guard::FreezeError::Db(error) => internal(error),
                error => bad(&error.to_string()),
            })?;
        return Ok(receipt(
            serde_json::json!({"contractVersion":3,"legacyWritesFrozen":status.frozen,"legacyFreezeGeneration":status.generation}),
        ));
    }
    if operation == "legacy_freeze_status" {
        let status = tinycloud
            .legacy_meeting_freeze_status(space)
            .await
            .map_err(internal)?;
        return Ok(receipt(
            serde_json::json!({"contractVersion":3,"legacyWritesFrozen":status.frozen,"legacyFreezeGeneration":status.generation}),
        ));
    }
    // Reject known frozen cleanup before SQL tombstones/removals. The core KV
    // transaction guard independently closes races and internal cleanup bypasses.
    if matches!(operation.as_str(), "delete" | "purge")
        && tinycloud
            .legacy_meeting_freeze_status(space)
            .await
            .map_err(internal)?
            .frozen
    {
        return Err(SqlError::PermissionDenied(
            "legacy meeting artifacts are frozen".into(),
        ));
    }
    if operation == "stage" {
        publication::validate_snapshot(&command)?;
        let raw = command["snapshotRaw"]
            .as_str()
            .ok_or_else(|| bad("publication_invalid_command"))?
            .to_owned();
        let key = command["snapshotKey"]
            .as_str()
            .ok_or_else(|| bad("publication_invalid_command"))?
            .to_owned();
        let revision = command["revision"]
            .as_str()
            .ok_or_else(|| bad("publication_invalid_command"))?
            .to_owned();
        command["operation"] = serde_json::json!("prepare_stage");
        sql.meeting_publication(space, command.clone()).await?;
        if !verify(tinycloud, space, &key, &revision).await? {
            let mut buffer = staging.stage(space).await.map_err(internal)?;
            buffer.write_all(raw.as_bytes()).await.map_err(internal)?;
            buffer.flush().await.map_err(internal)?;
            match tinycloud
                .invoke_internal_meeting_snapshot_put::<BlockStage>(
                    space.clone(),
                    key.parse().map_err(internal)?,
                    Metadata(BTreeMap::from([(
                        "content-type".into(),
                        "application/json".into(),
                    )])),
                    buffer,
                    Some(KvPrecondition::DoesNotExist),
                )
                .await
            {
                Ok(_) | Err(TxStoreError::KvPreconditionFailed) => {}
                Err(error) => return Err(internal(error)),
            }
        }
        if !verify(tinycloud, space, &key, &revision).await? {
            return Err(bad("publication_snapshot_missing"));
        }
        command["operation"] = serde_json::json!("stage");
        command.as_object_mut().unwrap().remove("snapshotRaw");
        // A superseding reservation/delete cannot publish this verified staged object.
        // Failed finalization remains indexed for purge. Do not delete here: another
        // node may already have published an idempotent attempt with the same digest.
        return sql.meeting_publication(space, command).await;
    }
    if operation == "publish" {
        let key = command["snapshotKey"]
            .as_str()
            .ok_or_else(|| bad("publication_invalid_command"))?;
        let revision = command["revision"]
            .as_str()
            .ok_or_else(|| bad("publication_invalid_command"))?;
        if !publication::protected_snapshot_path(key)
            || !verify(tinycloud, space, key, revision).await?
        {
            return Err(bad("publication_snapshot_missing"));
        }
    }
    command.as_object_mut().unwrap().remove("cleanupKeys");
    if operation == "purge" {
        let source = command["source"]
            .as_str()
            .filter(|source| {
                matches!(
                    *source,
                    "fireflies" | "google-meet" | "tinycloud-transcriber"
                )
            })
            .ok_or_else(|| bad("publication_invalid_source"))?;
        let prefix: Path = format!("{}/{source}/", publication::SQL_PATH)
            .parse()
            .map_err(internal)?;
        let keys = tinycloud
            .public_kv_list(space, &prefix)
            .await
            .map_err(internal)?;
        command["cleanupKeys"] = serde_json::json!(keys
            .into_iter()
            .map(|key| key.to_string())
            .collect::<Vec<_>>());
    }
    let mut result = sql.meeting_publication(space, command).await?;
    if operation == "capabilities" {
        let SqlResponse::Query(query) = &mut result.response else {
            return Err(bad("publication_receipt_invalid"));
        };
        let Some(SqlValue::Text(raw)) = query.rows.first_mut().and_then(|row| row.first_mut())
        else {
            return Err(bad("publication_receipt_invalid"));
        };
        let mut value: serde_json::Value = serde_json::from_str(raw).map_err(internal)?;
        value["legacyWriteFreeze"] = serde_json::json!(true);
        *raw = value.to_string();
    }
    if matches!(operation.as_str(), "delete" | "purge") {
        let SqlResponse::Query(query) = &result.response else {
            return Err(bad("publication_receipt_invalid"));
        };
        let Some(SqlValue::Text(raw)) = query.rows.first().and_then(|r| r.first()) else {
            return Err(bad("publication_receipt_invalid"));
        };
        let receipt: serde_json::Value = serde_json::from_str(raw).map_err(internal)?;
        for key in receipt["snapshotKeys"]
            .as_array()
            .ok_or_else(|| bad("publication_receipt_invalid"))?
        {
            let key = key
                .as_str()
                .ok_or_else(|| bad("publication_receipt_invalid"))?;
            if !publication::connector_owned_path(key) {
                return Err(bad("publication_receipt_invalid"));
            }
            tinycloud
                .invoke_internal_meeting_snapshot_delete::<BlockStage>(
                    space.clone(),
                    key.parse().map_err(internal)?,
                )
                .await
                .map_err(internal)?;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tinycloud_core::sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database};
    use tinycloud_core::{
        database_artifacts::SeaOrmDatabaseArtifactRepository,
        keys::StaticSecret,
        storage::{either::Either, StorageConfig},
        types::SpaceIdWrap,
    };

    async fn legacy_route_fixture(
        activate: bool,
    ) -> (
        TinyCloud,
        SqlService,
        BlockStage,
        SpaceId,
        tempfile::TempDir,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        let storage =
            crate::storage::file_system::FileSystemConfig::new(directory.path().join("blocks"))
                .open()
                .await
                .unwrap();
        let tinycloud = TinyCloud::new(
            conn.clone(),
            Either::B(storage),
            StaticSecret::new(vec![0; 32]).unwrap(),
        )
        .await
        .unwrap();
        let key = tinycloud_auth::ssi::jwk::JWK::generate_ed25519().unwrap();
        let space = SpaceId::new(
            tinycloud_auth::resolver::DID_METHODS
                .generate(&key, "key")
                .unwrap(),
            "freeze-catalog".parse().unwrap(),
        );
        tinycloud_core::models::space::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(&conn)
        .await
        .unwrap();
        let sql = SqlService::new(
            directory.path().join("sql").display().to_string(),
            u64::MAX,
            std::sync::Arc::new(SeaOrmDatabaseArtifactRepository::new(conn)),
        );
        if activate {
            sql.meeting_publication(
                &space,
                serde_json::json!({"contractVersion":3,"operation":"activate"}),
            )
            .await
            .unwrap();
            sql.meeting_publication(&space, serde_json::json!({"contractVersion":3,"operation":"reserve","source":"fireflies","sourceId":"old","operationId":"initial"})).await.unwrap();
        }
        let staging = BlockStage::from(crate::config::StagingStorage::Memory);
        (tinycloud, sql, staging, space, directory)
    }

    async fn catalog(sql: &SqlService, space: &SpaceId) -> serde_json::Value {
        let result = sql
            .execute(
                space,
                publication::DATABASE,
                SqlRequest::Query {
                    sql: "SELECT * FROM connector_meeting ORDER BY id".into(),
                    params: vec![],
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".into(),
            )
            .await
            .unwrap();
        serde_json::to_value(result.response).unwrap()
    }

    #[tokio::test]
    async fn legacy_freeze_delete_and_purge_leave_catalog_unchanged() {
        for operation in ["delete", "purge"] {
            let (tinycloud, sql, staging, space, _directory) = legacy_route_fixture(true).await;
            let before = catalog(&sql, &space).await;
            let frozen = execute(&tinycloud,&sql,&staging,&space,serde_json::json!({"contractVersion":3,"operation":"freeze_legacy","expectedGeneration":0})).await.unwrap();
            let SqlResponse::Query(query) = frozen.response else {
                panic!("freeze receipt")
            };
            assert_eq!(query.columns, vec!["receipt"]);
            let SqlValue::Text(raw) = &query.rows[0][0] else {
                panic!("freeze receipt")
            };
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(raw).unwrap(),
                serde_json::json!({"contractVersion":3,"legacyWritesFrozen":true,"legacyFreezeGeneration":1})
            );
            let result = execute(&tinycloud,&sql,&staging,&space,serde_json::json!({"contractVersion":3,"operation":operation,"source":"fireflies","sourceId":"old","operationId":operation})).await;
            assert!(result.is_err(), "frozen {operation} must reject");
            assert_eq!(
                catalog(&sql, &space).await,
                before,
                "frozen {operation} changed catalog before cleanup rejection"
            );
            assert!(result
                .unwrap_err()
                .to_string()
                .contains("legacy meeting artifacts are frozen"));
            execute(&tinycloud,&sql,&staging,&space,serde_json::json!({"contractVersion":3,"operation":"unfreeze_legacy","expectedGeneration":1})).await.unwrap();
            execute(&tinycloud,&sql,&staging,&space,serde_json::json!({"contractVersion":3,"operation":operation,"source":"fireflies","sourceId":"old","operationId":operation})).await.unwrap();
            assert_ne!(
                catalog(&sql, &space).await,
                before,
                "released {operation} did not resume"
            );
        }
    }
    fn parsed_receipt(result: SqlExecutionResult) -> serde_json::Value {
        let SqlResponse::Query(query) = result.response else {
            panic!("query receipt")
        };
        assert_eq!(query.columns, vec!["receipt"]);
        let SqlValue::Text(raw) = &query.rows[0][0] else {
            panic!("JSON receipt")
        };
        serde_json::from_str(raw).unwrap()
    }
    #[tokio::test]
    async fn legacy_freeze_controls_are_generation_checked_without_catalog_activation() {
        let (tinycloud, sql, staging, space, _directory) = legacy_route_fixture(false).await;
        let status = parsed_receipt(
            execute(
                &tinycloud,
                &sql,
                &staging,
                &space,
                serde_json::json!({"contractVersion":3,"operation":"legacy_freeze_status"}),
            )
            .await
            .unwrap(),
        );
        assert_eq!(
            status,
            serde_json::json!({"contractVersion":3,"legacyWritesFrozen":false,"legacyFreezeGeneration":0})
        );
        let capabilities = parsed_receipt(
            execute(
                &tinycloud,
                &sql,
                &staging,
                &space,
                serde_json::json!({"contractVersion":3,"operation":"capabilities"}),
            )
            .await
            .unwrap(),
        );
        assert_eq!(capabilities["legacyWriteFreeze"], true);
        for (operation, expected, frozen, generation) in [
            ("freeze_legacy", 0, true, 1),
            ("freeze_legacy", 0, true, 1),
            ("unfreeze_legacy", 1, false, 2),
            ("unfreeze_legacy", 1, false, 2),
            ("freeze_legacy", 2, true, 3),
        ] {
            let receipt=parsed_receipt(execute(&tinycloud,&sql,&staging,&space,serde_json::json!({"contractVersion":3,"operation":operation,"expectedGeneration":expected})).await.unwrap());
            assert_eq!(
                receipt,
                serde_json::json!({"contractVersion":3,"legacyWritesFrozen":frozen,"legacyFreezeGeneration":generation})
            );
        }
        let stale=execute(&tinycloud,&sql,&staging,&space,serde_json::json!({"contractVersion":3,"operation":"unfreeze_legacy","expectedGeneration":1})).await.unwrap_err();
        assert!(stale
            .to_string()
            .contains("legacy_freeze_generation_conflict"));
        let reserve=sql.meeting_publication(&space,serde_json::json!({"contractVersion":3,"operation":"reserve","source":"fireflies","sourceId":"old","operationId":"probe"})).await.unwrap_err();
        assert!(
            reserve
                .to_string()
                .contains("publication_activation_required"),
            "freeze unexpectedly activated catalog: {reserve}"
        );
    }
    fn request(operation: &str) -> SqlRequest {
        SqlRequest::ExecuteStatement {
            name: publication::STATEMENT.into(),
            params: vec![SqlValue::Text(
                serde_json::json!({"contractVersion":3,"operation":operation,"expectedGeneration":0}).to_string(),
            )],
        }
    }
    #[test]
    fn legacy_freeze_rejects_invalid_expected_generation() {
        for expected in [
            serde_json::Value::Null,
            serde_json::json!(-1),
            serde_json::json!(1.5),
            serde_json::json!("0"),
            serde_json::json!(i64::MAX),
            serde_json::json!(u64::MAX),
        ] {
            let request = SqlRequest::ExecuteStatement { name:publication::STATEMENT.into(), params:vec![SqlValue::Text(serde_json::json!({"contractVersion":3,"operation":"freeze_legacy","expectedGeneration":expected}).to_string())] };
            assert!(
                command(
                    &request,
                    Some(publication::SQL_PATH),
                    "tinycloud.sql/write",
                    &None
                )
                .is_err(),
                "accepted invalid generation {expected}"
            );
        }
    }
    #[test]
    fn publication_route_rejects_read_only_and_constrained_authority() {
        assert!(command(
            &request("reserve"),
            Some(publication::SQL_PATH),
            "tinycloud.sql/read",
            &None
        )
        .is_err());
        assert!(command(
            &request("reserve"),
            Some(publication::SQL_PATH),
            "tinycloud.sql/write",
            &Some(SqlCaveats::default())
        )
        .is_err());
    }
    #[test]
    fn publication_route_rejects_wrong_database_and_private_operations() {
        assert!(command(
            &request("reserve"),
            Some("other/connectors"),
            "tinycloud.sql/write",
            &None
        )
        .is_err());
        assert!(command(
            &request("prepare_stage"),
            Some(publication::SQL_PATH),
            "tinycloud.sql/write",
            &None
        )
        .is_err());
    }
    #[test]
    fn publication_route_recognizes_fixed_command() {
        assert!(command(
            &request("activate"),
            Some(publication::SQL_PATH),
            "tinycloud.sql/*",
            &None
        )
        .unwrap()
        .is_some());
        assert_eq!(
            command(
                &request("capabilities"),
                Some(publication::SQL_PATH),
                "tinycloud.sql/write",
                &None
            )
            .unwrap()
            .unwrap()["operation"],
            "capabilities"
        );
    }

    #[test]
    fn legacy_freeze_commands_require_existing_unconstrained_publication_authority() {
        for operation in ["freeze_legacy", "unfreeze_legacy", "legacy_freeze_status"] {
            assert!(command(
                &request(operation),
                Some(publication::SQL_PATH),
                "tinycloud.sql/write",
                &None
            )
            .unwrap()
            .is_some());
            assert!(command(
                &request(operation),
                Some(publication::SQL_PATH),
                "tinycloud.sql/read",
                &None
            )
            .is_err());
            assert!(command(
                &request(operation),
                Some(publication::SQL_PATH),
                "tinycloud.sql/write",
                &Some(SqlCaveats::default())
            )
            .is_err());
            assert!(command(
                &request(operation),
                Some("other/connectors"),
                "tinycloud.sql/write",
                &None
            )
            .is_err());
        }
    }
    #[test]
    fn publication_route_accepts_fixed_execute_without_schema() {
        let request = SqlRequest::Execute {
            sql: publication::STATEMENT.into(),
            params: vec![SqlValue::Text(
                serde_json::json!({"contractVersion":3,"operation":"capabilities"}).to_string(),
            )],
            schema: None,
        };
        assert!(command(
            &request,
            Some(publication::SQL_PATH),
            "tinycloud.sql/write",
            &None
        )
        .unwrap()
        .is_some());
        let SqlRequest::Execute { sql, params, .. } = request else {
            unreachable!()
        };
        assert!(command(
            &SqlRequest::Execute {
                sql,
                params,
                schema: Some(vec!["DROP TABLE connector_meeting".into()])
            },
            Some(publication::SQL_PATH),
            "tinycloud.sql/write",
            &None
        )
        .is_err());
    }
    #[rocket::post("/", data = "<data>")]
    async fn framing(data: rocket::Data<'_>) -> Result<String, (Status, String)> {
        super::super::read_json_body_limited(DataIn::One(data), publication::ENVELOPE_LIMIT)
            .await
            .map(|body| body.len().to_string())
    }
    #[rocket::async_test]
    async fn publication_route_checks_complete_utf8_framing() {
        let client = rocket::local::asynchronous::Client::tracked(
            rocket::build().mount("/", rocket::routes![framing]),
        )
        .await
        .unwrap();
        let body = "é".repeat(publication::ENVELOPE_LIMIT / 2);
        assert_eq!(
            client
                .post("/")
                .body(body.clone())
                .dispatch()
                .await
                .status(),
            Status::Ok
        );
        assert_eq!(
            client
                .post("/")
                .body(format!("{body} "))
                .dispatch()
                .await
                .status(),
            Status::PayloadTooLarge
        );
        assert_eq!(
            client.post("/").body(vec![255]).dispatch().await.status(),
            Status::BadRequest
        );
    }
}

//! Status and release compatibility for the withdrawn publication protocol.
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
    if command["contractVersion"] != 3 || command["operation"].as_str().is_none() {
        return Err((Status::BadRequest, "publication_invalid_command".into()));
    }
    if !matches!(
        command["operation"].as_str(),
        Some("capabilities" | "unfreeze_legacy" | "legacy_freeze_status")
    ) {
        return Err((Status::BadRequest, "publication_withdrawn".into()));
    }
    if command["operation"] == "unfreeze_legacy" && expected_generation(&command).is_none() {
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
/// Only status and generation-checked release remain from publication v3.
pub(super) async fn execute(
    tinycloud: &TinyCloud,
    sql: &SqlService,
    space: &SpaceId,
    command: serde_json::Value,
) -> Result<SqlExecutionResult, SqlError> {
    if command["contractVersion"] != 3 {
        return Err(bad("publication_invalid_command"));
    }
    let operation = command["operation"]
        .as_str()
        .ok_or_else(|| bad("publication_invalid_command"))?;
    match operation {
        "unfreeze_legacy" => {
            let expected = expected_generation(&command)
                .ok_or_else(|| bad("legacy_freeze_invalid_expected_generation"))?;
            let status = tinycloud
                .set_legacy_meeting_write_freeze(space, false, expected)
                .await
                .map_err(|error| match error {
                    tinycloud_core::meeting_legacy_guard::FreezeError::Db(error) => internal(error),
                    error => bad(&error.to_string()),
                })?;
            Ok(receipt(
                serde_json::json!({"contractVersion":3,"legacyWritesFrozen":status.frozen,"legacyFreezeGeneration":status.generation}),
            ))
        }
        "legacy_freeze_status" => {
            let status = tinycloud
                .legacy_meeting_freeze_status(space)
                .await
                .map_err(internal)?;
            Ok(receipt(
                serde_json::json!({"contractVersion":3,"legacyWritesFrozen":status.frozen,"legacyFreezeGeneration":status.generation}),
            ))
        }
        "capabilities" => {
            let mut result = sql.meeting_publication(space, command).await?;
            let SqlResponse::Query(query) = &mut result.response else {
                return Err(bad("publication_receipt_invalid"));
            };
            let Some(SqlValue::Text(raw)) = query.rows.first_mut().and_then(|row| row.first_mut())
            else {
                return Err(bad("publication_receipt_invalid"));
            };
            let mut value: serde_json::Value = serde_json::from_str(raw).map_err(internal)?;
            value["legacyWriteFreeze"] = serde_json::json!(false);
            *raw = value.to_string();
            Ok(result)
        }
        _ => Err(bad("publication_withdrawn")),
    }
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

    #[test]
    fn publication_rollback_rejects_withdrawn_commands_at_admission() {
        for operation in [
            "activate",
            "reserve",
            "stage",
            "publish",
            "inspect",
            "delete",
            "purge",
            "freeze_legacy",
        ] {
            let error = command(
                &request(operation),
                Some(publication::SQL_PATH),
                "tinycloud.sql/write",
                &None,
            )
            .expect_err("withdrawn publication command admitted");
            assert_eq!(error.0, Status::BadRequest);
            assert_eq!(error.1, "publication_withdrawn");
        }
    }

    async fn legacy_route_fixture() -> (TinyCloud, SqlService, SpaceId, tempfile::TempDir) {
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
        (tinycloud, sql, space, directory)
    }

    #[tokio::test]
    async fn publication_rollback_rejects_direct_execution_without_catalog_changes() {
        let (tinycloud, sql, space, _directory) = legacy_route_fixture().await;
        for operation in [
            "activate",
            "reserve",
            "prepare_stage",
            "stage",
            "publish",
            "inspect",
            "delete",
            "purge",
            "freeze_legacy",
        ] {
            let error = execute(&tinycloud, &sql, &space, serde_json::json!({"contractVersion":3,"operation":operation,"expectedGeneration":0}))
                .await.expect_err("withdrawn command executed directly");
            assert!(
                error.to_string().contains("publication_withdrawn"),
                "{operation}: {error}"
            );
        }
        assert_eq!(
            tinycloud
                .legacy_meeting_freeze_status(&space)
                .await
                .unwrap()
                .generation,
            0
        );
        let catalog = sql
            .execute(
                &space,
                publication::DATABASE,
                SqlRequest::Query {
                    sql: "SELECT COUNT(*) FROM sqlite_master".into(),
                    params: vec![],
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".into(),
            )
            .await
            .unwrap();
        let SqlResponse::Query(query) = catalog.response else {
            panic!("catalog query")
        };
        assert_eq!(query.rows, vec![vec![SqlValue::Integer(0)]]);
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
    async fn publication_rollback_releases_existing_freeze_with_generation_checks() {
        let (tinycloud, sql, space, _directory) = legacy_route_fixture().await;
        // Simulate a durable freeze written by the previous release.
        tinycloud
            .set_legacy_meeting_write_freeze(&space, true, 0)
            .await
            .unwrap();
        let status = parsed_receipt(
            execute(
                &tinycloud,
                &sql,
                &space,
                serde_json::json!({"contractVersion":3,"operation":"legacy_freeze_status"}),
            )
            .await
            .unwrap(),
        );
        assert_eq!(
            status,
            serde_json::json!({"contractVersion":3,"legacyWritesFrozen":true,"legacyFreezeGeneration":1})
        );
        let capabilities = parsed_receipt(
            execute(
                &tinycloud,
                &sql,
                &space,
                serde_json::json!({"contractVersion":3,"operation":"capabilities"}),
            )
            .await
            .unwrap(),
        );
        assert_eq!(capabilities["legacyWriteFreeze"], false);
        assert_eq!(capabilities["writerFencing"], false);
        assert_eq!(capabilities["digestVerification"], false);
        assert_eq!(capabilities["snapshotImmutability"], true);
        let stale = execute(&tinycloud, &sql, &space,
            serde_json::json!({"contractVersion":3,"operation":"unfreeze_legacy","expectedGeneration":0})).await.unwrap_err();
        assert!(stale
            .to_string()
            .contains("legacy_freeze_generation_conflict"));
        assert!(
            tinycloud
                .legacy_meeting_freeze_status(&space)
                .await
                .unwrap()
                .frozen
        );
        // Exact-ticket release and a lost-ack retry must return the same generation.
        for _ in 0..2 {
            let receipt = parsed_receipt(execute(&tinycloud, &sql, &space,
                serde_json::json!({"contractVersion":3,"operation":"unfreeze_legacy","expectedGeneration":1})).await.unwrap());
            assert_eq!(
                receipt,
                serde_json::json!({"contractVersion":3,"legacyWritesFrozen":false,"legacyFreezeGeneration":2})
            );
        }
        let catalog = sql
            .execute(
                &space,
                publication::DATABASE,
                SqlRequest::Query {
                    sql: "SELECT COUNT(*) FROM sqlite_master".into(),
                    params: vec![],
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".into(),
            )
            .await
            .unwrap();
        let SqlResponse::Query(query) = catalog.response else {
            panic!("catalog query")
        };
        assert_eq!(query.rows, vec![vec![SqlValue::Integer(0)]]);
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
            let request = SqlRequest::ExecuteStatement { name:publication::STATEMENT.into(), params:vec![SqlValue::Text(serde_json::json!({"contractVersion":3,"operation":"unfreeze_legacy","expectedGeneration":expected}).to_string())] };
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
            &request("unfreeze_legacy"),
            Some(publication::SQL_PATH),
            "tinycloud.sql/read",
            &None
        )
        .is_err());
        assert!(command(
            &request("unfreeze_legacy"),
            Some(publication::SQL_PATH),
            "tinycloud.sql/write",
            &Some(SqlCaveats::default())
        )
        .is_err());
    }
    #[test]
    fn publication_route_rejects_wrong_database_and_private_operations() {
        assert!(command(
            &request("unfreeze_legacy"),
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
            &request("capabilities"),
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
        for operation in ["unfreeze_legacy", "legacy_freeze_status"] {
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

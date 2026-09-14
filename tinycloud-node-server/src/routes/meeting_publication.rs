//! Native publication commands share /invoke admission and the existing SQL catalog.
use super::*;
use tinycloud_core::sql::{publication, SqlExecutionResult, SqlResponse, SqlValue};

pub(super) fn command(
    request: &SqlRequest,
    path: Option<&str>,
    ability: &str,
    caveats: &Option<SqlCaveats>,
) -> Result<Option<serde_json::Value>, (Status, String)> {
    let SqlRequest::ExecuteStatement { name, params } = request else {
        return Ok(None);
    };
    if name != publication::STATEMENT {
        return Ok(None);
    }
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
            )
        )
    {
        return Err((Status::BadRequest, "publication_invalid_command".into()));
    }
    Ok(Some(command))
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
    let result = sql.meeting_publication(space, command).await?;
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
    fn request(operation: &str) -> SqlRequest {
        SqlRequest::ExecuteStatement {
            name: publication::STATEMENT.into(),
            params: vec![SqlValue::Text(
                serde_json::json!({"contractVersion":3,"operation":operation}).to_string(),
            )],
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

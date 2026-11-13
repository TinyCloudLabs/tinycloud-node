//! Direct-owner lifecycle management, separate from delegated data operations.
use crate::{authorization::AuthHeaderGetter, storage::purge_ledger::PurgeLedgerStore};
use rocket::{
    http::Status,
    request::{FromRequest, Outcome, Request},
    response::status::Custom,
    serde::json::Json,
    State,
};
use serde::{Deserialize, Serialize};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use time::OffsetDateTime;
use tinycloud_auth::{identity::canonicalize_did, resource::SpaceId};
use tinycloud_core::{
    models::{space, space_purge_job, space_purge_nonce, space_purge_request, space_retirement},
    sea_orm::{
        sea_query::{Alias, Expr, LikeExpr, Order, Query, UnionType},
        ActiveModelTrait,
        ActiveValue::Set,
        ColumnTrait, ConnectionTrait, DatabaseTransaction, EntityTrait, PaginatorTrait,
        QueryFilter, TransactionTrait,
    },
    space_purge_auth::{verify_owner, OwnerProof, OwnerProofError},
    space_purge_fence::SpacePurgeFence,
    space_purge_ledger::LedgerKeys,
    util::InvocationInfo,
    RecoveringConnection,
};

#[derive(Debug, Serialize)]
pub struct ErrorEnvelope {
    error: ErrorCode,
    #[serde(rename = "hostId", skip_serializing_if = "Option::is_none")]
    host_id: Option<String>,
}
#[derive(Debug, Serialize)]
struct ErrorCode {
    code: &'static str,
}
#[derive(Debug)]
pub struct ApiError {
    status: Status,
    code: &'static str,
}
impl<'r> rocket::response::Responder<'r, 'static> for ApiError {
    fn respond_to(self, request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let host_id = request
            .rocket()
            .state::<LifecycleRuntime>()
            .map(|runtime| runtime.host_id.clone());
        Custom(
            self.status,
            Json(ErrorEnvelope {
                error: ErrorCode { code: self.code },
                host_id,
            }),
        )
        .respond_to(request)
    }
}
fn error(status: Status, code: &'static str) -> ApiError {
    ApiError { status, code }
}
fn unavailable<E>(_: E) -> ApiError {
    error(Status::ServiceUnavailable, "unavailable_retryable")
}
fn proof_error(err: OwnerProofError) -> ApiError {
    match err {
        OwnerProofError::NotOwner => error(Status::NotFound, "not_found"),
        OwnerProofError::Invalid => error(Status::Unauthorized, "authentication_failed"),
    }
}

pub struct IdempotencyKey(String);
#[rocket::async_trait]
impl<'r> FromRequest<'r> for IdempotencyKey {
    type Error = ();
    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, ()> {
        let mut headers = request.headers().get("Idempotency-Key");
        match (headers.next(), headers.next()) {
            (Some(value), None) if value.len() <= 64 => Outcome::Success(Self(value.into())),
            _ => Outcome::Error((Status::BadRequest, ())),
        }
    }
}

#[derive(Clone)]
pub struct LifecycleRuntime {
    conn: RecoveringConnection,
    keys: Arc<LedgerKeys>,
    ledger: Arc<dyn PurgeLedgerStore>,
    pub fence: Arc<SpacePurgeFence>,
    host_id: String,
    ledger_verified: Arc<AtomicBool>,
    pub(crate) reconcile_requested: Arc<tokio::sync::Notify>,
    pub(crate) work_requested: Arc<tokio::sync::Notify>,
}
impl LifecycleRuntime {
    /// An existing independent ledger cannot be bypassed by removing config.
    /// The caller must reconcile the returned runtime before serving requests.
    pub async fn from_settings(
        conn: RecoveringConnection,
        ledger: Arc<dyn PurgeLedgerStore>,
        host_id: Option<String>,
        tombstone_key: Option<String>,
    ) -> Result<Option<Self>, std::io::Error> {
        let invalid = || std::io::Error::other("space lifecycle configuration unavailable");
        match (host_id, tombstone_key) {
            (None, None) => {
                if !ledger.list_purge_records().await?.is_empty()
                    || tinycloud_core::models::space_purge_fence::Entity::find()
                        .filter(tinycloud_core::models::space_purge_fence::Column::Fenced.eq(true))
                        .one(&conn)
                        .await
                        .map_err(|_| invalid())?
                        .is_some()
                    || space_retirement::Entity::find()
                        .one(&conn)
                        .await
                        .map_err(|_| invalid())?
                        .is_some()
                    || space_purge_job::Entity::find()
                        .one(&conn)
                        .await
                        .map_err(|_| invalid())?
                        .is_some()
                    || tinycloud_core::models::resource_purge_job::Entity::find()
                        .one(&conn)
                        .await
                        .map_err(|_| invalid())?
                        .is_some()
                {
                    return Err(invalid());
                }
                Ok(None)
            }
            (host, Some(raw)) => {
                let keys = LedgerKeys::from_config(raw).map_err(|_| invalid())?;
                let host = host.ok_or_else(invalid)?;
                Self::new(conn, Arc::new(keys), ledger, host)
                    .map(Some)
                    .map_err(|_| invalid())
            }
            (Some(_), None) => Err(invalid()),
        }
    }

    pub fn new(
        conn: RecoveringConnection,
        keys: Arc<LedgerKeys>,
        ledger: Arc<dyn PurgeLedgerStore>,
        host_id: String,
    ) -> Result<Self, &'static str> {
        if host_id.is_empty()
            || host_id.len() > 63
            || !host_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err("invalid host id");
        }
        Ok(Self {
            conn,
            fence: Arc::new(SpacePurgeFence::new(keys.clone())),
            keys,
            ledger,
            host_id,
            ledger_verified: Arc::new(AtomicBool::new(false)),
            reconcile_requested: Arc::new(tokio::sync::Notify::new()),
            work_requested: Arc::new(tokio::sync::Notify::new()),
        })
    }
    fn owner_hmacs(&self, owner: &str) -> Result<Vec<Vec<u8>>, ApiError> {
        self.keys
            .key_ids()
            .map(|id| {
                self.keys
                    .target_hmac(id, "owner", owner)
                    .map_err(unavailable)
            })
            .collect()
    }
    async fn management_transaction(
        &self,
        proof: &OwnerProof,
        kind: &str,
        target_kind: &str,
        target: &str,
    ) -> Result<DatabaseTransaction, ApiError> {
        if !self.ledger_verified.load(Ordering::Acquire) {
            return Err(unavailable(()));
        }
        let now = OffsetDateTime::now_utc();
        let tx = self.conn.begin().await.map_err(unavailable)?;
        self.fence
            .lock_owner(&tx, &proof.owner_did)
            .await
            .map_err(unavailable)?;
        space_purge_nonce::Entity::delete_many()
            .filter(space_purge_nonce::Column::ExpiresAt.lt(now - time::Duration::seconds(30)))
            .exec(&tx)
            .await
            .map_err(unavailable)?;
        for key_id in self.keys.key_ids() {
            let digest = self
                .keys
                .nonce_hmac(key_id, &proof.owner_did, &proof.nonce)
                .map_err(unavailable)?;
            if space_purge_nonce::Entity::find_by_id(digest)
                .one(&tx)
                .await
                .map_err(unavailable)?
                .is_some()
            {
                return Err(error(Status::Unauthorized, "authentication_failed"));
            }
        }
        let nonce = self
            .keys
            .nonce_hmac(self.keys.active_key_id(), &proof.owner_did, &proof.nonce)
            .map_err(unavailable)?;
        space_purge_nonce::ActiveModel {
            nonce_hmac: Set(nonce),
            expires_at: Set(
                OffsetDateTime::from_unix_timestamp(proof.expires_at).map_err(unavailable)?
            ),
        }
        .insert(&tx)
        .await
        .map_err(unavailable)?;
        let owner_hmacs = self.owner_hmacs(&proof.owner_did)?;
        let targets: Vec<_> = self
            .keys
            .key_ids()
            .map(|id| self.keys.target_hmac(id, target_kind, target))
            .collect::<Result<_, _>>()
            .map_err(unavailable)?;
        if let Some(existing) = space_purge_request::Entity::find_by_id((
            proof.idempotency_key.clone(),
            kind.to_owned(),
        ))
        .one(&tx)
        .await
        .map_err(unavailable)?
        {
            if kind == "status" {
                return Err(error(Status::Conflict, "idempotency_conflict"));
            }
            if !owner_hmacs.contains(&existing.owner_hmac)
                || !targets.contains(&existing.target_hmac)
            {
                return Err(error(Status::Conflict, "idempotency_conflict"));
            }
        } else {
            let recent = space_purge_request::Entity::find()
                .filter(space_purge_request::Column::OwnerHmac.is_in(owner_hmacs))
                .filter(
                    space_purge_request::Column::AcceptedAt.gt(now - time::Duration::minutes(1)),
                )
                .count(&tx)
                .await
                .map_err(unavailable)?;
            if recent >= 1200 {
                return Err(error(Status::TooManyRequests, "rate_limited"));
            }
            space_purge_request::ActiveModel {
                idempotency_key: Set(proof.idempotency_key.clone()),
                kind: Set(kind.into()),
                owner_hmac: Set(self
                    .keys
                    .target_hmac(self.keys.active_key_id(), "owner", &proof.owner_did)
                    .map_err(unavailable)?),
                target_hmac: Set(self
                    .keys
                    .target_hmac(self.keys.active_key_id(), target_kind, target)
                    .map_err(unavailable)?),
                operation_id: Set(proof.idempotency_key.clone()),
                accepted_at: Set(now),
            }
            .insert(&tx)
            .await
            .map_err(unavailable)?;
        }
        Ok(tx)
    }
    /// Verify all external records before applying any. Reconciliation import
    /// and pending-job resumption are completed before ordinary space serving.
    pub async fn verify_ledger(
        &self,
    ) -> Result<Vec<tinycloud_core::space_purge_ledger::LedgerRecord>, ApiError> {
        self.fence.set_serving_ready(false);
        self.ledger_verified.store(false, Ordering::Release);
        let mut records = Vec::new();
        for key in self
            .ledger
            .list_purge_records()
            .await
            .map_err(unavailable)?
        {
            let bytes = self
                .ledger
                .read_purge_record(&key)
                .await
                .map_err(unavailable)?
                .ok_or_else(|| unavailable(()))?;
            records.push(self.keys.verify(&key, &bytes).map_err(unavailable)?);
        }
        // Management requests remain available to recover canonical targets;
        // this alone does not enable ordinary space traffic.
        self.ledger_verified.store(true, Ordering::Release);
        Ok(records)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListRequest {
    version: u8,
    #[serde(rename = "ownerDid")]
    owner_did: String,
    cursor: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ListResponse {
    pub version: u8,
    pub host_id: String,
    pub owner_did: String,
    pub spaces: Vec<String>,
    pub next_cursor: Option<String>,
    pub last_page: bool,
}

fn owner_prefix(owner: &str) -> String {
    format!("tinycloud:{}:", &owner[4..])
}
fn prefix_pattern(prefix: &str) -> String {
    format!(
        "{}%",
        prefix
            .replace('!', "!!")
            .replace('%', "!%")
            .replace('_', "!_")
    )
}

#[rocket::post("/space/list", format = "json", data = "<body>")]
pub async fn list_my_spaces(
    runtime: &State<LifecycleRuntime>,
    auth: AuthHeaderGetter<InvocationInfo>,
    key: IdempotencyKey,
    body: Json<ListRequest>,
) -> Result<Json<ListResponse>, ApiError> {
    use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
    if body.version != 1 {
        return Err(error(Status::BadRequest, "invalid_request"));
    }
    let owner = canonicalize_did(&body.owner_did)
        .map_err(|_| error(Status::BadRequest, "invalid_request"))?;
    let proof = verify_owner(
        &auth.0 .0.invocation,
        "tinycloud.space/list",
        &owner,
        &owner,
        &key.0,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
    .map_err(proof_error)?;
    let cursor = body
        .cursor
        .as_ref()
        .map(|value| {
            if value.len() > 4096 {
                return Err(error(Status::BadRequest, "invalid_cursor"));
            }
            let bytes = decode_config(value, URL_SAFE_NO_PAD)
                .map_err(|_| error(Status::BadRequest, "invalid_cursor"))?;
            let raw = String::from_utf8(bytes)
                .map_err(|_| error(Status::BadRequest, "invalid_cursor"))?;
            let space: SpaceId = raw
                .parse()
                .map_err(|_| error(Status::BadRequest, "invalid_cursor"))?;
            if space.did().as_str() != owner || space.to_string() != raw {
                return Err(error(Status::BadRequest, "invalid_cursor"));
            }
            Ok(raw)
        })
        .transpose()?;
    let _admission = runtime.fence.lifecycle_operation().await;
    let tx = runtime
        .management_transaction(&proof, "list", "owner", &owner)
        .await?;
    let mut all = Query::select();
    all.column(space::Column::Id).from(space::Entity);
    let mut active = Query::select();
    active
        .column(space_purge_job::Column::Space)
        .from(space_purge_job::Entity)
        .and_where(Expr::col(space_purge_job::Column::Phase).ne("complete"));
    all.union(UnionType::Distinct, active);
    // SQL-only namespaces need not have a hosted KV space row.
    for (table, column) in [
        ("database_alias", "space"),
        ("database_artifact", "space"),
        ("database_legacy_artifact", "space"),
        ("sql_store_manifest", "space"),
        ("sql_store_object", "space"),
    ] {
        let mut namespace = Query::select();
        namespace.column(Alias::new(column)).from(Alias::new(table));
        all.union(UnionType::Distinct, namespace);
    }
    let binary_id = match tx.get_database_backend() {
        tinycloud_core::sea_orm::DbBackend::Postgres => "id COLLATE \"C\"",
        tinycloud_core::sea_orm::DbBackend::Sqlite => "id COLLATE BINARY",
        tinycloud_core::sea_orm::DbBackend::MySql => "BINARY id",
    };
    let mut page = Query::select();
    page.column(Alias::new("id"))
        .from_subquery(all.clone(), Alias::new("owned"))
        .and_where(
            Expr::col(Alias::new("id"))
                .like(LikeExpr::new(prefix_pattern(&owner_prefix(&owner))).escape('!')),
        )
        .order_by_expr(Expr::cust(binary_id), Order::Asc)
        .limit(501);
    if let Some(cursor) = cursor {
        page.and_where(Expr::expr(Expr::cust(binary_id)).gt(cursor));
    }
    let rows = tx
        .query_all(tx.get_database_backend().build(&page))
        .await
        .map_err(unavailable)?;
    let mut spaces = rows
        .into_iter()
        .map(|row| row.try_get::<String>("", "id"))
        .collect::<Result<Vec<_>, _>>()
        .map_err(unavailable)?;
    for id in &spaces {
        let parsed: SpaceId = id.parse().map_err(unavailable)?;
        if parsed.did().as_str() != owner || parsed.to_string() != *id {
            return Err(unavailable(()));
        }
    }
    if spaces.is_empty() {
        let mut known_namespace = Query::select();
        known_namespace
            .column(Alias::new("id"))
            .from_subquery(all, Alias::new("owned"))
            .and_where(
                Expr::col(Alias::new("id"))
                    .like(LikeExpr::new(prefix_pattern(&owner_prefix(&owner))).escape('!')),
            )
            .limit(1);
        let known_space = tx
            .query_one(tx.get_database_backend().build(&known_namespace))
            .await
            .map_err(unavailable)?
            .is_some();
        let hashes = runtime.owner_hmacs(&owner)?;
        let known_retirement = space_retirement::Entity::find()
            .filter(space_retirement::Column::OwnerHmac.is_in(hashes.clone()))
            .one(&tx)
            .await
            .map_err(unavailable)?
            .is_some();
        let known_job = space_purge_job::Entity::find()
            .filter(space_purge_job::Column::OwnerHmac.is_in(hashes))
            .one(&tx)
            .await
            .map_err(unavailable)?
            .is_some();
        if !known_space && !known_retirement && !known_job {
            tx.commit().await.map_err(unavailable)?;
            return Err(error(Status::NotFound, "not_found"));
        }
    }
    let last_page = spaces.len() <= 500;
    spaces.truncate(500);
    let next_cursor = if last_page {
        None
    } else {
        spaces
            .last()
            .map(|id| encode_config(id.as_bytes(), URL_SAFE_NO_PAD))
    };
    tx.commit().await.map_err(unavailable)?;
    Ok(Json(ListResponse {
        version: 1,
        host_id: runtime.host_id.clone(),
        owner_did: owner,
        spaces,
        next_cursor,
        last_page,
    }))
}

/// An external write may have succeeded even when its acknowledgement or DB
/// commit fails. Reconcile before admitting any further data operations.
struct LedgerCommitGuard<'a> {
    runtime: &'a LifecycleRuntime,
    committed: bool,
}
impl Drop for LedgerCommitGuard<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.runtime.fence.set_serving_ready(false);
            self.runtime.ledger_verified.store(false, Ordering::Release);
            self.runtime.reconcile_requested.notify_one();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetireRequest {
    version: u8,
    owner_did: String,
}
#[derive(Serialize, Deserialize)]
pub struct RetireResponse {
    pub version: u8,
    #[serde(rename = "hostId")]
    pub host_id: String,
    pub state: String,
}

impl LifecycleRuntime {
    /// A previous external write may have survived a failed DB transaction.
    /// Its authenticated operation ID and timestamp remain authoritative.
    async fn publish_acceptance(
        &self,
        record: &tinycloud_core::space_purge_ledger::LedgerRecord,
    ) -> Result<tinycloud_core::space_purge_ledger::LedgerRecord, ApiError> {
        let path = record.object_key().map_err(unavailable)?;
        match self
            .ledger
            .append_purge_record(&path, &record.to_bytes().map_err(unavailable)?)
            .await
        {
            Ok(()) => Ok(record.clone()),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                let bytes = self
                    .ledger
                    .read_purge_record(&path)
                    .await
                    .map_err(unavailable)?
                    .ok_or_else(|| unavailable(()))?;
                let existing = self.keys.verify(&path, &bytes).map_err(unavailable)?;
                if existing.kind != record.kind
                    || existing.key_id != record.key_id
                    || existing.target_hmac != record.target_hmac
                    || existing.state != record.state
                {
                    return Err(unavailable(()));
                }
                Ok(existing)
            }
            Err(err) => Err(unavailable(err)),
        }
    }
    async fn bind_operation(
        &self,
        tx: &DatabaseTransaction,
        proof: &OwnerProof,
        kind: &str,
        operation_id: &str,
    ) -> Result<(), ApiError> {
        let request = space_purge_request::Entity::find_by_id((
            proof.idempotency_key.clone(),
            kind.to_owned(),
        ))
        .one(tx)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| unavailable(()))?;
        let mut update: space_purge_request::ActiveModel = request.into();
        update.operation_id = Set(operation_id.into());
        update.update(tx).await.map_err(unavailable)?;
        Ok(())
    }
}

#[rocket::post("/space/retire-owner", format = "json", data = "<body>")]
pub async fn retire_owner(
    runtime: &State<LifecycleRuntime>,
    auth: AuthHeaderGetter<InvocationInfo>,
    key: IdempotencyKey,
    body: Json<RetireRequest>,
) -> Result<Custom<Json<RetireResponse>>, ApiError> {
    if body.version != 1 {
        return Err(error(Status::BadRequest, "invalid_request"));
    }
    let owner = canonicalize_did(&body.owner_did)
        .map_err(|_| error(Status::BadRequest, "invalid_request"))?;
    let proof = verify_owner(
        &auth.0 .0.invocation,
        "tinycloud.space/retire-owner",
        &owner,
        &owner,
        &key.0,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
    .map_err(proof_error)?;
    let _admission = runtime.fence.lifecycle_operation().await;
    let _owner_drain = runtime.fence.retirement_drain(&owner).await;
    let tx = runtime
        .management_transaction(&proof, "retire-owner", "owner", &owner)
        .await?;
    let existing = space_retirement::Entity::find()
        .filter(space_retirement::Column::OwnerHmac.is_in(runtime.owner_hmacs(&owner)?))
        .one(&tx)
        .await
        .map_err(unavailable)?;
    let (key_id, digest, operation_id, timestamp) = match &existing {
        Some(row) => (
            row.hmac_key_id.clone(),
            row.owner_hmac.clone(),
            row.retirement_id.clone(),
            row.accepted_at.unix_timestamp(),
        ),
        None => (
            runtime.keys.active_key_id().to_owned(),
            runtime
                .keys
                .target_hmac(runtime.keys.active_key_id(), "owner", &owner)
                .map_err(unavailable)?,
            proof.idempotency_key.clone(),
            OffsetDateTime::now_utc().unix_timestamp(),
        ),
    };
    let candidate = runtime
        .keys
        .sign(
            &key_id,
            "owner",
            &digest,
            &operation_id,
            "retired",
            timestamp,
        )
        .map_err(unavailable)?;
    let mut ledger_commit = LedgerCommitGuard {
        runtime,
        committed: false,
    };
    let record = runtime.publish_acceptance(&candidate).await?;
    if existing.is_some() && record.operation_id != operation_id {
        return Err(unavailable(()));
    }
    runtime
        .fence
        .fence_hmac(&tx, "owner", &record.key_id, &digest)
        .await
        .map_err(unavailable)?;
    if existing.is_none() {
        space_retirement::ActiveModel {
            owner_hmac: Set(digest),
            hmac_key_id: Set(record.key_id.clone()),
            retirement_id: Set(record.operation_id.clone()),
            accepted_at: Set(
                OffsetDateTime::from_unix_timestamp(record.timestamp).map_err(unavailable)?
            ),
        }
        .insert(&tx)
        .await
        .map_err(unavailable)?;
    }
    runtime
        .bind_operation(&tx, &proof, "retire-owner", &record.operation_id)
        .await?;
    tinycloud_core::space_purge_records::request_all(&tx)
        .await
        .map_err(unavailable)?;
    tx.commit().await.map_err(unavailable)?;
    ledger_commit.committed = true;
    runtime.work_requested.notify_one();
    Ok(Custom(
        if existing.is_none() {
            Status::Accepted
        } else {
            Status::Ok
        },
        Json(RetireResponse {
            version: 1,
            host_id: runtime.host_id.clone(),
            state: "retired".into(),
        }),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeRequest {
    version: u8,
    space_id: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StatusRequest {
    version: u8,
    purge_id: String,
    space_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct PurgeResponse {
    pub version: u8,
    #[serde(rename = "hostId")]
    pub host_id: String,
    pub purge_id: String,
    pub state: String,
    pub accepted_at: String,
    pub updated_at: String,
}
fn purge_response(host_id: &str, job: &space_purge_job::Model) -> Result<PurgeResponse, ApiError> {
    use time::format_description::well_known::Rfc3339;
    Ok(PurgeResponse {
        version: 1,
        host_id: host_id.into(),
        purge_id: job.purge_id.clone(),
        state: if job.phase == "complete" {
            "complete"
        } else {
            "purging"
        }
        .into(),
        accepted_at: job.accepted_at.format(&Rfc3339).map_err(unavailable)?,
        updated_at: job.updated_at.format(&Rfc3339).map_err(unavailable)?,
    })
}
fn request_space(raw: &str) -> Result<SpaceId, ApiError> {
    raw.parse()
        .map_err(|_| error(Status::BadRequest, "invalid_request"))
}
impl LifecycleRuntime {
    fn space_hmacs(&self, space: &SpaceId) -> Result<Vec<Vec<u8>>, ApiError> {
        self.keys
            .key_ids()
            .map(|id| {
                self.keys
                    .target_hmac(id, "space", &space.to_string())
                    .map_err(unavailable)
            })
            .collect()
    }
    fn job_matches(&self, job: &space_purge_job::Model, space: &SpaceId) -> Result<bool, ApiError> {
        let space_hash = self
            .keys
            .target_hmac(&job.hmac_key_id, "space", &space.to_string())
            .map_err(unavailable)?;
        let owner_hash = self
            .keys
            .target_hmac(&job.hmac_key_id, "owner", space.did().as_str())
            .map_err(unavailable)?;
        Ok(job.tombstone_hmac == space_hash
            && job.owner_hmac == owner_hash
            && job
                .space
                .as_ref()
                .is_none_or(|raw| raw == &space.to_string()))
    }
}

#[rocket::post("/space/purge", format = "json", data = "<body>")]
pub async fn purge_space(
    runtime: &State<LifecycleRuntime>,
    auth: AuthHeaderGetter<InvocationInfo>,
    key: IdempotencyKey,
    body: Json<PurgeRequest>,
) -> Result<Custom<Json<PurgeResponse>>, ApiError> {
    if body.version != 1 {
        return Err(error(Status::BadRequest, "invalid_request"));
    }
    let space = request_space(&body.space_id)?;
    let canonical = space.to_string();
    let proof = verify_owner(
        &auth.0 .0.invocation,
        "tinycloud.space/delete",
        &format!("{canonical}/space"),
        space.did().as_str(),
        &key.0,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
    .map_err(proof_error)?;
    let _admission = runtime.fence.lifecycle_operation().await;
    let tx = runtime
        .management_transaction(&proof, "purge", "space", &canonical)
        .await?;
    if let Some(job) = space_purge_job::Entity::find()
        .filter(space_purge_job::Column::TombstoneHmac.is_in(runtime.space_hmacs(&space)?))
        .one(&tx)
        .await
        .map_err(unavailable)?
    {
        if !runtime.job_matches(&job, &space)? {
            return Err(unavailable(()));
        }
        runtime
            .bind_operation(&tx, &proof, "purge", &job.purge_id)
            .await?;
        let response = purge_response(&runtime.host_id, &job)?;
        tx.commit().await.map_err(unavailable)?;
        return Ok(Custom(Status::Ok, Json(response)));
    }
    let recent = space_purge_job::Entity::find()
        .filter(
            space_purge_job::Column::OwnerHmac.is_in(runtime.owner_hmacs(space.did().as_str())?),
        )
        .filter(
            space_purge_job::Column::AcceptedAt
                .gt(OffsetDateTime::now_utc() - time::Duration::minutes(1)),
        )
        .count(&tx)
        .await
        .map_err(unavailable)?;
    if recent >= 60 {
        return Err(error(Status::TooManyRequests, "rate_limited"));
    }
    let key_id = runtime.keys.active_key_id();
    let digest = runtime
        .keys
        .target_hmac(key_id, "space", &canonical)
        .map_err(unavailable)?;
    let candidate = runtime
        .keys
        .sign(
            key_id,
            "space",
            &digest,
            &proof.idempotency_key,
            "purging",
            OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(unavailable)?;
    let mut ledger_commit = LedgerCommitGuard {
        runtime,
        committed: false,
    };
    let record = runtime.publish_acceptance(&candidate).await?;
    let generation = runtime
        .fence
        .fence_hmac(&tx, "space", &record.key_id, &digest)
        .await
        .map_err(unavailable)?;
    let now = OffsetDateTime::now_utc();
    let job = space_purge_job::ActiveModel {
        purge_id: Set(record.operation_id.clone()),
        space: Set(Some(canonical)),
        tombstone_hmac: Set(digest),
        hmac_key_id: Set(record.key_id.clone()),
        owner_hmac: Set(runtime
            .keys
            .target_hmac(&record.key_id, "owner", space.did().as_str())
            .map_err(unavailable)?),
        accepted_at: Set(
            OffsetDateTime::from_unix_timestamp(record.timestamp).map_err(unavailable)?
        ),
        phase: Set("drain".into()),
        fence_generation: Set(generation),
        updated_at: Set(now),
        next_attempt_at: Set(now),
        attempt_count: Set(0),
        last_error_code: Set(None),
        lease_token: Set(None),
        lease_until: Set(None),
    }
    .insert(&tx)
    .await
    .map_err(unavailable)?;
    runtime
        .bind_operation(&tx, &proof, "purge", &job.purge_id)
        .await?;
    let response = purge_response(&runtime.host_id, &job)?;
    tx.commit().await.map_err(unavailable)?;
    ledger_commit.committed = true;
    runtime.work_requested.notify_one();
    Ok(Custom(Status::Accepted, Json(response)))
}

#[rocket::post("/space/purge/status", format = "json", data = "<body>")]
pub async fn purge_status(
    runtime: &State<LifecycleRuntime>,
    auth: AuthHeaderGetter<InvocationInfo>,
    key: IdempotencyKey,
    body: Json<StatusRequest>,
) -> Result<Json<PurgeResponse>, ApiError> {
    if body.version != 1 {
        return Err(error(Status::BadRequest, "invalid_request"));
    }
    let space = request_space(&body.space_id)?;
    let id = uuid::Uuid::parse_str(&body.purge_id)
        .map_err(|_| error(Status::BadRequest, "invalid_request"))?
        .to_string();
    let proof = verify_owner(
        &auth.0 .0.invocation,
        "tinycloud.space/delete",
        &format!("{space}/space"),
        space.did().as_str(),
        &key.0,
        OffsetDateTime::now_utc().unix_timestamp(),
    )
    .await
    .map_err(proof_error)?;
    let _admission = runtime.fence.lifecycle_operation().await;
    let tx = runtime
        .management_transaction(&proof, "status", "space", &space.to_string())
        .await?;
    runtime.bind_operation(&tx, &proof, "status", &id).await?;
    let job = space_purge_job::Entity::find_by_id(id)
        .one(&tx)
        .await
        .map_err(unavailable)?;
    let response = match job {
        Some(job) if runtime.job_matches(&job, &space)? => {
            Some(purge_response(&runtime.host_id, &job)?)
        }
        _ => None,
    };
    tx.commit().await.map_err(unavailable)?;
    response
        .map(Json)
        .ok_or_else(|| error(Status::NotFound, "not_found"))
}

pub mod leases;
pub mod reconcile;
pub mod resources;

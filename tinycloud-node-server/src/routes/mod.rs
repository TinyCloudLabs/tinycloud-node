use anyhow::Result;
use futures::io::AsyncWriteExt;
use percent_encoding::percent_decode_str;
use rocket::{data::ToByteUnit, http::Status, serde::json::Json, State};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path as StdPath, PathBuf},
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::identity::did_principal_matches;
use tinycloud_auth::resource::{Path, SpaceId};
use tokio::io::AsyncReadExt;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info_span, Instrument};

use crate::{
    auth_guards::{DataIn, DataOut, InvOut, KVResponse, ObjectHeaders},
    authorization::AuthHeaderGetter,
    config::Config,
    hooks::{HookRuntime, WriteEvent},
    quota::QuotaCache,
    routes::public::is_public_space,
    signed_urls::{
        load_signed_kv_ticket, mint_signed_kv_url, validate_signed_kv_hash_binding,
        validate_signed_kv_ticket, SignedKvUrlRequest, SignedKvUrlResponse, SignedUrlRuntime,
    },
    tracing::TracingSpan,
    BlockConfig, BlockStage, BlockStores, TinyCloud,
};
#[cfg(feature = "duckdb")]
use tinycloud_core::duckdb::{
    DuckDbCaveats, DuckDbError, DuckDbRequest, DuckDbResponse, DuckDbService,
};
use tinycloud_core::{
    encryption_network::EncryptionService,
    events::Invocation,
    hash::Hash,
    models::{
        abilities, actor, database_artifact, delegation, epoch, hook_delivery, hook_subscription,
        invocation, kv_delete, kv_write, revocation, space,
    },
    relationships::{epoch_order, event_order, invoked_abilities, parent_delegations},
    sea_orm::sea_query::OnConflict,
    sea_orm::ActiveValue::Set,
    sea_orm::{
        self, ActiveModelTrait, ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter,
        QueryOrder,
    },
    sql::{SqlCaveats, SqlError, SqlRequest, SqlService},
    storage::{HashBuffer, ImmutableReadStore, ImmutableStaging},
    types::{Metadata, Resource},
    util::{Capability, DelegationInfo, InvocationInfo},
    write_hooks::{db_table_path, hook_delivery_id, subscription_matches_event, TouchedTables},
    InvocationOutcome, TransactResult, TxError, TxStoreError,
};

pub mod admin;
pub mod attestation;
pub mod encryption;
pub mod hooks;
pub mod public;
pub mod util;
use util::LimitedReader;

#[derive(Serialize)]
pub struct NodeInfo {
    pub protocol: u32,
    pub version: String,
    pub features: Vec<&'static str>,
    #[serde(rename = "nodeId")]
    pub node_id: String,
    #[serde(rename = "inTEE")]
    pub in_tee: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_url: Option<String>,
}

fn build_info(
    tee: &State<Option<crate::tee::TeeContext>>,
    quota_cache: &State<QuotaCache>,
    encryption: &State<EncryptionService>,
) -> NodeInfo {
    #[allow(unused_mut)]
    let mut features = vec!["kv", "delegation", "sharing", "sql"];
    #[cfg(feature = "duckdb")]
    features.push("duckdb");
    features.extend(["hooks", "signed-urls", "encryption"]);
    #[cfg(feature = "dstack")]
    features.push("tee");
    NodeInfo {
        protocol: tinycloud_auth::protocol::PROTOCOL_VERSION,
        version: env!("CARGO_PKG_VERSION").to_string(),
        features,
        node_id: encryption.node_did().to_string(),
        in_tee: tee.inner().is_some(),
        quota_url: quota_cache.quota_url().map(|s| s.to_string()),
    }
}

#[get("/info")]
pub fn info(
    tee: &State<Option<crate::tee::TeeContext>>,
    quota_cache: &State<QuotaCache>,
    encryption: &State<EncryptionService>,
) -> Json<NodeInfo> {
    Json(build_info(tee, quota_cache, encryption))
}

#[get("/version")]
pub fn version(
    tee: &State<Option<crate::tee::TeeContext>>,
    quota_cache: &State<QuotaCache>,
    encryption: &State<EncryptionService>,
) -> Json<NodeInfo> {
    Json(build_info(tee, quota_cache, encryption))
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalFactRangeResponse {
    pub node_id: String,
    pub planes: Vec<LocalFactPlaneRange>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalFactPlaneRange {
    pub name: &'static str,
    pub empty: bool,
    pub tables: Vec<LocalFactTableRange>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalFactTableRange {
    pub name: &'static str,
    pub empty: bool,
    pub count: usize,
    pub start: Option<String>,
    pub end: Option<String>,
    pub keys: Vec<String>,
}

fn hash_to_cid(hash: Hash) -> String {
    hash.to_cid(0x55).to_string()
}

fn build_table_range(name: &'static str, mut keys: Vec<String>) -> LocalFactTableRange {
    keys.sort_unstable();
    keys.dedup();

    let count = keys.len();
    let empty = count == 0;
    let start = keys.first().cloned();
    let end = keys.last().cloned();

    LocalFactTableRange {
        name,
        empty,
        count,
        start,
        end,
        keys,
    }
}

fn build_plane_range(name: &'static str, tables: Vec<LocalFactTableRange>) -> LocalFactPlaneRange {
    let empty = tables.iter().all(|table| table.empty);

    LocalFactPlaneRange {
        name,
        empty,
        tables,
    }
}

fn encode_base64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    base64::decode(value).map_err(|err| err.to_string())
}

fn format_rfc3339(value: &OffsetDateTime) -> String {
    value
        .format(&Rfc3339)
        .expect("current timestamps should format as RFC3339")
}

fn parse_rfc3339(value: Option<String>) -> Result<Option<OffsetDateTime>, String> {
    match value {
        Some(value) => OffsetDateTime::parse(&value, &Rfc3339)
            .map(Some)
            .map_err(|err| err.to_string()),
        None => Ok(None),
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationSnapshot {
    pub node_id: String,
    pub spaces: Vec<ReconciliationSpace>,
    pub actors: Vec<ReconciliationActor>,
    pub delegations: Vec<ReconciliationDelegation>,
    pub revocations: Vec<ReconciliationRevocation>,
    pub abilities: Vec<ReconciliationAbility>,
    pub parent_delegations: Vec<ReconciliationParentDelegation>,
    pub invocations: Vec<ReconciliationInvocation>,
    pub invoked_abilities: Vec<ReconciliationInvokedAbility>,
    pub kv_writes: Vec<ReconciliationKvWrite>,
    pub kv_deletes: Vec<ReconciliationKvDelete>,
    pub database_artifacts: Vec<ReconciliationDatabaseArtifact>,
    pub epochs: Vec<ReconciliationEpoch>,
    pub epoch_orders: Vec<ReconciliationEpochOrder>,
    pub event_orders: Vec<ReconciliationEventOrder>,
    pub blocks: Vec<ReconciliationBlock>,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationSpace {
    pub id: tinycloud_core::types::SpaceIdWrap,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationActor {
    pub id: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationDelegation {
    pub id: String,
    pub delegator: String,
    pub delegatee: String,
    pub expiry: Option<String>,
    pub issued_at: Option<String>,
    pub not_before: Option<String>,
    pub facts: Option<tinycloud_core::types::Facts>,
    pub serialization: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationRevocation {
    pub id: String,
    pub revoker: String,
    pub revoked: String,
    pub serialization: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationAbility {
    pub resource: Resource,
    pub ability: tinycloud_core::types::Ability,
    pub delegation: String,
    pub caveats: tinycloud_core::types::Caveats,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationParentDelegation {
    pub parent: String,
    pub child: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationInvocation {
    pub id: String,
    pub invoker: String,
    pub issued_at: String,
    pub facts: Option<tinycloud_core::types::Facts>,
    pub serialization: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationInvokedAbility {
    pub invocation: String,
    pub resource: Resource,
    pub ability: tinycloud_core::types::Ability,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationKvWrite {
    pub space: tinycloud_core::types::SpaceIdWrap,
    pub key: tinycloud_core::types::Path,
    pub invocation: String,
    pub seq: i64,
    pub epoch: String,
    pub epoch_seq: i64,
    pub value: String,
    pub metadata: Metadata,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationKvDelete {
    pub invocation_id: String,
    pub space: tinycloud_core::types::SpaceIdWrap,
    pub key: tinycloud_core::types::Path,
    pub deleted_invocation_id: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationDatabaseArtifact {
    pub service: String,
    pub space: String,
    pub name: String,
    pub revision: i64,
    pub content_hash: String,
    pub payload: String,
    pub size_bytes: i64,
    pub backend: String,
    pub storage_mode: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationEpoch {
    pub seq: i64,
    pub id: String,
    pub space: tinycloud_core::types::SpaceIdWrap,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationEpochOrder {
    pub parent: String,
    pub child: String,
    pub space: tinycloud_core::types::SpaceIdWrap,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationEventOrder {
    pub seq: i64,
    pub epoch: String,
    pub epoch_seq: i64,
    pub event: String,
    pub space: tinycloud_core::types::SpaceIdWrap,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationBlock {
    pub path: String,
    pub bytes: String,
}

macro_rules! collect_table_range {
    ($db:expr, $entity:ty, $name:expr, $mapper:expr) => {{
        let keys = <$entity>::find()
            .all($db)
            .await?
            .into_iter()
            .map($mapper)
            .collect::<Vec<_>>();
        build_table_range($name, keys)
    }};
}

async fn local_fact_ranges(
    tinycloud: &State<TinyCloud>,
    encryption: &State<EncryptionService>,
) -> Result<LocalFactRangeResponse, DbErr> {
    let tx = tinycloud.readable().await?;

    let auth_fact_plane = build_plane_range(
        "authFacts",
        vec![
            collect_table_range!(&tx, space::Entity, "space", |row: space::Model| {
                format!("space:{}", row.id.0)
            }),
            collect_table_range!(&tx, actor::Entity, "actor", |row: actor::Model| {
                format!("actor:{}", row.id)
            }),
            collect_table_range!(
                &tx,
                delegation::Entity,
                "delegation",
                |row: delegation::Model| {
                    format!(
                        "delegation:{}|{}|{}",
                        hash_to_cid(row.id),
                        row.delegator,
                        row.delegatee
                    )
                }
            ),
            collect_table_range!(
                &tx,
                revocation::Entity,
                "revocation",
                |row: revocation::Model| {
                    format!(
                        "revocation:{}|{}|{}",
                        hash_to_cid(row.id),
                        row.revoker,
                        hash_to_cid(row.revoked)
                    )
                }
            ),
            collect_table_range!(
                &tx,
                abilities::Entity,
                "ability",
                |row: abilities::Model| {
                    format!(
                        "ability:{}|{}|{}",
                        row.resource,
                        row.ability,
                        hash_to_cid(row.delegation)
                    )
                }
            ),
            collect_table_range!(
                &tx,
                parent_delegations::Entity,
                "parentDelegation",
                |row: parent_delegations::Model| {
                    format!(
                        "parent-delegation:{}|{}",
                        hash_to_cid(row.parent),
                        hash_to_cid(row.child)
                    )
                }
            ),
        ],
    );

    let authored_fact_plane = build_plane_range(
        "authoredFacts",
        vec![
            collect_table_range!(
                &tx,
                invocation::Entity,
                "invocation",
                |row: invocation::Model| {
                    format!("invocation:{}|{}", hash_to_cid(row.id), row.invoker)
                }
            ),
            collect_table_range!(
                &tx,
                invoked_abilities::Entity,
                "invokedAbilities",
                |row: invoked_abilities::Model| {
                    format!(
                        "invoked-ability:{}|{}|{}",
                        hash_to_cid(row.invocation),
                        row.resource,
                        row.ability
                    )
                }
            ),
            collect_table_range!(&tx, kv_write::Entity, "kvWrite", |row: kv_write::Model| {
                format!(
                    "kv-write:{}|{}|{}|{}",
                    row.space.0,
                    row.key,
                    hash_to_cid(row.invocation),
                    hash_to_cid(row.value)
                )
            }),
            collect_table_range!(
                &tx,
                kv_delete::Entity,
                "kvDelete",
                |row: kv_delete::Model| {
                    format!(
                        "kv-delete:{}|{}|{}|{}",
                        row.space.0,
                        row.key,
                        hash_to_cid(row.invocation_id),
                        hash_to_cid(row.deleted_invocation_id)
                    )
                }
            ),
        ],
    );

    let blob_plane = build_plane_range(
        "blobs",
        vec![collect_table_range!(
            &tx,
            database_artifact::Entity,
            "databaseArtifact",
            |row: database_artifact::Model| {
                format!(
                    "database-artifact:{}|{}|{}|{:020}|{}",
                    row.service, row.space, row.name, row.revision, row.content_hash
                )
            }
        )],
    );

    let derived_view_input_plane = build_plane_range(
        "derivedViewInputs",
        vec![
            collect_table_range!(&tx, epoch::Entity, "epoch", |row: epoch::Model| {
                format!(
                    "epoch:{}|{:020}|{}",
                    row.space.0,
                    row.seq,
                    hash_to_cid(row.id)
                )
            }),
            collect_table_range!(
                &tx,
                epoch_order::Entity,
                "epochOrder",
                |row: epoch_order::Model| {
                    format!(
                        "epoch-order:{}|{}|{}",
                        row.space.0,
                        hash_to_cid(row.parent),
                        hash_to_cid(row.child)
                    )
                }
            ),
            collect_table_range!(
                &tx,
                event_order::Entity,
                "eventOrder",
                |row: event_order::Model| {
                    format!(
                        "event-order:{}|{}|{:020}|{:020}|{}",
                        row.space.0,
                        hash_to_cid(row.epoch),
                        row.epoch_seq,
                        row.seq,
                        hash_to_cid(row.event)
                    )
                }
            ),
        ],
    );

    Ok(LocalFactRangeResponse {
        node_id: encryption.node_did().to_string(),
        planes: vec![
            auth_fact_plane,
            authored_fact_plane,
            blob_plane,
            derived_view_input_plane,
        ],
    })
}

#[get("/reconciliation/ranges")]
pub async fn reconciliation_ranges(
    tinycloud: &State<TinyCloud>,
    encryption: &State<EncryptionService>,
) -> Result<Json<LocalFactRangeResponse>, (Status, String)> {
    local_fact_ranges(tinycloud, encryption)
        .await
        .map(Json)
        .map_err(|e| (Status::InternalServerError, e.to_string()))
}

fn has_host_capability(delegation: &DelegationInfo) -> bool {
    delegation.capabilities.iter().any(|cap| {
        cap.ability.to_string() == "tinycloud.space/host" && cap.resource.space().is_some()
    })
}

fn validate_host_reconciliation_access(
    delegation: &DelegationInfo,
) -> Result<(), (Status, String)> {
    if !has_host_capability(delegation) {
        return Err((Status::Unauthorized, "Host delegation required".to_string()));
    }

    let space = delegation
        .capabilities
        .iter()
        .find_map(|cap| cap.resource.space())
        .ok_or_else(|| {
            (
                Status::Unauthorized,
                "Host delegation must target a space".to_string(),
            )
        })?;

    if !did_principal_matches(space.did().as_str(), &delegation.delegator) {
        return Err((
            Status::Unauthorized,
            "Host delegation must be issued by the space owner".to_string(),
        ));
    }

    Ok(())
}

fn local_block_root(config: &Config) -> Result<PathBuf, String> {
    match &config.storage.blocks {
        BlockConfig::B(fs) => Ok(fs.path().to_path_buf()),
        BlockConfig::A(_) => Err(
            "host-host reconciliation currently requires local filesystem block storage"
                .to_string(),
        ),
    }
}

async fn collect_block_snapshots(root: &StdPath) -> Result<Vec<ReconciliationBlock>, String> {
    let mut snapshots = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(current) = stack.pop() {
        let mut dir = match tokio::fs::read_dir(&current).await {
            Ok(dir) => dir,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err.to_string()),
        };

        while let Some(entry) = dir.next_entry().await.map_err(|err| err.to_string())? {
            let ty = entry.file_type().await.map_err(|err| err.to_string())?;
            let path = entry.path();
            if ty.is_dir() {
                stack.push(path);
                continue;
            }
            if !ty.is_file() {
                continue;
            }

            let rel = path
                .strip_prefix(root)
                .map_err(|err| err.to_string())?
                .to_string_lossy()
                .into_owned();
            let bytes = tokio::fs::read(&path)
                .await
                .map_err(|err| err.to_string())?;
            snapshots.push(ReconciliationBlock {
                path: rel,
                bytes: encode_base64(&bytes),
            });
        }
    }

    snapshots.sort_by(|a, b| a.path.cmp(&b.path));
    snapshots.dedup_by(|a, b| a.path == b.path);
    Ok(snapshots)
}

async fn write_block_snapshots(
    root: &StdPath,
    blocks: &[ReconciliationBlock],
) -> Result<(), String> {
    for block in blocks {
        let path = root.join(&block.path);
        let bytes = decode_base64(&block.bytes)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|err| err.to_string())?;
        }
        tokio::fs::write(&path, bytes)
            .await
            .map_err(|err| err.to_string())?;
    }
    Ok(())
}

async fn insert_many_ignore<E, C, M>(
    db: &C,
    rows: Vec<M>,
    conflict: OnConflict,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
    E: EntityTrait,
    E::ActiveModel: sea_orm::ActiveModelTrait<Entity = E>,
    M: sea_orm::IntoActiveModel<E::ActiveModel>,
{
    let _ = conflict;
    let rows = rows
        .into_iter()
        .map(sea_orm::IntoActiveModel::into_active_model)
        .collect::<Vec<_>>();

    if rows.is_empty() {
        return Ok(());
    }

    let mut conflict = OnConflict::new();
    conflict.do_nothing();

    match E::insert_many(rows).on_conflict(conflict).exec(db).await {
        Err(DbErr::RecordNotInserted) => Ok(()),
        result => {
            result?;
            Ok(())
        }
    }
}

// Deterministic SQL reducer policy:
// prefer the higher revision, then break ties by content hash so every peer
// converges on the same winning materialized view without consulting clocks.
fn database_artifact_prefers_incoming(
    existing: &database_artifact::Model,
    incoming: &database_artifact::Model,
) -> bool {
    incoming.revision > existing.revision
        || (incoming.revision == existing.revision && incoming.content_hash > existing.content_hash)
}

async fn upsert_database_artifact<C>(
    db: &C,
    incoming: database_artifact::Model,
) -> Result<(), DbErr>
where
    C: ConnectionTrait,
{
    let key = (
        incoming.service.clone(),
        incoming.space.clone(),
        incoming.name.clone(),
    );
    let existing = database_artifact::Entity::find_by_id(key).one(db).await?;

    if let Some(existing) = existing.as_ref() {
        if !database_artifact_prefers_incoming(existing, &incoming) {
            return Ok(());
        }
    }

    let active = database_artifact::ActiveModel {
        service: Set(incoming.service),
        space: Set(incoming.space),
        name: Set(incoming.name),
        revision: Set(incoming.revision),
        content_hash: Set(incoming.content_hash),
        payload: Set(incoming.payload),
        size_bytes: Set(incoming.size_bytes),
        backend: Set(incoming.backend),
        storage_mode: Set(incoming.storage_mode),
        created_at: Set(incoming.created_at),
        updated_at: Set(incoming.updated_at),
    };

    match existing {
        Some(_) => {
            active.update(db).await?;
        }
        None => {
            active.insert(db).await?;
        }
    }

    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconciliationApplyResponse {
    pub node_id: String,
    pub spaces: usize,
    pub actors: usize,
    pub delegations: usize,
    pub revocations: usize,
    pub abilities: usize,
    pub parent_delegations: usize,
    pub invocations: usize,
    pub invoked_abilities: usize,
    pub kv_writes: usize,
    pub kv_deletes: usize,
    pub database_artifacts: usize,
    pub epochs: usize,
    pub epoch_orders: usize,
    pub event_orders: usize,
    pub blocks: usize,
}

async fn build_reconciliation_snapshot(
    tinycloud: &State<TinyCloud>,
    config: &State<Config>,
    encryption: &State<EncryptionService>,
) -> Result<ReconciliationSnapshot, String> {
    let tx = tinycloud.readable().await.map_err(|err| err.to_string())?;

    let spaces = space::Entity::find()
        .order_by_asc(space::Column::Id)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationSpace { id: row.id })
        .collect::<Vec<_>>();

    let actors = actor::Entity::find()
        .order_by_asc(actor::Column::Id)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationActor { id: row.id })
        .collect::<Vec<_>>();

    let delegations = delegation::Entity::find()
        .order_by_asc(delegation::Column::Id)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationDelegation {
            id: hash_to_cid(row.id),
            delegator: row.delegator,
            delegatee: row.delegatee,
            expiry: row.expiry.as_ref().map(format_rfc3339),
            issued_at: row.issued_at.as_ref().map(format_rfc3339),
            not_before: row.not_before.as_ref().map(format_rfc3339),
            facts: row.facts,
            serialization: encode_base64(&row.serialization),
        })
        .collect::<Vec<_>>();

    let revocations = revocation::Entity::find()
        .order_by_asc(revocation::Column::Id)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationRevocation {
            id: hash_to_cid(row.id),
            revoker: row.revoker,
            revoked: hash_to_cid(row.revoked),
            serialization: encode_base64(&row.serialization),
        })
        .collect::<Vec<_>>();

    let abilities = abilities::Entity::find()
        .order_by_asc(abilities::Column::Delegation)
        .order_by_asc(abilities::Column::Resource)
        .order_by_asc(abilities::Column::Ability)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationAbility {
            resource: row.resource,
            ability: row.ability,
            delegation: hash_to_cid(row.delegation),
            caveats: row.caveats,
        })
        .collect::<Vec<_>>();

    let parent_delegations = parent_delegations::Entity::find()
        .order_by_asc(parent_delegations::Column::Parent)
        .order_by_asc(parent_delegations::Column::Child)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationParentDelegation {
            parent: hash_to_cid(row.parent),
            child: hash_to_cid(row.child),
        })
        .collect::<Vec<_>>();

    let invocations = invocation::Entity::find()
        .order_by_asc(invocation::Column::Id)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationInvocation {
            id: hash_to_cid(row.id),
            invoker: row.invoker,
            issued_at: format_rfc3339(&row.issued_at),
            facts: row.facts,
            serialization: encode_base64(&row.serialization),
        })
        .collect::<Vec<_>>();

    let invoked_abilities = invoked_abilities::Entity::find()
        .order_by_asc(invoked_abilities::Column::Invocation)
        .order_by_asc(invoked_abilities::Column::Resource)
        .order_by_asc(invoked_abilities::Column::Ability)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationInvokedAbility {
            invocation: hash_to_cid(row.invocation),
            resource: row.resource,
            ability: row.ability,
        })
        .collect::<Vec<_>>();

    let kv_writes = kv_write::Entity::find()
        .order_by_asc(kv_write::Column::Space)
        .order_by_asc(kv_write::Column::Key)
        .order_by_asc(kv_write::Column::Invocation)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationKvWrite {
            space: row.space,
            key: row.key,
            invocation: hash_to_cid(row.invocation),
            seq: row.seq,
            epoch: hash_to_cid(row.epoch),
            epoch_seq: row.epoch_seq,
            value: hash_to_cid(row.value),
            metadata: row.metadata,
        })
        .collect::<Vec<_>>();

    let kv_deletes = kv_delete::Entity::find()
        .order_by_asc(kv_delete::Column::InvocationId)
        .order_by_asc(kv_delete::Column::Space)
        .order_by_asc(kv_delete::Column::Key)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationKvDelete {
            invocation_id: hash_to_cid(row.invocation_id),
            space: row.space,
            key: row.key,
            deleted_invocation_id: hash_to_cid(row.deleted_invocation_id),
        })
        .collect::<Vec<_>>();

    let database_artifacts = database_artifact::Entity::find()
        .order_by_asc(database_artifact::Column::Service)
        .order_by_asc(database_artifact::Column::Space)
        .order_by_asc(database_artifact::Column::Name)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationDatabaseArtifact {
            service: row.service,
            space: row.space,
            name: row.name,
            revision: row.revision,
            content_hash: row.content_hash,
            payload: encode_base64(&row.payload),
            size_bytes: row.size_bytes,
            backend: row.backend,
            storage_mode: row.storage_mode,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
        .collect::<Vec<_>>();

    let epochs = epoch::Entity::find()
        .order_by_asc(epoch::Column::Space)
        .order_by_asc(epoch::Column::Seq)
        .order_by_asc(epoch::Column::Id)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationEpoch {
            seq: row.seq,
            id: hash_to_cid(row.id),
            space: row.space,
        })
        .collect::<Vec<_>>();

    let epoch_orders = epoch_order::Entity::find()
        .order_by_asc(epoch_order::Column::Space)
        .order_by_asc(epoch_order::Column::Parent)
        .order_by_asc(epoch_order::Column::Child)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationEpochOrder {
            parent: hash_to_cid(row.parent),
            child: hash_to_cid(row.child),
            space: row.space,
        })
        .collect::<Vec<_>>();

    let event_orders = event_order::Entity::find()
        .order_by_asc(event_order::Column::Space)
        .order_by_asc(event_order::Column::Epoch)
        .order_by_asc(event_order::Column::EpochSeq)
        .order_by_asc(event_order::Column::Seq)
        .all(&tx)
        .await
        .map_err(|err| err.to_string())?
        .into_iter()
        .map(|row| ReconciliationEventOrder {
            seq: row.seq,
            epoch: hash_to_cid(row.epoch),
            epoch_seq: row.epoch_seq,
            event: hash_to_cid(row.event),
            space: row.space,
        })
        .collect::<Vec<_>>();

    let blocks_root = local_block_root(config)?;
    let blocks = collect_block_snapshots(&blocks_root).await?;

    Ok(ReconciliationSnapshot {
        node_id: encryption.node_did().to_string(),
        spaces,
        actors,
        delegations,
        revocations,
        abilities,
        parent_delegations,
        invocations,
        invoked_abilities,
        kv_writes,
        kv_deletes,
        database_artifacts,
        epochs,
        epoch_orders,
        event_orders,
        blocks,
    })
}

async fn apply_reconciliation_snapshot(
    tinycloud: &State<TinyCloud>,
    config: &State<Config>,
    snapshot: ReconciliationSnapshot,
) -> Result<ReconciliationApplyResponse, String> {
    let blocks_root = local_block_root(config)?;
    write_block_snapshots(&blocks_root, &snapshot.blocks).await?;

    let tx = tinycloud.writable().await.map_err(|err| err.to_string())?;

    insert_many_ignore::<space::Entity, _, _>(
        &tx,
        snapshot
            .spaces
            .iter()
            .cloned()
            .map(|row| space::Model { id: row.id })
            .collect::<Vec<_>>(),
        OnConflict::column(space::Column::Id)
            .do_nothing()
            .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<actor::Entity, _, _>(
        &tx,
        snapshot
            .actors
            .iter()
            .cloned()
            .map(|row| actor::Model { id: row.id })
            .collect::<Vec<_>>(),
        OnConflict::column(actor::Column::Id)
            .do_nothing()
            .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<delegation::Entity, _, _>(
        &tx,
        snapshot
            .delegations
            .iter()
            .cloned()
            .map(|row| {
                let expiry = parse_rfc3339(row.expiry).map_err(|err| err.to_string())?;
                let issued_at = parse_rfc3339(row.issued_at).map_err(|err| err.to_string())?;
                let not_before = parse_rfc3339(row.not_before).map_err(|err| err.to_string())?;
                Ok::<_, String>(delegation::Model {
                    id: row
                        .id
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    delegator: row.delegator,
                    delegatee: row.delegatee,
                    expiry,
                    issued_at,
                    not_before,
                    facts: row.facts,
                    serialization: decode_base64(&row.serialization)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::column(delegation::Column::Id)
            .do_nothing()
            .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<revocation::Entity, _, _>(
        &tx,
        snapshot
            .revocations
            .iter()
            .cloned()
            .map(|row| {
                Ok::<_, String>(revocation::Model {
                    id: row
                        .id
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    revoker: row.revoker,
                    revoked: row
                        .revoked
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    serialization: decode_base64(&row.serialization)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::column(revocation::Column::Id)
            .do_nothing()
            .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<abilities::Entity, _, _>(
        &tx,
        snapshot
            .abilities
            .iter()
            .cloned()
            .map(|row| abilities::Model {
                resource: row.resource,
                ability: row.ability,
                delegation: row
                    .delegation
                    .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                    .map_err(|err| err.to_string())
                    .unwrap()
                    .into(),
                caveats: row.caveats,
            })
            .collect::<Vec<_>>(),
        OnConflict::columns([
            abilities::Column::Resource,
            abilities::Column::Ability,
            abilities::Column::Delegation,
        ])
        .do_nothing()
        .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<parent_delegations::Entity, _, _>(
        &tx,
        snapshot
            .parent_delegations
            .iter()
            .cloned()
            .map(|row| {
                Ok::<_, String>(parent_delegations::Model {
                    parent: row
                        .parent
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    child: row
                        .child
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::columns([
            parent_delegations::Column::Parent,
            parent_delegations::Column::Child,
        ])
        .do_nothing()
        .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<invocation::Entity, _, _>(
        &tx,
        snapshot
            .invocations
            .iter()
            .cloned()
            .map(|row| {
                Ok::<_, String>(invocation::Model {
                    id: row
                        .id
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    invoker: row.invoker,
                    issued_at: OffsetDateTime::parse(&row.issued_at, &Rfc3339)
                        .map_err(|err| err.to_string())?,
                    facts: row.facts,
                    serialization: decode_base64(&row.serialization)?,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::column(invocation::Column::Id)
            .do_nothing()
            .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<invoked_abilities::Entity, _, _>(
        &tx,
        snapshot
            .invoked_abilities
            .iter()
            .cloned()
            .map(|row| {
                Ok::<_, String>(invoked_abilities::Model {
                    invocation: row
                        .invocation
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    resource: row.resource,
                    ability: row.ability,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::columns([
            invoked_abilities::Column::Invocation,
            invoked_abilities::Column::Resource,
            invoked_abilities::Column::Ability,
        ])
        .do_nothing()
        .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<epoch::Entity, _, _>(
        &tx,
        snapshot
            .epochs
            .iter()
            .cloned()
            .map(|row| {
                Ok::<_, String>(epoch::Model {
                    seq: row.seq,
                    id: row
                        .id
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    space: row.space,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::columns([epoch::Column::Id, epoch::Column::Space, epoch::Column::Seq])
            .do_nothing()
            .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<epoch_order::Entity, _, _>(
        &tx,
        snapshot
            .epoch_orders
            .iter()
            .cloned()
            .map(|row| {
                Ok::<_, String>(epoch_order::Model {
                    parent: row
                        .parent
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    child: row
                        .child
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    space: row.space,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::columns([
            epoch_order::Column::Parent,
            epoch_order::Column::Child,
            epoch_order::Column::Space,
        ])
        .do_nothing()
        .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<event_order::Entity, _, _>(
        &tx,
        snapshot
            .event_orders
            .iter()
            .cloned()
            .map(|row| {
                Ok::<_, String>(event_order::Model {
                    seq: row.seq,
                    epoch: row
                        .epoch
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    epoch_seq: row.epoch_seq,
                    event: row
                        .event
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    space: row.space,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::columns([
            event_order::Column::Epoch,
            event_order::Column::EpochSeq,
            event_order::Column::Space,
        ])
        .do_nothing()
        .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<kv_write::Entity, _, _>(
        &tx,
        snapshot
            .kv_writes
            .iter()
            .cloned()
            .map(|row| {
                Ok::<_, String>(kv_write::Model {
                    space: row.space,
                    key: row.key,
                    invocation: row
                        .invocation
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    seq: row.seq,
                    epoch: row
                        .epoch
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    epoch_seq: row.epoch_seq,
                    value: row
                        .value
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    metadata: row.metadata,
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::columns([
            kv_write::Column::Space,
            kv_write::Column::Key,
            kv_write::Column::Invocation,
        ])
        .do_nothing()
        .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    insert_many_ignore::<kv_delete::Entity, _, _>(
        &tx,
        snapshot
            .kv_deletes
            .iter()
            .cloned()
            .map(|row| {
                Ok::<_, String>(kv_delete::Model {
                    invocation_id: row
                        .invocation_id
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                    space: row.space,
                    key: row.key,
                    deleted_invocation_id: row
                        .deleted_invocation_id
                        .parse::<tinycloud_auth::ipld_core::cid::Cid>()
                        .map_err(|err| err.to_string())?
                        .into(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?,
        OnConflict::columns([kv_delete::Column::InvocationId, kv_delete::Column::Space])
            .do_nothing()
            .to_owned(),
    )
    .await
    .map_err(|err| err.to_string())?;

    for row in snapshot.database_artifacts.iter().cloned() {
        upsert_database_artifact(
            &tx,
            database_artifact::Model {
                service: row.service,
                space: row.space,
                name: row.name,
                revision: row.revision,
                content_hash: row.content_hash,
                payload: decode_base64(&row.payload)?,
                size_bytes: row.size_bytes,
                backend: row.backend,
                storage_mode: row.storage_mode,
                created_at: row.created_at,
                updated_at: row.updated_at,
            },
        )
        .await
        .map_err(|err| err.to_string())?;
    }

    tx.commit().await.map_err(|err| err.to_string())?;

    Ok(ReconciliationApplyResponse {
        node_id: snapshot.node_id,
        spaces: snapshot.spaces.len(),
        actors: snapshot.actors.len(),
        delegations: snapshot.delegations.len(),
        revocations: snapshot.revocations.len(),
        abilities: snapshot.abilities.len(),
        parent_delegations: snapshot.parent_delegations.len(),
        invocations: snapshot.invocations.len(),
        invoked_abilities: snapshot.invoked_abilities.len(),
        kv_writes: snapshot.kv_writes.len(),
        kv_deletes: snapshot.kv_deletes.len(),
        database_artifacts: snapshot.database_artifacts.len(),
        epochs: snapshot.epochs.len(),
        epoch_orders: snapshot.epoch_orders.len(),
        event_orders: snapshot.event_orders.len(),
        blocks: snapshot.blocks.len(),
    })
}

#[get("/reconciliation/snapshot")]
pub async fn reconciliation_snapshot(
    d: AuthHeaderGetter<DelegationInfo>,
    tinycloud: &State<TinyCloud>,
    config: &State<Config>,
    encryption: &State<EncryptionService>,
) -> Result<Json<ReconciliationSnapshot>, (Status, String)> {
    let delegation = d.0 .0;
    validate_host_reconciliation_access(&delegation)?;

    build_reconciliation_snapshot(tinycloud, config, encryption)
        .await
        .map(Json)
        .map_err(|err| (Status::InternalServerError, err))
}

#[post("/reconciliation/snapshot", data = "<snapshot>")]
pub async fn reconciliation_snapshot_apply(
    d: AuthHeaderGetter<DelegationInfo>,
    snapshot: Json<ReconciliationSnapshot>,
    tinycloud: &State<TinyCloud>,
    config: &State<Config>,
) -> Result<Json<ReconciliationApplyResponse>, (Status, String)> {
    let delegation = d.0 .0;
    validate_host_reconciliation_access(&delegation)?;

    apply_reconciliation_snapshot(tinycloud, config, snapshot.into_inner())
        .await
        .map(Json)
        .map_err(|err| (Status::InternalServerError, err))
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

#[post("/signed/kv", format = "json", data = "<request>")]
pub async fn create_signed_kv_url(
    invocation: AuthHeaderGetter<InvocationInfo>,
    request: Json<SignedKvUrlRequest>,
    runtime: &State<SignedUrlRuntime>,
    tinycloud: &State<TinyCloud>,
) -> Result<Json<SignedKvUrlResponse>, (Status, String)> {
    let invocation_info = invocation.0 .0.clone();
    verify_auth(invocation.0, tinycloud).await?;
    let response = mint_signed_kv_url(
        &invocation_info,
        request.into_inner(),
        runtime.inner(),
        tinycloud.inner(),
    )
    .await?;
    Ok(Json(response))
}

#[get("/signed/kv/<ticket_id>")]
pub async fn signed_kv_get(
    ticket_id: &str,
    tinycloud: &State<TinyCloud>,
) -> Result<
    KVResponse<tinycloud_core::storage::Content<<BlockStores as ImmutableReadStore>::Readable>>,
    (Status, String),
> {
    let ticket = load_signed_kv_ticket(tinycloud.inner(), ticket_id).await?;
    let (space_id, key) = validate_signed_kv_ticket(&ticket)?;

    match tinycloud
        .kv_get(&space_id, &key)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?
    {
        Some((md, hash, content)) => {
            validate_signed_kv_hash_binding(&ticket, &hash)?;
            Ok(KVResponse::new(md, hash, content))
        }
        None => Err((Status::NotFound, "Key not found".to_string())),
    }
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
#[cfg(feature = "duckdb")]
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
    hook_runtime: &State<HookRuntime>,
) -> Result<DataOut<<BlockStores as ImmutableReadStore>::Readable>, (Status, String)> {
    invoke_impl(
        i,
        req_span,
        headers,
        data,
        staging,
        tinycloud,
        config,
        quota_cache,
        sql_service,
        duckdb_service,
        hook_runtime,
    )
    .await
}

#[post("/invoke", data = "<data>")]
#[cfg(not(feature = "duckdb"))]
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
    hook_runtime: &State<HookRuntime>,
) -> Result<DataOut<<BlockStores as ImmutableReadStore>::Readable>, (Status, String)> {
    invoke_impl(
        i,
        req_span,
        headers,
        data,
        staging,
        tinycloud,
        config,
        quota_cache,
        sql_service,
        (),
        hook_runtime,
    )
    .await
}

#[cfg(feature = "duckdb")]
type DuckDbInvokeState<'a> = &'a State<DuckDbService>;
#[cfg(not(feature = "duckdb"))]
type DuckDbInvokeState<'a> = ();

type KvInputMap = HashMap<
    (SpaceId, Path),
    (
        Metadata,
        HashBuffer<<BlockStage as ImmutableStaging>::Writable>,
    ),
>;
type ExpectedKvBatchInputs = BTreeMap<String, (SpaceId, Path)>;

fn metadata_header<'a>(metadata: &'a Metadata, name: &str) -> Option<&'a str> {
    metadata
        .0
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn is_multipart(headers: &ObjectHeaders) -> bool {
    metadata_header(&headers.0, "content-type")
        .map(|value| {
            value
                .to_ascii_lowercase()
                .starts_with("multipart/form-data")
        })
        .unwrap_or(false)
}

fn kv_put_capabilities(invocation: &InvocationInfo) -> Vec<(SpaceId, Path)> {
    invocation
        .capabilities
        .iter()
        .filter_map(|c| match (&c.resource, c.ability.as_ref().as_ref()) {
            (Resource::TinyCloud(r), "tinycloud.kv/put")
                if r.service().as_str() == "kv" && r.path().is_some() =>
            {
                Some((r.space().clone(), r.path()?.clone()))
            }
            _ => None,
        })
        .collect()
}

fn is_tight_kv_put_capability(capability: &Capability) -> bool {
    matches!(
        (&capability.resource, capability.ability.as_ref().as_ref()),
        (Resource::TinyCloud(resource), "tinycloud.kv/put")
            if resource.service().as_str() == "kv" && resource.path().is_some()
    )
}

fn validate_kv_batch_capabilities(
    invocation: &InvocationInfo,
    put_caps: &[(SpaceId, Path)],
) -> Result<ExpectedKvBatchInputs, (Status, String)> {
    validate_kv_batch_capability_set(&invocation.capabilities, put_caps)
}

fn validate_kv_batch_capability_set(
    capabilities: &[Capability],
    put_caps: &[(SpaceId, Path)],
) -> Result<ExpectedKvBatchInputs, (Status, String)> {
    if put_caps.is_empty() {
        return Ok(BTreeMap::new());
    }

    if !capabilities.iter().all(is_tight_kv_put_capability) {
        return Err((
            Status::BadRequest,
            "KV batch put only accepts tinycloud.kv/put capabilities with paths".to_string(),
        ));
    }

    let (space, _) = put_caps.first().ok_or_else(|| {
        (
            Status::BadRequest,
            "No KV put capabilities found".to_string(),
        )
    })?;
    if put_caps.iter().any(|(candidate, _)| candidate != space) {
        return Err((
            Status::BadRequest,
            "KV batch put must target one space".to_string(),
        ));
    }

    let mut expected = BTreeMap::<String, (SpaceId, Path)>::new();
    for (space, path) in put_caps {
        if expected
            .insert(path.to_string(), (space.clone(), path.clone()))
            .is_some()
        {
            return Err((
                Status::BadRequest,
                format!("Duplicate KV batch put capability for path {path}"),
            ));
        }
    }

    Ok(expected)
}

fn decode_multipart_path_field_name(field_name: &str) -> Result<String, (Status, String)> {
    percent_decode_str(field_name)
        .decode_utf8()
        .map(|decoded| decoded.into_owned())
        .map_err(|e| {
            (
                Status::BadRequest,
                format!("Multipart KV part name is not valid percent-encoded UTF-8: {e}"),
            )
        })
}

fn field_metadata(field: &multer::Field<'_>) -> Metadata {
    let mut metadata = BTreeMap::new();
    for (name, value) in field.headers().iter() {
        let key = name.as_str();
        if key.eq_ignore_ascii_case("content-disposition")
            || key.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        if let Ok(value) = value.to_str() {
            metadata.insert(key.to_string(), value.to_string());
        }
    }
    if let Some(content_type) = field.content_type() {
        metadata
            .entry("content-type".to_string())
            .or_insert_with(|| content_type.to_string());
    }
    Metadata(metadata)
}

async fn staged_batch_remaining(
    space: &SpaceId,
    tinycloud: &State<TinyCloud>,
    config: &State<Config>,
    quota_cache: &State<QuotaCache>,
) -> Result<Option<(u64, u64, u64)>, (Status, String)> {
    let effective_limit = if is_public_space(space) {
        Some(config.public_spaces.storage_limit)
    } else {
        quota_cache.get_limit(space).await
    };

    let Some(limit) = effective_limit else {
        return Ok(None);
    };

    let limit_bytes = limit.as_u64();
    let current_size = tinycloud
        .store_size(space)
        .await
        .map_err(|e| (Status::InternalServerError, e.to_string()))?
        .ok_or_else(|| (Status::NotFound, "space not found".to_string()))?;
    let remaining = match limit_bytes.checked_sub(current_size) {
        None | Some(0) => {
            return Err((
                Status::new(402),
                format!(
                    "Storage quota exceeded. Used: {} bytes, Limit: {} bytes",
                    current_size, limit_bytes
                ),
            ))
        }
        Some(remaining) => remaining,
    };

    Ok(Some((remaining, current_size, limit_bytes)))
}

async fn copy_multipart_field_to_stage(
    mut field: multer::Field<'_>,
    stage: &mut HashBuffer<<BlockStage as ImmutableStaging>::Writable>,
    remaining: &mut Option<(u64, u64, u64)>,
) -> Result<(), (Status, String)> {
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| (Status::BadRequest, e.to_string()))?
    {
        if let Some((remaining_bytes, current_size, limit_bytes)) = remaining.as_mut() {
            let chunk_len = u64::try_from(chunk.len())
                .map_err(|e| (Status::InternalServerError, e.to_string()))?;
            if chunk_len > *remaining_bytes {
                return Err((
                    Status::PayloadTooLarge,
                    format!(
                        "Write exceeds remaining storage. Used: {} bytes, Limit: {} bytes",
                        current_size, limit_bytes
                    ),
                ));
            }
            *remaining_bytes -= chunk_len;
        }

        stage
            .write_all(&chunk)
            .await
            .map_err(|e| (Status::InternalServerError, e.to_string()))?;
    }

    Ok(())
}

async fn build_batch_kv_inputs(
    data: rocket::Data<'_>,
    headers: &ObjectHeaders,
    expected: &ExpectedKvBatchInputs,
    staging: &State<BlockStage>,
    tinycloud: &State<TinyCloud>,
    config: &State<Config>,
    quota_cache: &State<QuotaCache>,
) -> Result<KvInputMap, (Status, String)> {
    if expected.is_empty() {
        return Ok(HashMap::new());
    }

    let content_type = metadata_header(&headers.0, "content-type").ok_or_else(|| {
        (
            Status::BadRequest,
            "Missing multipart content-type".to_string(),
        )
    })?;
    let boundary =
        multer::parse_boundary(content_type).map_err(|e| (Status::BadRequest, e.to_string()))?;
    let mut multipart = multer::Multipart::with_reader(data.open(1u8.gigabytes()), boundary);
    let mut inputs = HashMap::new();
    let (space, _) = expected
        .values()
        .next()
        .expect("non-empty KV batch inputs have a target space");
    let mut remaining = staged_batch_remaining(space, tinycloud, config, quota_cache).await?;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| (Status::BadRequest, e.to_string()))?
    {
        let encoded_path = field
            .name()
            .ok_or_else(|| {
                (
                    Status::BadRequest,
                    "Multipart KV part is missing a field name".to_string(),
                )
            })?
            .to_string();
        let path = decode_multipart_path_field_name(&encoded_path)?;
        let Some((space, typed_path)) = expected.get(&path) else {
            return Err((
                Status::BadRequest,
                format!("Multipart KV part {path} is not authorized by the invocation"),
            ));
        };
        if inputs.contains_key(&(space.clone(), typed_path.clone())) {
            return Err((
                Status::BadRequest,
                format!("Duplicate multipart KV part for path {path}"),
            ));
        }

        let metadata = field_metadata(&field);
        let mut stage = staging
            .stage(space)
            .await
            .map_err(|e| (Status::InternalServerError, e.to_string()))?;
        copy_multipart_field_to_stage(field, &mut stage, &mut remaining).await?;
        inputs.insert((space.clone(), typed_path.clone()), (metadata, stage));
    }

    if inputs.len() != expected.len() {
        let missing = expected
            .keys()
            .filter(|path| {
                !inputs
                    .keys()
                    .any(|(_, input_path)| input_path.as_str() == path.as_str())
            })
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        return Err((
            Status::BadRequest,
            format!("Missing multipart KV parts for signed paths: {missing}"),
        ));
    }

    Ok(inputs)
}

#[allow(clippy::too_many_arguments)]
async fn invoke_impl(
    i: AuthHeaderGetter<InvocationInfo>,
    req_span: TracingSpan,
    headers: ObjectHeaders,
    data: DataIn<'_>,
    staging: &State<BlockStage>,
    tinycloud: &State<TinyCloud>,
    config: &State<Config>,
    quota_cache: &State<QuotaCache>,
    sql_service: &State<SqlService>,
    #[cfg_attr(not(feature = "duckdb"), allow(unused_variables))] duckdb_service: DuckDbInvokeState<
        '_,
    >,
    hook_runtime: &State<HookRuntime>,
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
            let result = handle_sql_invoke(
                i,
                data,
                tinycloud,
                sql_service,
                hook_runtime,
                &sql_caps,
            )
            .await;
            timer.observe_duration();
            return result;
        }

        #[cfg(feature = "duckdb")]
        {
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
                    hook_runtime,
                    &duckdb_caps,
                    arrow_format,
                )
                .await;
                timer.observe_duration();
                return result;
            }
        }

        #[cfg(not(feature = "duckdb"))]
        if i.0 .0.capabilities.iter().any(|c| {
            matches!(
                (&c.resource, c.ability.as_ref().as_ref()),
                (Resource::TinyCloud(r), ability)
                    if r.service().as_str() == "duckdb"
                        && ability.starts_with("tinycloud.duckdb/")
            )
        }) {
            timer.observe_duration();
            return Err((
                Status::NotImplemented,
                "DuckDB support is not enabled on this node".to_string(),
            ));
        }

        let put_caps = kv_put_capabilities(&i.0 .0);
        let is_multipart_request = is_multipart(&headers);
        let expected_batch_inputs = if is_multipart_request && !put_caps.is_empty() {
            Some(validate_kv_batch_capabilities(&i.0 .0, &put_caps)?)
        } else {
            None
        };
        let batch_written_paths = expected_batch_inputs.as_ref().map(|expected| {
            expected
                .values()
                .map(|(_, path)| path.clone())
                .collect::<Vec<_>>()
        });

        let inputs = match (data, put_caps.as_slice(), is_multipart_request) {
            (DataIn::None | DataIn::One(_), [], _) => HashMap::new(),
            (DataIn::One(d), [(space, path)], false) => {
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
            (DataIn::One(d), [_, ..], true) => {
                build_batch_kv_inputs(
                    d,
                    &headers,
                    expected_batch_inputs
                        .as_ref()
                        .expect("multipart KV batch inputs were validated"),
                    staging,
                    tinycloud,
                    config,
                    quota_cache,
                )
                .await?
            }
            (DataIn::One(_), [_, _, ..], false) => {
                return Err((Status::BadRequest, "KV batch put requires multipart/form-data".to_string()));
            }
            _ => {
                return Err((Status::BadRequest, "Invalid inputs".to_string()));
            }
        };
        let invocation_info = i.0 .0.clone();
        let res = match tinycloud.invoke::<BlockStage>(i.0, inputs).await {
            Ok((tx_result, mut outcomes)) => {
                emit_kv_hook_events(hook_runtime, tinycloud, &invocation_info, &tx_result).await;
                if let Some(written_paths) = batch_written_paths {
                    if outcomes.len() != written_paths.len()
                        || !outcomes.iter().all(|outcome| {
                            matches!(outcome, InvocationOutcome::KvWrite)
                        })
                    {
                        Err((
                            Status::InternalServerError,
                            "KV batch put committed unexpected invocation outcomes".to_string(),
                        ))
                    } else {
                        Ok(DataOut::One(InvOut(InvocationOutcome::KvBatchWrite(
                            written_paths,
                        ))))
                    }
                } else {
                    Ok(match (outcomes.pop(), outcomes.pop(), outcomes.drain(..)) {
                        (None, None, _) => DataOut::None,
                        (Some(o), None, _) => DataOut::One(InvOut(o)),
                        (Some(o), Some(next), rest) => {
                            let mut v = vec![InvOut(o), InvOut(next)];
                            v.extend(rest.map(InvOut));
                            DataOut::Many(v)
                        }
                        _ => unreachable!(),
                    })
                }
            }
            Err(e) => Err((
                match e {
                    TxStoreError::Tx(TxError::SpaceNotFound) => Status::NotFound,
                    TxStoreError::Tx(TxError::Db(DbErr::ConnectionAcquire(_))) => {
                        Status::InternalServerError
                    }
                    _ => Status::Unauthorized,
                },
                e.to_string(),
            )),
        };

        timer.observe_duration();
        res
    }
    .instrument(span)
    .await
}

async fn emit_kv_hook_events(
    hook_runtime: &HookRuntime,
    tinycloud: &State<TinyCloud>,
    invocation: &InvocationInfo,
    tx_result: &TransactResult,
) {
    let Some(commit_hash) = tx_result
        .commits
        .values()
        .find_map(|commit| commit.committed_events.first().copied())
    else {
        return;
    };

    let timestamp = match OffsetDateTime::now_utc().format(&Rfc3339) {
        Ok(timestamp) => timestamp,
        Err(_) => return,
    };

    let tx = match tinycloud.readable().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::warn!(error = %e, "failed to read committed hook events");
            return;
        }
    };

    let write_rows = match kv_write::Entity::find()
        .filter(kv_write::Column::Invocation.eq(commit_hash))
        .order_by_asc(kv_write::Column::Seq)
        .order_by_asc(kv_write::Column::Epoch)
        .order_by_asc(kv_write::Column::EpochSeq)
        .all(&tx)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load kv write hook rows");
            return;
        }
    };

    let delete_rows = match kv_delete::Entity::find()
        .filter(kv_delete::Column::InvocationId.eq(commit_hash))
        .all(&tx)
        .await
    {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load kv delete hook rows");
            return;
        }
    };

    let mut writes = HashMap::new();
    for row in write_rows {
        writes.insert((row.space.as_ref().to_string(), row.key.to_string()), row);
    }

    let mut deletes = HashMap::new();
    for row in delete_rows {
        deletes.insert((row.space.as_ref().to_string(), row.key.to_string()), row);
    }

    let mut per_space_index = HashMap::<String, u32>::new();
    let mut emitted = HashSet::<(String, String, String)>::new();

    for capability in &invocation.capabilities {
        let Some((space, service, ability, path)) = capability
            .resource
            .tinycloud_resource()
            .and_then(|resource| {
                Some((
                    resource.space(),
                    resource.service().as_str(),
                    capability.ability.as_ref().as_ref(),
                    resource.path()?,
                ))
            })
        else {
            continue;
        };

        if service != "kv" || !matches!(ability, "tinycloud.kv/put" | "tinycloud.kv/del") {
            continue;
        }

        let space_id = space.to_string();
        let commit = match tx_result.commits.get(space) {
            Some(commit) => commit,
            None => continue,
        };
        let event_index = per_space_index.entry(space_id.clone()).or_insert(0);
        let current_index = *event_index;

        let key = (space_id.clone(), path.to_string());
        let event = match ability {
            "tinycloud.kv/put" => writes.get(&key).map(|row| WriteEvent {
                event_type: "write".to_string(),
                id: format!("{}:{current_index}", commit.rev.to_cid(0x55)),
                space: space_id.clone(),
                service: "kv".to_string(),
                ability: "tinycloud.kv/put".to_string(),
                path: Some(row.key.to_string()),
                actor: invocation.invoker.clone(),
                epoch: commit.rev.to_cid(0x55).to_string(),
                event_index: current_index,
                timestamp: timestamp.clone(),
            }),
            "tinycloud.kv/del" => deletes.get(&key).map(|row| WriteEvent {
                event_type: "write".to_string(),
                id: format!("{}:{current_index}", commit.rev.to_cid(0x55)),
                space: space_id.clone(),
                service: "kv".to_string(),
                ability: "tinycloud.kv/del".to_string(),
                path: Some(row.key.to_string()),
                actor: invocation.invoker.clone(),
                epoch: commit.rev.to_cid(0x55).to_string(),
                event_index: current_index,
                timestamp: timestamp.clone(),
            }),
            _ => None,
        };

        let Some(event) = event else {
            tracing::warn!(
                space = %space_id,
                path = %path,
                ability = %ability,
                "missing committed kv hook row for invocation"
            );
            continue;
        };

        let emitted_key = (space_id, path.to_string(), ability.to_string());
        if !emitted.insert(emitted_key) {
            continue;
        }

        *event_index += 1;
        hook_runtime.bus().publish(event);
    }
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
    hook_runtime: &State<HookRuntime>,
    sql_caps: &[(tinycloud_auth::resource::SpaceId, Option<String>, String)],
) -> Result<DataOut<<BlockStores as ImmutableReadStore>::Readable>, (Status, String)> {
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

    let actor = i.0 .0.invoker.clone();
    let auth_result = verify_auth(i.0, tinycloud).await?;
    let body_str = read_json_body(data).await?;

    let (space, path, ability) = select_database_scope(sql_caps, "sql")?;
    let db_name = SqlService::db_name_from_path(path);
    let space_id = space.to_string();

    let sql_request: SqlRequest =
        serde_json::from_str(&body_str).map_err(|e| (Status::BadRequest, e.to_string()))?;

    if matches!(sql_request, SqlRequest::Export) {
        let data = sql_service
            .export(space, &db_name)
            .await
            .map_err(|e| (sql_error_to_status(&e), e.to_string()))?;
        return Ok(DataOut::One(InvOut(InvocationOutcome::SqlExport(data))));
    }

    let response = sql_service
        .execute(space, &db_name, sql_request, caveats, ability.to_string())
        .await
        .map_err(|e| (sql_error_to_status(&e), e.to_string()))?;

    if let Some(epoch) = auth_result
        .commits
        .get(space)
        .map(|commit| commit.rev.to_cid(0x55).to_string())
    {
        if let Ok(timestamp) = OffsetDateTime::now_utc().format(&Rfc3339) {
            let events = database_write_events(
                &space_id,
                "sql",
                &db_name,
                &actor,
                &epoch,
                &timestamp,
                &response.write_targets,
            );

            enqueue_database_webhook_deliveries(tinycloud, &events)
                .await
                .map_err(|e| {
                    (
                        Status::InternalServerError,
                        format!("sql write committed but webhook enqueue failed: {e}"),
                    )
                })?;

            publish_database_hook_events(hook_runtime, &events);
        }
    }

    let json = serde_json::to_value(response.response)
        .map_err(|e| (Status::InternalServerError, e.to_string()))?;

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

#[cfg(feature = "duckdb")]
async fn handle_duckdb_invoke(
    i: AuthHeaderGetter<InvocationInfo>,
    data: DataIn<'_>,
    tinycloud: &State<TinyCloud>,
    duckdb_service: &State<DuckDbService>,
    hook_runtime: &State<HookRuntime>,
    duckdb_caps: &[(tinycloud_auth::resource::SpaceId, Option<String>, String)],
    arrow_format: bool,
) -> Result<DataOut<<BlockStores as ImmutableReadStore>::Readable>, (Status, String)> {
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

    let actor = i.0 .0.invoker.clone();
    let auth_result = verify_auth(i.0, tinycloud).await?;

    let (space, path, ability) = select_database_scope(duckdb_caps, "duckdb")?;
    let db_name = DuckDbService::db_name_from_path(path);
    let space_id = space.to_string();

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
            ability.to_string(),
            arrow_format,
        )
        .await
        .map_err(|e| (duckdb_error_to_status(&e), e.to_string()))?;

    if let Some(epoch) = auth_result
        .commits
        .get(space)
        .map(|commit| commit.rev.to_cid(0x55).to_string())
    {
        if let Ok(timestamp) = OffsetDateTime::now_utc().format(&Rfc3339) {
            let events = database_write_events(
                &space_id,
                "duckdb",
                &db_name,
                &actor,
                &epoch,
                &timestamp,
                &response.write_targets,
            );

            enqueue_database_webhook_deliveries(tinycloud, &events)
                .await
                .map_err(|e| {
                    (
                        Status::InternalServerError,
                        format!("duckdb write committed but webhook enqueue failed: {e}"),
                    )
                })?;

            publish_database_hook_events(hook_runtime, &events);
        }
    }

    match response.response {
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

#[cfg(feature = "duckdb")]
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

fn database_write_events(
    space: &str,
    service: &str,
    db_name: &str,
    actor: &str,
    epoch: &str,
    timestamp: &str,
    write_targets: &[TouchedTables],
) -> Vec<WriteEvent> {
    let mut events = Vec::new();
    let mut event_index = 0u32;
    let ability = database_write_ability(service);

    for target in write_targets {
        let TouchedTables::Supported(tables) = target else {
            continue;
        };

        for table in tables {
            events.push(WriteEvent {
                event_type: "write".to_string(),
                id: format!("{epoch}:{event_index}"),
                space: space.to_string(),
                service: service.to_string(),
                ability: ability.to_string(),
                path: Some(db_table_path(db_name, table)),
                actor: actor.to_string(),
                epoch: epoch.to_string(),
                event_index,
                timestamp: timestamp.to_string(),
            });
            event_index += 1;
        }
    }

    events
}

fn publish_database_hook_events(hook_runtime: &HookRuntime, events: &[WriteEvent]) {
    for event in events {
        hook_runtime.bus().publish(event.clone());
    }
}

async fn enqueue_database_webhook_deliveries(
    tinycloud: &TinyCloud,
    events: &[WriteEvent],
) -> Result<(), DbErr> {
    // Phase 4 guarantee: SQL/DuckDB writes are already committed by the service path
    // before these durable delivery rows are inserted into metadata storage.
    if events.is_empty() {
        return Ok(());
    }

    let mut cached_subscriptions =
        HashMap::<(String, String, String), Vec<hook_subscription::Model>>::new();
    let mut pending = Vec::<hook_delivery::Model>::new();

    for event in events {
        let Some(path) = event.path.as_deref() else {
            continue;
        };

        let cache_key = (event.space.clone(), event.service.clone(), path.to_string());

        if !cached_subscriptions.contains_key(&cache_key) {
            let rows = tinycloud
                .list_active_hook_subscriptions(&event.space, &event.service, Some(path))
                .await?;
            cached_subscriptions.insert(cache_key.clone(), rows);
        }

        let subscriptions = cached_subscriptions
            .get(&cache_key)
            .expect("subscription cache entry should exist");
        if subscriptions.is_empty() {
            continue;
        }

        let payload_json = serde_json::to_string(event)
            .expect("database webhook payload serialization should succeed");

        pending.extend(
            subscriptions
                .iter()
                .filter(|subscription| {
                    subscription_matches_event(subscription, path, &event.ability)
                })
                .map(|subscription| hook_delivery::Model {
                    id: hook_delivery_id(&subscription.id, &event.id),
                    subscription_id: subscription.id.clone(),
                    event_id: event.id.clone(),
                    payload_json: payload_json.clone(),
                    status: tinycloud_core::db::HOOK_DELIVERY_STATUS_PENDING.to_string(),
                    attempts: 0,
                    next_attempt_at: None,
                    last_error: None,
                    created_at: event.timestamp.clone(),
                    delivered_at: None,
                }),
        );
    }

    tinycloud.enqueue_hook_deliveries(pending).await
}

fn database_write_ability(service: &str) -> &'static str {
    match service {
        "sql" => "tinycloud.sql/write",
        "duckdb" => "tinycloud.duckdb/write",
        _ => "tinycloud.kv/put",
    }
}

fn select_database_scope<'a>(
    caps: &'a [(tinycloud_auth::resource::SpaceId, Option<String>, String)],
    service: &str,
) -> Result<
    (
        &'a tinycloud_auth::resource::SpaceId,
        Option<&'a str>,
        &'a str,
    ),
    (Status, String),
> {
    let Some((space, _path, ability)) = caps.first() else {
        return Err((
            Status::BadRequest,
            format!("No {service} capabilities found"),
        ));
    };

    let same_space = caps
        .iter()
        .all(|(candidate_space, _, _)| candidate_space == space);
    if !same_space {
        return Err((
            Status::BadRequest,
            format!("Ambiguous {service} capabilities span multiple spaces"),
        ));
    }

    let path_ref = select_database_path(caps, service)?;

    Ok((
        space,
        path_ref,
        preferred_database_ability(caps, service).unwrap_or(ability.as_str()),
    ))
}

fn select_database_path<'a>(
    caps: &'a [(tinycloud_auth::resource::SpaceId, Option<String>, String)],
    service: &str,
) -> Result<Option<&'a str>, (Status, String)> {
    let mut selected_path = None;

    for (_, candidate_path, _) in caps {
        let Some(candidate_path) = candidate_path.as_deref() else {
            continue;
        };

        match selected_path {
            None => selected_path = Some(candidate_path),
            Some(selected) if selected == candidate_path => {}
            Some(_) => {
                return Err((
                    Status::BadRequest,
                    format!("Ambiguous {service} capabilities span multiple database paths"),
                ));
            }
        }
    }

    Ok(selected_path)
}

fn preferred_database_ability<'a>(
    caps: &'a [(tinycloud_auth::resource::SpaceId, Option<String>, String)],
    service: &str,
) -> Option<&'a str> {
    let preferred_abilities: &[&str] = match service {
        "sql" => &[
            "tinycloud.sql/write",
            "tinycloud.sql/admin",
            "tinycloud.sql/*",
            "tinycloud.sql/read",
            "tinycloud.sql/select",
        ],
        "duckdb" => &[
            "tinycloud.duckdb/write",
            "tinycloud.duckdb/admin",
            "tinycloud.duckdb/*",
            "tinycloud.duckdb/import",
            "tinycloud.duckdb/export",
            "tinycloud.duckdb/read",
            "tinycloud.duckdb/select",
        ],
        _ => &[],
    };

    preferred_abilities.iter().find_map(|preferred| {
        caps.iter()
            .find(|(_, _, ability)| ability.as_str() == *preferred)
            .map(|(_, _, ability)| ability.as_str())
    })
}

/// Verify authorization by invoking with empty inputs.
///
/// Shared by SQL and DuckDB invoke handlers. The caller must extract caveats
/// from `i` before calling this, since the invocation tuple is consumed here.
/// Hook events are only emitted after the service returns Ok. If a batch or
/// schema block partially applies and then fails, MVP does not emit hooks for
/// the partial write set.
async fn verify_auth(
    invocation: Invocation,
    tinycloud: &State<TinyCloud>,
) -> Result<TransactResult, (Status, String)> {
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
        })
        .map(|(tx_result, _)| tx_result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::HooksConfig, storage::file_system::FileSystemConfig as NodeFileSystemConfig,
    };
    use anyhow::Result;
    use tempfile::TempDir;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        resource::SpaceId,
        ssi::{dids::DIDBuf, jwk::JWK},
    };
    use tinycloud_core::{
        keys::StaticSecret,
        models::{hook_delivery, hook_subscription},
        sea_orm::{ColumnTrait, ConnectOptions, Database, EntityTrait, QueryFilter, QueryOrder},
        storage::either::Either,
        storage::StorageConfig as _,
        types::{Ability, Resource},
    };
    use tokio::time::{timeout, Duration};

    fn test_space_id(name: &str) -> SpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, name.parse().unwrap())
    }

    async fn test_tinycloud() -> Result<TinyCloud> {
        let tempdir = TempDir::new()?;
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?;
        let storage = NodeFileSystemConfig::new(tempdir.path()).open().await?;
        let _persisted = tempdir.keep();
        Ok(TinyCloud::new(
            db,
            Either::B(storage),
            StaticSecret::new(vec![0u8; 32]).unwrap(),
        )
        .await?)
    }

    fn kv_put_capability(space: &SpaceId, path: &str) -> Capability {
        let path = path.parse().unwrap();
        Capability {
            resource: Resource::TinyCloud(space.clone().to_resource(
                "kv".parse().unwrap(),
                Some(path),
                None,
                None,
            )),
            ability: Ability::try_from("tinycloud.kv/put".to_string()).unwrap(),
        }
    }

    fn sql_read_capability(space: &SpaceId) -> Capability {
        Capability {
            resource: Resource::TinyCloud(space.clone().to_resource(
                "sql".parse().unwrap(),
                Some("main".parse().unwrap()),
                None,
                None,
            )),
            ability: Ability::try_from("tinycloud.sql/read".to_string()).unwrap(),
        }
    }

    #[tokio::test]
    async fn multipart_batch_path_names_are_percent_decoded() {
        assert_eq!(
            decode_multipart_path_field_name("xyz.tinycloud.listen%2Ftranscript%2Fabc%253A1")
                .unwrap(),
            "xyz.tinycloud.listen/transcript/abc%3A1"
        );
    }

    #[tokio::test]
    async fn batch_validation_rejects_duplicate_put_paths() {
        let space = test_space_id("default");
        let path: Path = "app/transcript/1".parse().unwrap();
        let caps = vec![
            kv_put_capability(&space, "app/transcript/1"),
            kv_put_capability(&space, "app/transcript/1"),
        ];
        let result = validate_kv_batch_capability_set(
            &caps,
            &[(space.clone(), path.clone()), (space, path)],
        );

        assert_eq!(result.unwrap_err().0, Status::BadRequest);
    }

    #[tokio::test]
    async fn batch_validation_rejects_multiple_spaces() {
        let first = test_space_id("first");
        let second = test_space_id("second");
        let caps = vec![
            kv_put_capability(&first, "app/transcript/1"),
            kv_put_capability(&second, "app/transcript/2"),
        ];
        let result = validate_kv_batch_capability_set(
            &caps,
            &[
                (first, "app/transcript/1".parse().unwrap()),
                (second, "app/transcript/2".parse().unwrap()),
            ],
        );

        assert_eq!(result.unwrap_err().0, Status::BadRequest);
    }

    #[tokio::test]
    async fn batch_validation_rejects_mixed_capabilities() {
        let space = test_space_id("default");
        let caps = vec![
            kv_put_capability(&space, "app/transcript/1"),
            sql_read_capability(&space),
        ];
        let result = validate_kv_batch_capability_set(
            &caps,
            &[(space, "app/transcript/1".parse().unwrap())],
        );

        assert_eq!(result.unwrap_err().0, Status::BadRequest);
    }

    fn subscription_model(
        id: &str,
        space: &str,
        service: &str,
        path_prefix: Option<&str>,
        abilities: &[&str],
    ) -> hook_subscription::Model {
        hook_subscription::Model {
            id: id.to_string(),
            subscriber_did: "did:key:test".to_string(),
            space_id: space.to_string(),
            target_service: service.to_string(),
            path_prefix: path_prefix.map(ToString::to_string),
            abilities_json: hook_subscription::Model::set_abilities(
                &abilities
                    .iter()
                    .map(|ability| ability.to_string())
                    .collect::<Vec<_>>(),
            ),
            callback_url: "https://example.com/hooks".to_string(),
            encrypted_secret: vec![1, 2, 3],
            secret_key_id: "primary".to_string(),
            active: true,
            created_at: "2026-04-09T00:00:00Z".to_string(),
        }
    }

    #[tokio::test]
    async fn publish_database_hook_events_emits_table_paths() {
        let hook_runtime = HookRuntime::new(HooksConfig::default(), [7u8; 32]);
        let mut receiver = hook_runtime.bus().subscribe();

        let events = database_write_events(
            "tinycloud:space",
            "sql",
            "main.db",
            "did:key:test",
            "epoch",
            "2026-01-01T00:00:00Z",
            &[
                TouchedTables::supported(vec!["users".to_string(), "orders".to_string()]),
                TouchedTables::unsupported(),
                TouchedTables::supported(vec!["audit".to_string()]),
            ],
        );
        publish_database_hook_events(&hook_runtime, &events);

        let first = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        let second = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();
        let third = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(first.path.as_deref(), Some("main.db/users"));
        assert_eq!(first.ability, "tinycloud.sql/write");
        assert_eq!(first.event_index, 0);
        assert_eq!(second.path.as_deref(), Some("main.db/orders"));
        assert_eq!(second.ability, "tinycloud.sql/write");
        assert_eq!(second.event_index, 1);
        assert_eq!(third.path.as_deref(), Some("main.db/audit"));
        assert_eq!(third.ability, "tinycloud.sql/write");
        assert_eq!(third.event_index, 2);
    }

    #[tokio::test]
    async fn publish_database_hook_events_uses_canonical_duckdb_write_ability() {
        let hook_runtime = HookRuntime::new(HooksConfig::default(), [8u8; 32]);
        let mut receiver = hook_runtime.bus().subscribe();

        let events = database_write_events(
            "tinycloud:space",
            "duckdb",
            "analytics.duckdb",
            "did:key:test",
            "epoch",
            "2026-01-01T00:00:00Z",
            &[TouchedTables::supported(vec!["events".to_string()])],
        );
        publish_database_hook_events(&hook_runtime, &events);

        let event = timeout(Duration::from_secs(1), receiver.recv())
            .await
            .unwrap()
            .unwrap();

        assert_eq!(event.ability, "tinycloud.duckdb/write");
        assert_eq!(event.path.as_deref(), Some("analytics.duckdb/events"));
    }

    #[tokio::test]
    async fn select_database_scope_prefers_exact_path_over_wildcard_scope() {
        let space = test_space_id("alpha");
        let caps = vec![
            (space.clone(), None, "tinycloud.sql/read".to_string()),
            (
                space.clone(),
                Some("main.db".to_string()),
                "tinycloud.sql/write".to_string(),
            ),
        ];

        let (selected_space, selected_path, ability) = select_database_scope(&caps, "sql").unwrap();

        assert_eq!(selected_space, &space);
        assert_eq!(selected_path, Some("main.db"));
        assert_eq!(ability, "tinycloud.sql/write");
    }

    #[tokio::test]
    async fn select_database_scope_rejects_multiple_exact_paths() {
        let space = test_space_id("alpha");
        let caps = vec![
            (
                space.clone(),
                Some("main.db".to_string()),
                "tinycloud.sql/write".to_string(),
            ),
            (
                space,
                Some("analytics.db".to_string()),
                "tinycloud.sql/write".to_string(),
            ),
        ];

        let err =
            select_database_scope(&caps, "sql").expect_err("multiple paths should be rejected");

        assert_eq!(err.0, Status::BadRequest);
        assert_eq!(
            err.1,
            "Ambiguous sql capabilities span multiple database paths"
        );
    }

    #[tokio::test]
    async fn enqueue_database_webhook_deliveries_persists_matching_sql_and_duckdb() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let sql_sub = subscription_model(
            "sub_sql",
            "tinycloud:space",
            "sql",
            Some("main.db/users"),
            &["tinycloud.sql/write"],
        );
        let duck_sub = subscription_model(
            "sub_duck",
            "tinycloud:space",
            "duckdb",
            Some("analytics.duckdb/events"),
            &["tinycloud.duckdb/write"],
        );
        tinycloud.create_hook_subscription(sql_sub).await?;
        tinycloud.create_hook_subscription(duck_sub).await?;

        let sql_events = database_write_events(
            "tinycloud:space",
            "sql",
            "main.db",
            "did:key:alice",
            "epoch-sql",
            "2026-04-09T01:00:00Z",
            &[TouchedTables::supported(vec!["users".to_string()])],
        );
        let duck_events = database_write_events(
            "tinycloud:space",
            "duckdb",
            "analytics.duckdb",
            "did:key:alice",
            "epoch-duck",
            "2026-04-09T01:00:01Z",
            &[TouchedTables::supported(vec!["events".to_string()])],
        );
        let mut events = sql_events;
        events.extend(duck_events);

        enqueue_database_webhook_deliveries(&tinycloud, &events).await?;
        enqueue_database_webhook_deliveries(&tinycloud, &events).await?;

        let tx = tinycloud.readable().await?;
        let deliveries = hook_delivery::Entity::find()
            .order_by_asc(hook_delivery::Column::EventId)
            .all(&tx)
            .await?;
        assert_eq!(deliveries.len(), 2, "duplicate enqueue must be deduped");
        assert_eq!(
            deliveries[0].status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_PENDING
        );
        assert_eq!(
            deliveries[1].status,
            tinycloud_core::db::HOOK_DELIVERY_STATUS_PENDING
        );
        Ok(())
    }

    #[tokio::test]
    async fn enqueue_database_webhook_deliveries_skips_unsupported_write_targets() -> Result<()> {
        let tinycloud = test_tinycloud().await?;
        let sql_sub = subscription_model(
            "sub_sql",
            "tinycloud:space",
            "sql",
            Some("main.db/users"),
            &["tinycloud.sql/write"],
        );
        tinycloud.create_hook_subscription(sql_sub).await?;

        let events = database_write_events(
            "tinycloud:space",
            "sql",
            "main.db",
            "did:key:alice",
            "epoch-sql",
            "2026-04-09T01:00:00Z",
            &[TouchedTables::unsupported()],
        );
        assert!(events.is_empty());
        enqueue_database_webhook_deliveries(&tinycloud, &events).await?;

        let tx = tinycloud.readable().await?;
        let deliveries = hook_delivery::Entity::find()
            .filter(hook_delivery::Column::SubscriptionId.eq("sub_sql"))
            .all(&tx)
            .await?;
        assert!(deliveries.is_empty());
        Ok(())
    }
}

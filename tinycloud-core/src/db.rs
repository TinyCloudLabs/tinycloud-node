use crate::encryption::ColumnEncryption;
use crate::events::{epoch_hash, Delegation, Event, HashError, Invocation, Operation, Revocation};
use crate::hash::Hash;
use crate::keys::{get_did_key, Secrets};
use crate::migrations::Migrator;
use crate::models::*;
use crate::relationships::*;
use crate::sql_sizes::SqlSizes;
use crate::storage::{
    either::EitherError, Content, HashBuffer, ImmutableReadStore, ImmutableStaging,
    ImmutableWriteStore, StorageSetup, StoreSize,
};
use crate::types::{
    AccountDelegationRecord, CapabilitiesReadParams, DelegationQuery, DelegationQueryDirection,
    DelegationQueryPage, DelegationQueryStatus, DelegationResource, ListFilters, Metadata,
    Resource, SpaceIdWrap,
};
use crate::util::{Capability, DelegationInfo, DelegationMode};
use sea_orm::{
    entity::prelude::*,
    error::{DbErr, RuntimeErr, SqlxError},
    query::*,
    sea_query::{Alias, Expr, LikeExpr, OnConflict, Query},
    ActiveValue::Set,
    ConnectionTrait, DatabaseTransaction, IntoActiveModel, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Weak};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::{
    authorization::{EncodingError, TinyCloudDelegation},
    identity::{canonicalize_did, did_principal_matches},
    resource::{Path, SpaceId},
};

pub const HOOK_DELIVERY_STATUS_PENDING: &str = "pending";
pub const HOOK_DELIVERY_STATUS_RETRYING: &str = "retrying";
pub const HOOK_DELIVERY_STATUS_DELIVERED: &str = "delivered";
pub const HOOK_DELIVERY_STATUS_DEAD_LETTER: &str = "dead_letter";

type KvObjectKey = (SpaceId, Path);
type KvObjectLock = tokio::sync::Mutex<()>;
type KvObjectLockRegistry = Arc<tokio::sync::Mutex<HashMap<KvObjectKey, Weak<KvObjectLock>>>>;

#[derive(Debug, Clone)]
pub struct PendingWebhookDelivery {
    pub id: String,
    pub subscription_id: String,
    pub event_id: String,
    pub payload_json: String,
    pub attempts: i64,
    pub callback_url: String,
    pub encrypted_secret: Vec<u8>,
    pub secret_key_id: String,
    pub subscription_active: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountDelegationQueryError {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error("delegation query invocation is not authorized")]
    Unauthorized,
}

#[derive(Debug, Clone)]
pub struct SpaceDatabase<C, B, S> {
    conn: C,
    storage: B,
    secrets: S,
    encryption: Option<ColumnEncryption>,
    sql_sizes: SqlSizes,
    revocation_chain_locks: Arc<tokio::sync::Mutex<HashMap<Hash, Weak<tokio::sync::Mutex<()>>>>>,
    kv_object_locks: KvObjectLockRegistry,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KvPrecondition {
    /// The key must not have a live value.
    DoesNotExist,
    /// The live value must have this BLAKE3 digest.
    Matches([u8; 32]),
}

fn kv_precondition_matches(precondition: KvPrecondition, current: Option<Hash>) -> bool {
    match (precondition, current) {
        (KvPrecondition::DoesNotExist, None) => true,
        (KvPrecondition::Matches(expected), Some(actual)) => actual.as_ref() == expected,
        _ => false,
    }
}

#[derive(Debug, Clone, Default)]
pub struct KvInvokeOptions {
    pub preconditions: HashMap<(SpaceId, Path), KvPrecondition>,
    pub max_response_bytes: Option<u64>,
    pub list_limit: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct Commit {
    pub rev: Hash,
    pub seq: i64,
    pub committed_events: Vec<Hash>,
    pub consumed_epochs: Vec<Hash>,
}

#[derive(Debug, Clone)]
pub struct TransactResult {
    pub commits: HashMap<SpaceId, Commit>,
    pub skipped_spaces: Vec<SpaceId>,
    /// CIDs of delegations that were processed (saved) regardless of space existence.
    /// Used to return a CID even when all spaces were skipped.
    pub delegation_cids: Vec<Hash>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationStatus {
    Active,
    Revoked,
    Expired,
    Unavailable,
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TxError<S: StorageSetup, K: Secrets> {
    #[error("database error: {0}")]
    Db(#[from] DbErr),
    #[error(transparent)]
    Ucan(#[from] tinycloud_auth::ssi::ucan::Error),
    #[error(transparent)]
    Cacao(#[from] tinycloud_auth::cacaos::siwe_cacao::VerificationError),
    #[error(transparent)]
    InvalidDelegation(#[from] delegation::DelegationError),
    #[error(transparent)]
    InvalidInvocation(#[from] invocation::InvocationError),
    #[error(transparent)]
    InvalidRevocation(#[from] revocation::RevocationError),
    #[error("Epoch Hashing Err: {0}")]
    EpochHashingErr(#[from] HashError),
    #[error(transparent)]
    Encoding(#[from] EncodingError),
    #[error(transparent)]
    StoreSetup(S::Error),
    #[error(transparent)]
    Secrets(K::Error),
    #[error("Space not found")]
    SpaceNotFound,
    #[error("epoch insert failed: {0}")]
    EpochInsert(DbErr),
    #[error("Invalid delegation CID: {0}")]
    InvalidCid(String),
    #[error("encryption error: {0}")]
    Encryption(#[from] crate::encryption::EncryptionError),
    #[error("delegation-chain-traversal-limit-exceeded")]
    ChainTraversalLimitExceeded,
}

#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TxStoreError<B, S, K>
where
    B: ImmutableReadStore + ImmutableWriteStore<S> + StorageSetup,
    S: ImmutableStaging,
    S::Writable: 'static + Unpin,
    K: Secrets,
{
    #[error(transparent)]
    Tx(#[from] TxError<B, K>),
    #[error(transparent)]
    StoreRead(<B as ImmutableReadStore>::Error),
    #[error(transparent)]
    StoreWrite(<B as ImmutableWriteStore<S>>::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("Missing Input for requested action")]
    MissingInput,
    #[error("KV precondition failed")]
    KvPreconditionFailed,
    #[error("conditional KV transaction conflicted; retry the request")]
    KvSerializationConflict,
    #[error("KV response is {size} bytes, exceeding the requested limit of {limit} bytes")]
    KvResponseTooLarge { size: u64, limit: u64 },
}

impl<B, S, K> From<DbErr> for TxStoreError<B, S, K>
where
    B: ImmutableReadStore + ImmutableWriteStore<S> + StorageSetup,
    S: ImmutableStaging,
    S::Writable: 'static + Unpin,
    K: Secrets,
{
    fn from(e: DbErr) -> Self {
        TxStoreError::Tx(e.into())
    }
}

/// Error type for `SpaceDatabase::compute_deploy` (P1 atomic deploy
/// primitive, compute-service.md §5.1/F4).
#[cfg(feature = "compute")]
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ComputeDeployError<B: StorageSetup, K: Secrets> {
    #[error(transparent)]
    Tx(#[from] TxError<B, K>),
    #[error(transparent)]
    Artifact(#[from] crate::database_artifacts::DatabaseArtifactError),
    #[error("compute deploy grant is missing the computeFunctionBinding caveat for content_cid {0} on one or more capability rows")]
    BindingCaveatMismatch(String),
}

#[cfg(feature = "compute")]
impl<B: StorageSetup, K: Secrets> From<DbErr> for ComputeDeployError<B, K> {
    fn from(e: DbErr) -> Self {
        ComputeDeployError::Tx(TxError::Db(e))
    }
}

/// Result of a successful `SpaceDatabase::compute_deploy` (P1).
#[cfg(feature = "compute")]
#[derive(Debug, Clone)]
pub struct ComputeDeployOutcome {
    pub content_cid: String,
    pub revision: i64,
    pub size_bytes: i64,
    pub delegation_cid: String,
    /// Set when a prior artifact at the same `(service, space, name)` had a
    /// DIFFERENT content hash and its bound `D_fn` was found and revoked
    /// (re-deploy hygiene, §5.1).
    pub superseded_content_cid: Option<String>,
    pub superseded_delegation_cid: Option<String>,
}

impl<B, K> SpaceDatabase<DatabaseConnection, B, K> {
    pub async fn new(conn: DatabaseConnection, storage: B, secrets: K) -> Result<Self, DbErr> {
        Migrator::up(&conn, None).await?;
        Ok(Self {
            conn,
            storage,
            secrets,
            encryption: None,
            sql_sizes: SqlSizes::default(),
            revocation_chain_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            kv_object_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        })
    }

    pub fn with_encryption(mut self, encryption: Option<ColumnEncryption>) -> Self {
        self.encryption = encryption;
        self
    }

    pub fn with_sql_sizes(mut self, sql_sizes: SqlSizes) -> Self {
        self.sql_sizes = sql_sizes;
        self
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    K: Secrets,
{
    pub async fn stage_key(&self, space_id: &SpaceId) -> Result<String, K::Error> {
        self.secrets.stage_keypair(space_id).await.map(get_did_key)
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    C: TransactionTrait,
{
    // to allow users to make custom read queries
    pub async fn readable(&self) -> Result<DatabaseTransaction, DbErr> {
        self.conn
            .begin_with_config(None, Some(sea_orm::AccessMode::ReadOnly))
            .await
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    C: ConnectionTrait,
{
    /// List every space id known to this node (the full `space` table).
    /// Used by the admin usage endpoint to enumerate spaces without touching
    /// SQL directly.
    pub async fn list_space_ids(&self) -> Result<Vec<SpaceId>, DbErr> {
        Ok(space::Entity::find()
            .all(&self.conn)
            .await?
            .into_iter()
            .map(|s| s.id.0)
            .collect())
    }

    /// Return lifecycle-complete delegations related to the authenticated account.
    ///
    /// The account is derived from the verified invocation signer and its one
    /// current session proof. Callers cannot select another account in the query.
    pub async fn query_account_delegations(
        &self,
        invocation: &crate::util::InvocationInfo,
        query: &DelegationQuery,
    ) -> Result<DelegationQueryPage, AccountDelegationQueryError> {
        let now = OffsetDateTime::now_utc();
        invocation::verify_and_authorize(&self.conn, invocation, now)
            .await
            .map_err(|_| AccountDelegationQueryError::Unauthorized)?;
        let principal = account_query_principal(&self.conn, invocation)
            .await?
            .ok_or(AccountDelegationQueryError::Unauthorized)?;
        let account_dids = account_session_dids(&self.conn, &principal).await?;
        let actors = account_dids.iter().cloned().collect::<Vec<_>>();
        let rows = delegation::Entity::find()
            .filter(
                Condition::any()
                    .add(delegation::Column::Delegator.is_in(actors.clone()))
                    .add(delegation::Column::Delegatee.is_in(actors)),
            )
            .find_with_related(abilities::Entity)
            .all(&self.conn)
            .await?;
        let (delegations, ability_rows): (Vec<_>, Vec<_>) = rows.into_iter().unzip();
        let roots = delegations.iter().map(|row| row.id).collect::<Vec<_>>();
        let ancestor_state = load_account_ancestor_state(&self.conn, &roots).await?;
        let now = OffsetDateTime::now_utc();
        let mut records = Vec::new();

        for (delegation, abilities) in delegations.into_iter().zip(ability_rows) {
            let granted = account_dids.contains(&delegation.delegator);
            let direction = if granted { "granted" } else { "received" };
            if matches!(query.direction, DelegationQueryDirection::Granted) && !granted
                || matches!(query.direction, DelegationQueryDirection::Received) && granted
            {
                continue;
            }

            let mut grouped: std::collections::BTreeMap<
                String,
                Vec<(String, crate::types::Caveats)>,
            > = std::collections::BTreeMap::new();
            for ability in abilities {
                grouped
                    .entry(ability.resource.to_string())
                    .or_default()
                    .push((ability.ability.to_string(), ability.caveats));
            }
            if let Some(space_filter) = query.space.as_deref() {
                let matches_space = grouped.keys().any(|resource| {
                    resource
                        .parse::<Resource>()
                        .ok()
                        .and_then(|resource| resource.space().cloned())
                        .map(|space| {
                            space.to_string() == space_filter
                                || space.name().as_str() == space_filter
                        })
                        .unwrap_or(false)
                });
                if !matches_space {
                    continue;
                }
            }
            let resources = grouped
                .into_iter()
                .map(|(resource, mut entries)| {
                    entries.sort_by(|left, right| {
                        left.0.cmp(&right.0).then_with(|| {
                            serde_json::to_string(&left.1)
                                .unwrap_or_default()
                                .cmp(&serde_json::to_string(&right.1).unwrap_or_default())
                        })
                    });
                    DelegationResource {
                        resource,
                        actions: entries.iter().map(|entry| entry.0.clone()).collect(),
                        caveats: entries.into_iter().map(|entry| entry.1).collect(),
                    }
                })
                .collect();

            let lifecycle = ancestor_state.lifecycle(delegation.id, now)?;
            let status_matches = match query.status {
                None => true,
                Some(DelegationQueryStatus::Active) => lifecycle.status == "active",
                Some(DelegationQueryStatus::Pending) => lifecycle.status == "pending",
                Some(DelegationQueryStatus::Expired) => lifecycle.status == "expired",
                Some(DelegationQueryStatus::Revoked) => {
                    matches!(lifecycle.status, "revoked" | "ancestor_revoked")
                }
                Some(DelegationQueryStatus::AncestorRevoked) => {
                    lifecycle.status == "ancestor_revoked"
                }
            };
            if !status_matches {
                continue;
            }

            let cid = delegation.id.to_cid(0x55).to_string();
            let mut parents = ancestor_state
                .parents
                .get(&delegation.id)
                .cloned()
                .unwrap_or_default();
            parents.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            parents.dedup();
            records.push(AccountDelegationRecord {
                cid,
                direction: direction.to_string(),
                delegator_did: delegation.delegator,
                delegate_did: delegation.delegatee,
                resources,
                parents: parents
                    .into_iter()
                    .map(|parent| parent.to_cid(0x55).to_string())
                    .collect(),
                issued_at: delegation.issued_at,
                not_before: delegation.not_before,
                expires_at: delegation.expiry,
                status: lifecycle.status.to_string(),
                revoked_at: lifecycle
                    .direct_revocation
                    .as_ref()
                    .and_then(|row| row.revoked_at),
                revoked_by: lifecycle
                    .direct_revocation
                    .as_ref()
                    .map(|row| row.revoker.clone()),
                revoked_ancestor_cid: lifecycle.revoked_ancestor_cid,
            });
        }

        records.sort_by(|left, right| {
            right
                .issued_at
                .cmp(&left.issued_at)
                .then_with(|| left.cid.cmp(&right.cid))
        });
        if let Some(cursor) = query
            .decoded_cursor()
            .map_err(|_| AccountDelegationQueryError::Unauthorized)?
        {
            let Some(position) = records.iter().position(|record| record.cid == cursor) else {
                return Err(AccountDelegationQueryError::Unauthorized);
            };
            records.drain(..=position);
        }
        let limit = query.limit.unwrap_or(50) as usize;
        let next_cursor = (records.len() > limit)
            .then(|| DelegationQuery::encode_cursor(&records[limit - 1].cid));
        records.truncate(limit);
        Ok(DelegationQueryPage {
            schema_version: 2,
            items: records,
            next_cursor,
        })
    }

    pub async fn list_due_webhook_deliveries(
        &self,
        limit: u64,
    ) -> Result<Vec<PendingWebhookDelivery>, DbErr> {
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current timestamps should format as RFC3339");

        hook_delivery::Entity::find()
            .filter(
                Condition::all()
                    .add(
                        hook_delivery::Column::Status
                            .is_in([HOOK_DELIVERY_STATUS_PENDING, HOOK_DELIVERY_STATUS_RETRYING]),
                    )
                    .add(
                        Condition::any()
                            .add(hook_delivery::Column::NextAttemptAt.is_null())
                            .add(hook_delivery::Column::NextAttemptAt.lte(now)),
                    ),
            )
            .order_by_asc(hook_delivery::Column::CreatedAt)
            .order_by_asc(hook_delivery::Column::Attempts)
            .limit(limit)
            .find_also_related(hook_subscription::Entity)
            .all(&self.conn)
            .await
            .map(|rows| {
                rows.into_iter()
                    .filter_map(|(delivery, subscription)| {
                        subscription.map(|subscription| PendingWebhookDelivery {
                            id: delivery.id,
                            subscription_id: delivery.subscription_id,
                            event_id: delivery.event_id,
                            payload_json: delivery.payload_json,
                            attempts: delivery.attempts,
                            callback_url: subscription.callback_url,
                            encrypted_secret: subscription.encrypted_secret,
                            secret_key_id: subscription.secret_key_id,
                            subscription_active: subscription.active,
                        })
                    })
                    .collect()
            })
    }

    pub async fn mark_webhook_delivery_delivered(
        &self,
        delivery_id: &str,
        attempts: i64,
    ) -> Result<(), DbErr> {
        let Some(delivery) = hook_delivery::Entity::find_by_id(delivery_id.to_string())
            .one(&self.conn)
            .await?
        else {
            return Ok(());
        };

        let delivered_at = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current timestamps should format as RFC3339");
        let mut active = delivery.into_active_model();
        active.status = Set(HOOK_DELIVERY_STATUS_DELIVERED.to_string());
        active.attempts = Set(attempts);
        active.next_attempt_at = Set(None);
        active.last_error = Set(None);
        active.delivered_at = Set(Some(delivered_at));
        active.update(&self.conn).await?;
        Ok(())
    }

    pub async fn mark_webhook_delivery_failed(
        &self,
        delivery_id: &str,
        attempts: i64,
        next_attempt_at: Option<OffsetDateTime>,
        last_error: String,
        dead_letter: bool,
    ) -> Result<(), DbErr> {
        let Some(delivery) = hook_delivery::Entity::find_by_id(delivery_id.to_string())
            .one(&self.conn)
            .await?
        else {
            return Ok(());
        };

        let mut active = delivery.into_active_model();
        active.status = Set(if dead_letter {
            HOOK_DELIVERY_STATUS_DEAD_LETTER.to_string()
        } else {
            HOOK_DELIVERY_STATUS_RETRYING.to_string()
        });
        active.attempts = Set(attempts);
        active.next_attempt_at = Set(next_attempt_at.map(|value| {
            value
                .format(&Rfc3339)
                .expect("current timestamps should format as RFC3339")
        }));
        active.last_error = Set(Some(last_error));
        active.delivered_at = Set(None);
        active.update(&self.conn).await?;
        Ok(())
    }

    pub async fn count_active_hook_subscriptions(&self, space_id: &str) -> Result<u64, DbErr> {
        hook_subscription::Entity::find()
            .filter(
                Condition::all()
                    .add(hook_subscription::Column::SpaceId.eq(space_id))
                    .add(hook_subscription::Column::Active.eq(true)),
            )
            .count(&self.conn)
            .await
    }

    pub async fn create_hook_subscription(
        &self,
        model: hook_subscription::Model,
    ) -> Result<hook_subscription::Model, DbErr> {
        hook_subscription::Entity::insert(hook_subscription::ActiveModel::from(model.clone()))
            .exec(&self.conn)
            .await?;
        Ok(model)
    }

    pub async fn enqueue_hook_deliveries(
        &self,
        models: Vec<hook_delivery::Model>,
    ) -> Result<(), DbErr> {
        if models.is_empty() {
            return Ok(());
        }

        match hook_delivery::Entity::insert_many(
            models
                .into_iter()
                .map(hook_delivery::ActiveModel::from)
                .collect::<Vec<_>>(),
        )
        .on_conflict(
            OnConflict::column(hook_delivery::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec(&self.conn)
        .await
        {
            Err(DbErr::RecordNotInserted) => {}
            result => {
                result?;
            }
        }
        Ok(())
    }

    pub async fn list_active_hook_subscriptions(
        &self,
        space_id: &str,
        target_service: &str,
        prefix: Option<&str>,
    ) -> Result<Vec<hook_subscription::Model>, DbErr> {
        let mut query = hook_subscription::Entity::find().filter(
            Condition::all()
                .add(hook_subscription::Column::SpaceId.eq(space_id))
                .add(hook_subscription::Column::TargetService.eq(target_service))
                .add(hook_subscription::Column::Active.eq(true)),
        );

        if let Some(prefix) = prefix.and_then(normalize_hook_prefix) {
            query = query.filter(
                Condition::any()
                    .add(hook_subscription::Column::PathPrefix.eq(prefix))
                    .add(hook_subscription::Column::PathPrefix.starts_with(format!("{prefix}/"))),
            );
        }

        query
            .order_by_asc(hook_subscription::Column::CreatedAt)
            .all(&self.conn)
            .await
    }

    pub async fn find_hook_subscription(
        &self,
        subscription_id: &str,
    ) -> Result<Option<hook_subscription::Model>, DbErr> {
        hook_subscription::Entity::find_by_id(subscription_id.to_string())
            .one(&self.conn)
            .await
    }

    pub async fn create_signed_kv_ticket(
        &self,
        model: signed_kv_ticket::Model,
    ) -> Result<signed_kv_ticket::Model, DbErr> {
        signed_kv_ticket::Entity::insert(signed_kv_ticket::ActiveModel::from(model.clone()))
            .exec(&self.conn)
            .await?;
        Ok(model)
    }

    pub async fn find_signed_kv_ticket(
        &self,
        ticket_id: &str,
    ) -> Result<Option<signed_kv_ticket::Model>, DbErr> {
        signed_kv_ticket::Entity::find_by_id(ticket_id.to_string())
            .one(&self.conn)
            .await
    }

    pub async fn deactivate_hook_subscription(&self, subscription_id: &str) -> Result<(), DbErr> {
        let Some(model) = hook_subscription::Entity::find_by_id(subscription_id.to_string())
            .one(&self.conn)
            .await?
        else {
            return Ok(());
        };

        let mut active = model.into_active_model();
        active.active = Set(false);
        active.update(&self.conn).await?;
        Ok(())
    }
}

fn normalize_hook_prefix(prefix: &str) -> Option<&str> {
    let trimmed = prefix.trim_matches('/');
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    B: StoreSize,
{
    /// Total metered usage for a space: block-store (KV) bytes folded with the
    /// sum of SQL/DuckDB artifact bytes (`SqlSizes`). Returns `None` only when
    /// BOTH are absent (truly-unknown space → 404 preserved); a SQL-only space
    /// reports `Some(sql_bytes)`.
    pub async fn store_size(&self, space_id: &SpaceId) -> Result<Option<u64>, B::Error> {
        let blocks = self.storage.total_size(space_id).await?; // Option<u64>
        let sql = self.sql_sizes.space_total(space_id).await; // u64 (0 if none)
        Ok(match (blocks, sql) {
            (None, 0) => None,                                // truly absent → 404 preserved
            (blocks, sql) => Some(blocks.unwrap_or(0) + sql), // SQL-only → Some(sql)
        })
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    C: ConnectionTrait,
    B: ImmutableReadStore,
{
    pub async fn public_kv_get(
        &self,
        space_id: &SpaceId,
        key: &Path,
    ) -> Result<Option<(Metadata, Hash, Content<B::Readable>)>, EitherError<DbErr, B::Error>> {
        self.kv_get(space_id, key).await
    }

    pub async fn kv_get(
        &self,
        space_id: &SpaceId,
        key: &Path,
    ) -> Result<Option<(Metadata, Hash, Content<B::Readable>)>, EitherError<DbErr, B::Error>> {
        get_kv(&self.conn, &self.storage, space_id, key).await
    }

    pub async fn public_kv_metadata(
        &self,
        space_id: &SpaceId,
        key: &Path,
    ) -> Result<Option<Metadata>, DbErr> {
        metadata(&self.conn, space_id, key).await
    }

    pub async fn public_kv_list(
        &self,
        space_id: &SpaceId,
        prefix: &Path,
    ) -> Result<Vec<Path>, DbErr> {
        list(&self.conn, space_id, prefix).await
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    C: TransactionTrait,
{
    pub async fn check_db_connection(&self) -> Result<(), DbErr> {
        // there's a `ping` method on the connection, but we can't access it from here
        // but starting a transaction should be enough to check the connection
        self.conn.begin().await.map(|_| ())
    }
}

pub type InvocationInputs<W> = HashMap<(SpaceId, Path), (Metadata, HashBuffer<W>)>;

impl<C, B, K> SpaceDatabase<C, B, K>
where
    C: TransactionTrait + ConnectionTrait,
    B: StorageSetup,
    K: Secrets,
{
    async fn acquire_chain_guards(
        &self,
        roots: &[Hash],
    ) -> Result<Vec<tokio::sync::OwnedMutexGuard<()>>, TxError<B, K>> {
        let mut keys = revocation::ancestor_chain_ids_for_roots(&self.conn, roots)
            .await
            .map_err(|error| match error {
                revocation::ChainTraversalError::Db(error) => TxError::Db(error),
                revocation::ChainTraversalError::LimitExceeded => {
                    TxError::ChainTraversalLimitExceeded
                }
            })?;
        keys.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
        keys.dedup();

        let locks = {
            let mut registry = self.revocation_chain_locks.lock().await;
            registry.retain(|_, lock| lock.strong_count() > 0);
            keys.into_iter()
                .map(|key| {
                    if let Some(lock) = registry.get(&key).and_then(Weak::upgrade) {
                        lock
                    } else {
                        let lock = Arc::new(tokio::sync::Mutex::new(()));
                        registry.insert(key, Arc::downgrade(&lock));
                        lock
                    }
                })
                .collect::<Vec<_>>()
        };

        let mut guards = Vec::with_capacity(locks.len());
        for lock in locks {
            guards.push(lock.lock_owned().await);
        }
        Ok(guards)
    }

    async fn acquire_kv_object_guards(
        &self,
        keys: &[(SpaceId, Path)],
    ) -> Vec<tokio::sync::OwnedMutexGuard<()>> {
        let mut keys = keys.to_vec();
        keys.sort_by(|(left_space, left_path), (right_space, right_path)| {
            left_space
                .to_string()
                .cmp(&right_space.to_string())
                .then_with(|| left_path.as_str().cmp(right_path.as_str()))
        });
        keys.dedup();

        let locks = {
            let mut registry = self.kv_object_locks.lock().await;
            registry.retain(|_, lock| lock.strong_count() > 0);
            keys.into_iter()
                .map(|key| {
                    if let Some(lock) = registry.get(&key).and_then(Weak::upgrade) {
                        lock
                    } else {
                        let lock = Arc::new(tokio::sync::Mutex::new(()));
                        registry.insert(key, Arc::downgrade(&lock));
                        lock
                    }
                })
                .collect::<Vec<_>>()
        };

        let mut guards = Vec::with_capacity(locks.len());
        for lock in locks {
            guards.push(lock.lock_owned().await);
        }
        guards
    }

    async fn transact(&self, events: Vec<Event>) -> Result<TransactResult, TxError<B, K>> {
        let tx = self
            .conn
            .begin_with_config(chain_isolation_level(&self.conn), None)
            .await?;

        let result = transact(
            &tx,
            &self.storage,
            &self.secrets,
            events,
            self.encryption.as_ref(),
        )
        .await?;

        tx.commit().await?;

        Ok(result)
    }

    pub async fn delegate(&self, delegation: Delegation) -> Result<TransactResult, TxError<B, K>> {
        let roots: Vec<Hash> = delegation
            .0
            .parents
            .iter()
            .copied()
            .map(Hash::from)
            .collect();
        let _chain_guards = self.acquire_chain_guards(&roots).await?;
        self.transact(vec![Event::Delegation(Box::new(delegation))])
            .await
    }

    pub async fn revoke(&self, revocation: Revocation) -> Result<TransactResult, TxError<B, K>> {
        let mut roots = vec![Hash::from(revocation.0.revoked)];
        roots.extend(revocation.0.parents.iter().copied().map(Hash::from));
        let _chain_guards = self.acquire_chain_guards(&roots).await?;
        self.transact(vec![Event::Revocation(Box::new(revocation))])
            .await
    }

    /// Atomic compute deploy primitive (compute-service.md §5.1/F4, plan
    /// P1). ONE SeaORM transaction that:
    ///
    ///   (a) processes `grant` (the deploy-time `D_fn`) through the
    ///       STANDARD delegation verification/persistence path -- the same
    ///       `transact()`/`delegation::process` pipeline `delegate()` above
    ///       uses (signature check, delegation-side containment, per-
    ///       ability caveat persistence) -- and
    ///   (b) saves the WASM artifact via the transaction-aware
    ///       `database_artifacts::save_artifact_conn` (service tag
    ///       `"compute"`, identity = content CID, against the SAME `tx`).
    ///
    /// Commits only if both succeed (a `D_fn`-verification failure leaves NO
    /// artifact row; an artifact-persist failure leaves NO delegation row).
    /// The caller MUST update the `SqlSizes` mirror AFTER this returns `Ok`
    /// (mirror-after-commit, §5/F8) -- this method does not touch
    /// `self.sql_sizes` itself so the mirror write provably only happens
    /// once the transaction is durable.
    ///
    /// Every capability row of `grant` MUST carry the `computeFunctionBinding`
    /// caveat (§6.2/D2) naming the content CID computed here from `wasm` --
    /// checked BEFORE the transaction opens, so a malformed grant never
    /// touches the DB.
    ///
    /// Re-deploy hygiene (§5.1, "SHOULD"): when a prior artifact exists at
    /// `(service, space, name)` with a DIFFERENT content hash, this looks
    /// for a still-active delegation from the SAME delegator whose binding
    /// caveat names the OLD content hash and revokes it in the same
    /// transaction. This is a NODE-INTERNAL bookkeeping revocation, not the
    /// signed `/revoke` path (`revocation::process` requires a fresh
    /// signature the deploy request does not carry) -- it is authorized
    /// because the identity performing it (`grant`'s delegator) was JUST
    /// cryptographically verified as the signer of the NEW `D_fn` earlier in
    /// this same transaction, and the search is scoped to that delegator's
    /// own prior grants for this exact function only.
    #[cfg(feature = "compute")]
    pub async fn compute_deploy(
        &self,
        grant: Delegation,
        service: &str,
        space: &SpaceId,
        name: &str,
        wasm: Vec<u8>,
    ) -> Result<ComputeDeployOutcome, ComputeDeployError<B, K>> {
        let content_cid = crate::hash::hash(&wasm).to_cid(0x55).to_string();

        let expected_caveat = crate::compute::compute_function_binding_caveat(&content_cid);
        let all_bound = !grant.0.capabilities.is_empty()
            && grant
                .0
                .capabilities
                .iter()
                .all(|c| c.caveats.0.values().any(|v| *v == expected_caveat));
        if !all_bound {
            return Err(ComputeDeployError::BindingCaveatMismatch(content_cid));
        }

        let delegator = grant.0.delegator.clone();
        let space_str = space.to_string();

        let roots: Vec<Hash> = grant.0.parents.iter().copied().map(Hash::from).collect();
        let _chain_guards = self.acquire_chain_guards(&roots).await?;

        let tx = self
            .conn
            .begin_with_config(chain_isolation_level(&self.conn), None)
            .await?;

        // Read the prior artifact (if any) BEFORE it is overwritten below,
        // to drive re-deploy hygiene.
        let existing =
            crate::database_artifacts::load_artifact_conn(&tx, service, &space_str, name).await?;

        // (a) process the new D_fn through the standard delegation path.
        let result = transact(
            &tx,
            &self.storage,
            &self.secrets,
            vec![Event::Delegation(Box::new(grant))],
            self.encryption.as_ref(),
        )
        .await?;
        let delegation_hash = *result
            .delegation_cids
            .first()
            .ok_or_else(|| TxError::InvalidCid("compute deploy: missing D_fn CID".to_string()))?;

        // Re-deploy hygiene: revoke a superseded D_fn bound to the OLD
        // content hash, scoped to the same delegator.
        let mut superseded_content_cid = None;
        let mut superseded_delegation_cid = None;
        if let Some(existing) = &existing {
            if existing.content_hash != content_cid {
                if let Some(superseded_hash) =
                    find_superseded_compute_delegation(&tx, &delegator, &existing.content_hash)
                        .await?
                {
                    superseded_content_cid = Some(existing.content_hash.clone());
                    superseded_delegation_cid = Some(superseded_hash.to_cid(0x55).to_string());
                    insert_internal_revocation(&tx, &delegator, superseded_hash).await?;
                }
            }
        }

        // (b) transaction-aware artifact save, in the SAME `tx`.
        let artifact =
            crate::database_artifacts::save_artifact_conn(&tx, service, &space_str, name, wasm)
                .await?;

        tx.commit().await?;

        Ok(ComputeDeployOutcome {
            content_cid: artifact.content_hash,
            revision: artifact.revision,
            size_bytes: artifact.size_bytes,
            delegation_cid: delegation_hash.to_cid(0x55).to_string(),
            superseded_content_cid,
            superseded_delegation_cid,
        })
    }

    pub async fn delegation_status(
        &self,
        target: Hash,
        invoker: &str,
        proofs: &[tinycloud_auth::authorization::Cid],
    ) -> Result<Option<DelegationStatus>, TxError<B, K>> {
        if proofs.len() > 1 {
            return Ok(None);
        }
        let Some(delegation) = delegation::Entity::find_by_id(target)
            .one(&self.conn)
            .await?
        else {
            return Ok(None);
        };
        let abilities = abilities::Entity::find()
            .filter(abilities::Column::Delegation.eq(target))
            .all(&self.conn)
            .await?;

        let mut roots = vec![target];
        roots.extend(proofs.iter().copied().map(Hash::from));
        let _chain_guards = match self.acquire_chain_guards(&roots).await {
            Ok(guards) => guards,
            Err(TxError::ChainTraversalLimitExceeded) => {
                return Ok(Some(DelegationStatus::Unavailable));
            }
            Err(error) => return Err(error),
        };

        let principal = match revocation::control_proof_decision(
            &self.conn,
            invoker,
            proofs,
            "tinycloud.delegation/status",
            &target,
        )
        .await?
        {
            revocation::ControlProofDecision::DirectSigner(principal)
            | revocation::ControlProofDecision::PersistentPrincipal(principal) => principal,
            revocation::ControlProofDecision::Denied => return Ok(None),
        };
        let authorized = did_principal_matches(&delegation.delegator, &principal)
            || did_principal_matches(&delegation.delegatee, &principal)
            || abilities.iter().any(|ability| {
                ability
                    .resource
                    .space()
                    .map(|space| did_principal_matches(space.did().as_str(), &principal))
                    .unwrap_or(false)
            });
        if !authorized {
            return Ok(None);
        }

        if revocation::is_revoked(&self.conn, &target).await? {
            return Ok(Some(DelegationStatus::Revoked));
        }
        match revocation::first_revoked_ancestor(&self.conn, &target).await {
            Ok(Some(_)) => return Ok(Some(DelegationStatus::Revoked)),
            Ok(None) => {}
            Err(revocation::ChainTraversalError::LimitExceeded) => {
                return Ok(Some(DelegationStatus::Unavailable));
            }
            Err(revocation::ChainTraversalError::Db(error)) => return Err(error.into()),
        }

        let now = OffsetDateTime::now_utc();
        if delegation
            .expiry
            .map(|expiry| now >= expiry)
            .unwrap_or(false)
        {
            return Ok(Some(DelegationStatus::Expired));
        }
        if delegation
            .not_before
            .map(|not_before| now < not_before)
            .unwrap_or(false)
        {
            return Ok(Some(DelegationStatus::Unavailable));
        }
        Ok(Some(DelegationStatus::Active))
    }

    pub async fn invoke<S>(
        &self,
        invocation: Invocation,
        inputs: InvocationInputs<S::Writable>,
    ) -> Result<(TransactResult, Vec<InvocationOutcome<B::Readable>>), TxStoreError<B, S, K>>
    where
        B: ImmutableWriteStore<S> + ImmutableReadStore,
        S: ImmutableStaging,
        S::Writable: 'static + Unpin,
    {
        self.invoke_with_options(invocation, inputs, KvInvokeOptions::default())
            .await
    }

    pub async fn invoke_with_options<S>(
        &self,
        invocation: Invocation,
        mut inputs: InvocationInputs<S::Writable>,
        options: KvInvokeOptions,
    ) -> Result<(TransactResult, Vec<InvocationOutcome<B::Readable>>), TxStoreError<B, S, K>>
    where
        B: ImmutableWriteStore<S> + ImmutableReadStore,
        S: ImmutableStaging,
        S::Writable: 'static + Unpin,
    {
        let roots: Vec<Hash> = invocation
            .0
            .parents
            .iter()
            .copied()
            .map(Hash::from)
            .collect();
        let _chain_guards = self.acquire_chain_guards(&roots).await?;
        let mutation_keys = invocation
            .0
            .capabilities
            .iter()
            .filter_map(|cap| {
                let resource = cap.resource.tinycloud_resource()?;
                let ability =
                    crate::policy_capability::resolve_alias(cap.ability.as_ref().as_ref());
                if resource.service().as_str() != "kv"
                    || !matches!(ability, "tinycloud.kv/put" | "tinycloud.kv/del")
                {
                    return None;
                }
                Some((resource.space().clone(), resource.path()?.clone()))
            })
            .collect::<Vec<_>>();
        let _kv_object_guards = self.acquire_kv_object_guards(&mutation_keys).await;
        let mut stages = HashMap::new();
        let mut ops = Vec::new();
        let mut write_hashes = HashMap::new();
        // for each capability being invoked
        for cap in invocation.0.capabilities.iter() {
            match cap.resource.tinycloud_resource().and_then(|r| {
                Some((
                    r.space(),
                    r.service().as_str(),
                    // TC-119: resolve deprecated aliases to canonical so an
                    // invocation using `kv/delete` dispatches identically to
                    // `kv/del`. Identity for canonical URNs, so dispatch for
                    // every non-alias action is byte-for-byte unchanged.
                    crate::policy_capability::resolve_alias(cap.ability.as_ref().as_ref()),
                    r.path()?,
                ))
            }) {
                // stage inputs for content writes
                Some((space, "kv", "tinycloud.kv/put", path)) => {
                    let (metadata, mut stage) = inputs
                        .remove(&(space.clone(), path.clone()))
                        .ok_or(TxStoreError::MissingInput)?;

                    let value = stage.hash();

                    stages.insert((space.clone(), path.clone()), stage);
                    write_hashes.insert((space.clone(), path.clone()), value);
                    // add write for tx
                    ops.push(Operation::KvWrite {
                        space: space.clone(),
                        key: path.clone(),
                        metadata,
                        value,
                    });
                }
                // add delete for tx
                Some((space, "kv", "tinycloud.kv/del", path)) => {
                    ops.push(Operation::KvDelete {
                        space: space.clone(),
                        key: path.clone(),
                        version: None,
                    });
                }
                _ => {}
            }
        }

        let has_preconditions = !options.preconditions.is_empty();
        let isolation_level = if has_preconditions {
            conditional_kv_isolation_level(&self.conn)
        } else {
            chain_isolation_level(&self.conn)
        };
        let tx = self.conn.begin_with_config(isolation_level, None).await?;
        let mut deleted_hashes = HashMap::new();
        for key @ (space, path) in &mutation_keys {
            let current = get_kv_entity(&tx, space, path)
                .await?
                .map(|entry| entry.value);
            if let Some(precondition) = options.preconditions.get(key) {
                if !kv_precondition_matches(*precondition, current) {
                    return Err(TxStoreError::KvPreconditionFailed);
                }
            }
            if let Some(hash) = current {
                deleted_hashes.insert(key.clone(), hash);
            }
        }
        let caps = invocation.0.capabilities.clone();
        let invoker = invocation.0.invoker.clone();
        // Extract capabilities read params from UCAN facts field
        // Facts is Vec<JsonValue>, we look for an object with capabilitiesReadParams key
        let caps_read_params: Option<CapabilitiesReadParams> = invocation
            .0
            .invocation
            .payload()
            .facts
            .as_ref()
            .and_then(|facts| {
                facts.iter().find_map(|fact| {
                    fact.as_object()
                        .and_then(|obj| obj.get("capabilitiesReadParams"))
                        .and_then(|v| serde_json::from_value(v.clone()).ok())
                })
            });
        //  verify and commit invocation and kv operations
        let commit = transact(
            &tx,
            &self.storage,
            &self.secrets,
            vec![Event::Invocation(Box::new(invocation), ops)],
            self.encryption.as_ref(),
        )
        .await
        .map_err(|error| {
            if has_preconditions && is_serialization_failure(&error) {
                TxStoreError::KvSerializationConflict
            } else {
                TxStoreError::Tx(error)
            }
        })?;

        let mut results = Vec::new();
        // perform and record side effects
        for cap in caps.iter().filter_map(|c| {
            c.resource.tinycloud_resource().and_then(|r| {
                Some((
                    r.space(),
                    r.service().as_str(),
                    // TC-119: resolve deprecated aliases to canonical (see the
                    // staging loop above) — identity for canonical URNs.
                    crate::policy_capability::resolve_alias(c.ability.as_ref().as_ref()),
                    r.path()?,
                ))
            })
        }) {
            match cap {
                (space, "kv", "tinycloud.kv/get", path) => {
                    let data =
                        get_kv(&tx, &self.storage, space, path)
                            .await
                            .map_err(|e| match e {
                                EitherError::A(e) => TxStoreError::Tx(e.into()),
                                EitherError::B(e) => TxStoreError::StoreRead(e),
                            })?;
                    if let (Some(limit), Some((_, _, content))) =
                        (options.max_response_bytes, data.as_ref())
                    {
                        if content.len() > limit {
                            return Err(TxStoreError::KvResponseTooLarge {
                                size: content.len(),
                                limit,
                            });
                        }
                    }
                    results.push(InvocationOutcome::KvRead(data));
                }
                (space, "kv", "tinycloud.kv/list", path) => {
                    let (list, truncated) =
                        list_bounded(&tx, space, path, options.list_limit).await?;
                    results.push(InvocationOutcome::KvList(list, truncated))
                }
                (space, "kv", "tinycloud.kv/del", path) => {
                    // KV deletion is logical. Blobs are content-addressed and may be
                    // shared by live sibling keys or retained version history.
                    results.push(InvocationOutcome::KvDelete(
                        deleted_hashes.get(&(space.clone(), path.clone())).copied(),
                    ))
                }
                (space, "kv", "tinycloud.kv/put", path) => {
                    if let Some(stage) = stages.remove(&(space.clone(), path.clone())) {
                        self.storage
                            .persist(space, stage)
                            .await
                            .map_err(TxStoreError::StoreWrite)?;
                        let hash = write_hashes
                            .get(&(space.clone(), path.clone()))
                            .copied()
                            .expect("staged KV writes have a content hash");
                        results.push(InvocationOutcome::KvWrite(hash))
                    }
                }
                (space, "kv", "tinycloud.kv/metadata", path) => results.push(
                    InvocationOutcome::KvMetadata(metadata_with_hash(&tx, space, path).await?),
                ),
                (space, "capabilities", "tinycloud.capabilities/read", path)
                    if path.as_str() == "all" =>
                {
                    match &caps_read_params {
                        None => {
                            // Backward compatible: no params means return all valid delegations
                            results.push(InvocationOutcome::OpenSessions(
                                get_valid_delegations(&tx, space, self.encryption.as_ref()).await?,
                            ))
                        }
                        Some(CapabilitiesReadParams::List { filters }) => {
                            // List with optional filters
                            results.push(InvocationOutcome::OpenSessions(
                                get_filtered_delegations(
                                    &tx,
                                    space,
                                    &invoker,
                                    filters.as_ref(),
                                    self.encryption.as_ref(),
                                )
                                .await?,
                            ))
                        }
                        Some(CapabilitiesReadParams::Chain { delegation_cid }) => {
                            // Get the delegation chain for a specific delegation
                            results.push(InvocationOutcome::DelegationChain(
                                get_delegation_chain(
                                    &tx,
                                    space,
                                    delegation_cid,
                                    self.encryption.as_ref(),
                                )
                                .await?,
                            ))
                        }
                    }
                }
                _ => {}
            };
        }

        // commit tx if all side effects worked
        tx.commit().await.map_err(|error| {
            if has_preconditions && is_serialization_db_error(&error) {
                TxStoreError::KvSerializationConflict
            } else {
                TxStoreError::Tx(error.into())
            }
        })?;
        Ok((commit, results))
    }
}

fn chain_isolation_level<C: ConnectionTrait>(db: &C) -> Option<sea_orm::IsolationLevel> {
    match db.get_database_backend() {
        // SQLite's default transaction mode is serializable; sqlx rejects an
        // explicit SET TRANSACTION isolation statement for SQLite.
        sea_orm::DatabaseBackend::Sqlite => None,
        sea_orm::DatabaseBackend::Postgres | sea_orm::DatabaseBackend::MySql => {
            // Revocation ordering is enforced by the chain-scoped guards held
            // through commit. SERIALIZABLE also made unrelated chains contend
            // on the shared epoch-tip read/write path, producing routine 40001
            // aborts for every authenticated operation class.
            Some(sea_orm::IsolationLevel::ReadCommitted)
        }
    }
}

/// Find an active (non-revoked) delegation from `delegator` whose bound
/// `computeFunctionBinding` caveat names `old_content_cid`, for
/// `SpaceDatabase::compute_deploy`'s re-deploy hygiene step (§5.1). Scoped
/// to `delegator` so this can never surface (let alone revoke) another
/// principal's delegation.
#[cfg(feature = "compute")]
async fn find_superseded_compute_delegation<C: ConnectionTrait>(
    db: &C,
    delegator: &str,
    old_content_cid: &str,
) -> Result<Option<Hash>, DbErr> {
    let expected = crate::compute::compute_function_binding_caveat(old_content_cid);
    let candidates = delegation::Entity::find()
        .filter(delegation::Column::Delegator.eq(delegator.to_string()))
        .find_with_related(abilities::Entity)
        .all(db)
        .await?;
    for (candidate, caps) in candidates {
        if revocation::is_revoked(db, &candidate.id).await? {
            continue;
        }
        if caps
            .iter()
            .any(|c| c.caveats.0.values().any(|v| *v == expected))
        {
            return Ok(Some(candidate.id));
        }
    }
    Ok(None)
}

/// Insert a NODE-INTERNAL revocation row directly (bypassing the signed
/// `/revoke` path -- see `compute_deploy`'s doc comment for why this is
/// safe here). Idempotent: a repeat call for the same `revoked` hash is a
/// no-op (`OnConflict::do_nothing`).
#[cfg(feature = "compute")]
async fn insert_internal_revocation<C: ConnectionTrait>(
    db: &C,
    revoker: &str,
    revoked: Hash,
) -> Result<(), DbErr> {
    let marker = format!(
        "compute/superseded-redeploy-revocation/{}",
        revoked.to_cid(0x55)
    );
    let id = crate::hash::hash(marker.as_bytes());
    match revocation::Entity::insert(revocation::ActiveModel {
        id: Set(id),
        revoker: Set(revoker.to_string()),
        revoked: Set(revoked),
        serialization: Set(marker.into_bytes()),
        revoked_at: Set(Some(OffsetDateTime::now_utc())),
    })
    .on_conflict(OnConflict::column(revocation::Column::Id).do_nothing().to_owned())
    .exec(db)
    .await
    {
        Err(DbErr::RecordNotInserted) => Ok(()),
        r => {
            r?;
            Ok(())
        }
    }
}

fn conditional_kv_isolation_level<C: ConnectionTrait>(db: &C) -> Option<sea_orm::IsolationLevel> {
    conditional_kv_isolation_for_backend(db.get_database_backend())
}

fn conditional_kv_isolation_for_backend(
    backend: sea_orm::DatabaseBackend,
) -> Option<sea_orm::IsolationLevel> {
    match backend {
        sea_orm::DatabaseBackend::Sqlite => None,
        sea_orm::DatabaseBackend::Postgres | sea_orm::DatabaseBackend::MySql => {
            Some(sea_orm::IsolationLevel::Serializable)
        }
    }
}

fn is_serialization_failure<S: StorageSetup, K: Secrets>(error: &TxError<S, K>) -> bool {
    match error {
        TxError::Db(error) | TxError::EpochInsert(error) => is_serialization_db_error(error),
        _ => false,
    }
}

fn is_serialization_db_error(error: &DbErr) -> bool {
    matches!(
        error,
        DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(database_error)))
        | DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(database_error)))
            if matches!(
                database_error.code().as_deref(),
                Some("40001" | "40P01" | "1213" | "5" | "6" | "SQLITE_BUSY" | "SQLITE_LOCKED")
            )
    )
}

#[derive(Debug)]
pub enum InvocationOutcome<R> {
    KvList(Vec<Path>, bool),
    KvDelete(Option<Hash>),
    KvMetadata(Option<(Metadata, Hash)>),
    KvWrite(Hash),
    KvBatchWrite(Vec<Path>),
    KvRead(Option<(Metadata, Hash, Content<R>)>),
    OpenSessions(HashMap<Hash, DelegationInfo>),
    /// Ordered delegation chain from leaf to root
    DelegationChain(Vec<DelegationInfo>),
    SqlResult(serde_json::Value),
    SqlExport(Vec<u8>),
    DuckDbResult(serde_json::Value),
    DuckDbExport(Vec<u8>),
    DuckDbArrow(Vec<u8>),
}

impl<S: StorageSetup, K: Secrets> From<delegation::Error> for TxError<S, K> {
    fn from(e: delegation::Error) -> Self {
        match e {
            delegation::Error::InvalidDelegation(e) => Self::InvalidDelegation(e),
            delegation::Error::Db(e) => Self::Db(e),
        }
    }
}

impl<S: StorageSetup, K: Secrets> From<invocation::Error> for TxError<S, K> {
    fn from(e: invocation::Error) -> Self {
        match e {
            invocation::Error::InvalidInvocation(e) => Self::InvalidInvocation(e),
            invocation::Error::Db(e) => Self::Db(e),
        }
    }
}

impl<S: StorageSetup, K: Secrets> From<revocation::Error> for TxError<S, K> {
    fn from(e: revocation::Error) -> Self {
        match e {
            revocation::Error::InvalidRevocation(e) => Self::InvalidRevocation(e),
            revocation::Error::Db(e) => Self::Db(e),
        }
    }
}

async fn event_spaces<'a, C: ConnectionTrait>(
    db: &C,
    ev: &'a [(Hash, Event)],
) -> Result<HashMap<SpaceId, Vec<&'a (Hash, Event)>>, DbErr> {
    // get orderings of events listed as revoked by events in the ev list
    let mut spaces = HashMap::<SpaceId, Vec<&'a (Hash, Event)>>::new();
    let revoked_events = event_order::Entity::find()
        .filter(
            event_order::Column::Event.is_in(ev.iter().filter_map(|(_, e)| match e {
                Event::Revocation(r) => Some(Hash::from(r.0.revoked)),
                _ => None,
            })),
        )
        .all(db)
        .await?;
    for e in ev {
        match &e.1 {
            Event::Delegation(d) => {
                for space in d.0.spaces() {
                    let entry = spaces.entry(space.clone()).or_default();
                    if !entry.iter().any(|(h, _)| h == &e.0) {
                        entry.push(e);
                    }
                }
            }
            Event::Invocation(i, _) => {
                for space in i.0.spaces() {
                    let entry = spaces.entry(space.clone()).or_default();
                    if !entry.iter().any(|(h, _)| h == &e.0) {
                        entry.push(e);
                    }
                }
            }
            Event::Revocation(r) => {
                let r_hash = Hash::from(r.0.revoked);
                for revoked in &revoked_events {
                    if r_hash == revoked.event {
                        let entry = spaces.entry(revoked.space.0.clone()).or_default();
                        if !entry.iter().any(|(h, _)| h == &e.0) {
                            entry.push(e);
                        }
                    }
                }
            }
        }
    }
    Ok(spaces)
}

pub(crate) async fn transact<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    store_setup: &S,
    secrets: &K,
    events: Vec<Event>,
    encryption: Option<&ColumnEncryption>,
) -> Result<TransactResult, TxError<S, K>> {
    // for each event, get the hash and the relevent space(s)
    let event_hashes = events
        .into_iter()
        .map(|e| (e.hash(), e))
        .collect::<Vec<(Hash, Event)>>();
    let event_spaces = event_spaces(db, &event_hashes).await?;
    let mut new_spaces = event_hashes
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Delegation(d) => Some(d.0.capabilities.iter().filter_map(|c| {
                match (&c.resource, c.ability.as_ref().as_ref()) {
                    (Resource::TinyCloud(r), "tinycloud.space/host")
                        if r.path().is_none()
                            && r.service().as_str() == "space"
                            && r.query().is_none()
                            && r.fragment().is_none() =>
                    {
                        Some(SpaceIdWrap(r.space().clone()))
                    }
                    _ => None,
                }
            })),
            _ => None,
        })
        .flatten()
        .collect::<Vec<SpaceIdWrap>>();
    new_spaces.dedup();

    if !new_spaces.is_empty() {
        match space::Entity::insert_many(
            new_spaces
                .iter()
                .cloned()
                .map(|id| space::Model { id })
                .map(space::ActiveModel::from),
        )
        .on_conflict(
            OnConflict::column(space::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec(db)
        .await
        {
            Err(DbErr::RecordNotInserted) => (),
            r => {
                r?;
            }
        };
    }

    // For delegation-only transactions, skip spaces that don't exist yet
    // instead of failing with SpaceNotFound
    let is_delegation_only = event_hashes
        .iter()
        .all(|(_, e)| matches!(e, Event::Delegation(_)));

    let (event_spaces, skipped_spaces) = if is_delegation_only {
        let new_space_ids: HashSet<SpaceId> = new_spaces.iter().map(|s| s.0.clone()).collect();
        // Spaces that were just created via new_spaces are definitely existing
        let all_space_ids: Vec<SpaceIdWrap> = event_spaces
            .keys()
            .filter(|s| !new_space_ids.contains(s))
            .cloned()
            .map(SpaceIdWrap)
            .collect();

        let existing: HashSet<SpaceId> = if all_space_ids.is_empty() {
            HashSet::new()
        } else {
            space::Entity::find()
                .filter(space::Column::Id.is_in(all_space_ids))
                .all(db)
                .await?
                .into_iter()
                .map(|s| s.id.0)
                .collect()
        };

        // new_spaces are always existing (just inserted above)
        let existing: HashSet<SpaceId> = existing.into_iter().chain(new_space_ids).collect();

        let skipped: Vec<SpaceId> = event_spaces
            .keys()
            .filter(|s| !existing.contains(s))
            .cloned()
            .collect();

        let filtered: HashMap<_, _> = event_spaces
            .into_iter()
            .filter(|(s, _)| existing.contains(s))
            .collect();

        (filtered, skipped)
    } else {
        // Non-delegation-only txns must reference spaces that already exist
        // (or are created in this same txn via `new_spaces`). A missing space
        // is a genuine SpaceNotFound (404); checking up-front lets an FK
        // violation on the epoch insert be treated as an integrity error (500)
        // rather than silently coerced to 404.
        let new_space_ids: HashSet<SpaceId> = new_spaces.iter().map(|s| s.0.clone()).collect();
        let to_check: Vec<SpaceIdWrap> = event_spaces
            .keys()
            .filter(|s| !new_space_ids.contains(s))
            .cloned()
            .map(SpaceIdWrap)
            .collect();
        if !to_check.is_empty() {
            let existing: HashSet<SpaceId> = space::Entity::find()
                .filter(space::Column::Id.is_in(to_check))
                .all(db)
                .await?
                .into_iter()
                .map(|s| s.id.0)
                .collect();
            if event_spaces
                .keys()
                .any(|s| !new_space_ids.contains(s) && !existing.contains(s))
            {
                return Err(TxError::SpaceNotFound);
            }
        }
        (event_spaces, vec![])
    };

    // If all spaces were filtered out, we still process delegations below
    // but skip epoch/event ordering creation
    if !event_spaces.is_empty() {
        // get max sequence for each of the spaces
        let mut max_seqs = event_order::Entity::find()
            .filter(event_order::Column::Space.is_in(event_spaces.keys().cloned().map(SpaceIdWrap)))
            .select_only()
            .column(event_order::Column::Space)
            .column_as(event_order::Column::Seq.max(), "max_seq")
            .group_by(event_order::Column::Space)
            .into_tuple::<(SpaceIdWrap, i64)>()
            .all(db)
            .await?
            .into_iter()
            .fold(HashMap::new(), |mut m, (space, seq)| {
                m.insert(space, seq + 1);
                m
            });

        // get 'most recent' epochs for each of the spaces
        let mut most_recent = epoch::Entity::find()
            .select_only()
            .left_join(epoch_order::Entity)
            .filter(
                Condition::all()
                    .add(epoch::Column::Space.is_in(event_spaces.keys().cloned().map(SpaceIdWrap)))
                    .add(epoch_order::Column::Child.is_null()),
            )
            .column(epoch::Column::Space)
            .column(epoch::Column::Id)
            .into_tuple::<(SpaceIdWrap, Hash)>()
            .all(db)
            .await?
            .into_iter()
            .fold(
                HashMap::new(),
                |mut m: HashMap<SpaceIdWrap, Vec<Hash>>, (space, epoch)| {
                    m.entry(space).or_default().push(epoch);
                    m
                },
            );

        // get all the orderings and associated data
        let (epoch_order, space_order, event_order, epochs) = event_spaces
            .into_iter()
            .map(|(space, events)| {
                let parents = most_recent.remove(&space).unwrap_or_default();
                let epoch = epoch_hash(&space, &events, &parents)?;
                let seq = max_seqs.remove(&space).unwrap_or(0);
                Ok((space, (epoch, events, seq, parents)))
            })
            .collect::<Result<HashMap<_, _>, HashError>>()?
            .into_iter()
            .map(|(space, (epoch, hashes, seq, parents))| {
                (
                    parents
                        .iter()
                        .map(|parent| epoch_order::Model {
                            parent: *parent,
                            child: epoch,
                            space: space.clone().into(),
                        })
                        .map(epoch_order::ActiveModel::from)
                        .collect::<Vec<epoch_order::ActiveModel>>(),
                    (
                        space.clone(),
                        (
                            seq,
                            epoch,
                            parents,
                            hashes
                                .iter()
                                .enumerate()
                                .map(|(i, (h, _))| (*h, i as i64))
                                .collect::<HashMap<_, _>>(),
                        ),
                    ),
                    hashes
                        .into_iter()
                        .enumerate()
                        .map(|(es, (hash, _))| event_order::Model {
                            event: *hash,
                            space: space.clone().into(),
                            seq,
                            epoch,
                            epoch_seq: es as i64,
                        })
                        .map(event_order::ActiveModel::from)
                        .collect::<Vec<event_order::ActiveModel>>(),
                    epoch::Model {
                        seq,
                        id: epoch,
                        space: space.into(),
                    },
                )
            })
            .fold(
                (
                    Vec::<epoch_order::ActiveModel>::new(),
                    HashMap::<SpaceId, (i64, Hash, Vec<Hash>, HashMap<Hash, i64>)>::new(),
                    Vec::<event_order::ActiveModel>::new(),
                    Vec::<epoch::ActiveModel>::new(),
                ),
                |(mut eo, mut so, mut ev, mut ep), (eo2, order, ev2, ep2)| {
                    eo.extend(eo2);
                    ev.extend(ev2);
                    so.insert(order.0, order.1);
                    ep.push(ep2.into());
                    (eo, so, ev, ep)
                },
            );

        // save epochs
        epoch::Entity::insert_many(epochs)
            .exec(db)
            .await
            .map_err(|e| {
                if let DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(db_err))) = &e {
                    tracing::error!(
                        error = %e,
                        db_error = %db_err,
                        db_error_code = ?db_err.code(),
                        db_error_kind = ?db_err.kind(),
                        "epoch insert failed with database error after space pre-check; \
                         treating as integrity error"
                    );
                } else {
                    tracing::error!(error = %e, "epoch insert failed");
                }
                TxError::EpochInsert(e)
            })?;

        // save epoch orderings
        if !epoch_order.is_empty() {
            epoch_order::Entity::insert_many(epoch_order)
                .exec(db)
                .await?;
        }

        // save event orderings
        event_order::Entity::insert_many(event_order)
            .exec(db)
            .await?;

        let mut delegation_cids = Vec::new();
        for (hash, event) in event_hashes {
            match event {
                Event::Delegation(d) => {
                    let cid = delegation::process(db, *d, encryption).await?;
                    delegation_cids.push(cid);
                }
                Event::Invocation(i, ops) => {
                    invocation::process(
                        db,
                        *i,
                        ops.into_iter()
                            .map(|op| {
                                let v = space_order
                                    .get(op.space())
                                    .and_then(|(s, e, _, h)| Some((s, e, h.get(&hash)?)))
                                    .unwrap();
                                op.version(*v.0, *v.1, *v.2)
                            })
                            .collect(),
                        encryption,
                    )
                    .await?;
                }
                Event::Revocation(r) => {
                    revocation::process(db, *r).await?;
                }
            };
        }

        for space in new_spaces {
            store_setup
                .create(&space.0)
                .await
                .map_err(TxError::StoreSetup)?;
            secrets
                .save_keypair(&space.0)
                .await
                .map_err(TxError::Secrets)?;
        }

        Ok(TransactResult {
            commits: space_order
                .into_iter()
                .map(|(o, (seq, rev, consumed_epochs, h))| {
                    (
                        o,
                        Commit {
                            seq,
                            rev,
                            consumed_epochs,
                            committed_events: h.keys().cloned().collect(),
                        },
                    )
                })
                .collect(),
            skipped_spaces,
            delegation_cids,
        })
    } else {
        // All spaces were skipped (delegation-only with no existing spaces)
        // Still process delegation events to save the delegation records
        let mut delegation_cids = Vec::new();
        for (_, event) in event_hashes {
            match event {
                Event::Delegation(d) => {
                    let cid = delegation::process(db, *d, encryption).await?;
                    delegation_cids.push(cid);
                }
                Event::Invocation(i, _ops) => {
                    invocation::process(db, *i, Vec::new(), encryption).await?;
                }
                Event::Revocation(r) => {
                    revocation::process(db, *r).await?;
                }
            };
        }

        for space in new_spaces {
            store_setup
                .create(&space.0)
                .await
                .map_err(TxError::StoreSetup)?;
            secrets
                .save_keypair(&space.0)
                .await
                .map_err(TxError::Secrets)?;
        }

        Ok(TransactResult {
            commits: HashMap::new(),
            skipped_spaces,
            delegation_cids,
        })
    }
}

async fn list<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    prefix: &Path,
) -> Result<Vec<Path>, DbErr> {
    list_bounded(db, space_id, prefix, None)
        .await
        .map(|(paths, _)| paths)
}

async fn list_bounded<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    prefix: &Path,
    limit: Option<usize>,
) -> Result<(Vec<Path>, bool), DbErr> {
    let newer = Alias::new("newer_kv_write");
    let newer_order = Condition::any()
        .add(
            Expr::col((newer.clone(), kv_write::Column::Seq))
                .gt(Expr::col((kv_write::Entity, kv_write::Column::Seq))),
        )
        .add(
            Condition::all()
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Seq))
                        .equals((kv_write::Entity, kv_write::Column::Seq)),
                )
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Epoch))
                        .gt(Expr::col((kv_write::Entity, kv_write::Column::Epoch))),
                ),
        )
        .add(
            Condition::all()
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Seq))
                        .equals((kv_write::Entity, kv_write::Column::Seq)),
                )
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Epoch))
                        .equals((kv_write::Entity, kv_write::Column::Epoch)),
                )
                .add(
                    Expr::col((newer.clone(), kv_write::Column::EpochSeq))
                        .gt(Expr::col((kv_write::Entity, kv_write::Column::EpochSeq))),
                ),
        );
    let newer_write = Query::select()
        .expr(Expr::val(1))
        .from_as(kv_write::Entity, newer.clone())
        .cond_where(
            Condition::all()
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Space))
                        .equals((kv_write::Entity, kv_write::Column::Space)),
                )
                .add(
                    Expr::col((newer.clone(), kv_write::Column::Key))
                        .equals((kv_write::Entity, kv_write::Column::Key)),
                )
                .add(newer_order),
        )
        .to_owned();
    let escaped_prefix = prefix
        .as_str()
        .replace('!', "!!")
        .replace('%', "!%")
        .replace('_', "!_");
    let mut query = Query::select();
    query
        .column((kv_write::Entity, kv_write::Column::Key))
        .from(kv_write::Entity)
        .left_join(
            kv_delete::Entity,
            Condition::all()
                .add(
                    Expr::col((kv_write::Entity, kv_write::Column::Space))
                        .equals((kv_delete::Entity, kv_delete::Column::Space)),
                )
                .add(
                    Expr::col((kv_write::Entity, kv_write::Column::Key))
                        .equals((kv_delete::Entity, kv_delete::Column::Key)),
                )
                .add(
                    Expr::col((kv_write::Entity, kv_write::Column::Invocation))
                        .equals((kv_delete::Entity, kv_delete::Column::DeletedInvocationId)),
                ),
        )
        .cond_where(
            Condition::all()
                .add(
                    Expr::col((kv_write::Entity, kv_write::Column::Key))
                        .like(LikeExpr::new(format!("{escaped_prefix}%")).escape('!')),
                )
                .add(
                    Expr::col((kv_write::Entity, kv_write::Column::Space))
                        .eq(SpaceIdWrap(space_id.clone())),
                )
                .add(Expr::col((kv_delete::Entity, kv_delete::Column::InvocationId)).is_null())
                .add(Condition::all().not().add(Expr::exists(newer_write))),
        )
        .order_by((kv_write::Entity, kv_write::Column::Key), Order::Asc);
    if let Some(limit) = limit {
        query.limit(limit.saturating_add(1) as u64);
    }
    let mut list = db
        .query_all(db.get_database_backend().build(&query))
        .await?
        .into_iter()
        .map(|row| row.try_get::<String>("", kv_write::Column::Key.as_str()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|key| key.parse())
        .collect::<Result<Vec<Path>, _>>()
        .map_err(|error| DbErr::Custom(format!("invalid persisted KV path: {error}")))?;
    let truncated = limit.map(|limit| list.len() > limit).unwrap_or(false);
    if let Some(limit) = limit {
        list.truncate(limit);
    }
    Ok((list, truncated))
}

async fn metadata<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    key: &Path,
    // TODO version: Option<(i64, Hash, i64)>,
) -> Result<Option<Metadata>, DbErr> {
    Ok(metadata_with_hash(db, space_id, key)
        .await?
        .map(|(metadata, _)| metadata))
}

async fn metadata_with_hash<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    key: &Path,
) -> Result<Option<(Metadata, Hash)>, DbErr> {
    match get_kv_entity(db, space_id, key).await? {
        Some(entry) => Ok(Some((entry.metadata, entry.value))),
        None => Ok(None),
    }
}

async fn get_kv<C: ConnectionTrait, B: ImmutableReadStore>(
    db: &C,
    store: &B,
    space_id: &SpaceId,
    key: &Path,
    // TODO version: Option<(i64, Hash, i64)>,
) -> Result<Option<(Metadata, Hash, Content<B::Readable>)>, EitherError<DbErr, B::Error>> {
    let e = match get_kv_entity(db, space_id, key)
        .await
        .map_err(EitherError::A)?
    {
        Some(entry) => entry,
        None => return Ok(None),
    };
    let content_hash = e.value;
    let c = match store
        .read(space_id, &content_hash)
        .await
        .map_err(EitherError::B)?
    {
        Some(c) => c,
        None => return Ok(None),
    };
    Ok(Some((e.metadata, content_hash, c)))
}

async fn get_kv_entity<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    key: &Path,
    // TODO version: Option<(i64, Hash, i64)>,
) -> Result<Option<kv_write::Model>, DbErr> {
    // Ok(if let Some((seq, epoch, epoch_seq)) = version {
    //     event_order::Entity::find_by_id((epoch, epoch_seq, space_id.clone().into()))
    //         .reverse_join(kv_write::Entity)
    //         .find_also_related(kv_delete::Entity)
    //         .filter(
    //             Condition::all()
    //                 .add(kv_write::Column::Key.eq(key))
    //                 .add(kv_write::Column::Space.eq(space_id.clone().into()))
    //                 .add(kv_delete::Column::InvocationId.is_null()),
    //         )
    //         .one(db)
    //         .await?
    //         .map(|(kv, _)| kv)
    // } else {
    // A delete tombstones the latest write. Select that write before checking
    // its tombstone so older versions cannot reappear after deletion.
    Ok(
        match kv_write::Entity::find()
            .filter(
                Condition::all()
                    .add(kv_write::Column::Key.eq(key.as_str()))
                    .add(kv_write::Column::Space.eq(SpaceIdWrap(space_id.clone()))),
            )
            .order_by_desc(kv_write::Column::Seq)
            .order_by_desc(kv_write::Column::Epoch)
            .order_by_desc(kv_write::Column::EpochSeq)
            .find_also_related(kv_delete::Entity)
            .one(db)
            .await?
        {
            Some((_, Some(_))) | None => None,
            Some((kv, None)) => Some(kv),
        },
    )
}

async fn get_valid_delegations<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    space_id: &SpaceId,
    encryption: Option<&ColumnEncryption>,
) -> Result<HashMap<Hash, DelegationInfo>, TxError<S, K>> {
    let (dels, abilities): (Vec<delegation::Model>, Vec<Vec<abilities::Model>>) =
        delegation::Entity::find()
            .left_join(revocation::Entity)
            .filter(revocation::Column::Id.is_null())
            .find_with_related(abilities::Entity)
            .all(db)
            .await?
            .into_iter()
            .unzip();
    let parents = dels.load_many(parent_delegations::Entity, db).await?;
    let now = time::OffsetDateTime::now_utc();
    dels.into_iter()
        .zip(abilities)
        .zip(parents)
        .filter_map(|((del, ability), parents)| {
            if del.expiry.map(|e| e > now).unwrap_or(true)
                && del.not_before.map(|n| n <= now).unwrap_or(true)
                && ability.iter().any(|a| a.resource.space() == Some(space_id))
            {
                let serialization =
                    match crate::encryption::maybe_decrypt(encryption, &del.serialization) {
                        Ok(s) => s,
                        Err(e) => return Some(Err(TxError::Encryption(e))),
                    };
                Some(match TinyCloudDelegation::from_bytes(&serialization) {
                    Ok(delegation) => Ok((
                        del.id,
                        DelegationInfo {
                            delegator: del.delegator,
                            delegate: del.delegatee,
                            parents: parents.into_iter().map(|p| p.parent.to_cid(0x55)).collect(),
                            expiry: del.expiry,
                            not_before: del.not_before,
                            issued_at: del.issued_at,
                            delegation_mode: mode_from_facts(&del.facts),
                            capabilities: ability
                                .into_iter()
                                .map(|a| Capability {
                                    resource: a.resource,
                                    ability: a.ability,
                                    caveats: a.caveats,
                                })
                                .collect(),
                            delegation,
                        },
                    )),
                    Err(e) => Err(TxError::Encoding(e)),
                })
            } else {
                None
            }
        })
        .collect::<Result<HashMap<Hash, DelegationInfo>, TxError<S, K>>>()
}

/// Decode the persisted `xyz.tinycloud.policy/delegationMode` marker from
/// a stored delegation row's facts column.
fn mode_from_facts(facts: &Option<crate::types::Facts>) -> DelegationMode {
    facts
        .as_ref()
        .and_then(|f| f.0.get(DelegationMode::FACT_KEY).and_then(|v| v.as_str()))
        .map(|s| {
            if s == "terminal" {
                DelegationMode::Terminal
            } else {
                DelegationMode::Attenuable
            }
        })
        .unwrap_or(DelegationMode::Attenuable)
}

/// Resolve a session key DID (did:key:...) to its root PKH DID (did:pkh:...).
///
/// Session keys are delegated to from PKH DIDs. This function traverses the delegation
/// chain to find the root PKH DID that authorized the session key.
///
/// Returns the original DID if it's already a PKH DID or if no delegation chain is found.
async fn resolve_pkh_did<C: ConnectionTrait>(db: &C, did: &str) -> Result<String, DbErr> {
    let canonical_did = canonicalize_did(did).unwrap_or_else(|_| did.to_string());

    // If already a PKH DID, return it directly
    if canonical_did.starts_with("did:pkh:") {
        return Ok(canonical_did);
    }

    // Look for a delegation where this DID is the delegatee
    // The delegator would be the next step up in the chain
    let mut current_did = canonical_did.clone();
    let mut visited = std::collections::HashSet::new();

    loop {
        // Prevent infinite loops
        if !visited.insert(current_did.clone()) {
            break;
        }

        // Find a delegation where current_did is the delegatee
        let parent_delegation = delegation::Entity::find()
            .filter(delegation::Column::Delegatee.eq(&current_did))
            .one(db)
            .await?;

        match parent_delegation {
            Some(del) => {
                // Found a parent - check if it's a PKH DID
                if del.delegator.starts_with("did:pkh:") {
                    return Ok(canonicalize_did(&del.delegator).unwrap_or(del.delegator));
                }
                // Continue up the chain
                current_did = canonicalize_did(&del.delegator).unwrap_or(del.delegator);
            }
            None => {
                // No parent found - return what we have
                break;
            }
        }
    }

    // Return the original DID if we couldn't resolve to a PKH
    Ok(canonical_did)
}

async fn account_query_principal<C: ConnectionTrait>(
    db: &C,
    invocation: &crate::util::InvocationInfo,
) -> Result<Option<String>, DbErr> {
    let [capability] = invocation.capabilities.as_slice() else {
        return Ok(None);
    };
    if capability.ability.as_ref().as_ref() != "tinycloud.delegation/list" {
        return Ok(None);
    }
    let Resource::TinyCloud(resource) = &capability.resource else {
        return Ok(None);
    };
    if resource.service().as_str() != "delegation"
        || resource
            .path()
            .is_some_and(|path| !path.as_str().is_empty())
        || resource.query().is_some()
        || resource.fragment().is_some()
    {
        return Ok(None);
    }
    let principal = canonicalize_did(resource.space().did().as_str())
        .unwrap_or_else(|_| resource.space().did().as_str().to_string());
    if !principal.starts_with("did:pkh:") {
        return Ok(None);
    }
    if invocation.parents.is_empty() {
        return Ok(did_principal_matches(&principal, &invocation.invoker).then_some(principal));
    }
    if invocation.parents.len() != 1 {
        return Ok(None);
    }
    let proof_id = Hash::from(invocation.parents[0]);
    let chain_ids = match revocation::ancestor_chain_ids(db, &proof_id).await {
        Ok(ids) => ids,
        Err(revocation::ChainTraversalError::Db(error)) => return Err(error),
        Err(revocation::ChainTraversalError::LimitExceeded) => return Ok(None),
    };
    let chain = delegation::Entity::find()
        .filter(delegation::Column::Id.is_in(chain_ids.iter().copied()))
        .all(db)
        .await?;
    Ok(chain
        .iter()
        .any(|delegation| did_principal_matches(&delegation.delegator, &principal))
        .then_some(principal))
}

const MAX_ACCOUNT_SESSION_NODES: usize = 256;
const MAX_ACCOUNT_SESSION_EDGES_PER_LEVEL: u64 = 1025;
const MAX_ACCOUNT_ANCESTOR_NODES: usize = 4096;

/// Discover only session/control DIDs that were delegated the account's list
/// capability. Ordinary recipients are deliberately not pulled into the
/// account relationship graph.
async fn account_session_dids<C: ConnectionTrait>(
    db: &C,
    principal: &str,
) -> Result<HashSet<String>, DbErr> {
    let mut account_dids = HashSet::from([principal.to_string()]);
    let mut frontier = vec![principal.to_string()];
    for _ in 0..revocation::MAX_CHAIN_TRAVERSAL_NODES {
        if frontier.is_empty() {
            return Ok(account_dids);
        }
        let rows = delegation::Entity::find()
            .filter(delegation::Column::Delegator.is_in(frontier.clone()))
            .limit(MAX_ACCOUNT_SESSION_EDGES_PER_LEVEL)
            .find_with_related(abilities::Entity)
            .all(db)
            .await?;
        if rows.len() as u64 == MAX_ACCOUNT_SESSION_EDGES_PER_LEVEL {
            return Err(DbErr::Custom(
                "account-session-graph-level-limit-exceeded".to_string(),
            ));
        }
        let mut next = Vec::new();
        for (delegation, abilities) in rows {
            let controls_account = abilities.iter().any(|ability| {
                ability.ability.as_ref().as_ref() == "tinycloud.delegation/list"
                    && ability
                        .resource
                        .tinycloud_resource()
                        .is_some_and(|resource| {
                            resource.service().as_str() == "delegation"
                                && resource
                                    .path()
                                    .map(|path| path.as_str().is_empty())
                                    .unwrap_or(true)
                                && resource.query().is_none()
                                && resource.fragment().is_none()
                                && did_principal_matches(resource.space().did().as_str(), principal)
                        })
            });
            if controls_account
                && delegation.delegatee.starts_with("did:key:")
                && account_dids.insert(delegation.delegatee.clone())
            {
                next.push(delegation.delegatee);
                if account_dids.len() > MAX_ACCOUNT_SESSION_NODES {
                    return Err(DbErr::Custom(
                        "account-session-graph-node-limit-exceeded".to_string(),
                    ));
                }
            }
        }
        next.sort();
        next.dedup();
        frontier = next;
    }
    Err(DbErr::Custom(
        "account-session-graph-depth-limit-exceeded".to_string(),
    ))
}

struct AccountAncestorState {
    parents: HashMap<Hash, Vec<Hash>>,
    delegations: HashMap<Hash, delegation::Model>,
    revocations: HashMap<Hash, Vec<revocation::Model>>,
}

struct AccountLifecycle {
    status: &'static str,
    direct_revocation: Option<revocation::Model>,
    revoked_ancestor_cid: Option<String>,
}

impl AccountAncestorState {
    fn lifecycle(&self, root: Hash, now: OffsetDateTime) -> Result<AccountLifecycle, DbErr> {
        let direct_revocation = self
            .revocations
            .get(&root)
            .and_then(|rows| rows.first())
            .cloned();
        if direct_revocation.is_some() {
            return Ok(AccountLifecycle {
                status: "revoked",
                direct_revocation,
                revoked_ancestor_cid: None,
            });
        }

        let mut frontier = self.parents.get(&root).cloned().unwrap_or_default();
        frontier.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
        let mut visited = HashSet::from([root]);
        let mut effective_ids = vec![root];
        while !frontier.is_empty() {
            let current_level = std::mem::take(&mut frontier);
            for current in current_level {
                if !visited.insert(current) {
                    continue;
                }
                if self
                    .revocations
                    .get(&current)
                    .is_some_and(|rows| !rows.is_empty())
                {
                    return Ok(AccountLifecycle {
                        status: "ancestor_revoked",
                        direct_revocation: None,
                        revoked_ancestor_cid: Some(current.to_cid(0x55).to_string()),
                    });
                }
                effective_ids.push(current);
                frontier.extend(self.parents.get(&current).cloned().unwrap_or_default());
            }
            frontier.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            frontier.dedup();
            if visited.len() > MAX_ACCOUNT_ANCESTOR_NODES {
                return Err(DbErr::Custom(
                    "account-ancestor-graph-node-limit-exceeded".to_string(),
                ));
            }
        }

        let effective = effective_ids
            .iter()
            .filter_map(|id| self.delegations.get(id))
            .collect::<Vec<_>>();
        if effective.len() != effective_ids.len() {
            return Err(DbErr::Custom(
                "account-ancestor-delegation-missing".to_string(),
            ));
        }
        let status = if effective
            .iter()
            .any(|row| row.expiry.is_some_and(|expiry| now >= expiry))
        {
            "expired"
        } else if effective
            .iter()
            .any(|row| row.not_before.is_some_and(|not_before| now < not_before))
        {
            "pending"
        } else {
            "active"
        };
        Ok(AccountLifecycle {
            status,
            direct_revocation: None,
            revoked_ancestor_cid: None,
        })
    }
}

async fn load_account_ancestor_state<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
) -> Result<AccountAncestorState, DbErr> {
    let mut all_ids = roots.iter().copied().collect::<HashSet<_>>();
    let mut frontier = roots.to_vec();
    let mut parents: HashMap<Hash, Vec<Hash>> = HashMap::new();
    for _ in 0..revocation::MAX_CHAIN_TRAVERSAL_NODES {
        if frontier.is_empty() {
            break;
        }
        let links = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.is_in(frontier))
            .all(db)
            .await?;
        let mut next = Vec::new();
        for link in links {
            parents.entry(link.child).or_default().push(link.parent);
            if all_ids.insert(link.parent) {
                next.push(link.parent);
                if all_ids.len() > MAX_ACCOUNT_ANCESTOR_NODES {
                    return Err(DbErr::Custom(
                        "account-ancestor-graph-node-limit-exceeded".to_string(),
                    ));
                }
            }
        }
        next.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
        next.dedup();
        frontier = next;
    }
    if !frontier.is_empty() {
        return Err(DbErr::Custom(
            "account-ancestor-graph-depth-limit-exceeded".to_string(),
        ));
    }
    for values in parents.values_mut() {
        values.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
        values.dedup();
    }
    let ids = all_ids.iter().copied().collect::<Vec<_>>();
    let delegation_rows = delegation::Entity::find()
        .filter(delegation::Column::Id.is_in(ids.iter().copied()))
        .all(db)
        .await?;
    let revocation_rows = revocation::Entity::find()
        .filter(revocation::Column::Revoked.is_in(ids))
        .all(db)
        .await?;
    let delegations = delegation_rows
        .into_iter()
        .map(|row| (row.id, row))
        .collect();
    let mut revocations: HashMap<Hash, Vec<revocation::Model>> = HashMap::new();
    for row in revocation_rows {
        revocations.entry(row.revoked).or_default().push(row);
    }
    for values in revocations.values_mut() {
        values.sort_by(|left, right| left.id.as_ref().cmp(right.id.as_ref()));
    }
    Ok(AccountAncestorState {
        parents,
        delegations,
        revocations,
    })
}

/// Get delegations with optional filters applied.
/// Filters by direction (created/received relative to invoker), path prefix, and actions.
async fn get_filtered_delegations<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    space_id: &SpaceId,
    invoker: &str,
    filters: Option<&ListFilters>,
    encryption: Option<&ColumnEncryption>,
) -> Result<HashMap<Hash, DelegationInfo>, TxError<S, K>> {
    // Resolve session key DID to PKH DID for direction filtering
    let pkh_did = resolve_pkh_did(db, invoker)
        .await
        .unwrap_or_else(|_| invoker.to_string());

    let (dels, abilities): (Vec<delegation::Model>, Vec<Vec<abilities::Model>>) =
        delegation::Entity::find()
            .left_join(revocation::Entity)
            .filter(revocation::Column::Id.is_null())
            .find_with_related(abilities::Entity)
            .all(db)
            .await?
            .into_iter()
            .unzip();
    let parents = dels.load_many(parent_delegations::Entity, db).await?;
    let now = time::OffsetDateTime::now_utc();

    // Extract filter values
    let direction = filters.and_then(|f| f.direction.as_deref());
    let path_prefix = filters.and_then(|f| f.path.as_deref());
    let actions = filters.and_then(|f| f.actions.as_ref());

    dels.into_iter()
        .zip(abilities)
        .zip(parents)
        .filter_map(|((del, ability), parents)| {
            // Time validity check
            if !(del.expiry.map(|e| e > now).unwrap_or(true)
                && del.not_before.map(|n| n <= now).unwrap_or(true))
            {
                return None;
            }

            // Space membership check
            if !ability.iter().any(|a| a.resource.space() == Some(space_id)) {
                return None;
            }

            // Direction filter (using resolved PKH DID, not session key DID)
            match direction {
                Some("created") if !did_principal_matches(&del.delegator, &pkh_did) => {
                    return None;
                }
                Some("received") if !did_principal_matches(&del.delegatee, &pkh_did) => {
                    return None;
                }
                _ => {}
            }

            // Path prefix filter
            if let Some(prefix) = path_prefix {
                let has_matching_path = ability.iter().any(|a| {
                    a.resource
                        .tinycloud_resource()
                        .and_then(|r| r.path())
                        .map(|p| p.as_str().starts_with(prefix))
                        .unwrap_or(false)
                });
                if !has_matching_path {
                    return None;
                }
            }

            // Actions filter
            if let Some(action_list) = actions {
                let has_matching_action = ability.iter().any(|a| {
                    action_list
                        .iter()
                        .any(|action| a.ability.as_ref().as_ref() == action.as_str())
                });
                if !has_matching_action {
                    return None;
                }
            }

            let serialization =
                match crate::encryption::maybe_decrypt(encryption, &del.serialization) {
                    Ok(s) => s,
                    Err(e) => return Some(Err(TxError::Encryption(e))),
                };
            Some(match TinyCloudDelegation::from_bytes(&serialization) {
                Ok(delegation) => Ok((
                    del.id,
                    DelegationInfo {
                        delegator: del.delegator,
                        delegate: del.delegatee,
                        parents: parents.into_iter().map(|p| p.parent.to_cid(0x55)).collect(),
                        expiry: del.expiry,
                        not_before: del.not_before,
                        issued_at: del.issued_at,
                        delegation_mode: mode_from_facts(&del.facts),
                        capabilities: ability
                            .into_iter()
                            .map(|a| Capability {
                                resource: a.resource,
                                ability: a.ability,
                                caveats: a.caveats,
                            })
                            .collect(),
                        delegation,
                    },
                )),
                Err(e) => Err(TxError::Encoding(e)),
            })
        })
        .collect::<Result<HashMap<Hash, DelegationInfo>, TxError<S, K>>>()
}

/// Get the delegation chain for a specific delegation, ordered from leaf to root.
/// The chain includes the requested delegation and all its ancestors.
async fn get_delegation_chain<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    db: &C,
    space_id: &SpaceId,
    delegation_cid: &str,
    encryption: Option<&ColumnEncryption>,
) -> Result<Vec<DelegationInfo>, TxError<S, K>> {
    use tinycloud_auth::ipld_core::cid::Cid;

    // Parse the delegation CID
    let cid: Cid = delegation_cid
        .parse()
        .map_err(|_| TxError::<S, K>::InvalidCid(delegation_cid.to_string()))?;
    let start_hash: Hash = cid.into();

    let mut chain = Vec::new();
    let mut current_hash = start_hash;
    let now = time::OffsetDateTime::now_utc();

    // Traverse the chain following parent relationships
    loop {
        // Find the delegation with this hash
        let del_with_abilities = delegation::Entity::find_by_id(current_hash)
            .left_join(revocation::Entity)
            .filter(revocation::Column::Id.is_null())
            .find_with_related(abilities::Entity)
            .all(db)
            .await?;

        if del_with_abilities.is_empty() {
            break;
        }

        let (del, ability) = del_with_abilities.into_iter().next().unwrap();

        // Time validity check
        if !(del.expiry.map(|e| e > now).unwrap_or(true)
            && del.not_before.map(|n| n <= now).unwrap_or(true))
        {
            break;
        }

        // Space membership check
        if !ability.iter().any(|a| a.resource.space() == Some(space_id)) {
            break;
        }

        // Get parent relationships
        let parents = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(current_hash))
            .all(db)
            .await?;

        let parent_cids: Vec<Cid> = parents.iter().map(|p| p.parent.to_cid(0x55)).collect();

        // Create DelegationInfo
        let serialization = crate::encryption::maybe_decrypt(encryption, &del.serialization)?;
        let delegation = TinyCloudDelegation::from_bytes(&serialization)?;
        let info = DelegationInfo {
            delegator: del.delegator,
            delegate: del.delegatee,
            parents: parent_cids.clone(),
            expiry: del.expiry,
            not_before: del.not_before,
            issued_at: del.issued_at,
            delegation_mode: mode_from_facts(&del.facts),
            capabilities: ability
                .into_iter()
                .map(|a| Capability {
                    resource: a.resource,
                    ability: a.ability,
                    caveats: a.caveats,
                })
                .collect(),
            delegation,
        };

        chain.push(info);

        // Move to the first parent (if any) to continue the chain
        // Note: We follow the first parent; for multiple parents, this gives one path
        if let Some(first_parent) = parents.into_iter().next() {
            current_hash = first_parent.parent;
        } else {
            // No more parents, we've reached the root
            break;
        }
    }

    Ok(chain)
}

#[cfg(test)]
mod test {
    use crate::{keys::StaticSecret, sql_sizes::SqlSizes, storage::memory::MemoryStore};

    use super::*;
    use sea_orm::{ConnectOptions, Database, DbBackend, Statement};
    use tinycloud_auth::{
        resolver::DID_METHODS,
        ssi::{dids::DIDBuf, jwk::JWK},
    };

    async fn get_db() -> Result<SpaceDatabase<sea_orm::DbConn, MemoryStore, StaticSecret>, DbErr> {
        SpaceDatabase::new(
            Database::connect(ConnectOptions::new("sqlite::memory:".to_string())).await?,
            MemoryStore::default(),
            StaticSecret::new([0u8; 32].to_vec()).unwrap(),
        )
        .await
    }

    fn test_space_id(name: &str) -> SpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, name.parse().unwrap())
    }

    #[tokio::test]
    async fn basic() {
        let _db = get_db().await.unwrap();
    }

    #[test]
    fn kv_preconditions_require_the_expected_object_state() {
        let current = crate::hash::hash(b"current");
        let other = crate::hash::hash(b"other");

        assert!(kv_precondition_matches(KvPrecondition::DoesNotExist, None));
        assert!(!kv_precondition_matches(
            KvPrecondition::DoesNotExist,
            Some(current)
        ));
        assert!(kv_precondition_matches(
            KvPrecondition::Matches(current.as_ref().try_into().unwrap()),
            Some(current)
        ));
        assert!(!kv_precondition_matches(
            KvPrecondition::Matches(other.as_ref().try_into().unwrap()),
            Some(current)
        ));
        assert!(!kv_precondition_matches(
            KvPrecondition::Matches(current.as_ref().try_into().unwrap()),
            None
        ));
    }

    #[test]
    fn conditional_kv_uses_cross_process_serializable_transactions() {
        assert_eq!(
            conditional_kv_isolation_for_backend(sea_orm::DatabaseBackend::Sqlite),
            None
        );
        for backend in [
            sea_orm::DatabaseBackend::Postgres,
            sea_orm::DatabaseBackend::MySql,
        ] {
            assert_eq!(
                conditional_kv_isolation_for_backend(backend),
                Some(sea_orm::IsolationLevel::Serializable)
            );
        }
    }

    #[tokio::test]
    async fn kv_object_guards_serialize_the_same_key() {
        let db = get_db().await.unwrap();
        let space = test_space_id("conditional-kv-lock");
        let key: Path = "files/report.txt".parse().unwrap();
        let first = db
            .acquire_kv_object_guards(&[(space.clone(), key.clone())])
            .await;

        let contender_db = db.clone();
        let contender_space = space.clone();
        let contender_key = key.clone();
        let contender = tokio::spawn(async move {
            contender_db
                .acquire_kv_object_guards(&[(contender_space, contender_key)])
                .await
        });
        tokio::task::yield_now().await;
        assert!(!contender.is_finished());

        let unrelated = db
            .acquire_kv_object_guards(&[(space, "files/other.txt".parse().unwrap())])
            .await;
        assert_eq!(unrelated.len(), 1);

        drop(first);
        assert_eq!(contender.await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn bounded_kv_list_counts_distinct_keys_in_order() {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        let db = get_db().await.unwrap();
        let space = test_space_id("bounded-kv-list");
        let actor_id = "did:key:bounded-kv-list";
        actor::ActiveModel {
            id: Set(actor_id.to_string()),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        space::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(&db.conn)
        .await
        .unwrap();

        let shared_value = crate::hash::hash(b"shared-value");
        for (index, key) in ["a", "a", "b", "c", "literal%key", "literalXkey"]
            .into_iter()
            .enumerate()
        {
            let invocation_id = crate::hash::hash(format!("invocation-{index}").as_bytes());
            let epoch_id = crate::hash::hash(format!("epoch-{index}").as_bytes());
            invocation::ActiveModel {
                id: Set(invocation_id),
                invoker: Set(actor_id.to_string()),
                issued_at: Set(OffsetDateTime::now_utc()),
                facts: Set(None),
                serialization: Set(vec![index as u8]),
            }
            .insert(&db.conn)
            .await
            .unwrap();
            epoch::ActiveModel {
                seq: Set(index as i64),
                id: Set(epoch_id),
                space: Set(SpaceIdWrap(space.clone())),
            }
            .insert(&db.conn)
            .await
            .unwrap();
            event_order::ActiveModel {
                seq: Set(index as i64),
                epoch: Set(epoch_id),
                epoch_seq: Set(0),
                event: Set(invocation_id),
                space: Set(SpaceIdWrap(space.clone())),
            }
            .insert(&db.conn)
            .await
            .unwrap();
            kv_write::ActiveModel {
                space: Set(SpaceIdWrap(space.clone())),
                key: Set(key.parse::<Path>().unwrap().into()),
                invocation: Set(invocation_id),
                seq: Set(index as i64),
                epoch: Set(epoch_id),
                epoch_seq: Set(0),
                value: Set(shared_value),
                metadata: Set(Metadata(std::collections::BTreeMap::new())),
            }
            .insert(&db.conn)
            .await
            .unwrap();
        }

        let (paths, truncated) = list_bounded(&db.conn, &space, &"".parse().unwrap(), Some(2))
            .await
            .unwrap();
        assert_eq!(
            paths.iter().map(Path::as_str).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(truncated);

        let (paths, truncated) = list_bounded(&db.conn, &space, &"".parse().unwrap(), Some(3))
            .await
            .unwrap();
        assert_eq!(
            paths.iter().map(Path::as_str).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
        assert!(truncated);
        assert_eq!(
            get_kv_entity(&db.conn, &space, &"b".parse().unwrap())
                .await
                .unwrap()
                .unwrap()
                .value,
            shared_value
        );
        assert_eq!(
            get_kv_entity(&db.conn, &space, &"c".parse().unwrap())
                .await
                .unwrap()
                .unwrap()
                .value,
            shared_value
        );

        let (paths, truncated) =
            list_bounded(&db.conn, &space, &"literal%".parse().unwrap(), Some(10))
                .await
                .unwrap();
        assert_eq!(
            paths.iter().map(Path::as_str).collect::<Vec<_>>(),
            vec!["literal%key"]
        );
        assert!(!truncated);

        let delete_invocation = crate::hash::hash(b"delete-invocation");
        invocation::ActiveModel {
            id: Set(delete_invocation),
            invoker: Set(actor_id.to_string()),
            issued_at: Set(OffsetDateTime::now_utc()),
            facts: Set(None),
            serialization: Set(vec![6]),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        kv_delete::ActiveModel {
            invocation_id: Set(delete_invocation),
            space: Set(SpaceIdWrap(space.clone())),
            key: Set("a".parse::<Path>().unwrap().into()),
            deleted_invocation_id: Set(crate::hash::hash(b"invocation-1")),
        }
        .insert(&db.conn)
        .await
        .unwrap();

        assert!(get_kv_entity(&db.conn, &space, &"a".parse().unwrap())
            .await
            .unwrap()
            .is_none());
        let (paths, truncated) = list_bounded(&db.conn, &space, &"".parse().unwrap(), Some(10))
            .await
            .unwrap();
        assert_eq!(
            paths.iter().map(Path::as_str).collect::<Vec<_>>(),
            vec!["b", "c", "literal%key", "literalXkey"]
        );
        assert!(!truncated);
    }

    #[tokio::test]
    async fn revoke_winner_serializes_before_descendant_issue_and_use_checks() {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        let db = get_db().await.unwrap();
        let parent_id = crate::hash::hash(b"race-parent");
        for actor_id in ["did:key:owner", "did:key:holder"] {
            actor::ActiveModel {
                id: Set(actor_id.to_string()),
            }
            .insert(&db.conn)
            .await
            .unwrap();
        }
        delegation::ActiveModel {
            id: Set(parent_id),
            delegator: Set("did:key:owner".to_string()),
            delegatee: Set("did:key:holder".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(b"race-parent".to_vec()),
        }
        .insert(&db.conn)
        .await
        .unwrap();

        let child_id = crate::hash::hash(b"race-child");
        delegation::ActiveModel {
            id: Set(child_id),
            delegator: Set("did:key:holder".to_string()),
            delegatee: Set("did:key:holder".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(b"race-child".to_vec()),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        parent_delegations::ActiveModel {
            parent: Set(parent_id),
            child: Set(child_id),
        }
        .insert(&db.conn)
        .await
        .unwrap();

        let revoke_guard = db
            .acquire_chain_guards(&[parent_id])
            .await
            .ok()
            .expect("revoke chain lock");
        let issue_db = db.clone();
        let issue = tokio::spawn(async move {
            let _guard = issue_db
                .acquire_chain_guards(&[parent_id])
                .await
                .ok()
                .expect("issue chain lock");
            crate::models::revocation::is_revoked(&issue_db.conn, &parent_id)
                .await
                .unwrap()
        });
        let use_db = db.clone();
        let use_existing = tokio::spawn(async move {
            let _guard = use_db
                .acquire_chain_guards(&[child_id])
                .await
                .ok()
                .expect("use chain lock");
            crate::models::revocation::is_revoked(&use_db.conn, &parent_id)
                .await
                .unwrap()
        });
        tokio::task::yield_now().await;
        assert!(!issue.is_finished());
        assert!(!use_existing.is_finished());

        revocation::ActiveModel {
            id: Set(crate::hash::hash(b"race-revocation")),
            revoker: Set("did:key:owner".to_string()),
            revoked: Set(parent_id),
            serialization: Set(b"race-revocation".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        drop(revoke_guard);

        assert!(issue.await.unwrap(), "new child check must observe revoke");
        assert!(
            use_existing.await.unwrap(),
            "existing child use check must observe revoke"
        );
    }

    #[tokio::test]
    async fn account_query_groups_resources_and_distinguishes_ancestor_revocation() {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        let db = get_db().await.unwrap();
        let owner = "did:pkh:eip155:1:0x0000000000000000000000000000000000000001";
        let recipient = "did:pkh:eip155:1:0x0000000000000000000000000000000000000002";
        for actor_id in [owner, recipient] {
            actor::ActiveModel {
                id: Set(actor_id.to_string()),
            }
            .insert(&db.conn)
            .await
            .unwrap();
        }
        let parent_id = crate::hash::hash(b"history-parent");
        let child_id = crate::hash::hash(b"history-child");
        for id in [parent_id, child_id] {
            delegation::ActiveModel {
                id: Set(id),
                delegator: Set(owner.to_string()),
                delegatee: Set(recipient.to_string()),
                expiry: Set(Some(OffsetDateTime::now_utc() + time::Duration::hours(1))),
                issued_at: Set(Some(OffsetDateTime::now_utc())),
                not_before: Set(None),
                facts: Set(None),
                serialization: Set(id.as_ref().to_vec()),
            }
            .insert(&db.conn)
            .await
            .unwrap();
        }
        parent_delegations::ActiveModel {
            parent: Set(parent_id),
            child: Set(child_id),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        for (resource, action) in [
            (
                "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:files/kv/docs",
                "tinycloud.kv/get",
            ),
            (
                "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:files/sql/main",
                "tinycloud.sql/read",
            ),
        ] {
            abilities::ActiveModel {
                resource: Set(resource.parse().unwrap()),
                ability: Set(action.to_string().try_into().unwrap()),
                delegation: Set(child_id),
                caveats: Set(Default::default()),
            }
            .insert(&db.conn)
            .await
            .unwrap();
        }
        revocation::ActiveModel {
            id: Set(crate::hash::hash(b"history-revocation")),
            revoker: Set(owner.to_string()),
            revoked: Set(parent_id),
            serialization: Set(b"history-revocation".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&db.conn)
        .await
        .unwrap();

        let state = load_account_ancestor_state(&db.conn, &[child_id])
            .await
            .unwrap();
        let child = state
            .lifecycle(child_id, OffsetDateTime::now_utc())
            .unwrap();
        assert_eq!(child.status, "ancestor_revoked");
        assert_eq!(
            child.revoked_ancestor_cid,
            Some(parent_id.to_cid(0x55).to_string())
        );

        revocation::Entity::delete_by_id(crate::hash::hash(b"history-revocation"))
            .exec(&db.conn)
            .await
            .unwrap();
        delegation::ActiveModel {
            id: Set(parent_id),
            expiry: Set(Some(OffsetDateTime::now_utc() - time::Duration::hours(1))),
            ..Default::default()
        }
        .update(&db.conn)
        .await
        .unwrap();
        let state = load_account_ancestor_state(&db.conn, &[child_id])
            .await
            .unwrap();
        assert_eq!(
            state
                .lifecycle(child_id, OffsetDateTime::now_utc())
                .unwrap()
                .status,
            "expired"
        );
    }

    #[tokio::test]
    async fn unrelated_delegation_chains_do_not_serialize() {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        let db = get_db().await.unwrap();
        actor::ActiveModel {
            id: Set("did:key:unrelated".to_string()),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        let first = crate::hash::hash(b"first-unrelated-chain");
        let second = crate::hash::hash(b"second-unrelated-chain");
        for id in [first, second] {
            delegation::ActiveModel {
                id: Set(id),
                delegator: Set("did:key:unrelated".to_string()),
                delegatee: Set("did:key:unrelated".to_string()),
                expiry: Set(None),
                issued_at: Set(None),
                not_before: Set(None),
                facts: Set(None),
                serialization: Set(id.as_ref().to_vec()),
            }
            .insert(&db.conn)
            .await
            .unwrap();
        }

        let first_guard = db
            .acquire_chain_guards(&[first])
            .await
            .ok()
            .expect("first chain lock");
        let other_db = db.clone();
        let unrelated = tokio::spawn(async move {
            other_db
                .acquire_chain_guards(&[second])
                .await
                .ok()
                .expect("unrelated chain lock")
        });
        let second_guard = tokio::time::timeout(std::time::Duration::from_secs(1), unrelated)
            .await
            .expect("an unrelated chain must not wait for the first chain")
            .unwrap();

        drop(second_guard);
        drop(first_guard);
    }

    #[tokio::test]
    async fn postgres_concurrent_epoch_appends_do_not_serialize() {
        let Ok(database_url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
            eprintln!("skipping PostgreSQL concurrency test: TINYCLOUD_TEST_POSTGRES_URL is unset");
            return;
        };

        let conn = Database::connect(ConnectOptions::new(database_url))
            .await
            .expect("connect to PostgreSQL test database");
        assert_eq!(
            chain_isolation_level(&conn),
            Some(sea_orm::IsolationLevel::ReadCommitted)
        );

        let suffix = format!(
            "{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let schema = format!("tc212_{suffix}");

        conn.execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .expect("create isolated test schema");

        let exercise: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
            let epoch_table = format!("{schema}.epoch");
            let order_table = format!("{schema}.epoch_order");

            conn.execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE TABLE {epoch_table} (id INTEGER PRIMARY KEY, space TEXT NOT NULL)"),
            ))
            .await?;
            conn.execute(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "CREATE TABLE {order_table} (parent INTEGER NOT NULL, child INTEGER NOT NULL, \
                     space TEXT NOT NULL, PRIMARY KEY (parent, child, space))"
                ),
            ))
            .await?;
            conn.execute(Statement::from_string(
                DbBackend::Postgres,
                format!("INSERT INTO {epoch_table} (id, space) VALUES (1, 'space')"),
            ))
            .await?;

            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            let append = |child: i32| {
                let conn = conn.clone();
                let barrier = Arc::clone(&barrier);
                let epoch_table = epoch_table.clone();
                let order_table = order_table.clone();
                tokio::spawn(async move {
                    let tx = conn
                        .begin_with_config(chain_isolation_level(&conn), None)
                        .await?;
                    let tips = tx
                        .query_all(Statement::from_string(
                            DbBackend::Postgres,
                            format!(
                                "SELECT epoch.id FROM {epoch_table} AS epoch \
                                 LEFT JOIN {order_table} AS ordering ON epoch.id = ordering.parent \
                                 WHERE epoch.space = 'space' AND ordering.child IS NULL"
                            ),
                        ))
                        .await?;
                    if tips.len() != 1 {
                        return Err(DbErr::Custom(format!(
                            "expected one shared epoch tip, got {}",
                            tips.len()
                        )));
                    }
                    barrier.wait().await;
                    tx.execute(Statement::from_string(
                        DbBackend::Postgres,
                        format!("INSERT INTO {epoch_table} (id, space) VALUES ({child}, 'space')"),
                    ))
                    .await?;
                    tx.execute(Statement::from_string(
                        DbBackend::Postgres,
                        format!(
                            "INSERT INTO {order_table} (parent, child, space) \
                             VALUES (1, {child}, 'space')"
                        ),
                    ))
                    .await?;
                    tx.commit().await
                })
            };

            let mut first = append(2);
            let mut second = append(3);
            match tokio::time::timeout(std::time::Duration::from_secs(15), async {
                tokio::join!(&mut first, &mut second)
            })
            .await
            {
                Ok((first, second)) => {
                    first??;
                    second??;
                }
                Err(error) => {
                    first.abort();
                    second.abort();
                    let _ = first.await;
                    let _ = second.await;
                    return Err(error.into());
                }
            }

            Ok(())
        }
        .await;

        conn.execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
        ))
        .await
        .expect("clean up isolated test schema");

        exercise.expect("both concurrent epoch appends committed");
    }

    #[tokio::test]
    async fn store_size_folds_sql_only_space_to_some() {
        let space = test_space_id("sql-only");
        let sql_sizes = SqlSizes::new();
        sql_sizes
            .update("sql", &space.to_string(), "main", 512)
            .await;
        let db = get_db().await.unwrap().with_sql_sizes(sql_sizes);
        // MemoryStore never saw this space, but SQL bytes exist → Some(512).
        assert_eq!(db.store_size(&space).await.unwrap(), Some(512));
    }

    #[tokio::test]
    async fn store_size_none_only_when_both_absent() {
        let space = test_space_id("untouched");
        let db = get_db().await.unwrap().with_sql_sizes(SqlSizes::new());
        assert_eq!(db.store_size(&space).await.unwrap(), None);
    }

    #[tokio::test]
    async fn list_space_ids_returns_all_created_spaces() {
        let db = get_db().await.unwrap();
        // Empty node → empty list.
        assert!(db.list_space_ids().await.unwrap().is_empty());

        let a = test_space_id("alpha");
        let b = test_space_id("beta");
        space::Entity::insert_many([
            space::ActiveModel::from(space::Model {
                id: SpaceIdWrap(a.clone()),
            }),
            space::ActiveModel::from(space::Model {
                id: SpaceIdWrap(b.clone()),
            }),
        ])
        .exec(&db.conn)
        .await
        .unwrap();

        let listed: HashSet<SpaceId> = db.list_space_ids().await.unwrap().into_iter().collect();
        assert_eq!(listed, HashSet::from([a, b]));
    }

    #[tokio::test]
    async fn epoch_insert_for_missing_space_is_fk_violation() {
        let db = get_db().await.unwrap();
        let space = test_space_id("ghost");
        // Insert an epoch row for a space that was never created. With SQLite
        // foreign keys enforced (sqlx default), this must trip the epoch->space
        // FK rather than silently succeed.
        let err = epoch::Entity::insert(epoch::ActiveModel::from(epoch::Model {
            seq: 0,
            id: crate::hash::hash(b"ghost-epoch"),
            space: SpaceIdWrap(space),
        }))
        .exec(&db.conn)
        .await
        .unwrap_err();

        match err {
            DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(db_err))) => {
                assert_eq!(
                    db_err.kind(),
                    sea_orm::sqlx::error::ErrorKind::ForeignKeyViolation,
                    "expected a foreign-key violation, got kind {:?} (code {:?})",
                    db_err.kind(),
                    db_err.code()
                );
            }
            other => panic!("expected FK database error, got {other:?}"),
        }
    }
}

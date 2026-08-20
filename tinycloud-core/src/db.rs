use crate::admission::AdmittedInvocation;
use crate::encryption::ColumnEncryption;
use crate::events::{
    epoch_hash, Delegation, Event, HashError, Invocation, Operation, Revocation, SerializedEvent,
};
use crate::hash::Hash;
use crate::keys::{get_did_key, Secrets, StaticSecret};
use crate::migrations::Migrator;
use crate::models::*;
use crate::read_audit::ReadAuditPipeline;
use crate::relationships::*;
use crate::sql_sizes::SqlSizes;
use crate::storage::{
    either::EitherError, ByteRangeSpec, Content, HashBuffer, ImmutableReadStore, ImmutableStaging,
    ImmutableWriteStore, RangeRead, StorageSetup, StoreSize,
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
    sea_query::{Expr, ExprTrait, LikeExpr, OnConflict, Query, SimpleExpr},
    ActiveValue::Set,
    ConnectionTrait, DatabaseTransaction, DbBackend, IntoActiveModel, TransactionTrait,
};
use sea_orm_migration::MigratorTrait;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;
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

/// Per-delegation guard protecting revocation ordering (TC-324).
///
/// Invocations take these SHARED, delegation registration and revocation take
/// them EXCLUSIVE. See [`SpaceDatabase::acquire_shared_chain_guards_for_keys`]
/// for the ordering argument this encodes.
type ChainLock = tokio::sync::RwLock<()>;
type ChainLockRegistry = Arc<tokio::sync::Mutex<HashMap<Hash, Weak<ChainLock>>>>;
/// Exclusive chain guard: held by delegation registration and revocation.
type ExclusiveChainGuard = tokio::sync::OwnedRwLockWriteGuard<()>;
/// Shared chain guard: held by invocations, which only read chain state.
type SharedChainGuard = tokio::sync::OwnedRwLockReadGuard<()>;

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

/// TC-409: which trust mode an invocation entered `invoke_with_options_mode`
/// under, and therefore which `Event` variant (and how much duplicate
/// verification work) it produces. `Admitted` is only reachable by consuming
/// an `AdmittedInvocation`, obtainable only from `AdmittedInvocation::admit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvokeMode {
    /// Untyped public entry point: signature verification runs during
    /// processing, same as always.
    Public,
    /// Envelope already verified once at admission. Authorization,
    /// revocation, caveat containment, and signed-time validity are still
    /// re-checked at execution; only the signature check is skipped.
    Admitted,
}

#[derive(Debug, Clone)]
pub struct SpaceDatabase<C, B, S> {
    conn: C,
    storage: B,
    secrets: S,
    encryption: Option<ColumnEncryption>,
    sql_sizes: SqlSizes,
    revocation_chain_locks: ChainLockRegistry,
    kv_object_locks: KvObjectLockRegistry,
    writer_lock: Option<Arc<tokio::sync::Mutex<()>>>,
    read_audit: ReadAuditPipeline,
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
    pub list_cursor: Option<Path>,
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

impl<B, K> SpaceDatabase<DatabaseConnection, B, K> {
    pub async fn new(conn: DatabaseConnection, storage: B, secrets: K) -> Result<Self, DbErr> {
        Migrator::up(&conn, None).await?;
        let writer_lock = (conn.get_database_backend() == sea_orm::DatabaseBackend::Sqlite)
            .then(|| Arc::new(tokio::sync::Mutex::new(())));
        let read_audit = ReadAuditPipeline::start(conn.clone(), writer_lock.clone());
        Ok(Self {
            conn,
            storage,
            secrets,
            encryption: None,
            sql_sizes: SqlSizes::default(),
            revocation_chain_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            kv_object_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            writer_lock,
            read_audit,
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

    /// Share the SQLite writer gate with control-plane transactions that use
    /// the same SeaORM connection outside `SpaceDatabase`.
    pub fn sqlite_writer_lock(&self) -> Option<Arc<tokio::sync::Mutex<()>>> {
        self.writer_lock.clone()
    }
}

impl<C, B, K> SpaceDatabase<C, B, K>
where
    K: Secrets,
{
    /// Number of durable read-audit records and group commits completed.
    pub fn read_audit_commit_stats(&self) -> (u64, u64) {
        self.read_audit.stats()
    }

    pub async fn stage_key(&self, space_id: &SpaceId) -> Result<String, K::Error> {
        self.secrets.stage_keypair(space_id).await.map(get_did_key)
    }
}

impl<C, B> SpaceDatabase<C, B, StaticSecret> {
    /// Node-local MAC key for opaque generic KV list cursors. The key never
    /// leaves the process and is derived from the configured node secret.
    pub fn kv_cursor_key(&self) -> [u8; 32] {
        self.secrets.derive_key(b"tinycloud/kv/list-cursor")
    }
}

impl<C, B, K> SpaceDatabase<C, B, K> {
    /// Exposes the node's capability database for projections that are
    /// committed alongside ordinary delegation/revocation writes.
    pub fn connection(&self) -> &C {
        &self.conn
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
    /// Run the ordinary invocation authorization kernel without recording an
    /// invocation or performing a data-plane operation.  Specialized routes
    /// (notably encryption decrypt) must call this before dispatch so they
    /// cannot authorize from asserted capabilities alone.
    pub async fn authorize_invocation(
        &self,
        invocation: &crate::util::InvocationInfo,
        now: OffsetDateTime,
    ) -> Result<(), crate::models::invocation::Error> {
        invocation::verify_and_authorize(&self.conn, invocation, now).await
    }

    /// Load and reparse a delegation from its exact signed Authorization
    /// bytes. The relational row is returned only so callers can compare all
    /// projections against the signed source of truth.
    pub async fn load_signed_delegation(
        &self,
        cid: tinycloud_auth::ipld_core::cid::Cid,
    ) -> Result<Option<(delegation::Model, Delegation)>, String> {
        let Some(row) = delegation::Entity::find_by_id(Hash::from(cid))
            .one(&self.conn)
            .await
            .map_err(|error| error.to_string())?
        else {
            return Ok(None);
        };
        let bytes = crate::encryption::maybe_decrypt(self.encryption.as_ref(), &row.serialization)
            .map_err(|error| error.to_string())?;
        let delegation =
            TinyCloudDelegation::from_bytes(&bytes).map_err(|error| error.to_string())?;
        let info = DelegationInfo::try_from(delegation).map_err(|error| error.to_string())?;
        let event = SerializedEvent(info, bytes);
        if event.content_hash() != row.id || event.content_hash() != Hash::from(cid) {
            return Err("delegation-signed-bytes-mismatch".to_string());
        }
        Ok(Some((row, event)))
    }

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

// -----------------------------------------------------------------------------
// Retention pruning (TC-287)
//
// Terminal `hook_delivery` rows and expired `signed_kv_ticket` rows accumulate
// forever once a delivery reaches a terminal state or a ticket lapses. These
// helpers delete them in bounded batches so a large backlog never turns into a
// single unbounded DELETE that holds the writer for an unpredictable time.
//
// Both tables store timestamps as RFC3339 *strings* (see
// `list_due_webhook_deliveries` and the `signed_kv_ticket` migration), so
// callers pass a pre-formatted cutoff string and we compare lexicographically
// in SQL — matching the existing string comparisons — rather than parsing per
// row.
// -----------------------------------------------------------------------------

/// Delete `hook_delivery` rows matching `condition` in batches of `batch_rows`.
///
/// Each iteration selects a page of primary keys and deletes exactly those
/// rows, so the statement count is bounded regardless of backlog size. The loop
/// stops as soon as a page comes back shorter than `batch_rows` (or empty),
/// which guarantees termination: every full page deletes `batch_rows` matching
/// rows, monotonically shrinking the candidate set.
async fn prune_hook_deliveries_in_batches<C: ConnectionTrait>(
    conn: &C,
    condition: Condition,
    batch_rows: u64,
) -> Result<u64, DbErr> {
    if batch_rows == 0 {
        return Ok(0);
    }
    let mut deleted = 0u64;
    loop {
        let ids: Vec<String> = hook_delivery::Entity::find()
            .select_only()
            .column(hook_delivery::Column::Id)
            .filter(condition.clone())
            .limit(batch_rows)
            .into_tuple::<String>()
            .all(conn)
            .await?;
        if ids.is_empty() {
            break;
        }
        let page = ids.len() as u64;
        deleted += hook_delivery::Entity::delete_many()
            .filter(hook_delivery::Column::Id.is_in(ids))
            .exec(conn)
            .await?
            .rows_affected;
        if page < batch_rows {
            break;
        }
    }
    Ok(deleted)
}

/// Delete `hook_delivery` rows in the terminal `delivered` state whose
/// `delivered_at` is older than `delivered_before` (RFC3339). Pending/retrying
/// rows are never touched, and rows with a NULL `delivered_at` are excluded by
/// the SQL comparison — only genuinely-delivered, aged rows are removed.
pub async fn prune_delivered_hook_deliveries<C: ConnectionTrait>(
    conn: &C,
    delivered_before: &str,
    batch_rows: u64,
) -> Result<u64, DbErr> {
    prune_hook_deliveries_in_batches(
        conn,
        Condition::all()
            .add(hook_delivery::Column::Status.eq(HOOK_DELIVERY_STATUS_DELIVERED))
            .add(hook_delivery::Column::DeliveredAt.lt(delivered_before)),
        batch_rows,
    )
    .await
}

/// Delete `hook_delivery` rows in the terminal `dead_letter` state whose
/// `created_at` is older than `created_before` (RFC3339). Dead-letter rows have
/// exhausted their retries, so `created_at` is the stable age reference.
pub async fn prune_dead_letter_hook_deliveries<C: ConnectionTrait>(
    conn: &C,
    created_before: &str,
    batch_rows: u64,
) -> Result<u64, DbErr> {
    prune_hook_deliveries_in_batches(
        conn,
        Condition::all()
            .add(hook_delivery::Column::Status.eq(HOOK_DELIVERY_STATUS_DEAD_LETTER))
            .add(hook_delivery::Column::CreatedAt.lt(created_before)),
        batch_rows,
    )
    .await
}

/// Delete `signed_kv_ticket` rows whose `expires_at` is older than
/// `expired_before` (RFC3339), in batches of `batch_rows`. Same batched
/// select-then-delete shape as the hook-delivery pruners.
pub async fn prune_expired_signed_kv_tickets<C: ConnectionTrait>(
    conn: &C,
    expired_before: &str,
    batch_rows: u64,
) -> Result<u64, DbErr> {
    if batch_rows == 0 {
        return Ok(0);
    }
    let mut deleted = 0u64;
    loop {
        let ids: Vec<String> = signed_kv_ticket::Entity::find()
            .select_only()
            .column(signed_kv_ticket::Column::Id)
            .filter(signed_kv_ticket::Column::ExpiresAt.lt(expired_before))
            .limit(batch_rows)
            .into_tuple::<String>()
            .all(conn)
            .await?;
        if ids.is_empty() {
            break;
        }
        let page = ids.len() as u64;
        deleted += signed_kv_ticket::Entity::delete_many()
            .filter(signed_kv_ticket::Column::Id.is_in(ids))
            .exec(conn)
            .await?
            .rows_affected;
        if page < batch_rows {
            break;
        }
    }
    Ok(deleted)
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

    pub async fn kv_get_range(
        &self,
        space_id: &SpaceId,
        key: &Path,
        range: ByteRangeSpec,
    ) -> Result<Option<(Metadata, Hash, RangeRead<B::Readable>)>, EitherError<DbErr, B::Error>>
    {
        let Some((metadata, hash)) = metadata_with_hash(&self.conn, space_id, key)
            .await
            .map_err(EitherError::A)?
        else {
            return Ok(None);
        };
        let Some(content) = self
            .storage
            .read_range(space_id, &hash, range)
            .await
            .map_err(EitherError::B)?
        else {
            return Ok(None);
        };
        Ok(Some((metadata, hash, content)))
    }

    pub async fn kv_metadata_with_hash(
        &self,
        space_id: &SpaceId,
        key: &Path,
    ) -> Result<Option<(Metadata, Hash)>, DbErr> {
        metadata_with_hash(&self.conn, space_id, key).await
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

    /// Return only immediate KV children, with a bounded keyset page. Share
    /// authorization calls this method after the authority bridge has checked
    /// the holder, prefix, action, and cursor binding; the database method does
    /// not make an authorization decision itself.
    pub async fn list_direct_children_bounded(
        &self,
        space_id: &SpaceId,
        prefix: &Path,
        limit: usize,
        after: Option<&Path>,
    ) -> Result<(Vec<Path>, bool, Option<Path>), DbErr> {
        list_direct_children_bounded(&self.conn, space_id, prefix, limit, after).await
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
    /// Acquire EXCLUSIVE guards over the ancestor closure of `roots`.
    ///
    /// Used by the writers of chain state — delegation registration and
    /// revocation. See [`Self::acquire_shared_chain_guards_for_keys`] for why
    /// invocations may take the same guards shared instead.
    async fn acquire_chain_guards(
        &self,
        roots: &[Hash],
    ) -> Result<Vec<ExclusiveChainGuard>, TxError<B, K>> {
        let keys = revocation::ancestor_chain_ids_for_roots(&self.conn, roots)
            .await
            .map_err(|error| match error {
                revocation::ChainTraversalError::Db(error) => TxError::Db(error),
                revocation::ChainTraversalError::LimitExceeded => {
                    TxError::ChainTraversalLimitExceeded
                }
            })?;
        Ok(self.acquire_exclusive_chain_guards_for_keys(keys).await)
    }

    /// Resolve `keys` to their per-delegation locks in a stable global order.
    ///
    /// Sorting and deduplicating here is the deadlock discipline: every
    /// acquisition — shared or exclusive — walks the key space in the same
    /// ascending order, so a task can only ever wait on a key greater than
    /// every key it already holds. That rules out a wait-for cycle regardless
    /// of which mode each participant asked for, and it is why two requests
    /// citing overlapping chains in opposite argument order cannot deadlock.
    async fn chain_locks_for_keys(&self, mut keys: Vec<Hash>) -> Vec<Arc<ChainLock>> {
        keys.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
        keys.dedup();

        let mut registry = self.revocation_chain_locks.lock().await;
        registry.retain(|_, lock| lock.strong_count() > 0);
        keys.into_iter()
            .map(|key| {
                if let Some(lock) = registry.get(&key).and_then(Weak::upgrade) {
                    lock
                } else {
                    let lock = Arc::new(ChainLock::new(()));
                    registry.insert(key, Arc::downgrade(&lock));
                    lock
                }
            })
            .collect()
    }

    /// Acquire EXCLUSIVE guards over `keys` (the full ancestor closure).
    ///
    /// Exclusion against the shared guards held by in-flight invocations is
    /// what serializes a revocation against every authorization decision made
    /// on the chain it revokes.
    async fn acquire_exclusive_chain_guards_for_keys(
        &self,
        keys: Vec<Hash>,
    ) -> Vec<ExclusiveChainGuard> {
        // Single instrumentation point for exclusive chain-guard acquisition:
        // delegate and revoke both route through here, so ChainGuardWait
        // captures the contention wait without duplicating timing per call
        // site.
        let guard_wait_start = Instant::now();
        let locks = self.chain_locks_for_keys(keys).await;
        let mut guards = Vec::with_capacity(locks.len());
        for lock in locks {
            guards.push(lock.write_owned().await);
        }
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::ChainGuardWait,
            crate::telemetry::StageOutcome::Ok,
            guard_wait_start.elapsed(),
        );
        guards
    }

    /// Acquire SHARED guards over `keys` (the full ancestor closure) for an
    /// invocation.
    ///
    /// An invocation only *reads* chain state: it evaluates the delegation
    /// chain and the revocation set to make an authorization decision. The
    /// rows it writes (its own invocation record and the `parent_delegations`
    /// edges pointing at the delegations it cited) are leaves hanging off the
    /// graph — they never alter any delegation's ancestor closure, and nothing
    /// traverses the graph downward from parent to child. So two invocations
    /// on the same chain never had to exclude one another; only a writer of
    /// chain state does. That mutual exclusion between invocations was the
    /// dominant source of `chain_guard_wait` in production, because a single
    /// busy account funnels all of its traffic through one root delegation.
    ///
    /// The security invariant is unchanged: a revocation takes these same
    /// guards EXCLUSIVE and holds them through commit, so it cannot commit
    /// while an invocation is being authorized against the chain it revokes,
    /// and an invocation that starts afterwards observes the revocation.
    ///
    /// Load-bearing detail: `tokio::sync::RwLock` is write-preferring (its
    /// internal semaphore hands out permits fairly, in FIFO order). Once a
    /// revocation is queued for the write guard, newly arriving invocations
    /// queue behind it rather than joining the current read cohort. A
    /// continuous stream of invocations therefore cannot starve a pending
    /// revocation — which is what makes shared invocation guards safe as a
    /// revocation-ordering mechanism rather than merely faster.
    async fn acquire_shared_chain_guards_for_keys(&self, keys: Vec<Hash>) -> Vec<SharedChainGuard> {
        let guard_wait_start = Instant::now();
        let locks = self.chain_locks_for_keys(keys).await;
        let mut guards = Vec::with_capacity(locks.len());
        for lock in locks {
            guards.push(lock.read_owned().await);
        }
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::ChainGuardWait,
            crate::telemetry::StageOutcome::Ok,
            guard_wait_start.elapsed(),
        );
        guards
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
        let _writer = match &self.writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
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
            None,
        )
        .await?;

        let start = Instant::now();
        let commit_result = tx.commit().await;
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::EpochPersist,
            crate::telemetry::StageOutcome::from(commit_result.is_ok()),
            start.elapsed(),
        );
        commit_result?;

        Ok(result)
    }

    pub async fn delegate(&self, delegation: Delegation) -> Result<TransactResult, TxError<B, K>> {
        let parent_hashes: Vec<Hash> = delegation
            .0
            .parents
            .iter()
            .copied()
            .map(Hash::from)
            .collect();
        let retained_hash = delegation.content_hash();
        // Capture expected row counts before consuming the delegation.
        let expected_ability_count = delegation.0.capabilities.len() as u64;
        let expected_parent_count = parent_hashes.len() as u64;
        let roots = delegation_guard_roots(retained_hash, &parent_hashes);
        let authz_start = Instant::now();
        let chain_guards = self.acquire_chain_guards(&roots).await;
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::AuthorizationGraphLoad,
            crate::telemetry::StageOutcome::from(chain_guards.is_ok()),
            authz_start.elapsed(),
        );
        let _chain_guards = chain_guards?;
        // Non-authoritative fast path: if the row is already committed before
        // we begin the transaction, skip the write entirely. Correctness does
        // not depend on this check — transact() handles the idempotent case
        // atomically via DelegationRegistration::Existing inside the txn.
        match delegation::Entity::find_by_id(retained_hash)
            .one(&self.conn)
            .await
        {
            Ok(Some(_)) => return Ok(already_registered_result(retained_hash)),
            Ok(None) => {}
            Err(e) => return Err(TxError::Db(e)),
        }
        match self
            .transact(vec![Event::Delegation(Box::new(delegation))])
            .await
        {
            Err(TxError::EpochInsert(epoch_err)) => {
                if is_pk_epoch_conflict(&epoch_err) {
                    reconcile_pk_epoch_delegation(
                        &self.conn,
                        retained_hash,
                        expected_ability_count,
                        expected_parent_count,
                    )
                    .await
                } else {
                    record_epoch_reconcile_failure(EpochReconcileReason::ClassifierMiss);
                    Err(TxError::EpochInsert(epoch_err))
                }
            }
            other => other,
        }
    }

    /// Atomically register control-plane roots in the ordinary delegation
    /// graph.  The policy v3 tables remain indexes; the graph rows are needed
    /// so an S0 can be admitted through the same proof resolver as every
    /// other delegation.
    pub async fn delegate_batch(
        &self,
        delegations: Vec<Delegation>,
    ) -> Result<TransactResult, TxError<B, K>> {
        self.transact(
            delegations
                .into_iter()
                .map(|delegation| Event::Delegation(Box::new(delegation)))
                .collect(),
        )
        .await
    }

    /// Register a control-plane delegation batch inside a caller-owned SQL
    /// transaction. This is used when the ordinary graph rows and their
    /// signed-byte projection indexes must commit or roll back together.
    pub async fn delegate_batch_in_transaction(
        &self,
        tx: &DatabaseTransaction,
        delegations: Vec<Delegation>,
    ) -> Result<TransactResult, TxError<B, K>> {
        transact(
            tx,
            &self.storage,
            &self.secrets,
            delegations
                .into_iter()
                .map(|delegation| Event::Delegation(Box::new(delegation)))
                .collect(),
            self.encryption.as_ref(),
            None,
        )
        .await
    }

    pub async fn revoke(&self, revocation: Revocation) -> Result<TransactResult, TxError<B, K>> {
        let mut roots = vec![Hash::from(revocation.0.revoked)];
        roots.extend(revocation.0.parents.iter().copied().map(Hash::from));
        let revocation_start = Instant::now();
        let chain_guards = self.acquire_chain_guards(&roots).await;
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::RevocationWork,
            crate::telemetry::StageOutcome::from(chain_guards.is_ok()),
            revocation_start.elapsed(),
        );
        let _chain_guards = chain_guards?;
        self.transact(vec![Event::Revocation(Box::new(revocation))])
            .await
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

    /// TC-409: process an invocation whose envelope was already verified
    /// once by `AdmittedInvocation::admit`. Skips only that duplicate
    /// signature check downstream; authorization, revocation, caveat
    /// containment, and signed-time validity are still re-checked against
    /// the current database state. This is the sole way to reach
    /// `Event::AdmittedInvocation` — a caller without an `AdmittedInvocation`
    /// cannot construct one.
    pub async fn invoke_admitted<S>(
        &self,
        invocation: AdmittedInvocation,
        inputs: InvocationInputs<S::Writable>,
    ) -> Result<(TransactResult, Vec<InvocationOutcome<B::Readable>>), TxStoreError<B, S, K>>
    where
        B: ImmutableWriteStore<S> + ImmutableReadStore,
        S: ImmutableStaging,
        S::Writable: 'static + Unpin,
    {
        self.invoke_with_options_admitted(invocation, inputs, KvInvokeOptions::default())
            .await
    }

    pub async fn invoke_with_options_admitted<S>(
        &self,
        invocation: AdmittedInvocation,
        inputs: InvocationInputs<S::Writable>,
        options: KvInvokeOptions,
    ) -> Result<(TransactResult, Vec<InvocationOutcome<B::Readable>>), TxStoreError<B, S, K>>
    where
        B: ImmutableWriteStore<S> + ImmutableReadStore,
        S: ImmutableStaging,
        S::Writable: 'static + Unpin,
    {
        self.invoke_with_options_mode(
            invocation.into_invocation(),
            inputs,
            options,
            InvokeMode::Admitted,
        )
        .await
    }

    pub async fn invoke_with_options<S>(
        &self,
        invocation: Invocation,
        inputs: InvocationInputs<S::Writable>,
        options: KvInvokeOptions,
    ) -> Result<(TransactResult, Vec<InvocationOutcome<B::Readable>>), TxStoreError<B, S, K>>
    where
        B: ImmutableWriteStore<S> + ImmutableReadStore,
        S: ImmutableStaging,
        S::Writable: 'static + Unpin,
    {
        self.invoke_with_options_mode(invocation, inputs, options, InvokeMode::Public)
            .await
    }

    async fn invoke_with_options_mode<S>(
        &self,
        invocation: Invocation,
        mut inputs: InvocationInputs<S::Writable>,
        options: KvInvokeOptions,
        mode: InvokeMode,
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
        let authz_start = Instant::now();
        let closure_start = Instant::now();
        let lock_keys = crate::auth_graph::load_closure_edges(&self.conn, &roots)
            .await
            .map(|(keys, _)| keys)
            .map_err(|error| match error {
                revocation::ChainTraversalError::Db(error) => TxError::Db(error),
                revocation::ChainTraversalError::LimitExceeded => {
                    TxError::ChainTraversalLimitExceeded
                }
            });
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::ChainClosureQuery,
            crate::telemetry::StageOutcome::from(lock_keys.is_ok()),
            closure_start.elapsed(),
        );
        let lock_keys = match lock_keys {
            Ok(keys) => keys,
            Err(error) => {
                crate::telemetry::observe_stage(
                    crate::telemetry::InvocationStage::AuthorizationGraphLoad,
                    crate::telemetry::StageOutcome::Error,
                    authz_start.elapsed(),
                );
                return Err(TxStoreError::Tx(error));
            }
        };
        // TC-324: invocations take the chain guards SHARED. The full ancestor
        // closure is still guarded and the guards are still held through
        // commit, so a revocation (which takes them exclusive) remains
        // serialized against this authorization decision. What is dropped is
        // invocation-vs-invocation exclusion, which the revocation-ordering
        // invariant never depended on.
        let _chain_guards = self.acquire_shared_chain_guards_for_keys(lock_keys).await;
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
        if mutation_keys.is_empty() {
            return self.invoke_read_only::<S>(invocation, options, mode).await;
        }
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
        let _writer = match &self.writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        let begin_start = Instant::now();
        let tx_result = self.conn.begin_with_config(isolation_level, None).await;
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::DbTxBegin,
            crate::telemetry::StageOutcome::from(tx_result.is_ok()),
            begin_start.elapsed(),
        );
        let tx = tx_result?;
        // DbTxBody spans post-begin to pre-commit. The guard defaults to an
        // `error` outcome so any `?`/early return inside the transaction is
        // recorded as a failure; it is disarmed to `ok` right before commit.
        let tx_body_timer =
            crate::telemetry::StageTimer::start(crate::telemetry::InvocationStage::DbTxBody);
        let auth_graph = match crate::auth_graph::AuthGraphSnapshot::load(&tx, &roots).await {
            Ok(graph) => graph,
            Err(error) => {
                crate::telemetry::observe_stage(
                    crate::telemetry::InvocationStage::AuthorizationGraphLoad,
                    crate::telemetry::StageOutcome::Error,
                    authz_start.elapsed(),
                );
                return Err(TxStoreError::Tx(match error {
                    revocation::ChainTraversalError::Db(error) => TxError::Db(error),
                    revocation::ChainTraversalError::LimitExceeded => {
                        TxError::ChainTraversalLimitExceeded
                    }
                }));
            }
        };
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::AuthorizationGraphLoad,
            crate::telemetry::StageOutcome::Ok,
            authz_start.elapsed(),
        );
        let mut deleted_hashes = HashMap::new();
        for key @ (space, path) in &mutation_keys {
            let current = get_kv_entity(&tx, space, path).await?;
            if let Some(precondition) = options.preconditions.get(key) {
                let matches = kv_precondition_matches(
                    *precondition,
                    current.as_ref().map(|entry| entry.value),
                );
                if !matches {
                    return Err(TxStoreError::KvPreconditionFailed);
                }
            }
            if let Some(entry) = current {
                deleted_hashes.insert(key.clone(), entry.value);
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
        let event = match mode {
            InvokeMode::Admitted => Event::AdmittedInvocation(Box::new(invocation), ops),
            InvokeMode::Public => Event::Invocation(Box::new(invocation), ops),
        };
        let commit = transact(
            &tx,
            &self.storage,
            &self.secrets,
            vec![event],
            self.encryption.as_ref(),
            Some(&auth_graph),
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
                    let (list, truncated) = list_bounded_after(
                        &tx,
                        space,
                        path,
                        options.list_limit,
                        options.list_cursor.as_ref(),
                    )
                    .await?;
                    results.push(InvocationOutcome::KvList(list, truncated, None))
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

        // Record the transaction body as successful (post-begin to
        // pre-commit) before the commit itself; commit latency is tracked
        // separately (EpochPersist on the delegate/revoke path).
        tx_body_timer.observe_ok();
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

    /// Execute a successful non-mutating invocation without entering the
    /// single-writer transaction. Authorization and data access remain under
    /// the caller's shared chain guards, which are held across this call and
    /// released only after it returns; the response waits for the grouped
    /// audit commit.
    async fn invoke_read_only<S>(
        &self,
        invocation: Invocation,
        options: KvInvokeOptions,
        mode: InvokeMode,
    ) -> Result<(TransactResult, Vec<InvocationOutcome<B::Readable>>), TxStoreError<B, S, K>>
    where
        B: ImmutableWriteStore<S> + ImmutableReadStore,
        S: ImmutableStaging,
        S::Writable: 'static + Unpin,
    {
        // TC-409: an admitted invocation already had its signature verified
        // once at the admission boundary; only re-check authorization and
        // signed-time validity here rather than verifying the signature a
        // second time.
        match mode {
            InvokeMode::Admitted => {
                invocation::authorize_admitted(&self.conn, &invocation.0, OffsetDateTime::now_utc())
                    .await
                    .map_err(TxError::<B, K>::from)?
            }
            InvokeMode::Public => invocation::verify_and_authorize(
                &self.conn,
                &invocation.0,
                OffsetDateTime::now_utc(),
            )
            .await
            .map_err(TxError::<B, K>::from)?,
        };

        let requested_spaces = invocation.0.spaces().cloned().collect::<HashSet<_>>();
        if !requested_spaces.is_empty() {
            let hosted = space::Entity::find()
                .filter(space::Column::Id.is_in(requested_spaces.iter().cloned().map(SpaceIdWrap)))
                .count(&self.conn)
                .await?;
            if hosted != requested_spaces.len() as u64 {
                return Err(TxError::SpaceNotFound.into());
            }
        }

        let caps_read_params: Option<CapabilitiesReadParams> = invocation
            .0
            .invocation
            .payload()
            .facts
            .as_ref()
            .and_then(|facts| {
                facts.iter().find_map(|fact| {
                    fact.as_object()
                        .and_then(|object| object.get("capabilitiesReadParams"))
                        .and_then(|value| serde_json::from_value(value.clone()).ok())
                })
            });
        let mut results = Vec::new();
        for cap in invocation.0.capabilities.iter().filter_map(|capability| {
            capability
                .resource
                .tinycloud_resource()
                .and_then(|resource| {
                    Some((
                        resource.space(),
                        resource.service().as_str(),
                        crate::policy_capability::resolve_alias(
                            capability.ability.as_ref().as_ref(),
                        ),
                        resource.path()?,
                    ))
                })
        }) {
            match cap {
                (space, "kv", "tinycloud.kv/get", path) => {
                    let data = get_kv(&self.conn, &self.storage, space, path)
                        .await
                        .map_err(|error| match error {
                            EitherError::A(error) => TxStoreError::Tx(error.into()),
                            EitherError::B(error) => TxStoreError::StoreRead(error),
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
                        list_bounded(&self.conn, space, path, options.list_limit).await?;
                    results.push(InvocationOutcome::KvList(list, truncated, None));
                }
                (space, "kv", "tinycloud.kv/metadata", path) => {
                    results.push(InvocationOutcome::KvMetadata(
                        metadata_with_hash(&self.conn, space, path).await?,
                    ));
                }
                (space, "capabilities", "tinycloud.capabilities/read", path)
                    if path.as_str() == "all" =>
                {
                    let outcome = match &caps_read_params {
                        None => {
                            get_valid_delegations(&self.conn, space, self.encryption.as_ref())
                                .await?
                        }
                        Some(CapabilitiesReadParams::List { filters }) => {
                            get_filtered_delegations(
                                &self.conn,
                                space,
                                &invocation.0.invoker,
                                filters.as_ref(),
                                self.encryption.as_ref(),
                            )
                            .await?
                        }
                        Some(CapabilitiesReadParams::Chain { delegation_cid }) => {
                            results.push(InvocationOutcome::DelegationChain(
                                get_delegation_chain(
                                    &self.conn,
                                    space,
                                    delegation_cid,
                                    self.encryption.as_ref(),
                                )
                                .await?,
                            ));
                            continue;
                        }
                    };
                    results.push(InvocationOutcome::OpenSessions(outcome));
                }
                _ => {}
            }
        }

        let read_audit_start = Instant::now();
        let record_result = self
            .read_audit
            .record(&invocation, self.encryption.as_ref())
            .await;
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::ReadAuditWait,
            crate::telemetry::StageOutcome::from(record_result.is_ok()),
            read_audit_start.elapsed(),
        );
        record_result?;
        Ok((
            TransactResult {
                commits: HashMap::new(),
                skipped_spaces: Vec::new(),
                delegation_cids: Vec::new(),
            },
            results,
        ))
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

/// Returns a `TransactResult` that acknowledges a delegation already durably
/// registered at `retained_hash` without creating new state.
fn already_registered_result(retained_hash: Hash) -> TransactResult {
    TransactResult {
        commits: HashMap::new(),
        skipped_spaces: Vec::new(),
        delegation_cids: vec![retained_hash],
    }
}

/// Bounded, privacy-safe diagnostic reason for a failed `/delegate` epoch
/// path. Never carries identifiers, hashes, database error text, or any
/// other request/response content — only this fixed tag and an aggregate
/// count are ever observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EpochReconcileReason {
    /// The epoch INSERT failed but `is_pk_epoch_conflict` did not recognize
    /// it as a pk-epoch race, so reconciliation was never attempted.
    ClassifierMiss,
    /// Reconciliation ran but found no delegation row for the retained hash.
    DelegationAbsent,
    /// Reconciliation ran but the ability row count did not match expected.
    AbilityMismatch,
    /// Reconciliation ran but the parent link count did not match expected.
    ParentMismatch,
    /// Reconciliation ran but no event_order row referenced the retained hash.
    EventOrderAbsent,
    /// A read performed during reconciliation itself returned a database error.
    ReconcileReadError,
}

impl EpochReconcileReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ClassifierMiss => "classifier_miss",
            Self::DelegationAbsent => "delegation_absent",
            Self::AbilityMismatch => "ability_mismatch",
            Self::ParentMismatch => "parent_mismatch",
            Self::EventOrderAbsent => "event_order_absent",
            Self::ReconcileReadError => "reconcile_read_error",
        }
    }

    fn counter(self) -> &'static AtomicU64 {
        static CLASSIFIER_MISS: AtomicU64 = AtomicU64::new(0);
        static DELEGATION_ABSENT: AtomicU64 = AtomicU64::new(0);
        static ABILITY_MISMATCH: AtomicU64 = AtomicU64::new(0);
        static PARENT_MISMATCH: AtomicU64 = AtomicU64::new(0);
        static EVENT_ORDER_ABSENT: AtomicU64 = AtomicU64::new(0);
        static RECONCILE_READ_ERROR: AtomicU64 = AtomicU64::new(0);
        match self {
            Self::ClassifierMiss => &CLASSIFIER_MISS,
            Self::DelegationAbsent => &DELEGATION_ABSENT,
            Self::AbilityMismatch => &ABILITY_MISMATCH,
            Self::ParentMismatch => &PARENT_MISMATCH,
            Self::EventOrderAbsent => &EVENT_ORDER_ABSENT,
            Self::ReconcileReadError => &RECONCILE_READ_ERROR,
        }
    }

    /// Test-observable aggregate count for this reason. Never exposes any
    /// per-request identifier — only the running total.
    pub fn count(self) -> u64 {
        self.counter().load(Ordering::Relaxed)
    }
}

/// Emits the diagnostic seam for a failed `/delegate` epoch path: a stable
/// bounded reason code via `tracing` plus an in-process aggregate count.
/// Carries no identifiers, Authorization bytes, hashes, or database text.
fn record_epoch_reconcile_failure(reason: EpochReconcileReason) {
    reason.counter().fetch_add(1, Ordering::Relaxed);
    tracing::warn!(reason = reason.as_str(), "delegate epoch path failed");
}

/// Post-rollback reconciliation for a confirmed pk-epoch conflict.
///
/// After a failed epoch INSERT (pk-epoch unique violation), the transaction is
/// fully rolled back. This does one bounded read-only pass to verify that the
/// exact delegation is already durably complete — covering the delegation row,
/// abilities, parent links, and event_order presence. Returns the retained CID
/// only when all invariants hold; otherwise preserves the original EpochInsert
/// error. No writes, no retries, no sleep.
async fn reconcile_pk_epoch_delegation<C: ConnectionTrait, S: StorageSetup, K: Secrets>(
    conn: &C,
    retained_hash: Hash,
    expected_ability_count: u64,
    expected_parent_count: u64,
) -> Result<TransactResult, TxError<S, K>> {
    // 1. Delegation row must exist.
    if delegation::Entity::find_by_id(retained_hash)
        .one(conn)
        .await
        .map_err(|e| {
            record_epoch_reconcile_failure(EpochReconcileReason::ReconcileReadError);
            TxError::Db(e)
        })?
        .is_none()
    {
        record_epoch_reconcile_failure(EpochReconcileReason::DelegationAbsent);
        return Err(TxError::EpochInsert(DbErr::Custom(
            "reconcile: delegation row absent after pk-epoch rollback".to_string(),
        )));
    }

    // 2. Exact expected ability count.
    let ability_count = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(retained_hash))
        .count(conn)
        .await
        .map_err(|e| {
            record_epoch_reconcile_failure(EpochReconcileReason::ReconcileReadError);
            TxError::Db(e)
        })?;
    if ability_count != expected_ability_count {
        record_epoch_reconcile_failure(EpochReconcileReason::AbilityMismatch);
        return Err(TxError::EpochInsert(DbErr::Custom(format!(
            "reconcile: ability count mismatch: expected {expected_ability_count} got {ability_count}"
        ))));
    }

    // 3. Exact expected parent link count.
    let parent_count = parent_delegations::Entity::find()
        .filter(parent_delegations::Column::Child.eq(retained_hash))
        .count(conn)
        .await
        .map_err(|e| {
            record_epoch_reconcile_failure(EpochReconcileReason::ReconcileReadError);
            TxError::Db(e)
        })?;
    if parent_count != expected_parent_count {
        record_epoch_reconcile_failure(EpochReconcileReason::ParentMismatch);
        return Err(TxError::EpochInsert(DbErr::Custom(format!(
            "reconcile: parent count mismatch: expected {expected_parent_count} got {parent_count}"
        ))));
    }

    // 4. At least one event_order row must reference the retained hash. Its
    //    epoch is not re-verified here: event_order.(epoch, space) carries a
    //    composite foreign key to epoch.(id, space) (see event_order::Relation
    //    in relationships/event_order.rs), so a durably committed event_order
    //    row is schema-guaranteed to reference an existing epoch row — a
    //    second read-based check here could never observe a different
    //    outcome and would only be speculative.
    let event_order_count = event_order::Entity::find()
        .filter(event_order::Column::Event.eq(retained_hash))
        .count(conn)
        .await
        .map_err(|e| {
            record_epoch_reconcile_failure(EpochReconcileReason::ReconcileReadError);
            TxError::Db(e)
        })?;
    if event_order_count == 0 {
        record_epoch_reconcile_failure(EpochReconcileReason::EventOrderAbsent);
        return Err(TxError::EpochInsert(DbErr::Custom(
            "reconcile: no event_order rows after pk-epoch rollback".to_string(),
        )));
    }

    Ok(already_registered_result(retained_hash))
}

/// Returns the sorted, deduplicated set of roots to lock for a delegation.
/// `retained_hash` (the delegation's own content hash) is always included so
/// that concurrent identical root delegations — which have no parents and would
/// otherwise produce an empty lock set — serialize on the same lock.
fn delegation_guard_roots(retained_hash: Hash, parent_hashes: &[Hash]) -> Vec<Hash> {
    let mut keys: Vec<Hash> = std::iter::once(retained_hash)
        .chain(parent_hashes.iter().copied())
        .collect();
    keys.sort_by(|a, b| a.as_ref().cmp(b.as_ref()));
    keys.dedup();
    keys
}

fn is_pk_epoch_conflict(error: &DbErr) -> bool {
    match error {
        DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(db_err)))
        | DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(db_err))) => {
            let code_owned = db_err.code();
            let code = code_owned.as_deref();
            if code == Some("23505") && db_err.constraint() == Some("pk-epoch") {
                return true;
            }
            // SQLite extended code 1555 = SQLITE_CONSTRAINT_PRIMARYKEY.
            // The driver omits constraint() for SQLite; match on the table name
            // in the message ("epoch.") to exclude other tables (e.g. epoch_order).
            if matches!(code, Some("1555") | Some("2067")) && db_err.message().contains("epoch.") {
                return true;
            }
            false
        }
        _ => false,
    }
}

#[derive(Debug)]
pub enum InvocationOutcome<R> {
    KvList(Vec<Path>, bool, Option<String>),
    KvDelete(Option<Hash>),
    KvMetadata(Option<(Metadata, Hash)>),
    KvWrite(Hash),
    KvBatchWrite(Vec<Path>),
    KvBatchRead(Vec<KvBatchReadItem>),
    KvRead(Option<(Metadata, Hash, Content<R>)>),
    OpenSessions(HashMap<Hash, DelegationInfo>),
    /// Ordered delegation chain from leaf to root
    DelegationChain(Vec<DelegationInfo>),
    SqlResult(serde_json::Value),
    SqlExport(Vec<u8>),
    DuckDbResult(serde_json::Value),
    DuckDbExport(Vec<u8>),
    DuckDbArrow(Vec<u8>),
    EncryptionDecrypt(crate::encryption_network::DecryptResponseBody),
}

#[derive(Debug)]
pub struct KvBatchReadItem {
    pub path: Path,
    pub value: Option<KvBatchReadValue>,
}

#[derive(Debug)]
pub struct KvBatchReadValue {
    pub metadata: Metadata,
    pub hash: Hash,
    pub data: Option<Vec<u8>>,
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
            Event::AdmittedInvocation(i, _) => {
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
    auth_graph: Option<&crate::auth_graph::AuthGraphSnapshot>,
) -> Result<TransactResult, TxError<S, K>> {
    // for each event, get the hash and the relevent space(s)
    let event_hashes = events
        .into_iter()
        .map(|e| (e.hash(), e))
        .collect::<Vec<(Hash, Event)>>();

    // ── Atomic delegation registration ──────────────────────────────────────
    // Register all delegations inside this transaction before any epoch rows
    // are written. This is the authoritative New/Existing decision; the
    // outcome determines which delegations participate in epoch construction.
    let mut registered: HashMap<Hash, delegation::DelegationRegistration> = HashMap::new();
    for (hash, event) in &event_hashes {
        if let Event::Delegation(d) = event {
            let reg = delegation::process(db, d, encryption).await?;
            registered.insert(*hash, reg);
        }
    }

    let event_spaces = event_spaces(db, &event_hashes).await?;

    // Exclude Existing delegations from epoch construction: they were already
    // registered in a prior committed transaction and must not create new
    // epoch, epoch_order, or event_order rows.
    let event_spaces: HashMap<SpaceId, Vec<&(Hash, Event)>> = event_spaces
        .into_iter()
        .filter_map(|(space, events)| {
            let eligible: Vec<_> = events
                .into_iter()
                .filter(|(hash, event)| {
                    !matches!(event, Event::Delegation(_))
                        || matches!(
                            registered.get(hash),
                            Some(delegation::DelegationRegistration::New(_))
                        )
                })
                .collect();
            if eligible.is_empty() {
                None
            } else {
                Some((space, eligible))
            }
        })
        .collect();

    // Only New delegations may trigger new space row creation.
    let mut new_spaces = event_hashes
        .iter()
        .filter_map(|(hash, e)| match e {
            Event::Delegation(d)
                if matches!(
                    registered.get(hash),
                    Some(delegation::DelegationRegistration::New(_))
                ) =>
            {
                Some(d.0.capabilities.iter().filter_map(|c| {
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
                }))
            }
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
                tracing::error!(
                    requested_spaces = ?event_spaces.keys().collect::<Vec<_>>(),
                    existing_spaces = ?existing,
                    "invocation referenced a space absent from the database"
                );
                return Err(TxError::SpaceNotFound);
            }
        }
        (event_spaces, vec![])
    };

    // If all spaces were filtered out, we still process delegations below
    // but skip epoch/event ordering creation
    if !event_spaces.is_empty() {
        // Next per-space sequence: one ungrouped MAX(seq) query per space
        // (spaces per commit are ~1). A grouped `GROUP BY space` aggregate gets
        // no min/max index shortcut and scans the index range per write; the
        // ungrouped form gets the O(log n) backward index probe on
        // `idx_event_order_space_seq`. Spaces with no events yield NULL and stay
        // absent from the map, so the later `.remove().unwrap_or(0)` still starts
        // them at sequence 0 — matching the grouped query's empty-group behavior.
        let mut max_seqs: HashMap<SpaceIdWrap, i64> = HashMap::new();
        for space in event_spaces.keys() {
            let max_seq = event_order::Entity::find()
                .filter(event_order::Column::Space.eq(SpaceIdWrap(space.clone())))
                .select_only()
                .column_as(event_order::Column::Seq.max(), "max_seq")
                .into_tuple::<Option<i64>>()
                .one(db)
                .await?
                .flatten();
            if let Some(seq) = max_seq {
                max_seqs.insert(SpaceIdWrap(space.clone()), seq + 1);
            }
        }

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
                Event::Delegation(_) => {
                    // Already registered atomically before epoch construction.
                    // Do not call delegation::process again.
                    if let Some(reg) = registered.get(&hash) {
                        delegation_cids.push(reg.hash());
                    }
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
                        auth_graph,
                    )
                    .await?;
                }
                Event::AdmittedInvocation(i, ops) => {
                    invocation::process_admitted(
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
                        auth_graph,
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
        // All spaces were skipped (delegation-only with no existing spaces).
        // Delegations are already registered; collect their CIDs.
        let mut delegation_cids = Vec::new();
        for (hash, event) in event_hashes {
            match event {
                Event::Delegation(_) => {
                    if let Some(reg) = registered.get(&hash) {
                        delegation_cids.push(reg.hash());
                    }
                }
                Event::Invocation(i, _ops) => {
                    invocation::process(db, *i, Vec::new(), encryption, auth_graph).await?;
                }
                Event::AdmittedInvocation(i, _ops) => {
                    invocation::process_admitted(db, *i, Vec::new(), encryption, auth_graph)
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
    list_bounded_after(db, space_id, prefix, limit, None).await
}

async fn list_bounded_after<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    prefix: &Path,
    limit: Option<usize>,
    after: Option<&Path>,
) -> Result<(Vec<Path>, bool), DbErr> {
    if let Some(after) = after {
        let prefix = prefix.as_str();
        let valid = after.as_str() == prefix
            || (prefix.is_empty() && !after.as_str().is_empty())
            || after
                .as_str()
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with('/'));
        if !valid {
            return Err(DbErr::Custom(
                "KV list cursor is outside the requested prefix".to_string(),
            ));
        }
    }
    let escaped_prefix = prefix
        .as_str()
        .replace('!', "!!")
        .replace('%', "!%")
        .replace('_', "!_");
    let mut query = Query::select();
    query
        .column((current_kv::Entity, current_kv::Column::Key))
        .from(current_kv::Entity)
        .cond_where(
            Condition::all()
                .add(Expr::col(current_kv::Column::Deleted).eq(false))
                .add(
                    Expr::col((current_kv::Entity, current_kv::Column::Key))
                        .like(LikeExpr::new(format!("{escaped_prefix}%")).escape('!')),
                )
                .add(
                    Expr::col((current_kv::Entity, current_kv::Column::Space))
                        .eq(SpaceIdWrap(space_id.clone())),
                ),
        );
    if let Some(after) = after {
        query.cond_where(
            Expr::col((current_kv::Entity, current_kv::Column::Key)).gt(after.as_str()),
        );
    }
    query.order_by((current_kv::Entity, current_kv::Column::Key), Order::Asc);
    if let Some(limit) = limit {
        query.limit(limit.saturating_add(1) as u64);
    }
    let mut list = db
        .query_all(db.get_database_backend().build(&query))
        .await?
        .into_iter()
        .map(|row| row.try_get::<String>("", current_kv::Column::Key.as_str()))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(|key| key.parse())
        .collect::<Result<Vec<Path>, _>>()
        .map_err(|error| DbErr::Custom(format!("invalid persisted KV path: {error}")))?;
    if let Some(after) = after {
        list.retain(|path| path.as_str() > after.as_str());
    }
    let truncated = limit.map(|limit| list.len() > limit).unwrap_or(false);
    if let Some(limit) = limit {
        list.truncate(limit);
    }
    Ok((list, truncated))
}

/// Return stable direct children of a KV folder. Unlike list_bounded, this
/// never exposes descendants as if they were children and de-duplicates keys
/// that share the same folder prefix. after is an exclusive lexical keyset
/// cursor, so immutable fixtures cannot produce duplicates or skips between
/// pages.
pub async fn list_direct_children_bounded<C: ConnectionTrait>(
    db: &C,
    space_id: &SpaceId,
    prefix: &Path,
    limit: usize,
    after: Option<&Path>,
) -> Result<(Vec<Path>, bool, Option<Path>), DbErr> {
    if limit == 0 {
        return Ok((Vec::new(), false, None));
    }
    let (descendants, _) = list_bounded(db, space_id, prefix, None).await?;
    let base = if prefix.as_str().is_empty() {
        String::new()
    } else {
        format!("{}/", prefix.as_str())
    };
    let mut children = std::collections::BTreeSet::new();
    for path in descendants {
        let Some(remainder) = path.as_str().strip_prefix(&base) else {
            continue;
        };
        if remainder.is_empty() {
            continue;
        }
        let child = remainder
            .split_once('/')
            .map_or(remainder, |(name, _)| name);
        let child = if base.is_empty() {
            child.to_owned()
        } else {
            format!("{base}{child}")
        };
        let child = child
            .parse::<Path>()
            .map_err(|error| DbErr::Custom(format!("invalid persisted KV path: {error}")))?;
        if after.is_none_or(|cursor| child.as_str() > cursor.as_str()) {
            children.insert(child);
        }
    }
    let mut children = children.into_iter().collect::<Vec<_>>();
    let truncated = children.len() > limit;
    if truncated {
        children.truncate(limit);
    }
    let next = truncated.then(|| children.last().cloned()).flatten();
    Ok((children, truncated, next))
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
) -> Result<Option<current_kv::Model>, DbErr> {
    let start = Instant::now();
    let query_result = current_kv::Entity::find_by_id((
        SpaceIdWrap(space_id.clone()),
        crate::types::Path(key.clone()),
    ))
    .filter(current_kv::Column::Deleted.eq(false))
    .one(db)
    .await;
    let result = match query_result {
        Ok(entry) => entry,
        Err(error) => {
            crate::telemetry::observe_stage(
                crate::telemetry::InvocationStage::KvIndexLookup,
                crate::telemetry::StageOutcome::Error,
                start.elapsed(),
            );
            return Err(error);
        }
    };
    crate::telemetry::observe_stage(
        crate::telemetry::InvocationStage::KvIndexLookup,
        crate::telemetry::StageOutcome::Ok,
        start.elapsed(),
    );
    Ok(result)
}

/// Half-open `[lower, upper)` bounds selecting every `ability.resource` that
/// belongs to `space_id`.
///
/// `ability.resource` is persisted through `Resource`'s `Display` impl, and a
/// TinyCloud resource always renders as
/// `{space}/{service}[/{path}][?query][#fragment]` (see `ResourceId`'s
/// `Display`). Both bounds are therefore derived from that same `Display`
/// impl, so the SQL prefix cannot drift from what the column actually holds
/// (address checksum canonicalisation, percent-encoding, and so on).
///
/// The upper bound appends U+10FFFD, the highest private-use code point.
/// Stored resources are `UriStr`-validated and therefore pure ASCII, and
/// U+10FFFD encodes as `F4 8F BF BD`, above every ASCII byte -- so under
/// **byte ordering** no resource belonging to the space can fall outside the
/// range. `byte_ordered_resource` is what guarantees the comparison actually
/// is byte-ordered; these bounds are meaningless without it.
///
/// The range is a *superset* filter, never an exact one. Callers keep the
/// exact `resource.space() == Some(space_id)` check in Rust to drop the rest.
fn space_resource_bounds(space_id: &SpaceId) -> (String, String) {
    let lower = format!("{space_id}/");
    let upper = format!("{lower}\u{10FFFD}");
    (lower, upper)
}

/// `ability.resource`, pinned to byte ordering.
///
/// Without this pin the bounds are compared using the *database's* collation,
/// and the prefix range silently means something else. Production runs
/// PostgreSQL with `en_US.UTF-8` (glibc), where U+10FFFD has no collation
/// weight at all: `{space}/` and `{space}/\u{10FFFD}` collate EQUAL, so the
/// half-open range is empty. Measured against the production database, the
/// unpinned range returned **0 rows** for a space whose true answer was
/// 55,568 -- every session would have activated with no delegations.
///
/// The byte-increment bound (`{space}0`) is no better: it fails the other way
/// on the same database, because glibc orders punctuation below digits only
/// at a lower weight level.
///
/// This is deliberately not conditional on the deployed collation. Byte
/// ordering is the only ordering under which these bounds mean what they say,
/// so it is stated unconditionally and the tests pin it.
///
/// Cost, on PostgreSQL: the pin also costs the index seek, and it does so
/// even on a C-collated database. `COLLATE "C"` carries collation OID 950,
/// while `pk-ability` was built with the column's default collation (OID
/// 100), and PostgreSQL requires an exact collation match to use an index --
/// so `ability` is scanned (measured on production: 68ms warm, 452ms cold).
/// That is still far cheaper than loading and decoding every delegation blob,
/// and it needs no migration. Recovering the seek needs an index on
/// `ability(resource)` declared `COLLATE "C"` (or `text_pattern_ops`) so its
/// OID matches, which is a migration and is deferred.
///
/// SQLite is unaffected: `COLLATE BINARY` there is the column's own
/// collation, so the range still resolves as an index seek.
fn byte_ordered_resource(backend: DbBackend) -> SimpleExpr {
    let resource = Expr::col((abilities::Entity, abilities::Column::Resource));
    // `$1` / `?` is sea-query's per-backend placeholder for the embedded
    // expression above, not for a bound value.
    match backend {
        DbBackend::Postgres => Expr::cust_with_expr(r#"$1 COLLATE "C""#, resource),
        // SQLite columns are BINARY (byte-ordered) by default; saying so
        // explicitly keeps the predicate index-usable and self-documenting.
        DbBackend::Sqlite => Expr::cust_with_expr("? COLLATE BINARY", resource),
        // MySQL's binary collation name depends on the column's charset, so
        // cast instead -- that is charset-independent.
        DbBackend::MySql => Expr::cust_with_expr("CAST(? AS BINARY)", resource),
    }
}

/// `delegation.id IN (SELECT delegation FROM ability WHERE <space range>)`.
///
/// A subquery rather than a predicate on the joined `ability` rows on purpose:
/// filtering the join directly would also truncate each returned delegation's
/// capability list, but callers need every capability a matching delegation
/// carries -- including capabilities in other spaces. `resource` is the
/// leading column of `ability`'s primary key, so on a byte-ordered database
/// the range resolves as an index seek with no new index.
fn delegations_touching_space(backend: DbBackend, space_id: &SpaceId) -> SimpleExpr {
    let (lower, upper) = space_resource_bounds(space_id);
    delegation::Column::Id.in_subquery(
        Query::select()
            .column(abilities::Column::Delegation)
            .from(abilities::Entity)
            .and_where(byte_ordered_resource(backend).gte(lower))
            .and_where(byte_ordered_resource(backend).lt(upper))
            .to_owned(),
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
            .filter(delegations_touching_space(
                db.get_database_backend(),
                space_id,
            ))
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
            // `delegations_touching_space` has already narrowed this to the
            // delegations whose resources fall in the space's prefix range;
            // the space check below is the exact filter over that superset.
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
            .filter(delegations_touching_space(
                db.get_database_backend(),
                space_id,
            ))
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

            // Space membership check. `delegations_touching_space` has already
            // narrowed this to the delegations whose resources fall in the
            // space's prefix range; this is the exact filter over that superset.
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
        use sea_orm::ActiveValue::Set;

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
        for (index, key) in [
            "a",
            "a",
            "b",
            "c",
            "literal%key",
            "literalXkey",
            "literal_key",
            "bang!key",
            "bangXkey",
        ]
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
            let write = kv_write::Model {
                space: SpaceIdWrap(space.clone()),
                key: key.parse::<Path>().unwrap().into(),
                invocation: invocation_id,
                seq: index as i64,
                epoch: epoch_id,
                epoch_seq: 0,
                value: shared_value,
                metadata: Metadata(std::collections::BTreeMap::new()),
            };
            kv_write::ActiveModel::from(write.clone())
                .insert(&db.conn)
                .await
                .unwrap();
            invocation::upsert_current_kv(&db.conn, write)
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
            vec!["a", "b", "bang!key"]
        );
        assert!(truncated);
        let (children, truncated, next) =
            list_direct_children_bounded(&db.conn, &space, &"".parse().unwrap(), 2, None)
                .await
                .unwrap();
        assert_eq!(
            children.iter().map(Path::as_str).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert!(truncated);
        assert_eq!(next.as_ref().map(Path::as_str), Some("b"));
        let (children, truncated, _) =
            list_direct_children_bounded(&db.conn, &space, &"".parse().unwrap(), 2, next.as_ref())
                .await
                .unwrap();
        // TC-381: the seed keys sort as
        // a, b, bang!key, bangXkey, c, literal%key, literalXkey, literal_key,
        // so the page after the "b" cursor is bang!key/bangXkey. This
        // expectation still said c/literal%key: it was written before
        // `bang!key`/`bangXkey` were added to the seed set on a parallel
        // branch, and the two merged cleanly because nothing in CI ran
        // tinycloud-core's tests.
        assert_eq!(
            children.iter().map(Path::as_str).collect::<Vec<_>>(),
            vec!["bang!key", "bangXkey"]
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

        for (prefix, expected) in [
            ("literal_", vec!["literal_key"]),
            ("bang!", vec!["bang!key"]),
        ] {
            let (paths, truncated) =
                list_bounded(&db.conn, &space, &prefix.parse().unwrap(), Some(10))
                    .await
                    .unwrap();
            assert_eq!(paths.iter().map(Path::as_str).collect::<Vec<_>>(), expected);
            assert!(!truncated);
        }

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
        invocation::delete_current_kv_if_invocation(
            &db.conn,
            &SpaceIdWrap(space.clone()),
            "a",
            crate::hash::hash(b"invocation-1"),
        )
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
            vec![
                "b",
                "bang!key",
                "bangXkey",
                "c",
                "literal%key",
                "literalXkey",
                "literal_key"
            ]
        );
        assert!(!truncated);
    }

    #[tokio::test]
    async fn current_reads_use_projection_indexes_with_large_history() {
        use sea_orm::ActiveValue::Set;

        let db = get_db().await.unwrap();
        db.conn
            .execute(Statement::from_string(
                DbBackend::Sqlite,
                "PRAGMA foreign_keys = OFF".to_string(),
            ))
            .await
            .unwrap();
        let space = test_space_id("projection-query-plan");
        let key: Path = "needle".parse().unwrap();
        let mut writes = Vec::with_capacity(5_000);
        for seq in 0..5_000 {
            writes.push(kv_write::ActiveModel {
                space: Set(SpaceIdWrap(space.clone())),
                key: Set(key.clone().into()),
                invocation: Set(crate::hash::hash(format!("history-{seq}").as_bytes())),
                seq: Set(seq),
                epoch: Set(crate::hash::hash(b"query-plan-epoch")),
                epoch_seq: Set(0),
                value: Set(crate::hash::hash(format!("value-{seq}").as_bytes())),
                metadata: Set(Metadata(std::collections::BTreeMap::new())),
            });
        }
        for chunk in writes.chunks(50) {
            kv_write::Entity::insert_many(chunk.iter().cloned())
                .exec(&db.conn)
                .await
                .unwrap();
        }
        let winner = kv_write::Entity::find()
            .filter(kv_write::Column::Space.eq(SpaceIdWrap(space.clone())))
            .filter(kv_write::Column::Key.eq(key.as_str()))
            .order_by_desc(kv_write::Column::Seq)
            .one(&db.conn)
            .await
            .unwrap()
            .unwrap();
        invocation::upsert_current_kv(&db.conn, winner)
            .await
            .unwrap();

        async fn explain(conn: &sea_orm::DatabaseConnection, sql: String) -> Vec<String> {
            conn.query_all(Statement::from_string(
                DbBackend::Sqlite,
                format!("EXPLAIN QUERY PLAN {sql}"),
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.try_get::<String>("", "detail").unwrap())
            .collect()
        }

        let space_sql = space.to_string().replace('\'', "''");
        let legacy_exact = explain(
            &db.conn,
            format!(
                "SELECT w.* FROM kv_write w LEFT JOIN kv_delete d ON w.space=d.space AND w.key=d.key AND w.invocation=d.deleted_invocation_id WHERE w.space='{space_sql}' AND w.key='needle' ORDER BY w.seq DESC,w.epoch DESC,w.epoch_seq DESC LIMIT 1"
            ),
        )
        .await;
        let current_exact = explain(
            &db.conn,
            format!("SELECT * FROM current_kv WHERE space='{space_sql}' AND key='needle' LIMIT 1"),
        )
        .await;
        let legacy_list = explain(
            &db.conn,
            format!(
                "SELECT w.key FROM kv_write w LEFT JOIN kv_delete d ON w.space=d.space AND w.key=d.key AND w.invocation=d.deleted_invocation_id WHERE w.space='{space_sql}' AND w.key LIKE 'need%' ESCAPE '!' AND d.invocation_id IS NULL AND NOT EXISTS (SELECT 1 FROM kv_write newer WHERE newer.space=w.space AND newer.key=w.key AND (newer.seq>w.seq OR (newer.seq=w.seq AND newer.epoch>w.epoch) OR (newer.seq=w.seq AND newer.epoch=w.epoch AND newer.epoch_seq>w.epoch_seq))) ORDER BY w.key LIMIT 11"
            ),
        )
        .await;
        let current_list = explain(
            &db.conn,
            format!(
                "SELECT key FROM current_kv WHERE space='{space_sql}' AND deleted=0 AND key LIKE 'need%' ESCAPE '!' ORDER BY key LIMIT 11"
            ),
        )
        .await;

        println!(
            "TC-271 query-plan evidence: history_rows=5000 projection_rows=1 legacy_exact={legacy_exact:?} current_exact={current_exact:?} legacy_list={legacy_list:?} current_list={current_list:?}"
        );
        assert!(legacy_exact.iter().any(|line| line.contains("kv_write")));
        assert!(legacy_list.iter().any(|line| line.contains("kv_write")));
        for plan in [&current_exact, &current_list] {
            assert!(plan.iter().any(|line| {
                line.contains("current_kv") && (line.contains("INDEX") || line.contains("PRIMARY"))
            }));
            assert!(plan
                .iter()
                .all(|line| !line.contains("kv_write") && !line.contains("kv_delete")));
        }
        assert_eq!(
            kv_write::Entity::find().count(&db.conn).await.unwrap(),
            5_000
        );
        assert_eq!(current_kv::Entity::find().count(&db.conn).await.unwrap(), 1);
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

    // ── TC-324: shared chain guards for invocations ─────────────────────────
    //
    // Invocations take the chain guards SHARED; delegation registration and
    // revocation take them EXCLUSIVE. The tests below pin both halves of that
    // contract: the concurrency that was bought, and the revocation ordering
    // that must survive buying it.

    type TestDb = SpaceDatabase<sea_orm::DbConn, MemoryStore, StaticSecret>;

    /// Insert a standalone delegation row and return its id.
    async fn insert_test_delegation(db: &TestDb, label: &str) -> Hash {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        let id = crate::hash::hash(label.as_bytes());
        delegation::ActiveModel {
            id: Set(id),
            delegator: Set("did:key:chain-guard-owner".to_string()),
            delegatee: Set("did:key:chain-guard-holder".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(label.as_bytes().to_vec()),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        id
    }

    /// Build `parent <- child`, the shape every chain-scoped guard walks.
    async fn insert_test_chain(db: &TestDb, label: &str) -> (Hash, Hash) {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        let parent = insert_test_delegation(db, &format!("{label}-parent")).await;
        let child = insert_test_delegation(db, &format!("{label}-child")).await;
        parent_delegations::ActiveModel {
            parent: Set(parent),
            child: Set(child),
        }
        .insert(&db.conn)
        .await
        .unwrap();
        (parent, child)
    }

    async fn insert_chain_guard_actors(db: &TestDb) {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        for actor_id in ["did:key:chain-guard-owner", "did:key:chain-guard-holder"] {
            actor::ActiveModel {
                id: Set(actor_id.to_string()),
            }
            .insert(&db.conn)
            .await
            .unwrap();
        }
    }

    /// Resolve the ancestor closure exactly as `invoke_with_options_mode`
    /// does, then take the guards shared — the production invocation path.
    async fn invocation_chain_keys(db: &TestDb, roots: &[Hash]) -> Vec<Hash> {
        crate::auth_graph::load_closure_edges(&db.conn, roots)
            .await
            .map(|(keys, _)| keys)
            .expect("chain closure query")
    }

    async fn acquire_invocation_guards(db: &TestDb, roots: &[Hash]) -> Vec<SharedChainGuard> {
        let keys = invocation_chain_keys(db, roots).await;
        db.acquire_shared_chain_guards_for_keys(keys).await
    }

    async fn insert_test_revocation(db: &TestDb, label: &str, revoked: Hash) {
        use sea_orm::{ActiveModelTrait, ActiveValue::Set};

        revocation::ActiveModel {
            id: Set(crate::hash::hash(label.as_bytes())),
            revoker: Set("did:key:chain-guard-owner".to_string()),
            revoked: Set(revoked),
            serialization: Set(label.as_bytes().to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&db.conn)
        .await
        .unwrap();
    }

    /// Let a spawned task run far enough to block on a contended guard.
    async fn settle() {
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    }

    /// TC-324 requirement 1: invocations sharing one root delegation must
    /// hold the chain guard at the same time, not merely all succeed.
    ///
    /// The barrier is the proof of overlap: it can only be satisfied if every
    /// task is inside the guarded section simultaneously. Under the previous
    /// exclusive mutex this test would deadlock until the timeout, because
    /// task 1 would hold the root guard while waiting for tasks that cannot
    /// acquire it.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn invocations_sharing_one_root_hold_the_chain_guard_concurrently() {
        const INVOCATIONS: usize = 8;

        let db = get_db().await.unwrap();
        insert_chain_guard_actors(&db).await;
        let (_parent, child) = insert_test_chain(&db, "shared-concurrency").await;

        // Resolve the closure once so the test measures guard behaviour, not
        // SQLite pool contention.
        let keys = invocation_chain_keys(&db, &[child]).await;
        assert_eq!(
            keys.len(),
            2,
            "the full ancestor closure must still be guarded, not just the cited delegation"
        );

        let rendezvous = Arc::new(tokio::sync::Barrier::new(INVOCATIONS));
        let mut handles = Vec::with_capacity(INVOCATIONS);
        for _ in 0..INVOCATIONS {
            let db = db.clone();
            let keys = keys.clone();
            let rendezvous = rendezvous.clone();
            handles.push(tokio::spawn(async move {
                let guards = db.acquire_shared_chain_guards_for_keys(keys).await;
                // Unreachable unless every other invocation also holds the
                // shared guards right now.
                rendezvous.wait().await;
                drop(guards);
            }));
        }

        for handle in handles {
            tokio::time::timeout(std::time::Duration::from_secs(10), handle)
                .await
                .expect("invocations sharing a root delegation must overlap under the chain guard")
                .unwrap();
        }
    }

    /// TC-324 requirement 2: the revocation barrier survives shared guards,
    /// in both directions.
    ///
    /// Direction A — a revocation cannot commit while an invocation holds
    /// shared guards on the chain it revokes.
    /// Direction B — an invocation that starts after the revocation commits
    /// observes the revocation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn revocation_waits_for_in_flight_invocations_and_is_visible_after() {
        let db = get_db().await.unwrap();
        insert_chain_guard_actors(&db).await;
        let (parent, child) = insert_test_chain(&db, "revocation-barrier").await;

        // An invocation is in flight, authorizing against the chain.
        let in_flight = acquire_invocation_guards(&db, &[child]).await;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let revoke_db = db.clone();
        let revoke = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            let guards = revoke_db
                .acquire_chain_guards(&[parent])
                .await
                .ok()
                .expect("revocation chain guards");
            // The write happens under the exclusive guards, as `revoke` does.
            insert_test_revocation(&revoke_db, "revocation-barrier-revocation", parent).await;
            drop(guards);
        });

        started_rx.await.unwrap();
        settle().await;

        // Direction A. `is_finished` alone would only say the task is slow;
        // the durable check is that the revocation has not become visible.
        assert!(
            !revoke.is_finished(),
            "a revocation must wait for in-flight invocations holding shared guards on that chain"
        );
        assert!(
            !crate::models::revocation::is_revoked(&db.conn, &parent)
                .await
                .unwrap(),
            "a revocation must not commit while an invocation is being authorized against the chain"
        );

        // The in-flight invocation finishes and releases its shared guards.
        drop(in_flight);
        tokio::time::timeout(std::time::Duration::from_secs(10), revoke)
            .await
            .expect("the revocation must proceed once the shared guards are released")
            .unwrap();

        // Direction B: an invocation starting now is rejected by the chain.
        let after = acquire_invocation_guards(&db, &[child]).await;
        assert!(
            crate::models::revocation::is_revoked(&db.conn, &parent)
                .await
                .unwrap(),
            "an invocation starting after the revocation commits must observe it"
        );
        drop(after);
    }

    /// TC-324 requirement 3: delegation registration still mutually excludes
    /// against invocations on the same chain, in both orders.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn delegation_registration_excludes_invocations_on_the_same_chain() {
        let db = get_db().await.unwrap();
        insert_chain_guard_actors(&db).await;
        let (parent, child) = insert_test_chain(&db, "registration-exclusion").await;

        // Registration first: an invocation must not slip in beside it.
        let registration = db
            .acquire_chain_guards(&[parent])
            .await
            .ok()
            .expect("delegation registration chain guards");

        let keys = invocation_chain_keys(&db, &[child]).await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let invoke_db = db.clone();
        let invoke_keys = keys.clone();
        let invoke = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            invoke_db
                .acquire_shared_chain_guards_for_keys(invoke_keys)
                .await
        });
        started_rx.await.unwrap();
        settle().await;
        assert!(
            !invoke.is_finished(),
            "an invocation must not authorize against a chain while a delegation is being registered on it"
        );
        drop(registration);
        let invocation_guards = tokio::time::timeout(std::time::Duration::from_secs(10), invoke)
            .await
            .expect("the invocation must proceed once registration releases the chain")
            .unwrap();

        // Reverse order: an in-flight invocation blocks registration.
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let register_db = db.clone();
        let register = tokio::spawn(async move {
            started_tx.send(()).unwrap();
            register_db
                .acquire_chain_guards(&[parent])
                .await
                .ok()
                .expect("delegation registration chain guards")
        });
        started_rx.await.unwrap();
        settle().await;
        assert!(
            !register.is_finished(),
            "delegation registration must wait for in-flight invocations on the same chain"
        );
        drop(invocation_guards);
        tokio::time::timeout(std::time::Duration::from_secs(10), register)
            .await
            .expect("registration must proceed once the shared guards are released")
            .unwrap();
    }

    /// TC-324 requirement 4: `tokio::sync::RwLock` is write-preferring, so a
    /// revocation queued behind a continuous stream of invocations still
    /// acquires within a bounded time. This is the property that makes shared
    /// invocation guards safe rather than merely fast — without it, a busy
    /// account could hold a revocation off indefinitely.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_queued_revocation_is_not_starved_by_a_stream_of_invocations() {
        const READERS: usize = 8;

        let db = get_db().await.unwrap();
        insert_chain_guard_actors(&db).await;
        let (parent, child) = insert_test_chain(&db, "starvation").await;
        let keys = invocation_chain_keys(&db, &[child]).await;

        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut readers = Vec::with_capacity(READERS);
        for _ in 0..READERS {
            let db = db.clone();
            let keys = keys.clone();
            let stop = stop.clone();
            readers.push(tokio::spawn(async move {
                let mut acquisitions = 0u64;
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    let guards = db.acquire_shared_chain_guards_for_keys(keys.clone()).await;
                    acquisitions += 1;
                    // Hold long enough that the reader cohorts overlap, so a
                    // reader-preferring lock really would starve the writer.
                    tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                    drop(guards);
                    tokio::task::yield_now().await;
                }
                acquisitions
            }));
        }

        // Let the invocation stream saturate the chain before queueing behind it.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        let queued_at = Instant::now();
        let revocation_guards = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            db.acquire_chain_guards(&[parent]),
        )
        .await
        .expect("a revocation must not be starved by a continuous stream of invocations")
        .ok()
        .expect("revocation chain guards");
        let waited = queued_at.elapsed();

        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        drop(revocation_guards);

        let mut total_acquisitions = 0u64;
        for reader in readers {
            total_acquisitions += reader.await.unwrap();
        }

        println!(
            "TC-324 starvation evidence: {total_acquisitions} shared acquisitions across \
             {READERS} concurrent invocation loops; queued revocation waited {waited:?}"
        );
        assert!(
            total_acquisitions >= READERS as u64,
            "the invocation stream must actually have been running (saw {total_acquisitions} acquisitions)"
        );
        assert!(
            waited < std::time::Duration::from_secs(2),
            "a queued revocation must acquire promptly; waited {waited:?}"
        );
    }

    /// TC-324 requirement 5: multi-chain acquisitions requested in inverse
    /// order must not deadlock, because every acquisition normalizes to the
    /// same sorted key order.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn inverse_order_multi_chain_acquisitions_do_not_deadlock() {
        let db = get_db().await.unwrap();
        insert_chain_guard_actors(&db).await;
        let (_first_parent, first) = insert_test_chain(&db, "inverse-order-first").await;
        let (_second_parent, second) = insert_test_chain(&db, "inverse-order-second").await;

        // The discipline itself: inverse argument order resolves to the same
        // lock sequence, so no participant can invert the acquisition order.
        let forward = db.chain_locks_for_keys(vec![first, second]).await;
        let reverse = db.chain_locks_for_keys(vec![second, first]).await;
        assert_eq!(forward.len(), 2);
        assert_eq!(reverse.len(), 2);
        assert!(
            forward
                .iter()
                .zip(reverse.iter())
                .all(|(left, right)| Arc::ptr_eq(left, right)),
            "inverse argument order must normalize to one global acquisition order"
        );
        drop(forward);
        drop(reverse);

        // And in anger: exclusive and shared acquisitions spanning both
        // chains, requested in opposing orders, repeatedly interleaved.
        let first_keys = invocation_chain_keys(&db, &[first, second]).await;
        let second_keys = invocation_chain_keys(&db, &[second, first]).await;
        for _ in 0..25 {
            let exclusive_forward = {
                let db = db.clone();
                tokio::spawn(async move { drop(db.acquire_chain_guards(&[first, second]).await) })
            };
            let exclusive_reverse = {
                let db = db.clone();
                tokio::spawn(async move { drop(db.acquire_chain_guards(&[second, first]).await) })
            };
            let shared_forward = {
                let db = db.clone();
                let keys = first_keys.clone();
                tokio::spawn(
                    async move { drop(db.acquire_shared_chain_guards_for_keys(keys).await) },
                )
            };
            let shared_reverse = {
                let db = db.clone();
                let keys = second_keys.clone();
                tokio::spawn(
                    async move { drop(db.acquire_shared_chain_guards_for_keys(keys).await) },
                )
            };

            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                exclusive_forward.await.unwrap();
                exclusive_reverse.await.unwrap();
                shared_forward.await.unwrap();
                shared_reverse.await.unwrap();
            })
            .await
            .expect("sorted key order must prevent a multi-chain lock-order inversion");
        }
    }

    #[tokio::test]
    async fn postgres_concurrent_epoch_appends_do_not_serialize() {
        let Some(database_url) = crate::test_support::postgres_test_url(
            "postgres_concurrent_epoch_appends_do_not_serialize",
        ) else {
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
    async fn sqlite_pk_epoch_conflict_matches_live_driver() {
        let db = get_db().await.unwrap();
        let space = test_space_id("pk-epoch-conflict");
        space::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(&db.conn)
        .await
        .unwrap();

        let epoch_id = crate::hash::hash(b"sqlite-pk-epoch-conflict");
        let model = epoch::ActiveModel {
            seq: Set(0),
            id: Set(epoch_id),
            space: Set(SpaceIdWrap(space.clone())),
        };

        epoch::Entity::insert(model.clone())
            .exec(&db.conn)
            .await
            .unwrap();

        let error = epoch::Entity::insert(model)
            .exec(&db.conn)
            .await
            .unwrap_err();

        // Sanitized metadata only — never print the full message
        if let DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(ref db_err)))
        | DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(ref db_err))) = error
        {
            let code = db_err.code();
            let constraint = db_err.constraint();
            let msg_has_pk_epoch = db_err.message().contains("pk-epoch");
            let msg_has_epoch = db_err.message().contains("epoch");
            let msg_has_unique =
                db_err.message().contains("unique") || db_err.message().contains("UNIQUE");
            eprintln!(
                "sqlite pk-epoch conflict: code={:?} constraint={:?} msg_has_pk_epoch={} msg_has_epoch={} msg_has_unique={}",
                code, constraint, msg_has_pk_epoch, msg_has_epoch, msg_has_unique
            );
        }

        assert!(
            is_pk_epoch_conflict(&error),
            "is_pk_epoch_conflict must return true for a duplicate pk-epoch insert"
        );
    }

    #[tokio::test]
    async fn sqlite_pk_epoch_batch_conflict_matches_live_driver() {
        let db = get_db().await.unwrap();
        let space = test_space_id("pk-epoch-batch-conflict");
        space::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(&db.conn)
        .await
        .unwrap();

        let epoch_id = crate::hash::hash(b"sqlite-pk-epoch-batch-conflict");
        let model = epoch::ActiveModel {
            seq: Set(0),
            id: Set(epoch_id),
            space: Set(SpaceIdWrap(space.clone())),
        };

        let error = epoch::Entity::insert_many([model.clone(), model])
            .exec(&db.conn)
            .await
            .unwrap_err();

        // Sanitized metadata only — never print the full message
        if let DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(ref db_err)))
        | DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(ref db_err))) = error
        {
            let code = db_err.code();
            let constraint = db_err.constraint();
            let msg_has_pk_epoch = db_err.message().contains("pk-epoch");
            let msg_has_epoch_dot = db_err.message().contains("epoch.");
            let msg_has_epoch = db_err.message().contains("epoch");
            let msg_has_unique =
                db_err.message().contains("unique") || db_err.message().contains("UNIQUE");
            eprintln!(
                "sqlite pk-epoch batch conflict: code={:?} constraint={:?} msg_has_pk_epoch={} msg_has_epoch_dot={} msg_has_epoch={} msg_has_unique={}",
                code, constraint, msg_has_pk_epoch, msg_has_epoch_dot, msg_has_epoch, msg_has_unique
            );
        }

        assert!(
            is_pk_epoch_conflict(&error),
            "is_pk_epoch_conflict must return true for a batch duplicate pk-epoch insert"
        );
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

    /// classifier_miss is the reason recorded when an EpochInsert error is
    /// *not* recognized by `is_pk_epoch_conflict` — e.g. the FK violation
    /// above, as opposed to an actual pk-epoch unique-constraint race.
    #[tokio::test]
    async fn classifier_miss_reason_recorded_for_non_pk_epoch_epoch_insert_error() {
        let db = get_db().await.unwrap();
        let space = test_space_id("classifier-miss-ghost");
        let err = epoch::Entity::insert(epoch::ActiveModel::from(epoch::Model {
            seq: 0,
            id: crate::hash::hash(b"classifier-miss-ghost-epoch"),
            space: SpaceIdWrap(space),
        }))
        .exec(&db.conn)
        .await
        .unwrap_err();

        assert!(
            !is_pk_epoch_conflict(&err),
            "an FK violation must not be classified as a pk-epoch conflict"
        );

        let before = EpochReconcileReason::ClassifierMiss.count();
        record_epoch_reconcile_failure(EpochReconcileReason::ClassifierMiss);
        assert_eq!(
            EpochReconcileReason::ClassifierMiss.count(),
            before + 1,
            "classifier_miss reason count must increment exactly once"
        );
    }

    /// reconcile_read_error is the reason recorded when a read performed
    /// during reconciliation itself fails at the database layer (as opposed
    /// to succeeding but finding a state mismatch). A live connection failure
    /// mid-reconciliation is not practical to reproduce deterministically in
    /// a unit test, so this proves the counting seam in isolation.
    #[test]
    fn reconcile_read_error_reason_count_increments() {
        let before = EpochReconcileReason::ReconcileReadError.count();
        record_epoch_reconcile_failure(EpochReconcileReason::ReconcileReadError);
        assert_eq!(
            EpochReconcileReason::ReconcileReadError.count(),
            before + 1,
            "reconcile_read_error reason count must increment exactly once"
        );
    }

    #[test]
    fn delegation_guard_roots_includes_self_and_deduplicates() {
        let h = crate::hash::hash;
        let retained = h(b"self");
        let parent_a = h(b"parent_a");
        let parent_b = h(b"parent_b");

        // Empty parent list: exactly the retained hash.
        let roots = delegation_guard_roots(retained, &[]);
        assert_eq!(roots, vec![retained]);

        // Existing parents: retained hash + both parents present.
        let roots = delegation_guard_roots(retained, &[parent_a, parent_b]);
        assert_eq!(roots.len(), 3);
        assert!(roots.contains(&retained));
        assert!(roots.contains(&parent_a));
        assert!(roots.contains(&parent_b));

        // Duplicate retained hash in parents is deduplicated.
        let roots = delegation_guard_roots(retained, &[parent_a, retained, parent_b]);
        assert_eq!(roots.len(), 3, "duplicate retained hash must be deduped");
        assert!(roots.contains(&retained));
        assert!(roots.contains(&parent_a));
        assert!(roots.contains(&parent_b));

        // Duplicate parent is deduplicated.
        let roots = delegation_guard_roots(retained, &[parent_a, parent_a]);
        assert_eq!(roots.len(), 2, "duplicate parent must be deduped");
        assert!(roots.contains(&retained));
        assert!(roots.contains(&parent_a));
    }

    // --- precheck helper and already_registered_result tests ---

    async fn insert_delegation_row(db: &sea_orm::DbConn, hash: Hash) {
        use sea_orm::ActiveModelTrait;
        for actor_id in ["did:key:a", "did:key:b"] {
            actor::ActiveModel {
                id: Set(actor_id.to_string()),
            }
            .insert(db)
            .await
            .ok();
        }
        delegation::ActiveModel {
            id: Set(hash),
            delegator: Set("did:key:a".to_string()),
            delegatee: Set("did:key:b".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(hash.as_ref().to_vec()),
        }
        .insert(db)
        .await
        .unwrap();
    }

    // --- already_registered_result precheck tests ---

    /// A delegation row already in the database is returned as durable without
    /// going through the epoch path: commits is empty, delegation_cids contains
    /// exactly the retained hash.
    #[tokio::test]
    async fn precheck_exact_retained_hash_returns_durable_cid_without_epoch() {
        let db = get_db().await.unwrap();
        let hash = crate::hash::hash(b"precheck-exact-retained");
        insert_delegation_row(&db.conn, hash).await;

        // Simulate what delegate() does for the pre-check query.
        let row = delegation::Entity::find_by_id(hash)
            .one(&db.conn)
            .await
            .expect("query must not fail");
        assert!(row.is_some(), "row must be present");

        let result = already_registered_result(hash);
        assert!(result.commits.is_empty(), "no epoch commits expected");
        assert!(result.skipped_spaces.is_empty());
        assert_eq!(result.delegation_cids, vec![hash]);
    }

    /// A hash that has no corresponding delegation row returns None, so the
    /// pre-check falls through to the normal transact path.
    #[tokio::test]
    async fn precheck_absent_hash_does_not_short_circuit() {
        let db = get_db().await.unwrap();
        let hash = crate::hash::hash(b"precheck-absent");

        let row = delegation::Entity::find_by_id(hash)
            .one(&db.conn)
            .await
            .expect("query must not fail");
        assert!(
            row.is_none(),
            "absent hash must return None — caller proceeds to transact"
        );
    }

    /// A different hash that is present must not be confused with the retained
    /// hash: the pre-check is an exact primary-key lookup.
    #[tokio::test]
    async fn precheck_different_hash_does_not_match_retained() {
        let db = get_db().await.unwrap();
        let present_hash = crate::hash::hash(b"precheck-different-present");
        let retained_hash = crate::hash::hash(b"precheck-different-retained");
        insert_delegation_row(&db.conn, present_hash).await;

        let row = delegation::Entity::find_by_id(retained_hash)
            .one(&db.conn)
            .await
            .expect("query must not fail");
        assert!(
            row.is_none(),
            "a different hash in the table must not satisfy the retained-hash lookup"
        );
    }

    // ── Atomic registration tests ────────────────────────────────────────────

    /// When a delegation is already committed to the DB, the ON CONFLICT path
    /// returns RecordNotInserted (→ DelegationRegistration::Existing).  The
    /// transact() filter then excludes the Existing delegation from epoch/
    /// event_order construction, so no new rows are created and the same CID
    /// is returned.  This test proves the DB-level invariant; the code
    /// structural proof covers the epoch-filter gate.
    #[tokio::test]
    async fn existing_delegation_returns_same_cid_with_no_new_epoch_rows() {
        let db = get_db().await.unwrap();
        let hash = crate::hash::hash(b"existing-no-epoch-bytes");
        insert_delegation_row(&db.conn, hash).await;

        let epoch_before = epoch::Entity::find().count(&db.conn).await.unwrap();
        let event_order_before = event_order::Entity::find().count(&db.conn).await.unwrap();

        // Re-insert via ON CONFLICT DO NOTHING — mimics what delegation::process
        // (→ save()) does inside transact() for the same serialization bytes.
        let result = delegation::Entity::insert(delegation::ActiveModel {
            id: Set(hash),
            delegator: Set("did:key:a".to_string()),
            delegatee: Set("did:key:b".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(hash.as_ref().to_vec()),
        })
        .on_conflict(
            OnConflict::column(delegation::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec(&db.conn)
        .await;

        // The Existing outcome (RecordNotInserted) must be detected.
        assert!(
            matches!(result, Err(DbErr::RecordNotInserted)),
            "committed delegation re-insert must return Existing"
        );

        // No new epoch or event_order rows — the transact() filter gate on
        // DelegationRegistration::Existing prevents their creation.
        assert_eq!(
            epoch::Entity::find().count(&db.conn).await.unwrap(),
            epoch_before,
            "Existing delegation must not create a new epoch row"
        );
        assert_eq!(
            event_order::Entity::find().count(&db.conn).await.unwrap(),
            event_order_before,
            "Existing delegation must not create a new event_order row"
        );

        // The same hash (CID) is still present exactly once.
        let del_count = delegation::Entity::find()
            .filter(delegation::Column::Id.eq(hash))
            .count(&db.conn)
            .await
            .unwrap();
        assert_eq!(del_count, 1, "exactly one delegation row must remain");
    }

    /// A transaction that claims a delegation (inserts it) but is then rolled
    /// back must allow a subsequent transaction to see New again — the claim
    /// rolls back atomically with any other writes in that transaction.
    #[tokio::test]
    async fn delegation_claim_rolls_back_so_retry_is_new() {
        use sea_orm::TransactionTrait;

        let db = get_db().await.unwrap();
        let ser = b"rollback-delegation-bytes".to_vec();
        let hash = crate::hash::hash(&ser);

        for actor in ["did:key:rb-owner", "did:key:rb-delegate"] {
            actor::ActiveModel {
                id: Set(actor.to_string()),
            }
            .insert(&db.conn)
            .await
            .ok();
        }

        // Begin a transaction, insert the delegation row, then roll back.
        {
            let tx = db.conn.begin().await.unwrap();
            delegation::ActiveModel {
                id: Set(hash),
                delegator: Set("did:key:rb-owner".to_string()),
                delegatee: Set("did:key:rb-delegate".to_string()),
                expiry: Set(None),
                issued_at: Set(None),
                not_before: Set(None),
                facts: Set(None),
                serialization: Set(ser.clone()),
            }
            .insert(&tx)
            .await
            .unwrap();
            tx.rollback().await.unwrap();
        }

        // The rolled-back row must not be visible outside the transaction.
        let row = delegation::Entity::find_by_id(hash)
            .one(&db.conn)
            .await
            .unwrap();
        assert!(
            row.is_none(),
            "rolled-back delegation must not be visible after rollback"
        );

        // A retry in a new transaction must observe New (not Existing).
        let tx2 = db.conn.begin().await.unwrap();
        let retry = delegation::Entity::insert(delegation::ActiveModel {
            id: Set(hash),
            delegator: Set("did:key:rb-owner".to_string()),
            delegatee: Set("did:key:rb-delegate".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(ser),
        })
        .on_conflict(
            OnConflict::column(delegation::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec(&tx2)
        .await;
        tx2.commit().await.unwrap();

        assert!(
            !matches!(retry, Err(DbErr::RecordNotInserted)),
            "retry after rollback must be New, not Existing"
        );
    }

    /// Two delegations with distinct serialization bytes produce distinct hashes
    /// and must not satisfy each other's exact-hash registration predicate.
    #[tokio::test]
    async fn distinct_delegations_do_not_satisfy_each_other() {
        use sea_orm::TransactionTrait;

        let db = get_db().await.unwrap();

        let ser_a = b"distinct-delegation-alpha".to_vec();
        let ser_b = b"distinct-delegation-beta".to_vec();
        let hash_a = crate::hash::hash(&ser_a);
        let hash_b = crate::hash::hash(&ser_b);
        assert_ne!(
            hash_a, hash_b,
            "test precondition: distinct bytes → distinct hashes"
        );

        for actor in ["did:key:dd-owner", "did:key:dd-delegate"] {
            actor::ActiveModel {
                id: Set(actor.to_string()),
            }
            .insert(&db.conn)
            .await
            .ok();
        }

        let make_model = |hash: Hash, ser: Vec<u8>| delegation::ActiveModel {
            id: Set(hash),
            delegator: Set("did:key:dd-owner".to_string()),
            delegatee: Set("did:key:dd-delegate".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(ser),
        };

        let tx = db.conn.begin().await.unwrap();
        for (hash, ser) in [(hash_a, ser_a), (hash_b, ser_b)] {
            delegation::Entity::insert(make_model(hash, ser))
                .on_conflict(
                    OnConflict::column(delegation::Column::Id)
                        .do_nothing()
                        .to_owned(),
                )
                .exec(&tx)
                .await
                .unwrap();
        }
        tx.commit().await.unwrap();

        let row_a = delegation::Entity::find_by_id(hash_a)
            .one(&db.conn)
            .await
            .unwrap()
            .expect("hash_a must be present");
        let row_b = delegation::Entity::find_by_id(hash_b)
            .one(&db.conn)
            .await
            .unwrap()
            .expect("hash_b must be present");

        assert_ne!(
            row_a.id, row_b.id,
            "distinct delegations must not share a primary key"
        );

        // A compound predicate using one hash against the other must return nothing.
        let cross_lookup = delegation::Entity::find_by_id(hash_b)
            .filter(delegation::Column::Id.eq(hash_a))
            .one(&db.conn)
            .await
            .unwrap();
        assert!(
            cross_lookup.is_none(),
            "hash_a must not satisfy hash_b's exact-hash predicate"
        );
    }

    // ── Reconciliation tests ─────────────────────────────────────────────────

    /// Build the complete durable state that reconcile_pk_epoch_delegation
    /// expects for a delegation that was committed by a concurrent winner.
    async fn insert_complete_delegation_state(
        db: &sea_orm::DbConn,
        retained_hash: Hash,
        space: &crate::types::SpaceIdWrap,
    ) {
        // actors
        for actor_id in ["did:key:rec-owner", "did:key:rec-delegate"] {
            actor::ActiveModel {
                id: Set(actor_id.to_string()),
            }
            .insert(db)
            .await
            .ok();
        }
        // delegation row
        delegation::Entity::insert(delegation::ActiveModel {
            id: Set(retained_hash),
            delegator: Set("did:key:rec-owner".to_string()),
            delegatee: Set("did:key:rec-delegate".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(retained_hash.as_ref().to_vec()),
        })
        .on_conflict(
            OnConflict::column(delegation::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec(db)
        .await
        .ok();
        // one ability row
        abilities::Entity::insert(abilities::ActiveModel {
            delegation: Set(retained_hash),
            resource: Set("tinycloud:did:key:rec-owner:files/kv/doc".parse().unwrap()),
            ability: Set("tinycloud.kv/put".to_string().try_into().unwrap()),
            caveats: Set(Default::default()),
        })
        .exec(db)
        .await
        .unwrap();
        // space row
        space::Entity::insert(space::ActiveModel::from(space::Model { id: space.clone() }))
            .on_conflict(
                OnConflict::column(space::Column::Id)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(db)
            .await
            .ok();
        // epoch row
        let epoch_id = crate::hash::hash(b"reconcile-epoch");
        epoch::Entity::insert(epoch::ActiveModel {
            seq: Set(0),
            id: Set(epoch_id),
            space: Set(space.clone()),
        })
        .on_conflict(
            OnConflict::columns([epoch::Column::Id, epoch::Column::Space])
                .do_nothing()
                .to_owned(),
        )
        .exec(db)
        .await
        .ok();
        // event_order row
        event_order::Entity::insert(event_order::ActiveModel {
            seq: Set(0),
            epoch: Set(epoch_id),
            epoch_seq: Set(0),
            event: Set(retained_hash),
            space: Set(space.clone()),
        })
        .exec(db)
        .await
        .unwrap();
    }

    /// Reconciliation succeeds when all rows are durably present and consistent.
    #[tokio::test]
    async fn reconcile_succeeds_when_state_is_complete_and_consistent() {
        let db = get_db().await.unwrap();
        let hash = crate::hash::hash(b"reconcile-complete-bytes");
        let space = crate::types::SpaceIdWrap(test_space_id("reconcile-complete"));

        insert_complete_delegation_state(&db.conn, hash, &space).await;

        let result = reconcile_pk_epoch_delegation::<_, MemoryStore, StaticSecret>(
            &db.conn, hash, 1, // one ability
            0, // zero parents
        )
        .await;

        assert!(
            result.is_ok(),
            "reconciliation must succeed when state is complete"
        );
        let tr = result.unwrap_or_else(|_| panic!("must be ok"));
        assert_eq!(
            tr.delegation_cids,
            vec![hash],
            "must return the retained CID"
        );
    }

    /// Reconciliation performs zero writes: calling it again after success still
    /// observes the same single row set (no duplicates introduced).
    #[tokio::test]
    async fn reconcile_is_read_only_zero_writes() {
        let db = get_db().await.unwrap();
        let hash = crate::hash::hash(b"reconcile-zero-writes-bytes");
        let space = crate::types::SpaceIdWrap(test_space_id("reconcile-zero-writes"));

        insert_complete_delegation_state(&db.conn, hash, &space).await;

        let del_before = delegation::Entity::find().count(&db.conn).await.unwrap();
        let ab_before = abilities::Entity::find().count(&db.conn).await.unwrap();
        let eo_before = event_order::Entity::find().count(&db.conn).await.unwrap();
        let ep_before = epoch::Entity::find().count(&db.conn).await.unwrap();

        let result =
            reconcile_pk_epoch_delegation::<_, MemoryStore, StaticSecret>(&db.conn, hash, 1, 0)
                .await;
        assert!(result.is_ok(), "reconciliation must succeed");

        assert_eq!(
            delegation::Entity::find().count(&db.conn).await.unwrap(),
            del_before,
            "reconciliation must not write delegation rows"
        );
        assert_eq!(
            abilities::Entity::find().count(&db.conn).await.unwrap(),
            ab_before,
            "reconciliation must not write ability rows"
        );
        assert_eq!(
            event_order::Entity::find().count(&db.conn).await.unwrap(),
            eo_before,
            "reconciliation must not write event_order rows"
        );
        assert_eq!(
            epoch::Entity::find().count(&db.conn).await.unwrap(),
            ep_before,
            "reconciliation must not write epoch rows"
        );
    }

    /// Negative: delegation row absent → reconciliation returns EpochInsert error.
    #[tokio::test]
    async fn reconcile_fails_when_delegation_row_absent() {
        let db = get_db().await.unwrap();
        let hash = crate::hash::hash(b"reconcile-no-deleg");
        let before = EpochReconcileReason::DelegationAbsent.count();

        let result =
            reconcile_pk_epoch_delegation::<_, MemoryStore, StaticSecret>(&db.conn, hash, 0, 0)
                .await;
        assert!(
            matches!(result, Err(TxError::EpochInsert(_))),
            "absent delegation row must return EpochInsert",
        );
        assert_eq!(
            EpochReconcileReason::DelegationAbsent.count(),
            before + 1,
            "delegation_absent reason count must increment exactly once"
        );
    }

    /// Negative: delegation row present but ability count mismatches expected.
    #[tokio::test]
    async fn reconcile_fails_when_ability_count_wrong() {
        let db = get_db().await.unwrap();
        let hash = crate::hash::hash(b"reconcile-wrong-ability-count");
        let space = crate::types::SpaceIdWrap(test_space_id("reconcile-wrong-ability"));

        insert_complete_delegation_state(&db.conn, hash, &space).await;
        let before = EpochReconcileReason::AbilityMismatch.count();
        // State has 1 ability; we claim 2 expected → mismatch.
        let result = reconcile_pk_epoch_delegation::<_, MemoryStore, StaticSecret>(
            &db.conn, hash, 2, // wrong
            0,
        )
        .await;
        assert!(
            matches!(result, Err(TxError::EpochInsert(_))),
            "ability count mismatch must return EpochInsert",
        );
        assert_eq!(
            EpochReconcileReason::AbilityMismatch.count(),
            before + 1,
            "ability_mismatch reason count must increment exactly once"
        );
    }

    /// Negative: delegation row present, ability count correct, but parent count
    /// mismatches (state has no parents, we expect one).
    #[tokio::test]
    async fn reconcile_fails_when_parent_count_wrong() {
        let db = get_db().await.unwrap();
        let hash = crate::hash::hash(b"reconcile-wrong-parent-count");
        let space = crate::types::SpaceIdWrap(test_space_id("reconcile-wrong-parent"));

        insert_complete_delegation_state(&db.conn, hash, &space).await;
        let before = EpochReconcileReason::ParentMismatch.count();
        let result = reconcile_pk_epoch_delegation::<_, MemoryStore, StaticSecret>(
            &db.conn, hash, 1, 1, // wrong: state has zero parents
        )
        .await;
        assert!(
            matches!(result, Err(TxError::EpochInsert(_))),
            "parent count mismatch must return EpochInsert",
        );
        assert_eq!(
            EpochReconcileReason::ParentMismatch.count(),
            before + 1,
            "parent_mismatch reason count must increment exactly once"
        );
    }

    /// Negative: delegation row and ability present, but no event_order row.
    #[tokio::test]
    async fn reconcile_fails_when_event_order_absent() {
        let db = get_db().await.unwrap();
        let hash = crate::hash::hash(b"reconcile-no-event-order");

        for actor_id in ["did:key:reo-owner", "did:key:reo-delegate"] {
            actor::ActiveModel {
                id: Set(actor_id.to_string()),
            }
            .insert(&db.conn)
            .await
            .ok();
        }
        // Insert delegation and one ability — no event_order row.
        delegation::Entity::insert(delegation::ActiveModel {
            id: Set(hash),
            delegator: Set("did:key:reo-owner".to_string()),
            delegatee: Set("did:key:reo-delegate".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(hash.as_ref().to_vec()),
        })
        .on_conflict(
            OnConflict::column(delegation::Column::Id)
                .do_nothing()
                .to_owned(),
        )
        .exec(&db.conn)
        .await
        .ok();
        abilities::Entity::insert(abilities::ActiveModel {
            delegation: Set(hash),
            resource: Set("tinycloud:did:key:reo-owner:files/kv/doc".parse().unwrap()),
            ability: Set("tinycloud.kv/put".to_string().try_into().unwrap()),
            caveats: Set(Default::default()),
        })
        .exec(&db.conn)
        .await
        .unwrap();

        let before = EpochReconcileReason::EventOrderAbsent.count();
        let result =
            reconcile_pk_epoch_delegation::<_, MemoryStore, StaticSecret>(&db.conn, hash, 1, 0)
                .await;
        assert!(
            matches!(result, Err(TxError::EpochInsert(_))),
            "absent event_order must return EpochInsert",
        );
        assert_eq!(
            EpochReconcileReason::EventOrderAbsent.count(),
            before + 1,
            "event_order_absent reason count must increment exactly once"
        );
    }

    /// Proves the schema invariant that reconcile_pk_epoch_delegation relies
    /// on to skip a per-event_order epoch existence re-check: the composite
    /// foreign key on event_order.(epoch, space) -> epoch.(id, space) makes
    /// it impossible to durably commit an event_order row whose epoch is
    /// absent for that space. If this test ever starts failing (the insert
    /// below stops being rejected), the removed check must be restored.
    #[tokio::test]
    async fn event_order_epoch_space_fk_rejects_row_with_no_matching_epoch() {
        let db = get_db().await.unwrap();
        let space = crate::types::SpaceIdWrap(test_space_id("event-order-fk-space"));
        space::Entity::insert(space::ActiveModel::from(space::Model { id: space.clone() }))
            .exec(&db.conn)
            .await
            .unwrap();

        let missing_epoch_id = crate::hash::hash(b"event-order-fk-missing-epoch");
        let err = event_order::Entity::insert(event_order::ActiveModel {
            seq: Set(0),
            epoch: Set(missing_epoch_id),
            epoch_seq: Set(0),
            event: Set(crate::hash::hash(b"event-order-fk-event")),
            space: Set(space),
        })
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

    // -------------------------------------------------------------------------
    // Retention pruning (TC-287)
    // -------------------------------------------------------------------------

    async fn fresh_retention_db() -> DatabaseConnection {
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        conn
    }

    fn rfc3339(instant: OffsetDateTime) -> String {
        instant.format(&Rfc3339).unwrap()
    }

    async fn insert_retention_subscription(conn: &DatabaseConnection) {
        hook_subscription::Entity::insert(hook_subscription::ActiveModel::from(
            hook_subscription::Model {
                id: "sub".to_string(),
                subscriber_did: "did:example:sub".to_string(),
                space_id: "space".to_string(),
                target_service: "kv".to_string(),
                path_prefix: None,
                abilities_json: None,
                callback_url: "https://example.com/hook".to_string(),
                encrypted_secret: vec![0u8; 4],
                secret_key_id: "kid".to_string(),
                active: true,
                created_at: rfc3339(OffsetDateTime::now_utc()),
            },
        ))
        .exec(conn)
        .await
        .unwrap();
    }

    async fn insert_retention_delivery(
        conn: &DatabaseConnection,
        id: &str,
        status: &str,
        created_at: &str,
        delivered_at: Option<&str>,
    ) {
        hook_delivery::Entity::insert(hook_delivery::ActiveModel::from(hook_delivery::Model {
            id: id.to_string(),
            subscription_id: "sub".to_string(),
            event_id: "evt".to_string(),
            payload_json: "{}".to_string(),
            status: status.to_string(),
            attempts: 0,
            next_attempt_at: None,
            last_error: None,
            created_at: created_at.to_string(),
            delivered_at: delivered_at.map(|value| value.to_string()),
        }))
        .exec(conn)
        .await
        .unwrap();
    }

    async fn insert_retention_ticket(conn: &DatabaseConnection, id: &str, expires_at: &str) {
        signed_kv_ticket::Entity::insert(signed_kv_ticket::ActiveModel::from(
            signed_kv_ticket::Model {
                id: id.to_string(),
                issuer_did: "did:example:issuer".to_string(),
                subject_did: "did:example:subject".to_string(),
                space_id: "space".to_string(),
                path: "path".to_string(),
                service: "kv".to_string(),
                ability: "tinycloud.kv/get".to_string(),
                created_at: expires_at.to_string(),
                expires_at: expires_at.to_string(),
                invocation_expires_at: None,
                parent_expires_at: None,
                content_hash: None,
                etag: None,
                parent_cids_json: None,
            },
        ))
        .exec(conn)
        .await
        .unwrap();
    }

    async fn remaining_delivery_ids(conn: &DatabaseConnection) -> Vec<String> {
        let mut ids: Vec<String> = hook_delivery::Entity::find()
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
        ids.sort();
        ids
    }

    #[tokio::test]
    async fn retention_prune_respects_status_and_age() {
        let conn = fresh_retention_db().await;
        insert_retention_subscription(&conn).await;

        let now = OffsetDateTime::now_utc();
        let stale = rfc3339(now - time::Duration::days(60));
        let recent = rfc3339(now - time::Duration::hours(1));
        let future = rfc3339(now + time::Duration::days(60));

        // Terminal + aged: eligible for pruning.
        insert_retention_delivery(
            &conn,
            "delivered_old",
            HOOK_DELIVERY_STATUS_DELIVERED,
            &stale,
            Some(&stale),
        )
        .await;
        insert_retention_delivery(
            &conn,
            "dead_letter_old",
            HOOK_DELIVERY_STATUS_DEAD_LETTER,
            &stale,
            None,
        )
        .await;

        // Terminal but recent: retained (age not met).
        insert_retention_delivery(
            &conn,
            "delivered_recent",
            HOOK_DELIVERY_STATUS_DELIVERED,
            &recent,
            Some(&recent),
        )
        .await;
        insert_retention_delivery(
            &conn,
            "dead_letter_recent",
            HOOK_DELIVERY_STATUS_DEAD_LETTER,
            &recent,
            None,
        )
        .await;

        // Delivered status but no delivered_at timestamp: never matched by the
        // NULL-excluding SQL comparison.
        insert_retention_delivery(
            &conn,
            "delivered_no_ts",
            HOOK_DELIVERY_STATUS_DELIVERED,
            &stale,
            None,
        )
        .await;

        // Non-terminal rows: must never be touched regardless of age.
        insert_retention_delivery(
            &conn,
            "pending_old",
            HOOK_DELIVERY_STATUS_PENDING,
            &stale,
            None,
        )
        .await;
        insert_retention_delivery(
            &conn,
            "retrying_old",
            HOOK_DELIVERY_STATUS_RETRYING,
            &stale,
            None,
        )
        .await;

        // Tickets: only those whose expiry is older than the grace cutoff go.
        insert_retention_ticket(&conn, "ticket_stale", &stale).await;
        insert_retention_ticket(&conn, "ticket_recent", &recent).await;
        insert_retention_ticket(&conn, "ticket_future", &future).await;

        let delivered_cutoff = rfc3339(now - time::Duration::days(7));
        let dead_letter_cutoff = rfc3339(now - time::Duration::days(30));
        let ticket_cutoff = rfc3339(now - time::Duration::days(7));

        assert_eq!(
            prune_delivered_hook_deliveries(&conn, &delivered_cutoff, 5000)
                .await
                .unwrap(),
            1,
            "only the aged delivered row should be pruned"
        );
        assert_eq!(
            prune_dead_letter_hook_deliveries(&conn, &dead_letter_cutoff, 5000)
                .await
                .unwrap(),
            1,
            "only the aged dead_letter row should be pruned"
        );
        assert_eq!(
            prune_expired_signed_kv_tickets(&conn, &ticket_cutoff, 5000)
                .await
                .unwrap(),
            1,
            "only the long-expired ticket should be pruned"
        );

        assert_eq!(
            remaining_delivery_ids(&conn).await,
            vec![
                "dead_letter_recent".to_string(),
                "delivered_no_ts".to_string(),
                "delivered_recent".to_string(),
                "pending_old".to_string(),
                "retrying_old".to_string(),
            ],
            "pending/retrying rows and recent/timestamp-less terminal rows survive"
        );

        let mut ticket_ids: Vec<String> = signed_kv_ticket::Entity::find()
            .all(&conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
        ticket_ids.sort();
        assert_eq!(
            ticket_ids,
            vec!["ticket_future".to_string(), "ticket_recent".to_string()],
            "recently-expired and not-yet-expired tickets survive"
        );
    }

    #[tokio::test]
    async fn retention_prune_batches_terminate_and_delete_everything_eligible() {
        let conn = fresh_retention_db().await;
        insert_retention_subscription(&conn).await;

        let now = OffsetDateTime::now_utc();
        let stale = rfc3339(now - time::Duration::days(60));
        for index in 0..12 {
            insert_retention_delivery(
                &conn,
                &format!("delivered_{index}"),
                HOOK_DELIVERY_STATUS_DELIVERED,
                &stale,
                Some(&stale),
            )
            .await;
        }

        let cutoff = rfc3339(now);

        // batch_rows == 0 is a guarded no-op, never an infinite loop.
        assert_eq!(
            prune_delivered_hook_deliveries(&conn, &cutoff, 0)
                .await
                .unwrap(),
            0
        );

        // batch_rows smaller than the backlog: the loop pages (5 + 5 + 2) and
        // terminates once a short page is seen, deleting every eligible row.
        assert_eq!(
            prune_delivered_hook_deliveries(&conn, &cutoff, 5)
                .await
                .unwrap(),
            12
        );
        assert!(
            hook_delivery::Entity::find()
                .all(&conn)
                .await
                .unwrap()
                .is_empty(),
            "all aged delivered rows should be gone after a batched sweep"
        );
    }

    // ---------------------------------------------------------------------
    // TC-320: the SQL-side space filter on `ability.resource`.
    // ---------------------------------------------------------------------

    /// One delegation plus its abilities, and optionally a revocation.
    /// Resources are given as strings so the rows go through exactly the
    /// `Resource` parse/`Display` round-trip production uses.
    async fn seed_delegation<C: ConnectionTrait>(
        db: &C,
        label: &str,
        resources: &[String],
        expiry: Option<OffsetDateTime>,
        not_before: Option<OffsetDateTime>,
        revoked: bool,
    ) -> Hash {
        use crate::types::{Ability, Caveats};
        use std::collections::BTreeMap;

        let id = crate::hash::hash(label.as_bytes());
        // Actors are FK prerequisites for the delegation row.
        for actor_id in [
            format!("did:key:delegator-{label}"),
            format!("did:key:delegatee-{label}"),
        ] {
            actor::ActiveModel { id: Set(actor_id) }
                .insert(db)
                .await
                .ok();
        }
        delegation::ActiveModel {
            id: Set(id),
            delegator: Set(format!("did:key:delegator-{label}")),
            delegatee: Set(format!("did:key:delegatee-{label}")),
            expiry: Set(expiry),
            issued_at: Set(None),
            not_before: Set(not_before),
            facts: Set(None),
            serialization: Set(label.as_bytes().to_vec()),
        }
        .insert(db)
        .await
        .unwrap();
        for resource in resources {
            abilities::ActiveModel {
                resource: Set(resource.parse().unwrap()),
                ability: Set(<Ability as TryFrom<String>>::try_from(
                    "tinycloud.kv/get".to_string(),
                )
                .unwrap()),
                delegation: Set(id),
                caveats: Set(Caveats(BTreeMap::new())),
            }
            .insert(db)
            .await
            .unwrap();
        }
        if revoked {
            revocation::ActiveModel {
                id: Set(crate::hash::hash(format!("revocation-{label}").as_bytes())),
                revoker: Set(format!("did:key:delegator-{label}")),
                revoked: Set(id),
                serialization: Set(label.as_bytes().to_vec()),
                revoked_at: Set(Some(OffsetDateTime::now_utc())),
            }
            .insert(db)
            .await
            .unwrap();
        }
        id
    }

    /// Delegation id -> its full sorted resource list.
    type Selection = HashMap<Hash, Vec<String>>;

    fn summarize(rows: Vec<(delegation::Model, Vec<abilities::Model>)>) -> Selection {
        rows.into_iter()
            .map(|(del, abilities)| {
                let mut resources: Vec<String> =
                    abilities.iter().map(|a| a.resource.to_string()).collect();
                resources.sort();
                (del.id, resources)
            })
            .collect()
    }

    /// The pre-TC-320 selection, verbatim: load *every* unrevoked delegation
    /// with its abilities, then filter by time and space in Rust. Kept as the
    /// parity oracle.
    async fn legacy_selection<C: ConnectionTrait>(
        db: &C,
        space_id: &SpaceId,
        now: OffsetDateTime,
    ) -> Selection {
        let rows = delegation::Entity::find()
            .left_join(revocation::Entity)
            .filter(revocation::Column::Id.is_null())
            .find_with_related(abilities::Entity)
            .all(db)
            .await
            .unwrap();
        summarize(
            rows.into_iter()
                .filter(|(del, ability)| {
                    del.expiry.map(|e| e > now).unwrap_or(true)
                        && del.not_before.map(|n| n <= now).unwrap_or(true)
                        && ability.iter().any(|a| a.resource.space() == Some(space_id))
                })
                .collect(),
        )
    }

    /// The TC-320 selection: the same thing, with the space prefix range
    /// pushed into SQL ahead of the identical Rust-side filter.
    async fn filtered_selection<C: ConnectionTrait>(
        db: &C,
        space_id: &SpaceId,
        now: OffsetDateTime,
    ) -> Selection {
        let rows = delegation::Entity::find()
            .left_join(revocation::Entity)
            .filter(revocation::Column::Id.is_null())
            .filter(delegations_touching_space(
                db.get_database_backend(),
                space_id,
            ))
            .find_with_related(abilities::Entity)
            .all(db)
            .await
            .unwrap();
        summarize(
            rows.into_iter()
                .filter(|(del, ability)| {
                    del.expiry.map(|e| e > now).unwrap_or(true)
                        && del.not_before.map(|n| n <= now).unwrap_or(true)
                        && ability.iter().any(|a| a.resource.space() == Some(space_id))
                })
                .collect(),
        )
    }

    /// Delegation ids the SQL range alone admits, with no Rust-side space
    /// filter. Shows how tight the prefix bound really is.
    async fn sql_range_only<C: ConnectionTrait>(db: &C, space_id: &SpaceId) -> HashSet<Hash> {
        delegation::Entity::find()
            .filter(delegations_touching_space(
                db.get_database_backend(),
                space_id,
            ))
            .all(db)
            .await
            .unwrap()
            .into_iter()
            .map(|del| del.id)
            .collect()
    }

    /// Pins the prefix-range scheme itself. The upper bound deliberately is
    /// NOT the usual "increment the last byte" (`{space}0`) trick: resource
    /// strings are ordered by the *database's* collation, and under a
    /// punctuation-ignoring collation (glibc `en_US.utf8`, the `postgres:16`
    /// image default) `{space}/kv/path` sorts after `{space}0`, which would
    /// silently drop live delegations.
    #[test]
    fn space_resource_bounds_bracket_every_resource_in_the_space() {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        let foo = SpaceId::new(did.clone(), "foo".parse().unwrap());
        let foobar = SpaceId::new(did.clone(), "foobar".parse().unwrap());
        let (lower, upper) = space_resource_bounds(&foo);

        assert_eq!(lower, format!("{foo}/"));
        assert_eq!(upper, format!("{foo}/\u{10FFFD}"));

        // Every resource in the space renders as `{space}/...` and lands
        // inside the range under byte ordering.
        for suffix in ["kv/a", "kv/deep/path#list", "sql", "", "9svc", "~svc"] {
            let resource: Resource = format!("{foo}/{suffix}").parse().unwrap();
            let rendered = resource.to_string();
            assert_eq!(resource.space(), Some(&foo));
            assert!(
                rendered.as_str() >= lower.as_str() && rendered.as_str() < upper.as_str(),
                "`{rendered}` fell outside [{lower}, {upper})"
            );
        }

        // The bound is derived from the same `Display` impl that writes the
        // column, so a prefix sibling cannot be confused with the target.
        let sibling: Resource = format!("{foobar}/kv/a").parse().unwrap();
        assert_ne!(sibling.space(), Some(&foo));
        assert!(
            sibling.to_string().as_str() >= upper.as_str(),
            "`foobar` must sort outside `foo`'s byte-ordered range"
        );

        // Both of these hold under byte ordering ONLY. The comparison is
        // pinned to byte ordering by `byte_ordered_resource`; see
        // `space_filter_pins_byte_ordering_in_every_backend_dialect`.
    }

    /// Regression guard for the production incident this scheme caused before
    /// the collation pin existed.
    ///
    /// The bounds are byte-oriented, but SQL compares strings using the
    /// *database's* collation. Production runs PostgreSQL under `en_US.UTF-8`
    /// (glibc), where U+10FFFD carries no collation weight, so
    /// `{space}/\u{10FFFD}` collates EQUAL to `{space}/` and the half-open
    /// range matches nothing: the unpinned query returned 0 rows against a
    /// space whose true answer was 55,568, which would have activated every
    /// session with no delegations at all.
    ///
    /// So every dialect must state the byte ordering explicitly. Asserting on
    /// the generated SQL catches this on any machine -- notably including CI,
    /// whose `postgres:16-alpine` service is C-collated and therefore cannot
    /// reproduce the failure by behaviour alone.
    #[test]
    fn space_filter_pins_byte_ordering_in_every_backend_dialect() {
        let space = test_space_id("collation-pin");
        for (backend, expected) in [
            (DbBackend::Postgres, r#"COLLATE "C""#),
            (DbBackend::Sqlite, "COLLATE BINARY"),
            (DbBackend::MySql, "CAST("),
        ] {
            let sql = delegation::Entity::find()
                .filter(delegations_touching_space(backend, &space))
                .build(backend)
                .sql;
            println!("TC-320 {backend:?}: {sql}");
            assert!(
                sql.contains(expected),
                "{backend:?} must pin the space range to byte ordering with `{expected}`, \
                 got {sql}"
            );
            // Both bounds, not just one.
            assert_eq!(
                sql.matches(expected).count(),
                2,
                "{backend:?} must pin BOTH range bounds, got {sql}"
            );
        }
    }

    #[tokio::test]
    async fn space_filtered_delegation_selection_matches_the_full_scan() {
        let db = get_db().await.unwrap();
        let conn = &db.conn;
        let now = OffsetDateTime::now_utc();

        // Prefix-sibling spaces have to share a base DID, otherwise the two
        // space strings diverge long before the name and the range could
        // never overlap in the first place.
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        let foo = SpaceId::new(did.clone(), "foo".parse().unwrap());
        let foobar = SpaceId::new(did.clone(), "foobar".parse().unwrap());
        let fo = SpaceId::new(did.clone(), "fo".parse().unwrap());
        let bar = SpaceId::new(did.clone(), "bar".parse().unwrap());
        // Same *name*, different controller.
        let other_foo = test_space_id("foo");

        let foo_live = seed_delegation(
            conn,
            "foo-live",
            &[format!("{foo}/kv/a")],
            None,
            None,
            false,
        )
        .await;
        let foo_nested = seed_delegation(
            conn,
            "foo-nested",
            &[format!("{foo}/kv/deep/path#list")],
            None,
            None,
            false,
        )
        .await;
        // Service with no path, and an empty-path service: both still render
        // as `{space}/...` and must stay inside the range.
        let foo_service_only = seed_delegation(
            conn,
            "foo-service-only",
            &[format!("{foo}/sql")],
            None,
            None,
            false,
        )
        .await;
        let foo_expired = seed_delegation(
            conn,
            "foo-expired",
            &[format!("{foo}/kv/b")],
            Some(now - time::Duration::hours(1)),
            None,
            false,
        )
        .await;
        let foo_future = seed_delegation(
            conn,
            "foo-future",
            &[format!("{foo}/kv/c")],
            None,
            Some(now + time::Duration::hours(1)),
            false,
        )
        .await;
        let foo_revoked = seed_delegation(
            conn,
            "foo-revoked",
            &[format!("{foo}/kv/d")],
            None,
            None,
            true,
        )
        .await;
        // Straddles two spaces: must appear for both, and must keep *both*
        // capabilities either way.
        let foo_and_bar = seed_delegation(
            conn,
            "foo-and-bar",
            &[format!("{foo}/kv/e"), format!("{bar}/kv/e")],
            None,
            None,
            false,
        )
        .await;
        let foobar_live = seed_delegation(
            conn,
            "foobar-live",
            &[format!("{foobar}/kv/a")],
            None,
            None,
            false,
        )
        .await;
        let fo_live =
            seed_delegation(conn, "fo-live", &[format!("{fo}/kv/a")], None, None, false).await;
        let other_foo_live = seed_delegation(
            conn,
            "other-foo-live",
            &[format!("{other_foo}/kv/a")],
            None,
            None,
            false,
        )
        .await;
        // Non-TinyCloud resource (`Resource::Other`) -- has no space at all.
        let urn_only = seed_delegation(
            conn,
            "urn-only",
            &["urn:example:thing".to_string()],
            None,
            None,
            false,
        )
        .await;
        let no_abilities = seed_delegation(conn, "no-abilities", &[], None, None, false).await;

        // Parity, space by space -- this is the contract: identical selection
        // *and* identical per-delegation capability lists.
        for (label, space) in [
            ("foo", &foo),
            ("foobar", &foobar),
            ("fo", &fo),
            ("bar", &bar),
            ("other_foo", &other_foo),
        ] {
            let legacy = legacy_selection(conn, space, now).await;
            let filtered = filtered_selection(conn, space, now).await;
            assert_eq!(
                legacy, filtered,
                "TC-320 changed the delegation set returned for space {label}"
            );
        }

        // ...and the parity is not vacuous.
        let foo_set = filtered_selection(conn, &foo, now).await;
        let foo_ids: HashSet<Hash> = foo_set.keys().copied().collect();
        assert_eq!(
            foo_ids,
            HashSet::from([foo_live, foo_nested, foo_service_only, foo_and_bar]),
            "unexpected delegation set for `foo`"
        );
        for (label, excluded) in [
            ("prefix sibling `foobar`", foobar_live),
            ("shorter prefix `fo`", fo_live),
            ("same name, other controller", other_foo_live),
            ("expired", foo_expired),
            ("not yet valid", foo_future),
            ("revoked", foo_revoked),
            ("non-TinyCloud resource", urn_only),
            ("no abilities", no_abilities),
        ] {
            assert!(!foo_ids.contains(&excluded), "{label} leaked into `foo`");
        }

        // A delegation spanning two spaces keeps its full capability list.
        // Filtering the joined `ability` rows instead of using a subquery
        // would silently truncate this to one resource.
        assert_eq!(
            foo_set.get(&foo_and_bar).map(|r| r.len()),
            Some(2),
            "cross-space delegation lost a capability when queried via `foo`"
        );
        assert_eq!(
            filtered_selection(conn, &bar, now)
                .await
                .get(&foo_and_bar)
                .map(|r| r.len()),
            Some(2),
            "cross-space delegation lost a capability when queried via `bar`"
        );

        // Under SQLite's byte-ordered collation the range is exact, so the
        // prefix sibling never even reaches Rust. On a collation that ignores
        // punctuation the range widens and the Rust-side space check above is
        // what keeps the result correct.
        let range_only = sql_range_only(conn, &foo).await;
        assert!(
            !range_only.contains(&foobar_live),
            "`foobar` must not fall inside `foo`'s byte-ordered prefix range"
        );
        assert!(
            range_only.contains(&foo_revoked),
            "the range is a space filter only -- revocation is still handled by the join"
        );
    }

    #[tokio::test]
    async fn space_filtered_delegation_lookup_searches_the_ability_primary_key() {
        let db = get_db().await.unwrap();
        let conn = &db.conn;

        // 300 delegations over 30 spaces under one controller, so the space
        // strings share a long prefix and the planner is choosing between a
        // real seek and a real scan.
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        for i in 0..300 {
            let space = SpaceId::new(did.clone(), format!("space-{}", i % 30).parse().unwrap());
            seed_delegation(
                conn,
                &format!("tc320-delegation-{i}"),
                &[format!("{space}/kv/key-{i}")],
                None,
                None,
                false,
            )
            .await;
        }
        conn.execute(Statement::from_string(
            DbBackend::Sqlite,
            "ANALYZE".to_string(),
        ))
        .await
        .unwrap();

        let target = SpaceId::new(did.clone(), "space-7".parse().unwrap());
        let explain = |space: Option<&SpaceId>| {
            let mut query = delegation::Entity::find()
                .left_join(revocation::Entity)
                .filter(revocation::Column::Id.is_null());
            if let Some(space) = space {
                query = query.filter(delegations_touching_space(DbBackend::Sqlite, space));
            }
            let mut stmt = query
                .find_with_related(abilities::Entity)
                .build(DbBackend::Sqlite);
            stmt.sql = format!("EXPLAIN QUERY PLAN {}", stmt.sql);
            async {
                conn.query_all(stmt)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|row| row.try_get::<String>("", "detail").unwrap())
                    .collect::<Vec<String>>()
            }
        };

        // Without the space filter this is the pre-TC-320 shape: a full scan
        // of every delegation ever written.
        let before = explain(None).await;
        println!("TC-320 BEFORE (no space filter): {before:?}");
        assert!(
            before.iter().any(|line| line.contains("SCAN delegation")),
            "the unfiltered capabilities-read query should scan `delegation`, got {before:?}"
        );

        let after = explain(Some(&target)).await;
        println!("TC-320 AFTER  (space filter):    {after:?}");
        assert!(
            after
                .iter()
                .any(|line| line.contains("SEARCH") && line.contains("resource>")),
            "the space filter must resolve as an indexed range seek on `resource`, got {after:?}"
        );
        assert!(
            !after.iter().any(|line| line.contains("SCAN ability")),
            "the space filter must not full-scan `ability`, got {after:?}"
        );
        assert!(
            !after.iter().any(|line| line.contains("SCAN delegation")),
            "the space filter must not full-scan `delegation`, got {after:?}"
        );
    }

    /// The same parity contract on a real PostgreSQL server. SQLite cannot
    /// prove any of the three things this covers: that the generated subquery
    /// is valid PostgreSQL, that the U+10FFFD upper bound survives parameter
    /// binding, and that the range resolves as an index scan on `ability`'s
    /// primary key.
    ///
    /// The index assertion is gated on the database's collation on purpose.
    /// A byte-ordered (`C`) database gets an index scan; on a linguistic
    /// collation the range still filters correctly in SQL -- the Rust-side
    /// space check keeps the result exact -- but the planner cannot use the
    /// primary key for it without a `text_pattern_ops` index.
    #[tokio::test]
    async fn postgres_space_filtered_delegation_selection_matches_the_full_scan() {
        let Some(database_url) = crate::test_support::postgres_test_url(
            "postgres_space_filtered_delegation_selection_matches_the_full_scan",
        ) else {
            return;
        };

        let admin = Database::connect(ConnectOptions::new(database_url.clone()))
            .await
            .expect("connect to PostgreSQL test database");
        let schema = format!(
            "tc320_{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .expect("create isolated TC-320 schema");

        let mut options = ConnectOptions::new(database_url);
        options
            .max_connections(4)
            .sqlx_logging(false)
            .set_schema_search_path(schema.clone());
        let conn = Database::connect(options)
            .await
            .expect("connect to isolated TC-320 schema");
        Migrator::up(&conn, None)
            .await
            .expect("migrate isolated TC-320 schema");

        let collation: String = admin
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT datcollate FROM pg_database WHERE datname = current_database()".to_string(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "datcollate")
            .unwrap();
        println!("TC-320 PostgreSQL collation: {collation}");

        let exercise: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
            let now = OffsetDateTime::now_utc();
            let jwk = JWK::generate_ed25519().unwrap();
            let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
            let foo = SpaceId::new(did.clone(), "foo".parse().unwrap());
            let foobar = SpaceId::new(did.clone(), "foobar".parse().unwrap());
            let bar = SpaceId::new(did.clone(), "bar".parse().unwrap());

            seed_delegation(
                &conn,
                "pg-foo-live",
                &[format!("{foo}/kv/a")],
                None,
                None,
                false,
            )
            .await;
            seed_delegation(
                &conn,
                "pg-foo-and-bar",
                &[format!("{foo}/kv/e"), format!("{bar}/kv/e")],
                None,
                None,
                false,
            )
            .await;
            seed_delegation(
                &conn,
                "pg-foobar-live",
                &[format!("{foobar}/kv/a")],
                None,
                None,
                false,
            )
            .await;
            // Bulk filler, inserted as raw SQL: parity is only interesting at
            // a volume where the space filter actually excludes something, and
            // realistic statistics make the logged plan representative of what
            // production does. 20k delegations across 500 spaces.
            let suffix = foo.suffix().to_string();
            conn.execute(Statement::from_string(
                DbBackend::Postgres,
                "INSERT INTO actor (id) VALUES ('did:key:tc320-bulk') \
                 ON CONFLICT DO NOTHING"
                    .to_string(),
            ))
            .await?;
            conn.execute(Statement::from_string(
                DbBackend::Postgres,
                // `1e20` is the blake3-256 multihash prefix (code 0x1e,
                // digest length 0x20); `Hash` rejects a bare 32-byte digest.
                "INSERT INTO delegation (id, delegator, delegatee, serialization) \
                 SELECT decode('1e20' || lpad(to_hex(i), 64, '0'), 'hex'), \
                        'did:key:tc320-bulk', 'did:key:tc320-bulk', '\\x00'::bytea \
                 FROM generate_series(1, 20000) i"
                    .to_string(),
            ))
            .await?;
            conn.execute(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "INSERT INTO ability (resource, ability, delegation, caveats) \
                     SELECT 'tinycloud:{suffix}:bulk-' || (i % 500) || '/kv/key-' || i, \
                            'tinycloud.kv/get', \
                            decode('1e20' || lpad(to_hex(i), 64, '0'), 'hex'), \
                            '{{}}'::json \
                     FROM generate_series(1, 20000) i"
                ),
            ))
            .await?;
            conn.execute(Statement::from_string(
                DbBackend::Postgres,
                "ANALYZE".to_string(),
            ))
            .await?;

            for (label, space) in [("foo", &foo), ("foobar", &foobar), ("bar", &bar)] {
                assert_eq!(
                    legacy_selection(&conn, space, now).await,
                    filtered_selection(&conn, space, now).await,
                    "TC-320 changed the delegation set returned for space {label} on PostgreSQL"
                );
            }
            assert_eq!(
                filtered_selection(&conn, &foo, now).await.len(),
                2,
                "expected exactly the two `foo` delegations on PostgreSQL"
            );

            let mut stmt = delegation::Entity::find()
                .left_join(revocation::Entity)
                .filter(revocation::Column::Id.is_null())
                .filter(delegations_touching_space(DbBackend::Postgres, &foo))
                .find_with_related(abilities::Entity)
                .build(DbBackend::Postgres);
            stmt.sql = format!("EXPLAIN {}", stmt.sql);
            let plan: Vec<String> = conn
                .query_all(stmt)
                .await?
                .into_iter()
                .map(|row| row.try_get::<String>("", "QUERY PLAN").unwrap())
                .collect();
            println!("TC-320 PostgreSQL plan ({collation}): {plan:?}");

            // What matters here is that the space range is evaluated by the
            // database at all, rather than every delegation being shipped to
            // Rust and filtered there. That is the whole point of TC-320 and
            // it holds under any collation.
            assert!(
                plan.iter()
                    .any(|line| line.contains("resource") && line.contains(">=")),
                "the space range must reach the database, got {plan:?}"
            );

            // Note what is deliberately NOT asserted: an index seek.
            // `COLLATE "C"` carries collation OID 950, while `pk-ability` was
            // built with the column's default collation (OID 100) -- and
            // PostgreSQL requires an exact collation match to use an index.
            // So the pin that makes this query correct also costs the seek,
            // even on a C-collated database. Measured on production: 68ms
            // warm, 452ms cold, versus loading and decoding 28,300 delegation
            // blobs. Recovering the seek needs an index declared
            // `COLLATE "C"` (or `text_pattern_ops`) so its OID matches, which
            // is a migration and is deliberately deferred.
            // SQLite is unaffected: `COLLATE BINARY` is the column's own
            // collation there, so that plan still seeks (see
            // `space_filtered_delegation_lookup_searches_the_ability_primary_key`).
            Ok(())
        }
        .await;

        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .expect("drop isolated TC-320 schema");
        exercise.expect("TC-320 PostgreSQL parity");
    }

    /// End-to-end regression test for the production incident.
    ///
    /// With `ability.resource` under a collation that gives the upper-bound
    /// sentinel no weight -- exactly what glibc `en_US.UTF-8` does, and what
    /// production runs -- `{space}/\u{10FFFD}` collates EQUAL to `{space}/`,
    /// the half-open range is empty, and the space filter returns nothing.
    /// Against the production database the unpinned query returned 0 rows
    /// where the correct answer was 55,568; every session would have activated
    /// with no delegations.
    ///
    /// Without the `COLLATE "C"` pin in `byte_ordered_resource` this test
    /// fails. CI's `postgres:16-alpine` service is C-collated and so cannot
    /// reproduce the failure by behaviour alone, which is exactly why the
    /// hostile collation is constructed here rather than assumed.
    #[tokio::test]
    async fn postgres_space_filter_survives_a_collation_that_ignores_the_sentinel() {
        let Some(database_url) = crate::test_support::postgres_test_url(
            "postgres_space_filter_survives_a_collation_that_ignores_the_sentinel",
        ) else {
            return;
        };

        let admin = Database::connect(ConnectOptions::new(database_url.clone()))
            .await
            .expect("connect to PostgreSQL test database");
        let schema = format!(
            "tc320_collation_{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .expect("create isolated TC-320 collation schema");

        let mut options = ConnectOptions::new(database_url);
        options
            .max_connections(4)
            .sqlx_logging(false)
            .set_schema_search_path(schema.clone());
        let conn = Database::connect(options)
            .await
            .expect("connect to isolated TC-320 collation schema");
        Migrator::up(&conn, None)
            .await
            .expect("migrate isolated TC-320 collation schema");

        let exercise: Result<(), Box<dyn std::error::Error + Send + Sync>> = async {
            // An ICU tailoring that makes U+10FFFD completely ignorable,
            // reproducing glibc's behaviour (glibc simply has no weight entry
            // for it, so it contributes nothing to the sort key).
            conn.execute(Statement::from_string(
                DbBackend::Postgres,
                format!(
                    "CREATE COLLATION tc320_ignorable (provider = icu, locale = 'en', \
                     rules = '&[last tertiary ignorable]={}', deterministic = true)",
                    '\u{10FFFD}'
                ),
            ))
            .await?;
            conn.execute(Statement::from_string(
                DbBackend::Postgres,
                "ALTER TABLE ability ALTER COLUMN resource TYPE character varying \
                 COLLATE tc320_ignorable"
                    .to_string(),
            ))
            .await?;

            let now = OffsetDateTime::now_utc();
            let jwk = JWK::generate_ed25519().unwrap();
            let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
            let foo = SpaceId::new(did.clone(), "foo".parse().unwrap());
            let bar = SpaceId::new(did.clone(), "bar".parse().unwrap());
            seed_delegation(
                &conn,
                "cl-foo-a",
                &[format!("{foo}/kv/a")],
                None,
                None,
                false,
            )
            .await;
            seed_delegation(
                &conn,
                "cl-foo-b",
                &[format!("{foo}/sql")],
                None,
                None,
                false,
            )
            .await;
            seed_delegation(
                &conn,
                "cl-bar-a",
                &[format!("{bar}/kv/a")],
                None,
                None,
                false,
            )
            .await;

            // Prove the hazard is actually live on this column: compared with
            // the column's own collation the range is empty, exactly as it was
            // in production.
            let (lower, upper) = space_resource_bounds(&foo);
            let (lo, hi) = (lower.replace('\'', "''"), upper.replace('\'', "''"));
            let count = |sql: String| {
                let conn = &conn;
                async move {
                    conn.query_one(Statement::from_string(DbBackend::Postgres, sql))
                        .await
                        .unwrap()
                        .unwrap()
                        .try_get::<i64>("", "count")
                        .unwrap()
                }
            };
            let unpinned = count(format!(
                "SELECT count(*) FROM ability WHERE resource >= '{lo}' AND resource < '{hi}'"
            ))
            .await;
            let pinned = count(format!(
                "SELECT count(*) FROM ability WHERE resource COLLATE \"C\" >= '{lo}' \
                 AND resource COLLATE \"C\" < '{hi}'"
            ))
            .await;
            println!("TC-320 hostile collation: unpinned={unpinned} rows, pinned={pinned} rows");
            assert_eq!(
                unpinned, 0,
                "the tailored collation must reproduce the production failure, \
                 otherwise this test proves nothing"
            );
            assert_eq!(pinned, 2, "the byte-ordered range must still find `foo`");

            // The real query must be unaffected by the column's collation.
            let filtered = filtered_selection(&conn, &foo, now).await;
            assert_eq!(
                filtered,
                legacy_selection(&conn, &foo, now).await,
                "the space filter must match the full scan even under a collation that \
                 ignores the upper-bound sentinel"
            );
            assert_eq!(
                filtered.len(),
                2,
                "the space filter returned no delegations -- this is the production outage"
            );
            Ok(())
        }
        .await;

        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .expect("drop isolated TC-320 collation schema");
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("DROP COLLATION IF EXISTS {schema}.tc320_ignorable"),
            ))
            .await
            .ok();
        exercise.expect("TC-320 PostgreSQL collation resilience");
    }
}

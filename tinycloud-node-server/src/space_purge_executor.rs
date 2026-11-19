//! Phase executor and the process's purge worker loop. The node schedules the
//! worker only after startup has verified and reconciled the independent
//! ledger (TC-2871).
use crate::{
    space_lifecycle::{LifecycleRuntime, PurgeStorageLayout},
    storage::{
        purge_completion::{complete_purge_with_encryption, verified_acceptance},
        purge_ledger::PurgeLedger,
        purge_reconcile::{PrefixStoreKind, VerifiedPurgePrefix},
        purge_restore::RestorePurgeStore,
        sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore, S3SqlObjectStore, WriteMode},
    },
    BlockStores,
};
use std::{sync::Arc, time::Duration};
use tinycloud_core::{
    encryption::ColumnEncryption,
    encryption_network::deletion_ledger::DeletionLedger,
    sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Statement, TransactionTrait},
    space_purge_fence::PurgeDrain,
    space_purge_ledger::{LedgerKeys, LedgerRecord},
    space_purge_worker::{self, ClaimedPurge},
    sql::SqlService,
    storage::either::Either,
};

pub enum SqlPurgeStore<'a> {
    S3(&'a S3SqlObjectStore),
    FileSystem(&'a FsSqlObjectStore),
}
#[derive(Debug, PartialEq, Eq)]
pub enum PhaseOutcome {
    Advanced,
    MoreObjects,
    Deferred,
    Complete,
    LeaseLost,
}
#[derive(Debug, thiserror::Error)]
pub enum PurgeExecutionError {
    #[error("purge database operation failed")]
    Database(#[from] DbErr),
    #[error("purge storage operation failed")]
    Storage,
    #[error("purge cache eviction failed")]
    Cache,
    #[error("purge drain binding mismatch")]
    Binding,
    #[error("purge lease lost")]
    LeaseLost,
    #[error("purge prefix inventory unavailable")]
    PrefixInventory,
    #[error("purge SQL storage unavailable")]
    SqlStorageUnavailable,
}
impl PurgeExecutionError {
    /// The fixed code a failed attempt records on its job; never an identity.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Database(_) => "database",
            Self::Storage => "storage",
            Self::Cache => "cache",
            Self::Binding => "binding",
            Self::LeaseLost => "lease_lost",
            Self::PrefixInventory => "prefix_inventory",
            Self::SqlStorageUnavailable => "sql_storage_unavailable",
        }
    }
}

/// The SQL object transport the purge lists and deletes through.
pub enum PurgeSqlObjects {
    S3(S3SqlObjectStore),
    FileSystem(FsSqlObjectStore),
}
impl PurgeSqlObjects {
    /// The SQL object store of the configured block backend: the block bucket
    /// on S3, `{datadir}/sql-store` on local storage. No write probe runs;
    /// the purge only lists and deletes.
    pub async fn open(storage: &crate::config::Storage) -> anyhow::Result<Self> {
        Ok(match &storage.blocks {
            Either::A(s3) => {
                Self::S3(S3SqlObjectStore::open_with_mode(s3, WriteMode::Conditional).await)
            }
            Either::B(fs) => Self::FileSystem(
                FsSqlObjectStore::open(storage.datadir.join("sql-store"), fs.path())
                    .map_err(|error| anyhow::anyhow!("purge SQL object store: {error}"))?,
            ),
        })
    }
    fn store(&self) -> SqlPurgeStore<'_> {
        match self {
            Self::S3(store) => SqlPurgeStore::S3(store),
            Self::FileSystem(store) => SqlPurgeStore::FileSystem(store),
        }
    }
}

/// Every store a space purge touches, shared by the worker and by
/// reconciliation. The caches are clones of the services the routes use, so
/// their evictions reach the live actors.
pub struct PurgeStores {
    pub blocks: BlockStores,
    pub ledger: Arc<PurgeLedger>,
    pub sql: SqlService,
    #[cfg(feature = "duckdb")]
    pub duckdb: Option<tinycloud_core::duckdb::DuckDbService>,
    pub sql_objects: PurgeSqlObjects,
    pub encryption: Option<ColumnEncryption>,
    /// `deletions.jsonl`, the handle the encryption service appends to. The
    /// owner-erasure step prunes erased owners from it (TC-2871 S5).
    pub deletions: Option<Arc<DeletionLedger>>,
}
impl PurgeStores {
    /// The physical stores acceptance records sign, in executor order.
    pub fn store_kinds(&self) -> Vec<PrefixStoreKind> {
        #[cfg(feature = "duckdb")]
        let duckdb = self.duckdb.is_some();
        #[cfg(not(feature = "duckdb"))]
        let duckdb = false;
        let mut kinds = vec![
            match self.blocks {
                Either::A(_) => PrefixStoreKind::KvS3,
                Either::B(_) => PrefixStoreKind::KvFileSystem,
            },
            match self.sql_objects {
                PurgeSqlObjects::S3(_) => PrefixStoreKind::SqlS3,
                PurgeSqlObjects::FileSystem(_) => PrefixStoreKind::SqlFileSystem,
            },
            PrefixStoreKind::SqliteCache,
        ];
        kinds.extend(duckdb.then_some(PrefixStoreKind::DuckDbCache));
        kinds
    }
    pub fn layout(&self) -> Result<PurgeStorageLayout, &'static str> {
        let kinds = self.store_kinds();
        PurgeStorageLayout::new(
            kinds[0],
            kinds[1],
            kinds.contains(&PrefixStoreKind::DuckDbCache),
        )
    }
    pub fn restore_store(&self, kind: PrefixStoreKind) -> Option<RestorePurgeStore<'_>> {
        match (kind, &self.blocks, &self.sql_objects) {
            (PrefixStoreKind::KvFileSystem, Either::B(store), _) => {
                Some(RestorePurgeStore::KvFileSystem(store))
            }
            (PrefixStoreKind::KvS3, Either::A(store), _) => Some(RestorePurgeStore::KvS3(store)),
            (PrefixStoreKind::SqlFileSystem, _, PurgeSqlObjects::FileSystem(store)) => {
                Some(RestorePurgeStore::SqlFileSystem(store))
            }
            (PrefixStoreKind::SqlS3, _, PurgeSqlObjects::S3(store)) => {
                Some(RestorePurgeStore::SqlS3(store))
            }
            (PrefixStoreKind::SqliteCache, _, _) => Some(RestorePurgeStore::SqliteCache(&self.sql)),
            #[cfg(feature = "duckdb")]
            (PrefixStoreKind::DuckDbCache, _, _) => {
                self.duckdb.as_ref().map(RestorePurgeStore::DuckDbCache)
            }
            _ => None,
        }
    }
    pub fn executor<'a>(
        &'a self,
        db: &'a DatabaseConnection,
        keys: &'a LedgerKeys,
    ) -> SpacePurgeExecutor<'a> {
        SpacePurgeExecutor {
            db,
            blocks: &self.blocks,
            ledger: &self.ledger,
            sql: &self.sql,
            #[cfg(feature = "duckdb")]
            duckdb: self.duckdb.as_ref(),
            sql_objects: Some(self.sql_objects.store()),
            keys,
            encryption: self.encryption.as_ref(),
        }
    }
}

/// How long an idle worker waits before polling again when no request wakes it.
const WORKER_IDLE: Duration = Duration::from_secs(10);

/// The process's purge worker: sweep one completed purge's residue, claim one
/// due phase or batch, execute it, release it on failure, and back off when
/// idle. After a purge completes, and whenever lifecycle work is requested
/// (a retirement, a purge, a reconcile), it runs the owner-erasure pass,
/// retrying it on every pass until it succeeds. One loop per process; claims
/// are leased in PostgreSQL. It does no work while the ledger is unverified
/// or a reconciliation failed.
pub async fn run_purge_worker(
    runtime: LifecycleRuntime,
    stores: Arc<PurgeStores>,
    shutdown: rocket::Shutdown,
) {
    tokio::pin!(shutdown);
    let mut erase_owners = true;
    loop {
        let worked = tokio::select! {
            worked = purge_step(&runtime, &stores, &mut erase_owners) => worked,
            _ = &mut shutdown => break,
        };
        if worked {
            continue;
        }
        tokio::select! {
            _ = runtime.work_requested.notified() => erase_owners = true,
            _ = tokio::time::sleep(WORKER_IDLE) => {}
            _ = &mut shutdown => break,
        }
    }
}

/// One bounded pass. True when it did work and another pass should follow.
async fn purge_step(
    runtime: &LifecycleRuntime,
    stores: &PurgeStores,
    erase_owners: &mut bool,
) -> bool {
    if !runtime.ledger_verified() {
        return false;
    }
    let db = runtime.connection().sea_orm_connection();
    let keys = runtime.keys();
    let swept =
        match tinycloud_core::space_purge_records::sweep_next(db, keys, stores.encryption.as_ref())
            .await
        {
            Ok(swept) => swept,
            Err(_) => {
                ::tracing::warn!(
                    event = "space_purge_sweep_failed",
                    "space purge residue sweep failed"
                );
                false
            }
        };
    let worked = match space_purge_worker::claim(db, &uuid::Uuid::new_v4().to_string()).await {
        Ok(Some(job)) => {
            match execute_job(runtime, stores, db, keys, &job).await {
                Ok(outcome) => {
                    ::tracing::info!(
                        event = "space_purge_phase",
                        phase = %job.phase,
                        outcome = ?outcome,
                        "space purge phase ran"
                    );
                    *erase_owners |= outcome == PhaseOutcome::Complete;
                }
                Err(code) => {
                    // The purge ID and the fixed code only: never error text.
                    ::tracing::warn!(
                        event = "space_purge_phase_failed",
                        purge_id = %job.purge_id,
                        code,
                        "space purge phase failed; retrying later"
                    );
                    if code != "lease_lost"
                        && space_purge_worker::retry(db, &job, code).await.is_err()
                    {
                        ::tracing::warn!(
                            event = "space_purge_release_failed",
                            "space purge attempt release failed"
                        );
                    }
                }
            }
            true
        }
        Ok(None) => swept,
        Err(_) => {
            ::tracing::warn!(
                event = "space_purge_claim_failed",
                "space purge claim failed"
            );
            false
        }
    };
    if *erase_owners {
        match crate::space_purge_owner_erasure::erase_retired_owners(
            db,
            &*stores.ledger,
            keys,
            stores.deletions.as_ref(),
        )
        .await
        {
            Ok(report) => {
                *erase_owners = false;
                if report != Default::default() {
                    ::tracing::info!(
                        event = "space_purge_owner_erasure",
                        owners_erased = report.owners_erased,
                        owners_rows_deleted = report.owners_rows_deleted,
                        owners_pruned = report.owners_pruned,
                        blocked_rows_present = report.blocked_rows_present,
                        "owner erasure pass ran"
                    );
                }
            }
            // Fixed text only; the flag stays set, so the next pass retries.
            Err(_) => ::tracing::warn!(
                event = "space_purge_owner_erasure_failed",
                "owner erasure pass failed; retrying later"
            ),
        }
    }
    worked
}

async fn execute_job(
    runtime: &LifecycleRuntime,
    stores: &PurgeStores,
    db: &DatabaseConnection,
    keys: &LedgerKeys,
    job: &ClaimedPurge,
) -> Result<PhaseOutcome, &'static str> {
    let space: tinycloud_auth::resource::SpaceId =
        job.space.parse().map_err(|_| "invalid_space")?;
    let drain = runtime
        .fence
        .drain(db, &space)
        .await
        .map_err(|_| "fence_unavailable")?;
    stores
        .executor(db, keys)
        .execute_claimed(job, &drain)
        .await
        .map_err(|error| error.code())
}

pub struct SpacePurgeExecutor<'a> {
    pub db: &'a DatabaseConnection,
    pub blocks: &'a BlockStores,
    /// The purge ledger's own store, never `blocks` (TC-2871).
    pub ledger: &'a PurgeLedger,
    pub sql: &'a SqlService,
    #[cfg(feature = "duckdb")]
    pub duckdb: Option<&'a tinycloud_core::duckdb::DuckDbService>,
    pub sql_objects: Option<SqlPurgeStore<'a>>,
    pub keys: &'a LedgerKeys,
    pub encryption: Option<&'a ColumnEncryption>,
}
impl SpacePurgeExecutor<'_> {
    /// Executes one accepted phase/batch under the exact exclusive lifetime
    /// guard. Nothing in this module installs a task or enables ordinary serving.
    pub async fn execute_claimed(
        &self,
        job: &ClaimedPurge,
        drain: &PurgeDrain,
    ) -> Result<PhaseOutcome, PurgeExecutionError> {
        if drain.space().to_string() != job.space {
            return Err(PurgeExecutionError::Binding);
        }
        if !space_purge_worker::renew(self.db, job).await? {
            return Ok(PhaseOutcome::LeaseLost);
        }
        let accepted = verified_acceptance(self.db, self.ledger, self.keys, job)
            .await
            .map_err(|_| PurgeExecutionError::PrefixInventory)?;
        self.verify_inventory(&accepted, drain.space())?;
        if !grace_ready(self.db, job).await? {
            return Ok(PhaseOutcome::Deferred);
        }
        // Every phase repeats local eviction: an object-phase restart can
        // encounter cache remnants left by the process that held the old lease.
        self.keep_lease(job, async {
            self.sql
                .drain_and_evict_space(drain.space())
                .await
                .map_err(|_| PurgeExecutionError::Cache)?;
            #[cfg(feature = "duckdb")]
            if let Some(duckdb) = self.duckdb {
                duckdb
                    .drain_and_evict_space(drain.space())
                    .await
                    .map_err(|_| PurgeExecutionError::Cache)?;
            }
            Ok(())
        })
        .await?;
        match job.phase.as_str() {
            "drain" => Ok(if space_purge_worker::advance(self.db, job).await? {
                PhaseOutcome::Advanced
            } else {
                PhaseOutcome::LeaseLost
            }),
            "database" => {
                let tx = self.db.begin().await?;
                tinycloud_core::space_purge_database::delete_sql_and_hook_rows(&tx, job).await?;
                let advanced = space_purge_worker::advance(&tx, job).await?;
                if advanced {
                    tx.commit().await?;
                    Ok(PhaseOutcome::Advanced)
                } else {
                    tx.rollback().await?;
                    Ok(PhaseOutcome::LeaseLost)
                }
            }
            // Signed records, share projections and their target links are
            // removed together in the terminal transaction, preserving R1-R6.
            "access" => Ok(if space_purge_worker::advance(self.db, job).await? {
                PhaseOutcome::Advanced
            } else {
                PhaseOutcome::LeaseLost
            }),
            "objects" => self.objects(job, drain).await,
            _ => Err(PurgeExecutionError::Binding),
        }
    }
    fn verify_inventory(
        &self,
        accepted: &LedgerRecord,
        space: &tinycloud_auth::resource::SpaceId,
    ) -> Result<(), PurgeExecutionError> {
        let kv = match self.blocks {
            Either::A(_) => (PrefixStoreKind::KvS3, format!("{space}/")),
            Either::B(_) => (
                PrefixStoreKind::KvFileSystem,
                format!("{}/{}/", space.suffix(), space.name()),
            ),
        };
        let sql_prefix = SqlPhysicalPrefix::for_space(space).as_str().to_owned();
        let sql = match &self.sql_objects {
            Some(SqlPurgeStore::S3(_)) => (PrefixStoreKind::SqlS3, sql_prefix),
            Some(SqlPurgeStore::FileSystem(_)) => (PrefixStoreKind::SqlFileSystem, sql_prefix),
            None => return Err(PurgeExecutionError::SqlStorageUnavailable),
        };
        let mut prefixes = vec![kv, sql, (PrefixStoreKind::SqliteCache, format!("{space}/"))];
        #[cfg(feature = "duckdb")]
        if self.duckdb.is_some() {
            prefixes.push((PrefixStoreKind::DuckDbCache, format!("{space}/")));
        }
        let path = accepted
            .object_key()
            .map_err(|_| PurgeExecutionError::PrefixInventory)?;
        let body = accepted
            .to_bytes()
            .map_err(|_| PurgeExecutionError::PrefixInventory)?;
        let mut expected = Vec::new();
        for (kind, prefix) in prefixes.drain(..) {
            VerifiedPurgePrefix::verify_candidate(self.keys, &path, &body, kind, &prefix)
                .map_err(|_| PurgeExecutionError::PrefixInventory)?;
            expected.push(
                self.keys
                    .prefix_hmac(&accepted.key_id, kind.as_str(), &prefix)
                    .map_err(|_| PurgeExecutionError::PrefixInventory)?,
            );
        }
        expected.sort();
        expected.dedup();
        // A signed prefix for a disabled or unavailable backend must also be
        // checked, never silently skipped while terminal progress is claimed.
        if expected != accepted.prefixes {
            return Err(PurgeExecutionError::PrefixInventory);
        }
        Ok(())
    }
    async fn keep_lease<T>(
        &self,
        job: &ClaimedPurge,
        work: impl std::future::Future<Output = Result<T, PurgeExecutionError>>,
    ) -> Result<T, PurgeExecutionError> {
        tokio::pin!(work);
        let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(10));
        heartbeat.tick().await;
        loop {
            tokio::select! {
                result=&mut work=>return result,
                _=heartbeat.tick()=>if !space_purge_worker::renew(self.db,job).await? {return Err(PurgeExecutionError::LeaseLost);}
            }
        }
    }
    async fn objects(
        &self,
        job: &ClaimedPurge,
        drain: &PurgeDrain,
    ) -> Result<PhaseOutcome, PurgeExecutionError> {
        if self.sql_objects.is_none() {
            // An empty database inventory cannot prove there are no restored
            // SQL objects. A configured physical transport must verify absence.
            return Err(PurgeExecutionError::SqlStorageUnavailable);
        }
        let empty = self
            .keep_lease(job, async {
                let kv = match self.blocks {
                    Either::A(store) => store
                        .purge_space_batch(drain.space())
                        .await
                        .map_err(|_| PurgeExecutionError::Storage)?,
                    Either::B(store) => store
                        .purge_space_batch(drain.space())
                        .await
                        .map_err(|_| PurgeExecutionError::Storage)?,
                };
                let prefix = SqlPhysicalPrefix::for_space(drain.space());
                let sql = match &self.sql_objects {
                    Some(SqlPurgeStore::S3(store)) => store
                        .purge_prefix_batch(&prefix)
                        .await
                        .map_err(|_| PurgeExecutionError::Storage)?,
                    Some(SqlPurgeStore::FileSystem(store)) => store
                        .purge_prefix_batch(&prefix)
                        .await
                        .map_err(|_| PurgeExecutionError::Storage)?,
                    None => return Err(PurgeExecutionError::SqlStorageUnavailable),
                };
                // Chunked checkpoint bytes are in PostgreSQL; see
                // reap_artifact_parts for why they are erased in this phase.
                let artifacts = tinycloud_core::space_purge_database::reap_artifact_parts(
                    self.db,
                    job,
                    ARTIFACT_CHUNKS_PER_BATCH,
                )
                .await?;
                Ok(kv && sql && artifacts)
            })
            .await?;
        if !empty {
            return Ok(if release_batch(self.db, job).await? {
                PhaseOutcome::MoreObjects
            } else {
                PhaseOutcome::LeaseLost
            });
        }
        let completed =
            complete_purge_with_encryption(self.db, self.ledger, self.keys, job, self.encryption)
                .await
                .map_err(|_| PurgeExecutionError::Storage)?;
        Ok(if completed {
            PhaseOutcome::Complete
        } else {
            PhaseOutcome::LeaseLost
        })
    }
}

/// One `artifact_reap_one` statement each, at most 1 MiB of payload per chunk.
const ARTIFACT_CHUNKS_PER_BATCH: usize = 256;

async fn release_batch(db: &DatabaseConnection, job: &ClaimedPurge) -> Result<bool, DbErr> {
    Ok(db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "UPDATE space_purge_job SET lease_token=NULL,lease_until=NULL,next_attempt_at=clock_timestamp(),updated_at=clock_timestamp(),last_error_code=NULL
         WHERE purge_id=$1 AND lease_token=$2 AND fence_generation=$3 AND phase='objects' AND lease_until>clock_timestamp()",
        [job.purge_id.clone().into(),job.lease_token.clone().into(),job.fence_generation.into()])).await?.rows_affected()==1)
}
/// Grace is durable and uses database time. Both accepted fence age and every
/// orphan upload claim must exceed the upload cap; no request-scoped sleep.
async fn grace_ready(db: &DatabaseConnection, job: &ClaimedPurge) -> Result<bool, DbErr> {
    let grace = tinycloud_core::kv_orphans::ORPHAN_GRACE.whole_seconds();
    let deferred=db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "WITH ready AS (SELECT GREATEST(accepted_at,COALESCE((SELECT max(created_at) FROM kv_orphan_attempt WHERE space=$2),accepted_at),COALESCE((SELECT max(created_at) FROM kv_orphan_candidate WHERE space=$2),accepted_at)) + $5::BIGINT * INTERVAL '1 second' AS due FROM space_purge_job WHERE purge_id=$1)
         UPDATE space_purge_job SET next_attempt_at=ready.due,lease_token=NULL,lease_until=NULL,last_error_code=NULL FROM ready
         WHERE purge_id=$1 AND lease_token=$3 AND fence_generation=$4 AND lease_until>clock_timestamp() AND clock_timestamp()<ready.due",
        [job.purge_id.clone().into(),job.space.clone().into(),job.lease_token.clone().into(),job.fence_generation.into(),grace.into()])).await?.rows_affected()!=0;
    Ok(!deferred)
}

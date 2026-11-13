//! Dormant phase executor. Bootstrap must prove complete fence/entry-point
//! coverage and authenticate accepted storage prefixes before scheduling it.
use crate::{
    storage::{
        purge_completion::{complete_purge_with_encryption, verified_acceptance},
        purge_ledger::PurgeLedgerStore,
        purge_reconcile::{PrefixStoreKind, VerifiedPurgePrefix},
        sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore, S3SqlObjectStore},
    },
    BlockStores,
};
use tinycloud_core::{
    encryption::ColumnEncryption,
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

pub struct SpacePurgeExecutor<'a> {
    pub db: &'a DatabaseConnection,
    pub blocks: &'a BlockStores,
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
        let accepted = match self.blocks {
            Either::A(store) => verified_acceptance(self.db, store, self.keys, job).await,
            Either::B(store) => verified_acceptance(self.db, store, self.keys, job).await,
        }
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
                Ok(kv && sql)
            })
            .await?;
        if !empty {
            return Ok(if release_batch(self.db, job).await? {
                PhaseOutcome::MoreObjects
            } else {
                PhaseOutcome::LeaseLost
            });
        }
        let completed = match self.blocks {
            Either::A(store) => self.complete(job, store).await?,
            Either::B(store) => self.complete(job, store).await?,
        };
        Ok(if completed {
            PhaseOutcome::Complete
        } else {
            PhaseOutcome::LeaseLost
        })
    }
    async fn complete(
        &self,
        job: &ClaimedPurge,
        store: &impl PurgeLedgerStore,
    ) -> Result<bool, PurgeExecutionError> {
        complete_purge_with_encryption(self.db, store, self.keys, job, self.encryption)
            .await
            .map_err(|_| PurgeExecutionError::Storage)
    }
}

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

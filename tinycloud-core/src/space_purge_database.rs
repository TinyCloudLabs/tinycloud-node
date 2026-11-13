//! Exact-space database leaves. Signed-record roots are handled at completion.
use crate::space_purge_worker::{renew, ClaimedPurge};
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseTransaction, DbErr, Statement};

/// Call after exclusive space drain and SQL/DuckDB actor eviction. This runs
/// within the caller's database-phase transaction, which must roll back on
/// failure. It deliberately preserves signed-record/event roots and SQL-store
/// object inventory until their separately acknowledged cleanup.
pub async fn delete_sql_and_hook_rows(
    tx: &DatabaseTransaction,
    job: &ClaimedPurge,
) -> Result<u64, DbErr> {
    if job.phase != "database" || !renew(tx, job).await? {
        return Err(DbErr::Custom("purge database lease unavailable".into()));
    }
    let bound = tx
        .query_one(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            "SELECT purge_id FROM space_purge_job WHERE purge_id=$1 AND space=$2",
            [job.purge_id.clone().into(), job.space.clone().into()],
        ))
        .await?;
    if bound.is_none() {
        return Err(DbErr::Custom("purge space binding mismatch".into()));
    }
    let mut deleted = 0;
    // Deliveries reference subscriptions, so they must be removed first.
    for sql in [
        "DELETE FROM hook_delivery WHERE subscription_id IN (SELECT id FROM hook_subscription WHERE space_id=$1)",
        "DELETE FROM hook_subscription WHERE space_id=$1",
        "DELETE FROM signed_kv_ticket WHERE space_id=$1",
        // Payload and WAL-delta bytes are both in database_artifact.
        "DELETE FROM database_artifact WHERE space=$1",
        "DELETE FROM database_alias WHERE space=$1",
        "DELETE FROM database_legacy_artifact WHERE space=$1",
        "DELETE FROM meeting_legacy_write_guard WHERE space=$1",
    ] {
        deleted+=tx.execute(Statement::from_sql_and_values(DatabaseBackend::Postgres,sql,
            [job.space.clone().into()])).await?.rows_affected();
    }
    Ok(deleted)
}

/// Remove physical-object inventory only after the object phase has verified
/// empty stores. Keeping it until terminal commit preserves restore candidates
/// and orphan-upload claims across crashes and provider retries.
pub(crate) async fn delete_verified_empty_inventory(
    tx: &DatabaseTransaction,
    job: &ClaimedPurge,
) -> Result<u64, DbErr> {
    if job.phase != "objects" || !renew(tx, job).await? {
        return Err(DbErr::Custom("purge inventory lease unavailable".into()));
    }
    let mut deleted = 0;
    for sql in [
        "DELETE FROM kv_orphan_attempt WHERE space=$1",
        "DELETE FROM kv_orphan_candidate WHERE space=$1",
        "DELETE FROM kv_blob_generation WHERE space=$1",
        "DELETE FROM sql_store_object WHERE space=$1",
        "DELETE FROM sql_store_manifest WHERE space=$1",
    ] {
        deleted += tx
            .execute(Statement::from_sql_and_values(
                DatabaseBackend::Postgres,
                sql,
                [job.space.clone().into()],
            ))
            .await?
            .rows_affected();
    }
    Ok(deleted)
}

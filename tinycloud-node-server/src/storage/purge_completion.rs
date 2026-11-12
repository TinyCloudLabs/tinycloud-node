//! Terminal purge publication. The executor calls this after verified empty storage.
use super::purge_ledger::PurgeLedgerStore;
use std::io::{Error, ErrorKind};
use tinycloud_core::{
    models::space_purge_job,
    sea_orm::{DatabaseConnection, EntityTrait},
    space_purge_ledger::{LedgerKeys, LedgerRecord},
    space_purge_worker::{self, ClaimedPurge},
};

/// Publish the external record first, then atomically commit the database
/// tombstone and completion. A crash between these steps reuses the signed record.
pub async fn complete_purge(
    db: &DatabaseConnection,
    store: &impl PurgeLedgerStore,
    keys: &LedgerKeys,
    job: &ClaimedPurge,
) -> Result<bool, Error> {
    if job.phase != "objects" {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "invalid completion phase",
        ));
    }
    if !space_purge_worker::renew(db, job)
        .await
        .map_err(Error::other)?
    {
        return Ok(false);
    }
    let current = space_purge_job::Entity::find_by_id(&job.purge_id)
        .one(db)
        .await
        .map_err(Error::other)?
        .ok_or_else(|| Error::other("missing purge job"))?;
    let record = keys
        .sign(
            &current.hmac_key_id,
            "space",
            &current.tombstone_hmac,
            &job.purge_id,
            "complete",
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .map_err(Error::other)?;
    let path = record.object_key().map_err(Error::other)?;
    let bytes = record.to_bytes().map_err(Error::other)?;
    let published: LedgerRecord = match store.append_purge_record(&path, &bytes).await {
        Ok(()) => record,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing = store
                .read_purge_record(&path)
                .await?
                .ok_or_else(|| Error::other("missing completion ledger record"))?;
            let existing = keys.verify(&path, &existing).map_err(Error::other)?;
            if existing.kind != record.kind
                || existing.state != record.state
                || existing.key_id != record.key_id
                || existing.target_hmac != record.target_hmac
                || existing.operation_id != record.operation_id
            {
                return Err(Error::other("completion ledger record mismatch"));
            }
            existing
        }
        Err(error) => return Err(error),
    };
    space_purge_worker::complete(db, job, keys, &published)
        .await
        .map_err(Error::other)
}

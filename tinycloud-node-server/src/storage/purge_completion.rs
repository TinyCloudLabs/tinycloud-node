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
    complete_purge_with_encryption(db, store, keys, job, None).await
}

pub async fn complete_purge_with_encryption(
    db: &DatabaseConnection,
    store: &impl PurgeLedgerStore,
    keys: &LedgerKeys,
    job: &ClaimedPurge,
    encryption: Option<&tinycloud_core::encryption::ColumnEncryption>,
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
    let acceptance = verified_acceptance(db, store, keys, job).await?;
    if !space_purge_worker::renew(db, job)
        .await
        .map_err(Error::other)?
    {
        return Ok(false);
    }
    let record = keys
        .completion_from_acceptance(acceptance, time::OffsetDateTime::now_utc().unix_timestamp())
        .map_err(|_| Error::other("invalid purge acceptance record"))?;
    let path = record.object_key().map_err(Error::other)?;
    let bytes = record.to_bytes().map_err(Error::other)?;
    let append = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        store.append_purge_record(&path, &bytes),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "purge ledger publication timed out"))?;
    let published: LedgerRecord = match append {
        Ok(()) => record,
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            if !space_purge_worker::renew(db, job)
                .await
                .map_err(Error::other)?
            {
                return Ok(false);
            }
            let existing = tokio::time::timeout(
                std::time::Duration::from_secs(20),
                store.read_purge_record(&path),
            )
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "purge ledger read timed out"))??
            .ok_or_else(|| Error::other("missing completion ledger record"))?;
            let existing = keys.verify(&path, &existing).map_err(Error::other)?;
            if existing.version != record.version
                || existing.prefixes != record.prefixes
                || existing.kind != record.kind
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
    if !space_purge_worker::renew(db, job)
        .await
        .map_err(Error::other)?
    {
        return Ok(false);
    }
    space_purge_worker::complete_with_encryption(db, job, keys, &published, encryption)
        .await
        .map_err(Error::other)
}

/// Read the independently durable acceptance before any physical work. A DB
/// record alone is a pending dual write, never authorization to delete.
pub(crate) async fn verified_acceptance(
    db: &DatabaseConnection,
    store: &impl PurgeLedgerStore,
    keys: &LedgerKeys,
    job: &ClaimedPurge,
) -> Result<LedgerRecord, Error> {
    let invalid = || Error::other("invalid or missing purge acceptance record");
    let current = space_purge_job::Entity::find_by_id(&job.purge_id)
        .one(db)
        .await
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let space: tinycloud_auth::resource::SpaceId = job.space.parse().map_err(|_| invalid())?;
    if space.to_string() != job.space
        || current.space.as_deref() != Some(job.space.as_str())
        || current.fence_generation != job.fence_generation
        || current.phase != job.phase
    {
        return Err(invalid());
    }
    let digest = keys
        .target_hmac(&current.hmac_key_id, "space", &job.space)
        .map_err(|_| invalid())?;
    if digest != current.tombstone_hmac {
        return Err(invalid());
    }
    let path = format!(
        "_purge-ledger/spaces/{}/{}/purging",
        current.hmac_key_id,
        hex::encode(&digest)
    );
    let body = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        store.read_purge_record(&path),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "purge acceptance read timed out"))??
    .ok_or_else(invalid)?;
    let accepted = keys.verify(&path, &body).map_err(|_| invalid())?;
    if accepted.version != 2
        || accepted.kind != "space"
        || accepted.state != "purging"
        || accepted.key_id != current.hmac_key_id
        || accepted.operation_id != job.purge_id
        || accepted.target_hmac != hex::encode(digest)
        || accepted.timestamp != current.accepted_at.unix_timestamp()
    {
        return Err(invalid());
    }
    Ok(accepted)
}

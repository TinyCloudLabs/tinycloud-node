//! Owner erasure after a retired owner's last space purge (TC-2871 S5,
//! option A). Three isolated steps, always in this order:
//!
//! - (a) [`publish_erased`]: the signed `("owner","erased")` record goes to
//!   the locked purge ledger;
//! - (b) `space_purge_database::erase_owner_encryption_rows`: one database
//!   transaction keeps the record's database copy and deletes the owner's
//!   `encryption_network*`, `encryption_ceremony` and `encryption_audit` rows;
//! - (c) [`prune_if_eligible`]: `deletions.jsonl` drops the owner's settled
//!   operations, only when the record verifies and no key row remains.
//!
//! A crash between steps is safe: once (a) is durable, the worker's next pass
//! ([`erase_retired_owners`]) and reconcile ([`redelete_erased_owners`]) both
//! redo (b) and (c) from the record. Owners are found by computing
//! `target_hmac(key_id, "owner", did)` over the DIDs the encryption tables and
//! `deletions.jsonl` name; an HMAC is never reversed. Once a node has written
//! an `erased` record it must not be rolled back below the release that
//! added it: an older reader refuses the record and stays fail-closed.
use crate::storage::purge_ledger::PurgeLedgerStore;
use serde::Serialize;
use std::{
    collections::{BTreeSet, HashMap},
    io::{Error, ErrorKind},
    sync::Arc,
};
use time::OffsetDateTime;
use tinycloud_core::{
    encryption_network::{
        deletion_ledger::{self, DeletionLedger, Record},
        NetworkId,
    },
    models::space_retirement,
    sea_orm::{DatabaseConnection, EntityTrait},
    space_purge_database::{
        encryption_owners, erase_owner_encryption_rows, owner_erasure_retirement, owner_key_rows,
    },
    space_purge_ledger::{owner_object_key, LedgerKeys, LedgerRecord},
};

/// Counts only: never a DID, digest or operation id.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct OwnerErasureReport {
    /// `erased` records this pass published (step a).
    pub owners_erased: usize,
    /// Owners with a verified `erased` record whose rows step (b) found and
    /// deleted: the first delete, or a re-delete after a crash or restore.
    pub owners_rows_deleted: usize,
    /// Owners whose settled `deletions.jsonl` operations step (c) removed.
    pub owners_pruned: usize,
    /// Owners with a verified `erased` record whose key rows remain, so
    /// `deletions.jsonl` keeps them.
    pub blocked_rows_present: usize,
}

fn fail<E>(step: &'static str) -> impl FnOnce(E) -> Error {
    move |_| Error::other(step)
}

/// Every canonical owner the encryption tables or `deletions.jsonl` name.
async fn named_owners(
    db: &DatabaseConnection,
    deletions: Option<&Arc<DeletionLedger>>,
) -> Result<BTreeSet<String>, Error> {
    let mut owners = encryption_owners(db)
        .await
        .map_err(fail("encryption owner inventory unavailable"))?;
    if let Some(deletions) = deletions {
        let path = deletions.path().to_path_buf();
        let contents = tokio::task::spawn_blocking(move || deletion_ledger::read(&path))
            .await
            .map_err(fail("deletion ledger unreadable"))?
            .map_err(fail("deletion ledger unreadable"))?;
        for record in contents.records {
            if let Record::Intent(intent) = record {
                if let Ok(network) = intent.network_id.parse::<NetworkId>() {
                    owners.insert(network.owner_did().to_owned());
                }
            }
        }
    }
    Ok(owners)
}

/// Step (a): append the `erased` record. If one is already there (a retry
/// after an unacknowledged write), it must verify and name the same owner,
/// key and retirement; the stored body is returned either way.
pub async fn publish_erased(
    ledger: &dyn PurgeLedgerStore,
    keys: &LedgerKeys,
    record: &LedgerRecord,
) -> Result<Vec<u8>, Error> {
    let invalid = fail("invalid owner erasure record");
    let path = record
        .object_key()
        .map_err(fail("invalid owner erasure record"))?;
    let body = record.to_bytes().map_err(invalid)?;
    match ledger.append_purge_record(&path, &body).await {
        Ok(()) => Ok(body),
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            let existing = ledger
                .read_purge_record(&path)
                .await?
                .ok_or_else(|| Error::other("owner erasure record unavailable"))?;
            let verified = keys
                .verify(&path, &existing)
                .map_err(fail("owner erasure record unverifiable"))?;
            if verified.kind != record.kind
                || verified.state != record.state
                || verified.key_id != record.key_id
                || verified.target_hmac != record.target_hmac
                || verified.operation_id != record.operation_id
            {
                return Err(Error::other("owner erasure record conflicts"));
            }
            Ok(existing)
        }
        Err(error) => Err(error),
    }
}

/// Step (c): prune `owner` from `deletions.jsonl`, only when the `erased`
/// record verifies and zero `encryption_network_key` rows remain for the
/// owner's networks. Rows that remain are counted as `blocked_rows_present`.
pub async fn prune_if_eligible(
    db: &DatabaseConnection,
    keys: &LedgerKeys,
    deletions: Option<&Arc<DeletionLedger>>,
    path: &str,
    body: &[u8],
    owner: &str,
    report: &mut OwnerErasureReport,
) -> Result<(), Error> {
    let record = keys
        .verify(path, body)
        .map_err(fail("owner erasure record unverifiable"))?;
    let digest = keys
        .target_hmac(&record.key_id, "owner", owner)
        .map_err(fail("owner digest unavailable"))?;
    if record.kind != "owner"
        || record.state != "erased"
        || record.target_hmac != hex::encode(digest)
    {
        return Err(Error::other("owner erasure record mismatch"));
    }
    if owner_key_rows(db, owner)
        .await
        .map_err(fail("owner key inventory unavailable"))?
        > 0
    {
        report.blocked_rows_present += 1;
        return Ok(());
    }
    let Some(deletions) = deletions else {
        return Ok(());
    };
    let deletions = deletions.clone();
    let owners = BTreeSet::from([owner.to_owned()]);
    let pruned = tokio::task::spawn_blocking(move || deletions.prune_owners(&owners))
        .await
        .map_err(fail("deletion ledger prune failed"))?
        .map_err(fail("deletion ledger prune failed"))?;
    if pruned.pruned_operations > 0 {
        report.owners_pruned += 1;
    }
    Ok(())
}

/// Steps (b) and (c) for an owner whose `erased` record is at `path`.
async fn finish_erasure(
    db: &DatabaseConnection,
    keys: &LedgerKeys,
    deletions: Option<&Arc<DeletionLedger>>,
    path: &str,
    body: &[u8],
    owner: &str,
    report: &mut OwnerErasureReport,
) -> Result<(), Error> {
    let deleted =
        erase_owner_encryption_rows(db, keys, path, body, owner, OffsetDateTime::now_utc())
            .await
            .map_err(fail("owner encryption erasure failed"))?;
    if deleted > 0 {
        report.owners_rows_deleted += 1;
    }
    prune_if_eligible(db, keys, deletions, path, body, owner, report).await
}

/// The purge worker's owner-erasure pass, run after a space purge completes
/// and retried until it succeeds. For every retired owner the encryption
/// tables or `deletions.jsonl` still name: with a verified `erased` record,
/// redo (b) and (c); otherwise, once `owner_erasure_retirement` holds (no
/// live space, every purge of the owner complete), publish the record from
/// the verified `retired` record and then run (b) and (c).
pub async fn erase_retired_owners(
    db: &DatabaseConnection,
    ledger: &dyn PurgeLedgerStore,
    keys: &LedgerKeys,
    deletions: Option<&Arc<DeletionLedger>>,
) -> Result<OwnerErasureReport, Error> {
    let mut report = OwnerErasureReport::default();
    let retired: BTreeSet<(String, Vec<u8>)> = space_retirement::Entity::find()
        .all(db)
        .await
        .map_err(fail("owner retirements unavailable"))?
        .into_iter()
        .map(|row| (row.hmac_key_id, row.owner_hmac))
        .collect();
    if retired.is_empty() {
        return Ok(report);
    }
    for owner in named_owners(db, deletions).await? {
        let mut retirement = None;
        for key_id in keys.key_ids() {
            let digest = keys
                .target_hmac(key_id, "owner", &owner)
                .map_err(fail("owner digest unavailable"))?;
            if retired.contains(&(key_id.to_owned(), digest.clone())) {
                retirement = Some((key_id.to_owned(), hex::encode(digest)));
                break;
            }
        }
        let Some((key_id, digest)) = retirement else {
            continue;
        };
        let erased_path = owner_object_key(&key_id, &digest, "erased")
            .map_err(fail("invalid owner erasure record"))?;
        if let Some(body) = ledger.read_purge_record(&erased_path).await? {
            finish_erasure(
                db,
                keys,
                deletions,
                &erased_path,
                &body,
                &owner,
                &mut report,
            )
            .await?;
            continue;
        }
        let Some(row) = owner_erasure_retirement(db, keys, &owner)
            .await
            .map_err(fail("owner erasure gate unavailable"))?
        else {
            continue;
        };
        let retired_path =
            owner_object_key(&row.hmac_key_id, &hex::encode(&row.owner_hmac), "retired")
                .map_err(fail("invalid owner retirement record"))?;
        let retired_body = ledger
            .read_purge_record(&retired_path)
            .await?
            .ok_or_else(|| Error::other("owner retirement record missing"))?;
        let retired_record = keys
            .verify(&retired_path, &retired_body)
            .map_err(fail("owner retirement record unverifiable"))?;
        if retired_record.operation_id != row.retirement_id {
            return Err(Error::other("owner retirement record conflicts"));
        }
        let record = keys
            .erasure_from_retirement(&retired_record, OffsetDateTime::now_utc().unix_timestamp())
            .map_err(fail("owner erasure record unavailable"))?;
        let path = record
            .object_key()
            .map_err(fail("invalid owner erasure record"))?;
        let body = publish_erased(ledger, keys, &record).await?;
        report.owners_erased += 1;
        finish_erasure(db, keys, deletions, &path, &body, &owner, &mut report).await?;
    }
    Ok(report)
}

/// Reconcile (restore runbook step 7): for each verified `erased` record,
/// re-delete the rows of the owner it names, then prune if eligible. The
/// owner is found by matching the record's digest over the DIDs the
/// encryption tables and `deletions.jsonl` name. Idempotent.
pub async fn redelete_erased_owners<'a>(
    db: &DatabaseConnection,
    keys: &LedgerKeys,
    deletions: Option<&Arc<DeletionLedger>>,
    records: impl IntoIterator<Item = (&'a String, &'a LedgerRecord)>,
) -> Result<OwnerErasureReport, Error> {
    let mut report = OwnerErasureReport::default();
    let erased: Vec<_> = records
        .into_iter()
        .filter(|(_, record)| record.kind == "owner" && record.state == "erased")
        .collect();
    if erased.is_empty() {
        return Ok(report);
    }
    let owners = named_owners(db, deletions).await?;
    let mut by_digest: HashMap<(&str, String), &str> = HashMap::new();
    let key_ids: BTreeSet<&str> = erased
        .iter()
        .map(|(_, record)| record.key_id.as_str())
        .collect();
    for key_id in key_ids {
        for owner in &owners {
            let digest = keys
                .target_hmac(key_id, "owner", owner)
                .map_err(fail("owner digest unavailable"))?;
            by_digest.insert((key_id, hex::encode(digest)), owner);
        }
    }
    for (path, record) in erased {
        let Some(owner) = by_digest.get(&(record.key_id.as_str(), record.target_hmac.clone()))
        else {
            continue;
        };
        let body = record
            .to_bytes()
            .map_err(fail("invalid owner erasure record"))?;
        finish_erasure(db, keys, deletions, path, &body, owner, &mut report).await?;
    }
    Ok(report)
}

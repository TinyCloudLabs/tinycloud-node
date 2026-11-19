//! Purge-ledger reconciliation, restore runbook step 7 (TC-2871). The node
//! runs it before it serves, and again whenever the outcome of an external
//! ledger write is unknown; `tinycloud node purge-ledger reconcile` runs the
//! same pass after a restore. The ledger wins: every verified record re-creates
//! its fence, retirement or tombstone, an accepted purge whose job is missing
//! is resumed, every owner with an `erased` record has its encryption rows
//! deleted again and is pruned from `deletions.jsonl`, and nothing is ever
//! un-fenced or deleted from the ledger.
pub use crate::storage::purge_reconcile::{PrefixStoreKind, RestoreDrain, VerifiedPurgePrefix};

use super::LifecycleRuntime;
use crate::{
    space_purge_executor::PurgeStores,
    storage::purge_reconcile::{
        finish_absent_prefix, repair_acceptance_copies, repair_one, scan_store_inventory,
        RepairOneOutcome,
    },
};
use serde::Serialize;
use std::{
    collections::{BTreeMap, HashMap},
    io::Error,
    sync::{atomic::Ordering, Arc},
    time::Duration,
};
use time::OffsetDateTime;
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    models::{space, space_purge_job, space_purge_ledger_copy, space_retirement},
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseConnection,
        DbBackend, EntityTrait, QueryFilter, Statement, TransactionTrait,
    },
    space_purge_ledger::LedgerRecord,
};

/// Counts only: never a space, owner, purge ID or HMAC.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ReconcileReport {
    /// Verified records, the external ledger and the database copies together.
    pub records: usize,
    /// Records copied to whichever of the two sides was missing them.
    pub repaired_copies: usize,
    /// Owner retirements whose fence and retirement row were applied.
    pub owner_retirements: usize,
    /// Space targets whose permanent fence was applied.
    pub space_fences: usize,
    pub resource_fences: usize,
    /// Completion tombstones the database was missing.
    pub tombstones_created: usize,
    /// Accepted purges whose job was missing and was re-created.
    pub purges_resumed: usize,
    /// Purge jobs already present and not complete; the worker resumes them.
    pub purges_in_progress: usize,
    /// Accepted purges with no job and no live space row: fenced, nothing to resume.
    pub purges_without_live_space: usize,
    /// Completed purges whose space row is back but whose acceptance record
    /// is gone (older than the lock period): fenced, not resumable.
    pub purges_unresumable: usize,
    /// Signed physical prefixes found and purged to empty.
    pub prefixes_purged: usize,
    /// Signed physical prefixes proved absent.
    pub prefixes_absent: usize,
    /// Prefixes still inside the upload grace; the next pass handles them.
    pub prefixes_deferred: usize,
    /// Prefixes of a store kind this node does not run; never proved here.
    pub prefixes_unavailable: usize,
    /// Owners with a verified `erased` record whose encryption rows were
    /// present (after a restore, or a crash after the record) and deleted.
    pub owners_erased_redeleted: usize,
    /// Erased owners whose settled `deletions.jsonl` operations were removed.
    pub owners_pruned: usize,
    /// Erased owners whose key rows remain, so `deletions.jsonl` keeps them.
    pub blocked_rows_present: usize,
}

impl ReconcileReport {
    pub fn log(&self) {
        ::tracing::info!(
            event = "space_purge_reconciled",
            records = self.records,
            repaired_copies = self.repaired_copies,
            owner_retirements = self.owner_retirements,
            space_fences = self.space_fences,
            resource_fences = self.resource_fences,
            tombstones_created = self.tombstones_created,
            purges_resumed = self.purges_resumed,
            purges_in_progress = self.purges_in_progress,
            purges_without_live_space = self.purges_without_live_space,
            purges_unresumable = self.purges_unresumable,
            prefixes_purged = self.prefixes_purged,
            prefixes_absent = self.prefixes_absent,
            prefixes_deferred = self.prefixes_deferred,
            prefixes_unavailable = self.prefixes_unavailable,
            owners_erased_redeleted = self.owners_erased_redeleted,
            owners_pruned = self.owners_pruned,
            blocked_rows_present = self.blocked_rows_present,
            "purge ledger reconciled"
        );
    }
}

fn fail<E>(step: &'static str) -> impl FnOnce(E) -> Error {
    move |_| Error::other(step)
}

/// Live space rows by `(key ID, space HMAC)`, built only when a resumable
/// purge needs one. The ledger itself never names a space.
type LiveSpaces = HashMap<(String, Vec<u8>), SpaceId>;

impl LifecycleRuntime {
    /// Verify every record, then apply it under the global restore drain.
    /// Space traffic is enabled only when the whole pass succeeds; on any
    /// failure the ledger stays unverified and space traffic stays refused.
    pub async fn reconcile(&self, stores: &PurgeStores) -> Result<ReconcileReport, Error> {
        let result = self.reconcile_once(stores).await;
        match &result {
            Ok(_) => {
                self.fence.set_serving_ready(true);
                self.work_requested.notify_one();
            }
            Err(_) => {
                self.ledger_verified.store(false, Ordering::Release);
                self.fence.set_serving_ready(false);
            }
        }
        result
    }

    async fn reconcile_once(&self, stores: &PurgeStores) -> Result<ReconcileReport, Error> {
        let db = self.conn.sea_orm_connection();
        let drain = self.fence.restore_drain().await;
        let external = self
            .verify_ledger()
            .await
            .map_err(fail("purge ledger verification failed"))?;
        let copies =
            repair_acceptance_copies(db, &*self.ledger, &self.keys, &drain, |_| Ok(())).await?;
        let mut records = BTreeMap::new();
        for record in external {
            let path = record
                .object_key()
                .map_err(fail("invalid purge ledger record"))?;
            records.insert(path, record);
        }
        for row in space_purge_ledger_copy::Entity::find()
            .all(db)
            .await
            .map_err(fail("purge ledger copies unavailable"))?
        {
            let record = self
                .keys
                .verify(&row.object_key, &row.body)
                .map_err(fail("purge ledger copy verification failed"))?;
            records.entry(row.object_key).or_insert(record);
        }
        let mut report = ReconcileReport {
            records: records.len(),
            repaired_copies: copies.repaired_copies,
            ..ReconcileReport::default()
        };
        type Target<'a> = (Option<&'a LedgerRecord>, Option<&'a LedgerRecord>);
        let mut targets: BTreeMap<(&str, &str), Target<'_>> = BTreeMap::new();
        for record in records.values() {
            match record.kind.as_str() {
                "owner" if record.state == "erased" => {}
                "owner" => {
                    self.import_retirement(db, record).await?;
                    report.owner_retirements += 1;
                }
                "resource" => {
                    let digest = hex::decode(&record.target_hmac)
                        .map_err(fail("invalid purge ledger record"))?;
                    let tx = db
                        .begin()
                        .await
                        .map_err(fail("purge fence import failed"))?;
                    self.fence
                        .fence_hmac(&tx, "resource", &record.key_id, &digest)
                        .await
                        .map_err(fail("purge fence import failed"))?;
                    tx.commit()
                        .await
                        .map_err(fail("purge fence import failed"))?;
                    report.resource_fences += 1;
                }
                _ => {
                    let target = targets
                        .entry((record.key_id.as_str(), record.target_hmac.as_str()))
                        .or_default();
                    if record.state == "purging" {
                        target.0 = Some(record);
                    } else {
                        target.1 = Some(record);
                    }
                }
            }
        }
        let mut live = None;
        for ((key_id, target), (accepted, completed)) in targets {
            self.import_space(
                db,
                key_id,
                target,
                accepted,
                completed,
                &mut live,
                &mut report,
            )
            .await?;
        }
        self.repair_prefixes(db, stores, &drain, &records, &mut report)
            .await?;
        let erased = crate::space_purge_owner_erasure::redelete_erased_owners(
            db,
            &self.keys,
            stores.deletions.as_ref(),
            &records,
        )
        .await?;
        report.owners_erased_redeleted = erased.owners_rows_deleted;
        report.owners_pruned = erased.owners_pruned;
        report.blocked_rows_present = erased.blocked_rows_present;
        drop(drain);
        Ok(report)
    }

    async fn import_retirement(
        &self,
        db: &DatabaseConnection,
        record: &LedgerRecord,
    ) -> Result<(), Error> {
        let failed = || Error::other("owner retirement import failed");
        let digest = hex::decode(&record.target_hmac).map_err(|_| failed())?;
        let tx = db.begin().await.map_err(|_| failed())?;
        tinycloud_core::space_purge_records::lock(&tx)
            .await
            .map_err(|_| failed())?;
        self.fence
            .fence_hmac(&tx, "owner", &record.key_id, &digest)
            .await
            .map_err(|_| failed())?;
        if space_retirement::Entity::find_by_id((digest.clone(), record.key_id.clone()))
            .one(&tx)
            .await
            .map_err(|_| failed())?
            .is_none()
        {
            space_retirement::ActiveModel {
                owner_hmac: Set(digest),
                hmac_key_id: Set(record.key_id.clone()),
                retirement_id: Set(record.operation_id.clone()),
                accepted_at: Set(
                    OffsetDateTime::from_unix_timestamp(record.timestamp).map_err(|_| failed())?
                ),
            }
            .insert(&tx)
            .await
            .map_err(|_| failed())?;
        }
        tinycloud_core::space_purge_records::request_all(&tx)
            .await
            .map_err(|_| failed())?;
        tx.commit().await.map_err(|_| failed())
    }

    #[allow(clippy::too_many_arguments)]
    async fn import_space(
        &self,
        db: &DatabaseConnection,
        key_id: &str,
        target: &str,
        accepted: Option<&LedgerRecord>,
        completed: Option<&LedgerRecord>,
        live: &mut Option<LiveSpaces>,
        report: &mut ReconcileReport,
    ) -> Result<(), Error> {
        let failed = || Error::other("space purge import failed");
        let operation_id = match (accepted, completed) {
            (Some(a), Some(c)) if a.operation_id != c.operation_id => {
                return Err(Error::other("purge ledger records conflict"))
            }
            (Some(record), _) | (None, Some(record)) => record.operation_id.clone(),
            (None, None) => return Ok(()),
        };
        let digest = hex::decode(target).map_err(|_| failed())?;
        let tx = db.begin().await.map_err(|_| failed())?;
        let generation = self
            .fence
            .fence_hmac(&tx, "space", key_id, &digest)
            .await
            .map_err(|_| failed())?;
        report.space_fences += 1;
        if let Some(completed) = completed {
            let completed_at =
                OffsetDateTime::from_unix_timestamp(completed.timestamp).map_err(|_| failed())?;
            let inserted = tx
                .execute(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "INSERT INTO space_purge_tombstone(tombstone_hmac,hmac_key_id,purge_id,completed_at)
                     VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING",
                    [
                        digest.clone().into(),
                        key_id.into(),
                        operation_id.clone().into(),
                        completed_at.into(),
                    ],
                ))
                .await
                .map_err(|_| failed())?;
            report.tombstones_created += inserted.rows_affected() as usize;
        }
        let jobs = space_purge_job::Entity::find()
            .filter(space_purge_job::Column::TombstoneHmac.eq(digest.clone()))
            .filter(space_purge_job::Column::HmacKeyId.eq(key_id))
            .all(&tx)
            .await
            .map_err(|_| failed())?;
        if !jobs.is_empty() {
            if jobs.iter().any(|job| job.purge_id != operation_id) {
                return Err(Error::other("purge job conflicts with the ledger"));
            }
            if jobs.iter().any(|job| job.phase != "complete") {
                report.purges_in_progress += 1;
            }
            return tx.commit().await.map_err(|_| failed());
        }
        if live.is_none() {
            *live = Some(self.live_spaces(db).await?);
        }
        let space = live
            .as_ref()
            .and_then(|live| live.get(&(key_id.to_owned(), digest.clone())));
        match (space, accepted) {
            (Some(space), Some(accepted)) => {
                let now = OffsetDateTime::now_utc();
                space_purge_job::ActiveModel {
                    purge_id: Set(operation_id),
                    space: Set(Some(space.to_string())),
                    tombstone_hmac: Set(digest),
                    hmac_key_id: Set(key_id.into()),
                    owner_hmac: Set(self
                        .keys
                        .target_hmac(key_id, "owner", space.did().as_str())
                        .map_err(|_| failed())?),
                    accepted_at: Set(OffsetDateTime::from_unix_timestamp(accepted.timestamp)
                        .map_err(|_| failed())?),
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
                .map_err(|_| failed())?;
                report.purges_resumed += 1;
            }
            (Some(_), None) => report.purges_unresumable += 1,
            (None, _) if completed.is_none() => report.purges_without_live_space += 1,
            (None, _) => {}
        }
        tx.commit().await.map_err(|_| failed())
    }

    async fn live_spaces(&self, db: &DatabaseConnection) -> Result<LiveSpaces, Error> {
        let mut live = HashMap::new();
        for row in space::Entity::find()
            .all(db)
            .await
            .map_err(fail("live space inventory unavailable"))?
        {
            let space = row.id.0;
            let canonical = space.to_string();
            for key_id in self.keys.key_ids() {
                let digest = self
                    .keys
                    .target_hmac(key_id, "space", &canonical)
                    .map_err(fail("live space inventory unavailable"))?;
                live.insert((key_id.to_owned(), digest), space.clone());
            }
        }
        Ok(live)
    }

    /// Match every signed prefix against the stores this node runs: purge a
    /// present one to empty, prove an absent one. Unmatched prefixes are never
    /// touched, and an HMAC is never reversed.
    async fn repair_prefixes(
        &self,
        db: &DatabaseConnection,
        stores: &PurgeStores,
        drain: &RestoreDrain,
        records: &BTreeMap<String, LedgerRecord>,
        report: &mut ReconcileReport,
    ) -> Result<(), Error> {
        let kinds = stores.store_kinds();
        let signed = || {
            records
                .iter()
                .filter(|(_, record)| record.kind == "space" && record.version == 2)
        };
        report.prefixes_unavailable = signed()
            .flat_map(|(_, record)| &record.prefixes)
            .filter(|prefix| !kinds.iter().any(|kind| kind.as_str() == prefix.store_kind))
            .count();
        for kind in kinds {
            let store = stores
                .restore_store(kind)
                .ok_or_else(|| Error::other("purge store unavailable"))?;
            let inventory = scan_store_inventory(&store, &self.keys, &self.fence, drain).await?;
            for (path, record) in signed() {
                let body = record
                    .to_bytes()
                    .map_err(fail("invalid purge ledger record"))?;
                for prefix in record
                    .prefixes
                    .iter()
                    .filter(|prefix| prefix.store_kind == kind.as_str())
                {
                    let Some(raw) = inventory.matching_prefix(&record.key_id, &prefix.prefix_hmac)
                    else {
                        let absent = inventory
                            .prove_absent(path, &body, &prefix.prefix_hmac)
                            .map_err(fail("purge prefix proof failed"))?;
                        match finish_absent_prefix(db, &absent).await? {
                            RepairOneOutcome::VerifiedEmpty => report.prefixes_absent += 1,
                            RepairOneOutcome::Deferred => report.prefixes_deferred += 1,
                            _ => {}
                        }
                        continue;
                    };
                    let proof =
                        VerifiedPurgePrefix::verify_candidate(&self.keys, path, &body, kind, raw)
                            .map_err(fail("purge prefix proof failed"))?;
                    loop {
                        let store = stores
                            .restore_store(kind)
                            .ok_or_else(|| Error::other("purge store unavailable"))?;
                        match repair_one(db, store, &self.fence, drain, &proof).await? {
                            RepairOneOutcome::MoreObjects => {}
                            RepairOneOutcome::VerifiedEmpty => {
                                report.prefixes_purged += 1;
                                break;
                            }
                            RepairOneOutcome::Deferred => {
                                report.prefixes_deferred += 1;
                                break;
                            }
                            RepairOneOutcome::Busy | RepairOneOutcome::LeaseLost => break,
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

/// How long a failed runtime reconciliation waits before it runs again.
const RECONCILE_RETRY: Duration = Duration::from_secs(30);

/// Re-run reconciliation whenever a lifecycle request could not confirm its
/// ledger write. Space traffic stays refused until a pass succeeds.
pub async fn run_reconciler(
    runtime: LifecycleRuntime,
    stores: Arc<PurgeStores>,
    shutdown: rocket::Shutdown,
) {
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = runtime.reconcile_requested.notified() => {}
            _ = &mut shutdown => return,
        }
        loop {
            let result = tokio::select! {
                result = runtime.reconcile(&stores) => result,
                _ = &mut shutdown => return,
            };
            match result {
                Ok(report) => {
                    report.log();
                    break;
                }
                Err(error) => {
                    ::tracing::error!(
                        event = "space_purge_reconcile_failed",
                        %error,
                        "purge ledger reconciliation failed; space traffic stays refused"
                    );
                    tokio::select! {
                        _ = tokio::time::sleep(RECONCILE_RETRY) => {}
                        _ = &mut shutdown => return,
                    }
                }
            }
        }
    }
}

//! Types passed to bounded physical restore repair. Construction stays private
//! to authenticated reconciliation; storage transports cannot authorize work.
pub use tinycloud_core::space_purge_fence::RestoreDrain;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixStoreKind {
    KvFileSystem,
    KvS3,
    SqlFileSystem,
    SqlS3,
    SqliteCache,
    DuckDbCache,
}
impl PrefixStoreKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::KvFileSystem => "kv-filesystem",
            Self::KvS3 => "kv-s3",
            Self::SqlFileSystem => "sql-filesystem",
            Self::SqlS3 => "sql-s3",
            Self::SqliteCache => "sqlite-cache",
            Self::DuckDbCache => "duckdb-cache",
        }
    }
}
pub struct VerifiedPurgePrefix {
    store_kind: PrefixStoreKind,
    prefix: String,
    ledger_key: String,
    prefix_hmac: String,
    earliest_repair_at: i64,
}
impl VerifiedPurgePrefix {
    /// Only an authenticated complete prefix inventory can authorize matching
    /// actual storage candidates. No caller-supplied digest is trusted.
    pub fn verify_candidate(
        keys: &tinycloud_core::space_purge_ledger::LedgerKeys,
        object_key: &str,
        body: &[u8],
        store_kind: PrefixStoreKind,
        prefix: &str,
    ) -> Result<Self, tinycloud_core::space_purge_ledger::LedgerError> {
        use tinycloud_core::space_purge_ledger::LedgerError;
        let record = keys.verify(object_key, body)?;
        if record.version != 2 || record.kind != "space" {
            return Err(LedgerError);
        }
        let candidate = keys.prefix_hmac(&record.key_id, store_kind.as_str(), prefix)?;
        if !record.prefixes.contains(&candidate) {
            return Err(LedgerError);
        }
        Ok(Self {
            store_kind,
            prefix: prefix.into(),
            ledger_key: object_key.into(),
            prefix_hmac: candidate.prefix_hmac,
            earliest_repair_at: repair_not_before(&record),
        })
    }

    pub fn ledger_key(&self) -> &str {
        &self.ledger_key
    }
    pub fn prefix_hmac(&self) -> &str {
        &self.prefix_hmac
    }
    pub fn store_kind(&self) -> PrefixStoreKind {
        self.store_kind
    }
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

/// Deliberate crash boundaries for durable-copy regression tests.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CopyRepairPoint {
    ExternalPublished,
    DatabaseCommitted,
}
pub struct CopyRepairCounts {
    pub repaired_copies: usize,
    /// Completion evidence remains authoritative, but its missing counterpart
    /// is NOT written before exact physical emptiness is proved again.
    pub completion_records_requiring_storage_check: usize,
}

/// Repair authenticated acceptance/retirement copies only forward. The caller
/// retains the global restore drain until physical and metadata repair finish.
/// This function never sets serving readiness or reports purge completion.
pub async fn repair_acceptance_copies(
    db: &tinycloud_core::sea_orm::DatabaseConnection,
    ledger: &dyn super::purge_ledger::PurgeLedgerStore,
    keys: &tinycloud_core::space_purge_ledger::LedgerKeys,
    _drain: &RestoreDrain,
    mut checkpoint: impl FnMut(CopyRepairPoint) -> std::io::Result<()>,
) -> std::io::Result<CopyRepairCounts> {
    use std::{collections::BTreeMap, io::Error};
    use tinycloud_core::{
        models::space_purge_ledger_copy,
        sea_orm::{EntityTrait, TransactionTrait},
    };
    let unavailable = || Error::other("purge reconciliation evidence unavailable");
    let mut records = BTreeMap::new();
    // Verify the entire union BEFORE repairing anything. Bad evidence never
    // becomes authority merely because it is in one durable copy.
    for row in space_purge_ledger_copy::Entity::find()
        .all(db)
        .await
        .map_err(|_| unavailable())?
    {
        let record = keys
            .verify(&row.object_key, &row.body)
            .map_err(|_| unavailable())?;
        records.insert(row.object_key, (record, false, true));
    }
    for path in ledger
        .list_purge_records()
        .await
        .map_err(|_| unavailable())?
    {
        let body = ledger
            .read_purge_record(&path)
            .await
            .map_err(|_| unavailable())?
            .ok_or_else(unavailable)?;
        let record = keys.verify(&path, &body).map_err(|_| unavailable())?;
        if let Some((other, external, _)) = records.get_mut(&path) {
            if other != &record {
                return Err(unavailable());
            }
            *external = true;
        } else {
            records.insert(path, (record, true, false));
        }
    }
    // A terminal record cannot change operation or lose acceptance prefixes.
    for (record, _, _) in records.values() {
        if record.state == "complete" {
            let accepted_key = record
                .object_key()
                .map_err(|_| unavailable())?
                .trim_end_matches("complete")
                .to_owned()
                + "purging";
            if let Some((accepted, _, _)) = records.get(&accepted_key) {
                if accepted.operation_id != record.operation_id
                    || accepted.version != record.version
                    || accepted.prefixes != record.prefixes
                    || accepted.timestamp > record.timestamp
                {
                    return Err(unavailable());
                }
            }
        }
    }
    let mut counts = CopyRepairCounts {
        repaired_copies: 0,
        completion_records_requiring_storage_check: 0,
    };
    for (path, (record, external, database)) in records {
        // Re-observation can follow a restore even if an earlier repair was
        // complete. Enqueue a new pending job; never downgrade old history.
        if record.kind == "space" && record.version == 2 {
            tinycloud_core::space_purge_prefix_repair::enqueue(db, keys, &record)
                .await
                .map_err(|_| unavailable())?;
        }
        if record.state == "complete" {
            counts.completion_records_requiring_storage_check += 1;
            continue;
        }
        let body = record.to_bytes().map_err(|_| unavailable())?;
        if !external {
            ledger
                .append_purge_record(&path, &body)
                .await
                .map_err(|_| unavailable())?;
            checkpoint(CopyRepairPoint::ExternalPublished)?;
            counts.repaired_copies += 1;
        }
        if !database {
            let tx = db.begin().await.map_err(|_| unavailable())?;
            tinycloud_core::space_purge_ledger_copy::retain(
                &tx,
                keys,
                &path,
                &body,
                time::OffsetDateTime::now_utc(),
            )
            .await
            .map_err(|_| unavailable())?;
            tx.commit().await.map_err(|_| unavailable())?;
            checkpoint(CopyRepairPoint::DatabaseCommitted)?;
            counts.repaired_copies += 1;
        }
    }
    Ok(counts)
}

fn repair_not_before(record: &tinycloud_core::space_purge_ledger::LedgerRecord) -> i64 {
    if record.state == "purging" {
        record
            .timestamp
            .saturating_add(tinycloud_core::kv_orphans::ORPHAN_GRACE.whole_seconds())
    } else {
        0
    }
}

/// Complete observed namespace inventory, held only while the global drain
/// excludes publishers. It is never serialized and cannot recover lost IDs.
pub struct CompletePrefixInventory<'keys> {
    keys: &'keys tinycloud_core::space_purge_ledger::LedgerKeys,
    kind: PrefixStoreKind,
    prefixes: std::collections::BTreeMap<String, std::collections::BTreeMap<String, String>>,
    _drain: RestoreDrain,
}
pub struct VerifiedAbsentPrefix {
    _drain: RestoreDrain,
    ledger_key: String,
    kind: PrefixStoreKind,
    prefix_hmac: String,
    earliest_repair_at: i64,
}
impl CompletePrefixInventory<'_> {
    pub fn matching_prefix(&self, key_id: &str, digest: &str) -> Option<&str> {
        self.prefixes.get(key_id)?.get(digest).map(String::as_str)
    }
    pub fn prove_absent(
        &self,
        path: &str,
        body: &[u8],
        digest: &str,
    ) -> Result<VerifiedAbsentPrefix, tinycloud_core::space_purge_ledger::LedgerError> {
        use tinycloud_core::space_purge_ledger::{LedgerError, PrefixHmac};
        let record = self.keys.verify(path, body)?;
        if record.kind != "space"
            || record.version != 2
            || !self.prefixes.contains_key(&record.key_id)
            || self.matching_prefix(&record.key_id, digest).is_some()
            || !record.prefixes.contains(&PrefixHmac {
                store_kind: self.kind.as_str().into(),
                prefix_hmac: digest.into(),
            })
        {
            return Err(LedgerError);
        }
        Ok(VerifiedAbsentPrefix {
            _drain: self._drain.clone(),
            ledger_key: path.into(),
            kind: self.kind,
            prefix_hmac: digest.into(),
            earliest_repair_at: repair_not_before(&record),
        })
    }
}

pub async fn scan_store_inventory<'keys>(
    store: &super::purge_restore::RestorePurgeStore<'_>,
    keys: &'keys tinycloud_core::space_purge_ledger::LedgerKeys,
    fence: &tinycloud_core::space_purge_fence::SpacePurgeFence,
    drain: &RestoreDrain,
) -> std::io::Result<CompletePrefixInventory<'keys>> {
    use super::purge_restore::RestorePurgeStore;
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::Error,
    };
    fence
        .validate_restore_drain(drain)
        .map_err(|_| Error::other("invalid restore admission barrier"))?;
    let failed = || Error::other("restore namespace inventory unavailable");
    let kind = match store {
        RestorePurgeStore::KvFileSystem(_) => PrefixStoreKind::KvFileSystem,
        RestorePurgeStore::KvS3(_) => PrefixStoreKind::KvS3,
        RestorePurgeStore::SqlFileSystem(_) => PrefixStoreKind::SqlFileSystem,
        RestorePurgeStore::SqlS3(_) => PrefixStoreKind::SqlS3,
        RestorePurgeStore::SqliteCache(_) => PrefixStoreKind::SqliteCache,
        #[cfg(feature = "duckdb")]
        RestorePurgeStore::DuckDbCache(_) => PrefixStoreKind::DuckDbCache,
    };
    let mut result = CompletePrefixInventory {
        keys,
        kind,
        prefixes: keys
            .key_ids()
            .map(|id| (id.to_owned(), BTreeMap::new()))
            .collect(),
        _drain: drain.clone(),
    };
    let mut cursor: Option<String> = None;
    let mut seen = BTreeSet::new();
    loop {
        let (prefixes, next): (Vec<String>, Option<String>) = match store {
            RestorePurgeStore::KvFileSystem(store) => {
                let page = store
                    .list_purge_prefixes(cursor.as_deref())
                    .await
                    .map_err(|_| failed())?;
                (
                    page.prefixes.into_iter().map(|p| p.prefix).collect(),
                    page.next_cursor,
                )
            }
            RestorePurgeStore::KvS3(store) => {
                let page = store
                    .list_purge_prefixes(cursor.as_deref())
                    .await
                    .map_err(|_| failed())?;
                (
                    page.prefixes.into_iter().map(|p| p.prefix).collect(),
                    page.next_cursor,
                )
            }
            RestorePurgeStore::SqlFileSystem(store) => {
                let page = store
                    .list_purge_prefixes(cursor.as_deref())
                    .await
                    .map_err(|_| failed())?;
                (
                    page.prefixes
                        .into_iter()
                        .map(|p| p.as_str().to_owned())
                        .collect(),
                    page.next_cursor,
                )
            }
            RestorePurgeStore::SqlS3(store) => {
                let page = store
                    .list_purge_prefixes(cursor.as_deref())
                    .await
                    .map_err(|_| failed())?;
                (
                    page.prefixes
                        .into_iter()
                        .map(|p| p.as_str().to_owned())
                        .collect(),
                    page.next_cursor,
                )
            }
            RestorePurgeStore::SqliteCache(service) => (
                service
                    .enumerate_cache_spaces_for_restore(drain)
                    .await
                    .map_err(|_| failed())?
                    .into_iter()
                    .map(|space| format!("{space}/"))
                    .collect(),
                None,
            ),
            #[cfg(feature = "duckdb")]
            RestorePurgeStore::DuckDbCache(service) => (
                service
                    .enumerate_cache_spaces_for_restore(drain)
                    .await
                    .map_err(|_| failed())?
                    .into_iter()
                    .map(|space| format!("{space}/"))
                    .collect(),
                None,
            ),
        };
        for prefix in prefixes {
            for (id, map) in &mut result.prefixes {
                let digest = keys
                    .prefix_hmac(id, kind.as_str(), &prefix)
                    .map_err(|_| failed())?;
                if let Some(other) = map.insert(digest.prefix_hmac, prefix.clone()) {
                    if other != prefix {
                        return Err(failed());
                    }
                }
            }
        }
        match next {
            None => break,
            Some(next) if next.is_empty() || !seen.insert(next.clone()) => return Err(failed()),
            Some(next) => cursor = Some(next),
        }
    }
    Ok(result)
}

#[derive(Debug, PartialEq, Eq)]
pub enum RepairOneOutcome {
    Deferred,
    MoreObjects,
    VerifiedEmpty,
    Busy,
    LeaseLost,
}

/// One bounded authenticated physical batch, with a live lease heartbeat.
/// This advances only opaque repair progress, never a purge or ledger state.
pub async fn repair_one(
    db: &tinycloud_core::sea_orm::DatabaseConnection,
    store: super::purge_restore::RestorePurgeStore<'_>,
    fence: &tinycloud_core::space_purge_fence::SpacePurgeFence,
    drain: &RestoreDrain,
    proof: &VerifiedPurgePrefix,
) -> std::io::Result<RepairOneOutcome> {
    use super::purge_restore::{purge_restore_prefix_batch, RestorePrefixOutcome};
    use tinycloud_core::space_purge_prefix_repair as queue;
    let failed = || std::io::Error::other("restore prefix repair unavailable");
    fence.validate_restore_drain(drain).map_err(|_| failed())?;
    if time::OffsetDateTime::now_utc().unix_timestamp() < proof.earliest_repair_at {
        return Ok(RepairOneOutcome::Deferred);
    }
    let Some(claim) = queue::claim(
        db,
        &uuid::Uuid::new_v4().to_string(),
        proof.ledger_key(),
        proof.store_kind().as_str(),
        proof.prefix_hmac(),
    )
    .await
    .map_err(|_| failed())?
    else {
        return Ok(RepairOneOutcome::Busy);
    };
    let work = purge_restore_prefix_batch(store, drain, proof);
    tokio::pin!(work);
    let mut heartbeat = tokio::time::interval(std::time::Duration::from_secs(10));
    heartbeat.tick().await;
    let outcome = loop {
        tokio::select! {
            result = &mut work => break result,
            _ = heartbeat.tick() => {
                if !queue::renew(db,&claim).await.map_err(|_|failed())? { return Ok(RepairOneOutcome::LeaseLost); }
            }
        }
    };
    match outcome {
        Ok(RestorePrefixOutcome::VerifiedEmpty) => {
            if queue::complete(db, &claim).await.map_err(|_| failed())? {
                Ok(RepairOneOutcome::VerifiedEmpty)
            } else {
                Ok(RepairOneOutcome::LeaseLost)
            }
        }
        Ok(RestorePrefixOutcome::MoreObjects) => {
            if queue::release(db, &claim).await.map_err(|_| failed())? {
                Ok(RepairOneOutcome::MoreObjects)
            } else {
                Ok(RepairOneOutcome::LeaseLost)
            }
        }
        Err(_) => {
            let _ = queue::release(db, &claim).await;
            Err(failed())
        }
    }
}

pub async fn finish_absent_prefix(
    db: &tinycloud_core::sea_orm::DatabaseConnection,
    proof: &VerifiedAbsentPrefix,
) -> std::io::Result<RepairOneOutcome> {
    use tinycloud_core::space_purge_prefix_repair as queue;
    let failed = || std::io::Error::other("restore prefix repair unavailable");
    if time::OffsetDateTime::now_utc().unix_timestamp() < proof.earliest_repair_at {
        return Ok(RepairOneOutcome::Deferred);
    }
    let Some(claim) = queue::claim(
        db,
        &uuid::Uuid::new_v4().to_string(),
        &proof.ledger_key,
        proof.kind.as_str(),
        &proof.prefix_hmac,
    )
    .await
    .map_err(|_| failed())?
    else {
        return Ok(RepairOneOutcome::Busy);
    };
    if queue::complete(db, &claim).await.map_err(|_| failed())? {
        Ok(RepairOneOutcome::VerifiedEmpty)
    } else {
        Ok(RepairOneOutcome::LeaseLost)
    }
}

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

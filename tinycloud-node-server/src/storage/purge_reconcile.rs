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
        })
    }

    pub fn store_kind(&self) -> PrefixStoreKind {
        self.store_kind
    }
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

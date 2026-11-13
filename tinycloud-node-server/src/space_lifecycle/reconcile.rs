//! Types passed to bounded physical restore repair. Construction stays private
//! to authenticated reconciliation; storage transports cannot authorize work.
pub use tinycloud_core::space_purge_fence::RestoreDrain;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrefixStoreKind {
    KvFileSystem,
    KvS3,
    SqlFileSystem,
    SqlS3,
}
pub struct VerifiedPurgePrefix {
    store_kind: PrefixStoreKind,
    prefix: String,
}
impl VerifiedPurgePrefix {
    pub fn store_kind(&self) -> PrefixStoreKind {
        self.store_kind
    }
    pub fn prefix(&self) -> &str {
        &self.prefix
    }
}

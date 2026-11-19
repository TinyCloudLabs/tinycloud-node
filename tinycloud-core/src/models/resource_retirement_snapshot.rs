//! Local-only outside-reader provenance; raw relationship bytes are never ledger data.
use sea_orm::entity::prelude::*;

/// Raw local provenance. ORM ActiveModel debug output must redact it too.
#[derive(Clone, PartialEq, Eq, sea_orm::DeriveValueType)]
pub struct SnapshotBody(Vec<u8>);
impl SnapshotBody {
    /// Data only; parsing this wrapper never authenticates retirement authority.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
impl std::fmt::Debug for SnapshotBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SnapshotBody([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "resource_retirement_snapshot")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub retirement_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub hmac_key_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub target_hmac: Vec<u8>,
    pub network_hmac: Vec<u8>,
    pub snapshot_body: SnapshotBody,
    pub snapshot_commitment: Vec<u8>,
}
impl std::fmt::Debug for Model {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResourceRetirementSnapshot")
            .finish_non_exhaustive()
    }
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

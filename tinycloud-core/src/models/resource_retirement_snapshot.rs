//! Local-only outside-reader provenance; raw relationship bytes are never ledger data.
use sea_orm::entity::prelude::*;

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
    pub snapshot_body: Vec<u8>,
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

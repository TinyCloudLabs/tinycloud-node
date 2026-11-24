//! Authenticated bytes retained independently from object-store publication.
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "space_purge_ledger_copy")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub object_key: String,
    pub body: Vec<u8>,
    pub recorded_at: OffsetDateTime,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

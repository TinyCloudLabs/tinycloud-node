use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "space_purge_tombstone")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub tombstone_hmac: Vec<u8>,
    #[sea_orm(primary_key, auto_increment = false)]
    pub hmac_key_id: String,
    pub purge_id: String,
    pub completed_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

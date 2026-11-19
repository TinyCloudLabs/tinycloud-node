use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "space_purge_request")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub idempotency_key: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: String,
    pub owner_hmac: Vec<u8>,
    pub target_hmac: Vec<u8>,
    pub operation_id: String,
    pub accepted_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

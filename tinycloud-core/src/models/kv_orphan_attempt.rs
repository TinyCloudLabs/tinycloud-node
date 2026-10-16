use crate::hash::Hash;
use crate::types::SpaceIdWrap;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "kv_orphan_attempt")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: SpaceIdWrap,
    #[sea_orm(primary_key, auto_increment = false)]
    pub value: Hash,
    #[sea_orm(primary_key, auto_increment = false)]
    pub attempt_id: String,
    pub generation: i64,
    pub created_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

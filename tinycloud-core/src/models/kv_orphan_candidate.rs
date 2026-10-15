use crate::hash::Hash;
use crate::types::SpaceIdWrap;
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "kv_orphan_candidate")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: SpaceIdWrap,
    #[sea_orm(primary_key, auto_increment = false)]
    pub value: Hash,
    pub created_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

use crate::hash::Hash;
use crate::types::SpaceIdWrap;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "kv_blob_generation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: SpaceIdWrap,
    #[sea_orm(primary_key, auto_increment = false)]
    pub value: Hash,
    pub generation: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

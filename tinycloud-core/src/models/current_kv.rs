use crate::hash::Hash;
use crate::types::{Metadata, Path, SpaceIdWrap};
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "current_kv")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub space: SpaceIdWrap,
    #[sea_orm(primary_key)]
    pub key: Path,
    pub invocation: Hash,
    pub seq: i64,
    pub epoch: Hash,
    pub epoch_seq: i64,
    pub value: Hash,
    pub metadata: Metadata,
    pub deleted: bool,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

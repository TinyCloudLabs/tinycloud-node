use crate::hash::Hash;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "space_purge_shared_residue")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub purge_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub record_kind: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub record_id: Hash,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

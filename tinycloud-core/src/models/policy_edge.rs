use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_edge")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub child_cid: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub position: i32,
    pub parent_cid: String,
    pub edge_kind: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

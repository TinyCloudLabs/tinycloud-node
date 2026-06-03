use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "encryption_network_member")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub network_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub node_id: String,
    pub role: String,
    pub share_index: i32,
    pub joined_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

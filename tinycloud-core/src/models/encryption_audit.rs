use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "encryption_audit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub request_hash: String,
    pub requester: String,
    pub network_id: String,
    pub node_id: String,
    pub outcome: String,
    pub decided_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

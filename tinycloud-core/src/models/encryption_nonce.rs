use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "encryption_nonce")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub requester_did: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub nonce: String,
    pub expires_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

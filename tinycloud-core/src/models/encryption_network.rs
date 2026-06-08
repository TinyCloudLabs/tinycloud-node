use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "encryption_network")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub network_id: String,
    pub owner_did: String,
    pub name: String,
    pub alg: String,
    pub key_version: i64,
    pub public_key: Vec<u8>,
    pub state: String,
    pub threshold_n: i32,
    pub threshold_t: i32,
    pub key_backend: String,
    pub sealed_private_key: Option<Vec<u8>>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

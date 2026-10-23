use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "encryption_network_key")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub network_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub key_path: String,
    pub kind: String,
    pub state: String,
    pub public_key: Vec<u8>,
    pub sealed_seed: Option<Vec<u8>>,
    pub key_version: i64,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

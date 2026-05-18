use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "database_artifact")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub service: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    pub revision: i64,
    pub content_hash: String,
    pub payload: Vec<u8>,
    pub size_bytes: i64,
    pub backend: String,
    pub storage_mode: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

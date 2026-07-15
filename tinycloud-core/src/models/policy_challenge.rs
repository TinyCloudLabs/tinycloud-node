use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_challenge")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub challenge_id: String,
    pub challenge_json: Json,
    pub nonce_hash_hex: String,
    pub issued_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

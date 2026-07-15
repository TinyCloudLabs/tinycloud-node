use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_delegation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub delegation_cid: String,
    pub role: String,
    pub delegation_mode: String,
    pub artifact_json: Json,
    pub not_before: String,
    pub expires_at: String,
    pub status_checked_at: String,
    pub status_sequence: i64,
    pub revoked_at: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

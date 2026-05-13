use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "signed_kv_ticket")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: String,
    pub issuer_did: String,
    pub subject_did: String,
    pub space_id: String,
    pub path: String,
    pub service: String,
    pub ability: String,
    pub created_at: String,
    pub expires_at: String,
    pub invocation_expires_at: Option<String>,
    pub parent_expires_at: Option<String>,
    pub content_hash: Option<String>,
    pub etag: Option<String>,
    pub parent_cids_json: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

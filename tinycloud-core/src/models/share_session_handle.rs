use sea_orm::entity::prelude::*;
use std::fmt;

#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "share_session_handle")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub session_handle: String,
    pub authority_session_cid: String,
    pub binding_json: Json,
    pub holder_digest: String,
    pub issued_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

impl fmt::Debug for Model {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionHandleMapping { [REDACTED] }")
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

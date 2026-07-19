use sea_orm::entity::prelude::*;
use std::fmt;

#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "share_anonymous_challenge")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub challenge_id: String,
    pub request_digest: String,
    pub binding_json: Json,
    pub origin_digest: String,
    pub ip_digest: String,
    pub share_digest: String,
    pub nonce_hash: String,
    pub issued_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
}

impl fmt::Debug for Model {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AnonymousChallenge { [REDACTED] }")
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

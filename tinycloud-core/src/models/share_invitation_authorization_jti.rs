use sea_orm::entity::prelude::*;
use std::fmt;

#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "share_invitation_authorization_jti")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub jti: String,
    pub authorization_digest: String,
    pub binding_json: Json,
    pub issued_at: String,
    pub expires_at: String,
    pub consumed_at: Option<String>,
}

impl fmt::Debug for Model {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationAuthorizationJti { [REDACTED] }")
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

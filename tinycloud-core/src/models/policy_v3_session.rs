use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_v3_session")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub session_cid: String,
    pub policy_cid: String,
    pub authorization_bytes: Vec<u8>,
    pub recipient_did: String,
    pub claim_jti: String,
    pub claim_digest_hex: String,
    pub vp_digest_hex: String,
    pub state: String,
    pub not_before: String,
    pub expires_at: String,
    pub admitted_at: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

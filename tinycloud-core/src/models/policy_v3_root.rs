use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_v3_root")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub root_cid: String,
    pub policy_cid: String,
    pub role: String,
    pub authorization_bytes: Vec<u8>,
    pub status_checkpoint_bytes: Option<Vec<u8>>,
    pub previous_checkpoint_digest_hex: Option<String>,
    pub status_sequence: i64,
    pub admission_epoch: i64,
    pub status_checked_at: Option<String>,
    pub status_fresh_until: Option<String>,
    pub revoked_at: Option<String>,
    pub revocation_bytes: Option<Vec<u8>>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

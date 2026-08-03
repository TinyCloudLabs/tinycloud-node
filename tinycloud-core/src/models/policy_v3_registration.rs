use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_v3_registration")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub policy_cid: String,
    pub policy_bytes: Vec<u8>,
    pub policy_digest_hex: String,
    pub owner_did: String,
    pub policy_root_cid: String,
    pub enforcement_root_cid: String,
    pub content_source_digest_hex: String,
    pub native_projection_hash_hex: String,
    pub attested_enforcer_binding_bytes: Vec<u8>,
    pub registered_at: String,
    pub expires_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

//! Durable v2 share-policy registrations.
//!
//! The policy bytes are encrypted at rest.  The CID and the derived binding
//! fields remain plaintext so registrations can be addressed and rejected
//! without decrypting a policy into logs or a second authority store.

use sea_orm::entity::prelude::*;
use std::fmt;

#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "owner_share_policy")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub policy_cid: String,
    #[sea_orm(unique)]
    pub registration_cid: String,
    #[sea_orm(unique)]
    pub owner_delegation_cid: String,
    #[sea_orm(unique)]
    pub enforcement_delegation_cid: String,
    pub policy_bytes: Vec<u8>,
    pub policy_digest: String,
    pub matcher_digest: String,
    pub content_source_digest: String,
    pub owner_did: String,
    pub share_key_did: String,
    pub enforcer_did: String,
    pub node_audience: String,
    pub target_origin: String,
    pub space_id: String,
    pub resource_kind: String,
    pub resource_path: String,
    pub actions: Json,
    pub registered_at: String,
    pub expires_at: String,
    pub revoked_at: Option<String>,
}

impl fmt::Debug for Model {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnerSharePolicy { [REDACTED] }")
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

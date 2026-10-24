//! TC-1423: how a Policy/v3 registration's owner held what its roots grant.
//!
//! One row per registered policy, written in the registration transaction or
//! lazily on first use for policies registered before this table existed. A
//! missing row means the policy is pending classification.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_v3_owner_binding")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub policy_cid: String,
    /// `bound`, `bound-uncapped`, `root-authority` or `unknown`.
    pub state: String,
    /// Minimum expiry over the recorded authority closure (RFC 3339 UTC);
    /// `None` when no closure node expires or nothing is recorded.
    pub authority_expires_at: Option<String>,
    /// Why no authority is recorded (`unknown` rows only).
    pub unknown_reason: Option<String>,
    /// Version of the classifier that wrote the row; `unknown` rows written
    /// by an older version are classified again.
    pub classifier_version: i32,
    /// `record`, `enforce` or `backfill`.
    pub registered_mode: String,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

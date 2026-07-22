//! N4-owned replay control for the #117 policy-session establishment step.
//!
//! A row here is inserted exactly once per `(nonce, presentation_jti)` pair
//! atomically with the `#117` ancestry revalidation and the opaque session
//! handle in [`crate::share_email::bridge`]. It is never treated as an
//! authorization decision by itself.

use sea_orm::entity::prelude::*;
use std::fmt;

#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "share_policy_presentation_jti")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub presentation_jti: String,
    pub nonce: String,
    pub policy_cid: String,
    pub session_handle: String,
    pub issued_at: String,
    pub expires_at: String,
}

impl fmt::Debug for Model {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharePolicyPresentationJti { [REDACTED] }")
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

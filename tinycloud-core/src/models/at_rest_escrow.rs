//! Escrow bundles of ARK generations and their ceremony verification
//! records (TC-887). Superseded bundles are kept, marked inactive.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "at_rest_escrow")]
pub struct Model {
    /// Escrow fingerprint, lowercase hex.
    #[sea_orm(primary_key, auto_increment = false)]
    pub efp: String,
    pub generation: i32,
    /// `tinycloud_at_rest_escrow::EscrowBundle` as JSON.
    pub bundle: String,
    /// The bundle the node escrows to now (one per generation).
    pub active: bool,
    /// `tinycloud_at_rest_escrow::VerificationRecord` as JSON, after a
    /// successful ceremony test-unlock.
    pub record: Option<String>,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

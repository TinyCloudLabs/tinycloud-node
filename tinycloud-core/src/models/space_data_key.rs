//! Per-space data keys (DEKs), wrapped under an ARK generation's KEK
//! (TC-887). Deleting a space's rows crypto-shreds its sealed blobs.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "space_data_key")]
pub struct Model {
    /// Canonical `SpaceId::to_string()`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub dek_id: i32,
    /// The ARK generation whose KEK wrapped `wrapped`.
    pub generation: i32,
    /// `nonce(12) ‖ AES-256-GCM(KEK_g, DEK)`.
    pub wrapped: Vec<u8>,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

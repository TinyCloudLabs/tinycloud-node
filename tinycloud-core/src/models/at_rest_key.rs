//! One generation of the at-rest root key (ARK), sealed under the node's
//! wrap key W. Rows are never deleted (TC-887).

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "at_rest_key")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub generation: i32,
    /// 16 random bytes.
    pub ark_id: Vec<u8>,
    /// Which W sealed `sealed` (the HKDF info label).
    pub w_label: String,
    /// `nonce(12) ‖ AES-256-GCM(W, ARK)`.
    pub sealed: Vec<u8>,
    /// This generation's ARK sealed under the next generation's chain key;
    /// set when the next generation is made.
    pub chain: Option<Vec<u8>>,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

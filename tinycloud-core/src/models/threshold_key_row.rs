//! A threshold network member's state for one key (TC-2225), set by the
//! owner's `key.state` statements under the `stateSeq` merge rule. No public
//! key and no seed: keys are identity-based on the device.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "threshold_key_row")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub network_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub key_path: String,
    /// `active` or `blocked`.
    pub state: String,
    pub key_version: i64,
    pub state_seq: i64,
    /// CID of the statement that set the row: the lowest CID among the
    /// statements at `state_seq`, so every arrival order agrees.
    pub statement_cid: String,
    /// Two different statements share the row's `state_seq`; the key is
    /// blocked until a higher `state_seq` arrives.
    pub conflict: bool,
    pub updated_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

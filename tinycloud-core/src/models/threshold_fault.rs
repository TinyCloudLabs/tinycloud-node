//! A fault recorded against a threshold network party (TC-2225): an object a
//! peer member sent that acceptance refused, or owner key-state statements
//! that conflict.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "threshold_fault")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i64,
    pub network_id: String,
    /// The party at fault: the peer member's DID, or the network owner's.
    pub source_did: String,
    /// CID of the object the fault is about.
    pub object_cid: String,
    pub reason: String,
    pub recorded_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

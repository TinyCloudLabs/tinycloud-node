//! The owner's `network.revoke` statement for a threshold network (TC-2225).
//! Terminal: once a row exists, every key of the network is revoked.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "threshold_network_revocation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub network_id: String,
    /// CID of the first accepted `network.revoke` statement.
    pub statement_cid: String,
    pub recorded_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

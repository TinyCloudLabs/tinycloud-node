//! TC-1423: the ancestor closure of the delegations a Policy/v3 owner used as
//! authority for a registration. The closure is immutable (edges are signed
//! parents); CID aliases are resolved when it is queried.

use crate::hash::Hash;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_v3_owner_authority")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub policy_cid: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub delegation_id: Hash,
    /// Distance from the nearest recorded delegation (0 for the delegation
    /// itself).
    pub depth: i32,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

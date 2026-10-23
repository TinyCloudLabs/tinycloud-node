//! TC-1274: the current head epochs of each space, maintained by `transact`
//! under the space's sequence lock. A derived cache of the `epoch` /
//! `epoch_order` anti-join; see `crate::epoch_head` for when it is trusted.

use crate::hash::Hash;
use crate::types::SpaceIdWrap;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "epoch_head")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: SpaceIdWrap,
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Hash,
    /// The head epoch's `seq`.
    pub seq: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

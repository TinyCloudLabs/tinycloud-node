//! The node-identity fence for the `sql/v1/` namespace.
//!
//! One row (asserted at insert time) holds the node's 128-bit store ID in
//! hex and its creation time. The boot check pairs this with the object
//! `sql/v1/_owner/v1` so a bucket that was once owned by a different
//! control database refuses to start.
//!
//! TC-1491.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sql_store_owner")]
pub struct Model {
    /// Lowercase hex of 128 random bits (32 characters).
    #[sea_orm(primary_key, auto_increment = false)]
    pub store_id: String,
    /// RFC 3339 UTC timestamp of the first enable that wrote this row.
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

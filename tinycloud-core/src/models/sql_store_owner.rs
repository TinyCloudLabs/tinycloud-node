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
    /// Fixed singleton guard: the row has exactly one id, `1`. Taking the
    /// primary key off `store_id` and onto this column turns "there is at
    /// most one row" into a schema-enforced invariant: a concurrent first
    /// enable losing writer sees `ON CONFLICT DO NOTHING` and inserts
    /// nothing, where a `WHERE NOT EXISTS` clause would race.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: i16,
    /// Lowercase hex of 128 random bits (32 characters). Unique by virtue
    /// of the singleton row above, so no extra unique index is needed.
    pub store_id: String,
    /// RFC 3339 UTC timestamp of the first enable that wrote this row.
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

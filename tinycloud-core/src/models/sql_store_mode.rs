//! The per-database mode record of the SQL block store (TC-1491 P4.1).
//!
//! One row per SQL database says where it is mastered: `pg_master`,
//! `shadow`, `cutting_over`, `store_master`, `copying_back` or `owner_lost`
//! (design section 4, contract 4.6). An absent row means `pg_master`. The
//! transition rules are in `sql::store::mode`; nothing outside tests writes
//! or reads this table yet.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sql_store_mode")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: String,
    /// The physical artifact name, as in `sql_store_manifest`.
    #[sea_orm(primary_key, auto_increment = false)]
    pub db_id: String,
    /// One of the six `StoreMode` strings.
    pub mode: String,
    /// Bumped on every owner change; never reset.
    pub epoch: i64,
    /// The node holding the working copy (set entering `store_master`).
    pub owner_node: Option<String>,
    /// The node currently holding the lease (P4.2c).
    pub lease_holder: Option<String>,
    /// RFC 3339 end of that lease (P4.2c).
    pub lease_expires_at: Option<String>,
    /// Canonical RFC 3339 UTC time of the last transition.
    pub mode_changed_at: String,
    /// The `database_artifact.revision` a cutover froze (P4.4; audit).
    pub cutover_revision: Option<i64>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

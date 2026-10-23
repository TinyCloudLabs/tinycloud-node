//! TC-1491: the published frontier of one database's SQL store copy.
//! Advisory while Postgres is master; see `docs/sql-block-store-contract.md`.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sql_store_manifest")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: String,
    /// The physical artifact name.
    #[sea_orm(primary_key, auto_increment = false)]
    pub db_id: String,
    pub lineage: String,
    pub epoch: i64,
    /// Publication counter: +1 per publish, never reset.
    pub revision: i64,
    #[sea_orm(column_type = "Text")]
    pub base_snapshot_key: String,
    pub base_seq: i64,
    /// `database_artifact.checkpoint_content_hash` the snapshot was cut from.
    pub base_checkpoint_cid: String,
    pub last_seq: i64,
    pub publish_id: String,
    pub published_at: String,
    pub frontier_bytes: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

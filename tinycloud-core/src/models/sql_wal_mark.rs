//! A WAL mark: where the stored WAL of a database ended at one revision.
//!
//! `save_delta` writes one row per revision in the same transaction that
//! stores the WAL, so the shadow uploader can carve the bytes between two
//! revisions out of the cumulative `database_artifact.delta_payload` and
//! upload only those (`wal-delta-v1`, contract 4.5). A mark names the
//! checkpoint it belongs to; `save` (a new checkpoint truncates the WAL)
//! and a chunked snapshot delete every mark of the database.
//!
//! `wal_prefix_sha256` is the SHA-256 of the WAL bytes `[0, wal_end_bytes)`.
//! The uploader checks it while streaming: an upload-time consistency check
//! that the stored WAL still extends the one the mark was cut from. It is not
//! a security control: it lives next to the bytes it covers.
//!
//! TC-1491.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sql_wal_mark")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub service: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub name: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub revision: i64,
    /// The `database_artifact.checkpoint_content_hash` the WAL applies to.
    pub checkpoint_content_hash: String,
    /// Length of the stored WAL at this revision.
    pub wal_end_bytes: i64,
    /// Lowercase hex SHA-256 of the WAL bytes `[0, wal_end_bytes)`.
    pub wal_prefix_sha256: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

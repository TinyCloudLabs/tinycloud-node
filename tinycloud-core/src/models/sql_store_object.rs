//! TC-1491: inventory of objects uploaded to the SQL store. The object key's
//! fields are columns so the primary key stays within MySQL's index limit and
//! frontier checks are queries, not key parsing.

use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "sql_store_object")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub db_id: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub lineage: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub kind: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub base_seq: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub from_seq: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub to_seq: i64,
    #[sea_orm(primary_key, auto_increment = false)]
    pub content_hash: String,
    pub format: String,
    /// The full object key; derivable from the columns above, not indexed.
    #[sea_orm(column_type = "Text")]
    pub key: String,
    pub bytes: i64,
    pub state: String,
    pub created_at: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

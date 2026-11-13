//! Restore progress contains no reversible target or physical prefix.
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "space_purge_prefix_repair")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub repair_id: String,
    pub object_key: String,
    pub store_kind: String,
    pub prefix_hmac: String,
    pub phase: String,
    pub updated_at: OffsetDateTime,
    pub next_attempt_at: OffsetDateTime,
    pub attempt_count: i64,
    pub lease_token: Option<String>,
    pub lease_until: Option<OffsetDateTime>,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

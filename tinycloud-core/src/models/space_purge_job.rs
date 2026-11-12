use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "space_purge_job")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub purge_id: String,
    pub space: Option<String>,
    pub tombstone_hmac: Vec<u8>,
    pub hmac_key_id: String,
    pub owner_hmac: Vec<u8>,
    pub accepted_at: OffsetDateTime,
    pub phase: String,
    pub fence_generation: i64,
    pub updated_at: OffsetDateTime,
    pub next_attempt_at: OffsetDateTime,
    pub attempt_count: i64,
    pub last_error_code: Option<String>,
    pub lease_token: Option<String>,
    pub lease_until: Option<OffsetDateTime>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

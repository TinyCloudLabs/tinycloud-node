use crate::types::{Path, SpaceIdWrap};
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "kv_quarantine")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub space: SpaceIdWrap,
    #[sea_orm(primary_key)]
    pub key: Path,

    pub peer_url: String,
    pub local_invocation_id: String,
    pub peer_status: String,
    pub peer_invocation_id: Option<String>,
    pub peer_deleted_invocation_id: Option<String>,
    pub quarantined_at: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

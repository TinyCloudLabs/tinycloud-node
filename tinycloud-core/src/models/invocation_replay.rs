use sea_orm::entity::prelude::*;
use time::OffsetDateTime;

use crate::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "invocation_replay")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub content_hash: Hash,
    pub expires_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

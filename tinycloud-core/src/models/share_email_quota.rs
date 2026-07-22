use sea_orm::entity::prelude::*;
use std::fmt;

#[derive(Clone, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "share_email_quota")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub bucket_kind: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub bucket_start: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub scope_digest: String,
    pub uses: i64,
    pub expires_at: String,
}

impl fmt::Debug for Model {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShareEmailQuota { [REDACTED] }")
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

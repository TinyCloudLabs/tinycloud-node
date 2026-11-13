//! One-use review evidence; authenticated payloads contain only target HMACs.
use sea_orm::entity::prelude::*;
use time::OffsetDateTime;
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "resource_review_consumption")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub decision_id: String,
    pub purge_id: String,
    pub authenticated_body: Vec<u8>,
    pub consumed_at: OffsetDateTime,
}
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

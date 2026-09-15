use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "meeting_legacy_write_guard")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: String,
    pub frozen: bool,
    pub generation: i64,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}
impl ActiveModelBehavior for ActiveModel {}

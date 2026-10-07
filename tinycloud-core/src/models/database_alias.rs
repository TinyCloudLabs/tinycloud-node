use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "database_alias")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub service: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub space: String,
    #[sea_orm(primary_key, auto_increment = false)]
    pub logical_name: String,
    pub path: Option<String>,
    pub physical_name: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

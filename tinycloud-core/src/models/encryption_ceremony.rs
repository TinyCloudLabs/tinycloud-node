use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "encryption_ceremony")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub ceremony_id: String,
    pub network_id: String,
    pub kind: String,
    pub state: String,
    pub transcript_hash: Option<String>,
    pub started_at: String,
    pub completed_at: Option<String>,
    pub failure: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

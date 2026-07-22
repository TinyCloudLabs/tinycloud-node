use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "policy_issuance_audit")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub issuance_id: String,
    #[sea_orm(unique)]
    pub session_delegation_cid: String,
    pub audit_json: Json,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

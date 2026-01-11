use crate::hash::Hash;
use crate::models::*;
use crate::types::SpaceIdWrap;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "epoch_order")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub parent: Hash,
    #[sea_orm(primary_key)]
    pub child: Hash,
    #[sea_orm(primary_key)]
    pub space: SpaceIdWrap,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    // inverse relation, delegations belong to delegators
    #[sea_orm(
        belongs_to = "epoch::Entity",
        from = "(Column::Parent, Column::Space)",
        to = "(epoch::Column::Id, epoch::Column::Space)"
    )]
    Parent,
    #[sea_orm(
        belongs_to = "epoch::Entity",
        from = "(Column::Child, Column::Space)",
        to = "(epoch::Column::Id, epoch::Column::Space)"
    )]
    Child,
    #[sea_orm(
        belongs_to = "space::Entity",
        from = "Column::Space",
        to = "space::Column::Id"
    )]
    Space,
}

impl Related<epoch::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Parent.def()
    }
}

impl Related<space::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Space.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

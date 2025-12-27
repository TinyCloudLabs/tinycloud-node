use crate::hash::Hash;
use crate::models::*;
use crate::types::NamespaceIdWrap;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "epoch_order")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub parent: Hash,
    #[sea_orm(primary_key)]
    pub child: Hash,
    #[sea_orm(primary_key)]
    pub namespace: NamespaceIdWrap,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    // inverse relation, delegations belong to delegators
    #[sea_orm(
        belongs_to = "epoch::Entity",
        from = "(Column::Parent, Column::Namespace)",
        to = "(epoch::Column::Id, epoch::Column::Namespace)"
    )]
    Parent,
    #[sea_orm(
        belongs_to = "epoch::Entity",
        from = "(Column::Child, Column::Namespace)",
        to = "(epoch::Column::Id, epoch::Column::Namespace)"
    )]
    Child,
    #[sea_orm(
        belongs_to = "namespace::Entity",
        from = "Column::Namespace",
        to = "namespace::Column::Id"
    )]
    Namespace,
}

impl Related<epoch::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Parent.def()
    }
}

impl Related<namespace::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Namespace.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

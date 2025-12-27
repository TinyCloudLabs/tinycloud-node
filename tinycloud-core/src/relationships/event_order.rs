use super::super::models::*;
use crate::hash::Hash;
use crate::types::NamespaceIdWrap;
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, PartialOrd, Ord)]
#[sea_orm(table_name = "event_order")]
pub struct Model {
    /// Sequence number
    pub seq: i64,
    #[sea_orm(primary_key)]
    pub epoch: Hash,
    /// Sequence number of the event within the epoch
    #[sea_orm(primary_key)]
    pub epoch_seq: i64,
    pub event: Hash,

    #[sea_orm(primary_key)]
    pub namespace: NamespaceIdWrap,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "epoch::Entity",
        from = "(Column::Epoch, Column::Namespace)",
        to = "(epoch::Column::Id, epoch::Column::Namespace)"
    )]
    Epoch,
    #[sea_orm(has_many = "kv_write::Entity")]
    KvWrite,
    #[sea_orm(
        belongs_to = "namespace::Entity",
        from = "Column::Namespace",
        to = "namespace::Column::Id"
    )]
    Namespace,
}

impl Related<epoch::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Epoch.def()
    }
}

impl Related<kv_write::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::KvWrite.def()
    }
}

impl Related<namespace::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Namespace.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

use crate::hash::Hash;
use crate::models::*;
use crate::types::{Metadata, Path, SpaceIdWrap};
use sea_orm::entity::prelude::*;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "kv_canonical_commit")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub space: SpaceIdWrap,
    #[sea_orm(primary_key)]
    pub seq: i64,
    pub key: Path,
    pub invocation_id: Hash,
    pub kind: String,
    pub value: Option<String>,
    pub metadata: Option<Metadata>,
    pub deleted_invocation_id: Option<String>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "invocation::Entity",
        from = "Column::InvocationId",
        to = "invocation::Column::Id"
    )]
    Invocation,
    #[sea_orm(
        belongs_to = "space::Entity",
        from = "Column::Space",
        to = "space::Column::Id"
    )]
    Space,
}

impl Related<invocation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Invocation.def()
    }
}

impl Related<space::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Space.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

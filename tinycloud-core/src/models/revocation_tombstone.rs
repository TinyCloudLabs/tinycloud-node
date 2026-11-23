//! The memory of a revocation that records GC deleted (TC-4092).
//!
//! A space purge deletes signed records, including the `revocation` rows of
//! the delegations it deletes, because `revocation` names its revoker (an
//! actor DID) and carries the signed bytes. Once the row is gone nothing would
//! stop the same signed bytes being registered again, so purge first writes
//! one row here: the canonical content hash of the revoked delegation and the
//! times needed to prune it later. No DID, space, owner or resource is stored.
//!
//! The four columns are the whole table. A column named like a principal or a
//! space would make `space_purge_table_inventory` require a classification.

use sea_orm::{entity::prelude::*, ConnectionTrait, QuerySelect};
use time::OffsetDateTime;

use crate::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "revocation_tombstone")]
pub struct Model {
    /// Canonical content hash of the revoked delegation: every stored
    /// encoding of it resolves to the same value (`delegation_cid_alias`).
    #[sea_orm(primary_key, auto_increment = false)]
    pub delegation_canonical: Hash,
    /// The delegation's own expiry. `NULL`: never prunable.
    pub delegation_expiry: Option<OffsetDateTime>,
    /// Copied from `revocation.revoked_at`.
    pub revoked_at: Option<OffsetDateTime>,
    /// When purge wrote the tombstone.
    pub recorded_at: OffsetDateTime,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}

/// Whether any of `ids` (the signed bytes' own hash and its canonical hash)
/// has a tombstone.
pub(crate) async fn is_tombstoned<C: ConnectionTrait>(db: &C, ids: &[Hash]) -> Result<bool, DbErr> {
    Ok(Entity::find()
        .select_only()
        .column(Column::DelegationCanonical)
        .filter(Column::DelegationCanonical.is_in(ids.iter().copied()))
        .limit(1)
        .into_tuple::<Hash>()
        .one(db)
        .await?
        .is_some())
}

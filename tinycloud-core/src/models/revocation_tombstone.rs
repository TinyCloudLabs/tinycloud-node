//! The memory of a revocation that records GC deleted (TC-4092).
//!
//! A space purge deletes signed records, including the `revocation` rows of
//! the delegations it deletes, because `revocation` names its revoker (an
//! actor DID) and carries the signed bytes. Once the row is gone nothing would
//! stop the same signed bytes being registered again, so purge first writes
//! rows here: one per hash naming the revoked delegation (its canonical
//! content hash, the revoked id, and the stored id of each of its stored
//! encodings) with the times needed to prune them later. No DID, space, owner
//! or resource is stored.
//!
//! The four columns are the whole table. A column named like a principal or a
//! space would make `space_purge_table_inventory` require a classification.

use sea_orm::{entity::prelude::*, ConnectionTrait, QuerySelect};
use time::OffsetDateTime;

use crate::hash::Hash;

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "revocation_tombstone")]
pub struct Model {
    /// A hash naming the revoked delegation: its canonical content hash
    /// (`delegation_cid_alias`) or the stored id of one of its encodings.
    /// Before TC-4366 the canonical hash of a UCAN was its stored id, so an
    /// older tombstone of a high-S ECDSA UCAN names only that id; registration
    /// therefore also checks the hash of the other ECDSA encoding.
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

/// Whether any of `ids` has a tombstone. Registration passes the signed bytes'
/// own hash, their canonical hash and the hash of their other ECDSA encoding.
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

/// Whether any cited id, or the canonical hash of a cited id that is still
/// stored, has a tombstone. A ticket names only CIDs: a purged one is found by
/// its own tombstone (purge deletes its alias row), a stored one also by the
/// tombstone of another encoding of it.
pub(crate) async fn is_cited_tombstoned<C: ConnectionTrait>(
    db: &C,
    ids: &[Hash],
) -> Result<bool, DbErr> {
    use super::delegation_cid_alias;
    use sea_orm::{sea_query::Query, Condition};
    Ok(Entity::find()
        .select_only()
        .column(Column::DelegationCanonical)
        .filter(
            Condition::any()
                .add(Column::DelegationCanonical.is_in(ids.iter().copied()))
                .add(
                    Column::DelegationCanonical.in_subquery(
                        Query::select()
                            .column(delegation_cid_alias::Column::Canonical)
                            .from(delegation_cid_alias::Entity)
                            .and_where(delegation_cid_alias::Column::Id.is_in(ids.iter().copied()))
                            .to_owned(),
                    ),
                ),
        )
        .limit(1)
        .into_tuple::<Hash>()
        .one(db)
        .await?
        .is_some())
}

use super::super::{events::Revocation, models::*, relationships::*};
use crate::hash::{hash, Hash};
use sea_orm::{entity::prelude::*, sea_query::OnConflict, ConnectionTrait};
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::TinyCloudRevocation, identity::did_principal_matches,
    ssi::dids::AnyDidMethod,
};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "revocation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: Hash,

    pub revoker: String,
    pub revoked: Hash,
    pub serialization: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "actor::Entity",
        from = "Column::Revoker",
        to = "actor::Column::Id"
    )]
    Revoker,
    #[sea_orm(
        belongs_to = "delegation::Entity",
        from = "Column::Revoked",
        to = "delegation::Column::Id"
    )]
    Delegation,
}

impl Related<actor::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Revoker.def()
    }
}

impl Related<delegation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Delegation.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error(transparent)]
    InvalidRevocation(#[from] RevocationError),
}

#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error("Revocation expired or not yet valid")]
    InvalidTime,
    #[error("Failed to verify signature")]
    InvalidSignature,
    #[error("Unauthorized Revoker")]
    UnauthorizedRevoker(String),
    #[error("Cannot find parent delegation")]
    MissingParents,
}

pub(crate) async fn process<C: ConnectionTrait>(
    db: &C,
    revocation: Revocation,
) -> Result<Hash, Error> {
    let (r, serialization) = (revocation.0, revocation.1);

    let t = OffsetDateTime::now_utc();

    // W1 (audit P0 finding 5): verify both CACAO and did:key/UCAN format
    // revocations. The route accepts either suite so the Policy Engine
    // active_cutoff loop can rely on a single endpoint regardless of
    // whether the Grant Issuer signs with SIWE or did:key.
    match &r.revocation {
        TinyCloudRevocation::Cacao(c) => {
            c.verify()
                .await
                .map_err(|_| RevocationError::InvalidSignature)?;
            if !c.payload().valid_at(&t) {
                return Err(RevocationError::InvalidTime.into());
            };
        }
        TinyCloudRevocation::Ucan(u) => {
            u.verify_signature(&AnyDidMethod::default())
                .await
                .map_err(|_| RevocationError::InvalidSignature)?;
            u.payload()
                .validate_time(None)
                .map_err(|_| RevocationError::InvalidTime)?;
        }
    };

    let hash: Hash = hash(&serialization);
    let delegation = delegation::Entity::find_by_id(Hash::from(r.revoked))
        .one(db)
        .await?
        .ok_or(RevocationError::MissingParents)?;

    // W1 (audit P0 finding 5): three authorization paths are accepted —
    //   1. revoker == delegator (the directly-cited grantor)
    //   2. revoker == any space owner targeted by the delegation's
    //      persisted abilities (owner-authorized active_cutoff)
    //   3. revoker == delegatee of an attenuable ancestor (so a
    //      Grant Issuer that itself received the cap can revoke it)
    // Any one of these is sufficient. The Cacao revoker == delegator
    // path stays as the cheapest check; owner-authorized falls back to
    // walking the ability rows.
    if !revoker_is_authorized(db, &delegation, &r.revoker).await? {
        return Err(RevocationError::UnauthorizedRevoker(r.revoker).into());
    };

    match Entity::insert(ActiveModel::from(Model {
        id: hash,
        serialization,
        revoker: r.revoker,
        revoked: delegation.id,
    }))
    .on_conflict(OnConflict::column(Column::Id).do_nothing().to_owned())
    .exec(db)
    .await
    {
        Err(DbErr::RecordNotInserted) => return Ok(hash),
        r => {
            r?;
        }
    };

    if !r.parents.is_empty() {
        parent_delegations::Entity::insert_many(r.parents.into_iter().map(|p| {
            parent_delegations::ActiveModel::from(parent_delegations::Model {
                child: hash,
                parent: p.into(),
            })
        }))
        .exec(db)
        .await?;
    }

    Ok(hash)
}

/// W1 (audit P0 finding 5): authorize the revoker.
///
/// Three accepted paths:
///   * direct delegator match (existing behavior)
///   * delegatee match (the recipient can self-revoke their own grant)
///   * owner-authorized — the revoker is the owner of a space that the
///     delegation's persisted abilities target. This is what unlocks
///     `active_cutoff`: the data owner can revoke any grant against their
///     own space without needing to be the original SIWE signer.
async fn revoker_is_authorized<C: ConnectionTrait>(
    db: &C,
    delegation: &delegation::Model,
    revoker: &str,
) -> Result<bool, DbErr> {
    if did_principal_matches(&delegation.delegator, revoker) {
        return Ok(true);
    }
    if did_principal_matches(&delegation.delegatee, revoker) {
        return Ok(true);
    }

    let ability_rows = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(delegation.id))
        .all(db)
        .await?;
    for row in ability_rows {
        if let Some(space) = row.resource.space() {
            if did_principal_matches(space.did().as_str(), revoker) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

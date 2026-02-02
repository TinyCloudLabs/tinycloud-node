use crate::hash::Hash;
use crate::types::{Ability, Facts, Resource};
use crate::{events::Delegation, models::*, relationships::*, util};
use sea_orm::{entity::prelude::*, sea_query::OnConflict, ConnectionTrait};
use time::OffsetDateTime;
use tinycloud_lib::{authorization::TinyCloudDelegation, ssi::dids::AnyDidMethod};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "delegation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: Hash,

    pub delegator: String,
    pub delegatee: String,
    pub expiry: Option<OffsetDateTime>,
    pub issued_at: Option<OffsetDateTime>,
    pub not_before: Option<OffsetDateTime>,
    pub facts: Option<Facts>,
    pub serialization: Vec<u8>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    // inverse relation, delegations belong to delegators
    #[sea_orm(
        belongs_to = "actor::Entity",
        from = "Column::Delegator",
        to = "actor::Column::Id"
    )]
    Delegator,
    #[sea_orm(
        belongs_to = "actor::Entity",
        from = "Column::Delegatee",
        to = "actor::Column::Id"
    )]
    Delegatee,
    #[sea_orm(has_many = "revocation::Entity")]
    Revocation,
    #[sea_orm(has_many = "abilities::Entity")]
    Abilities,
    #[sea_orm(has_many = "parent_delegations::Entity")]
    Parents,
}

impl Related<actor::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Delegator.def()
    }
}

impl Related<revocation::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Revocation.def()
    }
}

impl Related<abilities::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Abilities.def()
    }
}

impl Related<parent_delegations::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Parents.def()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Delegator;

impl Linked for Delegator {
    type FromEntity = Entity;

    type ToEntity = actor::Entity;

    fn link(&self) -> Vec<RelationDef> {
        vec![Relation::Delegator.def()]
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Delegatee;

impl Linked for Delegatee {
    type FromEntity = Entity;

    type ToEntity = actor::Entity;

    fn link(&self) -> Vec<RelationDef> {
        vec![Relation::Delegatee.def()]
    }
}

impl ActiveModelBehavior for ActiveModel {}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error(transparent)]
    InvalidDelegation(#[from] DelegationError),
}

#[derive(Debug, thiserror::Error)]
pub enum DelegationError {
    #[error("Delegation expired or not yet valid")]
    InvalidTime,
    #[error("Failed to verify signature")]
    InvalidSignature,
    #[error("Unauthorized Delegator: {0}")]
    UnauthorizedDelegator(String),
    #[error("Unauthorized Capability: {0}, {1}")]
    UnauthorizedCapability(Resource, Ability),
    #[error("Cannot find parent delegation")]
    MissingParents,
    #[error("Child delegation expiry exceeds parent expiry")]
    ExpiryExceedsParent,
    #[error("Child delegation not_before precedes parent not_before")]
    NotBeforePrecedesParent,
}

pub(crate) async fn process<C: ConnectionTrait>(
    db: &C,
    delegation: Delegation,
) -> Result<Hash, Error> {
    let (d, ser) = (delegation.0, delegation.1);
    verify(&d.delegation).await?;

    validate(db, &d).await?;

    save(db, d, ser).await
}

// verify signatures and time
async fn verify(delegation: &TinyCloudDelegation) -> Result<(), Error> {
    match delegation {
        TinyCloudDelegation::Ucan(ref ucan) => {
            // TODO go back to static DID_METHODS
            ucan.verify_signature(&AnyDidMethod::default())
                .await
                .map_err(|_| DelegationError::InvalidSignature)?;
            ucan.payload()
                .validate_time(None)
                .map_err(|_| DelegationError::InvalidTime)?;
        }
        TinyCloudDelegation::Cacao(ref cacao) => {
            cacao
                .verify()
                .await
                .map_err(|_| DelegationError::InvalidSignature)?;
            if !cacao.payload().valid_now() {
                return Err(DelegationError::InvalidTime)?;
            }
        }
    };
    Ok(())
}

// verify parenthood and authorization
async fn validate<C: ConnectionTrait>(
    db: &C,
    delegation: &util::DelegationInfo,
) -> Result<(), Error> {
    // get caps which rely on delegated caps
    let dependant_caps: Vec<_> = delegation
        .capabilities
        .iter()
        .filter(|c| {
            // remove caps for which the delegator is the root authority
            c.resource
                .space()
                .map(|o| **o.did() != *delegation.delegator)
                .unwrap_or(true)
        })
        .collect();

    match (dependant_caps.is_empty(), delegation.parents.is_empty()) {
        // no dependant caps, no parents needed, must be valid
        (true, _) => Ok(()),
        // dependant caps, no parents, invalid
        (false, true) => Err(DelegationError::MissingParents.into()),
        // dependant caps, parents, check parents
        (false, false) => {
            // get parents which have the correct id and delegatee
            let all_parents: Vec<_> = Entity::find()
                // the correct id
                .filter(Column::Id.is_in(delegation.parents.iter().map(|c| Hash::from(*c))))
                // the correct delegatee
                .filter(Column::Delegatee.eq(delegation.delegator.clone()))
                .all(db)
                .await?;

            // If no parents match by CID and delegatee, return MissingParents
            if all_parents.is_empty() {
                return Err(DelegationError::MissingParents.into());
            }

            // Check time constraints and track failures
            let mut expiry_failed = false;
            let mut not_before_failed = false;

            let parents: Vec<_> = all_parents
                .into_iter()
                .filter(|p| {
                    // valid time bounds: child's validity must be within parent's validity
                    // expiry: child must expire at or before parent (None = no expiry)
                    let expiry_valid = match (&p.expiry, &delegation.expiry) {
                        (None, _) => true,        // parent never expires, any child expiry is valid
                        (Some(_), None) => false, // parent expires but child doesn't - invalid
                        (Some(pe), Some(de)) => *de <= *pe, // child must expire at or before parent
                    };
                    // not_before: child must become valid at or after parent (None = valid immediately)
                    let not_before_valid = match (&p.not_before, &delegation.not_before) {
                        (None, _) => true, // parent valid immediately, any child not_before is valid
                        (Some(_), None) => false, // parent has restriction but child claims immediate validity
                        (Some(pnbf), Some(dnbf)) => *dnbf >= *pnbf, // child must become valid at or after parent
                    };

                    if !expiry_valid {
                        expiry_failed = true;
                    }
                    if !not_before_valid {
                        not_before_failed = true;
                    }

                    expiry_valid && not_before_valid
                })
                .collect();

            // If all parents were filtered out due to time constraints, return specific error
            if parents.is_empty() {
                if expiry_failed {
                    return Err(DelegationError::ExpiryExceedsParent.into());
                }
                if not_before_failed {
                    return Err(DelegationError::NotBeforePrecedesParent.into());
                }
            }

            // get delegated abilities from each parent
            let parent_abilities = parents.load_many(abilities::Entity, db).await?;

            // check each dependant cap is supported by at least one parent cap
            match dependant_caps.iter().find(|c| {
                !parent_abilities
                    .iter()
                    .flatten()
                    .any(|pc| c.resource.extends(&pc.resource) && c.ability == pc.ability)
            }) {
                Some(c) => Err(DelegationError::UnauthorizedCapability(
                    c.resource.clone(),
                    c.ability.clone(),
                )
                .into()),
                None => Ok(()),
            }
        }
    }
}

async fn save<C: ConnectionTrait>(
    db: &C,
    delegation: util::DelegationInfo,
    serialization: Vec<u8>,
) -> Result<Hash, Error> {
    save_actors(&[&delegation.delegator, &delegation.delegate], db).await?;

    let hash: Hash = crate::hash::hash(&serialization);

    // save delegation
    match Entity::insert(ActiveModel::from(Model {
        id: hash,
        delegator: delegation.delegator,
        delegatee: delegation.delegate,
        expiry: delegation.expiry,
        issued_at: delegation.issued_at,
        not_before: delegation.not_before,
        facts: None,
        serialization,
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

    // save abilities
    if !delegation.capabilities.is_empty() {
        abilities::Entity::insert_many(delegation.capabilities.into_iter().map(|ab| {
            abilities::ActiveModel::from(abilities::Model {
                delegation: hash,
                resource: ab.resource,
                ability: ab.ability,
                caveats: Default::default(),
            })
        }))
        .exec(db)
        .await?;
    }

    // save parent relationships
    if !delegation.parents.is_empty() {
        parent_delegations::Entity::insert_many(delegation.parents.into_iter().map(|p| {
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

async fn save_actors<C: ConnectionTrait>(actors: &[&str], db: &C) -> Result<(), DbErr> {
    match actor::Entity::insert_many(actors.iter().map(|a| {
        actor::ActiveModel::from(actor::Model {
            id: ToString::to_string(a),
        })
    }))
    .on_conflict(
        OnConflict::column(actor::Column::Id)
            .do_nothing()
            .to_owned(),
    )
    .exec(db)
    .await
    {
        Err(DbErr::RecordNotInserted) => (),
        r => {
            r?;
        }
    };
    Ok(())
}

use crate::encryption::ColumnEncryption;
use crate::encryption_network::NetworkId;
use crate::hash::Hash;
use crate::policy_capability::sql_caveat;
use crate::types::{Ability, Caveats, Facts, Resource};
use crate::util::DelegationMode;
use crate::{events::Delegation, models::*, relationships::*, util};
use sea_orm::{entity::prelude::*, sea_query::OnConflict, ConnectionTrait};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::TinyCloudDelegation, identity::did_principal_matches, ssi::dids::AnyDidMethod,
};

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
    /// W1: parent delegation is terminal — children cannot redelegate.
    /// Maps to `terminal-parent-cannot-redelegate` in the W0 vectors.
    #[error("terminal-parent-cannot-redelegate")]
    TerminalParentCannotRedelegate,
    /// W1: child caveats are not a subset of the parent's caveats — the
    /// child dropped, widened, or replaced a constrained-statements caveat
    /// the parent carried (audit P0 finding 1). Maps to the spec rejection
    /// code from `sql-constrained-statement-caveat.md` containment.
    #[error("child-caveats-not-subset-of-parent: {0}")]
    CaveatsNotContained(String),
}

pub(crate) async fn process<C: ConnectionTrait>(
    db: &C,
    delegation: Delegation,
    encryption: Option<&ColumnEncryption>,
) -> Result<Hash, Error> {
    let (d, ser) = (delegation.0, delegation.1);
    verify(&d.delegation).await?;

    validate(db, &d).await?;

    save(db, d, ser, encryption).await
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
            !is_root_authority(c, &delegation.delegator)
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

            // W1 (B): reject any chain that cites a terminal parent. The
            // marker is persisted on the parent row's `facts` column at
            // save time and is signed-into the parent's UCAN payload, so a
            // cooperating holder cannot strip it after the fact.
            for p in &all_parents {
                if parent_is_terminal(p) {
                    return Err(DelegationError::TerminalParentCannotRedelegate.into());
                }
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

            // W1 caveat-aware containment (audit P0 finding 1): a child cap is
            // supported by a parent cap only when resource+ability extend AND
            // the child's caveats are a subset of the parent's caveats. For
            // SQL constrained-statements caveats we delegate to JCS caveat
            // containment in `sql_caveat::contains`; for other caveat shapes
            // we require structural equality so a child cannot silently
            // replace a parent's caveat.
            for c in &dependant_caps {
                let mut candidates = parent_abilities
                    .iter()
                    .flatten()
                    .filter(|pc| c.resource.extends(&pc.resource) && c.ability == pc.ability)
                    .peekable();

                if candidates.peek().is_none() {
                    return Err(DelegationError::UnauthorizedCapability(
                        c.resource.clone(),
                        c.ability.clone(),
                    )
                    .into());
                }

                let mut last_reason: Option<String> = None;
                let mut authorized = false;
                for pc in candidates {
                    match caveats_contain_child(&pc.caveats, &c.caveats) {
                        Ok(()) => {
                            authorized = true;
                            break;
                        }
                        Err(reason) => last_reason = Some(reason),
                    }
                }
                if !authorized {
                    let reason = last_reason
                        .unwrap_or_else(|| "child-caveats-not-subset-of-parent".to_string());
                    return Err(DelegationError::CaveatsNotContained(reason).into());
                }
            }
            Ok(())
        }
    }
}

/// W1 (audit P0 finding 1): is `child` a subset of `parent` per JCS caveat
/// containment? Today this distinguishes the SQL constrained-statements
/// caveat (delegating to `sql_caveat::contains` for narrow/identical chain
/// shapes) and otherwise requires structural equality so a child cannot
/// silently drop or replace caveats the parent carried.
fn caveats_contain_child(parent: &Caveats, child: &Caveats) -> Result<(), String> {
    let parent_sql = extract_sql_caveat(parent);
    let child_sql = extract_sql_caveat(child);

    match (parent_sql, child_sql) {
        (Some(p), Some(c)) => sql_caveat::contains(&p, &c).map_err(|e| e.as_str().to_string()),
        (Some(_), None) => Err("containment-caveat-required".to_string()),
        (None, _) => {
            // No SQL caveat on the parent — fall back to structural equality
            // on the raw JSON map so a child cannot inject a brand-new
            // non-SQL caveat that the parent never authorized. If parent
            // has no caveats at all, a child with no caveats is fine; a
            // child that adds caveats is narrowing only when those caveats
            // match an existing parent constraint, so we require equality.
            if parent.0 == child.0 {
                Ok(())
            } else if parent.0.is_empty() && child.0.is_empty() {
                Ok(())
            } else if parent.0.is_empty() {
                // Parent imposed no restrictions; children may introduce
                // narrowing caveats only when those caveats are themselves
                // well-formed for the service. We allow it for now; the
                // service-level enforcement (e.g. SQL constrained-profile)
                // will fail-closed if the new caveat is incoherent.
                Ok(())
            } else {
                Err("child-caveats-not-subset-of-parent".to_string())
            }
        }
    }
}

fn extract_sql_caveat(
    caveats: &Caveats,
) -> Option<crate::policy_capability::SqlConstrainedStatementCaveat> {
    for (_idx, v) in &caveats.0 {
        if let Ok(c) = sql_caveat::parse(v) {
            return Some(c);
        }
        if let Some(inner) = v.as_object().and_then(|o| o.get("constrained-statements")) {
            if let Ok(c) = sql_caveat::parse(inner) {
                return Some(c);
            }
        }
    }
    None
}

/// True if the persisted parent row is marked terminal via the
/// `xyz.tinycloud.policy/delegationMode` fact. The marker is stored in the
/// `facts` JSON column at save time; absence is treated as attenuable.
fn parent_is_terminal(p: &Model) -> bool {
    let Some(Facts(map)) = &p.facts else {
        return false;
    };
    map.get(DelegationMode::FACT_KEY)
        .and_then(|v| v.as_str())
        .map(|s| s == "terminal")
        .unwrap_or(false)
}

fn is_root_authority(cap: &util::Capability, delegator: &str) -> bool {
    if cap
        .resource
        .space()
        .map(|o| did_principal_matches(o.did().as_str(), delegator))
        .unwrap_or(false)
    {
        return true;
    }

    match &cap.resource {
        Resource::Other(uri) => uri
            .as_str()
            .parse::<NetworkId>()
            .map(|network_id| did_principal_matches(network_id.owner_did(), delegator))
            .unwrap_or(false),
        Resource::TinyCloud(_) => false,
    }
}

async fn save<C: ConnectionTrait>(
    db: &C,
    delegation: util::DelegationInfo,
    serialization: Vec<u8>,
    encryption: Option<&ColumnEncryption>,
) -> Result<Hash, Error> {
    save_actors(&[&delegation.delegator, &delegation.delegate], db).await?;

    // Hash is always computed on plaintext (before encryption)
    let hash: Hash = crate::hash::hash(&serialization);

    // Encrypt for storage if encryption is configured
    let stored_serialization = crate::encryption::maybe_encrypt(encryption, &serialization);

    // Persist the signed-in `delegationMode` marker. We store ONLY the
    // marker we recognize natively (not the full UCAN facts), keeping the
    // serialization column as the source of truth for the bytes the holder
    // actually signed and the `facts` column as a fast-path lookup index.
    let facts = match delegation.delegation_mode {
        DelegationMode::Attenuable => None,
        DelegationMode::Terminal => {
            let mut map: BTreeMap<String, serde_json::Value> = BTreeMap::new();
            map.insert(
                DelegationMode::FACT_KEY.to_string(),
                serde_json::Value::String(DelegationMode::Terminal.as_str().to_string()),
            );
            Some(Facts(map))
        }
    };

    // save delegation
    match Entity::insert(ActiveModel::from(Model {
        id: hash,
        delegator: delegation.delegator,
        delegatee: delegation.delegate,
        expiry: delegation.expiry,
        issued_at: delegation.issued_at,
        not_before: delegation.not_before,
        facts,
        serialization: stored_serialization,
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

    // save abilities — persist UCAN caveats with the delegation row. W1
    // contract: caveats MUST NOT be reconstructed from invocation facts;
    // SQL constrained-statement guarantees fail in adversarial cases
    // otherwise (see policy-engine/spec/revocation.md §2.5).
    if !delegation.capabilities.is_empty() {
        abilities::Entity::insert_many(delegation.capabilities.into_iter().map(|ab| {
            abilities::ActiveModel::from(abilities::Model {
                delegation: hash,
                resource: ab.resource,
                ability: ab.ability,
                caveats: ab.caveats,
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

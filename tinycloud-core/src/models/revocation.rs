use super::super::{events::Revocation, models::*, relationships::*};
use crate::hash::{hash, Hash};
use crate::models::did_resolution::did_resolution_timeout;
use crate::types::Resource;
use sea_orm::{entity::prelude::*, sea_query::OnConflict, ConnectionTrait, QuerySelect};
use std::collections::HashSet;
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{Cid, TinyCloudRevocation},
    identity::did_principal_matches,
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

/// Maximum number of distinct delegation nodes examined while validating a
/// proof chain. This bounds database work for deep and wide proof DAGs.
pub const MAX_CHAIN_TRAVERSAL_NODES: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ChainTraversalError {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error("delegation-chain-traversal-limit-exceeded")]
    LimitExceeded,
}

pub(crate) async fn is_revoked<C: ConnectionTrait>(
    db: &C,
    delegation_id: &Hash,
) -> Result<bool, DbErr> {
    Ok(Entity::find()
        .filter(Column::Revoked.eq(*delegation_id))
        .count(db)
        .await?
        > 0)
}

pub(crate) async fn first_revoked_ancestor<C: ConnectionTrait>(
    db: &C,
    start: &Hash,
) -> Result<Option<String>, ChainTraversalError> {
    for ancestor in ancestor_chain_ids(db, start).await?.into_iter().skip(1) {
        if is_revoked(db, &ancestor).await? {
            return Ok(Some(ancestor.to_cid(0x55).to_string()));
        }
    }
    Ok(None)
}

pub(crate) async fn ancestor_chain_ids<C: ConnectionTrait>(
    db: &C,
    start: &Hash,
) -> Result<Vec<Hash>, ChainTraversalError> {
    ancestor_chain_ids_for_roots(db, &[*start]).await
}

pub(crate) async fn ancestor_chain_ids_for_roots<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
) -> Result<Vec<Hash>, ChainTraversalError> {
    let mut frontier = roots.to_vec();
    frontier.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
    frontier.dedup();
    if frontier.len() > MAX_CHAIN_TRAVERSAL_NODES {
        return Err(ChainTraversalError::LimitExceeded);
    }
    let mut visited = HashSet::new();
    let mut ordered = Vec::new();
    while let Some(current) = frontier.pop() {
        if !visited.insert(current) {
            continue;
        }
        if visited.len() > MAX_CHAIN_TRAVERSAL_NODES {
            return Err(ChainTraversalError::LimitExceeded);
        }
        let remaining = MAX_CHAIN_TRAVERSAL_NODES - visited.len();
        ordered.push(current);
        let parents = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(current))
            .limit((remaining + 1) as u64)
            .all(db)
            .await?;
        for link in parents {
            if !visited.contains(&link.parent) && !frontier.contains(&link.parent) {
                if visited.len() + frontier.len() >= MAX_CHAIN_TRAVERSAL_NODES {
                    return Err(ChainTraversalError::LimitExceeded);
                }
                frontier.push(link.parent);
            }
        }
    }
    Ok(ordered)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlProofDecision {
    DirectSigner(String),
    PersistentPrincipal(String),
    Denied,
}

/// Resolve the principal authorized for a control action. Proofless requests
/// stay direct-signer-only. A proof-bearing request must cite exactly one
/// current, unrevoked session/control delegation whose persisted abilities
/// explicitly include the requested action; invalid proofs never fall back.
pub(crate) async fn control_proof_decision<C: ConnectionTrait>(
    db: &C,
    signer: &str,
    proofs: &[Cid],
    requested_action: &str,
    target: &Hash,
) -> Result<ControlProofDecision, DbErr> {
    if proofs.is_empty() {
        return Ok(ControlProofDecision::DirectSigner(signer.to_string()));
    }
    if proofs.len() != 1 {
        return Ok(ControlProofDecision::Denied);
    }

    let now = OffsetDateTime::now_utc();
    let proof_id = Hash::from(proofs[0]);
    let Some(parent) = delegation::Entity::find_by_id(proof_id).one(db).await? else {
        return Ok(ControlProofDecision::Denied);
    };
    if !did_principal_matches(&parent.delegatee, signer)
        || parent.expiry.map(|expiry| now >= expiry).unwrap_or(false)
        || parent
            .not_before
            .map(|not_before| now < not_before)
            .unwrap_or(false)
    {
        return Ok(ControlProofDecision::Denied);
    }

    let chain_nodes = match ancestor_chain_ids(db, &proof_id).await {
        Ok(nodes) => nodes,
        Err(ChainTraversalError::Db(error)) => return Err(error),
        Err(ChainTraversalError::LimitExceeded) => return Ok(ControlProofDecision::Denied),
    };
    for node in chain_nodes {
        if is_revoked(db, &node).await? {
            return Ok(ControlProofDecision::Denied);
        }
    }

    let control_abilities = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(proof_id))
        .filter(abilities::Column::Ability.eq(requested_action))
        .all(db)
        .await?;
    let target_resource = format!("urn:cid:{}", target.to_cid(0x55));
    let has_control_ability = control_abilities
        .iter()
        .any(|ability| match &ability.resource {
            Resource::Other(resource) => resource.as_str() == target_resource,
            Resource::TinyCloud(resource) => {
                resource.service().as_str() == "delegation"
                    && resource
                        .path()
                        .map(|path| path.as_str().is_empty())
                        .unwrap_or(true)
                    && resource.query().is_none()
                    && resource.fragment().is_none()
                    && resource.space().did().as_str() == parent.delegator
            }
        });
    if !has_control_ability {
        return Ok(ControlProofDecision::Denied);
    }
    Ok(ControlProofDecision::PersistentPrincipal(parent.delegator))
}

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
            tokio::time::timeout(
                did_resolution_timeout(),
                u.verify_signature(&AnyDidMethod::default()),
            )
            .await
            .map_err(|_| RevocationError::InvalidSignature)?
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
    if !revoker_is_authorized(db, &delegation, &r.revoker, &r.parents).await? {
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
    proofs: &[Cid],
) -> Result<bool, DbErr> {
    let principal = match control_proof_decision(
        db,
        revoker,
        proofs,
        "tinycloud.delegation/revoke",
        &delegation.id,
    )
    .await?
    {
        ControlProofDecision::DirectSigner(principal)
        | ControlProofDecision::PersistentPrincipal(principal) => principal,
        ControlProofDecision::Denied => return Ok(false),
    };
    if did_principal_matches(&delegation.delegator, &principal) {
        return Ok(true);
    }
    if did_principal_matches(&delegation.delegatee, &principal) {
        return Ok(true);
    }

    let ability_rows = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(delegation.id))
        .all(db)
        .await?;
    for row in ability_rows {
        if let Some(space) = row.resource.space() {
            if did_principal_matches(space.did().as_str(), &principal) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database};
    use sea_orm_migration::MigratorTrait;

    async fn database() -> sea_orm::DbConn {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        actor::ActiveModel {
            id: Set("did:key:actor".to_string()),
        }
        .insert(&db)
        .await
        .unwrap();
        db
    }

    async fn insert_delegation(db: &sea_orm::DbConn, id: Hash) {
        delegation::ActiveModel {
            id: Set(id),
            delegator: Set("did:key:actor".to_string()),
            delegatee: Set("did:key:actor".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(id.as_ref().to_vec()),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn insert_link(db: &sea_orm::DbConn, child: Hash, parent: Hash) {
        parent_delegations::ActiveModel {
            parent: Set(parent),
            child: Set(child),
        }
        .insert(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn deep_chain_fails_closed_at_traversal_limit() {
        let db = database().await;
        let ids: Vec<_> = (0..=MAX_CHAIN_TRAVERSAL_NODES)
            .map(|index| hash(format!("deep-{index}").as_bytes()))
            .collect();
        for id in &ids {
            insert_delegation(&db, *id).await;
        }
        for pair in ids.windows(2) {
            insert_link(&db, pair[0], pair[1]).await;
        }

        assert!(matches!(
            first_revoked_ancestor(&db, &ids[0]).await,
            Err(ChainTraversalError::LimitExceeded)
        ));
    }

    #[tokio::test]
    async fn wide_proof_dag_fails_closed_at_traversal_limit() {
        let db = database().await;
        let child = hash(b"wide-child");
        insert_delegation(&db, child).await;
        for index in 0..MAX_CHAIN_TRAVERSAL_NODES {
            let parent = hash(format!("wide-parent-{index}").as_bytes());
            insert_delegation(&db, parent).await;
            insert_link(&db, child, parent).await;
        }

        assert!(matches!(
            first_revoked_ancestor(&db, &child).await,
            Err(ChainTraversalError::LimitExceeded)
        ));
    }

    #[tokio::test]
    async fn multiple_roots_share_one_combined_traversal_budget() {
        let db = database().await;
        let mut roots = Vec::new();
        for index in 0..33 {
            let root = hash(format!("multi-root-{index}").as_bytes());
            let parent = hash(format!("multi-parent-{index}").as_bytes());
            insert_delegation(&db, root).await;
            insert_delegation(&db, parent).await;
            insert_link(&db, root, parent).await;
            roots.push(root);
        }

        assert!(matches!(
            ancestor_chain_ids_for_roots(&db, &roots).await,
            Err(ChainTraversalError::LimitExceeded)
        ));
    }

    #[tokio::test]
    async fn cyclic_proof_graph_terminates_without_amplification() {
        let db = database().await;
        let first = hash(b"cycle-first");
        let second = hash(b"cycle-second");
        insert_delegation(&db, first).await;
        insert_delegation(&db, second).await;
        insert_link(&db, first, second).await;
        insert_link(&db, second, first).await;

        assert_eq!(first_revoked_ancestor(&db, &first).await.unwrap(), None);
    }
}

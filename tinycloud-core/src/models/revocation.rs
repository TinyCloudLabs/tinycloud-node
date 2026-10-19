use super::super::{events::Revocation, models::*, relationships::*};
use crate::encryption_network::NetworkId;
use crate::hash::{hash, Hash};
use crate::models::did_resolution::{verify_ucan_signature, UcanVerifyError};
use crate::types::Resource;
use sea_orm::Condition;
use sea_orm::{
    entity::prelude::*,
    sea_query::{Alias, Expr, JoinType, OnConflict, Query, SimpleExpr, UnionType},
    ConnectionTrait, FromQueryResult, QueryOrder, QuerySelect,
};
use std::collections::HashSet;
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{Cid, TinyCloudRevocation},
    identity::did_principal_matches,
    resource::SpaceId,
};

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "revocation")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false, unique)]
    pub id: Hash,

    pub revoker: String,
    pub revoked: Hash,
    pub serialization: Vec<u8>,
    pub revoked_at: Option<OffsetDateTime>,
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

const PARENT_DELEGATION_PAGE_SIZE: usize = MAX_CHAIN_TRAVERSAL_NODES + 1;

#[derive(Debug, thiserror::Error)]
pub enum ChainTraversalError {
    #[error(transparent)]
    Db(#[from] DbErr),
    #[error("delegation-chain-traversal-limit-exceeded")]
    LimitExceeded,
}

/// Resolve revocation targets through the persisted canonical identity. The
/// exact-target branch also handles graph rows created directly by unit tests.
fn target_condition(id: SimpleExpr) -> Condition {
    use delegation_cid_alias::{Column as AliasColumn, Entity as AliasEntity};
    let canonical = Query::select()
        .column(AliasColumn::Canonical)
        .from(AliasEntity)
        .and_where(Expr::col(AliasColumn::Id).eq(id.clone()))
        .to_owned();
    let equivalents = Query::select()
        .column(AliasColumn::Id)
        .from(AliasEntity)
        .and_where(Expr::col(AliasColumn::Canonical).in_subquery(canonical))
        .to_owned();
    Condition::any()
        .add(Expr::col((Entity, Column::Revoked)).eq(id))
        .add(Expr::col((Entity, Column::Revoked)).in_subquery(equivalents))
}

/// Correlated, indexed revocation exclusion for legacy delegation listings.
pub(crate) fn unrevoked_condition() -> SimpleExpr {
    Expr::exists(
        Query::select()
            .expr(Expr::value(1))
            .from(Entity)
            .cond_where(target_condition(
                Expr::col((delegation::Entity, delegation::Column::Id)).into(),
            ))
            .to_owned(),
    )
    .not()
}

/// Load effective revocations in one indexed batch while keeping the original
/// signed revocation target and bytes intact. The returned key is the queried
/// delegation, not necessarily the CID the owner named in the revocation.
pub(crate) async fn effective_rows<C: ConnectionTrait>(
    db: &C,
    ids: &[Hash],
) -> Result<Vec<(Hash, Model)>, DbErr> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    use delegation_cid_alias::{Column as AliasColumn, Entity as AliasEntity};
    let source = Alias::new("revocation_source_alias");
    let target = Alias::new("revocation_target_alias");
    let effective_id = Alias::new("effective_id");
    let columns = [
        Column::Id,
        Column::Revoker,
        Column::Revoked,
        Column::Serialization,
        Column::RevokedAt,
    ];
    let mut direct = Query::select();
    direct
        .columns(columns.map(|column| (Entity, column)))
        .expr_as(Expr::col((Entity, Column::Revoked)), effective_id.clone())
        .from(Entity)
        .and_where(Expr::col((Entity, Column::Revoked)).is_in(ids.iter().copied()));
    let mut aliased = Query::select();
    aliased
        .columns(columns.map(|column| (Entity, column)))
        .expr_as(Expr::col((source.clone(), AliasColumn::Id)), effective_id)
        .from_as(AliasEntity, source.clone())
        .join_as(
            JoinType::InnerJoin,
            AliasEntity,
            target.clone(),
            Expr::col((source.clone(), AliasColumn::Canonical))
                .equals((target.clone(), AliasColumn::Canonical)),
        )
        .join(
            JoinType::InnerJoin,
            Entity,
            Expr::col((target, AliasColumn::Id)).equals((Entity, Column::Revoked)),
        )
        .and_where(Expr::col((source, AliasColumn::Id)).is_in(ids.iter().copied()));
    // A self-alias appears in both branches. UNION removes that duplicate
    // without manufacturing a second revocation or rewriting its target.
    direct.union(UnionType::Distinct, aliased);
    db.query_all(db.get_database_backend().build(&direct))
        .await?
        .into_iter()
        .map(|row| {
            Ok((
                row.try_get("", "effective_id")?,
                Model::from_query_result(&row, "")?,
            ))
        })
        .collect()
}

/// Whether this delegation or any persisted equivalent CID has been revoked.
///
/// Use the caller's transaction for an admission-time recheck; signed targets
/// and stored delegation IDs are never rewritten.
pub async fn is_revoked<C: ConnectionTrait>(db: &C, delegation_id: &Hash) -> Result<bool, DbErr> {
    Ok(Entity::find()
        .filter(target_condition(Expr::value(*delegation_id)))
        .one(db)
        .await?
        .is_some())
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
        ordered.push(current);

        // Page parent edges. A single capped query can hide an unvisited
        // parent behind rows that are already in `visited` or `frontier`.
        // Continue until the child is exhausted or the actual closure exceeds
        // the node budget.
        let mut offset = 0;
        loop {
            let page_size = PARENT_DELEGATION_PAGE_SIZE;
            let parents = parent_delegations::Entity::find()
                .filter(parent_delegations::Column::Child.eq(current))
                .order_by_asc(parent_delegations::Column::Parent)
                .limit(page_size as u64)
                .offset(offset as u64)
                .all(db)
                .await?;
            let page_len = parents.len();
            for link in parents {
                if !visited.contains(&link.parent) && !frontier.contains(&link.parent) {
                    if visited.len() + frontier.len() >= MAX_CHAIN_TRAVERSAL_NODES {
                        return Err(ChainTraversalError::LimitExceeded);
                    }
                    frontier.push(link.parent);
                }
            }
            if page_len < page_size {
                break;
            }
            offset += page_len;
        }
    }
    Ok(ordered)
}

/// The delegation-control action being authorized. Status is visible to both
/// parties of a grant; revocation stays on the issuing side, so a recipient
/// (for example the holder of a shared link key) cannot cut off a grant that
/// others also rely on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ControlAction {
    Revoke,
    Status,
}

impl ControlAction {
    fn ability(self) -> &'static str {
        match self {
            Self::Revoke => "tinycloud.delegation/revoke",
            Self::Status => "tinycloud.delegation/status",
        }
    }

    /// Whether `principal` is a party to `delegation` that may take this
    /// action on it directly, without space ownership.
    pub(crate) fn party_may_act(self, delegation: &delegation::Model, principal: &str) -> bool {
        did_principal_matches(&delegation.delegator, principal)
            || (self == Self::Status && did_principal_matches(&delegation.delegatee, principal))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ControlProofDecision {
    DirectSigner(String),
    Scoped(ScopedControl),
    Denied,
}

/// One resource of a control grant, typed when the grant is loaded. Rows
/// that are none of these are dropped, so no other resource can ever widen
/// a control.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ControlScope {
    /// Exactly `urn:cid:<target>`.
    Cid(Hash),
    /// A `<space>/delegation` root of a space the grantor owns.
    Space(SpaceId),
    /// An encryption network the grantor owns. Compared as a parsed
    /// `NetworkId` (canonical owner DID, including chain id, plus name), so
    /// lowercase and EIP-55 spellings of one network are the same network.
    Network(NetworkId),
}

impl ControlScope {
    /// `target_resource` is `urn:cid:<target>`.
    fn parse(
        resource: &Resource,
        target: &Hash,
        target_resource: &str,
        grantor: &str,
    ) -> Option<Self> {
        match resource {
            Resource::Other(uri) if uri.as_str() == target_resource => Some(Self::Cid(*target)),
            Resource::Other(uri) => uri
                .as_str()
                .parse::<NetworkId>()
                .ok()
                .filter(|network| did_principal_matches(network.owner_did(), grantor))
                .map(Self::Network),
            Resource::TinyCloud(resource) => (resource.service().as_str() == "delegation"
                && resource
                    .path()
                    .map(|path| path.as_str().is_empty())
                    .unwrap_or(true)
                && resource.query().is_none()
                && resource.fragment().is_none()
                && did_principal_matches(resource.space().did().as_str(), grantor))
            .then(|| Self::Space(resource.space().clone())),
        }
    }

    fn covers(&self, resource: &Resource) -> bool {
        match (self, resource) {
            (Self::Space(space), Resource::TinyCloud(resource)) => resource.space() == space,
            // A target row that does not parse as a network is never covered.
            (Self::Network(network), Resource::Other(uri)) => uri
                .as_str()
                .parse::<NetworkId>()
                .is_ok_and(|target| &target == network),
            _ => false,
        }
    }
}

/// A current control grant bound to one requested target. Keep its complete
/// typed scopes: owning a space or network does not make a grant that names
/// it account-wide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopedControl {
    action: ControlAction,
    target: Hash,
    grantor: String,
    scopes: Vec<ControlScope>,
}

impl ScopedControl {
    fn has_cid_scope(&self) -> bool {
        self.scopes.contains(&ControlScope::Cid(self.target))
    }

    /// Check the grantor's direct party authority within an exact-CID grant.
    pub(crate) fn directly_authorizes_cid(
        &self,
        target: &Hash,
        delegation: &delegation::Model,
    ) -> bool {
        self.target == *target
            && self.has_cid_scope()
            && self.action.party_may_act(delegation, &self.grantor)
    }

    /// Require exact-CID authority, or coverage of every target row: a space
    /// row by its complete SpaceId, a network row by the identical network.
    /// No other resource is ever covered.
    pub(crate) fn authorizes_target(
        &self,
        target: &Hash,
        delegation: &delegation::Model,
        target_abilities: &[abilities::Model],
    ) -> bool {
        if self.target != *target {
            return false;
        }
        // Its issuer must still have direct authority over an exact-CID target.
        if self.has_cid_scope()
            && (self.directly_authorizes_cid(target, delegation)
                || target_abilities.iter().any(|ability| {
                    ability.resource.space().is_some_and(|space| {
                        did_principal_matches(space.did().as_str(), &self.grantor)
                    })
                }))
        {
            return true;
        }
        !target_abilities.is_empty()
            && target_abilities.iter().all(|target_ability| {
                self.scopes
                    .iter()
                    .any(|scope| scope.covers(&target_ability.resource))
            })
    }
}

/// Resolve a direct signer or the complete, target-bound control grant.
/// Proof-bearing authority keeps its resource scopes through authorization;
/// invalid proofs never fall back to the signer's or grantor's other rights.
pub(crate) async fn control_proof_decision<C: ConnectionTrait>(
    db: &C,
    signer: &str,
    proofs: &[Cid],
    action: ControlAction,
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

    let target_resource = format!("urn:cid:{}", target.to_cid(0x55));
    let scopes: Vec<ControlScope> = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(proof_id))
        .filter(abilities::Column::Ability.eq(action.ability()))
        .all(db)
        .await?
        .iter()
        .filter_map(|ability| {
            ControlScope::parse(
                &ability.resource,
                target,
                &target_resource,
                &parent.delegator,
            )
        })
        .collect();
    if scopes.is_empty() {
        return Ok(ControlProofDecision::Denied);
    }
    Ok(ControlProofDecision::Scoped(ScopedControl {
        action,
        target: *target,
        grantor: parent.delegator,
        scopes,
    }))
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
    #[error("did_method_disabled: DID method `{0}` is not resolvable on this node")]
    UnsupportedDidMethod(String),
    #[error("did_url_query_rejected: issuer DID URL must not carry a query")]
    DidUrlQueryRejected,
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
            verify_ucan_signature(u)
                .await
                .map_err(|error| match error {
                    UcanVerifyError::MethodDisabled { method } => {
                        RevocationError::UnsupportedDidMethod(method)
                    }
                    UcanVerifyError::QueryRejected => RevocationError::DidUrlQueryRejected,
                    UcanVerifyError::Timeout | UcanVerifyError::Invalid => {
                        RevocationError::InvalidSignature
                    }
                })?;
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

    // W1 (audit P0 finding 5) and TC-1436: authorized revokers are
    //   1. the delegator that issued this delegation (an intermediate
    //      delegator revokes the descendants it issued), or
    //   2. the owner of a space the delegation's persisted abilities
    //      target (owner-authorized active_cutoff), or
    //   3. the holder of a current revoke control grant issued by one of
    //      the above.
    // The delegatee alone is never authorized: it may hold a key that
    // others share, and revoking would cut them off as well.
    if !revoker_is_authorized(db, &delegation, &r.revoker, &r.parents).await? {
        return Err(RevocationError::UnauthorizedRevoker(r.revoker).into());
    };

    match Entity::insert(ActiveModel::from(Model {
        id: hash,
        serialization,
        revoker: r.revoker,
        revoked: delegation.id,
        revoked_at: Some(OffsetDateTime::now_utc()),
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
/// Accepted paths:
///   * direct delegator match: the issuer revokes what it issued
///   * owner-authorized — the revoker is the owner of a space that the
///     delegation's persisted abilities target. This is what unlocks
///     `active_cutoff`: the data owner can revoke any grant against their
///     own space without needing to be the original SIWE signer.
///   * a target-bound revoke control grant from either of the above
///
/// The delegatee is not a revoker (TC-1436).
async fn revoker_is_authorized<C: ConnectionTrait>(
    db: &C,
    delegation: &delegation::Model,
    revoker: &str,
    proofs: &[Cid],
) -> Result<bool, DbErr> {
    let principal =
        match control_proof_decision(db, revoker, proofs, ControlAction::Revoke, &delegation.id)
            .await?
        {
            ControlProofDecision::DirectSigner(principal) => principal,
            ControlProofDecision::Scoped(control) => {
                if control.directly_authorizes_cid(&delegation.id, delegation) {
                    return Ok(true);
                }
                let target_abilities = abilities::Entity::find()
                    .filter(abilities::Column::Delegation.eq(delegation.id))
                    .all(db)
                    .await?;
                return Ok(control.authorizes_target(
                    &delegation.id,
                    delegation,
                    &target_abilities,
                ));
            }
            ControlProofDecision::Denied => return Ok(false),
        };
    if ControlAction::Revoke.party_may_act(delegation, &principal) {
        return Ok(true);
    }

    let ability_rows = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(delegation.id))
        .all(db)
        .await?;
    let authorized = ability_rows.iter().any(|row| {
        row.resource
            .space()
            .is_some_and(|space| did_principal_matches(space.did().as_str(), &principal))
    });
    if authorized {
        // Observe every affected resource, not just the owner-match witness.
        for row in &ability_rows {
            if let Some(space) = row.resource.space() {
                crate::request_telemetry::observe_space(space);
            }
        }
    }
    Ok(authorized)
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn did_web_refusal_precedes_resolution() {
        use crate::test_support::did_resolution::*;
        use tinycloud_auth::ssi::jwk::{Algorithm, JWK};
        let listener = bound_listener();
        let issuer = format!(
            "did:web:127.0.0.1%3A{}",
            listener.local_addr().unwrap().port()
        );
        let jwk = JWK::generate_ed25519().unwrap();
        let mut payload = signed_ucan(&issuer, &jwk, Algorithm::EdDSA)
            .payload()
            .clone();
        payload.attenuation.with_actions(
            format!("urn:cid:{}", payload.proof[0]).parse().unwrap(),
            [("tinycloud.delegation/revoke".parse().unwrap(), [])],
        );
        let ucan = payload.sign(Algorithm::EdDSA, &jwk).unwrap();
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        let token = ucan.encode().unwrap();
        let event = crate::events::Revocation::from_header_ser::<
            tinycloud_auth::authorization::TinyCloudRevocation,
        >(&token)
        .unwrap();
        let result = super::process(&db, event).await;
        assert!(
            matches!(result, Err(super::Error::InvalidRevocation(super::RevocationError::UnsupportedDidMethod(method))) if method == "web")
        );
        assert_no_connections(&[&listener]).await;
    }
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

    async fn insert_delegation<C: ConnectionTrait>(db: &C, id: Hash) {
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

    async fn insert_link<C: ConnectionTrait>(db: &C, child: Hash, parent: Hash) {
        parent_delegations::ActiveModel {
            parent: Set(parent),
            child: Set(child),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn assert_shared_ancestor_is_loaded<C: ConnectionTrait>(db: &C) {
        let mut ids: Vec<_> = (0..MAX_CHAIN_TRAVERSAL_NODES)
            .map(|index| hash(format!("shared-ancestor-boundary-{index}").as_bytes()))
            .collect();
        ids.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
        let (roots, hidden_ancestor) = ids.split_at(MAX_CHAIN_TRAVERSAL_NODES - 1);
        for id in &ids {
            insert_delegation(db, *id).await;
        }
        // The lowest root is processed after the two cited parents. The
        // uncited ancestor sorts after both and used to fall beyond LIMIT.
        insert_link(db, roots[0], roots[MAX_CHAIN_TRAVERSAL_NODES - 3]).await;
        insert_link(db, roots[0], roots[MAX_CHAIN_TRAVERSAL_NODES - 2]).await;
        insert_link(db, roots[0], hidden_ancestor[0]).await;

        let chain = ancestor_chain_ids_for_roots(db, roots).await.unwrap();
        assert_eq!(chain.len(), MAX_CHAIN_TRAVERSAL_NODES);
        assert!(
            chain.contains(&hidden_ancestor[0]),
            "a parent after already-visited shared parents must be traversed"
        );
    }

    #[tokio::test]
    async fn shared_ancestor_after_visited_roots_is_loaded_on_sqlite() {
        let db = database().await;
        assert_shared_ancestor_is_loaded(&db).await;
    }

    #[tokio::test]
    async fn shared_ancestor_after_visited_roots_is_loaded_on_postgres() {
        use sea_orm::{DbBackend, Statement};

        let Some(database_url) = crate::test_support::postgres_test_url(
            "shared_ancestor_after_visited_roots_is_loaded_on_postgres",
        ) else {
            return;
        };
        let admin = Database::connect(ConnectOptions::new(database_url.clone()))
            .await
            .expect("connect to PostgreSQL test database");
        let schema = format!(
            "tc815_{}_{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .expect("create isolated TC-815 schema");
        let mut options = ConnectOptions::new(database_url);
        options.set_schema_search_path(schema.clone());
        let exercise = async {
            let db = Database::connect(options).await?;
            Migrator::up(&db, None).await?;
            actor::ActiveModel {
                id: Set("did:key:actor".to_string()),
            }
            .insert(&db)
            .await?;
            assert_shared_ancestor_is_loaded(&db).await;
            Ok::<_, sea_orm::DbErr>(())
        }
        .await;
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .expect("drop isolated TC-815 schema");
        exercise.expect("TC-815 PostgreSQL shared-ancestor traversal");
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
    async fn dense_64_node_dag_uses_one_parent_query_per_node() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let mut db = database().await;
        let ids: Vec<_> = (0..MAX_CHAIN_TRAVERSAL_NODES)
            .map(|index| hash(format!("dense-dag-{index}").as_bytes()))
            .collect();
        for id in &ids {
            insert_delegation(&db, *id).await;
        }
        for child in 1..ids.len() {
            for parent in 0..child {
                insert_link(&db, ids[child], ids[parent]).await;
            }
        }

        let query_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&query_count);
        db.set_metric_callback(move |_info| {
            counter.fetch_add(1, Ordering::Relaxed);
        });

        let chain = ancestor_chain_ids_for_roots(&db, &[ids[ids.len() - 1]])
            .await
            .unwrap();

        assert_eq!(chain.len(), MAX_CHAIN_TRAVERSAL_NODES);
        assert_eq!(
            query_count.load(Ordering::Relaxed),
            MAX_CHAIN_TRAVERSAL_NODES
        );
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

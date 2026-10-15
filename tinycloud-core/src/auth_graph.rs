//! TC-269: transaction-scoped authorization graph snapshot for the
//! production invocation path.
//!
//! Instead of walking `parent_delegations` one node at a time and issuing a
//! revocation lookup per ancestor (repeated for chain locking, revocation
//! checks, and chain-window validation), the snapshot batch-loads the whole
//! proof closure once: parent edges, then the
//! delegation rows, the closure's ability/caveat rows, and the closure's
//! revocations in one query each. All chain checks then run in memory against
//! the same consistent view.

use crate::hash::Hash;
use crate::models::{abilities, delegation, delegation_cid_alias, revocation};
use crate::relationships::parent_delegations;
use sea_orm::{
    entity::prelude::*,
    sea_query::{Alias, CommonTableExpression, Expr, JoinType, Query, UnionType, WithClause},
    ConnectionTrait, DbErr,
};
use std::collections::{HashMap, HashSet};
use tinycloud_auth::identity::principal_did;

pub(crate) use crate::models::revocation::ChainTraversalError;
use crate::models::revocation::MAX_CHAIN_TRAVERSAL_NODES;

/// Batched ancestor-closure load over `parent_delegations`. A recursive CTE
/// fetches all reachable edges in one query rather than walking one node at a
/// time. The in-memory pass enforces the same fail-closed node budget as the
/// per-node traversal used by the delegate/revoke paths.
pub(crate) async fn load_closure_edges<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
) -> Result<(Vec<Hash>, HashMap<Hash, Vec<Hash>>), ChainTraversalError> {
    load_closure(db, roots, false).await
}

/// Resolve the same bounded closure to canonical lock identities. Signed graph
/// IDs stay untouched; indexed alias joins share the closure's one round trip.
pub(crate) async fn load_chain_lock_ids<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
) -> Result<Vec<Hash>, ChainTraversalError> {
    load_closure(db, roots, true).await.map(|(ids, _)| ids)
}

/// The caller already loaded and bounded the signed proof closure. Resolve
/// its immutable signer/audience principals and canonical alias lock IDs in
/// one query; live revocation is still checked after acquiring those guards.
pub(crate) async fn invocation_authority_for_closure<C: ConnectionTrait>(
    db: &C,
    mut ids: Vec<Hash>,
) -> Result<(Vec<Hash>, Vec<String>), DbErr> {
    if ids.is_empty() {
        return Ok((ids, Vec::new()));
    }
    let query = Query::select()
        .columns([
            (delegation::Entity, delegation::Column::Id),
            (delegation::Entity, delegation::Column::Delegator),
            (delegation::Entity, delegation::Column::Delegatee),
        ])
        .expr_as(
            Expr::col((
                delegation_cid_alias::Entity,
                delegation_cid_alias::Column::Canonical,
            )),
            Alias::new("canonical_lock"),
        )
        .from(delegation::Entity)
        .join(
            JoinType::LeftJoin,
            delegation_cid_alias::Entity,
            Expr::col((delegation::Entity, delegation::Column::Id)).equals((
                delegation_cid_alias::Entity,
                delegation_cid_alias::Column::Id,
            )),
        )
        .and_where(
            Expr::col((delegation::Entity, delegation::Column::Id)).is_in(ids.iter().copied()),
        )
        .to_owned();
    let rows = db
        .query_all(db.get_database_backend().build(&query))
        .await?;
    if rows.len() != ids.len() {
        return Err(DbErr::Custom("authorization-chain-missing".into()));
    }
    let mut principals = Vec::with_capacity(rows.len() * 2);
    let mut aliases = HashMap::with_capacity(rows.len());
    for row in rows {
        let id: Hash = row.try_get("", "id")?;
        if let Some(canonical) = row.try_get::<Option<Hash>>("", "canonical_lock")? {
            aliases.insert(id, canonical);
        }
        for column in ["delegator", "delegatee"] {
            let did: String = row.try_get("", column)?;
            principals.push(
                principal_did(&did)
                    .map_err(|_| DbErr::Custom("authorization-principal-invalid".into()))?,
            );
        }
    }
    for id in &mut ids {
        if let Some(canonical) = aliases.get(id) {
            *id = *canonical;
        }
    }
    principals.sort_unstable();
    principals.dedup();
    Ok((ids, principals))
}

/// Every signer and audience in a bounded, persisted proof closure. Missing
/// rows and unparseable principals are authorization failures, not an empty
/// dependency set. CID identity and DID-principal identity remain separate.
pub(crate) async fn load_chain_principals<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
) -> Result<Vec<String>, ChainTraversalError> {
    let (ids, _) = load_closure_edges(db, roots).await?;
    principals_for_ids(db, &ids).await
}

/// Resolve the signers of an already bounded proof closure without re-running
/// its recursive query. The invocation request also needs these same IDs to
/// discover its policy session, so it can share this request-local snapshot.
pub(crate) async fn principals_for_ids<C: ConnectionTrait>(
    db: &C,
    ids: &[Hash],
) -> Result<Vec<String>, ChainTraversalError> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let rows = delegation::Entity::find()
        .filter(delegation::Column::Id.is_in(ids.iter().copied()))
        .all(db)
        .await?;
    if rows.len() != ids.len() {
        return Err(DbErr::Custom("authorization-chain-missing".into()).into());
    }
    let mut principals = Vec::with_capacity(rows.len() * 2);
    for row in rows {
        for did in [&row.delegator, &row.delegatee] {
            principals.push(
                principal_did(did)
                    .map_err(|_| DbErr::Custom("authorization-principal-invalid".into()))?,
            );
        }
    }
    principals.sort_unstable();
    principals.dedup();
    Ok(principals)
}

async fn load_closure<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
    canonical_locks: bool,
) -> Result<(Vec<Hash>, HashMap<Hash, Vec<Hash>>), ChainTraversalError> {
    let mut nodes = roots.to_vec();
    nodes.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
    nodes.dedup();
    if nodes.len() > MAX_CHAIN_TRAVERSAL_NODES {
        return Err(ChainTraversalError::LimitExceeded);
    }
    if nodes.is_empty() {
        return Ok((nodes, HashMap::new()));
    }

    let closure = Alias::new("authorization_edges");
    let child = Alias::new("child");
    let parent = Alias::new("parent");
    let base = Query::select()
        .columns([
            parent_delegations::Column::Child,
            parent_delegations::Column::Parent,
        ])
        .from(parent_delegations::Entity)
        .and_where(Expr::col(parent_delegations::Column::Child).is_in(nodes.iter().copied()))
        .to_owned();
    let recursive = Query::select()
        .columns([
            (
                parent_delegations::Entity,
                parent_delegations::Column::Child,
            ),
            (
                parent_delegations::Entity,
                parent_delegations::Column::Parent,
            ),
        ])
        .from(parent_delegations::Entity)
        .join(
            JoinType::InnerJoin,
            closure.clone(),
            Expr::col((
                parent_delegations::Entity,
                parent_delegations::Column::Child,
            ))
            .equals((closure.clone(), parent.clone())),
        )
        .to_owned();
    let mut closure_query = base;
    if canonical_locks {
        // Parentless stored roots otherwise produce no edge row. Seed them
        // only for locking; roots without a persisted alias retain their ID.
        let seed = Query::select()
            .expr_as(Expr::col(delegation_cid_alias::Column::Id), child.clone())
            .expr_as(Expr::val(Option::<Hash>::None), parent.clone())
            .from(delegation_cid_alias::Entity)
            .and_where(Expr::col(delegation_cid_alias::Column::Id).is_in(nodes.iter().copied()))
            .to_owned();
        closure_query.union(UnionType::Distinct, seed);
    }
    closure_query.union(UnionType::Distinct, recursive);
    let cte = CommonTableExpression::new()
        .table_name(closure.clone())
        .columns([child.clone(), parent.clone()])
        .query(closure_query)
        .to_owned();
    let edge_cap = MAX_CHAIN_TRAVERSAL_NODES * MAX_CHAIN_TRAVERSAL_NODES;
    let mut query = Query::select();
    query
        .columns([
            (closure.clone(), child.clone()),
            (closure.clone(), parent.clone()),
        ])
        .from(closure.clone())
        .limit((edge_cap + if canonical_locks { nodes.len() } else { 0 } + 1) as u64);
    if canonical_locks {
        for (column, alias, output) in [
            (
                child.clone(),
                Alias::new("child_alias"),
                Alias::new("child_lock"),
            ),
            (
                parent.clone(),
                Alias::new("parent_alias"),
                Alias::new("parent_lock"),
            ),
        ] {
            query
                .expr_as(
                    Expr::col((alias.clone(), delegation_cid_alias::Column::Canonical)),
                    output,
                )
                .join_as(
                    JoinType::LeftJoin,
                    delegation_cid_alias::Entity,
                    alias.clone(),
                    Expr::col((alias, delegation_cid_alias::Column::Id))
                        .equals((closure.clone(), column)),
                );
        }
    }
    let query = query.with(WithClause::new().recursive(true).cte(cte).to_owned());
    let rows = db
        .query_all(db.get_database_backend().build(&query))
        .await?;
    if rows.len() > edge_cap + if canonical_locks { nodes.len() } else { 0 } {
        return Err(ChainTraversalError::LimitExceeded);
    }

    let mut edges: HashMap<Hash, Vec<Hash>> = HashMap::new();
    let mut lock_aliases = HashMap::new();
    for row in rows {
        let edge_child: Hash = row.try_get("", "child")?;
        let edge_parent: Option<Hash> = row.try_get("", "parent")?;
        if canonical_locks {
            if let Some(canonical) = row.try_get::<Option<Hash>>("", "child_lock")? {
                if canonical != edge_child {
                    lock_aliases.insert(edge_child, canonical);
                }
            }
            if let (Some(parent), Some(canonical)) =
                (edge_parent, row.try_get::<Option<Hash>>("", "parent_lock")?)
            {
                if canonical != parent {
                    lock_aliases.insert(parent, canonical);
                }
            }
        }
        let Some(edge_parent) = edge_parent else {
            continue;
        };
        let parents = edges.entry(edge_child).or_default();
        if !parents.contains(&edge_parent) {
            parents.push(edge_parent);
        }
    }
    for parents in edges.values_mut() {
        parents.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
    }

    let mut visited = nodes.iter().copied().collect::<HashSet<_>>();
    let mut frontier = nodes.clone();
    while let Some(current) = frontier.pop() {
        for parent in edges.get(&current).map(Vec::as_slice).unwrap_or(&[]) {
            if visited.insert(*parent) {
                if visited.len() > MAX_CHAIN_TRAVERSAL_NODES {
                    return Err(ChainTraversalError::LimitExceeded);
                }
                nodes.push(*parent);
                frontier.push(*parent);
            }
        }
    }
    for id in &mut nodes {
        if let Some(canonical) = lock_aliases.get(id) {
            *id = *canonical;
        }
    }

    Ok((nodes, edges))
}

#[derive(Debug)]
pub(crate) struct AuthGraphSnapshot {
    parents: HashMap<Hash, Vec<Hash>>,
    delegations: HashMap<Hash, delegation::Model>,
    abilities: HashMap<Hash, Vec<abilities::Model>>,
    revoked: HashSet<Hash>,
}

impl AuthGraphSnapshot {
    /// Batch-load the authorization graph for the given proof roots on the
    /// supplied connection (the invocation transaction in production).
    pub(crate) async fn load<C: ConnectionTrait>(
        db: &C,
        roots: &[Hash],
    ) -> Result<Self, ChainTraversalError> {
        let (nodes, parents) = load_closure_edges(db, roots).await?;
        if nodes.is_empty() {
            return Ok(Self {
                parents,
                delegations: HashMap::new(),
                abilities: HashMap::new(),
                revoked: HashSet::new(),
            });
        }
        let delegations = delegation::Entity::find()
            .filter(delegation::Column::Id.is_in(nodes.iter().copied()))
            .all(db)
            .await?
            .into_iter()
            .map(|row| (row.id, row))
            .collect();

        let mut ability_rows: HashMap<Hash, Vec<abilities::Model>> = HashMap::new();
        for row in abilities::Entity::find()
            .filter(abilities::Column::Delegation.is_in(nodes.iter().copied()))
            .all(db)
            .await?
        {
            ability_rows.entry(row.delegation).or_default().push(row);
        }

        let revoked = revocation::effective_rows(db, &nodes)
            .await?
            .into_iter()
            .map(|(id, _)| id)
            .collect();

        Ok(Self {
            parents,
            delegations,
            abilities: ability_rows,
            revoked,
        })
    }

    pub(crate) fn delegation(&self, id: &Hash) -> Option<&delegation::Model> {
        self.delegations.get(id)
    }

    /// Persisted ability/caveat rows for any proof in the loaded closure.
    pub(crate) fn abilities(&self, id: &Hash) -> &[abilities::Model] {
        self.abilities.get(id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Whether one cited proof reaches a parentless or owner-issued authority
    /// through nodes whose abilities all cover the invoked capability.
    /// Results are memoized across branches and cited proofs; cycles, missing
    /// rows and budget overflow fail closed.
    pub(crate) fn has_covering_chain(
        &self,
        starts: impl IntoIterator<Item = Hash>,
        covers: impl Fn(&abilities::Model) -> bool,
        is_authority: impl Fn(&delegation::Model) -> bool,
    ) -> bool {
        fn visit<F: Fn(&abilities::Model) -> bool, A: Fn(&delegation::Model) -> bool>(
            graph: &AuthGraphSnapshot,
            id: Hash,
            covers: &F,
            is_authority: &A,
            memo: &mut HashMap<Hash, bool>,
            visiting: &mut HashSet<Hash>,
        ) -> bool {
            if let Some(&valid) = memo.get(&id) {
                return valid;
            }
            if visiting.contains(&id) || memo.len() + visiting.len() >= MAX_CHAIN_TRAVERSAL_NODES {
                return false;
            }
            visiting.insert(id);
            let valid = if let Some(row) = graph.delegation(&id) {
                graph.abilities(&id).iter().any(covers)
                    && (is_authority(row)
                        || graph.parents.get(&id).is_none_or(|parents| {
                            parents.is_empty()
                                || parents.iter().any(|parent| {
                                    visit(graph, *parent, covers, is_authority, memo, visiting)
                                })
                        }))
            } else {
                false
            };
            visiting.remove(&id);
            memo.insert(id, valid);
            valid
        }

        let mut memo = HashMap::new();
        let mut visiting = HashSet::new();
        starts
            .into_iter()
            .any(|id| visit(self, id, &covers, &is_authority, &mut memo, &mut visiting))
    }

    pub(crate) fn is_revoked(&self, id: &Hash) -> bool {
        self.revoked.contains(id)
    }

    /// `start` followed by its ancestors, walked with the same stack order
    /// as `revocation::ancestor_chain_ids`, without touching the database.
    pub(crate) fn chain_ids_from(&self, start: &Hash) -> Vec<Hash> {
        let mut frontier = vec![*start];
        let mut visited = HashSet::new();
        let mut ordered = Vec::new();
        while let Some(current) = frontier.pop() {
            if !visited.insert(current) {
                continue;
            }
            ordered.push(current);
            for parent in self.parents.get(&current).map(Vec::as_slice).unwrap_or(&[]) {
                if !visited.contains(parent) && !frontier.contains(parent) {
                    frontier.push(*parent);
                }
            }
        }
        ordered
    }

    /// First revoked strict ancestor of `start`, as a CID string.
    pub(crate) fn first_revoked_ancestor(&self, start: &Hash) -> Option<String> {
        self.chain_ids_from(start)
            .into_iter()
            .skip(1)
            .find(|ancestor| self.revoked.contains(ancestor))
            .map(|ancestor| ancestor.to_cid(0x55).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash;
    use crate::migrations::Migrator;
    use crate::models::actor;
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection,
        QueryFilter,
    };
    use sea_orm_migration::MigratorTrait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;
    use time::OffsetDateTime;

    async fn counted_database() -> (DatabaseConnection, Arc<AtomicUsize>) {
        let mut db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        actor::ActiveModel {
            id: Set("did:key:actor".to_string()),
        }
        .insert(&db)
        .await
        .unwrap();
        let counter = Arc::new(AtomicUsize::new(0));
        let query_counter = Arc::clone(&counter);
        db.set_metric_callback(move |_info| {
            query_counter.fetch_add(1, Ordering::SeqCst);
        });
        (db, counter)
    }

    async fn insert_delegation(db: &DatabaseConnection, id: Hash) {
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

    async fn insert_edge(db: &DatabaseConnection, child: Hash, parent: Hash) {
        parent_delegations::ActiveModel {
            parent: Set(parent),
            child: Set(child),
        }
        .insert(db)
        .await
        .unwrap();
    }

    /// Linear chain of `depth + 1` delegations; `ids[0]` is the leaf.
    async fn insert_chain(db: &DatabaseConnection, tag: &str, depth: usize) -> Vec<Hash> {
        let ids: Vec<Hash> = (0..=depth)
            .map(|index| hash(format!("{tag}-{index}").as_bytes()))
            .collect();
        for id in &ids {
            insert_delegation(db, *id).await;
        }
        for pair in ids.windows(2) {
            insert_edge(db, pair[0], pair[1]).await;
        }
        ids
    }

    #[tokio::test]
    async fn snapshot_depths_zero_one_and_four_match_per_node_traversal() {
        let (db, _) = counted_database().await;
        for depth in [0, 1, 4] {
            let ids = insert_chain(&db, &format!("closure-{depth}"), depth).await;
            let snapshot = AuthGraphSnapshot::load(&db, &[ids[0]]).await.unwrap();
            let mut expected = revocation::ancestor_chain_ids(&db, &ids[0]).await.unwrap();
            let mut actual = snapshot.chain_ids_from(&ids[0]);
            expected.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            actual.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            assert_eq!(actual, expected, "depth {depth}");
            assert!(
                snapshot
                    .chain_ids_from(&ids[0])
                    .iter()
                    .all(|id| snapshot.delegation(id).is_some()),
                "depth {depth}"
            );
        }
    }

    #[tokio::test]
    async fn snapshot_load_fails_closed_at_traversal_limit() {
        let (db, _) = counted_database().await;
        let ids = insert_chain(&db, "deep", MAX_CHAIN_TRAVERSAL_NODES).await;
        assert!(matches!(
            AuthGraphSnapshot::load(&db, &[ids[0]]).await,
            Err(ChainTraversalError::LimitExceeded)
        ));

        let boundary = insert_chain(&db, "boundary", MAX_CHAIN_TRAVERSAL_NODES - 1).await;
        let snapshot = AuthGraphSnapshot::load(&db, &[boundary[0]]).await.unwrap();
        assert_eq!(
            snapshot.chain_ids_from(&boundary[0]).len(),
            MAX_CHAIN_TRAVERSAL_NODES
        );
    }

    #[tokio::test]
    async fn snapshot_reports_direct_revocation() {
        let (db, _) = counted_database().await;
        let ids = insert_chain(&db, "direct-revoked", 1).await;
        revocation::ActiveModel {
            id: Set(hash(b"revoked-leaf")),
            revoker: Set("did:key:actor".to_string()),
            revoked: Set(ids[0]),
            serialization: Set(b"revoked-leaf".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&db)
        .await
        .unwrap();

        let snapshot = AuthGraphSnapshot::load(&db, &[ids[0]]).await.unwrap();
        assert!(snapshot.is_revoked(&ids[0]));
        assert_eq!(snapshot.first_revoked_ancestor(&ids[0]), None);
    }

    #[tokio::test]
    async fn snapshot_reports_ancestor_revocation() {
        let (db, _) = counted_database().await;
        let ids = insert_chain(&db, "revoked", 4).await;
        revocation::ActiveModel {
            id: Set(hash(b"revoked-mid")),
            revoker: Set("did:key:actor".to_string()),
            revoked: Set(ids[2]),
            serialization: Set(b"revoked-mid".to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(&db)
        .await
        .unwrap();

        let snapshot = AuthGraphSnapshot::load(&db, &[ids[0]]).await.unwrap();
        assert!(snapshot.is_revoked(&ids[2]));
        assert!(!snapshot.is_revoked(&ids[0]));
        assert_eq!(
            snapshot.first_revoked_ancestor(&ids[0]),
            Some(ids[2].to_cid(0x55).to_string())
        );
        // The revoked node itself is not its own ancestor.
        assert_eq!(snapshot.first_revoked_ancestor(&ids[2]), None);
    }

    #[tokio::test]
    async fn snapshot_exposes_missing_root_and_malformed_ancestor_fail_closed() {
        let (db, _) = counted_database().await;
        let missing_root = hash(b"missing-root");
        let snapshot = AuthGraphSnapshot::load(&db, &[missing_root]).await.unwrap();
        assert!(snapshot
            .chain_ids_from(&missing_root)
            .iter()
            .any(|id| snapshot.delegation(id).is_none()));

        let ids = insert_chain(&db, "malformed", 1).await;
        db.execute_unprepared("PRAGMA foreign_keys = OFF")
            .await
            .unwrap();
        delegation::Entity::delete_by_id(ids[1])
            .exec(&db)
            .await
            .unwrap();
        let snapshot = AuthGraphSnapshot::load(&db, &[ids[0]]).await.unwrap();
        assert_eq!(snapshot.chain_ids_from(&ids[0]), ids);
        assert!(snapshot
            .chain_ids_from(&ids[0])
            .iter()
            .any(|id| snapshot.delegation(id).is_none()));
    }

    /// TC-269 exact query-batch counter: the legacy invocation path issued a
    /// depth-amplified number of queries (per-node closure walks repeated for
    /// locking, revocation, and chain-window checks, plus a revocation lookup
    /// per ancestor). The new path uses one pre-transaction closure query to
    /// establish the lock set, then one transaction-scoped snapshot consisting
    /// of one closure query and one batch each for delegations, abilities, and
    /// revocations.
    #[tokio::test]
    async fn snapshot_query_batches_are_bounded_versus_depth_amplified_traversal() {
        for (depth, expected_legacy) in [(0, 6), (1, 10), (4, 22)] {
            let (db, counter) = counted_database().await;
            let ids = insert_chain(&db, &format!("counted-{depth}"), depth).await;
            let leaf = ids[0];

            // Legacy invocation-path sequence, reproduced from the per-node
            // helpers still used by the delegate/revoke/status paths.
            let before = counter.load(Ordering::SeqCst);
            revocation::ancestor_chain_ids_for_roots(&db, &[leaf])
                .await
                .unwrap();
            delegation::Entity::find()
                .filter(delegation::Column::Id.is_in([leaf]))
                .find_with_related(abilities::Entity)
                .all(&db)
                .await
                .unwrap();
            assert!(!revocation::is_revoked(&db, &leaf).await.unwrap());
            assert_eq!(
                revocation::first_revoked_ancestor(&db, &leaf)
                    .await
                    .unwrap(),
                None
            );
            let chain_ids = revocation::ancestor_chain_ids(&db, &leaf).await.unwrap();
            delegation::Entity::find()
                .filter(delegation::Column::Id.is_in(chain_ids))
                .all(&db)
                .await
                .unwrap();
            let legacy_queries = counter.load(Ordering::SeqCst) - before;

            // New production path: one recursive edge query to establish the
            // lock set, then a four-query transaction-scoped snapshot.
            let before = counter.load(Ordering::SeqCst);
            let (lock_keys, _) = load_closure_edges(&db, &[leaf]).await.unwrap();
            let snapshot = AuthGraphSnapshot::load(&db, &[leaf]).await.unwrap();
            let optimized_queries = counter.load(Ordering::SeqCst) - before;

            assert_eq!(lock_keys.len(), depth + 1);
            assert_eq!(snapshot.chain_ids_from(&leaf).len(), depth + 1);
            assert_eq!(legacy_queries, expected_legacy, "depth {depth}");
            assert_eq!(optimized_queries, 5, "depth {depth}");
        }
    }
}

//! TC-269: transaction-scoped authorization graph snapshot for the
//! production invocation path.
//!
//! Instead of walking `parent_delegations` one node at a time and issuing a
//! revocation lookup per ancestor (repeated for chain locking, revocation
//! checks, and chain-window validation), the snapshot batch-loads the whole
//! proof closure once: parent edges, then the
//! delegation rows, the closure's ability/caveat rows (cited roots and their
//! ancestors alike), and the closure's revocations in one query each. All
//! chain checks then run in memory against the same consistent view.

use crate::hash::Hash;
use crate::models::{abilities, delegation, revocation};
use crate::relationships::parent_delegations;
use sea_orm::{
    entity::prelude::*,
    sea_query::{Alias, CommonTableExpression, Expr, JoinType, Query, UnionType, WithClause},
    ConnectionTrait,
};
use std::collections::{HashMap, HashSet};

pub(crate) use crate::models::revocation::ChainTraversalError;
use crate::models::revocation::MAX_CHAIN_TRAVERSAL_NODES;

/// Depth-first cycle detection over a child->parents edge map, using the
/// classic white/gray/black coloring so a node currently on the DFS stack
/// (gray) being revisited proves a cycle. `edges` is bounded by
/// `MAX_CHAIN_TRAVERSAL_NODES` before this runs, so recursion depth is
/// bounded too.
fn has_cycle(edges: &HashMap<Hash, Vec<Hash>>) -> bool {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        InProgress,
        Done,
    }
    fn visit(
        node: Hash,
        edges: &HashMap<Hash, Vec<Hash>>,
        marks: &mut HashMap<Hash, Mark>,
    ) -> bool {
        match marks.get(&node) {
            Some(Mark::InProgress) => return true,
            Some(Mark::Done) => return false,
            None => {}
        }
        marks.insert(node, Mark::InProgress);
        if let Some(parents) = edges.get(&node) {
            for parent in parents {
                if visit(*parent, edges, marks) {
                    return true;
                }
            }
        }
        marks.insert(node, Mark::Done);
        false
    }

    let mut marks: HashMap<Hash, Mark> = HashMap::new();
    edges
        .keys()
        .any(|node| marks.get(node) != Some(&Mark::Done) && visit(*node, edges, &mut marks))
}

/// A single caveat value declares itself a `constrained-statements` caveat
/// either directly (top-level `mode: "constrained-statements"`) or nested
/// under a `"constrained-statements"` key. Unrelated caveat values (neither
/// shape present) are `Ok(None)` and silently skipped, matching prior
/// behavior. A value that *does* declare one of these shapes but fails to
/// parse (missing/malformed `statements`, `readOnly`, etc.) is a malformed
/// declared caveat and returns `Err`, so the caller fails closed instead of
/// treating a broken grant as an absent one.
fn declared_constrained_statement_caveat(
    v: &serde_json::Value,
) -> Result<
    Option<crate::policy_capability::sql_caveat::SqlConstrainedStatementCaveat>,
    crate::policy_capability::RejectionCode,
> {
    let declares_mode_directly = v
        .as_object()
        .and_then(|o| o.get("mode"))
        .and_then(serde_json::Value::as_str)
        == Some("constrained-statements");
    if declares_mode_directly {
        return crate::policy_capability::sql_caveat::parse(v).map(Some);
    }
    if let Some(inner) = v.as_object().and_then(|o| o.get("constrained-statements")) {
        return crate::policy_capability::sql_caveat::parse(inner).map(Some);
    }
    Ok(None)
}

/// Batched ancestor-closure load over `parent_delegations`. A recursive CTE
/// fetches all reachable edges in one query rather than walking one node at a
/// time. The in-memory pass enforces the same fail-closed node budget as the
/// per-node traversal used by the delegate/revoke paths.
pub(crate) async fn load_closure_edges<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
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
        .from(closure)
        .limit((edge_cap + 1) as u64);
    let query = query.with(WithClause::new().recursive(true).cte(cte).to_owned());
    let rows = db
        .query_all(db.get_database_backend().build(&query))
        .await?;
    if rows.len() > edge_cap {
        return Err(ChainTraversalError::LimitExceeded);
    }

    let mut edges: HashMap<Hash, Vec<Hash>> = HashMap::new();
    for row in rows {
        let edge_child: Hash = row.try_get("", "child")?;
        let edge_parent: Hash = row.try_get("", "parent")?;
        let parents = edges.entry(edge_child).or_default();
        if !parents.contains(&edge_parent) {
            parents.push(edge_parent);
        }
    }
    for parents in edges.values_mut() {
        parents.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
    }

    // TC-411: `rows.len() <= edge_cap` bounds edge *count*, not distinct node
    // *count* -- a sparse, wide graph (e.g. many nodes with few parents each)
    // can pass the edge check while still spanning far more than
    // `MAX_CHAIN_TRAVERSAL_NODES` distinct nodes. `has_cycle` below recurses
    // per distinct node, so that bound must be enforced first, over the
    // decoded closure, before any recursive traversal runs.
    let mut distinct_nodes: HashSet<Hash> = HashSet::new();
    for (child, parents) in &edges {
        distinct_nodes.insert(*child);
        distinct_nodes.extend(parents.iter().copied());
    }
    if distinct_nodes.len() > MAX_CHAIN_TRAVERSAL_NODES {
        return Err(ChainTraversalError::LimitExceeded);
    }

    // TC-411: a cycle in the loaded closure has no well-defined ancestor
    // order for caveat/revocation resolution. A per-node traversal's visited
    // set would still terminate against a cycle and silently accept the
    // chain; fail closed instead, reusing `LimitExceeded` (already the
    // established "reject this traversal outright" signal here -- see
    // `load_guarded`'s guarded/reloaded mismatch case below) rather than
    // widening the shared `ChainTraversalError` enum used across the
    // delegate/revoke paths outside this module's scope. `has_cycle`'s
    // recursion is now bounded by the distinct-node check above.
    if has_cycle(&edges) {
        return Err(ChainTraversalError::LimitExceeded);
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
        Self::load_from_closure(db, nodes, parents).await
    }

    /// Same as [`Self::load`], but for a closure (`nodes`/`parents`) already
    /// known from a prior `load_closure_edges` call on this same connection's
    /// database. Only safe to call with a closure that is already *proven*
    /// complete for the connection being read from -- see [`Self::load_guarded`]
    /// for the production caller, which re-derives and verifies the closure
    /// under the caller's chain guards instead of trusting a pre-guard read.
    ///
    /// Ability/caveat rows are loaded for every node in the bounded closure
    /// (`nodes`), not just the cited roots: `constrained_statement_caveat_candidates`
    /// walks each root's full ancestor chain and reads `abilities()` at every
    /// step, so an ancestor-only caveat (the descendant delegation carries no
    /// caveat of its own) would otherwise be silently invisible even though it
    /// is part of the already-loaded, already-bounded closure. `nodes` is
    /// capped at `MAX_CHAIN_TRAVERSAL_NODES` by `load_closure_edges`, so this
    /// stays a single bounded-size statement, not an unbounded one.
    pub(crate) async fn load_from_closure<C: ConnectionTrait>(
        db: &C,
        nodes: Vec<Hash>,
        parents: HashMap<Hash, Vec<Hash>>,
    ) -> Result<Self, ChainTraversalError> {
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

        let revoked = revocation::Entity::find()
            .filter(revocation::Column::Revoked.is_in(nodes.iter().copied()))
            .all(db)
            .await?
            .into_iter()
            .map(|row| row.revoked)
            .collect();

        Ok(Self {
            parents,
            delegations,
            abilities: ability_rows,
            revoked,
        })
    }

    /// TC-411: the production entry point for the invocation path. `roots`
    /// is the invocation's cited proofs; `guarded_keys` is the pre-guard
    /// closure node set the caller already holds chain guards over (see
    /// `SpaceDatabase::acquire_shared_chain_guards_for_keys`).
    ///
    /// A registration racing the guard acquisition (its exclusive guard
    /// released just as this invocation's shared guard is granted) can leave
    /// a cited root visible for the first time with ancestor edges that the
    /// pre-guard closure read never saw -- `guarded_keys` would then be
    /// missing those ancestors, and reusing it blindly would authorize
    /// against an incomplete chain. This re-derives the closure on `db`
    /// (expected to be the guarded connection/transaction) and fails closed
    /// with [`ChainTraversalError::LimitExceeded`] if the freshly observed
    /// node set is not *exactly* `guarded_keys`, instead of silently
    /// authorizing against the stale pre-guard view. `parent_delegations`
    /// rows are insert-only, so equality here proves the guarded view was
    /// already complete.
    pub(crate) async fn load_guarded<C: ConnectionTrait>(
        db: &C,
        roots: &[Hash],
        guarded_keys: &[Hash],
    ) -> Result<Self, ChainTraversalError> {
        let (nodes, edges) = load_closure_edges(db, roots).await?;
        let guarded: HashSet<Hash> = guarded_keys.iter().copied().collect();
        let reloaded: HashSet<Hash> = nodes.iter().copied().collect();
        if reloaded != guarded {
            return Err(ChainTraversalError::LimitExceeded);
        }
        Self::load_from_closure(db, nodes, edges).await
    }

    pub(crate) fn delegation(&self, id: &Hash) -> Option<&delegation::Model> {
        self.delegations.get(id)
    }

    /// Persisted ability/caveat rows for any node in the loaded closure
    /// (a cited proof root or one of its ancestors).
    pub(crate) fn abilities(&self, id: &Hash) -> &[abilities::Model] {
        self.abilities.get(id).map(Vec::as_slice).unwrap_or(&[])
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

    /// TC-411: every distinct SQL constrained-statement caveat reachable
    /// from `roots` (each root plus its full ancestor closure), read purely
    /// from this already-loaded snapshot -- zero additional statements.
    /// Mirrors the persisted-caveat shapes accepted by the historical
    /// per-request database walk (`constrained-statements` value directly,
    /// or nested under a `"constrained-statements"` key); resolving
    /// ambiguity across the returned candidates (zero/one/many) is the
    /// caller's responsibility so SQL-specific fail-closed semantics stay
    /// out of the shared authorization graph.
    ///
    /// A caveat value that *declares* itself as `constrained-statements`
    /// (top-level `mode`, or nested under a `"constrained-statements"` key)
    /// but fails to parse is a malformed declared caveat, not an unrelated
    /// one -- this fails closed with the underlying `RejectionCode` instead
    /// of silently dropping the caveat and leaving SQL unconstrained.
    pub(crate) fn constrained_statement_caveat_candidates(
        &self,
        roots: &[Hash],
    ) -> Result<
        Vec<crate::policy_capability::sql_caveat::SqlConstrainedStatementCaveat>,
        crate::policy_capability::RejectionCode,
    > {
        let mut visited = HashSet::new();
        let mut found = Vec::new();
        for root in roots {
            for id in self.chain_ids_from(root) {
                if !visited.insert(id) {
                    continue;
                }
                for row in self.abilities(&id) {
                    for v in row.caveats.0.values() {
                        if let Some(caveat) = declared_constrained_statement_caveat(v)? {
                            if !found.contains(&caveat) {
                                found.push(caveat);
                            }
                        }
                    }
                }
            }
        }
        Ok(found)
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

    /// Cost characteristics of the low-level `load_from_closure` primitive
    /// in isolation: given a closure already known to be complete for the
    /// connection being read from, it issues only the
    /// delegations/abilities/revocations batch (3 queries) instead of
    /// `load`'s 4 (which re-walks the recursive edge CTE), and depth 4 costs
    /// exactly what depth 1 costs. The production invocation path does NOT
    /// blindly reuse a pre-guard closure this way -- see
    /// `AuthGraphSnapshot::load_guarded` and
    /// `snapshot_load_guarded_fails_closed_on_concurrent_registration` below
    /// for why a pre-guard closure cannot be trusted without re-verification.
    #[tokio::test]
    async fn snapshot_reuses_preguard_closure_without_a_second_edge_query() {
        for depth in [0, 1, 4] {
            let (db, counter) = counted_database().await;
            let ids = insert_chain(&db, &format!("reuse-{depth}"), depth).await;
            let leaf = ids[0];

            let before = counter.load(Ordering::SeqCst);
            let (nodes, parents) = load_closure_edges(&db, &[leaf]).await.unwrap();
            let lock_query_count = counter.load(Ordering::SeqCst) - before;
            assert_eq!(lock_query_count, 1, "depth {depth}: lock-key closure query");

            let before = counter.load(Ordering::SeqCst);
            let snapshot = AuthGraphSnapshot::load_from_closure(&db, nodes, parents)
                .await
                .unwrap();
            let reuse_query_count = counter.load(Ordering::SeqCst) - before;

            assert_eq!(
                reuse_query_count, 3,
                "depth {depth}: reused-closure snapshot query count must be depth-independent"
            );
            assert_eq!(snapshot.chain_ids_from(&leaf).len(), depth + 1);
            // Depth 1 and depth 4 must cost exactly the same: 1 lock-key
            // query + 3 reused-closure snapshot queries, independent of how
            // many ancestors are in the chain.
            if depth == 1 || depth == 4 {
                assert_eq!(
                    lock_query_count, 1,
                    "depth {depth} lock-key cost vs depth 1/4 parity"
                );
                assert_eq!(
                    reuse_query_count, 3,
                    "depth {depth} snapshot cost vs depth 1/4 parity"
                );
            }
        }
    }

    /// TC-411: `load_guarded` re-derives the closure on the guarded
    /// connection and must fail closed when the guarded key set (computed
    /// pre-guard) does not match what is actually reachable now -- the
    /// signature of a delegation whose registration committed while this
    /// invocation was waiting to acquire its chain guard, so the pre-guard
    /// closure never saw the new ancestor edge.
    #[tokio::test]
    async fn snapshot_load_guarded_fails_closed_on_concurrent_registration() {
        let (db, _) = counted_database().await;
        let ids = insert_chain(&db, "race", 1).await;
        let leaf = ids[0];

        // Simulates the pre-guard closure read happening before the
        // ancestor edge (leaf -> ids[1]) is visible: the caller believes
        // `leaf` has no parents and only guards `[leaf]`.
        let stale_guarded_keys = vec![leaf];
        assert!(matches!(
            AuthGraphSnapshot::load_guarded(&db, &[leaf], &stale_guarded_keys).await,
            Err(ChainTraversalError::LimitExceeded)
        ));

        // Once the guarded key set matches what is actually reachable, the
        // same call succeeds and exposes the full chain.
        let complete_guarded_keys = ids.clone();
        let snapshot = AuthGraphSnapshot::load_guarded(&db, &[leaf], &complete_guarded_keys)
            .await
            .unwrap();
        assert_eq!(snapshot.chain_ids_from(&leaf).len(), 2);
    }

    async fn insert_ability(
        db: &DatabaseConnection,
        delegation: Hash,
        caveat_value: serde_json::Value,
    ) {
        use crate::types::Caveats;
        use std::collections::BTreeMap;
        let mut caveats = BTreeMap::new();
        caveats.insert("caveat".to_string(), caveat_value);
        abilities::ActiveModel {
            resource: Set("tinycloud:did:key:actor:files/kv/doc".parse().unwrap()),
            ability: Set("tinycloud.kv/put".to_string().try_into().unwrap()),
            delegation: Set(delegation),
            caveats: Set(Caveats(caveats)),
        }
        .insert(db)
        .await
        .unwrap();
    }

    /// TC-411 regression: a caveat that declares `mode:
    /// "constrained-statements"` directly on the cited root but is missing
    /// required fields (`readOnly`, `statements`) must fail closed rather
    /// than being silently dropped as if the grant were unconstrained.
    #[tokio::test]
    async fn constrained_statement_caveat_candidates_fails_closed_on_malformed_direct_caveat() {
        let (db, _) = counted_database().await;
        let ids = insert_chain(&db, "malformed-direct", 0).await;
        insert_ability(
            &db,
            ids[0],
            serde_json::json!({"mode": "constrained-statements"}),
        )
        .await;

        let snapshot = AuthGraphSnapshot::load(&db, &[ids[0]]).await.unwrap();
        assert!(snapshot
            .constrained_statement_caveat_candidates(&[ids[0]])
            .is_err());
    }

    /// Same as above, but the malformed declaration lives under the nested
    /// `"constrained-statements"` key rather than as a top-level `mode`.
    #[tokio::test]
    async fn constrained_statement_caveat_candidates_fails_closed_on_malformed_nested_caveat() {
        let (db, _) = counted_database().await;
        let ids = insert_chain(&db, "malformed-nested", 0).await;
        insert_ability(
            &db,
            ids[0],
            serde_json::json!({"constrained-statements": {"mode": "constrained-statements"}}),
        )
        .await;

        let snapshot = AuthGraphSnapshot::load(&db, &[ids[0]]).await.unwrap();
        assert!(snapshot
            .constrained_statement_caveat_candidates(&[ids[0]])
            .is_err());
    }

    /// A malformed declared caveat on a strict ancestor (not the cited root
    /// itself) must also fail closed -- `chain_ids_from` walks the whole
    /// closure, so this is not limited to the directly-cited proof.
    #[tokio::test]
    async fn constrained_statement_caveat_candidates_fails_closed_on_malformed_ancestor_caveat() {
        let (db, _) = counted_database().await;
        let ids = insert_chain(&db, "malformed-ancestor", 1).await;
        insert_ability(
            &db,
            ids[1],
            serde_json::json!({"mode": "constrained-statements", "readOnly": "not-a-bool"}),
        )
        .await;

        let snapshot = AuthGraphSnapshot::load(&db, &[ids[0]]).await.unwrap();
        assert!(snapshot
            .constrained_statement_caveat_candidates(&[ids[0]])
            .is_err());
    }

    /// An unrelated caveat (no `mode` field and no nested
    /// `"constrained-statements"` key) is not a declared SQL caveat and must
    /// be silently skipped rather than rejected.
    #[tokio::test]
    async fn constrained_statement_caveat_candidates_ignores_unrelated_caveats() {
        let (db, _) = counted_database().await;
        let ids = insert_chain(&db, "unrelated", 0).await;
        insert_ability(&db, ids[0], serde_json::json!({"tables": ["foo"]})).await;

        let snapshot = AuthGraphSnapshot::load(&db, &[ids[0]]).await.unwrap();
        assert_eq!(
            snapshot
                .constrained_statement_caveat_candidates(&[ids[0]])
                .unwrap(),
            Vec::new()
        );
    }

    /// TC-411 regression: a cyclic `parent_delegations` closure must fail
    /// closed. A per-node traversal's visited set would silently terminate
    /// against the cycle and accept the chain instead.
    #[tokio::test]
    async fn load_closure_edges_fails_closed_on_cyclic_proof() {
        let (db, _) = counted_database().await;
        let a = hash(b"cycle-a");
        let b = hash(b"cycle-b");
        insert_delegation(&db, a).await;
        insert_delegation(&db, b).await;
        insert_edge(&db, a, b).await;
        insert_edge(&db, b, a).await;

        assert!(matches!(
            load_closure_edges(&db, &[a]).await,
            Err(ChainTraversalError::LimitExceeded)
        ));
        assert!(matches!(
            AuthGraphSnapshot::load(&db, &[a]).await,
            Err(ChainTraversalError::LimitExceeded)
        ));
    }

    /// TC-411 regression: a wide (fan-out) graph can hold far more distinct
    /// nodes than `MAX_CHAIN_TRAVERSAL_NODES` while its edge count stays far
    /// below `edge_cap` (`MAX_CHAIN_TRAVERSAL_NODES^2`), since each node
    /// here has only one edge. The distinct-node bound must reject this
    /// before `has_cycle`'s recursion ever runs over it -- the `rows.len() >
    /// edge_cap` check alone would let it through.
    #[tokio::test]
    async fn load_closure_edges_fails_closed_on_wide_over_limit_graph() {
        let (db, _) = counted_database().await;
        let leaf = hash(b"wide-leaf");
        insert_delegation(&db, leaf).await;
        for index in 0..=MAX_CHAIN_TRAVERSAL_NODES {
            let parent = hash(format!("wide-parent-{index}").as_bytes());
            insert_delegation(&db, parent).await;
            insert_edge(&db, leaf, parent).await;
        }

        assert!(matches!(
            load_closure_edges(&db, &[leaf]).await,
            Err(ChainTraversalError::LimitExceeded)
        ));
        assert!(matches!(
            AuthGraphSnapshot::load(&db, &[leaf]).await,
            Err(ChainTraversalError::LimitExceeded)
        ));
    }
}

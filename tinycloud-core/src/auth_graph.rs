//! TC-269: transaction-scoped authorization graph snapshot for the
//! production invocation path.
//!
//! Instead of walking `parent_delegations` one node at a time, a single
//! transaction-scoped query returns tagged parent edges, delegation rows,
//! ability/caveat rows, and revocations for the entire proof closure. Rust
//! reconstructs the same snapshot and performs all chain checks in memory
//! against that consistent view.

use crate::hash::Hash;
use crate::models::{abilities, delegation, delegation_cid_alias, revocation};
use crate::relationships::parent_delegations;
use sea_orm::{
    entity::prelude::*,
    sea_query::{
        Alias, CommonTableExpression, Expr, JoinType, Query, SelectStatement, SimpleExpr,
        UnionType, WithClause, WithQuery,
    },
    ConnectionTrait,
};
use std::collections::{HashMap, HashSet};

pub(crate) use crate::models::revocation::ChainTraversalError;
use crate::models::revocation::MAX_CHAIN_TRAVERSAL_NODES;

/// Batched ancestor-closure load over `parent_delegations`. A recursive CTE
/// fetches all reachable edges in one query rather than walking one node at a
/// time. The in-memory pass enforces the same fail-closed node budget as the
/// per-node traversal used by the delegate/revoke paths. Production locks use
/// `load_chain_lock_ids`; tests keep this as the sequential edge oracle.
#[cfg(test)]
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

/// Each branch projects the same columns, with a distinct slot for each
/// underlying SQL type. In particular, JSON and text never share a UNION
/// slot, and the legacy model decoders still parse every field in Rust.
fn snapshot_branch<const N: usize>(kind: i32, fields: [SimpleExpr; N]) -> SelectStatement {
    let mut query = Query::select();
    query.expr_as(Expr::val(kind), Alias::new("kind"));
    let names = [
        "node",
        "parent",
        "delegator",
        "delegatee",
        "expiry",
        "issued_at",
        "not_before",
        "facts",
        "serialization",
        "serialization_format",
        "resource",
        "ability",
        "caveats",
        "renewal_original",
        "lease_cid",
        "lease_state",
        "lease_generation",
        "renewer_did",
        "renewer_epoch",
        "lease_expiry",
        "lease_original_expiry",
        "lease_period",
        "audience_key",
        "stamp_cid",
        "previous_stamp_cid",
        "stamp_epoch",
        "stamp_end",
        "signed_bytes",
        "signature",
        "lease_revoked",
        "stamp_generation",
    ];
    for (name, expr) in names.iter().zip(fields) {
        query.expr_as(expr, Alias::new(*name));
    }
    if N == 13 {
        let null = || Expr::cust("NULL");
        let extra: [SimpleExpr; 18] = if kind == 4 {
            [
                Expr::col((
                    Alias::new("renewal_lease"),
                    Alias::new("original_canonical"),
                ))
                .into(),
                Expr::col((Alias::new("renewal_lease"), Alias::new("lease_cid"))).into(),
                Expr::col((Alias::new("renewal_lease"), Alias::new("state"))).into(),
                Expr::col((Alias::new("renewal_lease"), Alias::new("generation"))).into(),
                Expr::col((Alias::new("renewal_lease"), Alias::new("renewer_did"))).into(),
                Expr::col((Alias::new("renewal_lease"), Alias::new("renewer_epoch"))).into(),
                Expr::col((Alias::new("renewal_lease"), Alias::new("lease_expiry"))).into(),
                Expr::col((Alias::new("renewal_lease"), Alias::new("original_expiry"))).into(),
                Expr::col((Alias::new("renewal_lease"), Alias::new("period_seconds"))).into(),
                Expr::col((
                    Alias::new("renewal_lease"),
                    Alias::new("audience_public_key"),
                ))
                .into(),
                Expr::col((Alias::new("renewal_stamp"), Alias::new("cid"))).into(),
                Expr::col((
                    Alias::new("renewal_stamp"),
                    Alias::new("previous_stamp_cid"),
                ))
                .into(),
                Expr::col((Alias::new("renewal_stamp"), Alias::new("renewer_epoch"))).into(),
                Expr::col((Alias::new("renewal_stamp"), Alias::new("new_end"))).into(),
                Expr::col((Alias::new("renewal_stamp"), Alias::new("signed_bytes"))).into(),
                Expr::col((Alias::new("renewal_stamp"), Alias::new("signature"))).into(),
                Expr::cust("FALSE"),
                Expr::col((Alias::new("renewal_stamp"), Alias::new("generation"))).into(),
            ]
        } else {
            std::array::from_fn(|_| null())
        };
        for (name, expr) in names.iter().skip(13).zip(extra) {
            query.expr_as(expr, Alias::new(*name));
        }
    }
    query
}

fn snapshot_query(roots: &[Hash]) -> WithQuery {
    let roots_name = Alias::new("proof_roots");
    let edges_name = Alias::new("authorization_edges");
    let bounded_name = Alias::new("bounded_edges");
    let nodes_name = Alias::new("graph_nodes");
    let lookup_name = Alias::new("lookup_nodes");
    let id = Alias::new("id");
    let child = Alias::new("child");
    let parent = Alias::new("parent");

    let mut root_query = Query::select();
    root_query.expr_as(Expr::val(roots[0]), id.clone());
    for root in roots.iter().skip(1) {
        root_query.union(
            UnionType::Distinct,
            Query::select().expr(Expr::val(*root)).to_owned(),
        );
    }
    let roots_cte = CommonTableExpression::new()
        .table_name(roots_name.clone())
        .column(id.clone())
        .query(root_query)
        .to_owned();

    let base = Query::select()
        .columns([
            parent_delegations::Column::Child,
            parent_delegations::Column::Parent,
        ])
        .from(parent_delegations::Entity)
        .and_where(
            Expr::col(parent_delegations::Column::Child).in_subquery(
                Query::select()
                    .column((roots_name.clone(), id.clone()))
                    .from(roots_name.clone())
                    .to_owned(),
            ),
        )
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
            edges_name.clone(),
            Expr::col((
                parent_delegations::Entity,
                parent_delegations::Column::Child,
            ))
            .equals((edges_name.clone(), parent.clone())),
        )
        .to_owned();
    let mut closure_query = base;
    closure_query.union(UnionType::Distinct, recursive);
    let edges_cte = CommonTableExpression::new()
        .table_name(edges_name.clone())
        .columns([child.clone(), parent.clone()])
        .query(closure_query)
        .to_owned();

    let edge_cap = MAX_CHAIN_TRAVERSAL_NODES * MAX_CHAIN_TRAVERSAL_NODES;
    let bounded_cte = CommonTableExpression::new()
        .table_name(bounded_name.clone())
        .columns([child.clone(), parent.clone()])
        .query(
            Query::select()
                .columns([
                    (edges_name.clone(), child.clone()),
                    (edges_name.clone(), parent.clone()),
                ])
                .from(edges_name)
                .limit((edge_cap + 1) as u64)
                .to_owned(),
        )
        .to_owned();
    let mut node_query = Query::select()
        .column((roots_name.clone(), id.clone()))
        .from(roots_name)
        .to_owned();
    node_query.union(
        UnionType::Distinct,
        Query::select()
            .column((bounded_name.clone(), child.clone()))
            .from(bounded_name.clone())
            .to_owned(),
    );
    node_query.union(
        UnionType::Distinct,
        Query::select()
            .column((bounded_name.clone(), parent.clone()))
            .from(bounded_name.clone())
            .to_owned(),
    );
    let nodes_cte = CommonTableExpression::new()
        .table_name(nodes_name.clone())
        .column(id.clone())
        .query(node_query)
        .to_owned();
    // The authorization limit is 64 nodes. Keep one sentinel in the planner-
    // visible metadata input; within_budget still counts every node from the
    // edge-bounded graph_nodes result, so truncation cannot authorize a chain.
    let lookup_cte = CommonTableExpression::new()
        .table_name(lookup_name.clone())
        .column(id.clone())
        .query(
            Query::select()
                .column((nodes_name.clone(), id.clone()))
                .from(nodes_name.clone())
                .limit((MAX_CHAIN_TRAVERSAL_NODES + 1) as u64)
                .to_owned(),
        )
        .to_owned();
    let null = || Expr::cust("NULL");
    let field = |table: Alias, column: Alias| Expr::col((table, column)).into();
    let node = |table: Alias| Expr::col((table, id.clone())).into();
    let within_budget = || {
        Expr::cust(format!(
            "(SELECT COUNT(*) FROM graph_nodes) <= {} AND (SELECT COUNT(*) FROM bounded_edges) <= {}",
            MAX_CHAIN_TRAVERSAL_NODES, edge_cap
        ))
    };
    // A zero-row type anchor precedes UNION ALL. PostgreSQL resolves an
    // untyped NULL in the first branch to text before seeing later branches;
    // selecting real columns here preserves timestamp/JSON/binary SQL types
    // without backend-specific casts or an extra database round trip.
    let mut query = snapshot_branch(
        4,
        [
            Expr::col((delegation::Entity, delegation::Column::Id)).into(),
            Expr::col((
                parent_delegations::Entity,
                parent_delegations::Column::Parent,
            ))
            .into(),
            Expr::col((delegation::Entity, delegation::Column::Delegator)).into(),
            Expr::col((delegation::Entity, delegation::Column::Delegatee)).into(),
            Expr::col((delegation::Entity, delegation::Column::Expiry)).into(),
            Expr::col((delegation::Entity, delegation::Column::IssuedAt)).into(),
            Expr::col((delegation::Entity, delegation::Column::NotBefore)).into(),
            Expr::col((delegation::Entity, delegation::Column::Facts)).into(),
            Expr::col((delegation::Entity, delegation::Column::Serialization)).into(),
            Expr::col((delegation::Entity, delegation::Column::SerializationFormat)).into(),
            Expr::col((abilities::Entity, abilities::Column::Resource)).into(),
            Expr::col((abilities::Entity, abilities::Column::Ability)).into(),
            Expr::col((abilities::Entity, abilities::Column::Caveats)).into(),
        ],
    );
    query
        .from(delegation::Entity)
        .from(parent_delegations::Entity)
        .from(abilities::Entity)
        .from(Alias::new("renewal_lease"))
        .from(Alias::new("renewal_stamp"))
        .and_where(Expr::val(1).eq(0));
    let mut edge_rows = snapshot_branch(
        0,
        [
            field(bounded_name.clone(), child),
            field(bounded_name.clone(), parent),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
        ],
    );
    edge_rows.from(bounded_name.clone());
    query.union(UnionType::All, edge_rows);
    let mut delegations = snapshot_branch(
        1,
        [
            node(lookup_name.clone()),
            null(),
            Expr::col((delegation::Entity, delegation::Column::Delegator)).into(),
            Expr::col((delegation::Entity, delegation::Column::Delegatee)).into(),
            Expr::col((delegation::Entity, delegation::Column::Expiry)).into(),
            Expr::col((delegation::Entity, delegation::Column::IssuedAt)).into(),
            Expr::col((delegation::Entity, delegation::Column::NotBefore)).into(),
            Expr::col((delegation::Entity, delegation::Column::Facts)).into(),
            Expr::col((delegation::Entity, delegation::Column::Serialization)).into(),
            Expr::col((delegation::Entity, delegation::Column::SerializationFormat)).into(),
            null(),
            null(),
            null(),
        ],
    );
    delegations
        .from(delegation::Entity)
        .join(
            JoinType::InnerJoin,
            lookup_name.clone(),
            Expr::col((delegation::Entity, delegation::Column::Id))
                .equals((lookup_name.clone(), id.clone())),
        )
        .and_where(within_budget());
    query.union(UnionType::All, delegations);
    let mut abilities_query = snapshot_branch(
        2,
        [
            node(lookup_name.clone()),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            Expr::col((abilities::Entity, abilities::Column::Resource)).into(),
            Expr::col((abilities::Entity, abilities::Column::Ability)).into(),
            Expr::col((abilities::Entity, abilities::Column::Caveats)).into(),
        ],
    );
    abilities_query
        .from(abilities::Entity)
        .join(
            JoinType::InnerJoin,
            lookup_name.clone(),
            Expr::col((abilities::Entity, abilities::Column::Delegation))
                .equals((lookup_name.clone(), id.clone())),
        )
        .and_where(within_budget());
    query.union(UnionType::All, abilities_query);
    let revocation_fields = || {
        let mut fields: [SimpleExpr; 13] = std::array::from_fn(|_| null());
        fields[0] = node(lookup_name.clone());
        fields
    };
    let mut revocations = snapshot_branch(3, revocation_fields());
    revocations
        .from(revocation::Entity)
        .join(
            JoinType::InnerJoin,
            lookup_name.clone(),
            Expr::col((revocation::Entity, revocation::Column::Revoked))
                .equals((lookup_name.clone(), id.clone())),
        )
        .and_where(within_budget());
    query.union(UnionType::All, revocations);
    // TC-1071: revoking any stored encoding revokes every encoding with the
    // same canonical identity. This mirrors `revocation::effective_rows`'
    // alias branch inside the same statement; signed targets stay unchanged.
    let source = Alias::new("revocation_source_alias");
    let target = Alias::new("revocation_target_alias");
    let mut aliased_revocations = snapshot_branch(3, revocation_fields());
    aliased_revocations
        .from(lookup_name.clone())
        .join_as(
            JoinType::InnerJoin,
            delegation_cid_alias::Entity,
            source.clone(),
            Expr::col((source.clone(), delegation_cid_alias::Column::Id))
                .equals((lookup_name.clone(), id.clone())),
        )
        .join_as(
            JoinType::InnerJoin,
            delegation_cid_alias::Entity,
            target.clone(),
            Expr::col((source, delegation_cid_alias::Column::Canonical))
                .equals((target.clone(), delegation_cid_alias::Column::Canonical)),
        )
        .join(
            JoinType::InnerJoin,
            revocation::Entity,
            Expr::col((target, delegation_cid_alias::Column::Id))
                .equals((revocation::Entity, revocation::Column::Revoked)),
        )
        .and_where(within_budget());
    query.union(UnionType::All, aliased_revocations);
    let lease = Alias::new("renewal_lease");
    let stamp = Alias::new("renewal_stamp");
    let original_alias = Alias::new("renewal_original_alias");
    let renewal_revoked = Expr::cust(format!(
        "EXISTS (WITH RECURSIVE lease_chain(id, depth) AS (SELECT renewal_lease.lease_cid, 0 UNION ALL SELECT p.parent, c.depth + 1 FROM parent_delegation p JOIN lease_chain c ON p.child = c.id WHERE c.depth < {MAX_CHAIN_TRAVERSAL_NODES}) SELECT 1 FROM lease_chain c JOIN revocation r ON r.revoked = c.id) OR EXISTS (WITH RECURSIVE lease_chain(id, depth) AS (SELECT renewal_lease.lease_cid, 0 UNION ALL SELECT p.parent, c.depth + 1 FROM parent_delegation p JOIN lease_chain c ON p.child = c.id WHERE c.depth < {MAX_CHAIN_TRAVERSAL_NODES}) SELECT 1 FROM lease_chain c JOIN delegation_cid_alias a ON a.id = c.id JOIN delegation_cid_alias other ON other.canonical = a.canonical JOIN revocation r ON r.revoked = other.id) OR EXISTS (WITH RECURSIVE lease_chain(id, depth) AS (SELECT renewal_lease.lease_cid, 0 UNION ALL SELECT p.parent, c.depth + 1 FROM parent_delegation p JOIN lease_chain c ON p.child = c.id WHERE c.depth < {MAX_CHAIN_TRAVERSAL_NODES}) SELECT 1 FROM lease_chain c JOIN parent_delegation p ON p.child = c.id WHERE c.depth = {MAX_CHAIN_TRAVERSAL_NODES})"
    ));
    let mut renewal_rows = snapshot_branch(
        5,
        [
            node(lookup_name.clone()),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            null(),
            Expr::col((lease.clone(), Alias::new("original_canonical"))).into(),
            Expr::col((lease.clone(), Alias::new("lease_cid"))).into(),
            Expr::col((lease.clone(), Alias::new("state"))).into(),
            Expr::col((lease.clone(), Alias::new("generation"))).into(),
            Expr::col((lease.clone(), Alias::new("renewer_did"))).into(),
            Expr::col((lease.clone(), Alias::new("renewer_epoch"))).into(),
            Expr::col((lease.clone(), Alias::new("lease_expiry"))).into(),
            Expr::col((lease.clone(), Alias::new("original_expiry"))).into(),
            Expr::col((lease.clone(), Alias::new("period_seconds"))).into(),
            Expr::col((lease.clone(), Alias::new("audience_public_key"))).into(),
            Expr::col((stamp.clone(), Alias::new("cid"))).into(),
            Expr::col((stamp.clone(), Alias::new("previous_stamp_cid"))).into(),
            Expr::col((stamp.clone(), Alias::new("renewer_epoch"))).into(),
            Expr::col((stamp.clone(), Alias::new("new_end"))).into(),
            Expr::col((stamp.clone(), Alias::new("signed_bytes"))).into(),
            Expr::col((stamp.clone(), Alias::new("signature"))).into(),
            renewal_revoked,
            Expr::col((stamp.clone(), Alias::new("generation"))).into(),
        ],
    );
    renewal_rows
        .from(lease.clone())
        .join(
            JoinType::InnerJoin,
            stamp.clone(),
            Expr::col((stamp.clone(), Alias::new("original_canonical")))
                .equals((lease.clone(), Alias::new("original_canonical")))
                .and(
                    Expr::col((stamp.clone(), Alias::new("lease_cid")))
                        .equals((lease.clone(), Alias::new("lease_cid"))),
                ),
        )
        .join_as(
            JoinType::InnerJoin,
            delegation_cid_alias::Entity,
            original_alias.clone(),
            Expr::col((
                original_alias.clone(),
                delegation_cid_alias::Column::Canonical,
            ))
            .equals((lease.clone(), Alias::new("original_canonical"))),
        )
        .join(
            JoinType::InnerJoin,
            lookup_name.clone(),
            Expr::col((original_alias, delegation_cid_alias::Column::Id))
                .equals((lookup_name.clone(), id.clone())),
        )
        .and_where(within_budget())
        .and_where(Expr::cust(
            "renewal_lease.lease_cid = renewal_stamp.lease_cid",
        ));
    query.union(UnionType::All, renewal_rows);
    query.with(
        WithClause::new()
            .recursive(true)
            .cte(roots_cte)
            .cte(edges_cte)
            .cte(bounded_cte)
            .cte(nodes_cte)
            .cte(lookup_cte)
            .to_owned(),
    )
}

// The old metadata query had no ORDER BY. Authorization accepts any matching
// ability, but the last rejected caveat supplies a diagnostic reason. Use the
// typed `(resource, ability)` order on every backend; only that diagnostic can
// differ from the old backend-dependent order.
fn sort_abilities(abilities: &mut HashMap<Hash, Vec<abilities::Model>>) {
    for rows in abilities.values_mut() {
        rows.sort_unstable_by(|left, right| {
            left.resource
                .cmp(&right.resource)
                .then_with(|| left.ability.cmp(&right.ability))
        });
    }
}
#[derive(Clone)]
struct RenewalCandidate {
    node: Hash,
    original: String,
    state: String,
    lease: String,
    stamp: String,
    previous: String,
    generation: u64,
    end: i64,
    signed_bytes: Vec<u8>,
    signature: Vec<u8>,
    did: String,
    epoch: u64,
    audience: [u8; 32],
    now: i64,
    period: i64,
    lease_expiry: i64,
    original_expiry: i64,
}
fn cap_effective_end(signed_end: i64, renewed_end: Option<i64>, ancestor_ends: &[i64]) -> i64 {
    let own_end = renewed_end.map_or(signed_end, |end| signed_end.max(end));
    ancestor_ends
        .iter()
        .copied()
        .min()
        .map_or(own_end, |cap| own_end.min(cap))
}
fn resolve_effective_end(
    id: Hash,
    parents: &HashMap<Hash, Vec<Hash>>,
    delegations: &HashMap<Hash, delegation::Model>,
    candidates: &HashMap<Hash, Vec<RenewalCandidate>>,
    revoked: &HashSet<Hash>,
    resolved: &mut HashMap<Hash, i64>,
    visiting: &mut HashSet<Hash>,
) -> Option<i64> {
    if let Some(end) = resolved.get(&id) {
        return Some(*end);
    }
    if revoked.contains(&id) {
        visiting.remove(&id);
        return None;
    }
    let result = (|| {
        let signed_end = delegations
            .get(&id)?
            .expiry
            .map_or(i64::MAX, |expiry| expiry.unix_timestamp());
        let mut ancestor_ends = Vec::new();
        for parent in parents.get(&id).into_iter().flatten() {
            ancestor_ends.push(resolve_effective_end(
                *parent,
                parents,
                delegations,
                candidates,
                revoked,
                resolved,
                visiting,
            )?);
        }
        let mut renewed_end = None;
        if let Some(rows) = candidates.get(&id) {
            let mut expected_previous = rows.first()?.lease.clone();
            let mut used = HashSet::new();
            loop {
                let matching = rows
                    .iter()
                    .enumerate()
                    .filter(|(_, candidate)| candidate.previous == expected_previous)
                    .collect::<Vec<_>>();
                if matching.is_empty() {
                    break;
                }
                if matching.len() != 1 {
                    return None;
                }
                let (index, candidate) = matching[0];
                let latest_allowed = candidate.now.checked_add(candidate.period)?;
                let stamp_verifier_now = candidate.end.checked_sub(1)?;
                if candidate.original_expiry != signed_end
                    || candidate.end > latest_allowed
                    || used.contains(&index)
                    || crate::renewal::verify_snapshot_stamp(
                        crate::renewal::SnapshotStampVerification {
                            signed_bytes: &candidate.signed_bytes,
                            signature_bytes: &candidate.signature,
                            expected_stamp_cid: &candidate.stamp,
                            expected_original_cid: &candidate.original,
                            expected_lease_cid: &candidate.lease,
                            generation: candidate.generation,
                            previous_stamp_cid: &candidate.previous,
                            new_end: candidate.end,
                            node_did: &candidate.did,
                            renewer_epoch: candidate.epoch,
                            audience_public_key: &candidate.audience,
                            verifier_now: stamp_verifier_now,
                            period: candidate.period,
                            lease_expiry: candidate.lease_expiry,
                            ancestor_ends: &ancestor_ends,
                        },
                    )
                    .is_err()
                {
                    return None;
                }
                used.insert(index);
                expected_previous = candidate.stamp.clone();
                renewed_end =
                    Some(renewed_end.map_or(candidate.end, |end: i64| end.max(candidate.end)));
            }
            if used.len() != rows.len() {
                return None;
            }
        }
        Some(cap_effective_end(signed_end, renewed_end, &ancestor_ends))
    })();
    visiting.remove(&id);
    if let Some(end) = result {
        resolved.insert(id, end);
    }
    result
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AuthGraphSnapshot {
    parents: HashMap<Hash, Vec<Hash>>,
    delegations: HashMap<Hash, delegation::Model>,
    abilities: HashMap<Hash, Vec<abilities::Model>>,
    revoked: HashSet<Hash>,
    renewal_effective_ends: HashMap<Hash, i64>,
}

impl AuthGraphSnapshot {
    /// Batch-load the authorization graph for the given proof roots on the
    /// supplied connection (the invocation transaction in production).
    pub(crate) async fn load<C: ConnectionTrait>(
        db: &C,
        roots: &[Hash],
    ) -> Result<Self, ChainTraversalError> {
        Self::load_inner(db, roots, None).await
    }

    pub(crate) async fn load_with_renewal_identity<C: ConnectionTrait>(
        db: &C,
        roots: &[Hash],
        stable_node_did: &str,
        renewer_did: &str,
        epoch: u64,
        verifier_now: i64,
    ) -> Result<Self, ChainTraversalError> {
        Self::load_inner(
            db,
            roots,
            Some((stable_node_did, renewer_did, epoch, verifier_now)),
        )
        .await
    }

    async fn load_inner<C: ConnectionTrait>(
        db: &C,
        roots: &[Hash],
        identity: Option<(&str, &str, u64, i64)>,
    ) -> Result<Self, ChainTraversalError> {
        let mut nodes = roots.to_vec();
        nodes.dedup();
        if nodes.len() > MAX_CHAIN_TRAVERSAL_NODES {
            return Err(ChainTraversalError::LimitExceeded);
        }
        if nodes.is_empty() {
            return Ok(Self {
                parents: HashMap::new(),
                delegations: HashMap::new(),
                abilities: HashMap::new(),
                revoked: HashSet::new(),
                renewal_effective_ends: HashMap::new(),
            });
        }

        let rows = db
            .query_all(db.get_database_backend().build(&snapshot_query(&nodes)))
            .await?;
        let mut parents: HashMap<Hash, Vec<Hash>> = HashMap::new();
        let mut delegations = HashMap::new();
        let mut abilities: HashMap<Hash, Vec<abilities::Model>> = HashMap::new();
        let mut revoked = HashSet::new();
        let mut renewal_candidates = Vec::new();
        let mut edge_count = 0;
        for row in rows {
            let node: Hash = row.try_get("", "node")?;
            match row.try_get::<i32>("", "kind")? {
                0 => {
                    edge_count += 1;
                    if edge_count > MAX_CHAIN_TRAVERSAL_NODES * MAX_CHAIN_TRAVERSAL_NODES {
                        return Err(ChainTraversalError::LimitExceeded);
                    }
                    parents
                        .entry(node)
                        .or_default()
                        .push(row.try_get("", "parent")?);
                }
                1 => {
                    delegations.insert(
                        node,
                        delegation::Model {
                            id: node,
                            delegator: row.try_get("", "delegator")?,
                            delegatee: row.try_get("", "delegatee")?,
                            expiry: row.try_get("", "expiry")?,
                            issued_at: row.try_get("", "issued_at")?,
                            not_before: row.try_get("", "not_before")?,
                            facts: row.try_get("", "facts")?,
                            serialization: row.try_get("", "serialization")?,
                            serialization_format: row.try_get("", "serialization_format")?,
                        },
                    );
                }
                2 => {
                    abilities.entry(node).or_default().push(abilities::Model {
                        delegation: node,
                        resource: row.try_get("", "resource")?,
                        ability: row.try_get("", "ability")?,
                        caveats: row.try_get("", "caveats")?,
                    });
                }
                3 => {
                    revoked.insert(node);
                }
                5 => {
                    let Some((stable_node_did, renewer_did, epoch, verifier_now)) = identity else {
                        continue;
                    };
                    let state: String = row.try_get("", "lease_state")?;
                    let lease_expiry: time::OffsetDateTime = row.try_get("", "lease_expiry")?;
                    if state != "active"
                        || lease_expiry.unix_timestamp() <= verifier_now
                        || row.try_get::<bool>("", "lease_revoked")?
                        || row.try_get::<String>("", "renewer_did")? != renewer_did
                    {
                        continue;
                    }
                    let renewer_epoch: i64 = row.try_get("", "renewer_epoch")?;
                    let stamp_epoch: i64 = row.try_get("", "stamp_epoch")?;
                    let stamp_generation: i64 = row.try_get("", "stamp_generation")?;
                    let period: i64 = row.try_get("", "lease_period")?;
                    if renewer_epoch as u64 != epoch
                        || stamp_epoch as u64 != epoch
                        || stamp_generation < 0
                        || period <= 0
                    {
                        continue;
                    }
                    let cid = |name: &str| -> Result<String, ChainTraversalError> {
                        Ok(Hash::try_from(row.try_get::<Vec<u8>>("", name)?)
                            .map_err(DbErr::from)?
                            .to_cid(0x55)
                            .to_string())
                    };
                    let audience: Vec<u8> = row.try_get("", "audience_key")?;
                    let Ok(audience): Result<[u8; 32], _> = audience.try_into() else {
                        continue;
                    };
                    let end: time::OffsetDateTime = row.try_get("", "stamp_end")?;
                    let original_expiry: time::OffsetDateTime =
                        row.try_get("", "lease_original_expiry")?;
                    renewal_candidates.push(RenewalCandidate {
                        node,
                        state,
                        original: cid("renewal_original")?,
                        lease: cid("lease_cid")?,
                        stamp: cid("stamp_cid")?,
                        previous: cid("previous_stamp_cid")?,
                        generation: stamp_generation as u64,
                        end: end.unix_timestamp(),
                        signed_bytes: row.try_get("", "signed_bytes")?,
                        signature: row.try_get("", "signature")?,
                        did: stable_node_did.to_owned(),
                        epoch,
                        audience,
                        now: verifier_now,
                        period,
                        lease_expiry: lease_expiry.unix_timestamp(),
                        original_expiry: original_expiry.unix_timestamp(),
                    });
                }
                _ => return Err(DbErr::Type("unknown authorization graph row".into()).into()),
            }
        }
        for ancestor_ids in parents.values_mut() {
            ancestor_ids.sort_by(|left, right| left.as_ref().cmp(right.as_ref()));
            ancestor_ids.dedup();
        }
        sort_abilities(&mut abilities);
        let mut visited = nodes.iter().copied().collect::<HashSet<_>>();
        let mut frontier = nodes.clone();
        while let Some(current) = frontier.pop() {
            for parent in parents.get(&current).map(Vec::as_slice).unwrap_or(&[]) {
                if visited.insert(*parent) {
                    if visited.len() > MAX_CHAIN_TRAVERSAL_NODES {
                        return Err(ChainTraversalError::LimitExceeded);
                    }
                    nodes.push(*parent);
                    frontier.push(*parent);
                }
            }
        }

        let mut grouped: HashMap<Hash, HashMap<String, Vec<RenewalCandidate>>> = HashMap::new();
        for candidate in renewal_candidates {
            grouped
                .entry(candidate.node)
                .or_default()
                .entry(candidate.lease.clone())
                .or_default()
                .push(candidate);
        }
        let mut candidate_map: HashMap<Hash, Vec<RenewalCandidate>> = HashMap::new();
        for (node, leases) in grouped {
            let active: Vec<_> = leases
                .values()
                .filter(|rows| rows[0].state == "active")
                .collect();
            if active.len() == 1 {
                candidate_map.insert(node, active[0].clone());
            }
        }
        let mut renewal_effective_ends = HashMap::new();
        let mut resolving = HashSet::new();
        for id in nodes.iter().copied() {
            let _ = resolve_effective_end(
                id,
                &parents,
                &delegations,
                &candidate_map,
                &revoked,
                &mut renewal_effective_ends,
                &mut resolving,
            );
        }
        Ok(Self {
            parents,
            delegations,
            abilities,
            revoked,
            renewal_effective_ends,
        })
    }
    pub(crate) fn effective_expiry(&self, id: &Hash) -> Option<i64> {
        self.renewal_effective_ends.get(id).copied()
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

    /// Whether a direct parent of `start` is revoked.
    pub(crate) fn has_revoked_parent(&self, start: &Hash) -> bool {
        self.parents
            .get(start)
            .is_some_and(|parents| parents.iter().any(|parent| self.revoked.contains(parent)))
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
    #[test]
    fn renewal_extension_can_exceed_signed_expiry_but_not_ancestor_end() {
        assert_eq!(cap_effective_end(100, Some(200), &[250]), 200);
        assert_eq!(cap_effective_end(100, Some(200), &[150]), 150);
    }
    use super::*;
    use crate::hash::hash;
    use crate::migrations::Migrator;
    use crate::models::actor;
    use crate::types::{Caveats, Facts};
    use sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection,
        DbBackend, EntityTrait, QueryFilter, Statement, Value,
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

    fn db_datetime(unix: i64) -> time::PrimitiveDateTime {
        let utc = OffsetDateTime::from_unix_timestamp(unix)
            .unwrap()
            .to_offset(time::UtcOffset::UTC);
        utc.date().with_time(utc.time())
    }

    #[allow(clippy::too_many_arguments)]
    async fn insert_snapshot_renewal(
        db: &DatabaseConnection,
        original: Hash,
        lease: Hash,
        ancestor: Hash,
        original_end: i64,
        ancestor_end: i64,
        now: i64,
        broken_predecessor: bool,
    ) -> (String, String, u64) {
        let backend = DbBackend::Sqlite;
        let (renewer_did, epoch, audience) = crate::renewal::renewal_identity_from_seed([7; 32]);
        let stable_node_did = "did:key:stable-node".to_owned();
        let signer =
            crate::renewal::RenewalSigner::from_seed([7; 32], stable_node_did.clone(), epoch);
        for (id, expiry) in [
            (original, original_end),
            (lease, now + 5_000),
            (ancestor, ancestor_end),
        ] {
            db.execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO delegation (id, delegator, delegatee, expiry, issued_at, not_before, facts, serialization, serialization_format) VALUES ($1,'did:key:actor','did:key:actor',$2,NULL,NULL,NULL,$3,0)",
                [
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(id)))),
                    Value::TimeDateTime(Some(Box::new(db_datetime(expiry)))),
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(id)))),
                ],
            )).await.unwrap();
            db.execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO delegation_cid_alias (id, canonical, encrypted) VALUES ($1,$1,FALSE)",
                [Value::Bytes(Some(Box::new(Vec::<u8>::from(id))))],
            ))
            .await
            .unwrap();
        }
        for child in [original, lease] {
            db.execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO parent_delegation (parent, child) VALUES ($1,$2)",
                [
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(ancestor)))),
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(child)))),
                ],
            ))
            .await
            .unwrap();
        }
        db.execute(Statement::from_sql_and_values(
            backend,
            "INSERT INTO renewal_lease (original_canonical, lease_cid, state, generation, grantor, renewer_did, renewer_epoch, lease_expiry, original_expiry, period_seconds, audience_public_key) VALUES ($1,$2,'active',1,'did:key:actor',$3,$4,$5,$6,5000,$7)",
            [
                Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
                Value::Bytes(Some(Box::new(Vec::<u8>::from(lease)))),
                Value::String(Some(Box::new(renewer_did.clone()))),
                Value::BigInt(Some(epoch as i64)),
                Value::TimeDateTime(Some(Box::new(db_datetime(now + 5_000)))),
                Value::TimeDateTime(Some(Box::new(db_datetime(original_end)))),
                Value::Bytes(Some(Box::new(audience.to_vec()))),
            ],
        )).await.unwrap();
        let original_cid = original.to_cid(0x55).to_string();
        let lease_cid = lease.to_cid(0x55).to_string();
        let mut previous = if broken_predecessor {
            hash(b"orphan-predecessor")
        } else {
            lease
        };
        for end in [now + 1_100, now + 1_200] {
            let end_text = OffsetDateTime::from_unix_timestamp(end)
                .unwrap()
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap();
            let (bytes, signature, _) = signer
                .sign_stamp(
                    &original_cid,
                    &lease_cid,
                    1,
                    &previous.to_cid(0x55).to_string(),
                    &end_text,
                )
                .unwrap();
            let stamp_hash = hash(&bytes);
            db.execute(Statement::from_sql_and_values(
                backend,
                "INSERT INTO renewal_stamp (cid, original_canonical, lease_cid, generation, previous_stamp_cid, renewer_epoch, new_end, signed_bytes, signature, replay_hash) VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8,$9)",
                [
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(stamp_hash)))),
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(original)))),
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(lease)))),
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(previous)))),
                    Value::BigInt(Some(epoch as i64)),
                    Value::TimeDateTime(Some(Box::new(db_datetime(end)))),
                    Value::Bytes(Some(Box::new(bytes.clone()))),
                    Value::Bytes(Some(Box::new(signature))),
                    Value::Bytes(Some(Box::new(hash(&bytes).as_ref().to_vec()))),
                ],
            )).await.unwrap();
            previous = stamp_hash;
        }
        (stable_node_did, renewer_did, epoch)
    }
    #[tokio::test]
    async fn snapshot_verifies_stamp_history_caps_expiry_and_fails_closed() {
        let (db, counter) = counted_database().await;
        let original = hash(b"snapshot-renewal-original");
        let lease = hash(b"snapshot-renewal-lease");
        let ancestor = hash(b"snapshot-renewal-ancestor");
        let (stable_did, renewer_did, epoch) =
            insert_snapshot_renewal(&db, original, lease, ancestor, 2_000, 2_250, 1_000, false)
                .await;
        assert_ne!(stable_did, renewer_did);
        let before = counter.load(Ordering::SeqCst);
        let snapshot = AuthGraphSnapshot::load_with_renewal_identity(
            &db,
            &[original],
            &stable_did,
            &renewer_did,
            epoch,
            2_150,
        )
        .await
        .unwrap();
        // The predecessor ends at 2_100, before verifier time 2_150.
        assert_eq!(counter.load(Ordering::SeqCst) - before, 1);
        assert_eq!(snapshot.effective_expiry(&original), Some(2_200));
        assert!(snapshot.effective_expiry(&original).unwrap() > 2_000);
        assert!(snapshot.effective_expiry(&original).unwrap() <= 2_250);

        let wrong_epoch = AuthGraphSnapshot::load_with_renewal_identity(
            &db,
            &[original],
            &stable_did,
            &renewer_did,
            epoch.wrapping_add(1),
            2_150,
        )
        .await
        .unwrap();
        assert_eq!(wrong_epoch.effective_expiry(&original), Some(2_000));

        revocation::ActiveModel {
            id: Set(hash(b"snapshot-renewal-revoke")),
            revoker: Set("did:key:actor".to_owned()),
            revoked: Set(lease),
            serialization: Set(vec![1]),
            revoked_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();
        let revoked = AuthGraphSnapshot::load_with_renewal_identity(
            &db,
            &[original],
            &stable_did,
            &renewer_did,
            epoch,
            2_150,
        )
        .await
        .unwrap();
        assert_eq!(revoked.effective_expiry(&original), Some(2_000));

        let (orphan_db, _) = counted_database().await;
        let original = hash(b"snapshot-renewal-orphan-original");
        let lease = hash(b"snapshot-renewal-orphan-lease");
        let ancestor = hash(b"snapshot-renewal-orphan-ancestor");
        let (stable_did, renewer_did, epoch) = insert_snapshot_renewal(
            &orphan_db, original, lease, ancestor, 2_000, 2_250, 1_000, true,
        )
        .await;
        let orphan = AuthGraphSnapshot::load_with_renewal_identity(
            &orphan_db,
            &[original],
            &stable_did,
            &renewer_did,
            epoch,
            2_150,
        )
        .await
        .unwrap();
        assert_eq!(orphan.effective_expiry(&original), None);
    }

    #[tokio::test]
    async fn invocation_accepts_active_renewal_after_original_signed_expiry() {
        let (db, _) = counted_database().await;
        let original = hash(b"snapshot-invocation-renewed-original");
        let lease = hash(b"snapshot-invocation-renewed-lease");
        let ancestor = hash(b"snapshot-invocation-renewed-ancestor");
        let (stable_did, renewer_did, epoch) =
            insert_snapshot_renewal(&db, original, lease, ancestor, 2_000, 2_250, 1_000, false)
                .await;
        for id in [original, ancestor] {
            db.execute(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT INTO ability (delegation, resource, ability, caveats) VALUES ($1,$2,$3,$4)",
                [
                    Value::Bytes(Some(Box::new(Vec::<u8>::from(id)))),
                    Value::String(Some(Box::new("tinycloud:key:actor:files/kv".to_owned()))),
                    Value::String(Some(Box::new("tinycloud.kv/get".to_owned()))),
                    Value::Json(Some(Box::new(serde_json::json!({})))),
                ],
            ))
            .await
            .unwrap();
        }
        let graph = AuthGraphSnapshot::load_with_renewal_identity(
            &db,
            &[original],
            &stable_did,
            &renewer_did,
            epoch,
            2_150,
        )
        .await
        .unwrap();
        let capability = crate::util::Capability {
            resource: "tinycloud:key:actor:files/kv/doc".parse().unwrap(),
            ability: "tinycloud.kv/get".to_owned().try_into().unwrap(),
            caveats: Caveats::default(),
        };
        crate::models::invocation::authorize_holder_with_graph(
            &db,
            "did:key:actor",
            &[capability],
            &[original.to_cid(0x55)],
            OffsetDateTime::from_unix_timestamp(2_150).unwrap(),
            &graph,
        )
        .await
        .unwrap();
    }
    // Frozen pre-batch implementation used only to compare complete snapshots.
    async fn load_sequential<C: ConnectionTrait>(
        db: &C,
        roots: &[Hash],
    ) -> Result<AuthGraphSnapshot, ChainTraversalError> {
        let (nodes, parents) = load_closure_edges(db, roots).await?;
        if nodes.is_empty() {
            return Ok(AuthGraphSnapshot {
                parents,
                delegations: HashMap::new(),
                abilities: HashMap::new(),
                revoked: HashSet::new(),
                renewal_effective_ends: HashMap::new(),
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
        // Compare the old loader's rows under the new explicit order, rather
        // than accidentally pinning one backend's unspecified row order.
        sort_abilities(&mut ability_rows);
        // Main's sequential TC-1071 semantics: revocations under any
        // persisted encoding of a delegation apply to every encoding.
        let revoked = revocation::effective_rows(db, &nodes)
            .await?
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        Ok(AuthGraphSnapshot {
            parents,
            delegations,
            abilities: ability_rows,
            revoked,
            renewal_effective_ends: HashMap::new(),
        })
    }

    fn assert_snapshot_matches_legacy(actual: &AuthGraphSnapshot, expected: &AuthGraphSnapshot) {
        let mut actual = (*actual).clone();
        actual.renewal_effective_ends.clear();
        assert_eq!(actual, *expected);
    }
    #[tokio::test]
    async fn snapshot_load_is_one_round_trip_and_matches_sequential() {
        let (db, counter) = counted_database().await;

        let ids = insert_chain(&db, "one-trip", 2).await;
        let expected = load_sequential(&db, &[ids[0]]).await.unwrap();
        let before = counter.load(Ordering::SeqCst);
        let actual = AuthGraphSnapshot::load(&db, &[ids[0]]).await.unwrap();
        assert_snapshot_matches_legacy(&actual, &expected);
        assert_eq!(counter.load(Ordering::SeqCst) - before, 1);
    }

    async fn assert_fixture_equivalence(db: &DatabaseConnection) {
        actor::ActiveModel {
            id: Set("did:key:actor".to_string()),
        }
        .insert(db)
        .await
        .unwrap();
        actor::ActiveModel {
            id: Set("did:key:alias".to_string()),
        }
        .insert(db)
        .await
        .unwrap();
        let ids = insert_chain(db, "cross-backend", 3).await;
        let alias = hash(b"cross-backend-alias");
        insert_delegation(db, alias).await;
        insert_edge(db, alias, ids[2]).await;
        insert_edge(db, ids[0], ids[2]).await;

        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let mut windowed: delegation::ActiveModel = delegation::Entity::find_by_id(ids[1])
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .into();
        windowed.delegator = Set("did:key:alias".to_string());
        windowed.issued_at = Set(Some(now - time::Duration::hours(1)));
        windowed.not_before = Set(Some(now - time::Duration::minutes(15)));
        windowed.expiry = Set(Some(now + time::Duration::hours(1)));
        windowed.facts = Set(Some(Facts(
            [(
                "alias".to_string(),
                serde_json::json!({"principal": "did:key:alias"}),
            )]
            .into(),
        )));
        windowed.update(db).await.unwrap();

        // Deliberately insert away from canonical `(resource, ability)` order.
        // A one-ability fixture cannot detect changed rejection-reason order.
        for id in [ids[0], ids[2], alias] {
            for (index, action) in ["put", "get", "list", "del"].iter().enumerate() {
                for suffix in ["z", "b", "a"] {
                    abilities::ActiveModel {
                        delegation: Set(id),
                        resource: Set(format!("tinycloud:did:key:actor:files/kv/{suffix}")
                            .parse()
                            .unwrap()),
                        ability: Set(format!("tinycloud.kv/{action}").try_into().unwrap()),
                        caveats: Set(Caveats(
                            [("limit".to_string(), serde_json::json!({"max": index + 1}))].into(),
                        )),
                    }
                    .insert(db)
                    .await
                    .unwrap();
                }
            }
        }
        revocation::ActiveModel {
            id: Set(hash(b"cross-backend-revocation")),
            revoker: Set("did:key:actor".to_string()),
            revoked: Set(ids[2]),
            serialization: Set(b"revoked".to_vec()),
            revoked_at: Set(Some(now)),
        }
        .insert(db)
        .await
        .unwrap();

        for roots in [
            vec![ids[0]],
            vec![alias, ids[0], alias],
            vec![hash(b"missing-proof"), ids[1]],
        ] {
            let before = load_sequential(db, &roots).await.unwrap();
            let after = AuthGraphSnapshot::load(db, &roots).await.unwrap();
            assert_snapshot_matches_legacy(&after, &before);
        }
        assert_eq!(
            AuthGraphSnapshot::load(db, &[]).await.unwrap(),
            load_sequential(db, &[]).await.unwrap()
        );
    }

    async fn assert_canonical_caveat_reason(db: &DatabaseConnection) {
        let id = hash(b"canonical-overlapping-caveats");
        delegation::ActiveModel {
            id: Set(id),
            delegator: Set("did:key:actor".to_string()),
            delegatee: Set("did:key:alias".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(id.as_ref().to_vec()),
            serialization_format: Set(0),
        }
        .insert(db)
        .await
        .unwrap();
        let sql_caveats = Caveats(
            [(
                "0".to_string(),
                serde_json::json!({
                    "mode": "constrained-statements",
                    "readOnly": true,
                    "statements": [
                        {"name": "get", "sql": "SELECT 1", "fixedParams": []}
                    ]
                }),
            )]
            .into(),
        );
        for (resource, caveats) in [
            (
                "tinycloud:did:key:actor:files/kv",
                Caveats([("tenant".to_string(), serde_json::json!("a"))].into()),
            ),
            ("tinycloud:did:key:actor:files/kv/doc", sql_caveats.clone()),
        ] {
            abilities::ActiveModel {
                delegation: Set(id),
                resource: Set(resource.parse().unwrap()),
                ability: Set("tinycloud.kv/get".to_string().try_into().unwrap()),
                caveats: Set(caveats),
            }
            .insert(db)
            .await
            .unwrap();
        }
        let snapshot = AuthGraphSnapshot::load(db, &[id]).await.unwrap();
        let rows = snapshot.abilities(&id);
        assert_eq!(rows.len(), 2);
        assert!(
            rows[0].resource < rows[1].resource,
            "canonical resource order"
        );

        let capability = crate::util::Capability {
            resource: "tinycloud:did:key:actor:files/kv/doc".parse().unwrap(),
            ability: "tinycloud.kv/get".to_string().try_into().unwrap(),
            caveats: Caveats::default(),
        };
        let parent = id.to_cid(0x55);
        let err = crate::models::invocation::authorize_holder(
            db,
            "did:key:alias",
            std::slice::from_ref(&capability),
            &[parent],
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap_err();
        assert!(
            matches!(
                &err,
                crate::models::invocation::Error::InvalidInvocation(
                    crate::models::invocation::InvocationError::CaveatsNotContained(reason)
                ) if reason == "containment-caveat-required"
            ),
            "unexpected canonical rejection: {err:?}"
        );

        // A matching constrained caveat still authorizes; sorting changes
        // only which diagnostic wins if *all* candidates reject.
        crate::models::invocation::authorize_holder(
            db,
            "did:key:alias",
            &[crate::util::Capability {
                caveats: sql_caveats,
                ..capability
            }],
            &[parent],
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    }

    async fn assert_closure_limit(db: &DatabaseConnection) {
        for size in [MAX_CHAIN_TRAVERSAL_NODES + 1, MAX_CHAIN_TRAVERSAL_NODES + 2] {
            let ids = insert_chain(db, &format!("too-deep-{size}"), size - 1).await;
            assert!(matches!(
                AuthGraphSnapshot::load(db, &[ids[0]]).await,
                Err(ChainTraversalError::LimitExceeded)
            ));
        }

        let ids = insert_chain(db, "boundary", MAX_CHAIN_TRAVERSAL_NODES - 1).await;
        let snapshot = AuthGraphSnapshot::load(db, &[ids[0]]).await.unwrap();
        assert_eq!(
            snapshot.chain_ids_from(&ids[0]).len(),
            MAX_CHAIN_TRAVERSAL_NODES
        );
        assert!(
            snapshot.delegation(ids.last().unwrap()).is_some(),
            "the 64th node must not be silently truncated"
        );
        assert_snapshot_matches_legacy(&snapshot, &load_sequential(db, &[ids[0]]).await.unwrap());
    }

    async fn insert_alias(db: &DatabaseConnection, id: Hash, canonical: Hash) {
        delegation_cid_alias::ActiveModel {
            id: Set(id),
            canonical: Set(canonical),
            encrypted: Set(false),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn insert_revocation(db: &DatabaseConnection, id: Hash, target: Hash) {
        revocation::ActiveModel {
            id: Set(id),
            revoker: Set("did:key:actor".to_string()),
            revoked: Set(target),
            serialization: Set(id.as_ref().to_vec()),
            revoked_at: Set(Some(OffsetDateTime::now_utc())),
        }
        .insert(db)
        .await
        .unwrap();
    }

    /// TC-1071: a revocation names one stored encoding; every other stored
    /// encoding with the same canonical identity is revoked too. The batched
    /// snapshot must refuse exactly where `revocation::effective_rows` does.
    async fn assert_alias_revocation_refused(db: &DatabaseConnection) {
        let ids = insert_chain(db, "alias-revoked", 2).await;
        let other = hash(b"alias-revoked-other-encoding");
        insert_delegation(db, other).await;
        let canonical = hash(b"alias-revoked-canonical");
        insert_alias(db, ids[1], canonical).await;
        insert_alias(db, other, canonical).await;
        insert_revocation(db, hash(b"alias-revoked-revocation"), other).await;

        assert!(revocation::is_revoked(db, &ids[1]).await.unwrap());
        let snapshot = AuthGraphSnapshot::load(db, &[ids[0]]).await.unwrap();
        assert!(
            snapshot.is_revoked(&ids[1]),
            "batched snapshot missed a revocation under another encoding"
        );
        assert_eq!(
            snapshot.first_revoked_ancestor(&ids[0]),
            Some(ids[1].to_cid(0x55).to_string())
        );
        assert_snapshot_matches_legacy(&snapshot, &load_sequential(db, &[ids[0]]).await.unwrap());
        let cited = AuthGraphSnapshot::load(db, &[ids[1]]).await.unwrap();
        assert!(cited.is_revoked(&ids[1]));
        assert!(!cited.is_revoked(&ids[2]));
    }

    /// Seeded property check: over random DAGs with mixed alias groups,
    /// revocations of cited and uncited encodings, and expired delegations,
    /// the production batched decision equals the decision computed from the
    /// sequential `effective_rows` snapshot and the per-node DB lookups.
    async fn assert_batched_matches_sequential_decisions(
        db: &DatabaseConnection,
        backend: &str,
        cases: u64,
    ) {
        use rand::{rngs::StdRng, Rng, SeedableRng};
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let capability = crate::util::Capability {
            resource: "tinycloud:did:key:actor:files/kv/doc".parse().unwrap(),
            ability: "tinycloud.kv/get".to_string().try_into().unwrap(),
            caveats: Caveats::default(),
        };
        let (mut alias_refusals, mut accepted, mut refused) = (0, 0, 0);
        for case in 0..cases {
            let seed = 0x7c73_5000 + case;
            let mut rng = StdRng::seed_from_u64(seed);
            let tag = format!("prop-{backend}-{seed}");
            let node = |kind: &str, index: usize| hash(format!("{tag}-{kind}-{index}").as_bytes());
            let count = rng.gen_range(1..=6);
            let ids: Vec<Hash> = (0..count).map(|index| node("delegation", index)).collect();
            // Other stored encodings of a canonical delegation; never cited.
            let encodings: Vec<Hash> = (0..rng.gen_range(0..=3))
                .map(|index| node("encoding", index))
                .collect();
            let canonicals = [node("canonical", 0), node("canonical", 1)];
            for id in ids.iter().chain(&encodings) {
                let expiry = match rng.gen_range(0..4) {
                    0 => Some(now - time::Duration::minutes(5)),
                    1 => Some(now + time::Duration::hours(1)),
                    _ => None,
                };
                delegation::ActiveModel {
                    id: Set(*id),
                    delegator: Set("did:key:actor".to_string()),
                    delegatee: Set("did:key:alias".to_string()),
                    expiry: Set(expiry),
                    issued_at: Set(None),
                    not_before: Set(None),
                    facts: Set(None),
                    serialization: Set(id.as_ref().to_vec()),
                    serialization_format: Set(0),
                }
                .insert(db)
                .await
                .unwrap();
                abilities::ActiveModel {
                    delegation: Set(*id),
                    resource: Set("tinycloud:did:key:actor:files/kv".parse().unwrap()),
                    ability: Set("tinycloud.kv/get".to_string().try_into().unwrap()),
                    caveats: Set(Caveats::default()),
                }
                .insert(db)
                .await
                .unwrap();
                if rng.gen_bool(0.6) {
                    insert_alias(db, *id, canonicals[rng.gen_range(0..2)]).await;
                }
            }
            for child in 1..count {
                let mut parents = HashSet::new();
                for _ in 0..rng.gen_range(0..=2) {
                    parents.insert(rng.gen_range(0..child));
                }
                for parent in parents {
                    insert_edge(db, ids[child], ids[parent]).await;
                }
            }
            let mut targets = HashSet::new();
            for id in ids.iter().chain(&encodings) {
                if rng.gen_bool(0.2) {
                    targets.insert(*id);
                }
            }
            for (index, target) in targets.iter().enumerate() {
                insert_revocation(db, node("revocation", index), *target).await;
            }

            let mut root_sets: Vec<Vec<Hash>> = ids.iter().map(|id| vec![*id]).collect();
            root_sets.push(ids.clone());
            for roots in root_sets {
                let context = format!("{backend} seed {seed} roots {roots:?}");
                let batched = AuthGraphSnapshot::load(db, &roots).await.unwrap();
                let sequential = load_sequential(db, &roots).await.unwrap();
                assert_snapshot_matches_legacy(&batched, &sequential);
                for root in &roots {
                    let revoked = revocation::is_revoked(db, root).await.unwrap();
                    assert_eq!(batched.is_revoked(root), revoked, "{context}");
                    assert_eq!(
                        batched.first_revoked_ancestor(root).is_some(),
                        revocation::first_revoked_ancestor(db, root)
                            .await
                            .unwrap()
                            .is_some(),
                        "{context}"
                    );
                    if revoked && !targets.contains(root) {
                        alias_refusals += 1;
                    }
                }
                let parents: Vec<_> = roots.iter().map(|id| id.to_cid(0x55)).collect();
                let production = crate::models::invocation::authorize_holder(
                    db,
                    "did:key:alias",
                    std::slice::from_ref(&capability),
                    &parents,
                    now,
                )
                .await;
                let reference = crate::models::invocation::authorize_holder_with_graph(
                    db,
                    "did:key:alias",
                    std::slice::from_ref(&capability),
                    &parents,
                    now,
                    &sequential,
                )
                .await;
                assert_eq!(
                    format!("{production:?}"),
                    format!("{reference:?}"),
                    "{context}"
                );
                if production.is_ok() {
                    accepted += 1;
                } else {
                    refused += 1;
                }
            }
        }
        // The generator must exercise every decision class it claims to.
        assert!(alias_refusals > 0, "{backend}: no alias-only revocation");
        assert!(
            accepted > 0 && refused > 0,
            "{backend}: one-sided decisions"
        );
    }

    #[tokio::test]
    async fn sqlite_snapshot_matches_sequential_for_chains_windows_caveats_revocations_aliases() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        assert_fixture_equivalence(&db).await;
        assert_canonical_caveat_reason(&db).await;
        assert_closure_limit(&db).await;
        assert_alias_revocation_refused(&db).await;
        assert_batched_matches_sequential_decisions(&db, "sqlite", 200).await;
    }

    #[tokio::test]
    async fn postgres_snapshot_matches_sequential_for_chains_windows_caveats_revocations_aliases() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_snapshot_matches_sequential_for_chains_windows_caveats_revocations_aliases",
        )
        .await
        else {
            return;
        };
        assert_fixture_equivalence(&fixture.conn).await;
        assert_canonical_caveat_reason(&fixture.conn).await;
        assert_closure_limit(&fixture.conn).await;
        assert_alias_revocation_refused(&fixture.conn).await;
        assert_batched_matches_sequential_decisions(&fixture.conn, "postgres", 60).await;
    }

    struct MySqlGraphFixture {
        url: String,
        name: String,
    }

    impl Drop for MySqlGraphFixture {
        fn drop(&mut self) {
            let (url, name) = (self.url.clone(), self.name.clone());
            let result = std::thread::spawn(move || {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(async {
                        Database::connect(url)
                            .await?
                            .execute(Statement::from_string(
                                DbBackend::MySql,
                                format!("DROP DATABASE IF EXISTS {name}"),
                            ))
                            .await
                            .map(|_| ())
                    })
            })
            .join();
            if !matches!(result, Ok(Ok(()))) {
                eprintln!("failed to drop isolated MySQL graph database {}", self.name);
            }
        }
    }

    #[tokio::test]
    async fn mysql_snapshot_matches_sequential_for_chains_windows_caveats_revocations_aliases() {
        let Ok(url) = std::env::var("TINYCLOUD_TEST_MYSQL_URL") else {
            eprintln!("skipping MySQL graph snapshot equivalence (TINYCLOUD_TEST_MYSQL_URL unset)");
            return;
        };
        let (prefix, _) = url
            .rsplit_once('/')
            .expect("MySQL URL must include a database");
        let name = format!(
            "tc_graph_{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let admin = Database::connect(url.clone()).await.unwrap();
        admin
            .execute(Statement::from_string(
                DbBackend::MySql,
                format!("CREATE DATABASE {name}"),
            ))
            .await
            .unwrap();
        let _fixture = MySqlGraphFixture {
            url: url.clone(),
            name: name.clone(),
        };
        let db = Database::connect(format!("{prefix}/{name}")).await.unwrap();
        // The full repository migrator predates MySQL's indexed-column length
        // limits. Keep this fixture scoped to the auth-graph model tables
        // rather than changing unrelated migrations for a query equivalence test.
        for ddl in [
            "CREATE TABLE actor (id VARCHAR(191) PRIMARY KEY)",
            "CREATE TABLE delegation (id VARBINARY(34) PRIMARY KEY, delegator VARCHAR(191) NOT NULL, delegatee VARCHAR(191) NOT NULL, expiry DATETIME NULL, issued_at DATETIME NULL, not_before DATETIME NULL, facts JSON NULL, serialization BLOB NOT NULL, serialization_format SMALLINT NOT NULL DEFAULT 0)",
            "CREATE TABLE parent_delegation (child VARBINARY(34) NOT NULL, parent VARBINARY(34) NOT NULL, PRIMARY KEY (parent, child))",
            "CREATE TABLE ability (resource VARCHAR(255) NOT NULL, ability VARCHAR(255) NOT NULL, delegation VARBINARY(34) NOT NULL, caveats JSON NOT NULL, PRIMARY KEY (resource, ability, delegation))",
            "CREATE TABLE revocation (id VARBINARY(34) PRIMARY KEY, revoker VARCHAR(191) NOT NULL, revoked VARBINARY(34) NOT NULL, serialization BLOB NOT NULL, revoked_at DATETIME NULL)",
            "CREATE TABLE delegation_cid_alias (id VARBINARY(64) PRIMARY KEY, canonical VARBINARY(64) NOT NULL, encrypted BOOLEAN NOT NULL, INDEX idx_delegation_cid_alias_canonical (canonical, id))",
        ] {
            db.execute(Statement::from_string(DbBackend::MySql, ddl.to_string()))
                .await
                .unwrap();
        }
        assert_fixture_equivalence(&db).await;
        assert_canonical_caveat_reason(&db).await;
        assert_closure_limit(&db).await;
        assert_alias_revocation_refused(&db).await;
        assert_batched_matches_sequential_decisions(&db, "mysql", 60).await;
        db.close().await.unwrap();
        admin.close().await.unwrap();
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
            serialization_format: Set(0),
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
    /// establish the lock set, then one tagged transaction-scoped snapshot query.
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
            // lock set, then one transaction-scoped snapshot query.
            let before = counter.load(Ordering::SeqCst);
            let lock_keys = load_chain_lock_ids(&db, &[leaf]).await.unwrap();
            let snapshot = AuthGraphSnapshot::load(&db, &[leaf]).await.unwrap();
            let optimized_queries = counter.load(Ordering::SeqCst) - before;

            assert_eq!(lock_keys.len(), depth + 1);
            assert_eq!(snapshot.chain_ids_from(&leaf).len(), depth + 1);
            assert_eq!(legacy_queries, expected_legacy, "depth {depth}");
            assert_eq!(optimized_queries, 2, "depth {depth}");
        }
    }
}

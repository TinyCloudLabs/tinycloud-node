//! TC-1423: graph queries behind Policy/v3 owner-authority bindings.
//!
//! The node records, for each policy registration, the ancestor closure of
//! the delegations its owner held as authority. These helpers load such a
//! closure in one round trip and resolve revocations, including those
//! recorded under an alias CID, in one more.

use crate::hash::Hash;
use crate::models::{delegation, delegation_cid_alias, revocation};
use sea_orm::{
    sea_query::{Expr, Query},
    ColumnTrait, ConnectionTrait, DbErr, EntityTrait, QueryFilter,
};
use std::collections::{HashMap, HashSet, VecDeque};
use time::OffsetDateTime;

pub use crate::models::revocation::{ChainTraversalError, MAX_CHAIN_TRAVERSAL_NODES};

/// The migration that created the binding tables; its applied-at time is the
/// default legacy cutover.
pub const OWNER_AUTHORITY_MIGRATION: &str = "m20261019_000000_policy_v3_owner_authority";

/// One delegation in an authority closure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureNode {
    pub id: Hash,
    /// Distance from the nearest leaf of the loaded closure.
    pub depth: u32,
    pub delegator: String,
    pub expiry: Option<OffsetDateTime>,
    pub not_before: Option<OffsetDateTime>,
}

/// Load `leaves` and every ancestor, bounded by the core traversal budget.
/// A closure node without a persisted delegation row fails closed.
pub async fn load_closure<C: ConnectionTrait>(
    db: &C,
    leaves: &[Hash],
) -> Result<Vec<ClosureNode>, ChainTraversalError> {
    let (ids, parents) = crate::auth_graph::load_closure_edges(db, leaves).await?;
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let mut depth: HashMap<Hash, u32> = HashMap::new();
    let mut queue = VecDeque::new();
    for leaf in leaves {
        if depth.insert(*leaf, 0).is_none() {
            queue.push_back(*leaf);
        }
    }
    while let Some(current) = queue.pop_front() {
        let next = depth[&current] + 1;
        for parent in parents.get(&current).map(Vec::as_slice).unwrap_or(&[]) {
            if !depth.contains_key(parent) {
                depth.insert(*parent, next);
                queue.push_back(*parent);
            }
        }
    }
    let rows: HashMap<Hash, delegation::Model> = delegation::Entity::find()
        .filter(delegation::Column::Id.is_in(ids.iter().copied()))
        .all(db)
        .await?
        .into_iter()
        .map(|row| (row.id, row))
        .collect();
    ids.iter()
        .map(|id| {
            let row = rows.get(id).ok_or_else(|| {
                ChainTraversalError::Db(DbErr::RecordNotFound(
                    "authority closure delegation".into(),
                ))
            })?;
            Ok(ClosureNode {
                id: *id,
                depth: depth.get(id).copied().unwrap_or(0),
                delegator: row.delegator.clone(),
                expiry: row.expiry,
                not_before: row.not_before,
            })
        })
        .collect()
}

/// The subset of `ids` that is revoked, directly or under an alias CID, in
/// one query.
pub async fn revoked_ids<C: ConnectionTrait>(db: &C, ids: &[Hash]) -> Result<HashSet<Hash>, DbErr> {
    Ok(revocation::effective_rows(db, ids)
        .await?
        .into_iter()
        .map(|(id, _)| id)
        .collect())
}

/// `id` and every CID persisted as the same canonical delegation.
pub async fn equivalent_ids<C: ConnectionTrait>(db: &C, id: Hash) -> Result<Vec<Hash>, DbErr> {
    let canonical = Query::select()
        .column(delegation_cid_alias::Column::Canonical)
        .from(delegation_cid_alias::Entity)
        .and_where(Expr::col(delegation_cid_alias::Column::Id).eq(id))
        .to_owned();
    let mut ids = delegation_cid_alias::Entity::find()
        .filter(delegation_cid_alias::Column::Canonical.in_subquery(canonical))
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.id)
        .collect::<Vec<_>>();
    if !ids.contains(&id) {
        ids.push(id);
    }
    Ok(ids)
}

/// The applied-at time of `version`, in Unix seconds; `None` when it is not applied.
pub async fn migration_applied_at<C: ConnectionTrait>(
    db: &C,
    version: &str,
) -> Result<Option<i64>, DbErr> {
    use sea_orm_migration::seaql_migrations;
    Ok(seaql_migrations::Entity::find_by_id(version.to_owned())
        .one(db)
        .await?
        .map(|row| row.applied_at))
}

/// Whether nothing in the ancestor closure of `roots` is revoked (directly
/// or under an alias CID): one recursive closure query plus one revocation
/// query, whatever the depth. Fails closed past the traversal budget.
pub async fn chains_unrevoked<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
) -> Result<bool, ChainTraversalError> {
    if roots.is_empty() {
        return Ok(true);
    }
    let (ids, _) = crate::auth_graph::load_closure_edges(db, roots).await?;
    Ok(revoked_ids(db, &ids).await?.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash;
    use crate::migrations::Migrator;
    use crate::models::actor;
    use crate::relationships::parent_delegations;
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database};
    use sea_orm_migration::MigratorTrait;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn chain_check_costs_two_queries_at_any_depth() {
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
        let ids: Vec<Hash> = (0..6)
            .map(|i| hash(format!("chain-{i}").as_bytes()))
            .collect();
        for id in &ids {
            delegation::ActiveModel {
                id: Set(*id),
                delegator: Set("did:key:actor".to_string()),
                delegatee: Set("did:key:actor".to_string()),
                expiry: Set(None),
                issued_at: Set(None),
                not_before: Set(None),
                facts: Set(None),
                serialization: Set(id.as_ref().to_vec()),
            }
            .insert(&db)
            .await
            .unwrap();
        }
        for pair in ids.windows(2) {
            parent_delegations::ActiveModel {
                child: Set(pair[0]),
                parent: Set(pair[1]),
            }
            .insert(&db)
            .await
            .unwrap();
        }
        let queries = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&queries);
        db.set_metric_callback(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        });
        assert!(chains_unrevoked(&db, &ids[..1]).await.unwrap());
        assert_eq!(queries.load(Ordering::SeqCst), 2);

        revocation::ActiveModel {
            id: Set(hash(b"revoke-chain-top")),
            revoker: Set("did:key:actor".to_string()),
            revoked: Set(ids[5]),
            serialization: Set(b"revocation".to_vec()),
            revoked_at: Set(None),
        }
        .insert(&db)
        .await
        .unwrap();
        queries.store(0, Ordering::SeqCst);
        assert!(!chains_unrevoked(&db, &ids[..1]).await.unwrap());
        assert_eq!(queries.load(Ordering::SeqCst), 2);
    }
}

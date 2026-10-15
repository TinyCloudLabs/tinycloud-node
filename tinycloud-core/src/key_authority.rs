//! Durable principal revocation and the database-side admission cutoff.
//!
//! Delegation CIDs identify signed statements; key tombstones identify DID
//! principals. Never use a CID alias as a substitute for a principal.

use crate::hash::{hash, Hash};
use crate::models::{
    delegation,
    key_revocation::{self, target},
};
use sea_orm::{
    sea_query::{Expr, OnConflict},
    ActiveValue::Set,
    ColumnTrait, Condition, ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, EntityTrait,
    QueryFilter, QueryOrder, QuerySelect,
};
use tinycloud_auth::{identity::principal_did, resource::SpaceId};

pub const REVOKED: &str = "authorization-key-revoked";

pub fn is_revoked_error(error: &DbErr) -> bool {
    matches!(error, DbErr::Custom(message) if message == REVOKED)
}

/// Domain-separated registry key for a DID principal. Every scoped operation
/// also participates in this global-principal guard.
pub fn principal_lock_id(principal: &str) -> Result<Hash, DbErr> {
    let did = principal_did(principal)
        .map_err(|_| DbErr::Custom("authorization-principal-invalid".into()))?;
    Ok(hash(
        format!("tinycloud/key-principal-guard/v1\0{did}").as_bytes(),
    ))
}

/// Fail closed if any signer or audience in the authorization dependency set
/// was explicitly revoked globally or in one of the affected spaces. An empty
/// scope list still checks the global tombstone.
pub async fn check_principals<C: ConnectionTrait>(
    db: &C,
    principals: &[String],
    spaces: &[String],
) -> Result<(), DbErr> {
    if principals.is_empty() {
        return Err(DbErr::Custom("authorization-principal-missing".into()));
    }
    let principals = canonical_principals(principals)?;
    let scope = spaces.iter().try_fold(
        Condition::any().add(key_revocation::Column::ScopeKey.eq("global")),
        |scope, raw| {
            let space = raw
                .parse::<SpaceId>()
                .map_err(|_| DbErr::Custom("authorization-scope-invalid".into()))?;
            Ok::<Condition, DbErr>(
                scope.add(key_revocation::Column::ScopeKey.eq(format!("space:{space}"))),
            )
        },
    )?;
    if key_revocation::Entity::find()
        .filter(key_revocation::Column::TargetDid.is_in(principals))
        .filter(scope)
        .one(db)
        .await?
        .is_some()
    {
        return Err(DbErr::Custom(REVOKED.into()));
    }
    Ok(())
}
/// Legacy email shares bind an owner DID, not a namespaced SpaceId. No scoped
/// tombstone can be proven unrelated to that historical authority, so deny on
/// any tombstone for its verified signers and audiences.
pub async fn check_principals_any_scope<C: ConnectionTrait>(
    db: &C,
    principals: &[String],
) -> Result<(), DbErr> {
    if principals.is_empty() {
        return Err(DbErr::Custom("authorization-principal-missing".into()));
    }
    if key_revocation::Entity::find()
        .filter(key_revocation::Column::TargetDid.is_in(canonical_principals(principals)?))
        .one(db)
        .await?
        .is_some()
    {
        return Err(DbErr::Custom(REVOKED.into()));
    }
    Ok(())
}

/// Check every signer and audience of a persisted proof closure, including
/// the requesting signer. The bounded graph load denies missing ancestry
/// rather than silently shrinking the key-revocation dependency set.
pub async fn check_invoker_chain<C: ConnectionTrait>(
    db: &C,
    roots: &[Hash],
    invoker: &str,
    spaces: &[String],
) -> Result<(), DbErr> {
    let mut principals = crate::auth_graph::load_chain_principals(db, roots)
        .await
        .map_err(|error| DbErr::Custom(error.to_string()))?;
    principals.push(invoker.to_owned());
    check_principals(db, &principals, spaces).await
}

/// Establish a per-principal row before checking authority in a mutating
/// transaction. Shared row locks permit independent admissions; an exclusive
/// key revoke of that DID conflicts with both global and scoped effects in
/// other node processes. SQLite's write transaction serializes these writes;
/// it does not understand SELECT FOR SHARE. Call before the revocation check
/// and keep `tx` alive through the authorized effect/commit.
pub async fn lock_targets(
    tx: &DatabaseTransaction,
    principals: &[String],
    exclusive: bool,
) -> Result<(), DbErr> {
    let principals = canonical_principals(principals)?;
    if principals.is_empty() {
        return Ok(());
    }
    // Retain the batched row-lock query, but pin the same byte order used by
    // recovery's Rust-sorted per-principal locks. PostgreSQL's default text
    // collation (and MySQL's) need not order mixed-case DIDs bytewise.
    ensure_target_rows(tx, &principals).await?;
    if tx.get_database_backend() != DbBackend::Sqlite {
        let query = target::Entity::find()
            .filter(target::Column::TargetDid.is_in(principals.iter().cloned()))
            .order_by_asc(crate::db::byte_ordered(
                tx.get_database_backend(),
                Expr::col((target::Entity, target::Column::TargetDid)),
            ));
        let rows = if exclusive {
            query.lock_exclusive().all(tx).await?
        } else {
            query.lock_shared().all(tx).await?
        };
        if rows.len() != principals.len() {
            return Err(DbErr::Custom("authorization-key-lock-missing".into()));
        }
    }
    Ok(())
}

/// Recovery authorization must lock the target and signer exclusively while
/// keeping every other live proof principal shared. Acquire the strongest
/// mode each principal needs on its first visit, across one canonical order:
/// taking intermediate SHARE locks before target UPDATE locks can deadlock
/// when two otherwise valid recovery chains cross.
pub(crate) async fn lock_recovery_targets(
    tx: &DatabaseTransaction,
    principals: &[String],
    target_did: &str,
    issuer_did: &str,
) -> Result<(), DbErr> {
    let invalid = || DbErr::Custom("authorization-principal-invalid".into());
    let target_did = principal_did(target_did).map_err(|_| invalid())?;
    let issuer_did = principal_did(issuer_did).map_err(|_| invalid())?;
    let mut ordered = Vec::with_capacity(principals.len() + 2);
    for principal in principals {
        ordered.push(principal_did(principal).map_err(|_| invalid())?);
    }
    ordered.push(target_did.clone());
    ordered.push(issuer_did.clone());
    ordered.sort_unstable();
    ordered.dedup();
    ensure_target_rows(tx, &ordered).await?;
    if tx.get_database_backend() != DbBackend::Sqlite {
        for principal in ordered {
            let query = target::Entity::find_by_id(principal.clone());
            let locked = if principal == target_did || principal == issuer_did {
                query.lock_exclusive().one(tx).await?
            } else {
                query.lock_shared().one(tx).await?
            };
            if locked.is_none() {
                return Err(DbErr::Custom("authorization-key-lock-missing".into()));
            }
        }
    }
    Ok(())
}

async fn ensure_target_rows(tx: &DatabaseTransaction, principals: &[String]) -> Result<(), DbErr> {
    match target::Entity::insert_many(principals.iter().cloned().map(|target_did| {
        target::ActiveModel {
            target_did: Set(target_did),
        }
    }))
    .on_conflict(
        OnConflict::column(target::Column::TargetDid)
            .do_nothing()
            .to_owned(),
    )
    .exec(tx)
    .await
    {
        Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
        Err(error) => Err(error),
    }
}

fn canonical_principals(principals: &[String]) -> Result<Vec<String>, DbErr> {
    let mut canonical = principals
        .iter()
        .map(|did| {
            principal_did(did).map_err(|_| DbErr::Custom("authorization-principal-invalid".into()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    canonical.sort_unstable();
    canonical.dedup();
    Ok(canonical)
}

/// Keep signed proof rows shared through a mutating admission or effect.
/// Generic CID revoke locks every canonical alias row exclusively, so this
/// conflicts across processes even if the submitted CID uses another alias.
pub async fn lock_signed_dependencies(
    tx: &DatabaseTransaction,
    cids: &[Hash],
) -> Result<(), DbErr> {
    if tx.get_database_backend() == DbBackend::Sqlite {
        return Ok(());
    }
    let mut ordered = cids.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    for id in ordered {
        if delegation::Entity::find_by_id(id)
            .lock_shared()
            .one(tx)
            .await?
            .is_none()
        {
            return Err(DbErr::Custom("authorization-proof-missing".into()));
        }
    }
    Ok(())
}

//! Durable fences for blobs uploaded before a KV transaction's sequence lock.

use std::{borrow::Cow, error::Error as StdError};

use sea_orm::{
    sea_query::{Expr, LockBehavior, LockType, OnConflict},
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait, TransactionTrait,
};
use time::{Duration, OffsetDateTime};
use tinycloud_auth::resource::SpaceId;

use crate::db_pool::RecoveringConnection;
use crate::hash::Hash;
use crate::models::{current_kv, kv_orphan_candidate as candidate, kv_write};
use crate::storage::ImmutableDeleteStore;
use crate::types::SpaceIdWrap;

const MAX_BATCH_SIZE: u64 = 256;

fn ordered_unique(blobs: &[(SpaceId, Hash)]) -> Cow<'_, [(SpaceId, Hash)]> {
    if blobs.windows(2).all(|pair| pair[0] < pair[1]) {
        return Cow::Borrowed(blobs);
    }
    let mut ordered = blobs.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    Cow::Owned(ordered)
}

/// Durably register every possible orphan before uploading any of these blobs.
///
/// An existing candidate gets a new grace period. This operation is intentionally
/// outside the KV transaction so a failed precondition or a crash leaves a
/// collectable candidate behind.
pub async fn register_candidates<C: ConnectionTrait>(
    conn: &C,
    blobs: &[(SpaceId, Hash)],
) -> Result<(), DbErr> {
    for (space, value) in ordered_unique(blobs).iter() {
        candidate::Entity::insert(candidate::ActiveModel {
            space: sea_orm::ActiveValue::Set(SpaceIdWrap(space.clone())),
            value: sea_orm::ActiveValue::Set(*value),
            created_at: sea_orm::ActiveValue::Set(OffsetDateTime::now_utc()),
        })
        .on_conflict(
            OnConflict::columns([candidate::Column::Space, candidate::Column::Value])
                .update_column(candidate::Column::CreatedAt)
                .to_owned(),
        )
        .exec(conn)
        .await?;
    }
    Ok(())
}

/// Register before upload on the recovering pool. Replaying the *same*
/// upsert after a lost connection is safe even if its first attempt committed:
/// the key and `created_at` are fixed in the statement. Transactional fences
/// use `register_candidates` instead and are never replayed independently.
pub async fn register_candidates_idempotent(
    conn: &RecoveringConnection,
    blobs: &[(SpaceId, Hash)],
) -> Result<(), DbErr> {
    for (space, value) in ordered_unique(blobs).iter() {
        let statement = candidate::Entity::insert(candidate::ActiveModel {
            space: sea_orm::ActiveValue::Set(SpaceIdWrap(space.clone())),
            value: sea_orm::ActiveValue::Set(*value),
            created_at: sea_orm::ActiveValue::Set(OffsetDateTime::now_utc()),
        })
        .on_conflict(
            OnConflict::columns([candidate::Column::Space, candidate::Column::Value])
                .update_column(candidate::Column::CreatedAt)
                .to_owned(),
        )
        .build(conn.get_database_backend());
        conn.execute_idempotent_preparatory(statement).await?;
    }
    Ok(())
}

/// Fence each blob against concurrent collection before uploading it.
///
/// Call after registration, inside the KV transaction, before any PUT or
/// per-space sequence lock. Hold the transaction through the upload and
/// successful KV commit. Sorting prevents reversed hash-lock deadlocks.
pub async fn lock_candidates(
    tx: &DatabaseTransaction,
    blobs: &[(SpaceId, Hash)],
) -> Result<(), DbErr> {
    // Upsert again inside the transaction: a previous writer may have
    // committed and deleted our pre-registered row while we waited to begin
    // this transaction. The upsert owns the hash fence through commit on
    // PostgreSQL, MySQL and SQLite, even when the row was absent.
    register_candidates(tx, blobs).await
}

/// Remove successful candidates atomically with their KV writes.
///
/// Call only once the writes have succeeded and before committing the KV
/// transaction. Rollback leaves candidates for the collector.
pub async fn finish_candidates(
    tx: &DatabaseTransaction,
    blobs: &[(SpaceId, Hash)],
) -> Result<(), DbErr> {
    for (space, value) in ordered_unique(blobs).iter() {
        candidate::Entity::delete_by_id((SpaceIdWrap(space.clone()), *value))
            .exec(tx)
            .await?;
    }
    Ok(())
}

/// A database operation or object-store deletion failed; the candidate is
/// retained for a future collection pass on rollback.
#[derive(Debug, thiserror::Error)]
pub enum CollectError<E: StdError + Send + Sync> {
    #[error("orphan candidate database operation failed: {0}")]
    Database(#[from] DbErr),
    #[error("orphan blob deletion failed: {0}")]
    Store(E),
}

async fn remove_if_unreferenced<S: ImmutableDeleteStore>(
    tx: &DatabaseTransaction,
    store: &S,
    row: candidate::Model,
) -> Result<bool, CollectError<S::Error>> {
    let historical = kv_write::Entity::find()
        .filter(kv_write::Column::Space.eq(row.space.clone()))
        .filter(kv_write::Column::Value.eq(row.value))
        .select_only()
        .column(kv_write::Column::Seq);
    let current = current_kv::Entity::find()
        .filter(current_kv::Column::Space.eq(row.space.clone()))
        .filter(current_kv::Column::Value.eq(row.value))
        .select_only()
        .column(current_kv::Column::Seq);
    // MySQL's REPEATABLE READ snapshot may precede the writer whose hash
    // fence we just acquired. Locking reads see its committed references.
    let (historical, current) = if tx.get_database_backend() == DbBackend::MySql {
        (historical.lock_exclusive(), current.lock_exclusive())
    } else {
        (historical, current)
    };
    let referenced = historical.into_tuple::<i64>().one(tx).await?.is_some()
        || current.into_tuple::<i64>().one(tx).await?.is_some();
    let removed = if referenced {
        false
    } else {
        store
            .remove(&row.space.0, &row.value)
            .await
            .map_err(CollectError::Store)?
            .is_some()
    };
    candidate::Entity::delete_by_id((row.space, row.value))
        .exec(tx)
        .await?;
    Ok(removed)
}

/// Refund a known failed invocation before returning to its caller. The
/// durable candidate remains for periodic recovery if deletion fails.
pub async fn refund_failed<C, S>(
    conn: &C,
    store: &S,
    blobs: &[(SpaceId, Hash)],
) -> Result<(), CollectError<S::Error>>
where
    C: ConnectionTrait + TransactionTrait,
    S: ImmutableDeleteStore,
{
    for (space, value) in ordered_unique(blobs).iter() {
        let tx = conn.begin().await?;
        let key = (SpaceIdWrap(space.clone()), *value);
        let row = if tx.get_database_backend() == DbBackend::Sqlite {
            let updated = candidate::Entity::update_many()
                .col_expr(
                    candidate::Column::CreatedAt,
                    Expr::col(candidate::Column::CreatedAt).into(),
                )
                .filter(candidate::Column::Space.eq(key.0.clone()))
                .filter(candidate::Column::Value.eq(key.1))
                .exec(&tx)
                .await?;
            if updated.rows_affected == 0 {
                continue;
            }
            candidate::Entity::find_by_id(key).one(&tx).await?
        } else {
            candidate::Entity::find_by_id(key)
                .lock_exclusive()
                .one(&tx)
                .await?
        };
        if let Some(row) = row {
            remove_if_unreferenced(&tx, store, row).await?;
        }
        tx.commit().await?;
    }
    Ok(())
}

pub async fn collect_candidates<C, S>(
    conn: &C,
    store: &S,
    max: u64,
    min_age: Duration,
) -> Result<usize, CollectError<S::Error>>
where
    C: ConnectionTrait + TransactionTrait,
    S: ImmutableDeleteStore,
{
    Ok(collect_candidates_with_progress(conn, store, max, min_age)
        .await?
        .0)
}

/// Collect at most `min(max, 256)` old candidates in one pass.
///
/// A row lock excludes uploaders of the same `(space, hash)` until reference
/// checks, blob deletion and candidate removal have completed. Historical
/// `kv_write` references are as important as current KV references: a sync
/// client may still read an older value.
pub async fn collect_candidates_with_progress<C, S>(
    conn: &C,
    store: &S,
    max: u64,
    min_age: Duration,
) -> Result<(usize, usize), CollectError<S::Error>>
where
    C: ConnectionTrait + TransactionTrait,
    S: ImmutableDeleteStore,
{
    let limit = max.min(MAX_BATCH_SIZE);
    if limit == 0 {
        return Ok((0, 0));
    }
    let cutoff = OffsetDateTime::now_utc()
        .checked_sub(min_age)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let tx = conn.begin().await?;
    let query = candidate::Entity::find()
        .filter(candidate::Column::CreatedAt.lte(cutoff))
        .order_by_asc(candidate::Column::CreatedAt)
        .order_by_asc(candidate::Column::Space)
        .order_by_asc(candidate::Column::Value)
        .limit(limit);
    let query = if tx.get_database_backend() == DbBackend::Postgres {
        query.lock_with_behavior(LockType::Update, LockBehavior::SkipLocked)
    } else {
        query
    };
    let rows = query.all(&tx).await?;
    let scanned = rows.len();
    let mut removed = 0;
    for row in rows {
        // PostgreSQL SELECT FOR UPDATE already owns this lock. MySQL
        // obtains a fresh locking read; SQLite upgrades to a write lock.
        if tx.get_database_backend() != DbBackend::Postgres {
            let fresh = if tx.get_database_backend() == DbBackend::Sqlite {
                let updated = candidate::Entity::update_many()
                    .col_expr(
                        candidate::Column::CreatedAt,
                        Expr::col(candidate::Column::CreatedAt).into(),
                    )
                    .filter(candidate::Column::Space.eq(row.space.clone()))
                    .filter(candidate::Column::Value.eq(row.value))
                    .exec(&tx)
                    .await?;
                if updated.rows_affected == 0 {
                    continue;
                }
                candidate::Entity::find_by_id((row.space.clone(), row.value))
                    .one(&tx)
                    .await?
            } else {
                candidate::Entity::find_by_id((row.space.clone(), row.value))
                    .lock_exclusive()
                    .one(&tx)
                    .await?
            };
            if !fresh.is_some_and(|candidate| candidate.created_at <= cutoff) {
                continue;
            }
        }

        removed += usize::from(remove_if_unreferenced(&tx, store, row).await?);
    }
    tx.commit().await?;
    Ok((removed, scanned))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash;
    use crate::models::kv_orphan_candidate;
    use crate::storage::{
        memory::MemoryStore, HashBuffer, ImmutableReadStore, ImmutableWriteStore, StoreSize,
    };
    use futures::io::AsyncWriteExt;
    use sea_orm::{
        sea_query::Expr, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend,
        EntityTrait, QueryFilter, Statement, TransactionTrait,
    };
    use sea_orm_migration::MigratorTrait;
    use tinycloud_auth::{resolver::DID_METHODS, ssi::jwk::JWK};

    async fn database() -> DatabaseConnection {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_owned()))
            .await
            .unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        db.execute(Statement::from_string(
            DbBackend::Sqlite,
            "PRAGMA foreign_keys = OFF",
        ))
        .await
        .unwrap();
        db
    }

    fn space() -> SpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, "files".parse().unwrap())
    }

    async fn upload(store: &MemoryStore, space: &SpaceId, bytes: &[u8]) -> Hash {
        let mut staged = HashBuffer::new(Vec::new());
        staged.write_all(bytes).await.unwrap();
        store.persist(space, staged).await.unwrap()
    }

    async fn age(db: &DatabaseConnection, space: &SpaceId, value: Hash) {
        kv_orphan_candidate::Entity::update_many()
            .col_expr(
                kv_orphan_candidate::Column::CreatedAt,
                Expr::value(time::OffsetDateTime::now_utc() - time::Duration::hours(2)),
            )
            .filter(kv_orphan_candidate::Column::Space.eq(crate::types::SpaceIdWrap(space.clone())))
            .filter(kv_orphan_candidate::Column::Value.eq(value))
            .exec(db)
            .await
            .unwrap();
    }

    async fn reference(db: &DatabaseConnection, table: &str, space: &SpaceId, value: Hash) {
        let sql = if table == "kv_write" {
            "INSERT INTO kv_write (space, key, invocation, seq, epoch, epoch_seq, value, metadata) VALUES (?, 'a', ?, 1, ?, 1, ?, '{}')"
        } else {
            "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, metadata, deleted) VALUES (?, 'a', ?, 1, ?, 1, ?, '{}', 0)"
        };
        db.execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            sql,
            [
                space.to_string().into(),
                Vec::<u8>::from(hash(table.as_bytes())).into(),
                Vec::<u8>::from(hash(b"epoch")).into(),
                Vec::<u8>::from(value).into(),
            ],
        ))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn historical_and_current_references_survive_collection() {
        let db = database().await;
        let store = MemoryStore::default();
        let history_space = space();
        let current_space = space();
        let historical = upload(&store, &history_space, b"historical").await;
        let current = upload(&store, &current_space, b"current").await;
        let candidates = [
            (history_space.clone(), historical),
            (current_space.clone(), current),
        ];
        register_candidates(&db, &candidates).await.unwrap();
        for (space, hash) in &candidates {
            age(&db, space, *hash).await;
        }
        reference(&db, "kv_write", &history_space, historical).await;
        reference(&db, "current_kv", &current_space, current).await;

        assert_eq!(
            collect_candidates(&db, &store, 10, time::Duration::hours(1))
                .await
                .unwrap(),
            0
        );
        for (space, hash) in &candidates {
            assert!(store.contains(space, hash).await.unwrap());
            assert!(kv_orphan_candidate::Entity::find_by_id((
                crate::types::SpaceIdWrap(space.clone()),
                *hash
            ))
            .one(&db)
            .await
            .unwrap()
            .is_none());
        }
    }

    #[tokio::test]
    async fn crashed_upload_is_refunded_after_five_minute_grace() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let value = hash(b"failed-precondition");
        register_candidates(&db, &[(space.clone(), value)])
            .await
            .unwrap();
        assert_eq!(upload(&store, &space, b"failed-precondition").await, value);
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(b"failed-precondition".len() as u64)
        );
        let tx = db.begin().await.unwrap();
        lock_candidates(&tx, &[(space.clone(), value)])
            .await
            .unwrap();
        tx.rollback().await.unwrap();
        age(&db, &space, value).await;

        assert_eq!(
            collect_candidates(&db, &store, 10, time::Duration::minutes(5))
                .await
                .unwrap(),
            1
        );
        assert!(!store.contains(&space, &value).await.unwrap());
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
        assert!(
            kv_orphan_candidate::Entity::find_by_id((crate::types::SpaceIdWrap(space), value))
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn grace_and_pass_limit_do_not_scan_or_delete_newer_rows() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let mut old = Vec::new();
        for bytes in [b"old-1".as_slice(), b"old-2", b"old-3"] {
            let value = upload(&store, &space, bytes).await;
            register_candidates(&db, &[(space.clone(), value)])
                .await
                .unwrap();
            age(&db, &space, value).await;
            old.push(value);
        }
        let fresh = upload(&store, &space, b"fresh").await;
        register_candidates(&db, &[(space.clone(), fresh)])
            .await
            .unwrap();
        assert_eq!(
            collect_candidates(&db, &store, 2, time::Duration::hours(1))
                .await
                .unwrap(),
            2
        );
        let mut surviving = 0;
        for value in &old {
            surviving += usize::from(store.contains(&space, value).await.unwrap());
        }
        assert_eq!(surviving, 1);
        assert!(store.contains(&space, &fresh).await.unwrap());
        assert_eq!(
            collect_candidates(&db, &store, 2, time::Duration::hours(1))
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            collect_candidates(&db, &store, 2, time::Duration::hours(1))
                .await
                .unwrap(),
            0
        );
        assert!(store.contains(&space, &fresh).await.unwrap());
    }

    #[tokio::test]
    async fn registering_existing_hash_resets_grace_period() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let value = upload(&store, &space, b"same-hash").await;
        register_candidates(&db, &[(space.clone(), value)])
            .await
            .unwrap();
        age(&db, &space, value).await;
        register_candidates(&db, &[(space.clone(), value)])
            .await
            .unwrap();

        assert_eq!(
            collect_candidates(&db, &store, 1, time::Duration::hours(1))
                .await
                .unwrap(),
            0
        );
        assert!(store.contains(&space, &value).await.unwrap());
    }

    #[tokio::test]
    async fn uploader_recreates_candidate_deleted_by_earlier_same_hash_commit() {
        let db = database().await;
        let space = space();
        let value = hash(b"same-hash");
        let blobs = [(space.clone(), value)];
        register_candidates(&db, &blobs).await.unwrap();
        // The next uploader has already pre-registered this same hash.
        let earlier = db.begin().await.unwrap();
        lock_candidates(&earlier, &blobs).await.unwrap();
        finish_candidates(&earlier, &blobs).await.unwrap();
        earlier.commit().await.unwrap();
        assert!(
            kv_orphan_candidate::Entity::find_by_id((SpaceIdWrap(space.clone()), value))
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
        let later = db.begin().await.unwrap();
        lock_candidates(&later, &blobs).await.unwrap();
        assert!(
            kv_orphan_candidate::Entity::find_by_id((SpaceIdWrap(space), value))
                .one(&later)
                .await
                .unwrap()
                .is_some(),
            "the second upload must have a durable hash fence after the first commit"
        );
        later.commit().await.unwrap();
    }

    #[tokio::test]
    async fn postgres_upload_fence_skips_locked_candidate() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_upload_fence_skips_locked_candidate",
        )
        .await
        else {
            return;
        };
        let store = MemoryStore::default();
        let space = space();
        let value = upload(&store, &space, b"upload-in-progress").await;
        register_candidates(&fixture.conn, &[(space.clone(), value)])
            .await
            .unwrap();
        kv_orphan_candidate::Entity::update_many()
            .col_expr(
                kv_orphan_candidate::Column::CreatedAt,
                Expr::value(time::OffsetDateTime::now_utc() - time::Duration::hours(2)),
            )
            .filter(kv_orphan_candidate::Column::Space.eq(crate::types::SpaceIdWrap(space.clone())))
            .filter(kv_orphan_candidate::Column::Value.eq(value))
            .exec(&fixture.conn)
            .await
            .unwrap();
        let tx = fixture.conn.begin().await.unwrap();
        lock_candidates(&tx, &[(space.clone(), value)])
            .await
            .unwrap();
        let collected = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            collect_candidates(&fixture.conn, &store, 1, time::Duration::hours(1)),
        )
        .await
        .expect("collector should skip the locked candidate")
        .unwrap();
        assert_eq!(collected, 0);
        assert!(store.contains(&space, &value).await.unwrap());
        tx.rollback().await.unwrap();
        assert_eq!(
            collect_candidates(&fixture.conn, &store, 1, time::Duration::hours(1))
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn successful_commit_removes_candidate_without_collecting_blob() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let value = hash(b"committed");
        register_candidates(&db, &[(space.clone(), value)])
            .await
            .unwrap();
        let tx = db.begin().await.unwrap();
        lock_candidates(&tx, &[(space.clone(), value)])
            .await
            .unwrap();
        assert_eq!(upload(&store, &space, b"committed").await, value);
        finish_candidates(&tx, &[(space.clone(), value)])
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            collect_candidates(&db, &store, 10, time::Duration::ZERO)
                .await
                .unwrap(),
            0
        );
        assert!(store.contains(&space, &value).await.unwrap());
    }
}

//! Durable fences for blobs uploaded before a KV transaction's sequence lock.

use std::{borrow::Cow, error::Error as StdError};

use sea_orm::{
    sea_query::{Expr, LockBehavior, LockType, OnConflict},
    ColumnTrait, ConnectionTrait, DatabaseTransaction, DbBackend, DbErr, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, Statement, TransactionTrait,
};
use time::{Duration, OffsetDateTime};
use tinycloud_auth::resource::SpaceId;

use crate::hash::Hash;
use crate::models::{
    current_kv, kv_blob_generation as ledger, kv_orphan_attempt as attempt,
    kv_orphan_candidate as candidate, kv_write,
};
use crate::storage::{ImmutableDeleteStore, ImmutableReadStore};
use crate::types::SpaceIdWrap;

const MAX_BATCH_SIZE: u64 = 256;
/// Expired registrations are collected only after the upload deadline.
pub const ORPHAN_GRACE: Duration = Duration::minutes(5);

const UNAVAILABLE_DELETING: &str = "KV blob is being deleted; retry registration";
const UNAVAILABLE_MISSING: &str = "KV blob attempt lost its active fence";

pub(crate) fn is_candidate_unavailable(error: &DbErr) -> bool {
    matches!(error, DbErr::Custom(message) if message == UNAVAILABLE_DELETING || message == UNAVAILABLE_MISSING)
}

fn ordered_unique(blobs: &[(SpaceId, Hash)]) -> Cow<'_, [(SpaceId, Hash)]> {
    if blobs.windows(2).all(|pair| pair[0] < pair[1]) {
        return Cow::Borrowed(blobs);
    }
    let mut ordered = blobs.to_vec();
    ordered.sort_unstable();
    ordered.dedup();
    Cow::Owned(ordered)
}

/// Register this invocation's durable claim in a short preparatory transaction.
/// The caller commits before uploading. Replaying the same ID is harmless.
pub async fn register_candidates<C: ConnectionTrait>(
    conn: &C,
    blobs: &[(SpaceId, Hash)],
    attempt_id: &str,
) -> Result<Vec<(SpaceId, Hash, i64)>, DbErr> {
    let mut registered_at = None;
    let mut generations = Vec::with_capacity(blobs.len());
    for (space, value) in ordered_unique(blobs).iter() {
        let key = SpaceIdWrap(space.clone());
        if conn.get_database_backend() == DbBackend::Postgres {
            // The ledger upsert serializes registration against deletion. A
            // deleting fence returns no row, so no caller starts an upload.
            let row = conn
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "WITH generation AS (
                    INSERT INTO kv_blob_generation (space, value, generation)
                    VALUES ($1, $2, 0)
                    ON CONFLICT (space, value) DO UPDATE
                        SET generation = kv_blob_generation.generation
                    RETURNING space, value, generation
                ), fence AS (
                    INSERT INTO kv_orphan_candidate
                        (space, value, generation, created_at, deleting_at, deletion_bytes)
                    SELECT space, value, generation, CURRENT_TIMESTAMP, NULL, NULL
                    FROM generation WHERE true
                    ON CONFLICT (space, value) DO UPDATE
                        SET created_at = EXCLUDED.created_at
                        WHERE kv_orphan_candidate.deleting_at IS NULL
                          AND kv_orphan_candidate.generation = EXCLUDED.generation
                    RETURNING space, value, generation
                ), claim AS (
                    INSERT INTO kv_orphan_attempt (space, value, attempt_id, generation, created_at)
                    SELECT space, value, $3, generation, CURRENT_TIMESTAMP FROM fence WHERE true
                    ON CONFLICT (space, value, attempt_id) DO NOTHING
                    RETURNING attempt_id
                )
                SELECT (SELECT generation FROM fence) AS generation,
                       (SELECT COUNT(*) FROM claim) AS inserted",
                    [key.into(), (*value).into(), attempt_id.to_owned().into()],
                ))
                .await?
                .ok_or_else(|| DbErr::Custom("KV candidate registration returned no row".into()))?;
            let generation: Option<i64> = row.try_get("", "generation")?;
            generations.push((
                space.clone(),
                *value,
                generation.ok_or_else(|| DbErr::Custom(UNAVAILABLE_DELETING.into()))?,
            ));
            continue;
        }
        if conn.get_database_backend() == DbBackend::MySql {
            conn.execute(Statement::from_sql_and_values(
                DbBackend::MySql,
                "INSERT INTO kv_blob_generation (space, value, generation) VALUES (?, ?, 0)
                 ON DUPLICATE KEY UPDATE generation = generation",
                [key.clone().into(), (*value).into()],
            ))
            .await?;
        } else {
            let inserted = ledger::Entity::insert(ledger::ActiveModel {
                space: sea_orm::ActiveValue::Set(key.clone()),
                value: sea_orm::ActiveValue::Set(*value),
                generation: sea_orm::ActiveValue::Set(0),
            })
            .on_conflict(
                OnConflict::columns([ledger::Column::Space, ledger::Column::Value])
                    .do_nothing()
                    .to_owned(),
            )
            .exec(conn)
            .await;
            match inserted {
                Ok(_) | Err(DbErr::RecordNotInserted) => {}
                Err(error) => return Err(error),
            }
        }
        let generation = if conn.get_database_backend() == DbBackend::MySql {
            ledger::Entity::find_by_id((key.clone(), *value))
                .lock_exclusive()
                .one(conn)
                .await?
        } else {
            ledger::Entity::find_by_id((key.clone(), *value))
                .one(conn)
                .await?
        }
        .ok_or_else(|| DbErr::Custom("KV generation ledger missing".into()))?
        .generation;
        if conn.get_database_backend() == DbBackend::MySql {
            conn.execute(Statement::from_sql_and_values(
                DbBackend::MySql,
                "INSERT INTO kv_orphan_candidate
                    (space, value, generation, created_at, deleting_at, deletion_bytes)
                 VALUES (?, ?, ?, UTC_TIMESTAMP(6), NULL, NULL)
                 ON DUPLICATE KEY UPDATE created_at = created_at",
                [key.clone().into(), (*value).into(), generation.into()],
            ))
            .await?;
        } else {
            let inserted = candidate::Entity::insert(candidate::ActiveModel {
                space: sea_orm::ActiveValue::Set(key.clone()),
                value: sea_orm::ActiveValue::Set(*value),
                generation: sea_orm::ActiveValue::Set(generation),
                created_at: sea_orm::ActiveValue::Set(OffsetDateTime::now_utc()),
                deleting_at: sea_orm::ActiveValue::Set(None),
                deletion_bytes: sea_orm::ActiveValue::Set(None),
            })
            .on_conflict(
                OnConflict::columns([candidate::Column::Space, candidate::Column::Value])
                    .do_nothing()
                    .to_owned(),
            )
            .exec(conn)
            .await;
            match inserted {
                Ok(_) | Err(DbErr::RecordNotInserted) => {}
                Err(error) => return Err(error),
            }
        }
        let now = match registered_at {
            Some(now) => now,
            None => {
                let now = database_now(conn).await?;
                registered_at = Some(now);
                now
            }
        };
        let active = if conn.get_database_backend() == DbBackend::Sqlite {
            candidate::Entity::update_many()
                .col_expr(candidate::Column::CreatedAt, Expr::value(now))
                .filter(candidate::Column::Space.eq(key.clone()))
                .filter(candidate::Column::Value.eq(*value))
                .filter(candidate::Column::Generation.eq(generation))
                .filter(candidate::Column::DeletingAt.is_null())
                .exec(conn)
                .await?
                .rows_affected
                == 1
        } else {
            let row = candidate::Entity::find_by_id((key.clone(), *value))
                .lock_exclusive()
                .one(conn)
                .await?;
            if row.is_some_and(|row| row.deleting_at.is_none() && row.generation == generation) {
                candidate::Entity::update_many()
                    .col_expr(candidate::Column::CreatedAt, Expr::value(now))
                    .filter(candidate::Column::Space.eq(key.clone()))
                    .filter(candidate::Column::Value.eq(*value))
                    .exec(conn)
                    .await?;
                true
            } else {
                false
            }
        };
        if !active {
            return Err(DbErr::Custom(UNAVAILABLE_DELETING.into()));
        }
        if conn.get_database_backend() == DbBackend::MySql {
            conn.execute(Statement::from_sql_and_values(
                DbBackend::MySql,
                "INSERT INTO kv_orphan_attempt (space, value, attempt_id, generation, created_at)
                 VALUES (?, ?, ?, ?, ?)
                 ON DUPLICATE KEY UPDATE attempt_id = attempt_id",
                [
                    key.into(),
                    (*value).into(),
                    attempt_id.to_owned().into(),
                    generation.into(),
                    now.into(),
                ],
            ))
            .await?;
        } else {
            let inserted = attempt::Entity::insert(attempt::ActiveModel {
                space: sea_orm::ActiveValue::Set(key),
                value: sea_orm::ActiveValue::Set(*value),
                attempt_id: sea_orm::ActiveValue::Set(attempt_id.to_owned()),
                generation: sea_orm::ActiveValue::Set(generation),
                created_at: sea_orm::ActiveValue::Set(now),
            })
            .on_conflict(
                OnConflict::columns([
                    attempt::Column::Space,
                    attempt::Column::Value,
                    attempt::Column::AttemptId,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec(conn)
            .await;
            match inserted {
                Ok(_) | Err(DbErr::RecordNotInserted) => {}
                Err(error) => return Err(error),
            }
        }
        generations.push((space.clone(), *value, generation));
    }
    Ok(generations)
}

/// Validate ownership inside the final KV transaction; never create a missing
/// fence here. The caller already finished ordinary storage I/O.
pub async fn lock_candidates(
    tx: &DatabaseTransaction,
    blobs: &[(SpaceId, Hash, i64)],
    attempt_id: &str,
) -> Result<(), DbErr> {
    for (space, value, generation) in blobs {
        let key = SpaceIdWrap(space.clone());
        if tx.get_database_backend() == DbBackend::Postgres {
            // The joined row lock covers both the active fence and this exact
            // durable attempt. GC removes attempts only after taking that
            // same fence lock, so neither row can disappear before commit.
            let owned = tx
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT 1 AS owned FROM kv_orphan_candidate AS fence
                     JOIN kv_orphan_attempt AS claim
                       ON claim.space = fence.space AND claim.value = fence.value
                         AND claim.generation = fence.generation
                     WHERE fence.space = $1 AND fence.value = $2
                       AND fence.generation = $4
                       AND fence.deleting_at IS NULL AND claim.attempt_id = $3
                     FOR UPDATE OF fence",
                    [
                        key.into(),
                        (*value).into(),
                        attempt_id.to_owned().into(),
                        (*generation).into(),
                    ],
                ))
                .await?
                .is_some();
            if !owned {
                return Err(DbErr::Custom(UNAVAILABLE_MISSING.into()));
            }
            continue;
        }
        let active = if tx.get_database_backend() == DbBackend::Sqlite {
            candidate::Entity::update_many()
                .col_expr(
                    candidate::Column::CreatedAt,
                    Expr::col(candidate::Column::CreatedAt).into(),
                )
                .filter(candidate::Column::Space.eq(key.clone()))
                .filter(candidate::Column::Value.eq(*value))
                .filter(candidate::Column::Generation.eq(*generation))
                .filter(candidate::Column::DeletingAt.is_null())
                .exec(tx)
                .await?
                .rows_affected
                == 1
        } else {
            candidate::Entity::find_by_id((key.clone(), *value))
                .lock_exclusive()
                .one(tx)
                .await?
                .is_some_and(|row| row.deleting_at.is_none() && row.generation == *generation)
        };
        if !active {
            return Err(DbErr::Custom(UNAVAILABLE_MISSING.into()));
        }
        let own = attempt::Entity::find_by_id((key, *value, attempt_id.to_owned()))
            .filter(attempt::Column::Generation.eq(*generation));
        // MySQL repeatable-read may already have an older snapshot from KV
        // authorization. A locking read observes attempts removed by GC.
        let own = if tx.get_database_backend() == DbBackend::MySql {
            own.lock_exclusive()
        } else {
            own
        };
        if own.one(tx).await?.is_none() {
            return Err(DbErr::Custom(UNAVAILABLE_MISSING.into()));
        }
    }
    Ok(())
}

/// Remove only this invocation's claims in the same transaction as its KV refs.
pub async fn finish_candidates(
    tx: &DatabaseTransaction,
    blobs: &[(SpaceId, Hash, i64)],
    attempt_id: &str,
) -> Result<(), DbErr> {
    for (space, value, generation) in blobs {
        let key = SpaceIdWrap(space.clone());
        if tx.get_database_backend() == DbBackend::Postgres {
            // This is only the *successful* KV commit path: transact already
            // wrote the reference in this transaction. Its earlier
            // lock_candidates call holds this fence; `locked` also makes the
            // dependency explicit for the single statement. PostgreSQL CTEs
            // share a snapshot, so exclude our own still-visible attempt
            // when deciding whether another writer remains.
            let row = tx
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "WITH locked AS MATERIALIZED (
                        SELECT space, value FROM kv_orphan_candidate
                        WHERE space = $1 AND value = $2 AND generation = $4
                          AND deleting_at IS NULL
                        FOR UPDATE
                    ), refs AS MATERIALIZED (
                        SELECT EXISTS(
                            SELECT 1 FROM kv_write WHERE space = $1 AND value = $2 AND generation = $4
                        ) OR EXISTS(
                            SELECT 1 FROM current_kv WHERE space = $1 AND value = $2 AND generation = $4
                        ) AS present
                    ), removed AS (
                        DELETE FROM kv_orphan_attempt
                        WHERE space = $1 AND value = $2 AND attempt_id = $3
                          AND generation = $4
                          AND EXISTS(SELECT 1 FROM locked)
                          AND (SELECT present FROM refs)
                        RETURNING space, value
                    ), retired AS (
                        DELETE FROM kv_orphan_candidate AS fence
                        USING removed
                        WHERE fence.space = removed.space
                          AND fence.value = removed.value
                          AND fence.generation = $4
                          AND NOT EXISTS(
                              SELECT 1 FROM kv_orphan_attempt AS other
                              WHERE other.space = fence.space
                                AND other.value = fence.value
                                AND other.generation = $4
                                AND other.attempt_id <> $3
                          )
                        RETURNING 1
                    )
                    SELECT (SELECT COUNT(*) FROM removed) AS removed,
                           (SELECT present FROM refs) AS referenced,
                           (SELECT COUNT(*) FROM retired) AS retired",
                    [key.into(), (*value).into(), attempt_id.to_owned().into(), (*generation).into()],
                ))
                .await?
                .ok_or_else(|| DbErr::Custom("KV candidate finish returned no row".into()))?;
            if !row.try_get::<bool>("", "referenced")? {
                return Err(DbErr::Custom("KV blob has no committed reference".into()));
            }
            if row.try_get::<i64>("", "removed")? != 1 {
                return Err(DbErr::Custom(
                    "KV blob attempt disappeared before commit".into(),
                ));
            }
            continue;
        }
        let removed = attempt::Entity::delete_many()
            .filter(attempt::Column::Space.eq(key.clone()))
            .filter(attempt::Column::Value.eq(*value))
            .filter(attempt::Column::AttemptId.eq(attempt_id))
            .filter(attempt::Column::Generation.eq(*generation))
            .exec(tx)
            .await?;
        if removed.rows_affected != 1 {
            return Err(DbErr::Custom(
                "KV blob attempt disappeared before commit".into(),
            ));
        }
        if !has_attempts(tx, &key, *value, *generation).await?
            && has_references(tx, &key, *value, *generation).await?
        {
            candidate::Entity::delete_many()
                .filter(candidate::Column::Space.eq(key))
                .filter(candidate::Column::Value.eq(*value))
                .filter(candidate::Column::Generation.eq(*generation))
                .exec(tx)
                .await?;
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum CollectError<E: StdError + Send + Sync> {
    #[error("orphan candidate database operation failed: {0}")]
    Database(#[from] DbErr),
    #[error("orphan blob metadata read failed: {0}")]
    Read(String),
    #[error("orphan stage cleanup timed out")]
    StageTimeout,
    #[error("orphan blob deletion failed: {0}")]
    Store(E),
}

async fn has_attempts<C: ConnectionTrait>(
    conn: &C,
    space: &SpaceIdWrap,
    value: Hash,
    generation: i64,
) -> Result<bool, DbErr> {
    let query = attempt::Entity::find()
        .filter(attempt::Column::Space.eq(space.clone()))
        .filter(attempt::Column::Value.eq(value))
        .filter(attempt::Column::Generation.eq(generation));
    let query = if conn.get_database_backend() == DbBackend::MySql {
        query.lock_exclusive()
    } else {
        query
    };
    Ok(query.one(conn).await?.is_some())
}

async fn has_references<C: ConnectionTrait>(
    conn: &C,
    space: &SpaceIdWrap,
    value: Hash,
    generation: i64,
) -> Result<bool, DbErr> {
    let historical = kv_write::Entity::find()
        .filter(kv_write::Column::Space.eq(space.clone()))
        .filter(kv_write::Column::Value.eq(value))
        .filter(kv_write::Column::Generation.eq(generation))
        .select_only()
        .column(kv_write::Column::Seq);
    let current = current_kv::Entity::find()
        .filter(current_kv::Column::Space.eq(space.clone()))
        .filter(current_kv::Column::Value.eq(value))
        .filter(current_kv::Column::Generation.eq(generation))
        .select_only()
        .column(current_kv::Column::Seq);
    // MySQL's repeatable-read snapshot could precede the writer whose fence
    // we just acquired. Locking reads see its committed references.
    let (historical, current) = if conn.get_database_backend() == DbBackend::MySql {
        (historical.lock_exclusive(), current.lock_exclusive())
    } else {
        (historical, current)
    };
    Ok(historical.into_tuple::<i64>().one(conn).await?.is_some()
        || current.into_tuple::<i64>().one(conn).await?.is_some())
}

async fn database_now<C: ConnectionTrait>(conn: &C) -> Result<OffsetDateTime, DbErr> {
    let sql = match conn.get_database_backend() {
        DbBackend::Sqlite => "SELECT CAST(strftime('%s','now') AS INTEGER) AS now_epoch",
        DbBackend::Postgres => {
            "SELECT CAST(EXTRACT(EPOCH FROM CURRENT_TIMESTAMP) AS BIGINT) AS now_epoch"
        }
        DbBackend::MySql => "SELECT CAST(UNIX_TIMESTAMP(CURRENT_TIMESTAMP) AS SIGNED) AS now_epoch",
    };
    let row = conn
        .query_one(Statement::from_string(conn.get_database_backend(), sql))
        .await?
        .ok_or_else(|| DbErr::Custom("database clock unavailable".into()))?;
    let epoch: i64 = row.try_get("", "now_epoch")?;
    OffsetDateTime::from_unix_timestamp(epoch).map_err(|e| DbErr::Custom(e.to_string()))
}

async fn lock_fence(
    tx: &DatabaseTransaction,
    space: &SpaceIdWrap,
    value: Hash,
    generation: i64,
    skip_locked: bool,
) -> Result<Option<candidate::Model>, DbErr> {
    if tx.get_database_backend() == DbBackend::Sqlite {
        let updated = candidate::Entity::update_many()
            .col_expr(
                candidate::Column::CreatedAt,
                Expr::col(candidate::Column::CreatedAt).into(),
            )
            .filter(candidate::Column::Space.eq(space.clone()))
            .filter(candidate::Column::Value.eq(value))
            .filter(candidate::Column::Generation.eq(generation))
            .exec(tx)
            .await?;
        if updated.rows_affected == 0 {
            return Ok(None);
        }
        candidate::Entity::find_by_id((space.clone(), value))
            .filter(candidate::Column::Generation.eq(generation))
            .one(tx)
            .await
    } else {
        let query = candidate::Entity::find_by_id((space.clone(), value))
            .filter(candidate::Column::Generation.eq(generation));
        let query = if skip_locked && tx.get_database_backend() == DbBackend::Postgres {
            query.lock_with_behavior(LockType::Update, LockBehavior::SkipLocked)
        } else {
            query.lock_exclusive()
        };
        query.one(tx).await
    }
}

/// Retire a failed attempt or an expired GC group under the hash fence. GC
/// keeps an expired cleanup claim only while a genuinely live sibling exists.
async fn prepare_deletion<C, S>(
    conn: &C,
    store: &S,
    space: &SpaceId,
    value: Hash,
    generation: i64,
    attempt_id: &str,
    gc_cutoff: Option<OffsetDateTime>,
) -> Result<bool, CollectError<<S as ImmutableDeleteStore>::Error>>
where
    C: ConnectionTrait + TransactionTrait,
    S: ImmutableDeleteStore + ImmutableReadStore,
{
    let bytes = store
        .read(space, &value, generation)
        .await
        .map_err(|error| CollectError::Read(error.to_string()))?
        .map_or(0, |content| content.len());
    let bytes =
        i64::try_from(bytes).map_err(|_| DbErr::Custom("orphan blob size exceeds i64".into()))?;
    let now = database_now(conn).await?;
    let tx = conn.begin().await?;
    let key = SpaceIdWrap(space.clone());
    let Some(fence) = lock_fence(&tx, &key, value, generation, gc_cutoff.is_some()).await? else {
        tx.commit().await?;
        return Ok(false);
    };
    if fence.deleting_at.is_some() {
        tx.commit().await?;
        return Ok(false);
    }
    let mut attempts = attempt::Entity::delete_many()
        .filter(attempt::Column::Space.eq(key.clone()))
        .filter(attempt::Column::Value.eq(value))
        .filter(attempt::Column::Generation.eq(generation));
    if let Some(cutoff) = gc_cutoff {
        // The fence excludes new registrations. If a live sibling exists,
        // retain this expired claim as the stage-cleanup obligation, but move
        // its next eligibility just past this pass's DB-time cutoff so a full
        // blocked page cannot hide unrelated orphans.
        let live = attempt::Entity::find()
            .filter(attempt::Column::Space.eq(key.clone()))
            .filter(attempt::Column::Value.eq(value))
            .filter(attempt::Column::Generation.eq(generation))
            .filter(attempt::Column::AttemptId.ne(attempt_id))
            .filter(attempt::Column::CreatedAt.gt(cutoff))
            .one(&tx)
            .await?
            .is_some();
        if live {
            attempt::Entity::update_many()
                .col_expr(
                    attempt::Column::CreatedAt,
                    Expr::value(cutoff + Duration::seconds(59)),
                )
                .filter(attempt::Column::Space.eq(key))
                .filter(attempt::Column::Value.eq(value))
                .filter(attempt::Column::Generation.eq(generation))
                .filter(attempt::Column::AttemptId.eq(attempt_id))
                .filter(attempt::Column::CreatedAt.lte(cutoff))
                .exec(&tx)
                .await?;
            tx.commit().await?;
            return Ok(false);
        }
        // All siblings are expired. Drain them together under this fence;
        // deleting one at a time would make two crashed uploads immortal.
        attempts = attempts.filter(attempt::Column::CreatedAt.lte(cutoff));
    } else {
        attempts = attempts.filter(attempt::Column::AttemptId.eq(attempt_id));
    }
    let removed = attempts.exec(&tx).await?;
    if removed.rows_affected == 0 {
        tx.commit().await?;
        return Ok(false);
    }
    if gc_cutoff.is_none() && has_attempts(&tx, &key, value, generation).await? {
        tx.commit().await?;
        return Ok(false);
    }
    if has_references(&tx, &key, value, generation).await? {
        // This is a rare local-filesystem cleanup, not a blob upload. Keep
        // the fence locked until only incomplete stages are gone, then retire
        // the candidate. A timeout or cancellation rolls this transaction
        // back, preserving its attempt for the next GC pass.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            store.cleanup_stages(space, &value, generation),
        )
        .await
        .map_err(|_| CollectError::StageTimeout)?
        .map_err(CollectError::Store)?;
        candidate::Entity::delete_many()
            .filter(candidate::Column::Space.eq(key))
            .filter(candidate::Column::Value.eq(value))
            .filter(candidate::Column::Generation.eq(generation))
            .exec(&tx)
            .await?;
        tx.commit().await?;
        return Ok(false);
    }
    candidate::Entity::update_many()
        .col_expr(candidate::Column::DeletingAt, Expr::value(now))
        .col_expr(candidate::Column::DeletionBytes, Expr::value(bytes))
        .filter(candidate::Column::Space.eq(key))
        .filter(candidate::Column::Value.eq(value))
        .filter(candidate::Column::Generation.eq(generation))
        .exec(&tx)
        .await?;
    tx.commit().await?;
    Ok(true)
}

/// Complete a committed deleting fence, with no DB transaction or checked-out
/// DB connection during the object-store call. A lost response leaves it for GC.
async fn complete_deletion<C, S>(
    conn: &C,
    store: &S,
    space: &SpaceId,
    value: Hash,
    generation: i64,
) -> Result<bool, CollectError<<S as ImmutableDeleteStore>::Error>>
where
    C: ConnectionTrait + TransactionTrait,
    S: ImmutableDeleteStore,
{
    let removed = store
        .remove(space, &value, generation)
        .await
        .map_err(CollectError::Store)?
        .is_some();
    // Registration locks ledger before fence; use that same order to retire
    // exactly the deleting generation and allocate the next storage key.
    let tx = conn.begin().await?;
    let key = SpaceIdWrap(space.clone());
    let current = if tx.get_database_backend() == DbBackend::Sqlite {
        ledger::Entity::update_many()
            .col_expr(
                ledger::Column::Generation,
                Expr::col(ledger::Column::Generation).into(),
            )
            .filter(ledger::Column::Space.eq(key.clone()))
            .filter(ledger::Column::Value.eq(value))
            .exec(&tx)
            .await?;
        ledger::Entity::find_by_id((key.clone(), value))
            .one(&tx)
            .await?
    } else {
        ledger::Entity::find_by_id((key.clone(), value))
            .lock_exclusive()
            .one(&tx)
            .await?
    };
    if current.is_some_and(|row| row.generation == generation) {
        let retired = candidate::Entity::delete_many()
            .filter(candidate::Column::Space.eq(key.clone()))
            .filter(candidate::Column::Value.eq(value))
            .filter(candidate::Column::Generation.eq(generation))
            .filter(candidate::Column::DeletingAt.is_not_null())
            .exec(&tx)
            .await?;
        if retired.rows_affected == 1 {
            ledger::Entity::update_many()
                .col_expr(
                    ledger::Column::Generation,
                    Expr::value(
                        generation
                            .checked_add(1)
                            .ok_or_else(|| DbErr::Custom("KV blob generation exhausted".into()))?,
                    ),
                )
                .filter(ledger::Column::Space.eq(key))
                .filter(ledger::Column::Value.eq(value))
                .filter(ledger::Column::Generation.eq(generation))
                .exec(&tx)
                .await?;
        }
    }
    tx.commit().await?;
    Ok(removed)
}

/// Pending refunds used while reconstructing object-store quota after restart.
/// The storage listing must intersect these keys with objects it actually saw.
pub async fn deleting_fences<C: ConnectionTrait>(
    conn: &C,
) -> Result<Vec<(SpaceId, Hash, i64)>, DbErr> {
    Ok(candidate::Entity::find()
        .filter(candidate::Column::DeletingAt.is_not_null())
        .order_by_asc(candidate::Column::Space)
        .order_by_asc(candidate::Column::Value)
        .all(conn)
        .await?
        .into_iter()
        .map(|row| (row.space.0, row.value, row.generation))
        .collect())
}

async fn defer_deletion<C: ConnectionTrait>(
    conn: &C,
    space: &SpaceId,
    value: Hash,
    generation: i64,
) -> Result<(), DbErr> {
    let retry_at = database_now(conn).await? + Duration::seconds(59);
    candidate::Entity::update_many()
        .col_expr(candidate::Column::DeletingAt, Expr::value(retry_at))
        .filter(candidate::Column::Space.eq(SpaceIdWrap(space.clone())))
        .filter(candidate::Column::Value.eq(value))
        .filter(candidate::Column::Generation.eq(generation))
        .filter(candidate::Column::DeletingAt.is_not_null())
        .exec(conn)
        .await?;
    Ok(())
}

async fn defer_attempt<C: ConnectionTrait>(
    conn: &C,
    space: &SpaceId,
    value: Hash,
    generation: i64,
    attempt_id: &str,
) -> Result<(), DbErr> {
    attempt::Entity::update_many()
        .col_expr(
            attempt::Column::CreatedAt,
            Expr::value(database_now(conn).await?),
        )
        .filter(attempt::Column::Space.eq(SpaceIdWrap(space.clone())))
        .filter(attempt::Column::Value.eq(value))
        .filter(attempt::Column::Generation.eq(generation))
        .filter(attempt::Column::AttemptId.eq(attempt_id))
        .exec(conn)
        .await?;
    Ok(())
}
pub async fn refund_failed<C, S>(
    conn: &C,
    store: &S,
    blobs: &[(SpaceId, Hash, i64)],
    attempt_id: &str,
) -> Result<(), CollectError<<S as ImmutableDeleteStore>::Error>>
where
    C: ConnectionTrait + TransactionTrait,
    S: ImmutableDeleteStore + ImmutableReadStore,
{
    for (space, value, generation) in blobs {
        if prepare_deletion(conn, store, space, *value, *generation, attempt_id, None).await? {
            complete_deletion(conn, store, space, *value, *generation).await?;
        }
    }
    Ok(())
}

pub async fn collect_candidates<C, S>(
    conn: &C,
    store: &S,
    max: u64,
    min_age: Duration,
) -> Result<usize, CollectError<<S as ImmutableDeleteStore>::Error>>
where
    C: ConnectionTrait + TransactionTrait,
    S: ImmutableDeleteStore + ImmutableReadStore,
{
    Ok(collect_candidates_with_progress(conn, store, max, min_age)
        .await?
        .0)
}

/// Reclaim expired attempts and retry committed deleting fences. Every
/// candidate is handled in a separate short transaction; slow S3 never holds
/// a fence or database connection.
pub async fn collect_candidates_with_progress<C, S>(
    conn: &C,
    store: &S,
    max: u64,
    min_age: Duration,
) -> Result<(usize, usize), CollectError<<S as ImmutableDeleteStore>::Error>>
where
    C: ConnectionTrait + TransactionTrait,
    S: ImmutableDeleteStore + ImmutableReadStore,
{
    let limit = max.min(MAX_BATCH_SIZE);
    if limit == 0 {
        return Ok((0, 0));
    }
    let now = database_now(conn).await?;
    let cutoff = now
        .checked_sub(min_age)
        .unwrap_or(OffsetDateTime::UNIX_EPOCH);
    let deleting = candidate::Entity::find()
        .filter(candidate::Column::DeletingAt.is_not_null())
        .filter(candidate::Column::DeletingAt.lte(now))
        .order_by_asc(candidate::Column::DeletingAt)
        .order_by_asc(candidate::Column::Space)
        .order_by_asc(candidate::Column::Value)
        .limit(limit)
        .all(conn)
        .await?;
    let attempts = attempt::Entity::find()
        .filter(attempt::Column::CreatedAt.lte(cutoff))
        .order_by_asc(attempt::Column::CreatedAt)
        .order_by_asc(attempt::Column::Space)
        .order_by_asc(attempt::Column::Value)
        .limit(limit.saturating_sub(deleting.len() as u64))
        .all(conn)
        .await?;
    let scanned = deleting.len() + attempts.len();
    let mut removed = 0;
    let mut first_error = None;
    for row in deleting {
        match complete_deletion(conn, store, &row.space.0, row.value, row.generation).await {
            Ok(did_remove) => removed += usize::from(did_remove),
            Err(error) => {
                defer_deletion(conn, &row.space.0, row.value, row.generation).await?;
                first_error.get_or_insert(error);
            }
        }
    }
    for row in attempts {
        match prepare_deletion(
            conn,
            store,
            &row.space.0,
            row.value,
            row.generation,
            &row.attempt_id,
            Some(cutoff),
        )
        .await
        {
            Ok(true) => {
                match complete_deletion(conn, store, &row.space.0, row.value, row.generation).await
                {
                    Ok(did_remove) => removed += usize::from(did_remove),
                    Err(error) => {
                        defer_deletion(conn, &row.space.0, row.value, row.generation).await?;
                        first_error.get_or_insert(error);
                    }
                }
            }
            Ok(false) => {}
            Err(error) => {
                defer_attempt(
                    conn,
                    &row.space.0,
                    row.value,
                    row.generation,
                    &row.attempt_id,
                )
                .await?;
                first_error.get_or_insert(error);
            }
        }
    }
    if let Some(error) = first_error {
        return Err(error);
    }
    Ok((removed, scanned))
}

/// Drain due work for one scheduled collector tick. A full page can contain
/// only temporarily retained claims; never spin indefinitely on it or keep a
/// database connection busy while starving later candidates.
pub async fn drain_candidates_for_interval<C, S>(
    conn: &C,
    store: &S,
    min_age: Duration,
) -> Result<usize, CollectError<<S as ImmutableDeleteStore>::Error>>
where
    C: ConnectionTrait + TransactionTrait,
    S: ImmutableDeleteStore + ImmutableReadStore,
{
    const PAGE_SIZE: usize = 256;
    const MAX_PAGES_PER_INTERVAL: usize = 4;
    let mut removed = 0;
    for _ in 0..MAX_PAGES_PER_INTERVAL {
        let (deleted, scanned) =
            collect_candidates_with_progress(conn, store, PAGE_SIZE as u64, min_age).await?;
        removed += deleted;
        if scanned < PAGE_SIZE {
            break;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::hash;
    use crate::models::{kv_orphan_attempt, kv_orphan_candidate};
    use crate::storage::{
        memory::MemoryStore, HashBuffer, ImmutableReadStore, ImmutableWriteStore, StoreSize,
    };
    use futures::io::AsyncWriteExt;
    use sea_orm::{
        sea_query::Expr, ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend,
        EntityTrait, QueryFilter, Statement, TransactionTrait,
    };
    use sea_orm_migration::MigratorTrait;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use tinycloud_auth::{resolver::DID_METHODS, ssi::jwk::JWK};
    use tokio::sync::Notify;

    #[derive(Clone)]
    struct InterruptedDelete {
        inner: Arc<MemoryStore>,
        entered: Arc<Notify>,
        resume: Arc<Notify>,
        pause: Arc<AtomicBool>,
        lose_response: Arc<AtomicBool>,
        fail_read: Arc<AtomicBool>,
    }

    impl InterruptedDelete {
        fn new(inner: Arc<MemoryStore>) -> Self {
            Self {
                inner,
                entered: Arc::new(Notify::new()),
                resume: Arc::new(Notify::new()),
                pause: Arc::new(AtomicBool::new(false)),
                lose_response: Arc::new(AtomicBool::new(false)),
                fail_read: Arc::new(AtomicBool::new(false)),
            }
        }
    }

    #[async_trait::async_trait]
    impl ImmutableReadStore for InterruptedDelete {
        type Error = std::io::Error;
        type Readable = <MemoryStore as ImmutableReadStore>::Readable;

        async fn contains(
            &self,
            space: &SpaceId,
            id: &Hash,
            generation: i64,
        ) -> Result<bool, Self::Error> {
            self.inner.contains(space, id, generation).await
        }

        async fn read(
            &self,
            space: &SpaceId,
            id: &Hash,
            generation: i64,
        ) -> Result<Option<crate::storage::Content<Self::Readable>>, Self::Error> {
            if self.fail_read.swap(false, Ordering::SeqCst) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "lost HEAD response",
                ));
            }
            self.inner.read(space, id, generation).await
        }

        async fn read_range(
            &self,
            space: &SpaceId,
            id: &Hash,
            generation: i64,
            range: crate::storage::ByteRangeSpec,
        ) -> Result<Option<crate::storage::RangeRead<Self::Readable>>, Self::Error> {
            self.inner.read_range(space, id, generation, range).await
        }
    }

    #[async_trait::async_trait]
    impl ImmutableDeleteStore for InterruptedDelete {
        type Error = std::io::Error;

        async fn remove(
            &self,
            space: &SpaceId,
            id: &Hash,
            generation: i64,
        ) -> Result<Option<()>, Self::Error> {
            if self.pause.swap(false, Ordering::SeqCst) {
                self.entered.notify_one();
                self.resume.notified().await;
            }
            let removed = self.inner.remove(space, id, generation).await?;
            if self.lose_response.swap(false, Ordering::SeqCst) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "lost DELETE response",
                ));
            }
            Ok(removed)
        }
        async fn cleanup_stages(
            &self,
            space: &SpaceId,
            id: &Hash,
            generation: i64,
        ) -> Result<(), Self::Error> {
            self.inner.cleanup_stages(space, id, generation).await
        }
    }

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
        upload_generation(store, space, bytes, 0).await
    }

    async fn upload_generation(
        store: &MemoryStore,
        space: &SpaceId,
        bytes: &[u8],
        generation: i64,
    ) -> Hash {
        let mut staged = HashBuffer::new(Vec::new());
        staged.write_all(bytes).await.unwrap();
        store.persist(space, staged, generation).await.unwrap()
    }

    async fn age(db: &DatabaseConnection, space: &SpaceId, value: Hash) {
        kv_orphan_attempt::Entity::update_many()
            .col_expr(
                kv_orphan_attempt::Column::CreatedAt,
                Expr::value(time::OffsetDateTime::now_utc() - time::Duration::hours(2)),
            )
            .filter(kv_orphan_attempt::Column::Space.eq(SpaceIdWrap(space.clone())))
            .filter(kv_orphan_attempt::Column::Value.eq(value))
            .exec(db)
            .await
            .unwrap();
    }

    async fn register(
        db: &DatabaseConnection,
        blobs: &[(SpaceId, Hash)],
        id: &str,
    ) -> Vec<(SpaceId, Hash, i64)> {
        let tx = db.begin().await.unwrap();
        let registered = register_candidates(&tx, blobs, id).await.unwrap();
        tx.commit().await.unwrap();
        registered
    }

    fn gen0(blobs: &[(SpaceId, Hash)]) -> Vec<(SpaceId, Hash, i64)> {
        blobs
            .iter()
            .map(|(space, value)| (space.clone(), *value, 0))
            .collect()
    }

    async fn reference<C: ConnectionTrait>(
        db: &C,
        table: &str,
        space: &SpaceId,
        value: Hash,
        generation: i64,
    ) {
        let sql = match (table, generation) {
            ("kv_write", 0) =>
                "INSERT INTO kv_write (space, key, invocation, seq, epoch, epoch_seq, value, metadata) VALUES (?, 'a', ?, 1, ?, 1, ?, '{}')",
            ("kv_write", _) =>
                "INSERT INTO kv_write (space, key, invocation, seq, epoch, epoch_seq, value, metadata, generation) VALUES (?, 'a', ?, 1, ?, 1, ?, '{}', ?)",
            (_, 0) =>
                "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, metadata, deleted) VALUES (?, 'a', ?, 1, ?, 1, ?, '{}', 0)",
            (_, _) =>
                "INSERT INTO current_kv (space, key, invocation, seq, epoch, epoch_seq, value, metadata, deleted, generation) VALUES (?, 'a', ?, 1, ?, 1, ?, '{}', 0, ?)",
        };
        let mut values: Vec<sea_orm::Value> = vec![
            space.to_string().into(),
            Vec::<u8>::from(hash(table.as_bytes())).into(),
            Vec::<u8>::from(hash(b"epoch")).into(),
            Vec::<u8>::from(value).into(),
        ];
        if generation != 0 {
            values.push(generation.into());
        }
        db.execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            sql,
            values,
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
        register(&db, &candidates, "a").await;
        for (space, hash) in &candidates {
            age(&db, space, *hash).await;
        }
        reference(&db, "kv_write", &history_space, historical, 0).await;
        reference(&db, "current_kv", &current_space, current, 0).await;
        assert_eq!(
            kv_write::Entity::find()
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .generation,
            0
        );
        assert_eq!(
            current_kv::Entity::find()
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .generation,
            0
        );

        assert_eq!(
            collect_candidates(&db, &store, 10, time::Duration::hours(1))
                .await
                .unwrap(),
            0
        );
        for (space, hash) in &candidates {
            assert!(store.contains(space, hash, 0).await.unwrap());
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
        register(&db, &[(space.clone(), value)], "a").await;
        assert_eq!(upload(&store, &space, b"failed-precondition").await, value);
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(b"failed-precondition".len() as u64)
        );
        let tx = db.begin().await.unwrap();
        lock_candidates(&tx, &[(space.clone(), value, 0)], "a")
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
        assert!(!store.contains(&space, &value, 0).await.unwrap());
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
            register(&db, &[(space.clone(), value)], "a").await;
            age(&db, &space, value).await;
            old.push(value);
        }
        let fresh = upload(&store, &space, b"fresh").await;
        register(&db, &[(space.clone(), fresh)], "a").await;
        assert_eq!(
            collect_candidates(&db, &store, 2, time::Duration::hours(1))
                .await
                .unwrap(),
            2
        );
        let mut surviving = 0;
        for value in &old {
            surviving += usize::from(store.contains(&space, value, 0).await.unwrap());
        }
        assert_eq!(surviving, 1);
        assert!(store.contains(&space, &fresh, 0).await.unwrap());
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
        assert!(store.contains(&space, &fresh, 0).await.unwrap());
    }

    #[tokio::test]
    async fn registering_existing_hash_resets_grace_period() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let value = upload(&store, &space, b"same-hash").await;
        register(&db, &[(space.clone(), value)], "a").await;
        age(&db, &space, value).await;
        register(&db, &[(space.clone(), value)], "b").await;

        assert_eq!(
            collect_candidates(&db, &store, 1, time::Duration::hours(1))
                .await
                .unwrap(),
            0
        );
        assert!(store.contains(&space, &value, 0).await.unwrap());
    }

    #[tokio::test]
    async fn first_failure_preserves_second_attempt_and_its_rollback_cleanup() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let value = hash(b"same candidate race");
        let blobs = [(space.clone(), value)];
        let tx = db.begin().await.unwrap();
        register_candidates(&tx, &blobs, "a").await.unwrap();
        tx.commit().await.unwrap();
        assert_eq!(upload(&store, &space, b"same candidate race").await, value);
        let tx = db.begin().await.unwrap();
        register_candidates(&tx, &blobs, "b").await.unwrap();
        tx.commit().await.unwrap();

        refund_failed(&db, &store, &gen0(&blobs), "a")
            .await
            .unwrap();
        assert!(store.contains(&space, &value, 0).await.unwrap());
        let b = db.begin().await.unwrap();
        lock_candidates(&b, &gen0(&blobs), "b").await.unwrap();
        b.rollback().await.unwrap();
        refund_failed(&db, &store, &gen0(&blobs), "b")
            .await
            .unwrap();
        assert!(!store.contains(&space, &value, 0).await.unwrap());
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
    }

    #[tokio::test]
    async fn successful_same_hash_writer_protects_failed_writers_blob() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let value = upload(&store, &space, b"referenced-dedup").await;
        let blobs = [(space.clone(), value)];
        register(&db, &blobs, "a").await;
        register(&db, &blobs, "b").await;
        let tx = db.begin().await.unwrap();
        lock_candidates(&tx, &gen0(&blobs), "b").await.unwrap();
        reference(&tx, "kv_write", &space, value, 0).await;
        finish_candidates(&tx, &gen0(&blobs), "b").await.unwrap();
        tx.commit().await.unwrap();
        refund_failed(&db, &store, &gen0(&blobs), "a")
            .await
            .unwrap();
        assert!(store.contains(&space, &value, 0).await.unwrap());
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(b"referenced-dedup".len() as u64)
        );
        assert_eq!(
            collect_candidates(&db, &store, 10, Duration::ZERO)
                .await
                .unwrap(),
            0
        );
        assert!(
            kv_orphan_candidate::Entity::find_by_id((SpaceIdWrap(space), value))
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn expired_same_hash_attempts_drain_as_one_unreferenced_group() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let value = upload(&store, &space, b"two crashed uploads").await;
        let blob = [(space.clone(), value)];
        register(&db, &blob, "crashed-a").await;
        register(&db, &blob, "crashed-b").await;
        age(&db, &space, value).await;

        assert_eq!(
            collect_candidates(&db, &store, 256, ORPHAN_GRACE)
                .await
                .unwrap(),
            1
        );
        assert!(!store.contains(&space, &value, 0).await.unwrap());
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
        assert_eq!(
            kv_orphan_attempt::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            kv_orphan_candidate::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn expired_same_hash_attempts_drain_without_removing_committed_reference() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let value = upload(&store, &space, b"referenced retry").await;
        let blob = [(space.clone(), value)];
        register(&db, &blob, "crashed-a").await;
        register(&db, &blob, "crashed-b").await;
        age(&db, &space, value).await;
        reference(&db, "kv_write", &space, value, 0).await;

        assert_eq!(
            collect_candidates(&db, &store, 256, ORPHAN_GRACE)
                .await
                .unwrap(),
            0
        );
        assert!(store.contains(&space, &value, 0).await.unwrap());
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(b"referenced retry".len() as u64)
        );
        assert_eq!(
            kv_orphan_attempt::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            0
        );
        assert_eq!(
            kv_orphan_candidate::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            0
        );
    }

    #[tokio::test]
    async fn full_page_retained_for_live_writer_does_not_hide_later_orphans() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let blocked = upload(&store, &space, b"blocked group").await;
        let blocked_blob = [(space.clone(), blocked)];
        for index in 0..256 {
            register(&db, &blocked_blob, &format!("crashed-{index}")).await;
        }
        age(&db, &space, blocked).await;
        register(&db, &blocked_blob, "active-writer").await;

        let later = upload(&store, &space, b"independent later orphan").await;
        register(&db, &[(space.clone(), later)], "later-crash").await;
        age(&db, &space, later).await;
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(3),
                drain_candidates_for_interval(&db, &store, ORPHAN_GRACE),
            )
            .await
            .expect("one collector tick must terminate on a blocked full page")
            .unwrap(),
            1,
            "the retained page must not starve an independent later orphan"
        );
        assert!(!store.contains(&space, &later, 0).await.unwrap());
        assert!(store.contains(&space, &blocked, 0).await.unwrap());
    }

    #[tokio::test]
    async fn replayed_registration_requires_own_attempt_without_duplicating_it() {
        let db = database().await;
        let space = space();
        let value = hash(b"replay");
        let blobs = [(space.clone(), value)];
        register(&db, &blobs, "a").await;
        register(&db, &blobs, "a").await;
        let attempts = kv_orphan_attempt::Entity::find()
            .filter(kv_orphan_attempt::Column::Space.eq(SpaceIdWrap(space.clone())))
            .filter(kv_orphan_attempt::Column::Value.eq(value))
            .all(&db)
            .await
            .unwrap();
        assert_eq!(attempts.len(), 1);
        let tx = db.begin().await.unwrap();
        let error = lock_candidates(&tx, &gen0(&blobs), "b").await.unwrap_err();
        assert!(is_candidate_unavailable(&error));
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn deleting_fence_refuses_new_attempt_until_delete_finishes() {
        let db = database().await;
        let space = space();
        let value = hash(b"stale delete cannot hit a new write");
        let blobs = [(space.clone(), value)];
        let tx = db.begin().await.unwrap();
        register_candidates(&tx, &blobs, "a").await.unwrap();
        tx.commit().await.unwrap();
        kv_orphan_candidate::Entity::update_many()
            .col_expr(
                kv_orphan_candidate::Column::DeletingAt,
                Expr::value(time::OffsetDateTime::now_utc()),
            )
            .filter(kv_orphan_candidate::Column::Space.eq(SpaceIdWrap(space)))
            .filter(kv_orphan_candidate::Column::Value.eq(value))
            .exec(&db)
            .await
            .unwrap();
        let tx = db.begin().await.unwrap();
        assert!(register_candidates(&tx, &blobs, "b").await.is_err());
        tx.rollback().await.unwrap();
    }

    #[tokio::test]
    async fn slow_delete_releases_database_and_refuses_new_preflight() {
        let db = database().await;
        let inner = Arc::new(MemoryStore::default());
        let store = InterruptedDelete::new(inner.clone());
        let space = space();
        let value = upload(&inner, &space, b"slow-delete").await;
        let blobs = [(space.clone(), value)];
        let old = register(&db, &blobs, "a").await;
        store.pause.store(true, Ordering::SeqCst);
        let deleting = tokio::spawn({
            let db = db.clone();
            let store = store.clone();
            let old = old.clone();
            async move { refund_failed(&db, &store, &old, "a").await }
        });
        store.entered.notified().await;
        let fence = kv_orphan_candidate::Entity::find_by_id((SpaceIdWrap(space.clone()), value))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fence.deletion_bytes, Some(b"slow-delete".len() as i64));
        assert!(fence.deleting_at.is_some());
        let tx = tokio::time::timeout(std::time::Duration::from_secs(1), db.begin())
            .await
            .unwrap()
            .unwrap();
        let error = register_candidates(&tx, &blobs, "b").await.unwrap_err();
        assert!(is_candidate_unavailable(&error));
        tx.rollback().await.unwrap();
        store.resume.notify_one();
        deleting.await.unwrap().unwrap();
        assert!(!inner.contains(&space, &value, 0).await.unwrap());
        let next = register(&db, &blobs, "b").await;
        assert_eq!(next[0].2, 1);
        assert_eq!(
            upload_generation(&inner, &space, b"slow-delete", 1).await,
            value
        );
        let tx = db.begin().await.unwrap();
        lock_candidates(&tx, &next, "b").await.unwrap();
        reference(&tx, "kv_write", &space, value, 1).await;
        finish_candidates(&tx, &next, "b").await.unwrap();
        tx.commit().await.unwrap();
        assert!(kv_write::Entity::find()
            .filter(kv_write::Column::Space.eq(SpaceIdWrap(space.clone())))
            .filter(kv_write::Column::Value.eq(value))
            .one(&db)
            .await
            .unwrap()
            .is_some());
        assert!(inner.contains(&space, &value, 1).await.unwrap());
        assert_eq!(
            inner.total_size(&space).await.unwrap(),
            Some(b"slow-delete".len() as u64)
        );
    }

    #[tokio::test]
    async fn lost_delete_response_retries_from_durable_fence_once() {
        let db = database().await;
        let inner = Arc::new(MemoryStore::default());
        let store = InterruptedDelete::new(inner.clone());
        let space = space();
        let value = upload(&inner, &space, b"lost-delete").await;
        let blobs = [(space.clone(), value)];
        let old = register(&db, &blobs, "a").await;
        store.lose_response.store(true, Ordering::SeqCst);
        assert!(refund_failed(&db, &store, &old, "a").await.is_err());
        let fence = kv_orphan_candidate::Entity::find_by_id((SpaceIdWrap(space.clone()), value))
            .one(&db)
            .await
            .unwrap()
            .unwrap();
        assert!(fence.deleting_at.is_some());
        assert_eq!(fence.deletion_bytes, Some(b"lost-delete".len() as i64));
        assert!(!inner.contains(&space, &value, 0).await.unwrap());
        assert_eq!(deleting_fences(&db).await.unwrap(), old);
        assert_eq!(
            collect_candidates(&db, &store, 10, Duration::ZERO)
                .await
                .unwrap(),
            0,
            "the retry confirms absence without charging a second refund"
        );
        assert!(
            kv_orphan_candidate::Entity::find_by_id((SpaceIdWrap(space.clone()), value))
                .one(&db)
                .await
                .unwrap()
                .is_none()
        );
        assert!(deleting_fences(&db).await.unwrap().is_empty());
        assert_eq!(inner.total_size(&space).await.unwrap(), Some(0));
    }

    #[tokio::test]
    async fn two_deleters_cannot_remove_a_newly_committed_same_hash() {
        let db = database().await;
        let inner = Arc::new(MemoryStore::default());
        let store = InterruptedDelete::new(inner.clone());
        let space = space();
        let value = upload(&inner, &space, b"two-deleter-race").await;
        let blobs = [(space.clone(), value)];
        let old = register(&db, &blobs, "a").await;

        store.pause.store(true, Ordering::SeqCst);
        let first = tokio::spawn({
            let db = db.clone();
            let store = store.clone();
            let old = old.clone();
            async move { refund_failed(&db, &store, &old, "a").await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), store.entered.notified())
            .await
            .unwrap();
        store.pause.store(true, Ordering::SeqCst);
        let second_entered = store.entered.notified();
        let second = tokio::spawn({
            let db = db.clone();
            let store = store.clone();
            async move { collect_candidates(&db, &store, 10, Duration::ZERO).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), second_entered)
            .await
            .unwrap();
        store.resume.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), first)
            .await
            .unwrap()
            .unwrap()
            .unwrap();

        let next = register(&db, &blobs, "b").await;
        assert_eq!(next[0].2, 1);
        let stale = db.begin().await.unwrap();
        assert!(is_candidate_unavailable(
            &lock_candidates(&stale, &old, "b").await.unwrap_err()
        ));
        stale.rollback().await.unwrap();
        assert_eq!(
            upload_generation(&inner, &space, b"two-deleter-race", 1).await,
            value
        );
        let tx = db.begin().await.unwrap();
        lock_candidates(&tx, &next, "b").await.unwrap();
        reference(&tx, "kv_write", &space, value, 1).await;
        finish_candidates(&tx, &next, "b").await.unwrap();
        tx.commit().await.unwrap();

        store.resume.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), second)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(
            inner.contains(&space, &value, 1).await.unwrap(),
            "a delayed gen0 DELETE removed newly committed gen1 content"
        );
        assert!(!inner.contains(&space, &value, 0).await.unwrap());
        assert_eq!(
            kv_write::Entity::find()
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .generation,
            1
        );
        assert_eq!(
            ledger::Entity::find_by_id((SpaceIdWrap(space), value))
                .one(&db)
                .await
                .unwrap()
                .unwrap()
                .generation,
            1
        );
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
        let prep = fixture.conn.begin().await.unwrap();
        register_candidates(&prep, &[(space.clone(), value)], "a")
            .await
            .unwrap();
        prep.commit().await.unwrap();
        kv_orphan_attempt::Entity::update_many()
            .col_expr(
                kv_orphan_attempt::Column::CreatedAt,
                Expr::value(time::OffsetDateTime::now_utc() - time::Duration::hours(2)),
            )
            .filter(kv_orphan_attempt::Column::Space.eq(SpaceIdWrap(space.clone())))
            .filter(kv_orphan_attempt::Column::Value.eq(value))
            .exec(&fixture.conn)
            .await
            .unwrap();
        let tx = fixture.conn.begin().await.unwrap();
        lock_candidates(&tx, &[(space.clone(), value, 0)], "a")
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
        assert!(store.contains(&space, &value, 0).await.unwrap());
        tx.rollback().await.unwrap();
        assert_eq!(
            collect_candidates(&fixture.conn, &store, 1, time::Duration::hours(1))
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn postgres_expired_same_hash_claims_drain_under_one_fence() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_expired_same_hash_claims_drain_under_one_fence",
        )
        .await
        else {
            return;
        };
        let store = MemoryStore::default();
        let space = space();
        let value = upload(&store, &space, b"expired-pg-group").await;
        let blob = [(space.clone(), value)];
        register(&fixture.conn, &blob, "crashed-a").await;
        register(&fixture.conn, &blob, "crashed-b").await;
        age(&fixture.conn, &space, value).await;
        assert_eq!(
            collect_candidates(&fixture.conn, &store, 256, ORPHAN_GRACE)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            kv_orphan_attempt::Entity::find()
                .all(&fixture.conn)
                .await
                .unwrap()
                .len(),
            0
        );
        assert!(!store.contains(&space, &value, 0).await.unwrap());
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
    }

    #[tokio::test]
    async fn postgres_failed_attempt_cannot_erase_another_durable_registration() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_failed_attempt_cannot_erase_another_durable_registration",
        )
        .await
        else {
            return;
        };
        let store = MemoryStore::default();
        let space = space();
        let value = upload(&store, &space, b"same-hash overlap").await;
        let blobs = [(space.clone(), value)];
        register(&fixture.conn, &blobs, "a").await;
        register(&fixture.conn, &blobs, "b").await;
        refund_failed(&fixture.conn, &store, &gen0(&blobs), "a")
            .await
            .unwrap();
        assert!(store.contains(&space, &value, 0).await.unwrap());
        let tx = fixture.conn.begin().await.unwrap();
        lock_candidates(&tx, &gen0(&blobs), "b").await.unwrap();
        tx.rollback().await.unwrap();
        refund_failed(&fixture.conn, &store, &gen0(&blobs), "b")
            .await
            .unwrap();
        assert!(!store.contains(&space, &value, 0).await.unwrap());
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
        assert!(deleting_fences(&fixture.conn).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn postgres_delete_in_flight_blocks_dedup_and_retries_lost_response() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_delete_in_flight_blocks_dedup_and_retries_lost_response",
        )
        .await
        else {
            return;
        };
        let inner = Arc::new(MemoryStore::default());
        let store = InterruptedDelete::new(inner.clone());
        let space = space();
        let value = upload(&inner, &space, b"delete-in-flight").await;
        let blobs = [(space.clone(), value)];
        let old = register(&fixture.conn, &blobs, "a").await;
        store.pause.store(true, Ordering::SeqCst);
        let deleting = tokio::spawn({
            let conn = fixture.conn.clone();
            let store = store.clone();
            let old = old.clone();
            async move { refund_failed(&conn, &store, &old, "a").await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), store.entered.notified())
            .await
            .unwrap();
        assert_eq!(deleting_fences(&fixture.conn).await.unwrap(), old);
        let tx = fixture.conn.begin().await.unwrap();
        let unavailable = register_candidates(&tx, &blobs, "b").await.unwrap_err();
        assert!(is_candidate_unavailable(&unavailable));
        tx.rollback().await.unwrap();
        store.resume.notify_one();
        deleting.await.unwrap().unwrap();
        assert!(!inner.contains(&space, &value, 0).await.unwrap());
        let second = register(&fixture.conn, &blobs, "b").await;
        assert_eq!(second[0].2, 1);
        assert_eq!(
            upload_generation(&inner, &space, b"delete-in-flight", 1).await,
            value
        );
        let tx = fixture.conn.begin().await.unwrap();
        lock_candidates(&tx, &second, "b").await.unwrap();
        tx.rollback().await.unwrap();
        assert!(inner.contains(&space, &value, 1).await.unwrap());
        refund_failed(&fixture.conn, &store, &second, "b")
            .await
            .unwrap();
        assert!(!inner.contains(&space, &value, 1).await.unwrap());

        // A successful physical DELETE with a lost reply keeps only the
        // deleting fence, which GC consumes without a second refund.
        let third = register(&fixture.conn, &blobs, "c").await;
        assert_eq!(third[0].2, 2);
        assert_eq!(
            upload_generation(&inner, &space, b"delete-in-flight", 2).await,
            value
        );
        store.lose_response.store(true, Ordering::SeqCst);
        assert!(refund_failed(&fixture.conn, &store, &third, "c")
            .await
            .is_err());
        assert_eq!(deleting_fences(&fixture.conn).await.unwrap(), third);
        assert!(!inner.contains(&space, &value, 2).await.unwrap());
        assert_eq!(
            collect_candidates(&fixture.conn, &store, 10, Duration::ZERO)
                .await
                .unwrap(),
            0
        );
        assert!(deleting_fences(&fixture.conn).await.unwrap().is_empty());
        assert_eq!(inner.total_size(&space).await.unwrap(), Some(0));
    }

    #[tokio::test]
    async fn postgres_generation_survives_independent_pool_and_delayed_delete() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_generation_survives_independent_pool_and_delayed_delete",
        )
        .await
        else {
            return;
        };
        let inner = Arc::new(MemoryStore::default());
        let store = InterruptedDelete::new(inner.clone());
        let space = space();
        let value = upload(&inner, &space, b"independent-pool").await;
        let blobs = [(space.clone(), value)];
        let first = register(&fixture.conn, &blobs, "first").await;
        assert_eq!(first[0].2, 0);
        store.pause.store(true, Ordering::SeqCst);
        let deletion = tokio::spawn({
            let conn = fixture.conn.clone();
            let store = store.clone();
            let first = first.clone();
            async move { refund_failed(&conn, &store, &first, "first").await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), store.entered.notified())
            .await
            .unwrap();
        store.pause.store(true, Ordering::SeqCst);
        let second_entered = store.entered.notified();
        let delayed = tokio::spawn({
            let conn = fixture.conn.clone();
            let store = store.clone();
            async move { collect_candidates(&conn, &store, 1, Duration::ZERO).await }
        });
        tokio::time::timeout(std::time::Duration::from_secs(5), second_entered)
            .await
            .unwrap();
        store.resume.notify_one();
        deletion.await.unwrap().unwrap();
        let schema: String = fixture
            .conn
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT current_schema() AS schema_name",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "schema_name")
            .unwrap();
        let url = crate::test_support::postgres_test_url(
            "postgres_generation_survives_independent_pool_and_delayed_delete",
        )
        .unwrap();
        let mut options = ConnectOptions::new(url);
        options.set_schema_search_path(schema);
        let restarted = Database::connect(options).await.unwrap();
        let second = register(&restarted, &blobs, "second").await;
        assert_eq!(second[0].2, 1);
        assert_eq!(
            upload_generation(&inner, &space, b"independent-pool", 1).await,
            value
        );
        let tx = restarted.begin().await.unwrap();
        lock_candidates(&tx, &second, "second").await.unwrap();
        tx.rollback().await.unwrap();
        store.resume.notify_one();
        delayed.await.unwrap().unwrap();
        assert!(inner.contains(&space, &value, 1).await.unwrap());
        assert_eq!(
            ledger::Entity::find_by_id((SpaceIdWrap(space.clone()), value))
                .one(&fixture.conn)
                .await
                .unwrap()
                .unwrap()
                .generation,
            1
        );
        let tx = restarted.begin().await.unwrap();
        lock_candidates(&tx, &second, "second").await.unwrap();
        tx.rollback().await.unwrap();
        restarted.close().await.unwrap();
    }

    #[tokio::test]
    async fn mysql_attempt_fence_preserves_other_writer_and_recovers_lost_delete() {
        let Ok(url) = std::env::var("TINYCLOUD_TEST_MYSQL_URL") else {
            eprintln!("skipping MySQL orphan fence (TINYCLOUD_TEST_MYSQL_URL unset)");
            return;
        };
        let (prefix, _) = url.rsplit_once('/').expect("MySQL URL needs a database");
        let name = format!(
            "tc735_orphan_{}_{}",
            std::process::id(),
            OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let admin = Database::connect(url.as_str()).await.unwrap();
        admin
            .execute(Statement::from_string(
                DbBackend::MySql,
                format!("CREATE DATABASE {name}"),
            ))
            .await
            .unwrap();
        let db = Database::connect(format!("{prefix}/{name}")).await.unwrap();
        // The older full MySQL migrator fails on unrelated indexed-column
        // widths. Exercise the production model columns and transaction
        // semantics here without altering unrelated migrations.
        for ddl in [
            "CREATE TABLE kv_blob_generation (
                space VARCHAR(191) NOT NULL, value VARBINARY(34) NOT NULL,
                generation BIGINT NOT NULL, PRIMARY KEY (space, value))",
            "CREATE TABLE kv_orphan_candidate (
                space VARCHAR(191) NOT NULL, value VARBINARY(34) NOT NULL,
                generation BIGINT NOT NULL, created_at DATETIME(6) NOT NULL,
                deleting_at DATETIME(6) NULL, deletion_bytes BIGINT NULL,
                PRIMARY KEY (space, value))",
            "CREATE TABLE kv_orphan_attempt (
                space VARCHAR(191) NOT NULL, value VARBINARY(34) NOT NULL,
                attempt_id VARCHAR(32) NOT NULL, generation BIGINT NOT NULL,
                created_at DATETIME(6) NOT NULL, PRIMARY KEY (space, value, attempt_id))",
            "CREATE TABLE kv_write (space VARCHAR(191), value VARBINARY(34),
                generation BIGINT NOT NULL DEFAULT 0, seq BIGINT NOT NULL, INDEX (space, value))",
            "CREATE TABLE current_kv (space VARCHAR(191), value VARBINARY(34),
                generation BIGINT NOT NULL DEFAULT 0, seq BIGINT NOT NULL, INDEX (space, value))",
        ] {
            db.execute(Statement::from_string(DbBackend::MySql, ddl))
                .await
                .unwrap();
        }
        let inner = Arc::new(MemoryStore::default());
        let store = InterruptedDelete::new(inner.clone());
        let space = space();
        let value = upload(&inner, &space, b"mysql-overlap").await;
        let blobs = [(space.clone(), value)];
        register(&db, &blobs, "a").await;
        register(&db, &blobs, "b").await;
        refund_failed(&db, &store, &gen0(&blobs), "a")
            .await
            .unwrap();
        assert!(inner.contains(&space, &value, 0).await.unwrap());
        let tx = db.begin().await.unwrap();
        lock_candidates(&tx, &gen0(&blobs), "b").await.unwrap();
        tx.rollback().await.unwrap();
        store.lose_response.store(true, Ordering::SeqCst);
        assert!(refund_failed(&db, &store, &gen0(&blobs), "b")
            .await
            .is_err());
        assert_eq!(deleting_fences(&db).await.unwrap(), gen0(&blobs));
        let tx = db.begin().await.unwrap();
        assert!(is_candidate_unavailable(
            &register_candidates(&tx, &blobs, "c").await.unwrap_err(),
        ));
        tx.rollback().await.unwrap();
        assert_eq!(
            collect_candidates(&db, &store, 10, Duration::ZERO)
                .await
                .unwrap(),
            0
        );
        let third = register(&db, &blobs, "c").await;
        assert_eq!(third[0].2, 1);
        assert_eq!(
            upload_generation(&inner, &space, b"mysql-overlap", 1).await,
            value
        );
        refund_failed(&db, &store, &third, "c").await.unwrap();
        assert_eq!(inner.total_size(&space).await.unwrap(), Some(0));
        let expired = upload(&inner, &space, b"mysql-two-expired").await;
        let expired_blob = [(space.clone(), expired)];
        register(&db, &expired_blob, "expired-a").await;
        register(&db, &expired_blob, "expired-b").await;
        age(&db, &space, expired).await;
        assert_eq!(
            collect_candidates(&db, &store, 256, ORPHAN_GRACE)
                .await
                .unwrap(),
            1
        );
        assert!(!inner.contains(&space, &expired, 0).await.unwrap());
        assert_eq!(inner.total_size(&space).await.unwrap(), Some(0));
        db.close().await.unwrap();
        admin
            .execute(Statement::from_string(
                DbBackend::MySql,
                format!("DROP DATABASE {name}"),
            ))
            .await
            .unwrap();
        admin.close().await.unwrap();
    }

    #[tokio::test]
    async fn successful_commit_removes_candidate_without_collecting_blob() {
        let db = database().await;
        let store = MemoryStore::default();
        let space = space();
        let value = hash(b"committed");
        register(&db, &[(space.clone(), value)], "a").await;
        let tx = db.begin().await.unwrap();
        lock_candidates(&tx, &[(space.clone(), value, 0)], "a")
            .await
            .unwrap();
        assert_eq!(upload(&store, &space, b"committed").await, value);
        reference(&tx, "kv_write", &space, value, 0).await;
        finish_candidates(&tx, &[(space.clone(), value, 0)], "a")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        assert_eq!(
            collect_candidates(&db, &store, 10, time::Duration::ZERO)
                .await
                .unwrap(),
            0
        );
        assert!(store.contains(&space, &value, 0).await.unwrap());
    }

    #[tokio::test]
    async fn failed_old_delete_does_not_starve_next_aged_attempt() {
        let db = database().await;
        let inner = Arc::new(MemoryStore::default());
        let store = InterruptedDelete::new(inner.clone());
        let space = space();
        let old = upload(&inner, &space, b"old failed delete").await;
        let next = upload(&inner, &space, b"next candidate").await;
        register(&db, &[(space.clone(), old)], "a").await;
        register(&db, &[(space.clone(), next)], "b").await;
        store.lose_response.store(true, Ordering::SeqCst);
        assert!(refund_failed(&db, &store, &[(space.clone(), old, 0)], "a")
            .await
            .is_err());
        kv_orphan_candidate::Entity::update_many()
            .col_expr(
                kv_orphan_candidate::Column::DeletingAt,
                Expr::value(OffsetDateTime::now_utc() - Duration::hours(2)),
            )
            .filter(kv_orphan_candidate::Column::Space.eq(SpaceIdWrap(space.clone())))
            .filter(kv_orphan_candidate::Column::Value.eq(old))
            .exec(&db)
            .await
            .unwrap();
        age(&db, &space, next).await;
        store.lose_response.store(true, Ordering::SeqCst);
        assert!(collect_candidates(&db, &store, 1, Duration::hours(1))
            .await
            .is_err());
        assert_eq!(
            collect_candidates(&db, &store, 1, Duration::hours(1))
                .await
                .unwrap(),
            1
        );
        assert!(!inner.contains(&space, &next, 0).await.unwrap());
    }

    #[tokio::test]
    async fn failed_old_metadata_read_does_not_starve_next_attempt() {
        let db = database().await;
        let inner = Arc::new(MemoryStore::default());
        let store = InterruptedDelete::new(inner.clone());
        let space = space();
        let old = upload(&inner, &space, b"old failed HEAD").await;
        let next = upload(&inner, &space, b"next after HEAD").await;
        register(&db, &[(space.clone(), old)], "a").await;
        register(&db, &[(space.clone(), next)], "b").await;
        age(&db, &space, old).await;
        age(&db, &space, next).await;
        store.fail_read.store(true, Ordering::SeqCst);
        assert!(collect_candidates(&db, &store, 1, Duration::hours(1))
            .await
            .is_err());
        assert!(inner.contains(&space, &old, 0).await.unwrap());
        assert_eq!(
            collect_candidates(&db, &store, 1, Duration::hours(1))
                .await
                .unwrap(),
            1
        );
        assert!(!inner.contains(&space, &next, 0).await.unwrap());
    }
}

use std::time::Instant;

use rocket::http::Status;
use time::{Duration, OffsetDateTime};
use tinycloud_core::models::invocation_replay;
use tinycloud_core::sea_orm::{
    sea_query::OnConflict, ActiveValue::Set, ColumnTrait, Condition, DatabaseConnection,
    EntityTrait, QueryFilter,
};
use tinycloud_core::{events::Invocation, hash::Hash, AdmittedInvocation};

const CLOCK_SKEW_SECONDS: i64 = 60;

/// Extra slack, above the clamped retention bound, before the periodic sweep
/// treats a row as over-cap and reclaims it (TC-341). A legitimate row can
/// never exceed `now + max_lifetime_secs + CLOCK_SKEW_SECONDS`, so any positive
/// margin protects boundary rows against clock jitter while still reclaiming
/// attacker rows written before the cap existed.
const CLEANUP_OVER_CAP_MARGIN_SECONDS: i64 = CLOCK_SKEW_SECONDS;

/// `9999-12-31T23:59:59Z`, the upper bound `OffsetDateTime::from_unix_timestamp`
/// accepts. Deadlines are clamped to it so an absurd `max_lifetime_secs` config
/// cannot overflow the timestamp conversion.
const MAX_UNIX_TIMESTAMP_SECONDS: i64 = 253_402_300_799;

#[derive(Debug, thiserror::Error)]
pub enum InvocationReplayError {
    #[error("duplicate invocation")]
    Duplicate,
    #[error("invocation replay storage unavailable")]
    Database,
}

#[derive(Clone)]
pub struct InvocationReplayCache {
    conn: DatabaseConnection,
}

impl InvocationReplayCache {
    pub fn new(conn: DatabaseConnection) -> Self {
        Self { conn }
    }

    /// Record an admitted invocation in the durable replay table.
    ///
    /// TC-409: the parameter type is `&AdmittedInvocation`, not a bare
    /// `Invocation` — the only way to obtain one is `AdmittedInvocation::admit`,
    /// which verifies the invocation's signature and enforces the lifetime cap.
    /// That makes "verified before this durable write" compile-time explicit
    /// instead of a caller obligation. The retained `expires_at` is clamped to
    /// `now + max_lifetime_secs + clock skew` so a row can never outlive the
    /// server's lifetime cap even if the (verified) expiration claims
    /// otherwise.
    pub async fn check_and_insert(
        &self,
        invocation: &AdmittedInvocation,
        max_lifetime_secs: u64,
    ) -> Result<(), InvocationReplayError> {
        let invocation = invocation.invocation();
        let start = Instant::now();
        let now = OffsetDateTime::now_utc();
        let key = invocation.content_hash();
        let expires_at = invocation_expires_at(invocation, now, max_lifetime_secs);
        let result = self.check_and_insert_key(key, expires_at).await;
        crate::prometheus::observe_stage(
            crate::prometheus::InvocationStage::ReplayCheck,
            crate::prometheus::StageOutcome::from(result.is_ok()),
            start.elapsed(),
        );
        result
    }

    async fn check_and_insert_key(
        &self,
        key: Hash,
        expires_at: OffsetDateTime,
    ) -> Result<(), InvocationReplayError> {
        let inserted = invocation_replay::Entity::insert(invocation_replay::ActiveModel {
            content_hash: Set(key),
            expires_at: Set(expires_at),
        })
        .on_conflict(
            OnConflict::column(invocation_replay::Column::ContentHash)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(&self.conn)
        .await
        .map_err(|error| {
            tracing::warn!(?error, "invocation replay insert failed");
            InvocationReplayError::Database
        })?;

        if inserted == 0 {
            crate::prometheus::observe_replay_insert(false);
            Err(InvocationReplayError::Duplicate)
        } else {
            crate::prometheus::observe_replay_insert(true);
            Ok(())
        }
    }

    /// Periodic sweep. Deletes rows that are expired (`expires_at <= now`) and
    /// rows beyond the lifetime cap (`expires_at` past `now + max_lifetime_secs`
    /// plus clock skew plus margin). The second clause reclaims over-cap rows
    /// written before the TC-341 cap shipped (or by a hostile unverified
    /// sender); once the cap is enforced no legitimate row can exceed that
    /// bound, so this is self-healing.
    pub async fn cleanup(
        &self,
        now: OffsetDateTime,
        max_lifetime_secs: u64,
    ) -> Result<u64, InvocationReplayError> {
        invocation_replay::Entity::delete_many()
            .filter(
                Condition::any()
                    .add(invocation_replay::Column::ExpiresAt.lte(now))
                    .add(
                        invocation_replay::Column::ExpiresAt
                            .gt(over_cap_boundary(now, max_lifetime_secs)),
                    ),
            )
            .exec(&self.conn)
            .await
            .map(|result| result.rows_affected)
            .map_err(|error| {
                tracing::warn!(?error, "invocation replay cleanup failed");
                InvocationReplayError::Database
            })
    }
}

impl From<InvocationReplayError> for (Status, String) {
    fn from(err: InvocationReplayError) -> Self {
        match err {
            InvocationReplayError::Duplicate => (Status::Conflict, err.to_string()),
            InvocationReplayError::Database => (Status::InternalServerError, err.to_string()),
        }
    }
}

fn invocation_expires_at(
    invocation: &Invocation,
    now: OffsetDateTime,
    max_lifetime_secs: u64,
) -> OffsetDateTime {
    clamp_expires_at(
        invocation.0.invocation.payload().expiration.as_seconds(),
        now,
        max_lifetime_secs,
    )
}

/// Retention deadline for a replay row: the claimed expiration plus clock skew,
/// but never beyond `now + max_lifetime_secs + clock skew` (TC-341). Clamping to
/// the cap *before* adding skew means a hostile or over-long (but verified)
/// expiration cannot pin a durable row further out than the server's lifetime
/// cap. Arithmetic saturates rather than wrapping so a 1e300 expiration cannot
/// overflow.
fn clamp_expires_at(
    claimed_exp_secs: f64,
    now: OffsetDateTime,
    max_lifetime_secs: u64,
) -> OffsetDateTime {
    let max_lifetime = i64::try_from(max_lifetime_secs).unwrap_or(i64::MAX);
    let cap_secs = now.unix_timestamp().saturating_add(max_lifetime);
    let bounded_secs = saturating_seconds(claimed_exp_secs)
        .min(cap_secs)
        .saturating_add(CLOCK_SKEW_SECONDS)
        .min(MAX_UNIX_TIMESTAMP_SECONDS);
    OffsetDateTime::from_unix_timestamp(bounded_secs)
        .unwrap_or(now + Duration::seconds(CLOCK_SKEW_SECONDS))
}

/// Upper bound a legitimate replay row can carry after the lifetime cap ships:
/// `now + max_lifetime_secs + clock skew + margin`. Rows beyond this were
/// written before the cap existed (or by a hostile unverified sender) and are
/// reclaimable. Clamped to the timestamp range so an absurd config cannot
/// overflow the conversion.
fn over_cap_boundary(now: OffsetDateTime, max_lifetime_secs: u64) -> OffsetDateTime {
    let max_lifetime = i64::try_from(max_lifetime_secs).unwrap_or(i64::MAX);
    let boundary_secs = now
        .unix_timestamp()
        .saturating_add(max_lifetime)
        .saturating_add(CLOCK_SKEW_SECONDS)
        .saturating_add(CLEANUP_OVER_CAP_MARGIN_SECONDS)
        .min(MAX_UNIX_TIMESTAMP_SECONDS);
    OffsetDateTime::from_unix_timestamp(boundary_secs)
        .expect("boundary clamped into the supported timestamp range")
}

/// Saturating whole-second truncation of an `exp` claim. Rust's `f64 as i64`
/// saturates at the integer bounds (it does not wrap or panic), so a hostile
/// out-of-range expiration collapses to `i64::MAX`/`i64::MIN` rather than
/// producing a garbage deadline.
fn saturating_seconds(seconds: f64) -> i64 {
    if seconds >= i64::MAX as f64 {
        i64::MAX
    } else if seconds <= i64::MIN as f64 {
        i64::MIN
    } else {
        seconds as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tinycloud_core::hash::hash;
    use tinycloud_core::migrations::Migrator;
    use tinycloud_core::sea_orm::{
        ConnectOptions, Database, DatabaseConnection, EntityTrait, PaginatorTrait,
    };
    use tinycloud_core::sea_orm_migration::MigratorTrait;

    async fn connect_database(url: &str) -> DatabaseConnection {
        let mut options = ConnectOptions::new(url.to_owned());
        options.max_connections(1);
        options.map_sqlx_sqlite_opts(|options| {
            options
                .create_if_missing(true)
                .pragma("journal_mode", "WAL")
                .busy_timeout(std::time::Duration::from_secs(5))
        });
        Database::connect(options).await.unwrap()
    }

    async fn fresh_database() -> DatabaseConnection {
        let db = connect_database("sqlite::memory:").await;
        Migrator::up(&db, None).await.unwrap();
        db
    }

    #[tokio::test]
    async fn duplicate_survives_new_cache_instance() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("replay.sqlite").display()
        );
        let db = connect_database(&url).await;
        Migrator::up(&db, None).await.unwrap();
        let first_cache = InvocationReplayCache::new(db.clone());
        let key = hash(b"invocation");
        let now = OffsetDateTime::now_utc();

        assert!(first_cache
            .check_and_insert_key(key, now + Duration::seconds(60))
            .await
            .is_ok());
        drop(first_cache);
        db.close().await.unwrap();

        let restarted_cache = InvocationReplayCache::new(connect_database(&url).await);
        assert!(matches!(
            restarted_cache
                .check_and_insert_key(key, now + Duration::seconds(60))
                .await,
            Err(InvocationReplayError::Duplicate)
        ));
    }

    #[tokio::test]
    async fn exactly_one_concurrent_cache_instance_wins() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite://{}?mode=rwc",
            directory.path().join("concurrent-replay.sqlite").display()
        );
        let first_db = connect_database(&url).await;
        Migrator::up(&first_db, None).await.unwrap();
        let second_db = connect_database(&url).await;
        let first = InvocationReplayCache::new(first_db);
        let second = InvocationReplayCache::new(second_db);
        let key = hash(b"concurrent invocation");
        let expires_at = OffsetDateTime::now_utc() + Duration::seconds(60);

        let (first_result, second_result) = tokio::join!(
            first.check_and_insert_key(key, expires_at),
            second.check_and_insert_key(key, expires_at)
        );

        assert_eq!(
            [first_result.is_ok(), second_result.is_ok()]
                .into_iter()
                .filter(|won| *won)
                .count(),
            1
        );
        assert_eq!(
            [first_result, second_result]
                .into_iter()
                .filter(|result| matches!(result, Err(InvocationReplayError::Duplicate)))
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn cleanup_only_removes_expired_entries() {
        let db = fresh_database().await;
        let cache = InvocationReplayCache::new(db.clone());
        let now = OffsetDateTime::now_utc();
        let expired = hash(b"expired");
        let boundary = hash(b"boundary");
        let active = hash(b"active");

        cache
            .check_and_insert_key(expired, now - Duration::seconds(1))
            .await
            .unwrap();
        cache.check_and_insert_key(boundary, now).await.unwrap();
        cache
            .check_and_insert_key(active, now + Duration::seconds(1))
            .await
            .unwrap();

        assert_eq!(cache.cleanup(now, 300).await.unwrap(), 2);
        assert_eq!(
            invocation_replay::Entity::find().count(&db).await.unwrap(),
            1
        );
        assert!(invocation_replay::Entity::find_by_id(active)
            .one(&db)
            .await
            .unwrap()
            .is_some());
    }

    #[test]
    fn clamp_bounds_far_future_expirations_to_the_lifetime_cap() {
        let now = OffsetDateTime::now_utc();
        let now_secs = now.unix_timestamp();

        // A within-window expiration keeps its own deadline plus clock skew.
        let within = clamp_expires_at((now_secs + 100) as f64, now, 300);
        assert_eq!(within.unix_timestamp(), now_secs + 100 + CLOCK_SKEW_SECONDS);

        // A far-future (hostile) expiration is clamped to now + cap + skew.
        let far = clamp_expires_at(4_102_444_800.0, now, 300);
        assert_eq!(far.unix_timestamp(), now_secs + 300 + CLOCK_SKEW_SECONDS);

        // An out-of-range expiration saturates instead of overflowing.
        let hostile = clamp_expires_at(1e300, now, 300);
        assert_eq!(
            hostile.unix_timestamp(),
            now_secs + 300 + CLOCK_SKEW_SECONDS
        );
    }

    #[tokio::test]
    async fn cleanup_reclaims_over_cap_rows_and_keeps_in_window_rows() {
        let db = fresh_database().await;
        let cache = InvocationReplayCache::new(db.clone());
        let now = OffsetDateTime::now_utc();
        let max_lifetime_secs = 300u64;

        let expired = hash(b"expired");
        let in_window = hash(b"in-window");
        let over_cap = hash(b"over-cap");

        // Expired: reclaimed by the existing clause.
        cache
            .check_and_insert_key(expired, now - Duration::seconds(1))
            .await
            .unwrap();
        // At the clamped retention bound (now + cap + skew), below the sweep
        // boundary — must be retained.
        cache
            .check_and_insert_key(
                in_window,
                now + Duration::seconds(max_lifetime_secs as i64 + CLOCK_SKEW_SECONDS),
            )
            .await
            .unwrap();
        // What an unverified sender could have pinned before the cap shipped.
        cache
            .check_and_insert_key(over_cap, now + Duration::days(3650))
            .await
            .unwrap();

        assert_eq!(cache.cleanup(now, max_lifetime_secs).await.unwrap(), 2);
        assert_eq!(
            invocation_replay::Entity::find().count(&db).await.unwrap(),
            1
        );
        assert!(invocation_replay::Entity::find_by_id(in_window)
            .one(&db)
            .await
            .unwrap()
            .is_some());
        assert!(invocation_replay::Entity::find_by_id(over_cap)
            .one(&db)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn request_check_is_one_statement_with_many_active_rows() {
        let mut db = fresh_database().await;
        let cache = InvocationReplayCache::new(db.clone());
        let expires_at = OffsetDateTime::now_utc() + Duration::hours(1);

        for index in 0..1000 {
            cache
                .check_and_insert_key(hash(format!("active-{index}").as_bytes()), expires_at)
                .await
                .unwrap();
        }

        let statements = Arc::new(AtomicUsize::new(0));
        let statement_counter = Arc::clone(&statements);
        db.set_metric_callback(move |_| {
            statement_counter.fetch_add(1, Ordering::SeqCst);
        });

        InvocationReplayCache::new(db)
            .check_and_insert_key(hash(b"new invocation"), expires_at)
            .await
            .unwrap();

        assert_eq!(statements.load(Ordering::SeqCst), 1);
    }
}

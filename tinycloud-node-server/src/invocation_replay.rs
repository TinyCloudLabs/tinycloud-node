use std::time::Instant;

use rocket::http::Status;
use time::{Duration, OffsetDateTime};
use tinycloud_core::models::invocation_replay;
use tinycloud_core::sea_orm::{
    sea_query::OnConflict, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait,
    QueryFilter,
};
use tinycloud_core::{events::Invocation, hash::Hash};

const CLOCK_SKEW_SECONDS: i64 = 60;

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

    pub async fn check_and_insert(
        &self,
        invocation: &Invocation,
    ) -> Result<(), InvocationReplayError> {
        let start = Instant::now();
        let now = OffsetDateTime::now_utc();
        let key = invocation.content_hash();
        let expires_at = invocation_expires_at(invocation, now);
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
            Err(InvocationReplayError::Duplicate)
        } else {
            Ok(())
        }
    }

    pub async fn cleanup_expired(&self, now: OffsetDateTime) -> Result<u64, InvocationReplayError> {
        invocation_replay::Entity::delete_many()
            .filter(invocation_replay::Column::ExpiresAt.lte(now))
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

fn invocation_expires_at(invocation: &Invocation, now: OffsetDateTime) -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(
        invocation.0.invocation.payload().expiration.as_seconds() as i64 + CLOCK_SKEW_SECONDS,
    )
    .unwrap_or(now + Duration::seconds(CLOCK_SKEW_SECONDS))
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

        assert_eq!(cache.cleanup_expired(now).await.unwrap(), 2);
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

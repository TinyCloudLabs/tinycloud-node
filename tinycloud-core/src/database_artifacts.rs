use async_trait::async_trait;
use sea_orm::{
    sea_query::Expr, ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, DbErr,
    EntityTrait, QueryFilter, QuerySelect,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

use crate::{hash::hash, models::database_artifact};

#[derive(Debug, Clone)]
pub struct DatabaseArtifact {
    pub payload: Vec<u8>,
    pub content_hash: String,
    pub revision: i64,
    pub size_bytes: i64,
    pub updated_at: String,
    pub backend: String,
    pub storage_mode: String,
    pub delta_payload: Option<Vec<u8>>,
    pub delta_content_hash: Option<String>,
    pub delta_size_bytes: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeltaSave {
    pub revision: i64,
    pub size_bytes: i64,
    pub delta_size_bytes: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum DatabaseArtifactError {
    #[error("database artifact storage error: {0}")]
    Db(#[from] DbErr),
    #[error("database artifact payload too large: {0} bytes")]
    PayloadTooLarge(u64),
    #[error("database artifact backend error: {0}")]
    Backend(String),
    #[error("database artifact checkpoint is missing")]
    MissingCheckpoint,
    #[error("database artifact backend does not support incremental persistence")]
    IncrementalPersistenceUnsupported,
}

#[async_trait]
pub trait DatabaseArtifactRepository: Send + Sync {
    async fn load(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError>;

    async fn save(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError>;

    async fn save_delta(
        &self,
        _service: &str,
        _space: &str,
        _name: &str,
        _payload: Vec<u8>,
    ) -> Result<DeltaSave, DatabaseArtifactError> {
        Err(DatabaseArtifactError::IncrementalPersistenceUnsupported)
    }
}

#[derive(Clone)]
pub struct SeaOrmDatabaseArtifactRepository {
    conn: DatabaseConnection,
    /// Test-only rendezvous seam (see [`wait_at_race_barrier`]) that lets two
    /// writers read the same base revision before either commits, so the
    /// full-checkpoint CAS conflict path can be exercised deterministically.
    #[cfg(test)]
    race_barrier: Option<std::sync::Arc<tokio::sync::Barrier>>,
}

impl SeaOrmDatabaseArtifactRepository {
    pub fn new(conn: DatabaseConnection) -> Self {
        Self {
            conn,
            #[cfg(test)]
            race_barrier: None,
        }
    }

    #[cfg(test)]
    fn with_race_barrier_for_test(mut self, barrier: std::sync::Arc<tokio::sync::Barrier>) -> Self {
        self.race_barrier = Some(barrier);
        self
    }

    /// Park at the shared test barrier (SQLite only, matching the other
    /// CAS-conflict tests) after reading the current revision and before the
    /// conditional update, so a concurrent writer can bump the revision in
    /// between and drive this writer's compare-and-swap to zero rows.
    #[cfg(test)]
    async fn wait_at_race_barrier(&self) {
        use sea_orm::ConnectionTrait;
        if self.conn.get_database_backend() == sea_orm::DbBackend::Sqlite {
            if let Some(barrier) = &self.race_barrier {
                barrier.wait().await;
            }
        }
    }
}

#[async_trait]
impl DatabaseArtifactRepository for SeaOrmDatabaseArtifactRepository {
    async fn load(
        &self,
        service: &str,
        space: &str,
        name: &str,
    ) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError> {
        database_artifact::Entity::find_by_id((
            service.to_string(),
            space.to_string(),
            name.to_string(),
        ))
        .one(&self.conn)
        .await
        .map(|row| {
            row.map(|model| DatabaseArtifact {
                payload: model.payload,
                content_hash: model.content_hash,
                revision: model.revision,
                size_bytes: model.size_bytes,
                updated_at: model.updated_at,
                backend: model.backend,
                storage_mode: model.storage_mode,
                delta_payload: model.delta_payload,
                delta_content_hash: model.delta_content_hash,
                delta_size_bytes: model.delta_size_bytes,
            })
        })
        .map_err(DatabaseArtifactError::Db)
    }

    async fn save(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
        let size_bytes = i64::try_from(payload.len())
            .map_err(|_| DatabaseArtifactError::PayloadTooLarge(payload.len() as u64))?;
        let content_hash = hash(&payload).to_cid(0x55).to_string();
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current timestamps should format as RFC3339");

        let existing = database_artifact::Entity::find_by_id((
            service.to_string(),
            space.to_string(),
            name.to_string(),
        ))
        .one(&self.conn)
        .await?;

        let revision = existing
            .as_ref()
            .map(|model| model.revision + 1)
            .unwrap_or(1);

        // Barrier seam (tests only): lets a second writer observe the same base
        // revision before either commits, exercising the CAS conflict path.
        #[cfg(test)]
        self.wait_at_race_barrier().await;

        match existing.as_ref() {
            Some(existing) => {
                // Compare-and-swap on the revision this save read: a concurrent
                // checkpoint/delta that bumped the revision in between makes this
                // match zero rows, so a stale actor cannot clobber newer committed
                // state (mirrors `save_delta`'s guard). Callers surface the
                // conflict and force actor rehydration rather than retry.
                let update = database_artifact::Entity::update_many()
                    .col_expr(database_artifact::Column::Revision, Expr::value(revision))
                    .col_expr(
                        database_artifact::Column::ContentHash,
                        Expr::value(content_hash.clone()),
                    )
                    .col_expr(
                        database_artifact::Column::Payload,
                        Expr::value(payload.clone()),
                    )
                    .col_expr(
                        database_artifact::Column::SizeBytes,
                        Expr::value(size_bytes),
                    )
                    .col_expr(
                        database_artifact::Column::Backend,
                        Expr::value("storage.database"),
                    )
                    .col_expr(
                        database_artifact::Column::StorageMode,
                        Expr::value("database-blob"),
                    )
                    .col_expr(
                        database_artifact::Column::UpdatedAt,
                        Expr::value(now.clone()),
                    )
                    .col_expr(
                        database_artifact::Column::CheckpointSizeBytes,
                        Expr::value(size_bytes),
                    )
                    .col_expr(
                        database_artifact::Column::CheckpointContentHash,
                        Expr::value(content_hash.clone()),
                    )
                    .col_expr(
                        database_artifact::Column::DeltaPayload,
                        Expr::value(Option::<Vec<u8>>::None),
                    )
                    .col_expr(
                        database_artifact::Column::DeltaContentHash,
                        Expr::value(Option::<String>::None),
                    )
                    .col_expr(
                        database_artifact::Column::DeltaSizeBytes,
                        Expr::value(0_i64),
                    )
                    .filter(database_artifact::Column::Service.eq(service))
                    .filter(database_artifact::Column::Space.eq(space))
                    .filter(database_artifact::Column::Name.eq(name))
                    .filter(database_artifact::Column::Revision.eq(existing.revision))
                    .exec(&self.conn)
                    .await?;
                if update.rows_affected != 1 {
                    return Err(DatabaseArtifactError::Backend(
                        "concurrent database artifact update".to_string(),
                    ));
                }
            }
            None => {
                database_artifact::ActiveModel {
                    service: Set(service.to_string()),
                    space: Set(space.to_string()),
                    name: Set(name.to_string()),
                    revision: Set(revision),
                    content_hash: Set(content_hash.clone()),
                    payload: Set(payload.clone()),
                    size_bytes: Set(size_bytes),
                    backend: Set("storage.database".to_string()),
                    storage_mode: Set("database-blob".to_string()),
                    created_at: Set(now.clone()),
                    updated_at: Set(now.clone()),
                    checkpoint_size_bytes: Set(size_bytes),
                    checkpoint_content_hash: Set(content_hash.clone()),
                    delta_payload: Set(None),
                    delta_content_hash: Set(None),
                    delta_size_bytes: Set(0),
                }
                .insert(&self.conn)
                .await?;
            }
        }

        Ok(DatabaseArtifact {
            payload,
            content_hash,
            revision,
            size_bytes,
            updated_at: now,
            backend: "storage.database".to_string(),
            storage_mode: "database-blob".to_string(),
            delta_payload: None,
            delta_content_hash: None,
            delta_size_bytes: 0,
        })
    }

    async fn save_delta(
        &self,
        service: &str,
        space: &str,
        name: &str,
        payload: Vec<u8>,
    ) -> Result<DeltaSave, DatabaseArtifactError> {
        let existing = database_artifact::Entity::find_by_id((
            service.to_string(),
            space.to_string(),
            name.to_string(),
        ))
        .select_only()
        .column(database_artifact::Column::Revision)
        .column(database_artifact::Column::CheckpointSizeBytes)
        .column(database_artifact::Column::CheckpointContentHash)
        .into_tuple::<(i64, i64, String)>()
        .one(&self.conn)
        .await?
        .ok_or(DatabaseArtifactError::MissingCheckpoint)?;

        let delta_size_bytes = i64::try_from(payload.len())
            .map_err(|_| DatabaseArtifactError::PayloadTooLarge(payload.len() as u64))?;
        let delta_content_hash = hash(&payload).to_cid(0x55).to_string();
        let logical_content_hash =
            hash(format!("{}:{}", existing.2, delta_content_hash).as_bytes())
                .to_cid(0x55)
                .to_string();
        let size_bytes = existing
            .1
            .checked_add(delta_size_bytes)
            .ok_or(DatabaseArtifactError::PayloadTooLarge(u64::MAX))?;
        let revision = existing.0 + 1;
        let now = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .expect("current timestamps should format as RFC3339");

        let update = database_artifact::Entity::update_many()
            .col_expr(database_artifact::Column::Revision, Expr::value(revision))
            .col_expr(
                database_artifact::Column::ContentHash,
                Expr::value(logical_content_hash),
            )
            .col_expr(
                database_artifact::Column::DeltaPayload,
                Expr::value(Some(payload)),
            )
            .col_expr(
                database_artifact::Column::DeltaContentHash,
                Expr::value(Some(delta_content_hash)),
            )
            .col_expr(
                database_artifact::Column::DeltaSizeBytes,
                Expr::value(delta_size_bytes),
            )
            .col_expr(
                database_artifact::Column::SizeBytes,
                Expr::value(size_bytes),
            )
            .col_expr(
                database_artifact::Column::StorageMode,
                Expr::value("checkpoint+wal"),
            )
            .col_expr(database_artifact::Column::UpdatedAt, Expr::value(now))
            .filter(database_artifact::Column::Service.eq(service))
            .filter(database_artifact::Column::Space.eq(space))
            .filter(database_artifact::Column::Name.eq(name))
            .filter(database_artifact::Column::Revision.eq(existing.0))
            .exec(&self.conn)
            .await?;
        if update.rows_affected != 1 {
            return Err(DatabaseArtifactError::Backend(
                "concurrent database artifact update".to_string(),
            ));
        }

        Ok(DeltaSave {
            revision,
            size_bytes,
            delta_size_bytes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ConnectOptions, Database};
    use sea_orm_migration::MigratorTrait;

    #[tokio::test]
    async fn delta_save_replaces_wal_and_checkpoint_clears_it() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let repo = SeaOrmDatabaseArtifactRepository::new(conn);

        repo.save("sql", "space", "main", vec![1; 100])
            .await
            .unwrap();
        let delta = repo
            .save_delta("sql", "space", "main", vec![2; 12])
            .await
            .unwrap();
        assert_eq!(delta.revision, 2);
        assert_eq!(delta.size_bytes, 112);
        assert_eq!(delta.delta_size_bytes, 12);

        let loaded = repo.load("sql", "space", "main").await.unwrap().unwrap();
        assert_eq!(loaded.payload, vec![1; 100]);
        assert_eq!(loaded.delta_payload, Some(vec![2; 12]));
        assert_eq!(loaded.storage_mode, "checkpoint+wal");

        repo.save("sql", "space", "main", vec![3; 80])
            .await
            .unwrap();
        let checkpoint = repo.load("sql", "space", "main").await.unwrap().unwrap();
        assert_eq!(checkpoint.size_bytes, 80);
        assert_eq!(checkpoint.delta_size_bytes, 0);
        assert_eq!(checkpoint.delta_payload, None);
    }

    #[tokio::test]
    async fn stale_full_checkpoint_save_conflicts_and_preserves_newer_revision() {
        // One shared in-memory database (single pooled connection) so two cloned
        // repositories race against the same rows. Per-statement pool acquisition
        // means neither holds the connection while parked at the barrier.
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let repo = SeaOrmDatabaseArtifactRepository::new(conn);

        // Seed the checkpoint both writers will read as their base (revision 1).
        let seeded = repo
            .save("sql", "space", "main", vec![1; 100])
            .await
            .unwrap();
        assert_eq!(seeded.revision, 1);

        // Both writers read revision 1, rendezvous at the barrier, then attempt
        // the full-checkpoint update. Exactly one wins the compare-and-swap; the
        // stale loser must fail without clobbering the winner's committed state.
        let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));
        let first = repo
            .clone()
            .with_race_barrier_for_test(std::sync::Arc::clone(&barrier));
        let second = repo
            .clone()
            .with_race_barrier_for_test(std::sync::Arc::clone(&barrier));

        let (a, b) = tokio::join!(
            first.save("sql", "space", "main", vec![2; 80]),
            second.save("sql", "space", "main", vec![3; 60]),
        );

        let (winner, loser_err) = match (a, b) {
            (Ok(win), Err(err)) => (win, err),
            (Err(err), Ok(win)) => (win, err),
            other => panic!("expected exactly one success and one conflict, got {other:?}"),
        };
        assert!(
            matches!(&loser_err, DatabaseArtifactError::Backend(message)
                if message == "concurrent database artifact update"),
            "stale checkpoint must fail with the concurrent-update conflict, got {loser_err:?}"
        );
        assert_eq!(
            winner.revision, 2,
            "winner commits the single next revision"
        );

        // The stale writer must not have clobbered: durable state is the winner's
        // payload at revision 2, never the loser's bytes.
        let loaded = repo.load("sql", "space", "main").await.unwrap().unwrap();
        assert_eq!(loaded.revision, 2);
        assert_eq!(
            loaded.payload, winner.payload,
            "stale writer must not overwrite the winner's checkpoint"
        );
    }
}

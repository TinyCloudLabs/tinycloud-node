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
    pub checkpoint_content_hash: String,
    pub delta_payload: Option<Vec<u8>>,
    pub delta_content_hash: Option<String>,
    pub delta_size_bytes: i64,
}

/// What the caller's local database state derives from, asserted at save time.
///
/// The revision compare-and-swap below is a CONCURRENCY guard only: both saves
/// re-read the current revision, so a writer that is merely *stale* — an actor
/// holding a database it hydrated from an older checkpoint, running alone —
/// reads the current revision, matches it, and overwrites the newer durable
/// state. Carrying the base the caller actually derives from turns that into a
/// lineage check the stale writer cannot pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactExpectation {
    /// No lineage assertion: replace whatever is durable. For callers that
    /// deliberately overwrite unrelated content (DuckDB `import_db`).
    Any,
    /// The caller derives from NO durable artifact, so it may only create one.
    /// A row appearing in the meantime means the caller's empty database would
    /// clobber content it never read.
    Absent,
    /// The caller derives from exactly this checkpoint. `checkpoint_content_hash`
    /// (not `content_hash`) is the anchor: a WAL delta advances the revision and
    /// the logical hash while leaving the base checkpoint — and therefore the
    /// bytes the caller actually hydrated — unchanged.
    Derived {
        revision: i64,
        checkpoint_content_hash: String,
    },
}

impl ArtifactExpectation {
    /// The expectation a caller carries after committing `revision` on top of
    /// the same base checkpoint (a WAL delta save).
    pub fn advanced_to(&self, revision: i64) -> Self {
        match self {
            Self::Derived {
                checkpoint_content_hash,
                ..
            } => Self::Derived {
                revision,
                checkpoint_content_hash: checkpoint_content_hash.clone(),
            },
            other => other.clone(),
        }
    }

    /// Reject before touching durable state when the base is already known to
    /// differ. The atomic check is the `WHERE` clause on the update itself;
    /// this only turns the common case into a precise error.
    fn check(&self, existing: Option<(i64, &str)>) -> Result<(), DatabaseArtifactError> {
        let conflict = match (self, existing) {
            (Self::Any, _) => false,
            (Self::Absent, existing) => existing.is_some(),
            (Self::Derived { .. }, None) => true,
            (
                Self::Derived {
                    revision,
                    checkpoint_content_hash,
                },
                Some((current_revision, current_hash)),
            ) => *revision != current_revision || checkpoint_content_hash != current_hash,
        };
        if conflict {
            return Err(DatabaseArtifactError::StaleLineage);
        }
        Ok(())
    }
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
    #[error("database artifact was written from a superseded checkpoint")]
    StaleLineage,
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
        expected: ArtifactExpectation,
    ) -> Result<DatabaseArtifact, DatabaseArtifactError>;

    async fn save_delta(
        &self,
        _service: &str,
        _space: &str,
        _name: &str,
        _payload: Vec<u8>,
        _expected: ArtifactExpectation,
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
                checkpoint_content_hash: model.checkpoint_content_hash,
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
        expected: ArtifactExpectation,
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

        expected.check(
            existing
                .as_ref()
                .map(|model| (model.revision, model.checkpoint_content_hash.as_str())),
        )?;

        // A full checkpoint that is a fraction of the content it replaces is
        // the shape of a database that reverted to an older (or empty) state
        // and re-anchored on it. Legitimate causes exist — VACUUM, a large
        // DELETE, WAL compaction — so this warns rather than rejects.
        if let Some(previous) = existing.as_ref() {
            if previous.size_bytes > 0 && size_bytes.saturating_mul(2) < previous.size_bytes {
                tracing::warn!(
                    service,
                    space,
                    name,
                    revision = previous.revision,
                    previous_logical_bytes = previous.size_bytes,
                    bytes = size_bytes,
                    "Database checkpoint shrank sharply against the artifact it replaces"
                );
            }
        }

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
                // Compare-and-swap on the (revision, checkpoint) this save read.
                // That alone is a CONCURRENCY guard: it catches a writer whose
                // base was superseded between this read and this update, and
                // nothing else — a save re-reads the row every time, so a writer
                // running alone always matches whatever is current no matter how
                // stale its own database is. The lineage assertion checked above
                // is what rejects that writer; pairing the two here is what makes
                // the assertion atomic. Callers surface the conflict and force
                // actor rehydration rather than retry.
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
                    .filter(
                        database_artifact::Column::CheckpointContentHash
                            .eq(existing.checkpoint_content_hash.clone()),
                    )
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
            content_hash: content_hash.clone(),
            revision,
            size_bytes,
            updated_at: now,
            backend: "storage.database".to_string(),
            storage_mode: "database-blob".to_string(),
            checkpoint_content_hash: content_hash,
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
        expected: ArtifactExpectation,
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

        // A WAL is only replayable against the checkpoint it was built on, so
        // an actor that hydrated from a different one must not attach its delta
        // here — the resulting (checkpoint, WAL) pair would not describe any
        // database that ever existed.
        expected.check(Some((existing.0, existing.2.as_str())))?;

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
            .filter(database_artifact::Column::CheckpointContentHash.eq(existing.2.clone()))
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

        repo.save(
            "sql",
            "space",
            "main",
            vec![1; 100],
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let delta = repo
            .save_delta(
                "sql",
                "space",
                "main",
                vec![2; 12],
                ArtifactExpectation::Any,
            )
            .await
            .unwrap();
        assert_eq!(delta.revision, 2);
        assert_eq!(delta.size_bytes, 112);
        assert_eq!(delta.delta_size_bytes, 12);

        let loaded = repo.load("sql", "space", "main").await.unwrap().unwrap();
        assert_eq!(loaded.payload, vec![1; 100]);
        assert_eq!(loaded.delta_payload, Some(vec![2; 12]));
        assert_eq!(loaded.storage_mode, "checkpoint+wal");

        repo.save(
            "sql",
            "space",
            "main",
            vec![3; 80],
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();
        let checkpoint = repo.load("sql", "space", "main").await.unwrap().unwrap();
        assert_eq!(checkpoint.size_bytes, 80);
        assert_eq!(checkpoint.delta_size_bytes, 0);
        assert_eq!(checkpoint.delta_payload, None);
    }

    /// The failure the revision compare-and-swap cannot see: one writer, no
    /// concurrency, holding a database built on a superseded checkpoint.
    #[tokio::test]
    async fn stale_lineage_save_is_rejected_with_no_concurrent_writer() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let repo = SeaOrmDatabaseArtifactRepository::new(conn);

        let base = repo
            .save(
                "sql",
                "space",
                "main",
                vec![1; 100],
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let stale = ArtifactExpectation::Derived {
            revision: base.revision,
            checkpoint_content_hash: base.checkpoint_content_hash.clone(),
        };

        // A live actor advances the database. The stale actor's base is now gone.
        let current = repo
            .save("sql", "space", "main", vec![2; 200], stale.clone())
            .await
            .unwrap();
        assert_eq!(current.revision, 2);

        // The stale actor runs ALONE and re-reads the row, so the revision CAS
        // it performs matches whatever is current — only the lineage it carries
        // says its 100 bytes never derived from these 200.
        let err = repo
            .save("sql", "space", "main", vec![1; 100], stale.clone())
            .await
            .expect_err("a save from a superseded checkpoint must not commit");
        assert!(
            matches!(err, DatabaseArtifactError::StaleLineage),
            "expected a lineage rejection, got {err:?}"
        );
        let err = repo
            .save_delta("sql", "space", "main", vec![9; 12], stale)
            .await
            .expect_err("a WAL built on a superseded checkpoint must not attach");
        assert!(
            matches!(err, DatabaseArtifactError::StaleLineage),
            "expected a lineage rejection, got {err:?}"
        );

        let loaded = repo.load("sql", "space", "main").await.unwrap().unwrap();
        assert_eq!(loaded.revision, 2);
        assert_eq!(loaded.payload, vec![2; 200]);
        assert_eq!(loaded.delta_payload, None);

        // The guard rejects only supersession: the caller that is actually
        // caught up still commits.
        repo.save(
            "sql",
            "space",
            "main",
            vec![3; 300],
            ArtifactExpectation::Derived {
                revision: current.revision,
                checkpoint_content_hash: current.checkpoint_content_hash,
            },
        )
        .await
        .expect("a caller on the current checkpoint must still commit");
    }

    /// The other half of the same defect: a database that hydrated from nothing
    /// (an empty one) must not overwrite a row that appeared meanwhile.
    #[tokio::test]
    async fn save_expecting_no_artifact_is_rejected_once_one_exists() {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let repo = SeaOrmDatabaseArtifactRepository::new(conn);

        repo.save(
            "sql",
            "space",
            "main",
            vec![1; 4096],
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();

        let err = repo
            .save(
                "sql",
                "space",
                "main",
                vec![0; 8],
                ArtifactExpectation::Absent,
            )
            .await
            .expect_err("an empty database must not clobber durable content");
        assert!(
            matches!(err, DatabaseArtifactError::StaleLineage),
            "expected a lineage rejection, got {err:?}"
        );

        let loaded = repo.load("sql", "space", "main").await.unwrap().unwrap();
        assert_eq!(loaded.revision, 1);
        assert_eq!(loaded.payload, vec![1; 4096]);
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
            .save(
                "sql",
                "space",
                "main",
                vec![1; 100],
                ArtifactExpectation::Any,
            )
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
            first.save(
                "sql",
                "space",
                "main",
                vec![2; 80],
                ArtifactExpectation::Any
            ),
            second.save(
                "sql",
                "space",
                "main",
                vec![3; 60],
                ArtifactExpectation::Any
            ),
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

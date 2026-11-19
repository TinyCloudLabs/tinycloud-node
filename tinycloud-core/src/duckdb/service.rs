use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Weak},
};

use dashmap::DashMap;
use tinycloud_auth::resource::SpaceId;

use crate::database_artifacts::{
    read_artifact, staging_path, sweep_stale_staging, ArtifactExpectation, CacheFileSink,
    DatabaseArtifactError, DatabaseArtifactRepository, MemorySink, StagingRelease,
};

use crate::request_telemetry::{self, QueryTimer};

use super::{
    caveats::DuckDbCaveats,
    database::{cache_file_paths, remove_cache_entry, spawn_actor_with_disk, DatabaseHandle},
    disk::{self, DuckDbDiskPolicy},
    storage,
    types::*,
};

const MAX_WAL_DELTA_BYTES: usize = 8 * 1024 * 1024;

/// DuckDB's main header carries an 8-byte checksum before its magic bytes.
const DUCKDB_MAGIC: &[u8] = b"DUCK";
const DUCKDB_MAGIC_OFFSET: usize = 8;

/// Per-(space, db) guards for hydration and execution-through-persistence.
type DatabaseLock = tokio::sync::Mutex<()>;
type DatabaseLockRegistry = Arc<tokio::sync::Mutex<HashMap<(String, String), Weak<DatabaseLock>>>>;

pub struct DuckDbService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    hydration_locks: DatabaseLockRegistry,
    operation_locks: DatabaseLockRegistry,
    /// What each live actor's local database derives from, carried into every
    /// durable save so a stale actor is rejected instead of clobbering. Written
    /// on hydration (the only path that creates an actor) and after each
    /// successful save, cleared alongside the actor by `discard_local_state`.
    lineage: Arc<DashMap<(String, String), ArtifactExpectation>>,
    base_path: String,
    memory_threshold: u64,
    idle_timeout_secs: u64,
    max_memory_per_connection: String,
    artifact_repository: Arc<dyn DatabaseArtifactRepository>,
    disk: DuckDbDiskPolicy,
}

struct ExecuteOptions {
    arrow_format: bool,
    without_growth: bool,
}

pub(crate) fn validate_db_name(name: &str) -> Result<(), DuckDbError> {
    if name.contains("..")
        || name.contains('/')
        || name.contains('\\')
        || name.contains('\0')
        || name.is_empty()
    {
        return Err(DuckDbError::PermissionDenied(
            "Invalid database name".into(),
        ));
    }
    Ok(())
}

impl DuckDbService {
    pub fn new(
        base_path: String,
        memory_threshold: u64,
        idle_timeout_secs: u64,
        max_memory_per_connection: String,
        artifact_repository: Arc<dyn DatabaseArtifactRepository>,
    ) -> Self {
        Self {
            databases: Arc::new(DashMap::new()),
            hydration_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            operation_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            lineage: Arc::new(DashMap::new()),
            base_path,
            memory_threshold,
            idle_timeout_secs,
            max_memory_per_connection,
            artifact_repository,
            disk: DuckDbDiskPolicy::default(),
        }
    }

    /// Keep disk headroom and cap spilling under `disk` (off by default).
    pub fn with_disk_policy(mut self, disk: DuckDbDiskPolicy) -> Self {
        self.disk = disk;
        self
    }

    /// Remove what a stopped process left in the cache: DuckDB spill
    /// directories and staging or renamed-aside names. Run once at startup,
    /// before any actor exists. The cache files themselves are kept, because
    /// a legacy database reopens them. Returns how many entries were removed.
    pub async fn sweep_stale_cache_files(&self) -> usize {
        let base = PathBuf::from(&self.base_path);
        tokio::task::spawn_blocking(move || {
            let mut removed = 0;
            let Ok(spaces) = std::fs::read_dir(&base) else {
                return 0;
            };
            for space in spaces.filter_map(Result::ok) {
                // `file_type` does not follow links: a link in place of a
                // space directory is never descended into.
                if !space.file_type().is_ok_and(|kind| kind.is_dir()) {
                    continue;
                }
                let Ok(entries) = std::fs::read_dir(space.path()) else {
                    continue;
                };
                for entry in entries.filter_map(Result::ok) {
                    let name = entry.file_name();
                    if is_stale_cache_name(&name.to_string_lossy())
                        && remove_cache_entry(&entry.path()).is_ok()
                    {
                        removed += 1;
                    }
                }
            }
            if removed > 0 {
                tracing::info!(removed, "Removed DuckDB cache leftovers at startup");
            }
            removed
        })
        .await
        .unwrap_or(0)
    }

    pub async fn execute(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: DuckDbRequest,
        caveats: Option<DuckDbCaveats>,
        ability: String,
        arrow_format: bool,
    ) -> Result<DuckDbExecutionResult, DuckDbError> {
        self.execute_inner(
            space,
            db_name,
            request,
            caveats,
            ability,
            ExecuteOptions {
                arrow_format,
                without_growth: false,
            },
        )
        .await
    }

    /// Execute a request in a full space, atomically refusing storage growth.
    ///
    /// DELETE, DROP, reads, and existing-object IF NOT EXISTS DDL are accepted
    /// only if their serialized checkpoint also fits the durable byte charge.
    /// No-ops on absent databases do not create charged artifacts. Refused
    /// writes are discarded before subsequent reads or persistence.
    pub async fn execute_without_growth(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: DuckDbRequest,
        caveats: Option<DuckDbCaveats>,
        ability: String,
        arrow_format: bool,
    ) -> Result<DuckDbExecutionResult, DuckDbError> {
        self.execute_inner(
            space,
            db_name,
            request,
            caveats,
            ability,
            ExecuteOptions {
                arrow_format,
                without_growth: true,
            },
        )
        .await
    }

    async fn execute_inner(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: DuckDbRequest,
        caveats: Option<DuckDbCaveats>,
        ability: String,
        options: ExecuteOptions,
    ) -> Result<DuckDbExecutionResult, DuckDbError> {
        request_telemetry::observe_space(space);
        let ExecuteOptions {
            arrow_format,
            without_growth,
        } = options;
        validate_db_name(db_name)?;

        let key = (space.to_string(), db_name.to_string());
        let operation_lock = Self::database_lock(&self.operation_locks, &key).await;
        let _operation = operation_lock.lock().await;
        let handle = self.handle(space, db_name).await?;

        // Room for this write and for the snapshot copy its save can take,
        // which is at most the local database files.
        let writes = self.disk.active() && disk::writes(&request, &caveats, &ability);
        let _reservation = if writes {
            let cache_path = self.cache_path(space, db_name);
            let local_bytes = local_file_bytes(&cache_path).await;
            self.disk
                .reserve(&disk::budget_key(&key.0, &key.1), local_bytes, &cache_path)?
        } else {
            None
        };

        let result = handle
            .execute(request, caveats, ability, arrow_format, without_growth)
            .await;
        if without_growth
            && result.is_err()
            && self.expectation(&key) == ArtifactExpectation::Absent
        {
            self.discard_local_state(&key).await?;
        }
        // A write stopped for disk headroom may have committed locally (an
        // interrupted COMMIT reports the interrupt after committing), or
        // applied earlier statements of its batch. Drop the local copy, so
        // the durable artifact stays the truth and no later save carries the
        // refused request.
        if writes && matches!(result, Err(DuckDbError::DiskHeadroom)) {
            self.discard_local_state(&key).await?;
        }
        let result = result?;

        if !result.write_targets.is_empty() {
            if without_growth && self.expectation(&key) == ArtifactExpectation::Absent {
                // The actor permits only shrinking/no-op writes on an empty
                // database. Its serialized header is still nonempty, so leave
                // the artifact absent and prevent later export from saving it.
                self.discard_local_state(&key).await?;
                return Ok(result);
            }
            // A DELETE can append WAL bytes despite reducing logical content.
            // Persist guarded writes as checkpoints, never as a larger charged
            // checkpoint+WAL artifact.
            let persisted = if without_growth {
                self.checkpoint(space, db_name, &handle, true).await
            } else {
                self.persist_write(space, db_name, &handle).await
            };
            if let Err(e) = persisted {
                self.discard_local_state(&key).await?;
                return Err(e);
            }
        }

        Ok(result)
    }

    /// Export only durable data, without changing its artifact or live WAL base.
    pub async fn export(&self, space: &SpaceId, db_name: &str) -> Result<Vec<u8>, DuckDbError> {
        request_telemetry::observe_space(space);
        validate_db_name(db_name)?;

        let key = (space.to_string(), db_name.to_string());
        let operation_lock = Self::database_lock(&self.operation_locks, &key).await;
        let _operation = operation_lock.lock().await;

        // The export is the response body, so it is buffered whole; the read
        // itself still streams in slices.
        let mut artifact = MemorySink::default();
        read_artifact(
            self.artifact_repository.as_ref(),
            "duckdb",
            &key.0,
            db_name,
            &mut artifact,
        )
        .await
        .map_err(artifact_error_to_duckdb)?
        .ok_or(DuckDbError::DatabaseNotFound)?;
        validate_payload(
            space,
            db_name,
            "checkpoint",
            &artifact.checkpoint,
            is_duckdb_file,
        )?;
        let Some(delta) = artifact.wal else {
            return Ok(artifact.checkpoint);
        };
        validate_payload(space, db_name, "wal", &delta, |payload| {
            !is_duckdb_file(payload)
        })?;

        // Checkpoint a disposable copy, never the live actor. Checkpointing
        // the actor here would reset its WAL base without persisting that base,
        // making a later incremental save incompatible with the durable file.
        let max_memory = self.max_memory_per_connection.clone();
        let context = request_telemetry::current();
        tokio::task::spawn_blocking(move || {
            let _context = request_telemetry::enter(context);
            let temp = tempfile::tempdir().map_err(|e| DuckDbError::Internal(e.to_string()))?;
            let path = temp.path().join("export.duckdb");
            std::fs::write(&path, artifact.checkpoint)
                .map_err(|e| DuckDbError::Internal(e.to_string()))?;
            std::fs::write(duckdb_wal_path(&path), delta)
                .map_err(|e| DuckDbError::Internal(e.to_string()))?;
            let conn = storage::open_connection(Some(&path), &max_memory)?;
            {
                let _timer = QueryTimer::new();
                conn.execute_batch("CHECKPOINT")
                    .map_err(|e| DuckDbError::Internal(e.to_string()))?;
            }
            drop(conn);
            std::fs::read(path).map_err(|e| DuckDbError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| DuckDbError::Internal(e.to_string()))?
    }

    pub async fn import_db(
        &self,
        space: &SpaceId,
        db_name: &str,
        data: &[u8],
    ) -> Result<(), DuckDbError> {
        request_telemetry::observe_space(space);
        validate_db_name(db_name)?;
        let operation_lock = Self::database_lock(
            &self.operation_locks,
            &(space.to_string(), db_name.to_string()),
        )
        .await;
        let _operation = operation_lock.lock().await;
        // An import holds the staged file and, when saved in parts, a snapshot
        // copy of it: twice its size on disk.
        let _reservation = self.disk.reserve(
            &disk::budget_key(&space.to_string(), db_name),
            (data.len() as u64).saturating_mul(2),
            &PathBuf::from(&self.base_path).join(space.to_string()),
        )?;

        let dir = std::path::PathBuf::from(&self.base_path).join(space.to_string());
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| DuckDbError::Internal(e.to_string()))?;

        let final_path = dir.join(format!("{}.duckdb", db_name));
        let temp_path = staging_path(&final_path);
        let _live = StagingRelease(temp_path.clone());

        // Stage, validate and move the file into place. Any failure before the
        // rename leaves the staged bytes behind, so it removes them.
        let key = (space.to_string(), db_name.to_string());
        let staged = async {
            tokio::fs::write(&temp_path, data)
                .await
                .map_err(|e| DuckDbError::ImportError(e.to_string()))?;

            // Validate with the same locked native policy as live and export connections.
            let temp_path_clone = temp_path.clone();
            let max_memory = self.max_memory_per_connection.clone();
            let context = request_telemetry::current();
            tokio::task::spawn_blocking(move || -> Result<(), DuckDbError> {
                let _context = request_telemetry::enter(context);
                let conn =
                    storage::open_connection(Some(&temp_path_clone), &max_memory).map_err(|e| {
                        match e {
                            DuckDbError::Internal(message) => DuckDbError::ImportError(format!(
                                "Invalid DuckDB file: {}",
                                message
                            )),
                            other => other,
                        }
                    })?;
                {
                    let _timer = QueryTimer::new();
                    conn.execute_batch("SELECT 1").map_err(|e| {
                        DuckDbError::ImportError(format!("Database validation failed: {}", e))
                    })?;
                }
                Ok(())
            })
            .await
            .map_err(|e| DuckDbError::Internal(format!("Validation task failed: {}", e)))??;

            // Close the previous actor before replacing its files: connection
            // shutdown may checkpoint its old WAL into that path.
            if let Some((_, handle)) = self.databases.remove(&key) {
                handle.shutdown().await?;
            }
            self.lineage.remove(&key);
            tokio::fs::rename(&temp_path, &final_path)
                .await
                .map_err(|e| DuckDbError::ImportError(format!("Failed to finalize import: {}", e)))
        }
        .await;
        if let Err(e) = staged {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(e);
        }

        // From here the imported file is in the cache; a failure to persist it
        // must not leave it there to be served.
        let persisted = async {
            if self
                .artifact_repository
                .chunked_checkpoints("duckdb", &key.0, db_name)
            {
                let snapshot = tempfile::NamedTempFile::new()
                    .map_err(|e| DuckDbError::Internal(e.to_string()))?;
                tokio::fs::write(snapshot.path(), data)
                    .await
                    .map_err(|e| DuckDbError::ImportError(e.to_string()))?;
                self.artifact_repository
                    .save_snapshot(
                        "duckdb",
                        &key.0,
                        db_name,
                        snapshot,
                        ArtifactExpectation::Any,
                    )
                    .await
                    .map(|_| ())
                    .map_err(artifact_error_to_duckdb)
            } else {
                self.artifact_repository
                    .save(
                        "duckdb",
                        &key.0,
                        db_name,
                        data.to_vec(),
                        ArtifactExpectation::Any,
                    )
                    .await
                    .map(|_| ())
                    .map_err(artifact_error_to_duckdb)
            }
        }
        .await;
        if let Err(error) = persisted {
            self.discard_local_state(&key).await?;
            return Err(error);
        }

        Ok(())
    }

    pub fn db_name_from_path(path: Option<&str>) -> String {
        crate::database_identity::logical_name(path)
    }

    /// The pre-N2 selector, for N3's explicit legacy-artifact inventory only.
    pub fn legacy_db_name_from_path(path: Option<&str>) -> String {
        crate::database_identity::legacy_duckdb_name(path)
    }

    /// Resolve the live actor for `key`, hydrating the on-disk cache first if
    /// there is none.
    ///
    /// Hydration deletes and rewrites the very files a running actor reads BY
    /// PATH, and two hydrations of one database interleave their writes, so the
    /// miss -> hydrate -> spawn window is serialized per (space, db) and the
    /// actor map is re-checked under the guard. Both properties are load-bearing:
    /// hydrating concurrently with another hydration, or under a live actor, is
    /// how a database silently reverts to an older checkpoint.
    async fn handle(&self, space: &SpaceId, db_name: &str) -> Result<DatabaseHandle, DuckDbError> {
        let key = (space.to_string(), db_name.to_string());
        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            return Ok(handle);
        }

        let hydration_lock = Self::database_lock(&self.hydration_locks, &key).await;
        let _hydrating = hydration_lock.lock().await;

        // Double-checked: whoever held the guard may have hydrated and spawned
        // the actor already, and hydrating under it is exactly what the guard
        // exists to prevent.
        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            return Ok(handle);
        }

        self.hydrate_cache(space, db_name).await?;

        Ok(self
            .databases
            .entry(key)
            .or_insert_with(|| {
                spawn_actor_with_disk(
                    space.to_string(),
                    db_name.to_string(),
                    self.base_path.clone(),
                    self.memory_threshold,
                    self.artifact_repository.chunked_checkpoints(
                        "duckdb",
                        &space.to_string(),
                        db_name,
                    ),
                    self.idle_timeout_secs,
                    self.max_memory_per_connection.clone(),
                    self.databases.clone(),
                    self.disk.clone(),
                )
            })
            .clone())
    }

    /// Resolve a per-database guard without retaining idle locks indefinitely.
    async fn database_lock(
        registry: &DatabaseLockRegistry,
        key: &(String, String),
    ) -> Arc<DatabaseLock> {
        let mut registry = registry.lock().await;
        registry.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = registry.get(key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(DatabaseLock::new(()));
        registry.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }

    async fn hydrate_cache(&self, space: &SpaceId, db_name: &str) -> Result<(), DuckDbError> {
        let cache_path = self.cache_path(space, db_name);
        let key = (space.to_string(), db_name.to_string());
        sweep_stale_staging(&[&cache_path, &duckdb_wal_path(&cache_path)]).await;
        let mut sink = CacheFileSink::new(
            "duckdb",
            format!("{space}/{db_name}"),
            cache_path.clone(),
            duckdb_wal_path(&cache_path),
            is_duckdb_file,
            is_not_duckdb_file,
        );
        match read_artifact(
            self.artifact_repository.as_ref(),
            "duckdb",
            &space.to_string(),
            db_name,
            &mut sink,
        )
        .await
        .map_err(artifact_error_to_duckdb)?
        {
            Some(meta) => {
                tracing::info!(
                    service = "duckdb",
                    revision = meta.revision,
                    storage_mode = %meta.storage_mode,
                    bytes = meta.checkpoint_size_bytes,
                    delta_bytes = meta.delta_size_bytes,
                    logical_bytes = meta.size_bytes,
                    content_hash = %meta.content_hash,
                    checkpoint_content_hash = %meta.checkpoint_content_hash,
                    "Loaded database artifact"
                );
                remove_duckdb_cache_files(&cache_path).await?;
                sink.commit()
                    .await
                    .map_err(|e| DuckDbError::Internal(e.to_string()))?;
                self.lineage.insert(
                    key,
                    ArtifactExpectation::Derived {
                        revision: meta.revision,
                        checkpoint_content_hash: meta.checkpoint_content_hash,
                    },
                );
                Ok(())
            }
            None => {
                tracing::info!(
                    service = "duckdb",
                    "No durable database artifact; starting from an empty database"
                );
                remove_duckdb_cache_files(&cache_path).await?;
                self.lineage.insert(key, ArtifactExpectation::Absent);
                Ok(())
            }
        }
    }

    fn cache_path(&self, space: &SpaceId, db_name: &str) -> PathBuf {
        PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.duckdb", db_name))
    }

    async fn discard_local_state(&self, key: &(String, String)) -> Result<(), DuckDbError> {
        if let Some((_, handle)) = self.databases.remove(key) {
            // DuckDB can flush on connection close. Await it before deleting
            // the cache so an old actor cannot overwrite a new hydration.
            handle.shutdown().await?;
        }
        self.lineage.remove(key);
        let cache_path = PathBuf::from(&self.base_path)
            .join(&key.0)
            .join(format!("{}.duckdb", key.1));
        remove_duckdb_cache_files(&cache_path).await
    }

    /// What the actor for `key` derives from.
    ///
    /// Every actor is created by `handle`, which records this during hydration,
    /// so a live actor always has an entry. A missing one means the actor
    /// outlived its record and there is nothing to assert against.
    fn expectation(&self, key: &(String, String)) -> ArtifactExpectation {
        match self.lineage.get(key).map(|entry| entry.clone()) {
            Some(expectation) => expectation,
            None => {
                tracing::warn!(
                    service = "duckdb",
                    "No recorded artifact lineage for a live database; saving without a lineage assertion"
                );
                ArtifactExpectation::Any
            }
        }
    }

    async fn persist_write(
        &self,
        space: &SpaceId,
        db_name: &str,
        handle: &DatabaseHandle,
    ) -> Result<(), DuckDbError> {
        let key = (space.to_string(), db_name.to_string());
        let expected = self.expectation(&key);

        let checkpoint = if expected != ArtifactExpectation::Absent {
            self.artifact_repository
                .load_meta("duckdb", &key.0, db_name)
                .await
                .map_err(artifact_error_to_duckdb)?
        } else {
            None
        };

        if self
            .artifact_repository
            .chunked_checkpoints("duckdb", &key.0, db_name)
        {
            if let Some(meta) = &checkpoint {
                let wal = if meta.checkpoint_size_bytes >= 0 {
                    handle
                        .wal_snapshot_for_checkpoint(
                            MAX_WAL_DELTA_BYTES as u64,
                            meta.checkpoint_size_bytes as u64,
                            meta.checkpoint_content_hash.clone(),
                        )
                        .await?
                } else {
                    None
                };
                if let Some(wal) = wal {
                    let saved = match self
                        .artifact_repository
                        .save_wal_snapshot("duckdb", &key.0, db_name, wal, expected)
                        .await
                    {
                        Ok(saved) => saved,
                        Err(
                            DatabaseArtifactError::MissingCheckpoint
                            | DatabaseArtifactError::IncrementalPersistenceUnsupported,
                        ) => {
                            return self.checkpoint(space, db_name, handle, false).await;
                        }
                        Err(error) => return Err(artifact_error_to_duckdb(error)),
                    };
                    self.lineage.insert(
                        key,
                        ArtifactExpectation::Derived {
                            revision: saved.revision,
                            checkpoint_content_hash: saved.checkpoint_content_hash,
                        },
                    );
                    return Ok(());
                }
            }
            return self.checkpoint(space, db_name, handle, false).await;
        }

        let wal = match checkpoint {
            Some(meta) if meta.checkpoint_size_bytes >= 0 => {
                handle
                    .wal_for_checkpoint(
                        meta.checkpoint_size_bytes as u64,
                        meta.checkpoint_content_hash,
                    )
                    .await?
            }
            _ => None,
        };
        if let Some(wal) = wal.filter(|wal| wal.len() < MAX_WAL_DELTA_BYTES) {
            match self
                .artifact_repository
                .save_delta("duckdb", &space.to_string(), db_name, wal, expected.clone())
                .await
            {
                Ok(saved) => {
                    // The delta rides on the same checkpoint, so only the
                    // revision this actor is caught up to moves.
                    self.lineage
                        .insert(key, expected.advanced_to(saved.revision));
                    tracing::info!(
                        service = "duckdb",
                        mode = "wal",
                        bytes = saved.delta_size_bytes,
                        logical_bytes = saved.size_bytes,
                        revision = saved.revision,
                        "Persisted incremental database artifact"
                    );
                    return Ok(());
                }
                Err(
                    DatabaseArtifactError::MissingCheckpoint
                    | DatabaseArtifactError::IncrementalPersistenceUnsupported,
                ) => {}
                Err(error) => return Err(artifact_error_to_duckdb(error)),
            }
        }

        self.checkpoint(space, db_name, handle, false).await
    }

    async fn checkpoint(
        &self,
        space: &SpaceId,
        db_name: &str,
        handle: &DatabaseHandle,
        without_growth: bool,
    ) -> Result<(), DuckDbError> {
        let key = (space.to_string(), db_name.to_string());
        let expected = self.expectation(&key);
        if self
            .artifact_repository
            .chunked_checkpoints("duckdb", &key.0, db_name)
        {
            let snapshot = handle.snapshot().await?;
            if without_growth {
                let size = snapshot
                    .as_file()
                    .metadata()
                    .map_err(|e| DuckDbError::Internal(e.to_string()))?
                    .len();
                let durable = self
                    .artifact_repository
                    .load_meta("duckdb", &key.0, db_name)
                    .await
                    .map_err(artifact_error_to_duckdb)?
                    .map_or(0, |m| m.size_bytes.max(0) as u64);
                if size > durable {
                    return Err(DuckDbError::StorageWouldGrow);
                }
            }
            let saved = self
                .artifact_repository
                .save_snapshot("duckdb", &key.0, db_name, snapshot, expected)
                .await
                .map_err(artifact_error_to_duckdb)?;
            self.lineage.insert(
                key,
                ArtifactExpectation::Derived {
                    revision: saved.revision,
                    checkpoint_content_hash: saved.checkpoint_content_hash,
                },
            );
            return Ok(());
        }
        let payload = handle.export().await?;
        let bytes = payload.len();
        if without_growth {
            let durable_bytes = self
                .artifact_repository
                .load_meta("duckdb", &key.0, db_name)
                .await
                .map_err(artifact_error_to_duckdb)?
                .map_or(0, |artifact| artifact.size_bytes.max(0) as u64);
            if bytes as u64 > durable_bytes {
                return Err(DuckDbError::StorageWouldGrow);
            }
        }
        let saved = self
            .artifact_repository
            .save("duckdb", &space.to_string(), db_name, payload, expected)
            .await
            .map_err(artifact_error_to_duckdb)?;
        self.lineage.insert(
            key,
            ArtifactExpectation::Derived {
                revision: saved.revision,
                checkpoint_content_hash: saved.checkpoint_content_hash.clone(),
            },
        );
        tracing::info!(
            service = "duckdb",
            mode = "checkpoint",
            bytes,
            logical_bytes = saved.size_bytes,
            revision = saved.revision,
            "Persisted database checkpoint"
        );
        Ok(())
    }
}

/// The WAL carries no header of its own; it must at least not be a database,
/// which is the shape a crossed hydration writes.
fn is_not_duckdb_file(payload: &[u8]) -> bool {
    !is_duckdb_file(payload)
}

/// Whether `payload` carries DuckDB's main-database header.
fn is_duckdb_file(payload: &[u8]) -> bool {
    payload
        .get(DUCKDB_MAGIC_OFFSET..DUCKDB_MAGIC_OFFSET + DUCKDB_MAGIC.len())
        .is_some_and(|magic| magic == DUCKDB_MAGIC)
}

/// Reject a hydration payload whose leading bytes are not the format the file
/// it is about to become is read as.
fn validate_payload(
    space: &SpaceId,
    db_name: &str,
    role: &'static str,
    payload: &[u8],
    is_valid: impl Fn(&[u8]) -> bool,
) -> Result<(), DuckDbError> {
    if is_valid(payload) {
        return Ok(());
    }
    tracing::error!(
        service = "duckdb",
        role,
        bytes = payload.len(),
        "Durable database artifact does not carry the expected file header; refusing to hydrate"
    );
    Err(DuckDbError::Internal(format!(
        "database artifact {role} for {space}/{db_name} does not carry the expected file header"
    )))
}

async fn remove_duckdb_cache_files(path: &Path) -> Result<(), DuckDbError> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        cache_file_paths(&path)
            .iter()
            .try_for_each(|candidate| remove_cache_entry(candidate))
    })
    .await
    .map_err(|e| DuckDbError::Internal(e.to_string()))?
    .map_err(|e| DuckDbError::Internal(e.to_string()))
}

fn duckdb_wal_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.wal", path.display()))
}

/// The bytes of the local main file and WAL at `path` (0 for absent files).
async fn local_file_bytes(path: &Path) -> u64 {
    let mut total = 0u64;
    for file in [path.to_path_buf(), duckdb_wal_path(path)] {
        if let Ok(metadata) = tokio::fs::metadata(&file).await {
            total = total.saturating_add(metadata.len());
        }
    }
    total
}

/// A DuckDB spill directory (`<db>.duckdb.tmp`) or a staging / renamed-aside
/// name (`<db>.duckdb.tmp.<pid>.<n>`, `<db>.duckdb.wal.tmp.<pid>.<n>`): never
/// live once the process that made it has stopped.
fn is_stale_cache_name(name: &str) -> bool {
    if name.ends_with(".duckdb.tmp") {
        return true;
    }
    let Some((_, suffix)) = name
        .rsplit_once(".duckdb.tmp.")
        .or_else(|| name.rsplit_once(".duckdb.wal.tmp."))
    else {
        return false;
    };
    matches!(
        suffix.split_once('.'),
        Some((pid, n))
            if !pid.is_empty()
                && !n.is_empty()
                && pid.bytes().all(|b| b.is_ascii_digit())
                && n.bytes().all(|b| b.is_ascii_digit())
    )
}

/// `DuckDbError` has no retryable-unavailable variant (adding one would reach
/// every route mapping), so an exhausted `ArtifactChanged` stays `Internal`.
/// The artifact size limits answer 507, as for SQL (TC-2961).
fn artifact_error_to_duckdb(err: DatabaseArtifactError) -> DuckDbError {
    match err {
        DatabaseArtifactError::StorageLimit | DatabaseArtifactError::WriteLimitExceeded { .. } => {
            DuckDbError::DatabaseSizeLimit
        }
        DatabaseArtifactError::ReadLimitExceeded { .. } => DuckDbError::DatabaseTooLargeToLoad,
        DatabaseArtifactError::ReplacementBusy => DuckDbError::Unavailable,
        err => DuckDbError::Internal(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database_artifacts::{test_support::ReadAll, SeaOrmDatabaseArtifactRepository},
        migrations::Migrator,
        sea_orm::{ConnectOptions, Database},
        sea_orm_migration::MigratorTrait,
        sql_sizes::{SizeTrackingArtifactRepository, SqlSizes},
    };
    use tempfile::TempDir;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        ssi::{dids::DIDBuf, jwk::JWK},
    };

    fn test_space_id(name: &str) -> SpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, name.parse().unwrap()).unwrap()
    }

    async fn artifact_repository() -> Arc<SeaOrmDatabaseArtifactRepository> {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        Arc::new(SeaOrmDatabaseArtifactRepository::new(db))
    }

    fn service(cache: &TempDir, repo: Arc<SeaOrmDatabaseArtifactRepository>) -> DuckDbService {
        DuckDbService::new(
            cache.path().to_string_lossy().to_string(),
            u64::MAX,
            300,
            "128MB".to_string(),
            repo,
        )
    }

    fn file_service(cache: &TempDir, repo: Arc<SeaOrmDatabaseArtifactRepository>) -> DuckDbService {
        DuckDbService::new(
            cache.path().to_string_lossy().to_string(),
            0,
            300,
            "128MB".to_string(),
            repo,
        )
    }

    #[tokio::test]
    async fn tc626_export_after_rejected_creation_stays_absent() {
        for memory_threshold in [u64::MAX, 0] {
            let sizes = SqlSizes::new();
            let repo = Arc::new(SizeTrackingArtifactRepository::new(
                artifact_repository().await,
                sizes.clone(),
            ));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("duckdb-rejected-export");
            let service = DuckDbService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                300,
                "128MB".into(),
                repo.clone(),
            );
            for (name, sql, grows) in [
                ("first", "CREATE TABLE data (id INTEGER)", true),
                ("invalid", "DELETE FROM missing", false),
                ("second", "CREATE TABLE data (id INTEGER)", true),
            ] {
                let retired = service.handle(&space, name).await.unwrap();
                let rejected = service
                    .execute_without_growth(
                        &space,
                        name,
                        DuckDbRequest::Execute {
                            schema: None,
                            sql: sql.into(),
                            params: vec![],
                        },
                        None,
                        "tinycloud.duckdb/write".into(),
                        false,
                    )
                    .await;
                if grows {
                    assert!(matches!(rejected, Err(DuckDbError::StorageWouldGrow)));
                } else {
                    assert!(matches!(rejected, Err(DuckDbError::DuckDb(_))));
                }
                let exported = service.export(&space, name).await;
                assert_eq!(sizes.space_total(&space).await, 0);
                assert!(matches!(exported, Err(DuckDbError::DatabaseNotFound)));
                assert!(repo
                    .read_all("duckdb", &space.to_string(), name)
                    .await
                    .unwrap()
                    .is_none());
                // Cleanup must close the rejected actor, not merely hide it
                // behind the export existence check.
                assert!(matches!(
                    retired
                        .execute(
                            DuckDbRequest::Query {
                                sql: "SELECT 1".into(),
                                params: vec![],
                            },
                            None,
                            "tinycloud.duckdb/read".into(),
                            false,
                            false,
                        )
                        .await,
                    Err(DuckDbError::Internal(_))
                ));
            }
        }
    }

    #[tokio::test]
    async fn tc626_export_of_read_only_absent_actor_stays_absent() {
        let sizes = SqlSizes::new();
        let repo = Arc::new(SizeTrackingArtifactRepository::new(
            artifact_repository().await,
            sizes.clone(),
        ));
        let cache = TempDir::new().unwrap();
        let space = test_space_id("duckdb-read-export");
        let service = DuckDbService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            300,
            "128MB".into(),
            repo.clone(),
        );
        service
            .execute(
                &space,
                "absent",
                DuckDbRequest::Query {
                    sql: "SELECT 1".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/read".into(),
                false,
            )
            .await
            .unwrap();
        let exported = service.export(&space, "absent").await;
        assert_eq!(sizes.space_total(&space).await, 0);
        assert!(matches!(exported, Err(DuckDbError::DatabaseNotFound)));
        assert!(repo
            .read_all("duckdb", &space.to_string(), "absent")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn tc626_review_absent_noops_do_not_create_charged_artifacts() {
        for memory_threshold in [u64::MAX, 0] {
            let sizes = SqlSizes::new();
            let repo = Arc::new(SizeTrackingArtifactRepository::new(
                artifact_repository().await,
                sizes.clone(),
            ));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("duckdb-absent-noops");
            let service = DuckDbService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                300,
                "128MB".into(),
                repo.clone(),
            );
            for name in ["unused-one", "unused-two", "unused-three"] {
                service
                    .execute_without_growth(
                        &space,
                        name,
                        DuckDbRequest::Execute {
                            schema: None,
                            sql: "DROP TABLE IF EXISTS absent".into(),
                            params: vec![],
                        },
                        None,
                        "tinycloud.duckdb/write".into(),
                        false,
                    )
                    .await
                    .expect("dropping an absent table is a successful no-op");
                assert_eq!(sizes.space_total(&space).await, 0);
                assert!(repo
                    .read_all("duckdb", &space.to_string(), name)
                    .await
                    .unwrap()
                    .is_none());
                assert!(matches!(
                    service.export(&space, name).await,
                    Err(DuckDbError::DatabaseNotFound)
                ));
            }
        }
    }

    #[tokio::test]
    async fn tc626_review_serialized_growth_is_rejected_and_discarded() {
        for memory_threshold in [u64::MAX, 0] {
            let sizes = SqlSizes::new();
            let repo = Arc::new(SizeTrackingArtifactRepository::new(
                artifact_repository().await,
                sizes.clone(),
            ));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("duckdb-durable-budget");
            let service = DuckDbService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                300,
                "128MB".into(),
                repo.clone(),
            );
            service
                .execute(
                    &space,
                    "main",
                    DuckDbRequest::Execute {
                        schema: Some(vec!["CREATE TABLE data (id INTEGER, body VARCHAR)".into()]),
                        sql: "INSERT INTO data VALUES (1, 'durable')".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/write".into(),
                    false,
                )
                .await
                .unwrap();
            let before = repo
                .read_all("duckdb", &space.to_string(), "main")
                .await
                .unwrap()
                .unwrap();
            let failed = service
                .execute(
                    &space,
                    "main",
                    DuckDbRequest::Execute {
                        schema: Some(vec![
                            "INSERT INTO data SELECT i + 2, md5(CAST(i AS VARCHAR)) FROM range(20000) t(i)".into(),
                        ]),
                        sql: "INSERT INTO missing_table VALUES (1)".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/write".into(),
                    false,
                )
                .await;
            assert!(matches!(failed, Err(DuckDbError::DuckDb(_))));
            let rejected = service
                .execute_without_growth(
                    &space,
                    "main",
                    DuckDbRequest::Execute {
                        schema: None,
                        sql: "DELETE FROM data WHERE id = 1".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/write".into(),
                    false,
                )
                .await;
            assert!(
                matches!(rejected, Err(DuckDbError::StorageWouldGrow)),
                "{rejected:?}"
            );
            let after = repo
                .read_all("duckdb", &space.to_string(), "main")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.revision, before.revision);
            assert_eq!(after.payload, before.payload);
            assert_eq!(after.delta_payload, before.delta_payload);
            assert_eq!(sizes.space_total(&space).await, before.size_bytes as u64);
            let query = || DuckDbRequest::Query {
                sql: "SELECT id, body FROM data ORDER BY id".into(),
                params: vec![],
            };
            let live = service
                .execute(
                    &space,
                    "main",
                    query(),
                    None,
                    "tinycloud.duckdb/read".into(),
                    false,
                )
                .await
                .unwrap();
            let DuckDbResponse::Query(live) = live.response else {
                panic!("query response required")
            };
            assert_eq!(
                live.rows,
                vec![vec![
                    DuckDbValue::Integer(1),
                    DuckDbValue::Text("durable".into())
                ]]
            );
            service
                .execute(
                    &space,
                    "main",
                    DuckDbRequest::Execute {
                        schema: None,
                        sql: "UPDATE data SET body = 'later' WHERE id = 1".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/write".into(),
                    false,
                )
                .await
                .unwrap();
            let cold_cache = TempDir::new().unwrap();
            let recovered = DuckDbService::new(
                cold_cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                300,
                "128MB".into(),
                repo,
            );
            let cold = recovered
                .execute(
                    &space,
                    "main",
                    query(),
                    None,
                    "tinycloud.duckdb/read".into(),
                    false,
                )
                .await
                .unwrap();
            let DuckDbResponse::Query(cold) = cold.response else {
                panic!("query response required")
            };
            assert_eq!(
                cold.rows,
                vec![vec![
                    DuckDbValue::Integer(1),
                    DuckDbValue::Text("later".into())
                ]]
            );
        }
    }

    #[tokio::test]
    async fn duckdb_write_survives_service_recreation_with_empty_cache() {
        let repo = artifact_repository().await;
        let cache_one = TempDir::new().unwrap();
        let cache_two = TempDir::new().unwrap();
        let space = test_space_id("duckdb-hydrate");

        service(&cache_one, repo.clone())
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Execute {
                    schema: Some(vec![
                        "CREATE TABLE events (id INTEGER, name VARCHAR)".to_string()
                    ]),
                    sql: "INSERT INTO events VALUES (1, 'durable')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/write".to_string(),
                false,
            )
            .await
            .unwrap();

        let recreated = service(&cache_two, repo);
        let result = recreated
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Query {
                    sql: "SELECT name FROM events ORDER BY id".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/read".to_string(),
                false,
            )
            .await
            .unwrap();

        match result.response {
            DuckDbResponse::Query(query) => {
                assert_eq!(query.row_count, 1);
                assert_eq!(query.rows[0][0], DuckDbValue::Text("durable".to_string()));
            }
            other => panic!("expected query response, got {:?}", other),
        }

        let exported = recreated.export(&space, "analytics").await.unwrap();
        assert!(!exported.is_empty(), "hydrated DuckDB should export");

        let hydrated_path = cache_two
            .path()
            .join(space.to_string())
            .join("analytics.duckdb");
        assert!(
            hydrated_path.exists(),
            "durable artifact should hydrate cache"
        );
    }

    #[tokio::test]
    async fn duckdb_file_backed_small_writes_persist_wal_not_full_database() {
        let repo = artifact_repository().await;
        let source_cache = TempDir::new().unwrap();
        let file_cache = TempDir::new().unwrap();
        let recovery_cache = TempDir::new().unwrap();
        let space = test_space_id("duckdb-wal-delta");
        let source = service(&source_cache, repo.clone());

        source
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Execute {
                    schema: None,
                    sql: "CREATE TABLE events (id INTEGER, name VARCHAR)".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/write".to_string(),
                false,
            )
            .await
            .unwrap();
        source
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO events VALUES (0, repeat('x', 1000000))".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/write".to_string(),
                false,
            )
            .await
            .unwrap();

        // Hydrating a fresh cache from the durable checkpoint starts the actor
        // file-backed, matching a heavy production database after restart.
        let service = file_service(&file_cache, repo.clone());
        service
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO events VALUES (1, 'one')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/write".to_string(),
                false,
            )
            .await
            .unwrap();
        let artifact = repo
            .read_all("duckdb", &space.to_string(), "analytics")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(artifact.storage_mode, "checkpoint+wal");
        assert!(artifact.delta_size_bytes > 0);
        println!(
            "duckdb artifact persistence: checkpoint={} delta={}",
            artifact.payload.len(),
            artifact.delta_size_bytes
        );
        assert!(
            artifact.delta_size_bytes < artifact.payload.len() as i64,
            "a small write should transfer fewer bytes than the checkpoint"
        );

        // Export must not rewrite durable state or checkpoint the live actor:
        // its next WAL must still derive from the existing durable base.
        let export_cache = TempDir::new().unwrap();
        let cold = file_service(&export_cache, repo.clone());
        for exporter in [&service, &cold] {
            let bytes = exporter.export(&space, "analytics").await.unwrap();
            let snapshot_dir = TempDir::new().unwrap();
            let snapshot_path = snapshot_dir.path().join("snapshot.duckdb");
            std::fs::write(&snapshot_path, bytes).unwrap();
            let snapshot = storage::open_connection(Some(&snapshot_path), "128MB").unwrap();
            let names: String = snapshot
                .query_row("SELECT name FROM events WHERE id = 1", [], |row| row.get(0))
                .unwrap();
            assert_eq!(names, "one");
            let after = repo
                .read_all("duckdb", &space.to_string(), "analytics")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.revision, artifact.revision);
            assert_eq!(after.size_bytes, artifact.size_bytes);
            assert_eq!(after.payload, artifact.payload);
            assert_eq!(after.delta_payload, artifact.delta_payload);
        }
        service
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO events VALUES (2, 'two')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/write".to_string(),
                false,
            )
            .await
            .unwrap();

        let recreated = file_service(&recovery_cache, repo);
        let result = recreated
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Query {
                    sql: "SELECT name FROM events WHERE id > 0 ORDER BY id".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/read".to_string(),
                false,
            )
            .await
            .unwrap();
        match result.response {
            DuckDbResponse::Query(query) => {
                assert_eq!(query.row_count, 2);
                assert_eq!(query.rows[0][0], DuckDbValue::Text("one".to_string()));
                assert_eq!(query.rows[1][0], DuckDbValue::Text("two".to_string()));
            }
            other => panic!("expected query response, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn duckdb_import_survives_service_recreation_with_empty_cache() {
        let source_repo = artifact_repository().await;
        let source_cache = TempDir::new().unwrap();
        let space = test_space_id("duckdb-import");

        let source = service(&source_cache, source_repo);
        source
            .execute(
                &space,
                "source",
                DuckDbRequest::Execute {
                    schema: Some(vec![
                        "CREATE TABLE events (id INTEGER, name VARCHAR)".to_string()
                    ]),
                    sql: "INSERT INTO events VALUES (1, 'imported')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/write".to_string(),
                false,
            )
            .await
            .unwrap();
        let exported = source.export(&space, "source").await.unwrap();

        let repo = artifact_repository().await;
        let import_cache = TempDir::new().unwrap();
        service(&import_cache, repo.clone())
            .import_db(&space, "imported", &exported)
            .await
            .unwrap();

        let empty_cache = TempDir::new().unwrap();
        let recreated = service(&empty_cache, repo);
        let result = recreated
            .execute(
                &space,
                "imported",
                DuckDbRequest::Query {
                    sql: "SELECT name FROM events ORDER BY id".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/read".to_string(),
                false,
            )
            .await
            .unwrap();

        match result.response {
            DuckDbResponse::Query(query) => {
                assert_eq!(query.row_count, 1);
                assert_eq!(query.rows[0][0], DuckDbValue::Text("imported".to_string()));
            }
            other => panic!("expected query response, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn duckdb_full_database_writes_persist_without_retaining_rejected_growth() {
        let repo = artifact_repository().await;
        let source_cache = TempDir::new().unwrap();
        let guarded_cache = TempDir::new().unwrap();
        let recovery_cache = TempDir::new().unwrap();
        let space = test_space_id("duckdb-full");
        let source = service(&source_cache, repo.clone());
        source
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Execute {
                    schema: Some(vec![
                        "CREATE TABLE events (id INTEGER); CREATE TABLE obsolete (id INTEGER)"
                            .to_string(),
                    ]),
                    sql: "INSERT INTO events VALUES (1), (2)".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/write".to_string(),
                false,
            )
            .await
            .unwrap();

        // A fresh service hydrates a real file-backed database.
        let guarded = file_service(&guarded_cache, repo.clone());
        guarded
            .execute_without_growth(
                &space,
                "analytics",
                DuckDbRequest::Execute {
                    schema: Some(vec![
                        "CREATE TABLE IF NOT EXISTS events (id INTEGER); DROP TABLE obsolete"
                            .to_string(),
                    ]),
                    sql: "DELETE FROM events WHERE id = ?".to_string(),
                    params: vec![DuckDbValue::Integer(1)],
                },
                None,
                "tinycloud.duckdb/write".to_string(),
                false,
            )
            .await
            .unwrap();

        let rejected = guarded
            .execute_without_growth(
                &space,
                "analytics",
                DuckDbRequest::Batch {
                    statements: vec![
                        DuckDbStatement {
                            sql: "DELETE FROM events".to_string(),
                            params: Vec::new(),
                        },
                        DuckDbStatement {
                            sql: "CREATE TABLE IF NOT EXISTS rejected (id INTEGER)".to_string(),
                            params: Vec::new(),
                        },
                    ],
                    transactional: false,
                },
                None,
                "tinycloud.duckdb/write".to_string(),
                false,
            )
            .await;
        assert!(matches!(rejected, Err(DuckDbError::StorageWouldGrow)));

        let recovered = file_service(&recovery_cache, repo);
        let result = recovered
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Query {
                    sql: "SELECT id FROM events".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.duckdb/read".to_string(),
                false,
            )
            .await
            .unwrap();
        match result.response {
            DuckDbResponse::Query(query) => {
                assert_eq!(query.rows, vec![vec![DuckDbValue::Integer(2)]]);
            }
            other => panic!("expected query response, got {other:?}"),
        }
        let schema = recovered
            .execute(
                &space,
                "analytics",
                DuckDbRequest::Describe,
                None,
                "tinycloud.duckdb/read".to_string(),
                false,
            )
            .await
            .unwrap();
        match schema.response {
            DuckDbResponse::Describe(schema) => {
                let tables: Vec<_> = schema
                    .tables
                    .iter()
                    .map(|table| table.name.as_str())
                    .collect();
                assert_eq!(tables, vec!["events"]);
            }
            other => panic!("expected schema response, got {other:?}"),
        }
    }
    #[tokio::test]
    async fn postgres_chunked_duckdb_save_wal_restart_and_import() {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};
        for memory_threshold in [0, u64::MAX] {
            let Some(fixture) = crate::test_support::PostgresTestSchema::new(
                "postgres_chunked_duckdb_save_wal_restart_and_import",
            )
            .await
            else {
                return;
            };
            let repo = Arc::new(
                SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone())
                    .with_chunk_limits(Some(crate::database_artifacts::chunks::ChunkLimits {
                        artifact_bytes: 64 * 1024 * 1024,
                        account_bytes: 128 * 1024 * 1024,
                    }))
                    .with_max_write_bytes(1024 * 1024),
            );
            let first = TempDir::new().unwrap();
            let second = TempDir::new().unwrap();
            let space = test_space_id("chunked-duckdb");
            let service = DuckDbService::new(
                first.path().to_string_lossy().into_owned(),
                memory_threshold,
                300,
                "128MB".into(),
                repo.clone(),
            );
            service
                .execute(
                    &space,
                    "analytics",
                    DuckDbRequest::Execute {
                        schema: Some(vec!["CREATE TABLE events(id BIGINT, body VARCHAR)".into()]),
                        sql: "INSERT INTO events SELECT i, md5(i::VARCHAR) FROM range(100000) t(i)"
                            .into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/admin".into(),
                    false,
                )
                .await
                .unwrap();
            let initial = repo
                .load_meta("duckdb", &space.to_string(), "analytics")
                .await
                .unwrap()
                .unwrap();
            assert!(
                initial.checkpoint_size_bytes > 1024 * 1024,
                "test must cross a chunk boundary"
            );
            let checkpoint: String = fixture
                .conn
                .query_one(Statement::from_string(
                    DbBackend::Postgres,
                    "SELECT checkpoint_part_id FROM database_artifact".to_string(),
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get("", "checkpoint_part_id")
                .unwrap();
            assert!(
                service.cache_path(&space, "analytics").exists(),
                "chunked actors start file-backed"
            );
            service
                .execute(
                    &space,
                    "analytics",
                    DuckDbRequest::Execute {
                        schema: None,
                        sql: "INSERT INTO events VALUES (100000, 'last')".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/write".into(),
                    false,
                )
                .await
                .unwrap();
            let saved = repo
                .load_meta("duckdb", &space.to_string(), "analytics")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(saved.revision, 2);
            assert!(saved.delta_size_bytes > 0);
            assert_eq!(
                saved.checkpoint_content_hash,
                initial.checkpoint_content_hash
            );
            service
                .discard_local_state(&(space.to_string(), "analytics".into()))
                .await
                .unwrap();
            drop(service);
            // A new repository with the flag off still opens published parts.
            let off = Arc::new(
                SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone())
                    .with_max_write_bytes(1024 * 1024),
            );
            let reopened = DuckDbService::new(
                second.path().to_string_lossy().into_owned(),
                0,
                300,
                "128MB".into(),
                off,
            );
            let result = reopened
                .execute(
                    &space,
                    "analytics",
                    DuckDbRequest::Query {
                        sql: "SELECT count(*),max(CASE WHEN id=100000 THEN body END) FROM events"
                            .into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/read".into(),
                    false,
                )
                .await
                .unwrap();
            let DuckDbResponse::Query(query) = result.response else {
                panic!("query required");
            };
            assert_eq!(
                query.rows,
                vec![vec![
                    DuckDbValue::Integer(100001),
                    DuckDbValue::Text("last".into())
                ]]
            );
            let handle = reopened
                .databases
                .get(&(space.to_string(), "analytics".into()))
                .unwrap()
                .clone();
            reopened
                .checkpoint(&space, "analytics", &handle, false)
                .await
                .unwrap();
            repo.reap_unused_parts(128).await.unwrap();
            let n: i64 = fixture
                .conn
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT count(*)::bigint AS n FROM artifact_chunk WHERE part_id=$1",
                    [checkpoint.into()],
                ))
                .await
                .unwrap()
                .unwrap()
                .try_get("", "n")
                .unwrap();
            assert_eq!(n, 0, "superseded checkpoint chunks must be gone");
            let exported = reopened.export(&space, "analytics").await.unwrap();
            assert!(exported.len() > 1024 * 1024);
            // Import replaces a live actor and uses bounded payload statements.
            reopened
                .import_db(&space, "analytics", &exported)
                .await
                .unwrap();
            let imported = repo
                .load_meta("duckdb", &space.to_string(), "analytics")
                .await
                .unwrap()
                .unwrap();
            assert!(!imported.has_delta());
            let result = reopened
                .execute(
                    &space,
                    "analytics",
                    DuckDbRequest::Query {
                        sql: "SELECT count(*) FROM events".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/read".into(),
                    false,
                )
                .await
                .unwrap();
            let DuckDbResponse::Query(query) = result.response else {
                panic!("query required");
            };
            assert_eq!(query.rows, vec![vec![DuckDbValue::Integer(100001)]]);
            reopened
                .discard_local_state(&(space.to_string(), "analytics".into()))
                .await
                .unwrap();
            repo.reap_unused_parts(128).await.unwrap();
            let state=fixture.conn.query_one(Statement::from_string(DbBackend::Postgres,
                "SELECT max(octet_length(payload))::bigint AS max_bytes,count(*) FILTER(WHERE pg_column_compression(payload) IS NOT NULL)::bigint AS compressed FROM artifact_chunk".to_string())).await.unwrap().unwrap();
            assert!(state.try_get::<i64>("", "max_bytes").unwrap() <= 1024 * 1024);
            assert_eq!(state.try_get::<i64>("", "compressed").unwrap(), 0);
        }
    }

    #[tokio::test]
    async fn postgres_chunked_duckdb_capacity_refusal_discards_local_write() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_duckdb_capacity_refusal_discards_local_write",
        )
        .await
        else {
            return;
        };
        let repo = Arc::new(
            SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(Some(
                crate::database_artifacts::chunks::ChunkLimits {
                    artifact_bytes: 1,
                    account_bytes: 1,
                },
            )),
        );
        let cache = TempDir::new().unwrap();
        let service = file_service(&cache, repo.clone());
        let space = test_space_id("chunked-duckdb-cap");
        let outcome = service
            .execute(
                &space,
                "main",
                DuckDbRequest::Execute {
                    schema: Some(vec!["CREATE TABLE items(id INTEGER)".into()]),
                    sql: "INSERT INTO items VALUES (1)".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await;
        assert!(
            matches!(outcome, Err(DuckDbError::DatabaseSizeLimit)),
            "{outcome:?}"
        );
        assert!(repo
            .load_meta("duckdb", &space.to_string(), "main")
            .await
            .unwrap()
            .is_none());
        assert!(!service
            .databases
            .contains_key(&(space.to_string(), "main".into())));
        assert!(!service.cache_path(&space, "main").exists());
    }
    #[tokio::test]
    async fn postgres_chunked_duckdb_actor_close_and_idle_evict_remove_files() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_duckdb_actor_close_and_idle_evict_remove_files",
        )
        .await
        else {
            return;
        };
        let repo = Arc::new(
            SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(Some(
                crate::database_artifacts::chunks::ChunkLimits {
                    artifact_bytes: 4 * 1024 * 1024,
                    account_bytes: 16 * 1024 * 1024,
                },
            )),
        );
        let cache = TempDir::new().unwrap();
        let service = DuckDbService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            1,
            "128MB".into(),
            repo,
        );
        let space = test_space_id("chunked-duckdb-eviction");
        let key = (space.to_string(), "main".to_string());
        service
            .execute(
                &space,
                "main",
                DuckDbRequest::Execute {
                    schema: Some(vec!["CREATE TABLE items(id INTEGER)".into()]),
                    sql: "INSERT INTO items VALUES (1)".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
        let path = service.cache_path(&space, "main");
        assert!(path.exists());
        let handle = service.databases.get(&key).unwrap().clone();
        handle.shutdown().await.unwrap();
        assert!(!path.exists(), "actor shutdown itself removes the cache");
        assert!(!duckdb_wal_path(&path).exists());
        let query = || DuckDbRequest::Query {
            sql: "SELECT id FROM items".into(),
            params: vec![],
        };
        for _ in 0..2 {
            let result = service
                .execute(
                    &space,
                    "main",
                    query(),
                    None,
                    "tinycloud.duckdb/read".into(),
                    false,
                )
                .await
                .unwrap();
            let DuckDbResponse::Query(query) = result.response else {
                panic!("query required");
            };
            assert_eq!(query.rows, vec![vec![DuckDbValue::Integer(1)]]);
            assert!(path.exists());
            let until = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
            while service.databases.contains_key(&key) {
                assert!(tokio::time::Instant::now() < until, "actor must idle-evict");
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            assert!(
                !path.exists(),
                "idle eviction removes the closed actor's file"
            );
            assert!(!duckdb_wal_path(&path).exists());
            assert!(!PathBuf::from(format!("{}.tmp", path.display())).exists());
        }
    }
    #[tokio::test]
    async fn postgres_chunked_duckdb_legacy_wal_falls_back_to_snapshot() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_duckdb_legacy_wal_falls_back_to_snapshot",
        )
        .await
        else {
            return;
        };
        let first = TempDir::new().unwrap();
        let second = TempDir::new().unwrap();
        let third = TempDir::new().unwrap();
        let space = test_space_id("legacy-duckdb-parts");
        let legacy = Arc::new(SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()));
        let source = file_service(&first, legacy);
        source
            .execute(
                &space,
                "main",
                DuckDbRequest::Execute {
                    schema: Some(vec!["CREATE TABLE items(id INTEGER)".into()]),
                    sql: "INSERT INTO items VALUES (1)".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
        source
            .discard_local_state(&(space.to_string(), "main".into()))
            .await
            .unwrap();
        let repo = Arc::new(
            SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(Some(
                crate::database_artifacts::chunks::ChunkLimits {
                    artifact_bytes: 4 * 1024 * 1024,
                    account_bytes: 16 * 1024 * 1024,
                },
            )),
        );
        let service = file_service(&second, repo.clone());
        for id in [2, 3] {
            service
                .execute(
                    &space,
                    "main",
                    DuckDbRequest::Execute {
                        schema: None,
                        sql: format!("INSERT INTO items VALUES ({id})"),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/write".into(),
                    false,
                )
                .await
                .unwrap();
            let meta = repo
                .load_meta("duckdb", &space.to_string(), "main")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(meta.storage_mode, "checkpoint-parts-v1");
            assert_eq!(meta.revision, id);
            assert_eq!(meta.has_delta(), id == 3);
        }
        service
            .discard_local_state(&(space.to_string(), "main".into()))
            .await
            .unwrap();
        let reopened = file_service(&third, repo);
        let result = reopened
            .execute(
                &space,
                "main",
                DuckDbRequest::Query {
                    sql: "SELECT id FROM items ORDER BY id".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/read".into(),
                false,
            )
            .await
            .unwrap();
        let DuckDbResponse::Query(query) = result.response else {
            panic!("query required");
        };
        assert_eq!(
            query.rows,
            vec![
                vec![DuckDbValue::Integer(1)],
                vec![DuckDbValue::Integer(2)],
                vec![DuckDbValue::Integer(3)]
            ]
        );
        reopened
            .discard_local_state(&(space.to_string(), "main".into()))
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn tc2990_large_file_backed_insert_recovers_all_acknowledged_rows() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let space = test_space_id("large-file-write-recovery");
        let key = (space.to_string(), "main".to_string());
        let service = file_service(&cache, repo.clone());
        service
            .execute(
                &space,
                "main",
                DuckDbRequest::Execute {
                    schema: Some(vec!["CREATE TABLE items(id BIGINT, body VARCHAR)".into()]),
                    sql: "INSERT INTO items VALUES (0, 'seed')".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
        // Hydration guarantees a file-backed actor, including when the native
        // size estimate keeps a newly-created database in memory.
        service.discard_local_state(&key).await.unwrap();
        let mut expected_count = 1i64;
        let mut expected_sum = 0i64;
        for (round, rows) in [(1i64, 5i64), (2, 300_000), (3, 5)] {
            service.execute(&space,"main",DuckDbRequest::Execute {
                schema:None,
                sql:format!("INSERT INTO items SELECT {round}*1000000+i, md5(i::VARCHAR) FROM range({rows}) t(i)"),
                params:vec![],
            },None,"tinycloud.duckdb/write".into(),false).await.unwrap();
            expected_count += rows;
            expected_sum += round * 1_000_000 * rows + rows * (rows - 1) / 2;
            let fresh = TempDir::new().unwrap();
            let reader = file_service(&fresh, repo.clone());
            let recovered=reader.execute(&space,"main",DuckDbRequest::Query {
                sql:"SELECT count(*),sum(id)::BIGINT,sum(CASE WHEN id=0 OR body=md5((id%1000000)::VARCHAR) THEN 1 ELSE 0 END)::BIGINT FROM items".into(),
                params:vec![],
            },None,"tinycloud.duckdb/read".into(),false).await;
            let _ = reader.discard_local_state(&key).await;
            let recovered = match recovered {
                Ok(result) => result,
                Err(error) => {
                    let _ = service.discard_local_state(&key).await;
                    panic!("acknowledged round {round} must recover from a fresh cache: {error:?}");
                }
            };
            let DuckDbResponse::Query(query) = recovered.response else {
                panic!("query required");
            };
            assert_eq!(
                query.rows,
                vec![vec![
                    DuckDbValue::Integer(expected_count),
                    DuckDbValue::Integer(expected_sum),
                    DuckDbValue::Integer(expected_count)
                ]]
            );
        }
        service.discard_local_state(&key).await.unwrap();
        let bytes = service.export(&space, "main").await.unwrap();
        let export_dir = TempDir::new().unwrap();
        let path = export_dir.path().join("recovered.duckdb");
        std::fs::write(&path, bytes).unwrap();
        let conn = storage::open_connection(Some(&path), "128MB").unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, expected_count);
    }
    #[tokio::test]
    async fn tc2990_wal_requires_both_checkpoint_length_and_cid() {
        let repo = artifact_repository().await;
        let source_cache = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        let space = test_space_id("wal-checkpoint-identity");
        let key = (space.to_string(), "main".to_string());
        let source = file_service(&source_cache, repo.clone());
        source
            .execute(
                &space,
                "main",
                DuckDbRequest::Execute {
                    schema: Some(vec!["CREATE TABLE items(id INTEGER)".into()]),
                    sql: "INSERT INTO items VALUES (1)".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
        source.discard_local_state(&key).await.unwrap();
        let service = file_service(&cache, repo.clone());
        service
            .execute(
                &space,
                "main",
                DuckDbRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO items VALUES (2)".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/write".into(),
                false,
            )
            .await
            .unwrap();
        let meta = repo
            .load_meta("duckdb", &space.to_string(), "main")
            .await
            .unwrap()
            .unwrap();
        assert!(
            meta.has_delta(),
            "a small write must retain the WAL fast path"
        );
        let handle = service.databases.get(&key).unwrap().clone();
        let wal = handle.wal().await.unwrap().unwrap();
        assert!(handle
            .wal_for_checkpoint(
                meta.checkpoint_size_bytes as u64 + 1,
                meta.checkpoint_content_hash.clone()
            )
            .await
            .unwrap()
            .is_none());
        let wrong = crate::hash::hash(b"different checkpoint")
            .to_cid(0x55)
            .to_string();
        assert!(handle
            .wal_for_checkpoint(meta.checkpoint_size_bytes as u64, wrong)
            .await
            .unwrap()
            .is_none());
        let verified = handle
            .wal_for_checkpoint(
                meta.checkpoint_size_bytes as u64,
                meta.checkpoint_content_hash,
            )
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            verified, wal,
            "failed identity checks must not checkpoint or truncate the WAL"
        );
        service.discard_local_state(&key).await.unwrap();
    }
    #[tokio::test]
    async fn postgres_chunked_duckdb_large_insert_recovers_owned_checkpoint() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_duckdb_large_insert_recovers_owned_checkpoint",
        )
        .await
        else {
            return;
        };
        let repo = Arc::new(
            SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(Some(
                crate::database_artifacts::chunks::ChunkLimits {
                    artifact_bytes: 64 * 1024 * 1024,
                    account_bytes: 256 * 1024 * 1024,
                },
            )),
        );
        let cache = TempDir::new().unwrap();
        let space = test_space_id("large-file-write-recovery");
        let key = (space.to_string(), "main".to_string());
        let service = file_service(&cache, repo.clone());
        service
            .execute(
                &space,
                "main",
                DuckDbRequest::Execute {
                    schema: Some(vec!["CREATE TABLE items(id BIGINT, body VARCHAR)".into()]),
                    sql: "INSERT INTO items VALUES (0, 'seed')".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
        // Hydration guarantees a file-backed actor, including when the native
        // size estimate keeps a newly-created database in memory.
        service.discard_local_state(&key).await.unwrap();
        let mut expected_count = 1i64;
        let mut expected_sum = 0i64;
        for (round, rows) in [(1i64, 5i64), (2, 300_000), (3, 5)] {
            service.execute(&space,"main",DuckDbRequest::Execute {
                schema:None,
                sql:format!("INSERT INTO items SELECT {round}*1000000+i, md5(i::VARCHAR) FROM range({rows}) t(i)"),
                params:vec![],
            },None,"tinycloud.duckdb/write".into(),false).await.unwrap();
            expected_count += rows;
            expected_sum += round * 1_000_000 * rows + rows * (rows - 1) / 2;
            let fresh = TempDir::new().unwrap();
            let reader = file_service(&fresh, repo.clone());
            let recovered=reader.execute(&space,"main",DuckDbRequest::Query {
                sql:"SELECT count(*),sum(id)::BIGINT,sum(CASE WHEN id=0 OR body=md5((id%1000000)::VARCHAR) THEN 1 ELSE 0 END)::BIGINT FROM items".into(),
                params:vec![],
            },None,"tinycloud.duckdb/read".into(),false).await;
            let _ = reader.discard_local_state(&key).await;
            let recovered = match recovered {
                Ok(result) => result,
                Err(error) => {
                    let _ = service.discard_local_state(&key).await;
                    panic!("acknowledged round {round} must recover from a fresh cache: {error:?}");
                }
            };
            let DuckDbResponse::Query(query) = recovered.response else {
                panic!("query required");
            };
            assert_eq!(
                query.rows,
                vec![vec![
                    DuckDbValue::Integer(expected_count),
                    DuckDbValue::Integer(expected_sum),
                    DuckDbValue::Integer(expected_count)
                ]]
            );
        }
        service.discard_local_state(&key).await.unwrap();
        let bytes = service.export(&space, "main").await.unwrap();
        let export_dir = TempDir::new().unwrap();
        let path = export_dir.path().join("recovered.duckdb");
        std::fs::write(&path, bytes).unwrap();
        let conn = storage::open_connection(Some(&path), "128MB").unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM items", [], |row| row.get(0))
            .unwrap();
        assert_eq!(count, expected_count);
    }

    fn write_request(sql: &str, schema: Option<&str>) -> DuckDbRequest {
        DuckDbRequest::Execute {
            schema: schema.map(|schema| vec![schema.to_string()]),
            sql: sql.into(),
            params: vec![],
        }
    }

    async fn query_rows(
        service: &DuckDbService,
        space: &SpaceId,
        sql: &str,
    ) -> Result<Vec<Vec<DuckDbValue>>, DuckDbError> {
        let result = service
            .execute(
                space,
                "main",
                DuckDbRequest::Query {
                    sql: sql.into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/read".into(),
                false,
            )
            .await?;
        let DuckDbResponse::Query(query) = result.response else {
            panic!("query required");
        };
        Ok(query.rows)
    }

    fn dir_entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .map(|entries| {
                entries
                    .filter_map(Result::ok)
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        names
    }

    fn chunked_repository(
        conn: &sea_orm::DatabaseConnection,
        artifact_bytes: u64,
    ) -> Arc<SeaOrmDatabaseArtifactRepository> {
        Arc::new(
            SeaOrmDatabaseArtifactRepository::new(conn.clone()).with_chunk_limits(Some(
                crate::database_artifacts::chunks::ChunkLimits {
                    artifact_bytes,
                    account_bytes: 128 << 20,
                },
            )),
        )
    }

    /// A valid DuckDB file of more than 1 MiB, written under the node's policy.
    fn large_duckdb_file() -> Vec<u8> {
        let scratch = TempDir::new().unwrap();
        let path = scratch.path().join("large.duckdb");
        {
            let conn = storage::open_connection(Some(&path), "128MB").unwrap();
            conn.execute_batch(
                "CREATE TABLE big AS SELECT i, md5(i::VARCHAR) AS s FROM range(200000) r(i); \
                 CHECKPOINT;",
            )
            .unwrap();
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.len() > 1 << 20);
        bytes
    }

    #[tokio::test]
    async fn duckdb_database_names_cannot_leave_the_cache_directory() {
        let root = TempDir::new().unwrap();
        let base = root.path().join("cache");
        std::fs::create_dir_all(&base).unwrap();
        let service = DuckDbService::new(
            base.to_string_lossy().into_owned(),
            0,
            300,
            "128MB".into(),
            artifact_repository().await,
        );
        let space = test_space_id("traversal");
        for name in ["../../escape", "..", "a/b", "a\\b", "", "x\0y", "../escape"] {
            let executed = service
                .execute(
                    &space,
                    name,
                    write_request(
                        "INSERT INTO t VALUES (1)",
                        Some("CREATE TABLE t(i INTEGER)"),
                    ),
                    None,
                    "tinycloud.duckdb/admin".into(),
                    false,
                )
                .await;
            assert!(
                matches!(executed, Err(DuckDbError::PermissionDenied(_))),
                "{name:?}: {executed:?}"
            );
            let imported = service.import_db(&space, name, b"x").await;
            assert!(
                matches!(imported, Err(DuckDbError::PermissionDenied(_))),
                "{name:?}: {imported:?}"
            );
        }
        assert_eq!(dir_entries(root.path()), vec!["cache".to_string()]);
        assert!(dir_entries(&base.join(space.to_string())).is_empty());
    }

    #[tokio::test]
    async fn duckdb_leftover_spill_directories_do_not_block_the_database() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let service = service(&cache, repo);
        let space = test_space_id("spill-leftover");
        let key = (space.to_string(), "main".to_string());
        service
            .execute(
                &space,
                "main",
                write_request(
                    "INSERT INTO t VALUES (1)",
                    Some("CREATE TABLE t(i INTEGER)"),
                ),
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
        service.discard_local_state(&key).await.unwrap();
        // What a killed process leaves: DuckDB's own spill directory, and one
        // an evicted actor had moved aside for deletion.
        let path = service.cache_path(&space, "main");
        let spill = PathBuf::from(format!("{}.tmp", path.display()));
        let aside = PathBuf::from(format!("{}.tmp.999999999.0", path.display()));
        for dir in [&spill, &aside] {
            std::fs::create_dir_all(dir).unwrap();
            std::fs::write(dir.join("duckdb_temp_storage-0.tmp"), b"x").unwrap();
        }
        assert_eq!(
            query_rows(&service, &space, "SELECT count(*) FROM t")
                .await
                .unwrap(),
            vec![vec![DuckDbValue::Integer(1)]]
        );
        assert!(!spill.exists() && !aside.exists());

        std::fs::create_dir_all(&spill).unwrap();
        std::fs::write(spill.join("duckdb_temp_storage-0.tmp"), b"x").unwrap();
        service.discard_local_state(&key).await.unwrap();
        assert!(dir_entries(path.parent().unwrap()).is_empty());
    }

    #[tokio::test]
    async fn duckdb_import_that_cannot_be_finalized_leaves_no_staging_file() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let service = service(&cache, repo.clone());
        let space = test_space_id("import-finalize");
        let path = service.cache_path(&space, "main");
        // A non-empty directory at the final path makes the rename fail.
        std::fs::create_dir_all(path.join("blocker")).unwrap();
        let imported = service
            .import_db(&space, "main", &large_duckdb_file())
            .await;
        assert!(
            matches!(imported, Err(DuckDbError::ImportError(_))),
            "{imported:?}"
        );
        assert_eq!(dir_entries(path.parent().unwrap()), vec!["main.duckdb"]);
        assert!(repo
            .load_meta("duckdb", &space.to_string(), "main")
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn postgres_chunked_duckdb_refused_and_invalid_imports_leave_no_files() {
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_duckdb_refused_and_invalid_imports_leave_no_files",
        )
        .await
        else {
            return;
        };
        let bytes = large_duckdb_file();
        let repo = chunked_repository(&fixture.conn, 1 << 20);
        let cache = TempDir::new().unwrap();
        let service = service(&cache, repo.clone());
        let space = test_space_id("chunked-import-refused");
        let dir = cache.path().join(space.to_string());

        let refused = service.import_db(&space, "main", &bytes).await;
        assert!(
            matches!(refused, Err(DuckDbError::DatabaseSizeLimit)),
            "{refused:?}"
        );
        assert!(dir_entries(&dir).is_empty(), "{:?}", dir_entries(&dir));
        assert!(repo
            .load_meta("duckdb", &space.to_string(), "main")
            .await
            .unwrap()
            .is_none());

        let invalid = service
            .import_db(&space, "main", b"not a duckdb file")
            .await;
        assert!(
            matches!(invalid, Err(DuckDbError::ImportError(_))),
            "{invalid:?}"
        );
        assert!(dir_entries(&dir).is_empty(), "{:?}", dir_entries(&dir));

        assert!(query_rows(&service, &space, "SELECT count(*) FROM big")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn postgres_chunked_duckdb_substituted_part_is_refused_before_open() {
        use sea_orm::{ConnectionTrait, DbBackend, Statement};
        let Some(fixture) = crate::test_support::PostgresTestSchema::new(
            "postgres_chunked_duckdb_substituted_part_is_refused_before_open",
        )
        .await
        else {
            return;
        };
        let repo = chunked_repository(&fixture.conn, 64 << 20);
        let cache = TempDir::new().unwrap();
        let service = service(&cache, repo.clone());
        let victim = test_space_id("victim");
        let other = test_space_id("other");
        for (space, value) in [(&victim, "victim-secret"), (&other, "other-secret")] {
            service
                .execute(
                    space,
                    "main",
                    write_request(
                        &format!("INSERT INTO t VALUES ('{value}')"),
                        Some("CREATE TABLE t(v VARCHAR)"),
                    ),
                    None,
                    "tinycloud.duckdb/admin".into(),
                    false,
                )
                .await
                .unwrap();
        }
        let victim_meta = repo
            .load_meta("duckdb", &victim.to_string(), "main")
            .await
            .unwrap()
            .unwrap();
        let other_meta = repo
            .load_meta("duckdb", &other.to_string(), "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            victim_meta.checkpoint_size_bytes,
            other_meta.checkpoint_size_bytes
        );
        let key = (victim.to_string(), "main".to_string());
        service.discard_local_state(&key).await.unwrap();

        // Storage-level substitution: the victim's chunks get the other
        // tenant's bytes of the same length.
        fixture
            .conn
            .execute_unprepared("ALTER TABLE artifact_chunk DISABLE TRIGGER USER")
            .await
            .unwrap();
        let substituted = fixture
            .conn
            .execute(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE artifact_chunk v SET payload = o.payload \
                 FROM database_artifact dv, database_artifact do_, artifact_chunk o \
                 WHERE dv.space = $1 AND dv.name = 'main' AND v.part_id = dv.checkpoint_part_id \
                 AND do_.space = $2 AND do_.name = 'main' \
                 AND o.part_id = do_.checkpoint_part_id AND o.ordinal = v.ordinal",
                [victim.to_string().into(), other.to_string().into()],
            ))
            .await
            .unwrap()
            .rows_affected();
        fixture
            .conn
            .execute_unprepared("ALTER TABLE artifact_chunk ENABLE TRIGGER USER")
            .await
            .unwrap();
        assert!(substituted >= 1);

        let outcome = query_rows(&service, &victim, "SELECT v FROM t").await;
        assert!(
            matches!(&outcome, Err(DuckDbError::Internal(message)) if message.contains("content hash")),
            "{outcome:?}"
        );
        let dir = cache.path().join(victim.to_string());
        assert!(dir_entries(&dir).is_empty(), "{:?}", dir_entries(&dir));
        assert!(!service.databases.contains_key(&key));
    }

    /// Free space the test sets; a node's real `statvfs` cannot be steered.
    struct FakeFree(std::sync::atomic::AtomicU64);

    impl crate::sql::durability::FreeSpace for FakeFree {
        fn free_bytes(&self, _: &Path) -> std::io::Result<u64> {
            Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
        }
    }

    fn disk_policy(free: &Arc<FakeFree>, min_free_bytes: u64) -> DuckDbDiskPolicy {
        DuckDbDiskPolicy {
            min_free_bytes,
            free_space: free.clone(),
            ..Default::default()
        }
    }

    async fn count_rows(service: &DuckDbService, space: &SpaceId) -> Vec<Vec<DuckDbValue>> {
        query_rows(service, space, "SELECT count(*) FROM t")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn duckdb_write_short_of_headroom_is_refused_before_it_runs() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let free = Arc::new(FakeFree((64u64 << 20).into()));
        let service =
            file_service(&cache, repo.clone()).with_disk_policy(disk_policy(&free, 8 << 20));
        let space = test_space_id("headroom-refused");
        service
            .execute(
                &space,
                "main",
                write_request(
                    "INSERT INTO t VALUES (1)",
                    Some("CREATE TABLE t(i INTEGER)"),
                ),
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
        let saved = repo
            .load_meta("duckdb", &space.to_string(), "main")
            .await
            .unwrap()
            .unwrap()
            .revision;

        free.0
            .store((8 << 20) - 1, std::sync::atomic::Ordering::SeqCst);
        let refused = service
            .execute(
                &space,
                "main",
                write_request("INSERT INTO t VALUES (2)", None),
                None,
                "tinycloud.duckdb/write".into(),
                false,
            )
            .await;
        assert!(
            matches!(refused, Err(DuckDbError::DiskHeadroom)),
            "{refused:?}"
        );
        let imported = service
            .import_db(&space, "main", &large_duckdb_file())
            .await;
        assert!(
            matches!(imported, Err(DuckDbError::DiskHeadroom)),
            "{imported:?}"
        );

        // Reads still run while the disk is short; nothing was applied or saved.
        assert_eq!(
            count_rows(&service, &space).await,
            vec![vec![DuckDbValue::Integer(1)]]
        );
        let meta = repo
            .load_meta("duckdb", &space.to_string(), "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.revision, saved);
        assert_eq!(service.disk.budget.reserved(), 0);

        free.0.store(64 << 20, std::sync::atomic::Ordering::SeqCst);
        service
            .execute(
                &space,
                "main",
                write_request("INSERT INTO t VALUES (2)", None),
                None,
                "tinycloud.duckdb/write".into(),
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            count_rows(&service, &space).await,
            vec![vec![DuckDbValue::Integer(2)]]
        );
    }

    #[tokio::test]
    async fn duckdb_reservation_counts_other_databases_in_flight() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let free = Arc::new(FakeFree((64u64 << 20).into()));
        let policy = disk_policy(&free, 8 << 20);
        let service = file_service(&cache, repo).with_disk_policy(policy.clone());
        let space = test_space_id("headroom-shared");
        // Another database (SQL or DuckDB) holds most of the free space.
        policy
            .budget
            .reserve("sql:other", 60 << 20, 0, free.as_ref(), cache.path(), 0)
            .unwrap();
        let refused = service
            .execute(
                &space,
                "main",
                write_request(
                    "INSERT INTO t VALUES (1)",
                    Some("CREATE TABLE t(i INTEGER)"),
                ),
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await;
        assert!(
            matches!(refused, Err(DuckDbError::DiskHeadroom)),
            "{refused:?}"
        );
        policy.budget.release("sql:other");
        service
            .execute(
                &space,
                "main",
                write_request(
                    "INSERT INTO t VALUES (1)",
                    Some("CREATE TABLE t(i INTEGER)"),
                ),
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn duckdb_statement_is_stopped_when_the_disk_runs_short_while_it_runs() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let free = Arc::new(FakeFree((64u64 << 20).into()));
        let service =
            file_service(&cache, repo.clone()).with_disk_policy(disk_policy(&free, 8 << 20));
        let space = test_space_id("headroom-watch");
        service
            .execute(
                &space,
                "main",
                write_request("INSERT INTO t VALUES (1)", Some("CREATE TABLE t(i BIGINT)")),
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
        let saved = repo
            .load_meta("duckdb", &space.to_string(), "main")
            .await
            .unwrap()
            .unwrap()
            .revision;

        // The disk runs short once the statement is under way.
        let shrink = {
            let free = free.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                free.0.store(0, std::sync::atomic::Ordering::SeqCst);
            })
        };
        let stopped = service
            .execute(
                &space,
                "main",
                write_request(
                    "INSERT INTO t SELECT i FROM range(2000000000) r(i) WHERE md5(i::VARCHAR) <> ''",
                    None,
                ),
                None,
                "tinycloud.duckdb/write".into(),
                false,
            )
            .await;
        shrink.await.unwrap();
        assert!(
            matches!(stopped, Err(DuckDbError::DiskHeadroom)),
            "{stopped:?}"
        );

        free.0.store(64 << 20, std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            count_rows(&service, &space).await,
            vec![vec![DuckDbValue::Integer(1)]]
        );
        let meta = repo
            .load_meta("duckdb", &space.to_string(), "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.revision, saved);
    }

    #[tokio::test]
    async fn duckdb_statement_past_the_spill_limit_is_the_disk() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let service = DuckDbService::new(
            cache.path().to_string_lossy().into_owned(),
            0,
            300,
            "16MB".into(),
            repo,
        )
        .with_disk_policy(DuckDbDiskPolicy {
            max_temp_directory_bytes: 1 << 20,
            ..Default::default()
        });
        let space = test_space_id("spill-limit");
        // 2M rows under a 16 MB memory limit must spill, past the 1 MiB limit.
        let big = service
            .execute(
                &space,
                "main",
                write_request(
                    "INSERT INTO t SELECT i, md5(i::VARCHAR) FROM range(2000000) r(i) ORDER BY 2",
                    Some("CREATE TABLE t(i BIGINT, s VARCHAR)"),
                ),
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await;
        assert!(matches!(big, Err(DuckDbError::DiskHeadroom)), "{big:?}");
        // The database stays usable for work that fits.
        service
            .execute(
                &space,
                "main",
                write_request(
                    "INSERT INTO t SELECT i, md5(i::VARCHAR) FROM range(1000) r(i)",
                    Some("CREATE TABLE IF NOT EXISTS t(i BIGINT, s VARCHAR)"),
                ),
                None,
                "tinycloud.duckdb/admin".into(),
                false,
            )
            .await
            .unwrap();
        let rows = query_rows(&service, &space, "SELECT count(*) FROM t")
            .await
            .unwrap();
        assert_eq!(rows, vec![vec![DuckDbValue::Integer(1000)]]);
    }

    #[tokio::test]
    async fn duckdb_startup_sweep_removes_leftovers_and_keeps_cache_files() {
        let cache = TempDir::new().unwrap();
        let service = service(&cache, artifact_repository().await);
        let dir = cache.path().join("space-a");
        std::fs::create_dir_all(dir.join("main.duckdb.tmp")).unwrap();
        std::fs::write(dir.join("main.duckdb.tmp").join("spill"), b"x").unwrap();
        std::fs::create_dir_all(dir.join("main.duckdb.tmp.4242.7")).unwrap();
        for name in [
            "main.duckdb",
            "main.duckdb.wal",
            "main.duckdb.tmp.4242.8",
            "main.duckdb.wal.tmp.4242.9",
            "main.duckdb.tmp.notapid.1",
            "notes.db",
        ] {
            std::fs::write(dir.join(name), b"x").unwrap();
        }
        assert_eq!(service.sweep_stale_cache_files().await, 4);
        assert_eq!(
            dir_entries(&dir),
            vec![
                "main.duckdb",
                "main.duckdb.tmp.notapid.1",
                "main.duckdb.wal",
                "notes.db"
            ]
        );
    }

    /// A link in place of a space directory is never descended into.
    #[cfg(unix)]
    #[tokio::test]
    async fn duckdb_startup_sweep_does_not_follow_a_linked_space() {
        let cache = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let service = service(&cache, artifact_repository().await);
        std::fs::create_dir_all(outside.path().join("x.duckdb.tmp")).unwrap();
        std::fs::write(outside.path().join("x.duckdb.tmp.1.2"), b"x").unwrap();
        std::os::unix::fs::symlink(outside.path(), cache.path().join("space-link")).unwrap();
        assert_eq!(service.sweep_stale_cache_files().await, 0);
        assert_eq!(
            dir_entries(outside.path()),
            vec!["x.duckdb.tmp", "x.duckdb.tmp.1.2"]
        );
    }

    mod headroom {
        use super::*;
        use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
        use std::time::Duration;

        const MIN: u64 = 8 << 20;
        const PLENTY: u64 = 64 << 20;

        async fn exec(
            service: &DuckDbService,
            space: &SpaceId,
            db: &str,
            request: DuckDbRequest,
        ) -> Result<DuckDbExecutionResult, DuckDbError> {
            service
                .execute(
                    space,
                    db,
                    request,
                    None,
                    "tinycloud.duckdb/admin".into(),
                    false,
                )
                .await
        }

        async fn count(service: &DuckDbService, space: &SpaceId, db: &str, sql: &str) -> i64 {
            let result = service
                .execute(
                    space,
                    db,
                    DuckDbRequest::Query {
                        sql: sql.into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.duckdb/read".into(),
                    false,
                )
                .await
                .unwrap();
            let DuckDbResponse::Query(rows) = result.response else {
                panic!("not a query response");
            };
            match &rows.rows[0][0] {
                DuckDbValue::Integer(n) => *n,
                other => panic!("{other:?}"),
            }
        }

        fn statement(sql: &str) -> DuckDbStatement {
            DuckDbStatement {
                sql: sql.into(),
                params: vec![],
            }
        }

        fn short_after(free: &Arc<FakeFree>, after: Duration) -> std::thread::JoinHandle<()> {
            let free = free.clone();
            std::thread::spawn(move || {
                std::thread::sleep(after);
                free.0.store(0, SeqCst);
            })
        }

        /// A repository with chunked artifacts on: databases are file-backed
        /// from their first write, as with the flag on.
        async fn chunked(
            test: &str,
        ) -> Option<(
            crate::test_support::PostgresTestSchema,
            Arc<SeaOrmDatabaseArtifactRepository>,
        )> {
            let fixture = crate::test_support::PostgresTestSchema::new(test).await?;
            let repo = Arc::new(
                SeaOrmDatabaseArtifactRepository::new(fixture.conn.clone()).with_chunk_limits(
                    Some(crate::database_artifacts::chunks::ChunkLimits {
                        artifact_bytes: 1 << 30,
                        account_bytes: 4 << 30,
                    }),
                ),
            );
            Some((fixture, repo))
        }

        fn chunked_service(
            cache: &TempDir,
            repo: Arc<SeaOrmDatabaseArtifactRepository>,
        ) -> DuckDbService {
            DuckDbService::new(
                cache.path().to_string_lossy().into_owned(),
                u64::MAX,
                300,
                "1GB".into(),
                repo,
            )
        }

        /// A write sent as `query` is held to the floor like any other write.
        #[tokio::test]
        async fn postgres_duckdb_query_shaped_write_is_held_to_the_floor() {
            let Some((_fixture, repo)) = chunked("postgres_duckdb_query_shaped_write_floor").await
            else {
                return;
            };
            let cache = TempDir::new().unwrap();
            let free = Arc::new(FakeFree(PLENTY.into()));
            let service =
                chunked_service(&cache, repo.clone()).with_disk_policy(disk_policy(&free, MIN));
            let space = test_space_id("query-shaped-write");
            exec(
                &service,
                &space,
                "main",
                write_request("INSERT INTO t VALUES (1)", Some("CREATE TABLE t(i BIGINT)")),
            )
            .await
            .unwrap();

            free.0.store(0, SeqCst);
            let query = exec(
                &service,
                &space,
                "main",
                DuckDbRequest::Query {
                    sql: "INSERT INTO t VALUES (3)".into(),
                    params: vec![],
                },
            )
            .await;
            assert!(
                matches!(query, Err(DuckDbError::DiskHeadroom)),
                "{:?}",
                query.map(|_| ())
            );

            // Free space running out while a long query-shaped write runs.
            free.0.store(PLENTY, SeqCst);
            let flip = short_after(&free, Duration::from_millis(200));
            let long = exec(
                &service,
                &space,
                "main",
                DuckDbRequest::Query {
                    sql: "INSERT INTO t SELECT i FROM range(8000000) r(i) WHERE md5(i::VARCHAR) <> ''"
                        .into(),
                    params: vec![],
                },
            )
            .await;
            flip.join().unwrap();
            assert!(
                matches!(long, Err(DuckDbError::DiskHeadroom)),
                "{:?}",
                long.map(|_| ())
            );

            free.0.store(PLENTY, SeqCst);
            assert_eq!(
                count(&service, &space, "main", "SELECT count(*) FROM t").await,
                1
            );
            let fresh = TempDir::new().unwrap();
            let durable = chunked_service(&fresh, repo);
            assert_eq!(
                count(&durable, &space, "main", "SELECT count(*) FROM t").await,
                1
            );
        }

        /// An admin's `PREPARE … AS INSERT` and `EXECUTE`, sent as queries,
        /// are held to the floor like the INSERT itself: the parser calls
        /// both read-only, but neither is a plain query.
        #[tokio::test]
        async fn postgres_duckdb_prepared_insert_is_held_to_the_floor() {
            let Some((_fixture, repo)) = chunked("postgres_duckdb_prepared_insert_floor").await
            else {
                return;
            };
            let cache = TempDir::new().unwrap();
            let free = Arc::new(FakeFree(PLENTY.into()));
            let service = chunked_service(&cache, repo).with_disk_policy(disk_policy(&free, MIN));
            let space = test_space_id("prepared-insert");
            exec(
                &service,
                &space,
                "main",
                write_request(
                    "INSERT INTO t VALUES ('x')",
                    Some("CREATE TABLE t(s VARCHAR)"),
                ),
            )
            .await
            .unwrap();
            let query = |sql: &str| DuckDbRequest::Query {
                sql: sql.into(),
                params: vec![],
            };
            free.0.store(0, SeqCst);
            let prepare = exec(
                &service,
                &space,
                "main",
                query("PREPARE grow AS INSERT INTO t SELECT md5(i::VARCHAR) FROM range(1000) r(i)"),
            )
            .await;
            assert!(
                matches!(prepare, Err(DuckDbError::DiskHeadroom)),
                "{:?}",
                prepare.map(|_| ())
            );
            free.0.store(PLENTY, SeqCst);
            exec(
                &service,
                &space,
                "main",
                query("PREPARE grow AS INSERT INTO t SELECT md5(i::VARCHAR) FROM range(1000) r(i)"),
            )
            .await
            .unwrap();
            free.0.store(0, SeqCst);
            let execute = exec(&service, &space, "main", query("EXECUTE grow")).await;
            assert!(
                matches!(execute, Err(DuckDbError::DiskHeadroom)),
                "{:?}",
                execute.map(|_| ())
            );
            free.0.store(PLENTY, SeqCst);
            assert_eq!(
                count(&service, &space, "main", "SELECT count(*) FROM t").await,
                1
            );
        }

        /// A request refused for headroom keeps nothing: not the statements of
        /// its batch that ran before the refusal, locally or after the next
        /// saved write.
        #[tokio::test]
        async fn duckdb_headroom_refusal_keeps_nothing_from_the_request() {
            let repo = artifact_repository().await;
            let cache = TempDir::new().unwrap();
            let free = Arc::new(FakeFree(PLENTY.into()));
            let service =
                file_service(&cache, repo.clone()).with_disk_policy(disk_policy(&free, MIN));
            let space = test_space_id("headroom-keeps-nothing");
            exec(
                &service,
                &space,
                "main",
                write_request(
                    "CREATE TABLE m(k VARCHAR)",
                    Some("CREATE TABLE t(i BIGINT)"),
                ),
            )
            .await
            .unwrap();
            let flip = short_after(&free, Duration::from_millis(300));
            let refused = exec(
                &service,
                &space,
                "main",
                DuckDbRequest::Batch {
                    statements: vec![
                        statement("INSERT INTO m VALUES ('before-the-refusal')"),
                        statement(
                            "INSERT INTO t SELECT i FROM range(2000000000) r(i) WHERE md5(i::VARCHAR) <> ''",
                        ),
                    ],
                    transactional: false,
                },
            )
            .await;
            flip.join().unwrap();
            free.0.store(PLENTY, SeqCst);
            assert!(
                matches!(refused, Err(DuckDbError::DiskHeadroom)),
                "{:?}",
                refused.map(|_| ())
            );
            let kept = "SELECT count(*) FROM m WHERE k = 'before-the-refusal'";
            assert_eq!(count(&service, &space, "main", kept).await, 0);
            exec(
                &service,
                &space,
                "main",
                write_request("INSERT INTO m VALUES ('next')", None),
            )
            .await
            .unwrap();
            let fresh = TempDir::new().unwrap();
            let durable = file_service(&fresh, repo);
            assert_eq!(count(&durable, &space, "main", kept).await, 0);
            assert_eq!(
                count(&durable, &space, "main", "SELECT count(*) FROM m").await,
                1
            );
        }

        /// Free space that runs short from a given watcher reading on, so a
        /// refusal can be placed late in a write, around its COMMIT.
        struct ShortFromReading {
            readings: AtomicU64,
            short_from: AtomicU64,
        }

        impl crate::sql::durability::FreeSpace for ShortFromReading {
            fn free_bytes(&self, _: &Path) -> std::io::Result<u64> {
                let n = self.readings.fetch_add(1, SeqCst) + 1;
                Ok(if n >= self.short_from.load(SeqCst) {
                    0
                } else {
                    1 << 36
                })
            }
        }

        /// A transactional batch refused near or during its COMMIT is never
        /// kept: an answer of 507 means the change is in neither the local
        /// copy nor the durable artifact.
        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn postgres_duckdb_batch_refused_around_commit_is_not_kept() {
            let Some((_fixture, repo)) = chunked("postgres_duckdb_batch_refused_commit").await
            else {
                return;
            };
            let cache = TempDir::new().unwrap();
            let free = Arc::new(ShortFromReading {
                readings: AtomicU64::new(0),
                short_from: AtomicU64::new(u64::MAX),
            });
            let service =
                chunked_service(&cache, repo.clone()).with_disk_policy(DuckDbDiskPolicy {
                    min_free_bytes: MIN,
                    free_space: free.clone(),
                    ..Default::default()
                });
            let space = test_space_id("batch-refused-commit");
            let setup = |db: String| {
                let (service, space) = (&service, &space);
                async move {
                    exec(
                        service,
                        space,
                        &db,
                        DuckDbRequest::Batch {
                            statements: vec![
                                statement("CREATE TABLE t(i BIGINT, s VARCHAR)"),
                                statement("CREATE TABLE m(k VARCHAR)"),
                                statement(
                                    "INSERT INTO t SELECT i, md5(i::VARCHAR) FROM range(1000000) r(i)",
                                ),
                            ],
                            transactional: false,
                        },
                    )
                    .await
                    .unwrap();
                }
            };
            let batch = |marker: &str| DuckDbRequest::Batch {
                statements: vec![
                    statement(&format!("INSERT INTO m VALUES ('{marker}')")),
                    statement(&format!("UPDATE t SET s = md5(s || '{marker}')")),
                ],
                transactional: true,
            };
            // How many free-space readings one batch takes.
            setup("calibrate".into()).await;
            let before = free.readings.load(SeqCst);
            exec(&service, &space, "calibrate", batch("calibrate"))
                .await
                .unwrap();
            let readings = free.readings.load(SeqCst) - before;
            let mut kept = Vec::new();
            for round in 0..10u64 {
                let db = format!("round{round}");
                free.short_from.store(u64::MAX, SeqCst);
                setup(db.clone()).await;
                let marker = format!("x{round}");
                let start = free.readings.load(SeqCst);
                free.short_from.store(
                    start + readings.saturating_sub(1 + 2 * round).max(2),
                    SeqCst,
                );
                let result = exec(&service, &space, &db, batch(&marker)).await;
                free.short_from.store(u64::MAX, SeqCst);
                let marked = format!("SELECT count(*) FROM m WHERE k = '{marker}'");
                let local = count(&service, &space, &db, &marked).await;
                if result.is_err() {
                    exec(
                        &service,
                        &space,
                        &db,
                        write_request("INSERT INTO m VALUES ('next')", None),
                    )
                    .await
                    .unwrap();
                    let fresh = TempDir::new().unwrap();
                    let durable =
                        count(&chunked_service(&fresh, repo.clone()), &space, &db, &marked).await;
                    if local != 0 || durable != 0 {
                        kept.push((round, local, durable));
                    }
                } else if local != 1 {
                    kept.push((round, local, -1));
                }
            }
            assert!(
                kept.is_empty(),
                "refused batches kept, or accepted batches lost: {kept:?}"
            );
        }

        /// A shortfall first seen between two DuckDB calls still stops the
        /// statement that follows: DuckDB clears an interrupt when a query
        /// starts, so the watcher keeps interrupting.
        #[test]
        fn duckdb_shortfall_between_calls_still_stops_the_next_statement() {
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("d.duckdb");
            let conn = storage::open_connection(Some(&path), "512MB").unwrap();
            let free = Arc::new(FakeFree(0.into()));
            let result = disk_policy(&free, MIN).watch("duckdb:test/d", &path, &conn, true, || {
                // Rust-side work between two DuckDB calls, where the first
                // reading lands.
                std::thread::sleep(Duration::from_millis(120));
                conn.execute_batch(
                    "CREATE TABLE big AS SELECT i, md5(i::VARCHAR) s FROM range(3000000) r(i)",
                )
                .map_err(|error| DuckDbError::DuckDb(error.to_string()))
            });
            assert!(
                matches!(result, Err(DuckDbError::DiskHeadroom)),
                "{result:?}"
            );
        }

        /// A write reserves its database's local size against the node-wide
        /// budget: while another operation holds room, a write that would
        /// leave less than the floor is refused before it runs, and the same
        /// write runs once that room is released. Nothing stays reserved.
        #[tokio::test]
        async fn postgres_duckdb_write_reserves_its_database_size() {
            let Some((_fixture, repo)) = chunked("postgres_duckdb_write_reserves_size").await
            else {
                return;
            };
            let cache = TempDir::new().unwrap();
            let free = Arc::new(FakeFree(PLENTY.into()));
            let policy = disk_policy(&free, MIN);
            let service = chunked_service(&cache, repo).with_disk_policy(policy.clone());
            let space = test_space_id("write-reserves-size");
            exec(
                &service,
                &space,
                "main",
                write_request(
                    "INSERT INTO t SELECT i, md5(i::VARCHAR) FROM range(200000) r(i)",
                    Some("CREATE TABLE t(i BIGINT, s VARCHAR)"),
                ),
            )
            .await
            .unwrap();
            let dir = cache.path().join(space.to_string());
            let size: u64 = ["", ".wal"]
                .iter()
                .map(|ext| {
                    std::fs::metadata(dir.join(format!("main.duckdb{ext}")))
                        .map(|m| m.len())
                        .unwrap_or(0)
                })
                .sum();
            assert!(size > 0, "the database is not file-backed");
            // Room above the floor for one database of this size, not two.
            free.0.store(MIN + size + size / 2, SeqCst);
            let in_flight = policy
                .reserve("duckdb:other/in-flight", size, &dir)
                .unwrap()
                .expect("the check is on");
            let small_write = || write_request("INSERT INTO t VALUES (-1, 'x')", None);
            let refused = exec(&service, &space, "main", small_write()).await;
            assert!(
                matches!(refused, Err(DuckDbError::DiskHeadroom)),
                "{:?}",
                refused.map(|_| ())
            );
            drop(in_flight);
            exec(&service, &space, "main", small_write()).await.unwrap();
            assert_eq!(policy.budget.reserved(), 0);
        }
    }
}

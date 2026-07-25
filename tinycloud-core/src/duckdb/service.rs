use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use dashmap::DashMap;
use tinycloud_auth::resource::SpaceId;

use crate::database_artifacts::{DatabaseArtifactError, DatabaseArtifactRepository};

use super::{
    caveats::DuckDbCaveats,
    database::{spawn_actor, DatabaseHandle},
    storage,
    types::*,
};

const MAX_WAL_DELTA_BYTES: usize = 8 * 1024 * 1024;

pub struct DuckDbService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    base_path: String,
    memory_threshold: u64,
    idle_timeout_secs: u64,
    max_memory_per_connection: String,
    artifact_repository: Arc<dyn DatabaseArtifactRepository>,
}

fn validate_db_name(name: &str) -> Result<(), DuckDbError> {
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
            base_path,
            memory_threshold,
            idle_timeout_secs,
            max_memory_per_connection,
            artifact_repository,
        }
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
        validate_db_name(db_name)?;

        let key = (space.to_string(), db_name.to_string());
        let handle = self.handle(space, db_name).await?;

        let result = handle
            .execute(request, caveats, ability, arrow_format)
            .await?;

        if !result.write_targets.is_empty() {
            if let Err(e) = self.persist_write(space, db_name, &handle).await {
                let _ = self.discard_local_state(&key).await;
                return Err(e);
            }
        }

        Ok(result)
    }

    pub async fn export(&self, space: &SpaceId, db_name: &str) -> Result<Vec<u8>, DuckDbError> {
        validate_db_name(db_name)?;

        let key = (space.to_string(), db_name.to_string());

        // If there's a live actor, route through it (handles both in-memory and file-backed)
        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            return self.checkpoint(space, db_name, &handle).await;
        }

        if self
            .artifact_repository
            .load("duckdb", &space.to_string(), db_name)
            .await
            .map_err(artifact_error_to_duckdb)?
            .is_none()
        {
            return Err(DuckDbError::DatabaseNotFound);
        }
        let handle = self.handle(space, db_name).await?;
        self.checkpoint(space, db_name, &handle).await
    }

    pub async fn import_db(
        &self,
        space: &SpaceId,
        db_name: &str,
        data: &[u8],
    ) -> Result<(), DuckDbError> {
        validate_db_name(db_name)?;

        let dir = std::path::PathBuf::from(&self.base_path).join(space.to_string());
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| DuckDbError::Internal(e.to_string()))?;

        let final_path = dir.join(format!("{}.duckdb", db_name));
        let temp_path = dir.join(format!("{}.duckdb.tmp", db_name));

        // Write to temp file first
        tokio::fs::write(&temp_path, data)
            .await
            .map_err(|e| DuckDbError::ImportError(e.to_string()))?;

        // Validate the temp file by opening it with DuckDB and applying security settings
        let temp_path_clone = temp_path.clone();
        let max_memory = self.max_memory_per_connection.clone();
        let valid = tokio::task::spawn_blocking(move || -> Result<(), DuckDbError> {
            let conn = duckdb::Connection::open(&temp_path_clone)
                .map_err(|e| DuckDbError::ImportError(format!("Invalid DuckDB file: {}", e)))?;
            storage::apply_security_settings(&conn, &max_memory)?;
            conn.execute_batch("SELECT 1").map_err(|e| {
                DuckDbError::ImportError(format!("Database validation failed: {}", e))
            })?;
            Ok(())
        })
        .await
        .map_err(|e| DuckDbError::Internal(format!("Validation task failed: {}", e)))?;

        if let Err(e) = valid {
            // Clean up temp file on validation failure
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(e);
        }

        // Rename temp to final
        tokio::fs::rename(&temp_path, &final_path)
            .await
            .map_err(|e| DuckDbError::ImportError(format!("Failed to finalize import: {}", e)))?;

        // Remove the existing handle so the next access reopens the database from the new file
        let key = (space.to_string(), db_name.to_string());
        self.databases.remove(&key);

        if let Err(e) = self
            .artifact_repository
            .save("duckdb", &space.to_string(), db_name, data.to_vec())
            .await
        {
            let _ = self.discard_local_state(&key).await;
            return Err(artifact_error_to_duckdb(e));
        }

        Ok(())
    }

    pub fn db_name_from_path(path: Option<&str>) -> String {
        path.map(|p| {
            let name = p.split('/').next_back().unwrap_or("default");
            if validate_db_name(name).is_err() {
                "default".to_string()
            } else {
                name.to_string()
            }
        })
        .unwrap_or_else(|| "default".to_string())
    }

    async fn handle(&self, space: &SpaceId, db_name: &str) -> Result<DatabaseHandle, DuckDbError> {
        let key = (space.to_string(), db_name.to_string());
        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            return Ok(handle);
        }

        self.hydrate_cache(space, db_name).await?;

        Ok(self
            .databases
            .entry(key)
            .or_insert_with(|| {
                spawn_actor(
                    space.to_string(),
                    db_name.to_string(),
                    self.base_path.clone(),
                    self.memory_threshold,
                    self.idle_timeout_secs,
                    self.max_memory_per_connection.clone(),
                    self.databases.clone(),
                )
            })
            .clone())
    }

    async fn hydrate_cache(&self, space: &SpaceId, db_name: &str) -> Result<(), DuckDbError> {
        let cache_path = self.cache_path(space, db_name);
        match self
            .artifact_repository
            .load("duckdb", &space.to_string(), db_name)
            .await
            .map_err(artifact_error_to_duckdb)?
        {
            Some(artifact) => {
                remove_duckdb_cache_files(&cache_path).await?;
                write_cache_file(&cache_path, &artifact.payload).await?;
                if let Some(delta) = artifact.delta_payload {
                    write_cache_file(&duckdb_wal_path(&cache_path), &delta).await?;
                }
                Ok(())
            }
            None => remove_duckdb_cache_files(&cache_path).await,
        }
    }

    fn cache_path(&self, space: &SpaceId, db_name: &str) -> PathBuf {
        PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.duckdb", db_name))
    }

    async fn discard_local_state(&self, key: &(String, String)) -> Result<(), DuckDbError> {
        self.databases.remove(key);
        let cache_path = PathBuf::from(&self.base_path)
            .join(&key.0)
            .join(format!("{}.duckdb", key.1));
        remove_duckdb_cache_files(&cache_path).await
    }

    async fn persist_write(
        &self,
        space: &SpaceId,
        db_name: &str,
        handle: &DatabaseHandle,
    ) -> Result<(), DuckDbError> {
        if let Some(wal) = handle
            .wal()
            .await?
            .filter(|wal| wal.len() < MAX_WAL_DELTA_BYTES)
        {
            match self
                .artifact_repository
                .save_delta("duckdb", &space.to_string(), db_name, wal)
                .await
            {
                Ok(saved) => {
                    tracing::info!(
                        service = "duckdb",
                        space = %space,
                        db = db_name,
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

        self.checkpoint(space, db_name, handle).await.map(|_| ())
    }

    async fn checkpoint(
        &self,
        space: &SpaceId,
        db_name: &str,
        handle: &DatabaseHandle,
    ) -> Result<Vec<u8>, DuckDbError> {
        let payload = handle.export().await?;
        let bytes = payload.len();
        let saved = self
            .artifact_repository
            .save("duckdb", &space.to_string(), db_name, payload.clone())
            .await
            .map_err(artifact_error_to_duckdb)?;
        tracing::info!(
            service = "duckdb",
            space = %space,
            db = db_name,
            mode = "checkpoint",
            bytes,
            logical_bytes = saved.size_bytes,
            revision = saved.revision,
            "Persisted database checkpoint"
        );
        Ok(payload)
    }
}

async fn write_cache_file(path: &Path, payload: &[u8]) -> Result<(), DuckDbError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| DuckDbError::Internal(e.to_string()))?;
    }

    let temp_path = path.with_extension("duckdb.tmp");
    tokio::fs::write(&temp_path, payload)
        .await
        .map_err(|e| DuckDbError::Internal(e.to_string()))?;
    tokio::fs::rename(&temp_path, path)
        .await
        .map_err(|e| DuckDbError::Internal(e.to_string()))
}

async fn remove_duckdb_cache_files(path: &Path) -> Result<(), DuckDbError> {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}.tmp", path.display())),
        PathBuf::from(format!("{}.wal", path.display())),
    ] {
        match tokio::fs::remove_file(&candidate).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(DuckDbError::Internal(e.to_string())),
        }
    }
    Ok(())
}

fn duckdb_wal_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.wal", path.display()))
}

fn artifact_error_to_duckdb(err: DatabaseArtifactError) -> DuckDbError {
    DuckDbError::Internal(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database_artifacts::SeaOrmDatabaseArtifactRepository,
        migrations::Migrator,
        sea_orm::{ConnectOptions, Database},
        sea_orm_migration::MigratorTrait,
    };
    use tempfile::TempDir;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        ssi::{dids::DIDBuf, jwk::JWK},
    };

    fn test_space_id(name: &str) -> SpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, name.parse().unwrap())
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
            .load("duckdb", &space.to_string(), "analytics")
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

        // DuckDB export checkpoints the engine, so the exported checkpoint is
        // durably installed before a subsequent WAL replaces the old delta.
        service.export(&space, "analytics").await.unwrap();
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
}

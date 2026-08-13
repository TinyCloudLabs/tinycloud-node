use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Weak,
    },
};

use dashmap::DashMap;
use tinycloud_auth::resource::SpaceId;

use crate::database_artifacts::{
    ArtifactExpectation, DatabaseArtifactError, DatabaseArtifactRepository,
};

use super::{
    caveats::SqlCaveats,
    database::{spawn_actor, DatabaseHandle},
    types::*,
};

const MAX_WAL_DELTA_BYTES: usize = 8 * 1024 * 1024;

/// The first 16 bytes of every SQLite main database file.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
/// The first 4 bytes of a SQLite WAL header. The low bit of the last byte
/// selects the checksum endianness; both values are valid.
const SQLITE_WAL_MAGIC: [&[u8]; 2] = [&[0x37, 0x7f, 0x06, 0x82], &[0x37, 0x7f, 0x06, 0x83]];

/// Per-(space, db) guard over cache hydration; see [`SqlService::handle`].
type HydrationLock = tokio::sync::Mutex<()>;
type HydrationLockRegistry =
    Arc<tokio::sync::Mutex<HashMap<(String, String), Weak<HydrationLock>>>>;

#[derive(Clone)]
pub struct SqlService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    hydration_locks: HydrationLockRegistry,
    /// What each live actor's local database derives from, carried into every
    /// durable save so a stale actor is rejected instead of clobbering. Written
    /// on hydration (the only path that creates an actor) and after each
    /// successful save, cleared alongside the actor by `discard_local_state`.
    lineage: Arc<DashMap<(String, String), ArtifactExpectation>>,
    base_path: String,
    memory_threshold: u64,
    artifact_repository: Arc<dyn DatabaseArtifactRepository>,
}

impl SqlService {
    pub fn new(
        base_path: String,
        memory_threshold: u64,
        artifact_repository: Arc<dyn DatabaseArtifactRepository>,
    ) -> Self {
        Self {
            databases: Arc::new(DashMap::new()),
            hydration_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            lineage: Arc::new(DashMap::new()),
            base_path,
            memory_threshold,
            artifact_repository,
        }
    }

    pub async fn execute(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
    ) -> Result<SqlExecutionResult, SqlError> {
        let key = (space.to_string(), db_name.to_string());
        let mut handle = self.handle(space, db_name).await?;

        let result = match handle
            .execute(request.clone(), caveats.clone(), ability.clone())
            .await
        {
            Err(SqlError::Internal(ref msg)) if msg.contains("Database actor not available") => {
                // Actor is dead — remove stale entry and respawn
                tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected, respawning");
                self.databases.remove(&key);
                handle = self.handle(space, db_name).await?;
                handle.execute(request, caveats, ability).await
            }
            other => other,
        }?;

        if !result.write_targets.is_empty() {
            if let Err(e) = self.persist_write(space, db_name, &handle).await {
                let _ = self.discard_local_state(&key).await;
                return Err(e);
            }
        }

        Ok(result)
    }

    pub async fn export(&self, space: &SpaceId, db_name: &str) -> Result<Vec<u8>, SqlError> {
        let key = (space.to_string(), db_name.to_string());

        // If there's a live actor, route through it (handles both in-memory and file-backed)
        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            match handle.export().await {
                Err(SqlError::Internal(ref msg))
                    if msg.contains("Database actor not available") =>
                {
                    // Actor is dead — remove stale entry and fall through to cold read
                    tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected during export, removing");
                    self.databases.remove(&key);
                }
                other => return other,
            }
        }

        if self
            .artifact_repository
            .load("sql", &space.to_string(), db_name)
            .await
            .map_err(artifact_error_to_sql)?
            .is_none()
        {
            return Err(SqlError::DatabaseNotFound);
        }
        self.handle(space, db_name).await?.export().await
    }

    pub fn db_name_from_path(path: Option<&str>) -> String {
        path.map(|p| p.split('/').next_back().unwrap_or("default").to_string())
            .unwrap_or_else(|| "default".to_string())
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
    async fn handle(&self, space: &SpaceId, db_name: &str) -> Result<DatabaseHandle, SqlError> {
        let key = (space.to_string(), db_name.to_string());
        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            return Ok(handle);
        }

        let hydration_lock = self.hydration_lock(&key).await;
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
                spawn_actor(
                    space.to_string(),
                    db_name.to_string(),
                    self.base_path.clone(),
                    self.memory_threshold,
                    self.databases.clone(),
                )
            })
            .clone())
    }

    /// The hydration guard for `key`, created on first use.
    ///
    /// The registry holds weak references and is swept on every acquisition, so
    /// it cannot outgrow the set of databases currently being hydrated.
    async fn hydration_lock(&self, key: &(String, String)) -> Arc<HydrationLock> {
        let mut registry = self.hydration_locks.lock().await;
        registry.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = registry.get(key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(HydrationLock::new(()));
        registry.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }

    async fn hydrate_cache(&self, space: &SpaceId, db_name: &str) -> Result<(), SqlError> {
        let cache_path = self.cache_path(space, db_name);
        let key = (space.to_string(), db_name.to_string());
        match self
            .artifact_repository
            .load("sql", &space.to_string(), db_name)
            .await
            .map_err(artifact_error_to_sql)?
        {
            Some(artifact) => {
                tracing::info!(
                    service = "sql",
                    space = %space,
                    db = db_name,
                    revision = artifact.revision,
                    storage_mode = %artifact.storage_mode,
                    bytes = artifact.payload.len(),
                    delta_bytes = artifact.delta_size_bytes,
                    logical_bytes = artifact.size_bytes,
                    content_hash = %artifact.content_hash,
                    checkpoint_content_hash = %artifact.checkpoint_content_hash,
                    "Loaded database artifact"
                );
                // Refuse to seed the cache with bytes SQLite would misread. A
                // checkpoint that is not a database opens as a fresh empty one,
                // and a WAL that is not a WAL is ignored outright — both revert
                // the database silently, and the next write makes the reverted
                // state durable.
                validate_payload(
                    space,
                    db_name,
                    "checkpoint",
                    &artifact.payload,
                    is_sqlite_database,
                )?;
                if let Some(delta) = artifact.delta_payload.as_deref() {
                    validate_payload(space, db_name, "wal", delta, is_sqlite_wal)?;
                }

                remove_sql_cache_files(&cache_path).await?;
                write_cache_file(&cache_path, &artifact.payload).await?;
                if let Some(delta) = artifact.delta_payload {
                    write_cache_file(&sql_wal_path(&cache_path), &delta).await?;
                }
                self.lineage.insert(
                    key,
                    ArtifactExpectation::Derived {
                        revision: artifact.revision,
                        checkpoint_content_hash: artifact.checkpoint_content_hash,
                    },
                );
                Ok(())
            }
            None => {
                tracing::info!(
                    service = "sql",
                    space = %space,
                    db = db_name,
                    "No durable database artifact; starting from an empty database"
                );
                remove_sql_cache_files(&cache_path).await?;
                self.lineage.insert(key, ArtifactExpectation::Absent);
                Ok(())
            }
        }
    }

    fn cache_path(&self, space: &SpaceId, db_name: &str) -> PathBuf {
        PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name))
    }

    async fn discard_local_state(&self, key: &(String, String)) -> Result<(), SqlError> {
        self.databases.remove(key);
        self.lineage.remove(key);
        let cache_path = PathBuf::from(&self.base_path)
            .join(&key.0)
            .join(format!("{}.db", key.1));
        remove_sql_cache_files(&cache_path).await
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
                    service = "sql",
                    space = %key.0,
                    db = %key.1,
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
    ) -> Result<(), SqlError> {
        let key = (space.to_string(), db_name.to_string());
        let expected = self.expectation(&key);

        if let Some(wal) = handle
            .wal()
            .await?
            .filter(|wal| wal.len() < MAX_WAL_DELTA_BYTES)
        {
            match self
                .artifact_repository
                .save_delta("sql", &space.to_string(), db_name, wal, expected.clone())
                .await
            {
                Ok(saved) => {
                    // The delta rides on the same checkpoint, so only the
                    // revision this actor is caught up to moves.
                    self.lineage
                        .insert(key, expected.advanced_to(saved.revision));
                    tracing::info!(
                        service = "sql",
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
                Err(error) => return Err(artifact_error_to_sql(error)),
            }
        }

        let payload = handle.checkpoint().await?;
        let bytes = payload.len();
        let saved = self
            .artifact_repository
            .save("sql", &space.to_string(), db_name, payload, expected)
            .await
            .map_err(artifact_error_to_sql)?;
        self.lineage.insert(
            key,
            ArtifactExpectation::Derived {
                revision: saved.revision,
                checkpoint_content_hash: saved.checkpoint_content_hash.clone(),
            },
        );
        tracing::info!(
            service = "sql",
            space = %space,
            db = db_name,
            mode = "checkpoint",
            bytes,
            logical_bytes = saved.size_bytes,
            revision = saved.revision,
            "Persisted database checkpoint"
        );
        Ok(())
    }
}

/// Whether `payload` carries SQLite's main-database header.
fn is_sqlite_database(payload: &[u8]) -> bool {
    payload.starts_with(SQLITE_MAGIC)
}

/// Whether `payload` carries a SQLite WAL header.
fn is_sqlite_wal(payload: &[u8]) -> bool {
    SQLITE_WAL_MAGIC
        .iter()
        .any(|magic| payload.starts_with(magic))
}

/// Reject a hydration payload whose leading bytes are not the format the file
/// it is about to become is read as.
fn validate_payload(
    space: &SpaceId,
    db_name: &str,
    role: &'static str,
    payload: &[u8],
    is_valid: impl Fn(&[u8]) -> bool,
) -> Result<(), SqlError> {
    if is_valid(payload) {
        return Ok(());
    }
    tracing::error!(
        service = "sql",
        space = %space,
        db = db_name,
        role,
        bytes = payload.len(),
        leading = %hex::encode(&payload[..payload.len().min(16)]),
        "Durable database artifact does not carry the expected file header; refusing to hydrate"
    );
    Err(SqlError::Internal(format!(
        "database artifact {role} for {space}/{db_name} does not carry the expected file header"
    )))
}

/// A temp sibling of `path`, unique per call.
///
/// The suffix is APPENDED to the whole path. `Path::with_extension` replaces
/// everything after the last `.`, so `main.db` and `main.db-wal` both mapped to
/// `main.db.tmp`: the checkpoint and WAL writes of one hydration raced on a
/// single file and cross-consumed each other's bytes, leaving either a WAL that
/// SQLite ignores (silent revert to the checkpoint) or a "database" with no
/// SQLite header (silent revert to empty).
fn temp_write_path(path: &Path) -> PathBuf {
    static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
    PathBuf::from(format!(
        "{}.tmp.{}.{}",
        path.display(),
        std::process::id(),
        NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
    ))
}

async fn write_cache_file(path: &Path, payload: &[u8]) -> Result<(), SqlError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    let temp_path = temp_write_path(path);
    if let Err(e) = tokio::fs::write(&temp_path, payload).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(SqlError::Internal(e.to_string()));
    }
    if let Err(e) = tokio::fs::rename(&temp_path, path).await {
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err(SqlError::Internal(e.to_string()));
    }
    Ok(())
}

async fn remove_sql_cache_files(path: &Path) -> Result<(), SqlError> {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match tokio::fs::remove_file(&candidate).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(SqlError::Internal(e.to_string())),
        }
    }
    Ok(())
}

fn sql_wal_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}-wal", path.display()))
}

fn artifact_error_to_sql(err: DatabaseArtifactError) -> SqlError {
    SqlError::Internal(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database_artifacts::{DatabaseArtifact, DeltaSave, SeaOrmDatabaseArtifactRepository},
        migrations::Migrator,
        sea_orm::{ConnectOptions, Database},
        sea_orm_migration::MigratorTrait,
    };
    use async_trait::async_trait;
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

    #[tokio::test]
    async fn sql_schema_ability_can_create_schema() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let space = test_space_id("sql-schema");
        let service = SqlService::new(cache.path().to_string_lossy().to_string(), u64::MAX, repo);

        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
                        .to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/schema".to_string(),
            )
            .await
            .expect("schema ability should create tables");
    }

    #[tokio::test]
    async fn sql_write_export_is_not_throttled_by_backup_pacing() {
        // Regression for tinycloud-node#112: handle_export paced the SQLite
        // backup at 5 pages / 250ms, capping export at ~80KB/s of database
        // size. Every write exports the full database, so a write on a ~2MB
        // database took ~25s and a production-sized (45MB) one ~9 minutes.
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let space = test_space_id("sql-export-speed");
        let service = SqlService::new(cache.path().to_string_lossy().to_string(), u64::MAX, repo);

        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "CREATE TABLE blobs (id INTEGER PRIMARY KEY, body TEXT NOT NULL)"
                        .to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/schema".to_string(),
            )
            .await
            .expect("create table");

        // Grow the database to ~2MB (1MB of random bytes hex-encoded).
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO blobs (body) VALUES (hex(randomblob(1000000)))".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/write".to_string(),
            )
            .await
            .expect("grow database");

        let start = std::time::Instant::now();
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO blobs (body) VALUES ('tiny')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/write".to_string(),
            )
            .await
            .expect("small write");
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "small write on a ~2MB database took {elapsed:?}; the export backup must not be paced"
        );
    }

    #[tokio::test]
    async fn sql_write_survives_service_recreation_with_empty_cache() {
        let repo = artifact_repository().await;
        let cache_one = TempDir::new().unwrap();
        let cache_two = TempDir::new().unwrap();
        let space = test_space_id("sql-hydrate");

        let service = SqlService::new(
            cache_one.path().to_string_lossy().to_string(),
            u64::MAX,
            repo.clone(),
        );
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: Some(vec![
                        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
                            .to_string(),
                    ]),
                    sql: "INSERT INTO items (name) VALUES (?)".to_string(),
                    params: vec![SqlValue::Text("durable".to_string())],
                },
                None,
                "tinycloud.sql/write".to_string(),
            )
            .await
            .unwrap();
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO items (name) VALUES (?)".to_string(),
                    params: vec![SqlValue::Text("updated".to_string())],
                },
                None,
                "tinycloud.sql/write".to_string(),
            )
            .await
            .unwrap();
        drop(service);

        let recreated = SqlService::new(
            cache_two.path().to_string_lossy().to_string(),
            u64::MAX,
            repo,
        );
        let result = recreated
            .execute(
                &space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT name FROM items ORDER BY id".to_string(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".to_string(),
            )
            .await
            .unwrap();

        match result.response {
            SqlResponse::Query(query) => {
                assert_eq!(query.row_count, 2);
                assert_eq!(query.rows[0][0], SqlValue::Text("durable".to_string()));
                assert_eq!(query.rows[1][0], SqlValue::Text("updated".to_string()));
            }
            other => panic!("expected query response, got {:?}", other),
        }

        let hydrated_path = cache_two.path().join(space.to_string()).join("main.db");
        assert!(
            hydrated_path.exists(),
            "durable artifact should hydrate cache"
        );
    }

    #[tokio::test]
    async fn file_backed_small_writes_persist_wal_not_full_database() {
        let repo = artifact_repository().await;
        let cache_one = TempDir::new().unwrap();
        let cache_two = TempDir::new().unwrap();
        let space = test_space_id("sql-wal-delta");
        let service = SqlService::new(
            cache_one.path().to_string_lossy().to_string(),
            0,
            repo.clone(),
        );

        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
                        .to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/schema".to_string(),
            )
            .await
            .unwrap();
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO items (name) VALUES ('one')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/write".to_string(),
            )
            .await
            .unwrap();

        let artifact = repo
            .load("sql", &space.to_string(), "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(artifact.storage_mode, "checkpoint+wal");
        assert!(artifact.delta_size_bytes > 0);
        println!(
            "sql artifact persistence: checkpoint={} delta={}",
            artifact.payload.len(),
            artifact.delta_size_bytes
        );
        assert!(
            artifact.delta_size_bytes < artifact.payload.len() as i64,
            "a small write should transfer fewer bytes than the checkpoint"
        );

        // User-facing export must not reset the WAL baseline. A later delta
        // still has to contain both acknowledged writes.
        service.export(&space, "main").await.unwrap();
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO items (name) VALUES ('two')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/write".to_string(),
            )
            .await
            .unwrap();

        let recreated = SqlService::new(cache_two.path().to_string_lossy().to_string(), 0, repo);
        let result = recreated
            .execute(
                &space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT name FROM items ORDER BY id".to_string(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".to_string(),
            )
            .await
            .unwrap();
        match result.response {
            SqlResponse::Query(query) => {
                assert_eq!(query.row_count, 2);
                assert_eq!(query.rows[0][0], SqlValue::Text("one".to_string()));
                assert_eq!(query.rows[1][0], SqlValue::Text("two".to_string()));
            }
            other => panic!("expected query response, got {other:?}"),
        }
    }

    #[test]
    fn hydration_temp_paths_never_collide_between_checkpoint_and_wal() {
        let database = PathBuf::from("/cache/space/main.db");
        let wal = sql_wal_path(&database);

        // The defect: `with_extension` REPLACES the last extension, so the two
        // distinct targets of one hydration mapped onto a single temp file and
        // cross-consumed each other's bytes.
        assert_eq!(
            database.with_extension("db.tmp"),
            wal.with_extension("db.tmp"),
            "this equality is the bug being fixed; if it ever stops holding the \
             regression below no longer proves anything"
        );

        let database_temp = temp_write_path(&database);
        let wal_temp = temp_write_path(&wal);
        assert_ne!(database_temp, wal_temp);
        assert_ne!(
            temp_write_path(&database),
            temp_write_path(&database),
            "two writes of one target must not share a temp path either"
        );

        // Same directory, so the rename that publishes the file stays atomic.
        assert_eq!(database_temp.parent(), database.parent());
        assert_eq!(wal_temp.parent(), wal.parent());
        // And a temp path must never be mistaken for the file it stages.
        assert_ne!(database_temp, database);
        assert_ne!(wal_temp, wal);
    }

    #[test]
    fn hydration_payload_headers_are_checked_against_their_role() {
        let database = [SQLITE_MAGIC, &[0u8; 84][..]].concat();
        let wal = [&[0x37, 0x7f, 0x06, 0x82][..], &[0u8; 28][..]].concat();
        let wal_big_endian_checksums = [&[0x37, 0x7f, 0x06, 0x83][..], &[0u8; 28][..]].concat();

        assert!(is_sqlite_database(&database));
        assert!(is_sqlite_wal(&wal));
        assert!(is_sqlite_wal(&wal_big_endian_checksums));

        // The two cross-consumption outcomes the temp-path collision produced.
        assert!(
            !is_sqlite_database(&wal),
            "WAL bytes on the database path open as a fresh empty database"
        );
        assert!(
            !is_sqlite_wal(&database),
            "checkpoint bytes on the WAL path make SQLite ignore the WAL"
        );

        assert!(!is_sqlite_database(&[]));
        assert!(!is_sqlite_wal(&[]));
        assert!(!is_sqlite_database(&SQLITE_MAGIC[..8]));
    }

    #[tokio::test]
    async fn hydration_rejects_a_checkpoint_that_is_not_a_database() {
        let repo = artifact_repository().await;
        let space = test_space_id("sql-bad-header");
        // A durable row whose payload is not a database: hydrating it would
        // hand SQLite bytes it opens as an empty database, and the next write
        // would make that emptiness durable.
        repo.save(
            "sql",
            &space.to_string(),
            "main",
            vec![0x37, 0x7f, 0x06, 0x82, 0, 0, 0, 0],
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();

        let cache = TempDir::new().unwrap();
        let service = SqlService::new(cache.path().to_string_lossy().to_string(), u64::MAX, repo);
        let err = service
            .execute(
                &space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT 1".to_string(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".to_string(),
            )
            .await
            .expect_err("hydration must refuse a checkpoint with no SQLite header");
        assert!(
            matches!(&err, SqlError::Internal(message) if message.contains("file header")),
            "expected a loud header failure, got {err:?}"
        );
        assert!(
            !cache
                .path()
                .join(space.to_string())
                .join("main.db")
                .exists(),
            "a rejected payload must never reach the cache"
        );
    }

    /// Counts `load` calls so a test can assert how many hydrations ran.
    struct CountingArtifactRepository {
        inner: Arc<SeaOrmDatabaseArtifactRepository>,
        loads: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl DatabaseArtifactRepository for CountingArtifactRepository {
        async fn load(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError> {
            self.loads.fetch_add(1, Ordering::Relaxed);
            self.inner.load(service, space, name).await
        }

        async fn save(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            self.inner
                .save(service, space, name, payload, expected)
                .await
        }

        async fn save_delta(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DeltaSave, DatabaseArtifactError> {
            self.inner
                .save_delta(service, space, name, payload, expected)
                .await
        }
    }

    #[tokio::test]
    async fn concurrent_cold_reads_hydrate_the_cache_exactly_once() {
        let repo = artifact_repository().await;
        let space = test_space_id("sql-cold-stampede");
        let seed_cache = TempDir::new().unwrap();
        let seed = SqlService::new(
            seed_cache.path().to_string_lossy().to_string(),
            u64::MAX,
            repo.clone(),
        );
        seed.execute(
            &space,
            "main",
            SqlRequest::Execute {
                schema: Some(vec![
                    "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)".to_string(),
                ]),
                sql: "INSERT INTO items (name) VALUES ('durable')".to_string(),
                params: Vec::new(),
            },
            None,
            "tinycloud.sql/write".to_string(),
        )
        .await
        .unwrap();
        drop(seed);

        // A cold service, then a stampede of readers for one database. Each
        // hydration deletes and rewrites the files the others are writing (and
        // that the actor will open), so exactly one may run.
        let loads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().to_string(),
            u64::MAX,
            Arc::new(CountingArtifactRepository {
                inner: repo,
                loads: loads.clone(),
            }),
        );

        let readers = (0..8)
            .map(|_| {
                let service = service.clone();
                let space = space.clone();
                tokio::spawn(async move {
                    service
                        .execute(
                            &space,
                            "main",
                            SqlRequest::Query {
                                sql: "SELECT name FROM items".to_string(),
                                params: Vec::new(),
                                max_rows: None,
                                max_bytes: None,
                            },
                            None,
                            "tinycloud.sql/read".to_string(),
                        )
                        .await
                })
            })
            .collect::<Vec<_>>();

        for reader in readers {
            let result = reader.await.unwrap().expect("every cold reader must serve");
            match result.response {
                SqlResponse::Query(query) => assert_eq!(query.row_count, 1),
                other => panic!("expected query response, got {other:?}"),
            }
        }
        assert_eq!(
            loads.load(Ordering::Relaxed),
            1,
            "the miss -> hydrate -> spawn window must be serialized per database"
        );
    }

    struct FailingArtifactRepository;

    #[async_trait]
    impl DatabaseArtifactRepository for FailingArtifactRepository {
        async fn load(
            &self,
            _service: &str,
            _space: &str,
            _name: &str,
        ) -> Result<Option<DatabaseArtifact>, DatabaseArtifactError> {
            Ok(None)
        }

        async fn save(
            &self,
            _service: &str,
            _space: &str,
            _name: &str,
            _payload: Vec<u8>,
            _expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            Err(DatabaseArtifactError::Backend("forced failure".to_string()))
        }
    }

    #[tokio::test]
    async fn sql_write_fails_when_durable_persistence_fails() {
        let cache = TempDir::new().unwrap();
        let space = test_space_id("sql-failure");
        let service = SqlService::new(
            cache.path().to_string_lossy().to_string(),
            u64::MAX,
            Arc::new(FailingArtifactRepository),
        );

        let err = service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: Some(vec!["CREATE TABLE items (name TEXT NOT NULL)".to_string()]),
                    sql: "INSERT INTO items (name) VALUES ('lost')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/write".to_string(),
            )
            .await
            .expect_err("write must fail when durable save fails");

        assert!(matches!(err, SqlError::Internal(_)));
        assert!(matches!(
            service.export(&space, "main").await,
            Err(SqlError::DatabaseNotFound)
        ));
    }
}

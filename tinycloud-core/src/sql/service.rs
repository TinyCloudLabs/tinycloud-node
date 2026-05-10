use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use dashmap::DashMap;
use tinycloud_auth::resource::SpaceId;

use crate::database_artifacts::{DatabaseArtifactError, DatabaseArtifactRepository};

use super::{
    caveats::SqlCaveats,
    database::{DatabaseHandle, spawn_actor},
    replication as sql_replication, storage,
    types::*,
};
use crate::types::SqlReadParams;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlNodeMode {
    Host,
    Replica,
}

pub struct SqlService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    base_path: String,
    memory_threshold: u64,
    artifact_repository: Arc<dyn DatabaseArtifactRepository>,
    mode: SqlNodeMode,
}

impl SqlService {
    pub fn new(
        base_path: String,
        memory_threshold: u64,
        mode: SqlNodeMode,
        artifact_repository: Arc<dyn DatabaseArtifactRepository>,
    ) -> Self {
        Self {
            databases: Arc::new(DashMap::new()),
            base_path,
            memory_threshold,
            artifact_repository,
            mode,
        }
    }

    pub async fn execute(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
        read_params: SqlReadParams,
    ) -> Result<SqlExecutionResult, SqlError> {
        let key = (space.to_string(), db_name.to_string());
        let mut handle = self.handle(space, db_name).await?;

        let result = match handle
            .execute(request.clone(), caveats.clone(), ability.clone(), read_params)
            .await
        {
            Err(SqlError::Internal(ref msg)) if msg.contains("Database actor not available") => {
                // Actor is dead — remove stale entry and respawn
                tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected, respawning");
                self.databases.remove(&key);
                handle = self.handle(space, db_name).await?;
                handle.execute(request, caveats, ability, read_params).await
            }
            other => other,
        }?;

        if !result.write_targets.is_empty() {
            let payload = match handle.export().await {
                Ok(payload) => payload,
                Err(e) => {
                    let _ = self.discard_local_state(&key).await;
                    return Err(e);
                }
            };
            if let Err(e) = self
                .artifact_repository
                .save("sql", &space.to_string(), db_name, payload)
                .await
            {
                let _ = self.discard_local_state(&key).await;
                return Err(artifact_error_to_sql(e));
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

        match self
            .artifact_repository
            .load("sql", &space.to_string(), db_name)
            .await
            .map_err(artifact_error_to_sql)?
        {
            Some(artifact) => {
                remove_sql_cache_files(&self.cache_path(space, db_name)).await?;
                write_cache_file(&self.cache_path(space, db_name), &artifact.payload).await?;
                Ok(artifact.payload)
            }
            None => Err(SqlError::DatabaseNotFound),
        }
    }

    pub async fn export_replication(
        &self,
        space: &SpaceId,
        db_name: &str,
        since_seq: Option<i64>,
    ) -> Result<sql_replication::SqlReplicationExport, SqlError> {
        let key = (space.to_string(), db_name.to_string());

        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            match handle.export_replication(since_seq).await {
                Err(SqlError::Internal(ref msg))
                    if msg.contains("Database actor not available") =>
                {
                    tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected during replication export, removing");
                    self.databases.remove(&key);
                }
                other => return other,
            }
        }

        let path = std::path::PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name));

        if !path.exists() {
            return Err(SqlError::DatabaseNotFound);
        }

        sql_replication::export_replication_from_path(&path, since_seq)
    }

    pub async fn current_replication_seq(
        &self,
        space: &SpaceId,
        db_name: &str,
    ) -> Result<i64, SqlError> {
        let key = (space.to_string(), db_name.to_string());

        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            match handle.export_replication(Some(i64::MAX)).await {
                Err(SqlError::Internal(ref msg))
                    if msg.contains("Database actor not available") =>
                {
                    tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected during replication seq lookup, removing");
                    self.databases.remove(&key);
                }
                Ok(export) => return Ok(export.exported_until_seq),
                Err(error) => return Err(error),
            }
        }

        let path = std::path::PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name));

        if !path.exists() {
            return Err(SqlError::DatabaseNotFound);
        }

        sql_replication::current_replication_seq_from_path(&path)
    }

    pub async fn import(
        &self,
        space: &SpaceId,
        db_name: &str,
        snapshot: &[u8],
        snapshot_reason: Option<String>,
        canonicalized_authored_ids: Vec<String>,
    ) -> Result<(), SqlError> {
        let key = (space.to_string(), db_name.to_string());

        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            match handle
                .import(
                    snapshot.to_vec(),
                    snapshot_reason.clone(),
                    canonicalized_authored_ids.clone(),
                )
                .await
            {
                Err(SqlError::Internal(ref msg))
                    if msg.contains("Database actor not available") =>
                {
                    tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected during import, removing");
                    self.databases.remove(&key);
                }
                Ok(()) => {
                    let payload = match handle.export().await {
                        Ok(payload) => payload,
                        Err(e) => {
                            let _ = self.discard_local_state(&key).await;
                            return Err(e);
                        }
                    };
                    self.artifact_repository
                        .save("sql", &space.to_string(), db_name, payload)
                        .await
                        .map_err(artifact_error_to_sql)?;
                    return Ok(());
                }
                Err(e) => {
                    let _ = self.discard_local_state(&key).await;
                    return Err(e);
                }
            }
        }

        let path = std::path::PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name));

        storage::import_snapshot_to_path(&path, snapshot)?;
        let conn = storage::open_connection(&storage::StorageMode::File(path))?;
        if let Some(reason) = snapshot_reason {
            sql_replication::append_snapshot_barrier(&conn, &reason)?;
        }
        let canonical_seq = sql_replication::current_replication_seq(&conn)?;
        for authored_id in canonicalized_authored_ids {
            sql_replication::record_canonicalized_authored_fact(
                &conn,
                &authored_id,
                canonical_seq,
                None,
            )?;
        }
        let payload = storage::export_snapshot_from_path(&self.cache_path(space, db_name))?;
        self.artifact_repository
            .save("sql", &space.to_string(), db_name, payload.clone())
            .await
            .map_err(artifact_error_to_sql)?;
        remove_sql_cache_files(&self.cache_path(space, db_name)).await?;
        write_cache_file(&self.cache_path(space, db_name), &payload).await
    }

    pub async fn apply_changeset(
        &self,
        space: &SpaceId,
        db_name: &str,
        changeset: &[u8],
        canonicalized_authored_ids: Vec<String>,
    ) -> Result<(), SqlError> {
        let key = (space.to_string(), db_name.to_string());

        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            match handle
                .apply_replication_changeset(changeset.to_vec(), canonicalized_authored_ids.clone())
                .await
            {
                Err(SqlError::Internal(ref msg))
                    if msg.contains("Database actor not available") =>
                {
                    tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected during changeset apply, removing");
                    self.databases.remove(&key);
                }
                Ok(()) => {
                    let payload = match handle.export().await {
                        Ok(payload) => payload,
                        Err(e) => {
                            let _ = self.discard_local_state(&key).await;
                            return Err(e);
                        }
                    };
                    self.artifact_repository
                        .save("sql", &space.to_string(), db_name, payload)
                        .await
                        .map_err(artifact_error_to_sql)?;
                    return Ok(());
                }
                Err(e) => {
                    let _ = self.discard_local_state(&key).await;
                    return Err(e);
                }
            }
        }

        let path = std::path::PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name));

        let conn = storage::open_connection(&storage::StorageMode::File(path))?;
        sql_replication::apply_changeset(&conn, changeset)?;
        sql_replication::append_changeset(&conn, changeset)?;
        let canonical_seq = sql_replication::current_replication_seq(&conn)?;
        for authored_id in canonicalized_authored_ids {
            sql_replication::record_canonicalized_authored_fact(
                &conn,
                &authored_id,
                canonical_seq,
                None,
            )?;
        }
        let payload = storage::export_snapshot_from_path(&self.cache_path(space, db_name))?;
        self.artifact_repository
            .save("sql", &space.to_string(), db_name, payload.clone())
            .await
            .map_err(artifact_error_to_sql)?;
        remove_sql_cache_files(&self.cache_path(space, db_name)).await?;
        write_cache_file(&self.cache_path(space, db_name), &payload).await
    }

    pub async fn apply_authored_replication_facts(
        &self,
        space: &SpaceId,
        db_name: &str,
        peer_url: Option<String>,
        facts: Vec<sql_replication::SqlAuthoredFact>,
    ) -> Result<sql_replication::SqlAuthoredFactApplyResult, SqlError> {
        let key = (space.to_string(), db_name.to_string());
        let handle = self
            .databases
            .entry(key.clone())
            .or_insert_with(|| {
                spawn_actor(
                    space.to_string(),
                    db_name.to_string(),
                    self.base_path.clone(),
                    self.memory_threshold,
                    self.mode,
                    self.databases.clone(),
                )
            })
            .clone();

        match handle
            .apply_authored_facts(peer_url.clone(), facts.clone())
            .await
        {
            Err(SqlError::Internal(ref msg)) if msg.contains("Database actor not available") => {
                tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected during authored fact apply, respawning");
                self.databases.remove(&key);
                let new_handle = self
                    .databases
                    .entry(key)
                    .or_insert_with(|| {
                        spawn_actor(
                            space.to_string(),
                            db_name.to_string(),
                            self.base_path.clone(),
                            self.memory_threshold,
                            self.mode,
                            self.databases.clone(),
                        )
                    })
                    .clone();
                new_handle.apply_authored_facts(peer_url, facts).await
            }
            other => other,
        }
    }

    pub fn node_mode(&self) -> SqlNodeMode {
        self.mode
    }

    pub fn read_peer_cursor(
        &self,
        space: &SpaceId,
        db_name: &str,
        peer_url: &str,
    ) -> Result<Option<i64>, SqlError> {
        sql_replication::read_peer_cursor(&self.base_path, &space.to_string(), db_name, peer_url)
    }

    pub fn write_peer_cursor(
        &self,
        space: &SpaceId,
        db_name: &str,
        peer_url: &str,
        seq: i64,
    ) -> Result<(), SqlError> {
        sql_replication::write_peer_cursor(
            &self.base_path,
            &space.to_string(),
            db_name,
            peer_url,
            seq,
        )
    }

    pub fn db_name_from_path(path: Option<&str>) -> String {
        path.map(|p| p.split('/').next_back().unwrap_or("default").to_string())
            .unwrap_or_else(|| "default".to_string())
    }

    pub fn node_mode(&self) -> SqlNodeMode {
        self.mode
    }

    async fn handle(&self, space: &SpaceId, db_name: &str) -> Result<DatabaseHandle, SqlError> {
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
                    self.mode,
                    self.databases.clone(),
                )
            })
            .clone())
    }

    async fn hydrate_cache(&self, space: &SpaceId, db_name: &str) -> Result<(), SqlError> {
        let cache_path = self.cache_path(space, db_name);
        match self
            .artifact_repository
            .load("sql", &space.to_string(), db_name)
            .await
            .map_err(artifact_error_to_sql)?
        {
            Some(artifact) => {
                remove_sql_cache_files(&cache_path).await?;
                write_cache_file(&cache_path, &artifact.payload).await
            }
            None => remove_sql_cache_files(&cache_path).await,
        }
    }

    fn cache_path(&self, space: &SpaceId, db_name: &str) -> PathBuf {
        PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name))
    }

    async fn discard_local_state(&self, key: &(String, String)) -> Result<(), SqlError> {
        self.databases.remove(key);
        let cache_path = PathBuf::from(&self.base_path)
            .join(&key.0)
            .join(format!("{}.db", key.1));
        remove_sql_cache_files(&cache_path).await
    }
}

async fn write_cache_file(path: &Path, payload: &[u8]) -> Result<(), SqlError> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    let temp_path = path.with_extension("db.tmp");
    tokio::fs::write(&temp_path, payload)
        .await
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    tokio::fs::rename(&temp_path, path)
        .await
        .map_err(|e| SqlError::Internal(e.to_string()))
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

fn artifact_error_to_sql(err: DatabaseArtifactError) -> SqlError {
    SqlError::Internal(err.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        database_artifacts::{DatabaseArtifact, SeaOrmDatabaseArtifactRepository},
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::{SqlRequest, SqlResponse, SqlValue};
    use tempfile::tempdir;

    fn test_space() -> SpaceId {
        "tinycloud:key:test:default".parse().expect("space id")
    }

    #[tokio::test]
    async fn host_canonicalizes_replica_authored_sql_facts() {
        let tempdir = tempdir().expect("tempdir");
        let host_path = tempdir.path().join("host");
        let replica_path = tempdir.path().join("replica");
        let host = SqlService::new(
            host_path.to_string_lossy().to_string(),
            1024 * 1024,
            SqlNodeMode::Host,
        );
        let replica = SqlService::new(
            replica_path.to_string_lossy().to_string(),
            1024 * 1024,
            SqlNodeMode::Replica,
        );
        let space = test_space();

        host.execute(
            &space,
            "default",
            SqlRequest::Execute {
                sql: "CREATE TABLE items (id TEXT PRIMARY KEY, label TEXT NOT NULL)".to_string(),
                params: vec![],
                schema: None,
            },
            None,
            "tinycloud.sql/admin".to_string(),
            SqlReadParams::Canonical,
        )
        .await
        .expect("create table on host");

        let host_snapshot = host.export(&space, "default").await.expect("host snapshot");
        replica
            .import(
                &space,
                "default",
                &host_snapshot,
                Some("initial-sync".to_string()),
                vec![],
            )
            .await
            .expect("import snapshot to replica");

        replica
            .execute(
                &space,
                "default",
                SqlRequest::Execute {
                    sql: "INSERT INTO items (id, label) VALUES (?, ?)".to_string(),
                    params: vec![
                        SqlValue::Text("item-1".to_string()),
                        SqlValue::Text("camera".to_string()),
                    ],
                    schema: None,
                },
                None,
                "tinycloud.sql/admin".to_string(),
                SqlReadParams::Provisional,
            )
            .await
            .expect("replica provisional insert");

        let export = replica
            .export_replication(&space, "default", Some(0))
            .await
            .expect("replica export");
        assert_eq!(export.authored_facts.len(), 1);

        let apply = host
            .apply_authored_replication_facts(
                &space,
                "default",
                Some("https://replica.example".to_string()),
                export.authored_facts.clone(),
            )
            .await
            .expect("apply authored facts on host");
        assert_eq!(apply.canonicalized_count, 1);
        assert_eq!(apply.rejected_count, 0);

        let query = host
            .execute(
                &space,
                "default",
                SqlRequest::Query {
                    sql: "SELECT id, label FROM items ORDER BY id".to_string(),
                    params: vec![],
                },
                None,
                "tinycloud.sql/admin".to_string(),
                SqlReadParams::Canonical,
            )
            .await
            .expect("query host canonical");

        let SqlResponse::Query(query) = query.response else {
            panic!("expected query response");
        };
        assert_eq!(query.row_count, 1);
    }

    #[tokio::test]
    async fn replica_applies_incremental_changeset_from_authority() {
        let tempdir = tempdir().expect("tempdir");
        let host_path = tempdir.path().join("host");
        let replica_path = tempdir.path().join("replica");
        let host = SqlService::new(
            host_path.to_string_lossy().to_string(),
            1024 * 1024,
            SqlNodeMode::Host,
        );
        let replica = SqlService::new(
            replica_path.to_string_lossy().to_string(),
            1024 * 1024,
            SqlNodeMode::Replica,
        );
        let space = test_space();

        host.execute(
            &space,
            "default",
            SqlRequest::Execute {
                sql: "CREATE TABLE items (id TEXT PRIMARY KEY, label TEXT NOT NULL, quantity INTEGER NOT NULL)"
                    .to_string(),
                params: vec![],
                schema: None,
            },
            None,
            "tinycloud.sql/admin".to_string(),
            SqlReadParams::Canonical,
        )
        .await
        .expect("create table on host");

        host.execute(
            &space,
            "default",
            SqlRequest::Execute {
                sql: "INSERT INTO items (id, label, quantity) VALUES (?, ?, ?)".to_string(),
                params: vec![
                    SqlValue::Text("item-1".to_string()),
                    SqlValue::Text("camera".to_string()),
                    SqlValue::Integer(2),
                ],
                schema: None,
            },
            None,
            "tinycloud.sql/admin".to_string(),
            SqlReadParams::Canonical,
        )
        .await
        .expect("insert item on host");

        let initial_snapshot = host.export(&space, "default").await.expect("host snapshot");
        replica
            .import(
                &space,
                "default",
                &initial_snapshot,
                Some("initial-sync".to_string()),
                vec![],
            )
            .await
            .expect("replica import");

        let since_seq = host
            .current_replication_seq(&space, "default")
            .await
            .expect("current seq after insert");
        assert_eq!(since_seq, 2);

        host.execute(
            &space,
            "default",
            SqlRequest::Execute {
                sql: "UPDATE items SET label = ?, quantity = ? WHERE id = ?".to_string(),
                params: vec![
                    SqlValue::Text("camera-pro".to_string()),
                    SqlValue::Integer(4),
                    SqlValue::Text("item-1".to_string()),
                ],
                schema: None,
            },
            None,
            "tinycloud.sql/admin".to_string(),
            SqlReadParams::Canonical,
        )
        .await
        .expect("update item on host");

        let incremental = host
            .export_replication(&space, "default", Some(since_seq))
            .await
            .expect("incremental export");
        assert_eq!(incremental.mode.as_str(), "changeset");
        assert!(!incremental.changeset.is_empty());

        replica
            .apply_changeset(&space, "default", &incremental.changeset, vec![])
            .await
            .expect("apply changeset on replica");

        let query = replica
            .execute(
                &space,
                "default",
                SqlRequest::Query {
                    sql: "SELECT id, label, quantity FROM items WHERE id = ?".to_string(),
                    params: vec![SqlValue::Text("item-1".to_string())],
                },
                None,
                "tinycloud.sql/admin".to_string(),
                SqlReadParams::Canonical,
            )
            .await
            .expect("query replica canonical");

        let SqlResponse::Query(query) = query.response else {
            panic!("expected query response");
        };
        assert_eq!(query.row_count, 1);
        assert_eq!(query.rows.len(), 1);
        assert_eq!(query.rows[0].len(), 3);
        match &query.rows[0][0] {
            SqlValue::Text(value) => assert_eq!(value, "item-1"),
            other => panic!("unexpected id value: {other:?}"),
        }
        match &query.rows[0][1] {
            SqlValue::Text(value) => assert_eq!(value, "camera-pro"),
            other => panic!("unexpected label value: {other:?}"),
        }
        match query.rows[0][2] {
            SqlValue::Integer(value) => assert_eq!(value, 4),
            ref other => panic!("unexpected quantity value: {other:?}"),
        }
    }
}

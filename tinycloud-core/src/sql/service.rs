use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use dashmap::DashMap;
use tinycloud_auth::resource::SpaceId;

use crate::database_artifacts::{DatabaseArtifactError, DatabaseArtifactRepository};

use super::{
    caveats::SqlCaveats,
    database::{spawn_actor, DatabaseHandle},
    types::*,
};

pub struct SqlService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
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

    pub fn db_name_from_path(path: Option<&str>) -> String {
        path.map(|p| p.split('/').next_back().unwrap_or("default").to_string())
            .unwrap_or_else(|| "default".to_string())
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

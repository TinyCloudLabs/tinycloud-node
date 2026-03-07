use std::sync::Arc;

use dashmap::DashMap;
use tinycloud_lib::resource::SpaceId;

use super::{
    caveats::DuckDbCaveats,
    database::{spawn_actor, DatabaseHandle},
    types::*,
};

pub struct DuckDbService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    base_path: String,
    memory_threshold: u64,
    idle_timeout_secs: u64,
    max_memory_per_connection: String,
}

impl DuckDbService {
    pub fn new(
        base_path: String,
        memory_threshold: u64,
        idle_timeout_secs: u64,
        max_memory_per_connection: String,
    ) -> Self {
        Self {
            databases: Arc::new(DashMap::new()),
            base_path,
            memory_threshold,
            idle_timeout_secs,
            max_memory_per_connection,
        }
    }

    pub async fn execute(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: DuckDbRequest,
        caveats: Option<DuckDbCaveats>,
        ability: String,
    ) -> Result<DuckDbResponse, DuckDbError> {
        let key = (space.to_string(), db_name.to_string());
        let handle = self
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
                )
            })
            .clone();

        handle.execute(request, caveats, ability).await
    }

    pub async fn export(&self, space: &SpaceId, db_name: &str) -> Result<Vec<u8>, DuckDbError> {
        let path = std::path::PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.duckdb", db_name));

        if !path.exists() {
            return Err(DuckDbError::DatabaseNotFound);
        }

        std::fs::read(&path).map_err(|e| DuckDbError::Internal(e.to_string()))
    }

    pub async fn import_db(
        &self,
        space: &SpaceId,
        db_name: &str,
        data: &[u8],
    ) -> Result<(), DuckDbError> {
        let dir = std::path::PathBuf::from(&self.base_path).join(space.to_string());
        std::fs::create_dir_all(&dir).map_err(|e| DuckDbError::Internal(e.to_string()))?;

        let path = dir.join(format!("{}.duckdb", db_name));
        std::fs::write(&path, data).map_err(|e| DuckDbError::ImportError(e.to_string()))?;

        // Remove the existing handle so the next access reopens the database from the new file
        let key = (space.to_string(), db_name.to_string());
        self.databases.remove(&key);

        Ok(())
    }

    pub fn db_name_from_path(path: Option<&str>) -> String {
        path.map(|p| p.split('/').next_back().unwrap_or("default").to_string())
            .unwrap_or_else(|| "default".to_string())
    }
}

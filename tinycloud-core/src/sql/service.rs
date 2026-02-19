use std::sync::Arc;

use dashmap::DashMap;
use tinycloud_lib::resource::SpaceId;

use super::{
    caveats::SqlCaveats,
    database::{spawn_actor, DatabaseHandle},
    types::*,
};

pub struct SqlService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    base_path: String,
    memory_threshold: u64,
}

impl SqlService {
    pub fn new(base_path: String, memory_threshold: u64) -> Self {
        Self {
            databases: Arc::new(DashMap::new()),
            base_path,
            memory_threshold,
        }
    }

    pub async fn execute(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
    ) -> Result<SqlResponse, SqlError> {
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
                )
            })
            .clone();

        handle.execute(request, caveats, ability).await
    }

    pub async fn export(&self, space: &SpaceId, db_name: &str) -> Result<Vec<u8>, SqlError> {
        let path = std::path::PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name));

        if !path.exists() {
            return Err(SqlError::DatabaseNotFound);
        }

        std::fs::read(&path).map_err(|e| SqlError::Internal(e.to_string()))
    }

    pub fn db_name_from_path(path: Option<&str>) -> String {
        path.map(|p| p.split('/').next_back().unwrap_or("default").to_string())
            .unwrap_or_else(|| "default".to_string())
    }
}

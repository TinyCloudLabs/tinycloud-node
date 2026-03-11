use std::sync::Arc;

use dashmap::DashMap;
use tinycloud_auth::resource::SpaceId;

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
            .entry(key.clone())
            .or_insert_with(|| {
                spawn_actor(
                    space.to_string(),
                    db_name.to_string(),
                    self.base_path.clone(),
                    self.memory_threshold,
                    self.databases.clone(),
                )
            })
            .clone();

        match handle
            .execute(request.clone(), caveats.clone(), ability.clone())
            .await
        {
            Err(SqlError::Internal(ref msg)) if msg.contains("Database actor not available") => {
                // Actor is dead — remove stale entry and respawn
                tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected, respawning");
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
                            self.databases.clone(),
                        )
                    })
                    .clone();
                new_handle.execute(request, caveats, ability).await
            }
            other => other,
        }
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

        // No live actor — try reading the file directly (cold database)
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

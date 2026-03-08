use std::sync::Arc;

use dashmap::DashMap;
use tinycloud_lib::resource::SpaceId;

use super::{
    caveats::DuckDbCaveats,
    database::{spawn_actor, DatabaseHandle},
    storage,
    types::*,
};

pub struct DuckDbService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    base_path: String,
    memory_threshold: u64,
    idle_timeout_secs: u64,
    max_memory_per_connection: String,
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
        arrow_format: bool,
    ) -> Result<DuckDbResponse, DuckDbError> {
        validate_db_name(db_name)?;

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
                    self.databases.clone(),
                )
            })
            .clone();

        handle
            .execute(request, caveats, ability, arrow_format)
            .await
    }

    pub async fn export(&self, space: &SpaceId, db_name: &str) -> Result<Vec<u8>, DuckDbError> {
        validate_db_name(db_name)?;

        let path = std::path::PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.duckdb", db_name));

        if !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Err(DuckDbError::DatabaseNotFound);
        }

        tokio::fs::read(&path)
            .await
            .map_err(|e| DuckDbError::Internal(e.to_string()))
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
}

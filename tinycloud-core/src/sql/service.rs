use std::sync::Arc;

use dashmap::DashMap;
use tinycloud_auth::resource::SpaceId;

use super::{
    caveats::SqlCaveats,
    database::{spawn_actor, DatabaseHandle},
    replication as sql_replication, storage,
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

        storage::export_snapshot_from_path(&path)
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
    ) -> Result<(), SqlError> {
        let key = (space.to_string(), db_name.to_string());

        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            match handle
                .import(snapshot.to_vec(), snapshot_reason.clone())
                .await
            {
                Err(SqlError::Internal(ref msg))
                    if msg.contains("Database actor not available") =>
                {
                    tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected during import, removing");
                    self.databases.remove(&key);
                }
                other => return other,
            }
        }

        let path = std::path::PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name));

        storage::import_snapshot_to_path(&path, snapshot)?;
        if let Some(reason) = snapshot_reason {
            let conn = storage::open_connection(&storage::StorageMode::File(path))?;
            sql_replication::append_snapshot_barrier(&conn, &reason)?;
        }
        Ok(())
    }

    pub async fn apply_changeset(
        &self,
        space: &SpaceId,
        db_name: &str,
        changeset: &[u8],
    ) -> Result<(), SqlError> {
        let key = (space.to_string(), db_name.to_string());

        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            match handle.apply_changeset(changeset.to_vec()).await {
                Err(SqlError::Internal(ref msg))
                    if msg.contains("Database actor not available") =>
                {
                    tracing::warn!(space=%space, db=%db_name, "Dead SQL actor detected during changeset apply, removing");
                    self.databases.remove(&key);
                }
                other => return other,
            }
        }

        let path = std::path::PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name));

        sql_replication::apply_changeset_to_path(&path, changeset)
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
}

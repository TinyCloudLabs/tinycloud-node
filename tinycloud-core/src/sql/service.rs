use std::sync::Arc;

use dashmap::DashMap;
use tinycloud_auth::resource::SpaceId;

use super::{
    caveats::SqlCaveats,
    database::{spawn_actor, DatabaseHandle},
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
    mode: SqlNodeMode,
}

impl SqlService {
    pub fn new(base_path: String, memory_threshold: u64, mode: SqlNodeMode) -> Self {
        Self {
            databases: Arc::new(DashMap::new()),
            base_path,
            memory_threshold,
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
                    self.mode,
                    self.databases.clone(),
                )
            })
            .clone();

        match handle
            .execute(
                request.clone(),
                caveats.clone(),
                ability.clone(),
                read_params,
            )
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
                            self.mode,
                            self.databases.clone(),
                        )
                    })
                    .clone();
                new_handle
                    .execute(request, caveats, ability, read_params)
                    .await
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
                other => return other,
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
        Ok(())
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
                other => return other,
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
        Ok(())
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

        let SqlResponse::Query(query) = query else {
            panic!("expected query response");
        };
        assert_eq!(query.row_count, 1);
    }
}

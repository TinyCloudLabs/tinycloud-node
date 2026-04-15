use std::path::PathBuf;
use std::sync::Arc;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use dashmap::DashMap;
use rand::{rngs::OsRng, RngCore};
use rusqlite::session::Session;
use rusqlite::{
    hooks::{AuthContext, Authorization},
    params, Connection,
};
use sqlparser::ast::Statement;
use tokio::sync::{mpsc, oneshot};

use super::{
    authorizer,
    caveats::SqlCaveats,
    parser, replication as sql_replication,
    service::SqlNodeMode,
    storage::{self, StorageMode},
    types::*,
};
use crate::types::SqlReadParams;

const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300); // 5 min

enum DbMessage {
    Execute {
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
        read_params: SqlReadParams,
        response_tx: oneshot::Sender<Result<SqlResponse, SqlError>>,
    },
    Export {
        response_tx: oneshot::Sender<Result<Vec<u8>, SqlError>>,
    },
    ExportReplication {
        since_seq: Option<i64>,
        response_tx: oneshot::Sender<Result<sql_replication::SqlReplicationExport, SqlError>>,
    },
    Import {
        snapshot: Vec<u8>,
        snapshot_reason: Option<String>,
        canonicalized_authored_ids: Vec<String>,
        response_tx: oneshot::Sender<Result<(), SqlError>>,
    },
    ApplyChangeset {
        changeset: Vec<u8>,
        canonicalized_authored_ids: Vec<String>,
        response_tx: oneshot::Sender<Result<(), SqlError>>,
    },
    ApplyAuthoredFacts {
        peer_url: Option<String>,
        facts: Vec<sql_replication::SqlAuthoredFact>,
        response_tx: oneshot::Sender<Result<sql_replication::SqlAuthoredFactApplyResult, SqlError>>,
    },
}

#[derive(Clone)]
pub struct DatabaseHandle {
    tx: mpsc::Sender<DbMessage>,
}

struct DatabaseStore {
    conn: Connection,
    mode: StorageMode,
    file_path: PathBuf,
}

struct ReplicaState {
    canonical: DatabaseStore,
    provisional: DatabaseStore,
    metadata: Connection,
}

struct PendingSqlFact {
    fact_id: i64,
    authored_id: String,
    base_canonical_seq: i64,
    request: SqlRequest,
    caveats: Option<SqlCaveats>,
    ability: String,
}

impl DatabaseHandle {
    pub async fn execute(
        &self,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
        read_params: SqlReadParams,
    ) -> Result<SqlResponse, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Execute {
                request,
                caveats,
                ability,
                read_params,
                response_tx,
            })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn export(&self) -> Result<Vec<u8>, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Export { response_tx })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn import(
        &self,
        snapshot: Vec<u8>,
        snapshot_reason: Option<String>,
        canonicalized_authored_ids: Vec<String>,
    ) -> Result<(), SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Import {
                snapshot,
                snapshot_reason,
                canonicalized_authored_ids,
                response_tx,
            })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn export_replication(
        &self,
        since_seq: Option<i64>,
    ) -> Result<sql_replication::SqlReplicationExport, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::ExportReplication {
                since_seq,
                response_tx,
            })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn apply_changeset(&self, changeset: Vec<u8>) -> Result<(), SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::ApplyChangeset {
                changeset,
                canonicalized_authored_ids: Vec::new(),
                response_tx,
            })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn apply_replication_changeset(
        &self,
        changeset: Vec<u8>,
        canonicalized_authored_ids: Vec<String>,
    ) -> Result<(), SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::ApplyChangeset {
                changeset,
                canonicalized_authored_ids,
                response_tx,
            })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn apply_authored_facts(
        &self,
        peer_url: Option<String>,
        facts: Vec<sql_replication::SqlAuthoredFact>,
    ) -> Result<sql_replication::SqlAuthoredFactApplyResult, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::ApplyAuthoredFacts {
                peer_url,
                facts,
                response_tx,
            })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }
}

impl DatabaseStore {
    fn open(file_path: PathBuf) -> Result<Self, SqlError> {
        let mode = if file_path.exists() {
            StorageMode::File(file_path.clone())
        } else {
            StorageMode::InMemory
        };
        let conn = storage::open_connection(&mode)?;
        Ok(Self {
            conn,
            mode,
            file_path,
        })
    }

    fn promote_if_needed(&mut self, memory_threshold: u64) -> Result<(), SqlError> {
        if matches!(self.mode, StorageMode::InMemory)
            && storage::database_size(&self.conn)? > memory_threshold
        {
            let new_conn = storage::promote_to_file(&self.conn, &self.file_path)?;
            self.conn = new_conn;
            self.mode = StorageMode::File(self.file_path.clone());
        }
        Ok(())
    }

    fn flush_if_needed(&mut self) -> Result<(), SqlError> {
        if matches!(self.mode, StorageMode::InMemory) && storage::database_size(&self.conn)? > 0 {
            let new_conn = storage::promote_to_file(&self.conn, &self.file_path)?;
            self.conn = new_conn;
            self.mode = StorageMode::File(self.file_path.clone());
        }
        Ok(())
    }
}

fn metadata_path(base_path: &str, space_id: &str, db_name: &str) -> PathBuf {
    PathBuf::from(base_path)
        .join(space_id)
        .join(format!("{}.metadata.db", db_name))
}

fn provisional_path(base_path: &str, space_id: &str, db_name: &str) -> PathBuf {
    PathBuf::from(base_path)
        .join(space_id)
        .join(format!("{}.provisional.db", db_name))
}

fn canonical_path(base_path: &str, space_id: &str, db_name: &str) -> PathBuf {
    PathBuf::from(base_path)
        .join(space_id)
        .join(format!("{}.db", db_name))
}

fn open_metadata_connection(path: &PathBuf) -> Result<Connection, SqlError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SqlError::Internal(e.to_string()))?;
    }
    let conn = Connection::open(path).map_err(|e| SqlError::Internal(e.to_string()))?;
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS pending_sql_fact (
            fact_id INTEGER PRIMARY KEY AUTOINCREMENT,
            authored_id TEXT,
            request_json TEXT NOT NULL,
            caveats_json TEXT,
            ability TEXT NOT NULL,
            status TEXT NOT NULL,
            reason TEXT,
            authored_at INTEGER NOT NULL DEFAULT (unixepoch()),
            last_attempted_at INTEGER,
            base_canonical_seq INTEGER
        );
        ",
    )
    .map_err(|e| SqlError::Internal(e.to_string()))?;
    ensure_pending_sql_fact_authored_ids(&conn)?;
    Ok(conn)
}

fn ensure_pending_sql_fact_authored_ids(metadata: &Connection) -> Result<(), SqlError> {
    let mut has_authored_id = false;
    let mut stmt = metadata
        .prepare("PRAGMA table_info(pending_sql_fact)")
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    for row in rows {
        if row.map_err(|e| SqlError::Internal(e.to_string()))? == "authored_id" {
            has_authored_id = true;
            break;
        }
    }

    if !has_authored_id {
        metadata
            .execute(
                "ALTER TABLE pending_sql_fact ADD COLUMN authored_id TEXT",
                [],
            )
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    let mut pending_fact_ids = Vec::new();
    let mut stmt = metadata
        .prepare(
            "SELECT fact_id FROM pending_sql_fact WHERE authored_id IS NULL OR authored_id = ''",
        )
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, i64>(0))
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    for row in rows {
        pending_fact_ids.push(row.map_err(|e| SqlError::Internal(e.to_string()))?);
    }

    for fact_id in pending_fact_ids {
        metadata
            .execute(
                "UPDATE pending_sql_fact SET authored_id = ? WHERE fact_id = ?",
                params![new_authored_id(), fact_id],
            )
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    metadata
        .execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_pending_sql_fact_authored_id ON pending_sql_fact(authored_id)",
            [],
        )
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    Ok(())
}

fn clone_store_from(
    source: &DatabaseStore,
    target_path: PathBuf,
) -> Result<DatabaseStore, SqlError> {
    let snapshot = storage::export_snapshot(&source.conn)?;
    let mode = if target_path.exists() {
        StorageMode::File(target_path.clone())
    } else {
        StorageMode::InMemory
    };
    let mut conn = storage::open_connection(&mode)?;
    storage::import_snapshot(&mut conn, &snapshot, matches!(mode, StorageMode::File(_)))?;
    Ok(DatabaseStore {
        conn,
        mode,
        file_path: target_path,
    })
}

fn new_authored_id() -> String {
    let mut bytes = [0u8; 18];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn append_pending_sql_fact(
    metadata: &Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    ability: &str,
    base_canonical_seq: i64,
) -> Result<(i64, String), SqlError> {
    let authored_id = new_authored_id();
    let request_json =
        serde_json::to_string(request).map_err(|e| SqlError::Internal(e.to_string()))?;
    let caveats_json = caveats
        .as_ref()
        .map(|value| serde_json::to_string(value).map_err(|e| SqlError::Internal(e.to_string())))
        .transpose()?;
    metadata
        .execute(
            "
            INSERT INTO pending_sql_fact (authored_id, request_json, caveats_json, ability, status, base_canonical_seq)
            VALUES (?, ?, ?, ?, 'pending', ?)
            ",
            params![authored_id, request_json, caveats_json, ability, base_canonical_seq],
        )
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    Ok((metadata.last_insert_rowid(), authored_id))
}

fn update_pending_sql_fact(
    metadata: &Connection,
    fact_id: i64,
    status: &str,
    reason: Option<&str>,
) -> Result<(), SqlError> {
    metadata
        .execute(
            "
            UPDATE pending_sql_fact
            SET status = ?, reason = ?, last_attempted_at = unixepoch()
            WHERE fact_id = ?
            ",
            params![status, reason, fact_id],
        )
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    Ok(())
}

fn delete_pending_sql_fact(metadata: &Connection, fact_id: i64) -> Result<(), SqlError> {
    metadata
        .execute(
            "DELETE FROM pending_sql_fact WHERE fact_id = ?",
            params![fact_id],
        )
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    Ok(())
}

fn delete_pending_sql_fact_by_authored_id(
    metadata: &Connection,
    authored_id: &str,
) -> Result<(), SqlError> {
    metadata
        .execute(
            "DELETE FROM pending_sql_fact WHERE authored_id = ?",
            params![authored_id],
        )
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    Ok(())
}

fn load_replayable_pending_facts(metadata: &Connection) -> Result<Vec<PendingSqlFact>, SqlError> {
    let mut stmt = metadata
        .prepare(
            "
            SELECT fact_id, authored_id, request_json, caveats_json, ability, COALESCE(base_canonical_seq, 0)
            FROM pending_sql_fact
            WHERE status IN ('pending', 'applied', 'rebase_needed')
            ORDER BY fact_id ASC
            ",
        )
        .map_err(|e| SqlError::Internal(e.to_string()))?;

    let rows = stmt
        .query_map([], |row| {
            let fact_id: i64 = row.get(0)?;
            let authored_id: String = row.get(1)?;
            let request_json: String = row.get(2)?;
            let caveats_json: Option<String> = row.get(3)?;
            let ability: String = row.get(4)?;
            let base_canonical_seq: i64 = row.get(5)?;
            Ok((
                fact_id,
                authored_id,
                request_json,
                caveats_json,
                ability,
                base_canonical_seq,
            ))
        })
        .map_err(|e| SqlError::Internal(e.to_string()))?;

    let mut facts = Vec::new();
    for row in rows {
        let (fact_id, authored_id, request_json, caveats_json, ability, base_canonical_seq) =
            row.map_err(|e| SqlError::Internal(e.to_string()))?;
        let request =
            serde_json::from_str(&request_json).map_err(|e| SqlError::Internal(e.to_string()))?;
        let caveats = caveats_json
            .as_deref()
            .map(|json| serde_json::from_str(json).map_err(|e| SqlError::Internal(e.to_string())))
            .transpose()?;
        facts.push(PendingSqlFact {
            fact_id,
            authored_id,
            base_canonical_seq,
            request,
            caveats,
            ability,
        });
    }

    Ok(facts)
}

pub fn spawn_actor(
    space_id: String,
    db_name: String,
    base_path: String,
    memory_threshold: u64,
    node_mode: SqlNodeMode,
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
) -> DatabaseHandle {
    let (tx, mut rx) = mpsc::channel::<DbMessage>(32);

    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        let mut host_store = if matches!(node_mode, SqlNodeMode::Host) {
            Some(
                DatabaseStore::open(canonical_path(&base_path, &space_id, &db_name))
                    .expect("Failed to open SQL host database"),
            )
        } else {
            None
        };
        let mut replica_state = if matches!(node_mode, SqlNodeMode::Replica) {
            let canonical = DatabaseStore::open(canonical_path(&base_path, &space_id, &db_name))
                .expect("Failed to open SQL canonical database");
            let provisional_path = provisional_path(&base_path, &space_id, &db_name);
            let provisional = if provisional_path.exists() {
                DatabaseStore::open(provisional_path)
                    .expect("Failed to open SQL provisional database")
            } else {
                clone_store_from(&canonical, provisional_path)
                    .expect("Failed to initialize SQL provisional database")
            };
            let metadata =
                open_metadata_connection(&metadata_path(&base_path, &space_id, &db_name))
                    .expect("Failed to open SQL metadata database");
            Some(ReplicaState {
                canonical,
                provisional,
                metadata,
            })
        } else {
            None
        };

        loop {
            let msg =
                match rt.block_on(async { tokio::time::timeout(IDLE_TIMEOUT, rx.recv()).await }) {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break,
                    Err(_) => break,
                };

            match msg {
                DbMessage::Execute {
                    request,
                    caveats,
                    ability,
                    read_params,
                    response_tx,
                } => {
                    let result = match node_mode {
                        SqlNodeMode::Host => handle_message(
                            &host_store.as_ref().expect("host store").conn,
                            &request,
                            &caveats,
                            &ability,
                            read_params,
                        ),
                        SqlNodeMode::Replica => handle_replica_message(
                            replica_state.as_mut().expect("replica state"),
                            &request,
                            &caveats,
                            &ability,
                            read_params,
                        ),
                    };

                    if result.is_ok() {
                        match node_mode {
                            SqlNodeMode::Host => {
                                if let Some(store) = host_store.as_mut() {
                                    if let Err(error) = store.promote_if_needed(memory_threshold) {
                                        tracing::error!(space=%space_id, db=%db_name, error=%error, "Failed to promote SQL host database");
                                    }
                                }
                            }
                            SqlNodeMode::Replica => {
                                if let Some(state) = replica_state.as_mut() {
                                    if let Err(error) =
                                        state.canonical.promote_if_needed(memory_threshold)
                                    {
                                        tracing::error!(space=%space_id, db=%db_name, error=%error, "Failed to promote SQL canonical database");
                                    }
                                    if let Err(error) =
                                        state.provisional.promote_if_needed(memory_threshold)
                                    {
                                        tracing::error!(space=%space_id, db=%db_name, error=%error, "Failed to promote SQL provisional database");
                                    }
                                }
                            }
                        }
                    }

                    let _ = response_tx.send(result);
                }
                DbMessage::Export { response_tx } => {
                    let result = match node_mode {
                        SqlNodeMode::Host => {
                            handle_export(&host_store.as_ref().expect("host store").conn)
                        }
                        SqlNodeMode::Replica => handle_export(
                            &replica_state
                                .as_ref()
                                .expect("replica state")
                                .canonical
                                .conn,
                        ),
                    };
                    let _ = response_tx.send(result);
                }
                DbMessage::ExportReplication {
                    since_seq,
                    response_tx,
                } => {
                    let result = match node_mode {
                        SqlNodeMode::Host => handle_export_replication(
                            &host_store.as_ref().expect("host store").conn,
                            since_seq,
                        ),
                        SqlNodeMode::Replica => export_replica_replication(
                            replica_state.as_ref().expect("replica state"),
                            since_seq,
                        ),
                    };
                    let _ = response_tx.send(result);
                }
                DbMessage::Import {
                    snapshot,
                    snapshot_reason,
                    canonicalized_authored_ids,
                    response_tx,
                } => {
                    let result = match node_mode {
                        SqlNodeMode::Host => {
                            let store = host_store.as_mut().expect("host store");
                            handle_import(
                                &mut store.conn,
                                &mut store.mode,
                                &store.file_path,
                                memory_threshold,
                                &snapshot,
                                snapshot_reason.as_deref(),
                                &canonicalized_authored_ids,
                            )
                        }
                        SqlNodeMode::Replica => handle_replica_import(
                            replica_state.as_mut().expect("replica state"),
                            memory_threshold,
                            &snapshot,
                            snapshot_reason.as_deref(),
                            &canonicalized_authored_ids,
                        ),
                    };
                    let _ = response_tx.send(result);
                }
                DbMessage::ApplyChangeset {
                    changeset,
                    canonicalized_authored_ids,
                    response_tx,
                } => {
                    let result = match node_mode {
                        SqlNodeMode::Host => handle_apply_changeset(
                            &host_store.as_ref().expect("host store").conn,
                            &changeset,
                            &canonicalized_authored_ids,
                        ),
                        SqlNodeMode::Replica => handle_replica_apply_changeset(
                            replica_state.as_mut().expect("replica state"),
                            memory_threshold,
                            &changeset,
                            &canonicalized_authored_ids,
                        ),
                    };
                    let _ = response_tx.send(result);
                }
                DbMessage::ApplyAuthoredFacts {
                    peer_url,
                    facts,
                    response_tx,
                } => {
                    let result = match node_mode {
                        SqlNodeMode::Host => handle_apply_authored_facts(
                            &host_store.as_ref().expect("host store").conn,
                            peer_url.as_deref(),
                            &facts,
                        ),
                        SqlNodeMode::Replica => Err(SqlError::Internal(
                            "replica nodes cannot canonicalize authored SQL facts".to_string(),
                        )),
                    };
                    let _ = response_tx.send(result);
                }
            }
        }

        match node_mode {
            SqlNodeMode::Host => {
                if let Some(store) = host_store.as_mut() {
                    if let Err(error) = store.flush_if_needed() {
                        tracing::error!(space=%space_id, db=%db_name, error=%error, "Failed to flush SQL host database on shutdown");
                    }
                }
            }
            SqlNodeMode::Replica => {
                if let Some(state) = replica_state.as_mut() {
                    if let Err(error) = state.canonical.flush_if_needed() {
                        tracing::error!(space=%space_id, db=%db_name, error=%error, "Failed to flush SQL canonical database on shutdown");
                    }
                    if let Err(error) = state.provisional.flush_if_needed() {
                        tracing::error!(space=%space_id, db=%db_name, error=%error, "Failed to flush SQL provisional database on shutdown");
                    }
                }
            }
        }

        databases.remove(&(space_id.clone(), db_name.clone()));
        tracing::debug!(space=%space_id, db=%db_name, "Database actor shutting down");
    });

    DatabaseHandle { tx }
}

fn handle_export(conn: &rusqlite::Connection) -> Result<Vec<u8>, SqlError> {
    storage::export_snapshot(conn)
}

fn handle_export_replication(
    conn: &rusqlite::Connection,
    since_seq: Option<i64>,
) -> Result<sql_replication::SqlReplicationExport, SqlError> {
    sql_replication::export_replication(conn, since_seq)
}

fn export_replica_replication(
    state: &ReplicaState,
    since_seq: Option<i64>,
) -> Result<sql_replication::SqlReplicationExport, SqlError> {
    let mut export = sql_replication::export_replication(&state.canonical.conn, since_seq)?;
    export.authored_facts = load_replayable_pending_facts(&state.metadata)?
        .into_iter()
        .map(|fact| sql_replication::SqlAuthoredFact {
            authored_id: fact.authored_id,
            base_canonical_seq: fact.base_canonical_seq,
            request: fact.request,
            caveats: fact.caveats,
            ability: fact.ability,
        })
        .collect();
    Ok(export)
}

fn handle_import(
    conn: &mut rusqlite::Connection,
    mode: &mut StorageMode,
    file_path: &PathBuf,
    memory_threshold: u64,
    snapshot: &[u8],
    snapshot_reason: Option<&str>,
    canonicalized_authored_ids: &[String],
) -> Result<(), SqlError> {
    storage::import_snapshot(conn, snapshot, matches!(mode, StorageMode::File(_)))?;

    if matches!(mode, StorageMode::InMemory) && storage::database_size(conn)? > memory_threshold {
        let new_conn = storage::promote_to_file(conn, file_path)?;
        *conn = new_conn;
        *mode = StorageMode::File(file_path.clone());
    }

    if let Some(reason) = snapshot_reason {
        sql_replication::append_snapshot_barrier(conn, reason)?;
    }

    for authored_id in canonicalized_authored_ids {
        let canonical_seq = sql_replication::current_replication_seq(conn)?;
        sql_replication::record_canonicalized_authored_fact(
            conn,
            authored_id,
            canonical_seq,
            None,
        )?;
    }

    Ok(())
}

fn handle_apply_changeset(
    conn: &rusqlite::Connection,
    changeset: &[u8],
    canonicalized_authored_ids: &[String],
) -> Result<(), SqlError> {
    sql_replication::apply_changeset(conn, changeset)?;
    sql_replication::append_changeset(conn, changeset)?;
    let canonical_seq = sql_replication::current_replication_seq(conn)?;
    for authored_id in canonicalized_authored_ids {
        sql_replication::record_canonicalized_authored_fact(
            conn,
            authored_id,
            canonical_seq,
            None,
        )?;
    }
    Ok(())
}

fn apply_canonicalized_authored_ids(
    state: &mut ReplicaState,
    canonicalized_authored_ids: &[String],
) -> Result<(), SqlError> {
    if canonicalized_authored_ids.is_empty() {
        return Ok(());
    }

    let canonical_seq = sql_replication::current_replication_seq(&state.canonical.conn)?;
    for authored_id in canonicalized_authored_ids {
        sql_replication::record_canonicalized_authored_fact(
            &state.canonical.conn,
            authored_id,
            canonical_seq,
            None,
        )?;
        delete_pending_sql_fact_by_authored_id(&state.metadata, authored_id)?;
    }

    Ok(())
}

fn rebuild_replica_provisional_from_canonical(state: &mut ReplicaState) -> Result<(), SqlError> {
    let snapshot = storage::export_snapshot(&state.canonical.conn)?;
    storage::import_snapshot(
        &mut state.provisional.conn,
        &snapshot,
        matches!(state.provisional.mode, StorageMode::File(_)),
    )?;

    for fact in load_replayable_pending_facts(&state.metadata)? {
        let result = handle_message_local(
            &state.provisional.conn,
            &state.provisional.conn,
            &fact.request,
            &fact.caveats,
            &fact.ability,
        );

        match result {
            Ok(_) => update_pending_sql_fact(&state.metadata, fact.fact_id, "applied", None)?,
            Err(error) => update_pending_sql_fact(
                &state.metadata,
                fact.fact_id,
                "rebase_needed",
                Some(&error.to_string()),
            )?,
        }
    }

    Ok(())
}

fn handle_replica_import(
    state: &mut ReplicaState,
    memory_threshold: u64,
    snapshot: &[u8],
    snapshot_reason: Option<&str>,
    canonicalized_authored_ids: &[String],
) -> Result<(), SqlError> {
    handle_import(
        &mut state.canonical.conn,
        &mut state.canonical.mode,
        &state.canonical.file_path,
        memory_threshold,
        snapshot,
        snapshot_reason,
        canonicalized_authored_ids,
    )?;
    apply_canonicalized_authored_ids(state, canonicalized_authored_ids)?;
    rebuild_replica_provisional_from_canonical(state)
}

fn handle_replica_apply_changeset(
    state: &mut ReplicaState,
    memory_threshold: u64,
    changeset: &[u8],
    canonicalized_authored_ids: &[String],
) -> Result<(), SqlError> {
    handle_apply_changeset(&state.canonical.conn, changeset, canonicalized_authored_ids)?;
    state.canonical.promote_if_needed(memory_threshold)?;
    apply_canonicalized_authored_ids(state, canonicalized_authored_ids)?;
    rebuild_replica_provisional_from_canonical(state)
}

fn handle_apply_authored_facts(
    conn: &rusqlite::Connection,
    peer_url: Option<&str>,
    facts: &[sql_replication::SqlAuthoredFact],
) -> Result<sql_replication::SqlAuthoredFactApplyResult, SqlError> {
    let mut result = sql_replication::SqlAuthoredFactApplyResult::default();

    for fact in facts {
        if sql_replication::canonicalized_authored_fact_exists(conn, &fact.authored_id)? {
            result
                .canonicalized_authored_ids
                .push(fact.authored_id.clone());
            continue;
        }

        match handle_message(
            conn,
            &fact.request,
            &fact.caveats,
            &fact.ability,
            SqlReadParams::Canonical,
        ) {
            Ok(_) => {
                let canonical_seq = sql_replication::current_replication_seq(conn)?;
                sql_replication::record_canonicalized_authored_fact(
                    conn,
                    &fact.authored_id,
                    canonical_seq,
                    peer_url,
                )?;
                result
                    .canonicalized_authored_ids
                    .push(fact.authored_id.clone());
                result.canonicalized_count += 1;
            }
            Err(error) => {
                tracing::warn!(
                    authored_id=%fact.authored_id,
                    error=%error,
                    "failed to canonicalize authored SQL fact"
                );
                result.rejected_count += 1;
            }
        }
    }

    Ok(result)
}

fn execute_statement_without_replication(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[SqlValue],
) -> Result<ExecuteResponse, SqlError> {
    execute_statement(conn, sql, params)
}

fn execute_batch_without_replication(
    conn: &rusqlite::Connection,
    statements: &[SqlStatement],
) -> Result<BatchResponse, SqlError> {
    let mut results = Vec::with_capacity(statements.len());
    for stmt in statements {
        results.push(execute_statement(conn, &stmt.sql, &stmt.params)?);
    }
    Ok(BatchResponse { results })
}

fn handle_message_local(
    read_conn: &rusqlite::Connection,
    write_conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    ability: &str,
) -> Result<SqlResponse, SqlError> {
    let is_admin = matches!(ability, "tinycloud.sql/admin" | "tinycloud.sql/*");

    match request {
        SqlRequest::Query { sql, params } => {
            parser::validate_sql(sql, caveats, ability)?;

            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            read_conn.authorizer(Some(auth));

            let result = execute_query(read_conn, sql, params);

            read_conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result.map(SqlResponse::Query)
        }
        SqlRequest::Execute {
            sql,
            params,
            schema,
        } => {
            if let Some(schema_stmts) = schema {
                for stmt_sql in schema_stmts {
                    parser::validate_sql(stmt_sql, caveats, ability)?;
                    let auth = authorizer::create_authorizer(
                        caveats.clone(),
                        ability.to_string(),
                        is_admin,
                    );
                    write_conn.authorizer(Some(auth));
                    write_conn
                        .execute_batch(stmt_sql)
                        .map_err(|e| SqlError::SchemaError(e.to_string()))?;
                    write_conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                }
            }

            let parsed_query = parser::validate_sql(sql, caveats, ability)?;
            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            write_conn.authorizer(Some(auth));

            let result = if parsed_query.is_read_only {
                execute_query(read_conn, sql, params).map(SqlResponse::Query)
            } else {
                execute_statement_without_replication(write_conn, sql, params)
                    .map(SqlResponse::Execute)
            };

            write_conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result
        }
        SqlRequest::Batch { statements } => {
            let parsed_queries = statements
                .iter()
                .map(|stmt| parser::validate_sql(&stmt.sql, caveats, ability))
                .collect::<Result<Vec<_>, _>>()?;

            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            write_conn.authorizer(Some(auth));

            let result = if parsed_queries.iter().any(|query| query.is_read_only) {
                Err(SqlError::ReadOnlyViolation)
            } else {
                execute_batch_without_replication(write_conn, statements).map(SqlResponse::Batch)
            };

            write_conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result
        }
        SqlRequest::ExecuteStatement { name, params } => {
            let caveats_ref = caveats
                .as_ref()
                .ok_or_else(|| SqlError::InvalidStatement("No caveats found".to_string()))?;
            let prepared = caveats_ref.find_statement(name).ok_or_else(|| {
                SqlError::InvalidStatement(format!("Statement '{}' not found", name))
            })?;

            let parsed_query = parser::validate_sql(&prepared.sql, caveats, ability)?;
            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            let target_conn = if parsed_query.is_read_only {
                read_conn
            } else {
                write_conn
            };
            target_conn.authorizer(Some(auth));

            let result = if parsed_query.is_read_only {
                execute_query(read_conn, &prepared.sql, params).map(SqlResponse::Query)
            } else {
                execute_statement_without_replication(write_conn, &prepared.sql, params)
                    .map(SqlResponse::Execute)
            };

            target_conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
            result
        }
        SqlRequest::Export => Err(SqlError::Internal(
            "Export should be handled by service".to_string(),
        )),
    }
}

fn execute_statement_requires_local_write(
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    ability: &str,
) -> Result<bool, SqlError> {
    match request {
        SqlRequest::Query { .. } | SqlRequest::Export => Ok(false),
        SqlRequest::Execute { sql, .. } => {
            let parsed = parser::validate_sql(sql, caveats, ability)?;
            Ok(!parsed.is_read_only)
        }
        SqlRequest::Batch { statements } => Ok(!statements.is_empty()),
        SqlRequest::ExecuteStatement { name, .. } => {
            let caveats_ref = caveats
                .as_ref()
                .ok_or_else(|| SqlError::InvalidStatement("No caveats found".to_string()))?;
            let prepared = caveats_ref.find_statement(name).ok_or_else(|| {
                SqlError::InvalidStatement(format!("Statement '{}' not found", name))
            })?;
            let parsed = parser::validate_sql(&prepared.sql, caveats, ability)?;
            Ok(!parsed.is_read_only)
        }
    }
}

fn handle_replica_message(
    state: &mut ReplicaState,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    ability: &str,
    read_params: SqlReadParams,
) -> Result<SqlResponse, SqlError> {
    let read_conn = if read_params.uses_provisional() {
        &state.provisional.conn
    } else {
        &state.canonical.conn
    };

    if !execute_statement_requires_local_write(request, caveats, ability)? {
        return handle_message_local(
            read_conn,
            &state.provisional.conn,
            request,
            caveats,
            ability,
        );
    }

    let base_canonical_seq = sql_replication::current_replication_seq(&state.canonical.conn)?;
    let (fact_id, _) = append_pending_sql_fact(
        &state.metadata,
        request,
        caveats,
        ability,
        base_canonical_seq,
    )?;

    let result = handle_message_local(
        read_conn,
        &state.provisional.conn,
        request,
        caveats,
        ability,
    );

    match &result {
        Ok(_) => update_pending_sql_fact(&state.metadata, fact_id, "applied", None)?,
        Err(_) => delete_pending_sql_fact(&state.metadata, fact_id)?,
    }

    result
}

fn handle_message(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    ability: &str,
    _read_params: SqlReadParams,
) -> Result<SqlResponse, SqlError> {
    let is_admin = matches!(ability, "tinycloud.sql/admin" | "tinycloud.sql/*");

    match request {
        SqlRequest::Query { sql, params } => {
            parser::validate_sql(sql, caveats, ability)?;

            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let result = execute_query(conn, sql, params);

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result.map(SqlResponse::Query)
        }
        SqlRequest::Execute {
            sql,
            params,
            schema,
        } => {
            let schema_present = schema.is_some();

            if let Some(schema_stmts) = schema {
                for stmt_sql in schema_stmts {
                    parser::validate_sql(stmt_sql, caveats, ability)?;
                    let auth = authorizer::create_authorizer(
                        caveats.clone(),
                        ability.to_string(),
                        is_admin,
                    );
                    conn.authorizer(Some(auth));
                    conn.execute_batch(stmt_sql)
                        .map_err(|e| SqlError::SchemaError(e.to_string()))?;
                    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                }
            }

            let parsed_query = parser::validate_sql(sql, caveats, ability)?;
            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let result = execute_statement_with_replication(
                conn,
                sql,
                params,
                &parsed_query,
                schema_present,
            );

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result.map(SqlResponse::Execute)
        }
        SqlRequest::Batch { statements } => {
            let parsed_queries = statements
                .iter()
                .map(|stmt| parser::validate_sql(&stmt.sql, caveats, ability))
                .collect::<Result<Vec<_>, _>>()?;

            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let result = execute_batch_with_replication(conn, statements, &parsed_queries);

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result.map(SqlResponse::Batch)
        }
        SqlRequest::ExecuteStatement { name, params } => {
            let caveats_ref = caveats
                .as_ref()
                .ok_or_else(|| SqlError::InvalidStatement("No caveats found".to_string()))?;
            let prepared = caveats_ref.find_statement(name).ok_or_else(|| {
                SqlError::InvalidStatement(format!("Statement '{}' not found", name))
            })?;

            let parsed_query = parser::validate_sql(&prepared.sql, caveats, ability)?;

            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let result = if parsed_query.is_read_only {
                execute_query(conn, &prepared.sql, params).map(SqlResponse::Query)
            } else {
                execute_statement_with_replication(
                    conn,
                    &prepared.sql,
                    params,
                    &parsed_query,
                    false,
                )
                .map(SqlResponse::Execute)
            };

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result
        }
        SqlRequest::Export => Err(SqlError::Internal(
            "Export should be handled by service".to_string(),
        )),
    }
}

fn execute_statement_with_replication(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[SqlValue],
    parsed_query: &parser::ParsedQuery,
    force_snapshot_barrier: bool,
) -> Result<ExecuteResponse, SqlError> {
    let supports_changesets = supports_changeset_capture(parsed_query) && !force_snapshot_barrier;

    if supports_changesets {
        return with_changeset_session(conn, |conn| execute_statement(conn, sql, params));
    }

    let result = execute_statement(conn, sql, params)?;
    if !parsed_query.is_read_only {
        let reason = if force_snapshot_barrier || parsed_query.is_ddl {
            "schema-change"
        } else {
            "unsupported-write"
        };
        sql_replication::append_snapshot_barrier(conn, reason)?;
    }
    Ok(result)
}

fn execute_batch_with_replication(
    conn: &rusqlite::Connection,
    statements: &[SqlStatement],
    parsed_queries: &[parser::ParsedQuery],
) -> Result<BatchResponse, SqlError> {
    let supports_changesets = parsed_queries.iter().all(supports_changeset_capture);

    if supports_changesets {
        return with_changeset_session(conn, |conn| {
            let mut results = Vec::with_capacity(statements.len());
            for stmt in statements {
                results.push(execute_statement(conn, &stmt.sql, &stmt.params)?);
            }
            Ok(BatchResponse { results })
        });
    }

    let mut results = Vec::with_capacity(statements.len());
    for stmt in statements {
        results.push(execute_statement(conn, &stmt.sql, &stmt.params)?);
    }

    let barrier_reason = if parsed_queries.iter().any(|query| query.is_ddl) {
        "schema-change"
    } else if parsed_queries.iter().any(|query| !query.is_read_only) {
        "unsupported-write"
    } else {
        ""
    };
    if !barrier_reason.is_empty() {
        sql_replication::append_snapshot_barrier(conn, barrier_reason)?;
    }

    Ok(BatchResponse { results })
}

fn supports_changeset_capture(parsed_query: &parser::ParsedQuery) -> bool {
    !parsed_query.is_read_only
        && !parsed_query.is_ddl
        && parsed_query.statements.len() == 1
        && matches!(
            parsed_query.statements.first(),
            Some(Statement::Insert { .. } | Statement::Update { .. } | Statement::Delete { .. })
        )
}

fn with_changeset_session<T, F>(conn: &rusqlite::Connection, body: F) -> Result<T, SqlError>
where
    F: FnOnce(&rusqlite::Connection) -> Result<T, SqlError>,
{
    let mut session = Session::new(conn).map_err(|e| SqlError::Internal(e.to_string()))?;
    session.table_filter(Some(|table: &str| {
        !sql_replication::is_internal_table_name(table)
    }));
    session
        .attach(None)
        .map_err(|e| SqlError::Internal(e.to_string()))?;

    let result = body(conn)?;
    if !session.is_empty() {
        let mut changeset = Vec::new();
        session
            .changeset_strm(&mut changeset)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
        sql_replication::append_changeset(conn, &changeset)?;
    }
    Ok(result)
}

fn sql_value_to_rusqlite(v: &SqlValue) -> rusqlite::types::Value {
    rusqlite::types::Value::from(v)
}

fn row_to_sql_value(row: &rusqlite::Row, idx: usize) -> Result<SqlValue, SqlError> {
    let value: rusqlite::types::Value =
        row.get(idx).map_err(|e| SqlError::Sqlite(e.to_string()))?;
    Ok(SqlValue::from(value))
}

fn estimate_value_size(val: &SqlValue) -> usize {
    match val {
        SqlValue::Null => 4,
        SqlValue::Integer(_) => 8,
        SqlValue::Real(_) => 8,
        SqlValue::Text(s) => s.len() + 2,
        SqlValue::Blob(b) => b.len() * 2,
    }
}

fn execute_query(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[SqlValue],
) -> Result<QueryResponse, SqlError> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| SqlError::Sqlite(e.to_string()))?;

    let columns: Vec<String> = stmt.column_names().into_iter().map(String::from).collect();

    let rusqlite_params: Vec<rusqlite::types::Value> =
        params.iter().map(sql_value_to_rusqlite).collect();
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = rusqlite_params
        .iter()
        .map(|p| p as &dyn rusqlite::types::ToSql)
        .collect();

    let mut rows = Vec::new();
    let mut size_estimate: usize = 0;

    let mut query_rows = stmt
        .query(param_refs.as_slice())
        .map_err(|e| SqlError::Sqlite(e.to_string()))?;

    while let Some(row) = query_rows
        .next()
        .map_err(|e| SqlError::Sqlite(e.to_string()))?
    {
        let mut values = Vec::new();
        for i in 0..columns.len() {
            let val = row_to_sql_value(row, i)?;
            size_estimate += estimate_value_size(&val);
            values.push(val);
        }
        rows.push(values);

        if size_estimate > MAX_RESPONSE_SIZE {
            return Err(SqlError::ResponseTooLarge(size_estimate as u64));
        }
    }

    let row_count = rows.len();
    Ok(QueryResponse {
        columns,
        rows,
        row_count,
    })
}

fn execute_statement(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[SqlValue],
) -> Result<ExecuteResponse, SqlError> {
    let rusqlite_params: Vec<rusqlite::types::Value> =
        params.iter().map(sql_value_to_rusqlite).collect();
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = rusqlite_params
        .iter()
        .map(|p| p as &dyn rusqlite::types::ToSql)
        .collect();

    conn.execute(sql, param_refs.as_slice())
        .map_err(|e| SqlError::Sqlite(e.to_string()))?;

    Ok(ExecuteResponse {
        changes: conn.changes(),
        last_insert_row_id: conn.last_insert_rowid(),
    })
}

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use rusqlite::hooks::{AuthContext, Authorization};
use tokio::sync::{mpsc, oneshot};

use super::{
    authorizer,
    caveats::SqlCaveats,
    parser,
    storage::{self, StorageMode},
    types::*,
};

const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB
const MAX_BOUNDED_QUERY_ROWS: usize = 1_000;
const MAX_BOUNDED_QUERY_BYTES: usize = 4 * 1024 * 1024;
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300); // 5 min

enum DbMessage {
    Execute {
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
        growth: GrowthPolicy,
        response_tx: oneshot::Sender<Result<SqlExecutionResult, SqlError>>,
    },
    Export {
        response_tx: oneshot::Sender<Result<Vec<u8>, SqlError>>,
    },
    Checkpoint {
        response_tx: oneshot::Sender<Result<Vec<u8>, SqlError>>,
    },
    Wal {
        response_tx: oneshot::Sender<Result<Option<Vec<u8>>, SqlError>>,
    },
    Shutdown {
        response_tx: oneshot::Sender<()>,
    },
}

/// Whether a write may grow the database file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrowthPolicy {
    Allow,
    /// The space is full: run the request, but undo it and fail with
    /// [`SqlError::StorageWouldGrow`] if the database grew. No-op DDL,
    /// `DELETE` and `DROP` free pages instead of adding them, so they pass.
    Forbid,
}

/// Distinguishes one actor from its replacement for the same (space, db); see
/// the deregistration at the end of [`spawn_actor`].
static NEXT_ACTOR_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone)]
pub struct DatabaseHandle {
    id: u64,
    tx: mpsc::Sender<DbMessage>,
}

impl DatabaseHandle {
    /// Close the connection before acknowledging that its local files can be removed.
    pub(crate) async fn shutdown(&self) -> Result<(), SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Shutdown { response_tx })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".into()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped shutdown response".into()))
    }
    pub async fn execute(
        &self,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
        growth: GrowthPolicy,
    ) -> Result<SqlExecutionResult, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Execute {
                request,
                caveats,
                ability,
                growth,
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

    pub async fn checkpoint(&self) -> Result<Vec<u8>, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Checkpoint { response_tx })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn wal(&self) -> Result<Option<Vec<u8>>, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Wal { response_tx })
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }
}

pub fn spawn_actor(
    space_id: String,
    db_name: String,
    base_path: String,
    memory_threshold: u64,
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
) -> DatabaseHandle {
    let (tx, mut rx) = mpsc::channel::<DbMessage>(32);
    let id = NEXT_ACTOR_ID.fetch_add(1, Ordering::Relaxed);

    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        let file_path = PathBuf::from(&base_path)
            .join(&space_id)
            .join(format!("{}.db", db_name));

        // Check if file already exists -- if so, open from file
        let mut mode = if file_path.exists() {
            StorageMode::File(file_path.clone())
        } else {
            StorageMode::InMemory
        };
        let mut conn = storage::open_connection(&mode).expect("Failed to open database");

        let shutdown_response = loop {
            // Block on receiving with timeout
            let msg =
                match rt.block_on(async { tokio::time::timeout(IDLE_TIMEOUT, rx.recv()).await }) {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break None, // Channel closed
                    Err(_) => break None,   // Idle timeout
                };

            match msg {
                DbMessage::Shutdown { response_tx } => break Some(response_tx),
                DbMessage::Execute {
                    request,
                    caveats,
                    ability,
                    growth,
                    response_tx,
                } => {
                    let result = match growth {
                        GrowthPolicy::Allow => handle_message(&conn, &request, &caveats, &ability),
                        GrowthPolicy::Forbid => {
                            handle_message_without_growth(&conn, &request, &caveats, &ability)
                        }
                    };
                    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

                    // Post-write promotion check
                    if result.is_ok() && matches!(mode, StorageMode::InMemory) {
                        if let Ok(size) = storage::database_size(&conn) {
                            if size > memory_threshold {
                                match storage::promote_to_file(&conn, &file_path) {
                                    Ok(new_conn) => {
                                        conn = new_conn;
                                        mode = StorageMode::File(file_path.clone());
                                        tracing::info!(space=%space_id, db=%db_name, "Promoted database to file storage");
                                    }
                                    Err(e) => {
                                        tracing::error!(space=%space_id, db=%db_name, error=%e, "Failed to promote database to file");
                                    }
                                }
                            }
                        }
                    }

                    let _ = response_tx.send(result);
                }
                DbMessage::Export { response_tx } => {
                    let result = handle_export(&conn, &mode, &file_path);
                    let _ = response_tx.send(result);
                }
                DbMessage::Checkpoint { response_tx } => {
                    let result = handle_checkpoint(&conn, &mode, &file_path);
                    let _ = response_tx.send(result);
                }
                DbMessage::Wal { response_tx } => {
                    let result = handle_wal(&mode, &file_path);
                    let _ = response_tx.send(result);
                }
            }
        };

        // SQLite can checkpoint its WAL on close. Finish that before removing
        // the registry entry or allowing a service to replace the local files.
        drop(conn);

        // Deregister only OUR OWN entry. A replacement actor may already have
        // been hydrated and registered for this key (the dead-actor respawn in
        // `SqlService::execute` does exactly that), and evicting it would send
        // the next request through hydration while it is live — deleting and
        // rewriting the files it holds open by path.
        databases.remove_if(&(space_id.clone(), db_name.clone()), |_, handle| {
            handle.id == id
        });
        tracing::debug!(space=%space_id, db=%db_name, "Database actor shutting down");
        if let Some(response_tx) = shutdown_response {
            let _ = response_tx.send(());
        }
    });

    DatabaseHandle { id, tx }
}

fn handle_wal(mode: &StorageMode, file_path: &Path) -> Result<Option<Vec<u8>>, SqlError> {
    if !matches!(mode, StorageMode::File(_)) {
        return Ok(None);
    }
    match std::fs::read(format!("{}-wal", file_path.display())) {
        Ok(wal) if !wal.is_empty() => Ok(Some(wal)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(SqlError::Internal(error.to_string())),
    }
}

fn handle_export(
    conn: &rusqlite::Connection,
    _mode: &StorageMode,
    _file_path: &PathBuf,
) -> Result<Vec<u8>, SqlError> {
    // Serialize through SQLite's backup API for both in-memory and WAL-backed
    // file databases so the exported artifact contains a complete checkpoint.
    let temp_dir = tempfile::tempdir().map_err(|e| SqlError::Internal(e.to_string()))?;
    let temp_path = temp_dir.path().join("export.db");

    let mut dest =
        rusqlite::Connection::open(&temp_path).map_err(|e| SqlError::Internal(e.to_string()))?;

    {
        let backup = rusqlite::backup::Backup::new(conn, &mut dest)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
        // Copy all pages in one step with no pause (rusqlite rejects the
        // sqlite "-1 = all pages" sentinel, so use i32::MAX). The actor owns
        // `conn` exclusively and every SQL write blocks on this export, so
        // pacing (5 pages / 250ms) caps write throughput at ~80KB/s of
        // database size — a 45MB database makes every write take ~9 minutes
        // (tinycloud-node#112).
        backup
            .run_to_completion(i32::MAX, std::time::Duration::ZERO, None)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    drop(dest);

    std::fs::read(&temp_path).map_err(|e| SqlError::Internal(e.to_string()))
}

fn handle_checkpoint(
    conn: &rusqlite::Connection,
    mode: &StorageMode,
    file_path: &PathBuf,
) -> Result<Vec<u8>, SqlError> {
    match mode {
        StorageMode::File(_) => {
            let busy: i64 = conn
                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
                .map_err(|e| SqlError::Internal(e.to_string()))?;
            if busy != 0 {
                return Err(SqlError::Internal("Database checkpoint is busy".into()));
            }
            std::fs::read(file_path).map_err(|e| SqlError::Internal(e.to_string()))
        }
        StorageMode::InMemory => handle_export(conn, mode, file_path),
    }
}

const GUARD_BEGIN: &str = "SAVEPOINT tinycloud_storage_guard";
const GUARD_KEEP: &str = "RELEASE tinycloud_storage_guard";
const GUARD_UNDO: &str = "ROLLBACK TO tinycloud_storage_guard; RELEASE tinycloud_storage_guard";

/// Run `request` inside a savepoint and keep its effects only if the
/// database did not grow (`PRAGMA page_count` reflects uncommitted pages on
/// this connection). Every failed guarded request is rolled back, including
/// schema entries and batch statements that ran before a later rejection.
fn handle_message_without_growth(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    ability: &str,
) -> Result<SqlExecutionResult, SqlError> {
    let before = page_count(conn)?;
    conn.execute_batch(GUARD_BEGIN)
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    let result = handle_message(conn, request, caveats, ability);
    // An early error return can leave the request's authorizer installed.
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    // ROLLBACK conflict handling can already have undone the transaction.
    if result.is_err() && conn.is_autocommit() {
        return result;
    }
    let grew = page_count(conn).map(|after| after > before);
    let end = match grew {
        Ok(false) if result.is_ok() => GUARD_KEEP,
        // Undo earlier statements on any error, even without page growth.
        _ => GUARD_UNDO,
    };
    if let Err(error) = conn.execute_batch(end) {
        // RELEASE is also the commit for the outermost savepoint. Deferred
        // constraints can fail here and leave both the mutation and savepoint
        // active; undo them before the next request or checkpoint runs.
        if !conn.is_autocommit() {
            conn.execute_batch(GUARD_UNDO)
                .map_err(|e| SqlError::Internal(e.to_string()))?;
        }
        return Err(SqlError::Sqlite(error.to_string()));
    }
    match grew? {
        false => result,
        true => Err(SqlError::StorageWouldGrow),
    }
}

fn page_count(conn: &rusqlite::Connection) -> Result<i64, SqlError> {
    conn.query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|e| SqlError::Internal(e.to_string()))
}

fn handle_message(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    ability: &str,
) -> Result<SqlExecutionResult, SqlError> {
    // TC-119: confers-admin gate (registry-aware). `sql/admin` and `sql/*`
    // (implies admin) pass; identical to the prior `admin | *` match.
    let is_admin = crate::policy_capability::ability_matches(ability, "tinycloud.sql/admin");

    match request {
        SqlRequest::Query {
            sql,
            params,
            max_rows,
            max_bytes,
        } => {
            let parsed = parser::validate_sql(sql, caveats, ability)?;

            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let result = execute_query(conn, sql, params, *max_rows, *max_bytes);

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result.map(|response| SqlExecutionResult {
                response: SqlResponse::Query(response),
                write_targets: parsed.write_targets,
            })
        }
        SqlRequest::Execute {
            sql,
            params,
            schema,
        } => {
            let mut write_targets = Vec::new();
            // Schema init
            if let Some(schema_stmts) = schema {
                for stmt_sql in schema_stmts {
                    let parsed = parser::validate_sql(stmt_sql, caveats, ability)?;
                    write_targets.extend(parsed.write_targets);
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

            let parsed = parser::validate_sql(sql, caveats, ability)?;
            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let result = execute_statement(conn, sql, params, is_insert_statement(&parsed));

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            let response = result.map(SqlResponse::Execute)?;
            write_targets.extend(parsed.write_targets);
            Ok(SqlExecutionResult {
                response,
                write_targets,
            })
        }
        SqlRequest::Batch { statements } => {
            let mut write_targets = Vec::new();
            let mut insert_statements = Vec::with_capacity(statements.len());
            // Hooks are emitted only after this branch returns Ok to the caller.
            // If a later statement fails after some earlier statements applied,
            // MVP intentionally under-emits rather than guessing partial success.
            for stmt in statements {
                let parsed = parser::validate_sql(&stmt.sql, caveats, ability)?;
                insert_statements.push(is_insert_statement(&parsed));
                write_targets.extend(parsed.write_targets);
            }

            let mut results = Vec::new();
            for (stmt, is_insert) in statements.iter().zip(insert_statements) {
                let auth =
                    authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
                conn.authorizer(Some(auth));
                let result = execute_statement(conn, &stmt.sql, &stmt.params, is_insert);
                conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                results.push(result?);
            }

            Ok(SqlExecutionResult {
                response: SqlResponse::Batch(BatchResponse { results }),
                write_targets,
            })
        }
        SqlRequest::ExecuteStatement { name, params } => {
            let caveats_ref = caveats
                .as_ref()
                .ok_or_else(|| SqlError::InvalidStatement("No caveats found".to_string()))?;
            let prepared = caveats_ref.find_statement(name).ok_or_else(|| {
                SqlError::InvalidStatement(format!("Statement '{}' not found", name))
            })?;

            let parsed = parser::validate_sql(&prepared.sql, caveats, ability)?;

            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let result = if is_query_statement(&parsed) {
                execute_query(conn, &prepared.sql, params, None, None).map(SqlResponse::Query)
            } else {
                execute_statement(conn, &prepared.sql, params, is_insert_statement(&parsed))
                    .map(SqlResponse::Execute)
            };

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result.map(|response| SqlExecutionResult {
                response,
                write_targets: parsed.write_targets,
            })
        }
        SqlRequest::Export => Err(SqlError::Internal(
            "Export should be handled by service".to_string(),
        )),
    }
}

fn sql_value_to_rusqlite(v: &SqlValue) -> rusqlite::types::Value {
    rusqlite::types::Value::from(v)
}

fn row_to_sql_value(row: &rusqlite::Row, idx: usize) -> Result<SqlValue, SqlError> {
    let value: rusqlite::types::Value =
        row.get(idx).map_err(|e| SqlError::Sqlite(e.to_string()))?;
    Ok(SqlValue::from(value))
}

fn is_query_statement(parsed: &parser::ParsedQuery) -> bool {
    matches!(
        parsed.statements.as_slice(),
        [sqlparser::ast::Statement::Query(_)]
    )
}

fn is_insert_statement(parsed: &parser::ParsedQuery) -> bool {
    matches!(
        parsed.statements.as_slice(),
        [sqlparser::ast::Statement::Insert { .. }]
    )
}

fn execute_query(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[SqlValue],
    max_rows: Option<usize>,
    max_bytes: Option<usize>,
) -> Result<QueryResponse, SqlError> {
    validate_query_limits(max_rows, max_bytes)?;
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
    let response_limit = max_bytes.unwrap_or(MAX_RESPONSE_SIZE);
    let mut serialized_size = serde_json::to_vec(&QueryResponse {
        columns: columns.clone(),
        rows: Vec::new(),
        row_count: 0,
    })
    .map_err(|e| SqlError::Internal(format!("Failed to serialize query response: {e}")))?
    .len();
    if serialized_size > response_limit {
        return Err(SqlError::ResponseTooLarge(serialized_size as u64));
    }

    let mut query_rows = stmt
        .query(param_refs.as_slice())
        .map_err(|e| SqlError::Sqlite(e.to_string()))?;

    while let Some(row) = query_rows
        .next()
        .map_err(|e| SqlError::Sqlite(e.to_string()))?
    {
        if max_rows.is_some_and(|limit| rows.len() >= limit) {
            return Err(SqlError::ResponseTooLarge(serialized_size as u64));
        }
        let mut values = Vec::new();
        for i in 0..columns.len() {
            let val = row_to_sql_value(row, i)?;
            values.push(val);
        }

        let row_size = serde_json::to_vec(&values)
            .map_err(|e| SqlError::Internal(format!("Failed to serialize query row: {e}")))?
            .len();
        let old_row_count_digits = rows.len().to_string().len();
        let new_row_count_digits = (rows.len() + 1).to_string().len();
        serialized_size +=
            row_size + usize::from(!rows.is_empty()) + new_row_count_digits - old_row_count_digits;
        if serialized_size > response_limit {
            return Err(SqlError::ResponseTooLarge(serialized_size as u64));
        }
        rows.push(values);
    }

    let row_count = rows.len();
    let response = QueryResponse {
        columns,
        rows,
        row_count,
    };
    let serialized_size = serde_json::to_vec(&response)
        .map_err(|e| SqlError::Internal(format!("Failed to serialize query response: {e}")))?
        .len();
    if serialized_size > response_limit {
        return Err(SqlError::ResponseTooLarge(serialized_size as u64));
    }

    Ok(response)
}

fn validate_query_limits(
    max_rows: Option<usize>,
    max_bytes: Option<usize>,
) -> Result<(), SqlError> {
    if max_rows.is_some_and(|value| value == 0 || value > MAX_BOUNDED_QUERY_ROWS) {
        return Err(SqlError::InvalidStatement(format!(
            "maxRows must be between 1 and {MAX_BOUNDED_QUERY_ROWS}"
        )));
    }
    if max_bytes.is_some_and(|value| value == 0 || value > MAX_BOUNDED_QUERY_BYTES) {
        return Err(SqlError::InvalidStatement(format!(
            "maxBytes must be between 1 and {MAX_BOUNDED_QUERY_BYTES}"
        )));
    }
    Ok(())
}

fn execute_statement(
    conn: &rusqlite::Connection,
    sql: &str,
    params: &[SqlValue],
    is_insert: bool,
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
        last_insert_row_id: is_insert.then(|| conn.last_insert_rowid()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tc626_review_release_escape_cannot_survive_checkpoint() {
        for memory_threshold in [u64::MAX, 0] {
            let dir = tempfile::tempdir().unwrap();
            let actor = spawn_actor(
                "space".into(),
                "guard".into(),
                dir.path().to_str().unwrap().into(),
                memory_threshold,
                Arc::new(DashMap::new()),
            );
            actor
                .execute(
                    SqlRequest::Execute {
                        schema: None,
                        sql: "CREATE TABLE data (value TEXT)".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                    GrowthPolicy::Allow,
                )
                .await
                .unwrap();
            actor
                .execute(
                    SqlRequest::Execute {
                        schema: Some(vec![
                            "PRAGMA user_version = 1; RELEASE tinycloud_storage_guard".into(),
                        ]),
                        sql: "INSERT INTO data VALUES (hex(zeroblob(65536)))".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                    GrowthPolicy::Forbid,
                )
                .await
                .expect_err("the caller must not release the storage guard");

            let result = actor
                .execute(
                    SqlRequest::Query {
                        sql: "SELECT count(*) FROM data".into(),
                        params: vec![],
                        max_rows: None,
                        max_bytes: None,
                    },
                    None,
                    "tinycloud.sql/read".into(),
                    GrowthPolicy::Allow,
                )
                .await
                .unwrap();
            let SqlResponse::Query(response) = result.response else {
                panic!("expected query response");
            };
            assert_eq!(response.rows, vec![vec![SqlValue::Integer(0)]]);

            let checkpoint = actor.checkpoint().await.unwrap();
            let restored_path = dir.path().join("restored.db");
            std::fs::write(&restored_path, checkpoint).unwrap();
            let restored = rusqlite::Connection::open(restored_path).unwrap();
            let count: i64 = restored
                .query_row("SELECT count(*) FROM data", [], |row| row.get(0))
                .unwrap();
            let version: i64 = restored
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(
                count, 0,
                "a later checkpoint must not persist rejected data"
            );
            assert_eq!(version, 0, "the rejected schema entry must also be undone");
        }
    }

    #[test]
    fn tc626_review_transaction_controls_undo_earlier_schema_entries() {
        for control in [
            "RELEASE tinycloud_storage_guard",
            "RELEASE SAVEPOINT tinycloud_storage_guard",
            "ROLLBACK",
            "ROLLBACK TO tinycloud_storage_guard",
            "COMMIT",
            "END",
            "SAVEPOINT caller_savepoint",
            "BEGIN",
        ] {
            for prefix in ["", "PRAGMA user_version = 1; /* boundary; */ "] {
                let conn = storage::open_connection(&StorageMode::InMemory).unwrap();
                conn.execute_batch(
                    "CREATE TABLE data (value TEXT); INSERT INTO data VALUES ('before')",
                )
                .unwrap();
                let sql = format!("{prefix}{control}");
                let result = handle_message_without_growth(
                    &conn,
                    &SqlRequest::Execute {
                        schema: Some(vec![
                            "UPDATE data SET value = 'rejected'".into(),
                            sql.clone(),
                        ]),
                        sql: "UPDATE data SET value = 'escaped'".into(),
                        params: vec![],
                    },
                    &None,
                    "tinycloud.sql/admin",
                );
                assert!(result.is_err(), "transaction control was accepted: {sql}");
                let value: String = conn
                    .query_row("SELECT value FROM data", [], |row| row.get(0))
                    .unwrap();
                let version: i64 = conn
                    .query_row("PRAGMA user_version", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(value, "before", "earlier schema entry survived {sql}");
                assert_eq!(version, 0, "PRAGMA mutation survived {sql}");
                assert!(
                    conn.is_autocommit(),
                    "request left a transaction open: {sql}"
                );
            }
        }
    }

    #[test]
    fn tc626_review_single_pragma_preserves_quoted_semicolons_and_comments() {
        let conn = storage::open_connection(&StorageMode::InMemory).unwrap();
        conn.execute_batch("CREATE TABLE \"quoted;name\" (value TEXT)")
            .unwrap();
        let result = handle_message_without_growth(
            &conn,
            &SqlRequest::Query {
                sql: "-- leading ;\nPRAGMA table_info('quoted;name'); /* trailing ; */".into(),
                params: vec![],
                max_rows: None,
                max_bytes: None,
            },
            &None,
            "tinycloud.sql/admin",
        )
        .unwrap();
        let SqlResponse::Query(response) = result.response else {
            panic!("expected query response");
        };
        assert_eq!(response.rows[0][1], SqlValue::Text("value".into()));

        handle_message_without_growth(
            &conn,
            &SqlRequest::Execute {
                schema: Some(vec!["PRAGMA user_version = 7; -- trailing ;".into()]),
                sql: "UPDATE \"quoted;name\" SET value = 'unused'".into(),
                params: vec![],
            },
            &None,
            "tinycloud.sql/admin",
        )
        .unwrap();
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 7);
        assert!(conn.is_autocommit());
    }

    #[test]
    fn growth_guard_rolls_back_failed_deferred_commit() {
        let conn = storage::open_connection(&StorageMode::InMemory).unwrap();
        conn.execute_batch(
            "CREATE TABLE parents (id INTEGER PRIMARY KEY);
             CREATE TABLE children (
                 parent_id INTEGER REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED
             );
             INSERT INTO parents VALUES (1);
             INSERT INTO children VALUES (1);",
        )
        .unwrap();
        let error = handle_message_without_growth(
            &conn,
            &SqlRequest::Execute {
                schema: None,
                sql: "DELETE FROM parents".into(),
                params: vec![],
            },
            &None,
            "tinycloud.sql/write",
        )
        .unwrap_err();
        assert!(matches!(error, SqlError::Sqlite(_)));

        // The failed RELEASE must not leave a deleted parent or an open outer
        // transaction that swallows the next request's successful commit.
        handle_message_without_growth(
            &conn,
            &SqlRequest::Execute {
                schema: None,
                sql: "DELETE FROM children".into(),
                params: vec![],
            },
            &None,
            "tinycloud.sql/write",
        )
        .unwrap();
        assert!(conn.is_autocommit());
        let parents: i64 = conn
            .query_row("SELECT count(*) FROM parents", [], |row| row.get(0))
            .unwrap();
        let children: i64 = conn
            .query_row("SELECT count(*) FROM children", [], |row| row.get(0))
            .unwrap();
        assert_eq!((parents, children), (1, 0));
    }

    #[test]
    fn bounded_query_rejects_more_rows_than_requested() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let err = execute_query(&conn, "SELECT 1 UNION ALL SELECT 2", &[], Some(1), None)
            .expect_err("the second row must exceed maxRows");

        assert!(matches!(err, SqlError::ResponseTooLarge(_)));
    }

    #[test]
    fn bounded_query_rejects_response_larger_than_requested() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let err = execute_query(&conn, "SELECT 'payload'", &[], None, Some(1))
            .expect_err("the text value must exceed maxBytes");

        assert!(matches!(err, SqlError::ResponseTooLarge(_)));
    }

    #[test]
    fn bounded_query_uses_exact_serialized_response_size() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let cases = [
            "SELECT 'quoted \\\"text\\\" and \\n newline' AS escaped",
            "SELECT 9223372036854775807 AS largest_integer",
            "SELECT X'0001FEFF' AS blob",
            "SELECT 1 AS one, 2 AS two, 3 AS three, 4 AS four, 5 AS five",
            "SELECT 1 UNION ALL SELECT 2 UNION ALL SELECT 3 UNION ALL SELECT 4 \
             UNION ALL SELECT 5 UNION ALL SELECT 6 UNION ALL SELECT 7 UNION ALL SELECT 8 \
             UNION ALL SELECT 9 UNION ALL SELECT 10",
        ];

        for sql in cases {
            let response = execute_query(&conn, sql, &[], None, None).unwrap();
            let exact_size = serde_json::to_vec(&response).unwrap().len();

            execute_query(&conn, sql, &[], None, Some(exact_size))
                .expect("the exact serialized response size must be accepted");
            let err = execute_query(&conn, sql, &[], None, Some(exact_size - 1))
                .expect_err("one byte below the serialized response size must fail");
            assert!(matches!(
                err,
                SqlError::ResponseTooLarge(actual) if actual == exact_size as u64
            ));
        }
    }

    #[test]
    fn only_insert_responses_include_last_insert_row_id() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT)")
            .unwrap();

        let insert = handle_message(
            &conn,
            &SqlRequest::Execute {
                sql: "INSERT INTO items (value) VALUES ('before')".to_string(),
                params: vec![],
                schema: None,
            },
            &None,
            "tinycloud.sql/write",
        )
        .unwrap();
        let SqlResponse::Execute(insert) = insert.response else {
            panic!("expected execute response");
        };
        assert_eq!(insert.last_insert_row_id, Some(1));

        for sql in [
            "UPDATE items SET value = 'after' WHERE id = 1",
            "DELETE FROM items WHERE id = 1",
        ] {
            let result = handle_message(
                &conn,
                &SqlRequest::Execute {
                    sql: sql.to_string(),
                    params: vec![],
                    schema: None,
                },
                &None,
                "tinycloud.sql/write",
            )
            .unwrap();
            let SqlResponse::Execute(response) = result.response else {
                panic!("expected execute response");
            };
            assert_eq!(response.last_insert_row_id, None);
            assert_eq!(
                serde_json::to_value(response).unwrap()["lastInsertRowId"],
                serde_json::Value::Null
            );
        }
    }

    #[test]
    fn batch_and_prepared_updates_do_not_reuse_insert_row_id() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE items (id INTEGER PRIMARY KEY, value TEXT)")
            .unwrap();

        let batch = handle_message(
            &conn,
            &SqlRequest::Batch {
                statements: vec![
                    SqlStatement {
                        sql: "INSERT INTO items (value) VALUES ('before')".to_string(),
                        params: vec![],
                    },
                    SqlStatement {
                        sql: "UPDATE items SET value = 'during' WHERE id = 1".to_string(),
                        params: vec![],
                    },
                ],
            },
            &None,
            "tinycloud.sql/write",
        )
        .unwrap();
        let SqlResponse::Batch(batch) = batch.response else {
            panic!("expected batch response");
        };
        assert_eq!(batch.results[0].last_insert_row_id, Some(1));
        assert_eq!(batch.results[1].last_insert_row_id, None);

        let caveats = SqlCaveats {
            statements: Some(vec![crate::sql::caveats::PreparedStatement {
                name: "update_item".to_string(),
                sql: "UPDATE items SET value = 'after' WHERE id = 1".to_string(),
            }]),
            ..Default::default()
        };
        let prepared = handle_message(
            &conn,
            &SqlRequest::ExecuteStatement {
                name: "update_item".to_string(),
                params: vec![],
            },
            &Some(caveats),
            "tinycloud.sql/write",
        )
        .unwrap();
        let SqlResponse::Execute(prepared) = prepared.response else {
            panic!("expected execute response");
        };
        assert_eq!(prepared.last_insert_row_id, None);
    }

    #[test]
    fn batch_does_not_reuse_schema_authorizer_state_between_statements() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE source (id INTEGER); INSERT INTO source VALUES (1)")
            .unwrap();

        let error = handle_message(
            &conn,
            &SqlRequest::Batch {
                statements: vec![
                    SqlStatement {
                        sql: "CREATE INDEX source_idx ON source(id)".to_string(),
                        params: vec![],
                    },
                    SqlStatement {
                        sql: "CREATE TABLE copied AS SELECT id FROM source".to_string(),
                        params: vec![],
                    },
                ],
            },
            &None,
            "tinycloud.sql/schema",
        )
        .expect_err("a prior DDL statement must not authorize a later CTAS source read");
        assert!(
            error.to_string().contains("not authorized")
                || error.to_string().contains("is prohibited"),
            "expected an authorization error, got: {error}"
        );
        let copied_tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM sqlite_schema WHERE type = 'table' AND name = 'copied'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(copied_tables, 0, "failed CTAS must not leave its table");
    }

    #[test]
    fn bounded_query_validates_public_limits() {
        assert!(matches!(
            validate_query_limits(Some(0), None),
            Err(SqlError::InvalidStatement(_))
        ));
        assert!(matches!(
            validate_query_limits(Some(MAX_BOUNDED_QUERY_ROWS + 1), None),
            Err(SqlError::InvalidStatement(_))
        ));
        assert!(matches!(
            validate_query_limits(None, Some(MAX_BOUNDED_QUERY_BYTES + 1)),
            Err(SqlError::InvalidStatement(_))
        ));
    }
}

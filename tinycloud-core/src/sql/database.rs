//! Request context travels with each actor message, not with the actor's idle
//! loop. Query metrics measure explicit native SQL calls (one attempt per
//! prepare/query lifecycle or execute/execute_batch call), including failures
//! and request-originated maintenance. Queueing, response serialization,
//! filesystem I/O, native backup and implicit connection-close work are not
//! SQL query time.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use rusqlite::hooks::{AuthContext, Authorization};
use tokio::sync::{mpsc, oneshot};

use crate::request_telemetry::{self, QueryTimer, RequestContext};

use super::{
    authority::{record_ddl_without_schema, SqlAuthority},
    authorizer::StatementScope,
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
    Publication {
        command: serde_json::Value,
        response_tx: oneshot::Sender<Result<SqlExecutionResult, SqlError>>,
    },
    Execute {
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
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
    tx: mpsc::Sender<(Option<Arc<RequestContext>>, DbMessage)>,
}

impl DatabaseHandle {
    /// Close the connection before acknowledging that its local files can be removed.
    pub(crate) async fn shutdown(&self) -> Result<(), SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Shutdown { response_tx },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".into()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped shutdown response".into()))
    }

    pub(crate) async fn publication(
        &self,
        command: serde_json::Value,
    ) -> Result<SqlExecutionResult, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Publication {
                    command,
                    response_tx,
                },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".into()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".into()))?
    }
    pub async fn execute(
        &self,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
        growth: GrowthPolicy,
    ) -> Result<SqlExecutionResult, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Execute {
                    request,
                    caveats,
                    authority,
                    growth,
                    response_tx,
                },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn export(&self) -> Result<Vec<u8>, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Export { response_tx },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn checkpoint(&self) -> Result<Vec<u8>, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((
                request_telemetry::current(),
                DbMessage::Checkpoint { response_tx },
            ))
            .await
            .map_err(|_| SqlError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| SqlError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn wal(&self) -> Result<Option<Vec<u8>>, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send((request_telemetry::current(), DbMessage::Wal { response_tx }))
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
    let (tx, mut rx) = mpsc::channel::<(Option<Arc<RequestContext>>, DbMessage)>(32);
    let id = NEXT_ACTOR_ID.fetch_add(1, Ordering::Relaxed);
    let initial_context = request_telemetry::current();

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
        let mut conn = {
            let _context = request_telemetry::enter(initial_context);
            let Ok(connection) = storage::open_connection(&mode) else {
                tracing::error!("Failed to open database");
                databases.remove_if(&(space_id, db_name), |_, handle| handle.id == id);
                return;
            };
            connection
        };

        let shutdown_response = loop {
            // Block on receiving with timeout
            let (context, msg) =
                match rt.block_on(async { tokio::time::timeout(IDLE_TIMEOUT, rx.recv()).await }) {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break None, // Channel closed
                    Err(_) => break None,   // Idle timeout
                };
            let _context = request_telemetry::enter(context);

            match msg {
                DbMessage::Shutdown { response_tx } => break Some(response_tx),
                DbMessage::Publication {
                    command,
                    response_tx,
                } => {
                    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                    let result =
                        super::publication::execute(&conn, &space_id, &command).map(|receipt| {
                            SqlExecutionResult {
                                response: SqlResponse::Query(QueryResponse {
                                    columns: vec!["receipt".into()],
                                    rows: vec![vec![SqlValue::Text(receipt.to_string())]],
                                    row_count: 1,
                                }),
                                write_targets: vec![],
                            }
                        });
                    let _ = response_tx.send(result);
                }
                DbMessage::Execute {
                    request,
                    caveats,
                    authority,
                    growth,
                    response_tx,
                } => {
                    let result = match growth {
                        GrowthPolicy::Allow => {
                            handle_message(&conn, &request, &caveats, &authority)
                        }
                        GrowthPolicy::Forbid => {
                            handle_message_without_growth(&conn, &request, &caveats, &authority)
                        }
                    };
                    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

                    // TC-1586: a PRAGMA changes connection state that would
                    // outlive the request on this shared connection.
                    if request_has_pragma(&request, &caveats)
                        && storage::reset_connection_state(&conn, &mode).is_err()
                    {
                        tracing::error!("Failed to reset SQL connection state");
                    }

                    // Post-write promotion check
                    if result.is_ok() && matches!(mode, StorageMode::InMemory) {
                        if let Ok(size) = storage::database_size(&conn) {
                            if size > memory_threshold {
                                match storage::promote_to_file(&conn, &file_path) {
                                    Ok(new_conn) => {
                                        conn = new_conn;
                                        mode = StorageMode::File(file_path.clone());
                                        tracing::info!("Promoted database to file storage");
                                    }
                                    Err(_) => {
                                        tracing::error!("Failed to promote database to file");
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
        tracing::debug!("Database actor shutting down");
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
            let busy: i64 = {
                let _timer = QueryTimer::new();
                conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
                    .map_err(|e| SqlError::Internal(e.to_string()))?
            };
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
    authority: &SqlAuthority,
) -> Result<SqlExecutionResult, SqlError> {
    let before = page_count(conn)?;
    {
        let _timer = QueryTimer::new();
        conn.execute_batch(GUARD_BEGIN)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }
    let result = handle_message(conn, request, caveats, authority);
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
    let end_result = {
        let _timer = QueryTimer::new();
        conn.execute_batch(end)
    };
    if let Err(error) = end_result {
        // RELEASE is also the commit for the outermost savepoint. Deferred
        // constraints can fail here and leave both the mutation and savepoint
        // active; undo them before the next request or checkpoint runs.
        if !conn.is_autocommit() {
            let _timer = QueryTimer::new();
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
    let _timer = QueryTimer::new();
    conn.query_row("PRAGMA page_count", [], |row| row.get(0))
        .map_err(|e| SqlError::Internal(e.to_string()))
}

/// `DdlPolicy::Log` bookkeeping for one request: count every statement that
/// only `write` let through, and warn once. The message is constant and the
/// counter is labelled by statement kind alone, so neither carries SQL text,
/// space ids, DIDs or table names.
#[derive(Default)]
struct DdlLog {
    warned: bool,
}

impl DdlLog {
    fn note(&mut self, parsed: &parser::ParsedQuery) {
        let Some(kind) = parsed.ddl_without_schema else {
            return;
        };
        record_ddl_without_schema(kind);
        if !self.warned {
            self.warned = true;
            tracing::warn!("sql ddl allowed without schema ability (ddl_requires_schema = log)");
        }
    }
}

fn handle_message(
    conn: &rusqlite::Connection,
    request: &SqlRequest,
    caveats: &Option<SqlCaveats>,
    authority: &SqlAuthority,
) -> Result<SqlExecutionResult, SqlError> {
    let mut ddl_log = DdlLog::default();
    let authorizer = |parsed: &parser::ParsedQuery| {
        super::authorizer::create_authorizer(caveats.clone(), authority, StatementScope::of(parsed))
    };

    match request {
        SqlRequest::Query {
            sql,
            params,
            max_rows,
            max_bytes,
        } => {
            let parsed = parser::validate_sql(sql, caveats, authority)?;
            ddl_log.note(&parsed);

            conn.authorizer(Some(authorizer(&parsed)));

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
            // Schema init. Each entry is judged like any other statement: a
            // schema-changing entry needs a schema-conferring ability.
            if let Some(schema_stmts) = schema {
                for stmt_sql in schema_stmts {
                    let parsed = parser::validate_sql(stmt_sql, caveats, authority)?;
                    ddl_log.note(&parsed);
                    write_targets.extend(parsed.write_targets.iter().cloned());
                    conn.authorizer(Some(authorizer(&parsed)));
                    {
                        let _timer = QueryTimer::new();
                        conn.execute_batch(stmt_sql)
                            .map_err(|e| SqlError::SchemaError(e.to_string()))?;
                    }
                    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                }
            }

            let parsed = parser::validate_sql(sql, caveats, authority)?;
            ddl_log.note(&parsed);
            conn.authorizer(Some(authorizer(&parsed)));

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
            let mut scopes = Vec::with_capacity(statements.len());
            // Hooks are emitted only after this branch returns Ok to the caller.
            // If a later statement fails after some earlier statements applied,
            // MVP intentionally under-emits rather than guessing partial success.
            for stmt in statements {
                let parsed = parser::validate_sql(&stmt.sql, caveats, authority)?;
                ddl_log.note(&parsed);
                insert_statements.push(is_insert_statement(&parsed));
                scopes.push(StatementScope::of(&parsed));
                write_targets.extend(parsed.write_targets);
            }

            let mut results = Vec::new();
            for ((stmt, is_insert), scope) in statements.iter().zip(insert_statements).zip(scopes) {
                let auth = super::authorizer::create_authorizer(caveats.clone(), authority, scope);
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

            // A named statement is judged as the SQL it holds: one that
            // resolves to DDL needs a schema-conferring ability on the
            // invocation, like the same SQL sent directly.
            let parsed = parser::validate_sql(&prepared.sql, caveats, authority)?;
            ddl_log.note(&parsed);

            conn.authorizer(Some(authorizer(&parsed)));

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
    // A `WITH … INSERT/UPDATE` is a Query to the parser but runs as a write.
    parsed.is_read_only
        && matches!(
            parsed.statements.as_slice(),
            [sqlparser::ast::Statement::Query(_)]
        )
}

/// Whether any statement the request carries is a PRAGMA, including the one a
/// named statement resolves to. Parse-free: only the first token is read.
fn request_has_pragma(request: &SqlRequest, caveats: &Option<SqlCaveats>) -> bool {
    let pragma = parser::is_pragma_sql;
    match request {
        SqlRequest::Query { sql, .. } => pragma(sql),
        SqlRequest::Execute { sql, schema, .. } => {
            pragma(sql) || schema.iter().flatten().any(|statement| pragma(statement))
        }
        SqlRequest::Batch { statements } => {
            statements.iter().any(|statement| pragma(&statement.sql))
        }
        SqlRequest::ExecuteStatement { name, .. } => caveats
            .as_ref()
            .and_then(|caveats| caveats.find_statement(name))
            .is_some_and(|statement| pragma(&statement.sql)),
        SqlRequest::Export => false,
    }
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
    let mut timer = QueryTimer::new();
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| SqlError::Sqlite(e.to_string()))?;
    timer.pause();

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

    timer.resume();
    let mut query_rows = stmt
        .query(param_refs.as_slice())
        .map_err(|e| SqlError::Sqlite(e.to_string()))?;
    timer.pause();

    loop {
        timer.resume();
        let next = query_rows.next();
        timer.pause();
        let Some(row) = next.map_err(|e| SqlError::Sqlite(e.to_string()))? else {
            break;
        };
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

    {
        let _timer = QueryTimer::new();
        conn.execute(sql, param_refs.as_slice())
            .map_err(|e| SqlError::Sqlite(e.to_string()))?;
    }

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
                    &SqlAuthority::from("tinycloud.sql/admin"),
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
            &SqlAuthority::from("tinycloud.sql/admin"),
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
            &SqlAuthority::from("tinycloud.sql/admin"),
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
            &SqlAuthority::from("tinycloud.sql/write"),
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
            &SqlAuthority::from("tinycloud.sql/write"),
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
            &SqlAuthority::from("tinycloud.sql/write"),
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
                &SqlAuthority::from("tinycloud.sql/write"),
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
            &SqlAuthority::from("tinycloud.sql/write"),
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
            &SqlAuthority::from("tinycloud.sql/write"),
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
            &SqlAuthority::from("tinycloud.sql/schema"),
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

#[cfg(test)]
mod publication_rollback_tests {
    use super::*;
    #[test]
    fn publication_rollback_restores_authorized_legacy_sql_and_bookkeeping() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE connector_meeting(id TEXT PRIMARY KEY,title TEXT,metadata TEXT,publication_state TEXT); INSERT INTO connector_meeting VALUES('old','Published','{}','published'); CREATE TABLE connector_publication_control(id INTEGER PRIMARY KEY,active INTEGER NOT NULL); INSERT INTO connector_publication_control VALUES(1,1);").unwrap();
        for sql in [
            "UPDATE connector_meeting SET title='Original',metadata='{ \"kept\": true }',publication_state=NULL WHERE id='old'",
            "UPDATE connector_publication_control SET active=0 WHERE id=1",
            "INSERT INTO connector_meeting(id,title) VALUES('new','Legacy sync')",
            "DELETE FROM connector_meeting WHERE id='new'",
        ] {
            handle_message(&conn, &SqlRequest::Execute { sql: sql.into(), params: vec![], schema: None }, &None, &SqlAuthority::from("tinycloud.sql/write")).unwrap_or_else(|error| panic!("legacy recovery rejected: {error}"));
        }
        assert_eq!(
            conn.query_row(
                "SELECT title,metadata,publication_state FROM connector_meeting WHERE id='old'",
                [],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?
                ))
            )
            .unwrap(),
            ("Original".into(), "{ \"kept\": true }".into(), None)
        );
        assert_eq!(
            conn.query_row(
                "SELECT active FROM connector_publication_control",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn publication_rollback_keeps_normal_read_only_authority() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE connector_meeting(id TEXT PRIMARY KEY,title TEXT); INSERT INTO connector_meeting VALUES('old','Original'); CREATE TABLE connector_publication_control(id INTEGER PRIMARY KEY,active INTEGER NOT NULL); INSERT INTO connector_publication_control VALUES(1,1);").unwrap();
        let result = handle_message(
            &conn,
            &SqlRequest::Execute {
                sql: "UPDATE connector_meeting SET title='Unauthorized'".into(),
                params: vec![],
                schema: None,
            },
            &None,
            &SqlAuthority::from("tinycloud.sql/read"),
        );
        assert!(result.is_err());
        assert_eq!(
            conn.query_row("SELECT title FROM connector_meeting", [], |row| row
                .get::<_, String>(0))
                .unwrap(),
            "Original"
        );
    }
}

/// TC-1581: schema-changing statements need `schema`; `write` is data only.
/// Every request variant is judged statement by statement against all the
/// abilities held, not against one preferred ability.
#[cfg(test)]
mod ddl_authority_tests {
    use super::*;
    use crate::sql::authority::{ddl_without_schema_count, DdlKind, DdlPolicy};
    use std::sync::{Arc, Mutex};

    const READ: &str = "tinycloud.sql/read";
    const WRITE: &str = "tinycloud.sql/write";
    const SCHEMA: &str = "tinycloud.sql/schema";
    const ADMIN: &str = "tinycloud.sql/admin";
    const STAR: &str = "tinycloud.sql/*";

    fn held(abilities: &[&str]) -> SqlAuthority {
        SqlAuthority::new(abilities.iter().copied())
    }

    fn execute(sql: &str, schema: Option<&[&str]>) -> SqlRequest {
        SqlRequest::Execute {
            sql: sql.to_string(),
            params: vec![],
            schema: schema.map(|s| s.iter().map(|s| s.to_string()).collect()),
        }
    }

    fn batch(statements: &[&str]) -> SqlRequest {
        SqlRequest::Batch {
            statements: statements
                .iter()
                .map(|sql| SqlStatement {
                    sql: sql.to_string(),
                    params: vec![],
                })
                .collect(),
        }
    }

    fn query(sql: &str) -> SqlRequest {
        SqlRequest::Query {
            sql: sql.to_string(),
            params: vec![],
            max_rows: None,
            max_bytes: None,
        }
    }

    fn caveats_with(statements: &[(&str, &str)]) -> Option<SqlCaveats> {
        Some(SqlCaveats {
            statements: Some(
                statements
                    .iter()
                    .map(|(name, sql)| crate::sql::caveats::PreparedStatement {
                        name: name.to_string(),
                        sql: sql.to_string(),
                    })
                    .collect(),
            ),
            ..SqlCaveats::default()
        })
    }

    fn run(
        conn: &rusqlite::Connection,
        request: &SqlRequest,
        caveats: &Option<SqlCaveats>,
        authority: &SqlAuthority,
    ) -> Result<SqlExecutionResult, SqlError> {
        handle_message(conn, request, caveats, authority)
    }

    fn table_exists(conn: &rusqlite::Connection, name: &str) -> bool {
        conn.query_row(
            "SELECT count(*) FROM sqlite_schema WHERE name = ?",
            [name],
            |row| row.get::<_, i64>(0),
        )
        .unwrap()
            > 0
    }

    fn is_denied(result: &Result<SqlExecutionResult, SqlError>) -> bool {
        matches!(
            result,
            Err(SqlError::PermissionDenied(_)) | Err(SqlError::ReadOnlyViolation)
        )
    }

    #[test]
    fn write_alone_cannot_change_the_schema_on_any_request_path() {
        let ddl = [
            "CREATE TABLE made (id INTEGER)",
            "DROP TABLE data",
            "ALTER TABLE data ADD COLUMN extra TEXT",
            "CREATE INDEX data_value ON data (value)",
            "CREATE VIEW data_view AS SELECT value FROM data",
        ];
        for sql in ddl {
            for abilities in [&[WRITE][..], &[READ, WRITE][..], &[READ][..]] {
                let authority = held(abilities);
                let conn = rusqlite::Connection::open_in_memory().unwrap();
                conn.execute_batch(
                    "CREATE TABLE data (value TEXT); INSERT INTO data VALUES ('kept')",
                )
                .unwrap();
                let schema_before: i64 = conn
                    .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
                    .unwrap();

                let named = caveats_with(&[("change", sql)]);
                let attempts = [
                    ("query", run(&conn, &query(sql), &None, &authority)),
                    (
                        "execute",
                        run(&conn, &execute(sql, None), &None, &authority),
                    ),
                    (
                        "execute schema[]",
                        run(&conn, &execute("SELECT 1", Some(&[sql])), &None, &authority),
                    ),
                    (
                        "batch",
                        run(
                            &conn,
                            &batch(&["INSERT INTO data VALUES ('second')", sql]),
                            &None,
                            &authority,
                        ),
                    ),
                    (
                        "named statement",
                        run(
                            &conn,
                            &SqlRequest::ExecuteStatement {
                                name: "change".into(),
                                params: vec![],
                            },
                            &named,
                            &authority,
                        ),
                    ),
                ];
                for (path, result) in attempts {
                    assert!(is_denied(&result), "{abilities:?} {path} {sql}: {result:?}");
                }

                let schema_after: i64 = conn
                    .query_row("SELECT count(*) FROM sqlite_schema", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(
                    schema_before, schema_after,
                    "{abilities:?} changed the schema: {sql}"
                );
                let rows: i64 = conn
                    .query_row("SELECT count(*) FROM data", [], |row| row.get(0))
                    .unwrap();
                assert_eq!(
                    rows, 1,
                    "a refused batch must not run its earlier statements"
                );
            }
        }
    }

    #[test]
    fn schema_conferring_abilities_run_ddl_on_every_request_path() {
        for abilities in [
            &[SCHEMA][..],
            &[WRITE, SCHEMA][..],
            &[ADMIN][..],
            &[STAR][..],
        ] {
            let authority = held(abilities);
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let named = caveats_with(&[("mk", "CREATE TABLE IF NOT EXISTS named (id INTEGER)")]);
            run(
                &conn,
                &query("CREATE TABLE via_query (id INTEGER)"),
                &None,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} query: {e:?}"));
            run(
                &conn,
                &execute("CREATE TABLE via_execute (id INTEGER)", None),
                &None,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} execute: {e:?}"));
            run(
                &conn,
                &batch(&["CREATE TABLE via_batch (id INTEGER)"]),
                &None,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} batch: {e:?}"));
            run(
                &conn,
                &SqlRequest::ExecuteStatement {
                    name: "mk".into(),
                    params: vec![],
                },
                &named,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} named: {e:?}"));
            for table in ["via_query", "via_execute", "via_batch", "named"] {
                assert!(table_exists(&conn, table), "{abilities:?} {table}");
            }
            run(
                &conn,
                &execute("DROP TABLE via_query", None),
                &None,
                &authority,
            )
            .unwrap_or_else(|e| panic!("{abilities:?} drop: {e:?}"));
        }
    }

    #[test]
    fn mixed_requests_need_both_abilities_or_admin() {
        let create = "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT)";
        let insert = "INSERT INTO notes (body) VALUES ('hello')";
        for (abilities, expected_ok) in [
            (&[WRITE, SCHEMA][..], true),
            (&[ADMIN][..], true),
            (&[STAR][..], true),
            (&[WRITE][..], false),
            (&[SCHEMA][..], false),
            (&[READ][..], false),
            (&[READ, SCHEMA][..], false),
        ] {
            let authority = held(abilities);

            // execute { schema: [DDL], sql: DML }: the SDK's migration shape.
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let result = run(&conn, &execute(insert, Some(&[create])), &None, &authority);
            assert_eq!(
                result.is_ok(),
                expected_ok,
                "{abilities:?} execute: {result:?}"
            );

            // batch [DDL, DML] is validated before anything runs.
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let result = run(&conn, &batch(&[create, insert]), &None, &authority);
            assert_eq!(
                result.is_ok(),
                expected_ok,
                "{abilities:?} batch: {result:?}"
            );
            if !expected_ok {
                assert!(
                    !table_exists(&conn, "notes"),
                    "{abilities:?}: a refused batch ran its DDL"
                );
            }
        }
    }

    #[test]
    fn data_statements_still_run_on_write_alone() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE data (id INTEGER PRIMARY KEY, value TEXT)")
            .unwrap();
        let authority = held(&[WRITE]);
        for sql in [
            "INSERT INTO data (value) VALUES ('a')",
            "INSERT OR REPLACE INTO data (id, value) VALUES (1, 'b')",
            "UPDATE data SET value = 'c' WHERE id = 1",
            "WITH x AS (SELECT 'd' AS value) INSERT INTO data (value) SELECT value FROM x",
            "DELETE FROM data WHERE id = 1",
        ] {
            run(&conn, &execute(sql, None), &None, &authority)
                .unwrap_or_else(|e| panic!("write must run {sql}: {e:?}"));
        }
        run(
            &conn,
            &batch(&["INSERT INTO data (value) VALUES ('e')"]),
            &None,
            &authority,
        )
        .unwrap();
        let read = run(
            &conn,
            &query("SELECT value FROM data ORDER BY id"),
            &None,
            &authority,
        )
        .unwrap();
        let SqlResponse::Query(rows) = read.response else {
            panic!("expected rows");
        };
        assert_eq!(rows.row_count, 2);

        // A named statement that is data runs on write alone as well.
        let named = caveats_with(&[("put", "INSERT INTO data (value) VALUES ('f')")]);
        run(
            &conn,
            &SqlRequest::ExecuteStatement {
                name: "put".into(),
                params: vec![],
            },
            &named,
            &authority,
        )
        .unwrap();
    }

    #[test]
    fn read_stays_read_only() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE data (value TEXT)")
            .unwrap();
        let authority = held(&[READ]);
        run(&conn, &query("SELECT value FROM data"), &None, &authority).unwrap();
        let result = run(
            &conn,
            &execute("INSERT INTO data VALUES ('x')", None),
            &None,
            &authority,
        );
        assert!(
            matches!(result, Err(SqlError::ReadOnlyViolation)),
            "{result:?}"
        );
    }

    #[test]
    fn pragma_is_unchanged_for_write_and_schema() {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        for abilities in [&[WRITE][..], &[SCHEMA][..], &[WRITE, SCHEMA][..]] {
            let authority = held(abilities);
            for request in [
                query("PRAGMA user_version = 9"),
                execute("PRAGMA user_version = 9", None),
                execute("SELECT 1", Some(&["PRAGMA user_version = 9"])),
            ] {
                let result = run(&conn, &request, &None, &authority);
                assert!(is_denied(&result), "{abilities:?}: {result:?}");
            }
        }
        for abilities in [&[ADMIN][..], &[STAR][..]] {
            run(
                &conn,
                &execute("PRAGMA user_version = 3", None),
                &None,
                &held(abilities),
            )
            .unwrap();
        }
        let version: i64 = conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
    }

    #[test]
    fn ddl_policy_switch_off_log_enforce() {
        let create = "CREATE TABLE IF NOT EXISTS made (id INTEGER)";
        for (policy, write_only_may_ddl) in [
            (DdlPolicy::Off, true),
            (DdlPolicy::Log, true),
            (DdlPolicy::Enforce, false),
        ] {
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let write_only = held(&[WRITE]).with_ddl_policy(policy);
            let result = run(&conn, &execute(create, None), &None, &write_only);
            assert_eq!(result.is_ok(), write_only_may_ddl, "{policy:?}: {result:?}");
            assert_eq!(
                table_exists(&conn, "made"),
                write_only_may_ddl,
                "{policy:?}"
            );

            // Holders of schema and read are judged the same in every mode.
            let conn = rusqlite::Connection::open_in_memory().unwrap();
            let both = held(&[WRITE, SCHEMA]).with_ddl_policy(policy);
            run(&conn, &execute(create, None), &None, &both).unwrap();
            let read = held(&[READ]).with_ddl_policy(policy);
            assert!(is_denied(&run(
                &conn,
                &execute("DROP TABLE made", None),
                &None,
                &read
            )));
        }
    }

    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
        type Writer = Captured;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn log_mode_counts_each_statement_and_warns_once_without_request_content() {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        let authority = held(&[WRITE]).with_ddl_policy(DdlPolicy::Log);
        let secret_table = "tc1581_secret_table_name";
        let create_before = ddl_without_schema_count(DdlKind::CreateTable);
        let drop_before = ddl_without_schema_count(DdlKind::Drop);

        run(
            &conn,
            &batch(&[
                &format!("CREATE TABLE {secret_table} (id INTEGER)"),
                &format!("CREATE TABLE {secret_table}_two (id INTEGER)"),
                &format!("DROP TABLE {secret_table}_two"),
                &format!("INSERT INTO {secret_table} (id) VALUES (1)"),
            ]),
            &None,
            &authority,
        )
        .unwrap();

        assert_eq!(
            ddl_without_schema_count(DdlKind::CreateTable) - create_before,
            2
        );
        assert_eq!(ddl_without_schema_count(DdlKind::Drop) - drop_before, 1);

        let logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(
            logged.matches("ddl_requires_schema = log").count(),
            1,
            "one warning per request: {logged}"
        );
        assert!(
            !logged.contains(secret_table),
            "log carried request content: {logged}"
        );
        assert!(!logged.to_lowercase().contains("create table"), "{logged}");

        // A holder of schema is not counted, and data statements never are.
        let before = ddl_without_schema_count(DdlKind::CreateTable);
        let both = held(&[WRITE, SCHEMA]).with_ddl_policy(DdlPolicy::Log);
        run(
            &conn,
            &execute("CREATE TABLE fine (id INTEGER)", None),
            &None,
            &both,
        )
        .unwrap();
        run(
            &conn,
            &execute("INSERT INTO fine VALUES (1)", None),
            &None,
            &authority,
        )
        .unwrap();
        assert_eq!(ddl_without_schema_count(DdlKind::CreateTable), before);
        let after_logged = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
        assert_eq!(after_logged.matches("ddl_requires_schema = log").count(), 1);
    }

    #[test]
    fn enforce_and_off_neither_count_nor_warn() {
        let captured = Captured::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(captured.clone())
            .with_ansi(false)
            .finish();
        let _guard = tracing::subscriber::set_default(subscriber);
        let before = ddl_without_schema_count(DdlKind::AlterTable);

        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (a)").unwrap();
        let off = held(&[WRITE]).with_ddl_policy(DdlPolicy::Off);
        run(
            &conn,
            &execute("ALTER TABLE t ADD COLUMN b", None),
            &None,
            &off,
        )
        .unwrap();
        let enforce = held(&[WRITE]).with_ddl_policy(DdlPolicy::Enforce);
        let denied = run(
            &conn,
            &execute("ALTER TABLE t ADD COLUMN c", None),
            &None,
            &enforce,
        );
        assert!(is_denied(&denied));

        assert_eq!(ddl_without_schema_count(DdlKind::AlterTable), before);
        assert!(captured.0.lock().unwrap().is_empty());
    }
}

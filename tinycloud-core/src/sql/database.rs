use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
use rusqlite::hooks::{AuthContext, Authorization};
use rusqlite::session::Session;
use sqlparser::ast::Statement;
use tokio::sync::{mpsc, oneshot};

use super::{
    authorizer,
    caveats::SqlCaveats,
    parser, replication as sql_replication,
    storage::{self, StorageMode},
    types::*,
};

const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300); // 5 min

enum DbMessage {
    Execute {
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
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
        response_tx: oneshot::Sender<Result<(), SqlError>>,
    },
    ApplyChangeset {
        changeset: Vec<u8>,
        response_tx: oneshot::Sender<Result<(), SqlError>>,
    },
}

#[derive(Clone)]
pub struct DatabaseHandle {
    tx: mpsc::Sender<DbMessage>,
}

impl DatabaseHandle {
    pub async fn execute(
        &self,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
    ) -> Result<SqlResponse, SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Execute {
                request,
                caveats,
                ability,
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

    pub async fn import(&self, snapshot: Vec<u8>) -> Result<(), SqlError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Import {
                snapshot,
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
                response_tx,
            })
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

        loop {
            // Block on receiving with timeout
            let msg =
                match rt.block_on(async { tokio::time::timeout(IDLE_TIMEOUT, rx.recv()).await }) {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break, // Channel closed
                    Err(_) => break,   // Idle timeout
                };

            match msg {
                DbMessage::Execute {
                    request,
                    caveats,
                    ability,
                    response_tx,
                } => {
                    let result = handle_message(&conn, &request, &caveats, &ability);

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
                    let result = handle_export(&conn);
                    let _ = response_tx.send(result);
                }
                DbMessage::ExportReplication {
                    since_seq,
                    response_tx,
                } => {
                    let result = handle_export_replication(&conn, since_seq);
                    let _ = response_tx.send(result);
                }
                DbMessage::Import {
                    snapshot,
                    response_tx,
                } => {
                    let result = handle_import(
                        &mut conn,
                        &mut mode,
                        &file_path,
                        memory_threshold,
                        &snapshot,
                    );
                    let _ = response_tx.send(result);
                }
                DbMessage::ApplyChangeset {
                    changeset,
                    response_tx,
                } => {
                    let result = handle_apply_changeset(&conn, &changeset);
                    let _ = response_tx.send(result);
                }
            }
        }

        // Flush in-memory database to file before shutdown so data is not lost
        if matches!(mode, StorageMode::InMemory) {
            if let Ok(size) = storage::database_size(&conn) {
                if size > 0 {
                    match storage::promote_to_file(&conn, &file_path) {
                        Ok(_) => {
                            tracing::info!(space=%space_id, db=%db_name, "Flushed in-memory database to file on shutdown");
                        }
                        Err(e) => {
                            tracing::error!(space=%space_id, db=%db_name, error=%e, "Failed to flush in-memory database on shutdown");
                        }
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

fn handle_import(
    conn: &mut rusqlite::Connection,
    mode: &mut StorageMode,
    file_path: &PathBuf,
    memory_threshold: u64,
    snapshot: &[u8],
) -> Result<(), SqlError> {
    storage::import_snapshot(conn, snapshot, matches!(mode, StorageMode::File(_)))?;

    if matches!(mode, StorageMode::InMemory) && storage::database_size(conn)? > memory_threshold {
        let new_conn = storage::promote_to_file(conn, file_path)?;
        *conn = new_conn;
        *mode = StorageMode::File(file_path.clone());
    }

    Ok(())
}

fn handle_apply_changeset(conn: &rusqlite::Connection, changeset: &[u8]) -> Result<(), SqlError> {
    sql_replication::apply_changeset(conn, changeset)
}

fn handle_message(
    conn: &rusqlite::Connection,
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

            // Schema init
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
        SqlValue::Null => 4,       // "null"
        SqlValue::Integer(_) => 8, // up to 20 digits
        SqlValue::Real(_) => 8,
        SqlValue::Text(s) => s.len() + 2, // quotes
        SqlValue::Blob(b) => b.len() * 2, // hex encoding overhead
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

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use sqlparser::ast::Statement;
use tokio::sync::{mpsc, oneshot};

use super::{
    caveats::DuckDbCaveats,
    describe, parser,
    storage::{self, StorageMode},
    types::*,
};

const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB

enum DbMessage {
    Execute {
        request: Box<DuckDbRequest>,
        caveats: Option<DuckDbCaveats>,
        ability: String,
        arrow_format: bool,
        without_growth: bool,
        response_tx: oneshot::Sender<Result<DuckDbExecutionResult, DuckDbError>>,
    },
    Export {
        response_tx: oneshot::Sender<Result<Vec<u8>, DuckDbError>>,
    },
    Wal {
        response_tx: oneshot::Sender<Result<Option<Vec<u8>>, DuckDbError>>,
    },
}

#[derive(Clone)]
pub struct DatabaseHandle {
    id: u64,
    tx: mpsc::Sender<DbMessage>,
}

/// Distinguishes one actor from its replacement for the same (space, db); see
/// the deregistrations in [`spawn_actor`].
static NEXT_ACTOR_ID: AtomicU64 = AtomicU64::new(0);

impl DatabaseHandle {
    pub async fn execute(
        &self,
        request: DuckDbRequest,
        caveats: Option<DuckDbCaveats>,
        ability: String,
        arrow_format: bool,
        without_growth: bool,
    ) -> Result<DuckDbExecutionResult, DuckDbError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Execute {
                request: Box::new(request),
                caveats,
                ability,
                arrow_format,
                without_growth,
                response_tx,
            })
            .await
            .map_err(|_| DuckDbError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| DuckDbError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn export(&self) -> Result<Vec<u8>, DuckDbError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Export { response_tx })
            .await
            .map_err(|_| DuckDbError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| DuckDbError::Internal("Database actor dropped response".to_string()))?
    }

    pub async fn wal(&self) -> Result<Option<Vec<u8>>, DuckDbError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Wal { response_tx })
            .await
            .map_err(|_| DuckDbError::Internal("Database actor not available".to_string()))?;
        response_rx
            .await
            .map_err(|_| DuckDbError::Internal("Database actor dropped response".to_string()))?
    }
}

pub fn spawn_actor(
    space_id: String,
    db_name: String,
    base_path: String,
    memory_threshold: u64,
    idle_timeout_secs: u64,
    max_memory_per_connection: String,
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
) -> DatabaseHandle {
    let (tx, mut rx) = mpsc::channel::<DbMessage>(32);
    let id = NEXT_ACTOR_ID.fetch_add(1, Ordering::Relaxed);
    let idle_timeout = std::time::Duration::from_secs(idle_timeout_secs);

    tokio::task::spawn_blocking(move || {
        let rt = tokio::runtime::Handle::current();
        let file_path = PathBuf::from(&base_path)
            .join(&space_id)
            .join(format!("{}.duckdb", db_name));

        // Check if file already exists -- if so, open from file
        let mut mode = if file_path.exists() {
            StorageMode::File(file_path.clone())
        } else {
            StorageMode::InMemory
        };
        let mut conn = match storage::open_connection(&mode, &max_memory_per_connection) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(error=%e, "Failed to open database");
                // Drain pending messages with error
                while let Ok(msg) = rx.try_recv() {
                    match msg {
                        DbMessage::Execute { response_tx, .. } => {
                            let _ = response_tx
                                .send(Err(DuckDbError::Internal(format!("Failed to open: {}", e))));
                        }
                        DbMessage::Export { response_tx } => {
                            let _ = response_tx
                                .send(Err(DuckDbError::Internal(format!("Failed to open: {}", e))));
                        }
                        DbMessage::Wal { response_tx } => {
                            let _ = response_tx
                                .send(Err(DuckDbError::Internal(format!("Failed to open: {}", e))));
                        }
                    }
                }
                databases.remove_if(&(space_id, db_name), |_, handle| handle.id == id);
                return;
            }
        };

        loop {
            // Block on receiving with timeout
            let msg =
                match rt.block_on(async { tokio::time::timeout(idle_timeout, rx.recv()).await }) {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break, // Channel closed
                    Err(_) => break,   // Idle timeout
                };

            match msg {
                DbMessage::Execute {
                    request,
                    caveats,
                    ability,
                    arrow_format,
                    without_growth,
                    response_tx,
                } => {
                    let result = if without_growth {
                        handle_message_without_growth(
                            &conn,
                            &request,
                            &caveats,
                            &ability,
                            arrow_format,
                        )
                    } else {
                        handle_message(&conn, &request, &caveats, &ability, arrow_format, None)
                    };

                    // Post-write promotion check
                    if result.is_ok() && matches!(mode, StorageMode::InMemory) {
                        if let Ok(size) = storage::database_size(&conn) {
                            if size > memory_threshold {
                                match storage::promote_to_file(
                                    &conn,
                                    &file_path,
                                    &max_memory_per_connection,
                                ) {
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
                DbMessage::Wal { response_tx } => {
                    let result = handle_wal(&mode, &file_path);
                    let _ = response_tx.send(result);
                }
            }
        }

        // Deregister only OUR OWN entry. A replacement actor may already have
        // been hydrated and registered for this key, and evicting it would send
        // the next request through hydration while it is live — deleting and
        // rewriting the files it holds open by path.
        databases.remove_if(&(space_id.clone(), db_name.clone()), |_, handle| {
            handle.id == id
        });
        tracing::debug!(space=%space_id, db=%db_name, "Database actor shutting down");
    });

    DatabaseHandle { id, tx }
}

fn handle_wal(mode: &StorageMode, file_path: &Path) -> Result<Option<Vec<u8>>, DuckDbError> {
    if !matches!(mode, StorageMode::File(_)) {
        return Ok(None);
    }
    match std::fs::read(format!("{}.wal", file_path.display())) {
        Ok(wal) if !wal.is_empty() => Ok(Some(wal)),
        Ok(_) => Ok(None),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(DuckDbError::Internal(error.to_string())),
    }
}

fn handle_export(
    conn: &duckdb::Connection,
    mode: &StorageMode,
    file_path: &PathBuf,
) -> Result<Vec<u8>, DuckDbError> {
    match mode {
        StorageMode::File(_) => {
            conn.execute_batch("CHECKPOINT;")
                .map_err(|e| DuckDbError::Internal(e.to_string()))?;
            std::fs::read(file_path).map_err(|e| DuckDbError::Internal(e.to_string()))
        }
        StorageMode::InMemory => {
            // In-memory: copy tables into a new file-backed database.
            // We can't use EXPORT/IMPORT DATABASE because enable_external_access=false
            // cannot be toggled at runtime.
            let temp_dir = tempfile::tempdir().map_err(|e| DuckDbError::Internal(e.to_string()))?;
            let temp_db_path = temp_dir.path().join("export.duckdb");

            let dest = duckdb::Connection::open(&temp_db_path)
                .map_err(|e| DuckDbError::Internal(e.to_string()))?;

            storage::copy_tables(conn, &dest)?;

            drop(dest);

            std::fs::read(&temp_db_path).map_err(|e| DuckDbError::Internal(e.to_string()))
        }
    }
}

fn handle_message(
    conn: &duckdb::Connection,
    request: &DuckDbRequest,
    caveats: &Option<DuckDbCaveats>,
    ability: &str,
    arrow_format: bool,
    mut storage_guard: Option<&mut StorageGuard>,
) -> Result<DuckDbExecutionResult, DuckDbError> {
    // No authorizer in DuckDB -- parser is the sole defense
    match request {
        DuckDbRequest::Query { sql, params } => {
            let parsed = validate_sql(conn, sql, caveats, ability, &mut storage_guard)?;
            if arrow_format {
                execute_query_arrow(conn, sql, params).map(|response| DuckDbExecutionResult {
                    response: DuckDbResponse::Arrow(response),
                    write_targets: parsed.write_targets,
                })
            } else {
                execute_query(conn, sql, params).map(|response| DuckDbExecutionResult {
                    response: DuckDbResponse::Query(response),
                    write_targets: parsed.write_targets,
                })
            }
        }
        DuckDbRequest::Execute {
            sql,
            params,
            schema,
        } => {
            let mut write_targets = Vec::new();
            // Schema init
            if let Some(schema_stmts) = schema {
                for stmt_sql in schema_stmts {
                    let parsed =
                        validate_sql(conn, stmt_sql, caveats, ability, &mut storage_guard)?;
                    write_targets.extend(parsed.write_targets);
                    conn.execute_batch(stmt_sql)
                        .map_err(|e| DuckDbError::SchemaError(e.to_string()))?;
                }
            }

            let parsed = validate_sql(conn, sql, caveats, ability, &mut storage_guard)?;
            execute_statement(conn, sql, params).map(|response| {
                write_targets.extend(parsed.write_targets);
                DuckDbExecutionResult {
                    response: DuckDbResponse::Execute(response),
                    write_targets,
                }
            })
        }
        DuckDbRequest::Batch {
            statements,
            transactional,
        } => {
            let mut write_targets = Vec::new();
            // Hooks are emitted only after this branch returns Ok to the caller.
            // If a later statement fails after some earlier statements applied,
            // MVP intentionally under-emits rather than guessing partial success.
            for stmt in statements {
                let parsed = validate_sql(conn, &stmt.sql, caveats, ability, &mut storage_guard)?;
                write_targets.extend(parsed.write_targets);
            }

            let response = if *transactional && storage_guard.is_none() {
                execute_batch_transactional(conn, statements)
            } else {
                execute_batch(conn, statements)
            }
            .map(DuckDbResponse::Batch)?;

            Ok(DuckDbExecutionResult {
                response,
                write_targets,
            })
        }
        DuckDbRequest::ExecuteStatement { name, params } => {
            let caveats_ref = caveats
                .as_ref()
                .ok_or_else(|| DuckDbError::InvalidStatement("No caveats found".to_string()))?;
            let prepared = caveats_ref.find_statement(name).ok_or_else(|| {
                DuckDbError::InvalidStatement(format!("Statement '{}' not found", name))
            })?;

            let parsed = validate_sql(conn, &prepared.sql, caveats, ability, &mut storage_guard)?;

            let response = if prepared
                .sql
                .trim_start()
                .to_uppercase()
                .starts_with("SELECT")
            {
                execute_query(conn, &prepared.sql, params).map(DuckDbResponse::Query)
            } else {
                execute_statement(conn, &prepared.sql, params).map(DuckDbResponse::Execute)
            }?;

            Ok(DuckDbExecutionResult {
                response,
                write_targets: parsed.write_targets,
            })
        }
        DuckDbRequest::Describe => {
            describe::describe_schema(conn, caveats).map(|response| DuckDbExecutionResult {
                response: DuckDbResponse::Describe(response),
                write_targets: Vec::new(),
            })
        }
        DuckDbRequest::Ingest { .. } => Err(DuckDbError::Internal(
            "KV bridge not yet available".to_string(),
        )),
        DuckDbRequest::ExportToKv { .. } => Err(DuckDbError::Internal(
            "KV bridge not yet available".to_string(),
        )),
        DuckDbRequest::Export => Err(DuckDbError::Internal(
            "Export should be handled by service".to_string(),
        )),
        DuckDbRequest::Import { .. } => Err(DuckDbError::Internal(
            "Import should be handled by service".to_string(),
        )),
    }
}

/// DuckDB's block counts are checkpoint-oriented, not a measure of pending
/// logical growth. Instead admit only shrinking statements, reads, and
/// IF NOT EXISTS DDL, then verify that DDL introduced no catalog objects.
/// Catalog identities avoid reimplementing DuckDB's identifier/search-path
/// resolution, including quoted names and temporary-object shadowing.
#[derive(Default)]
struct StorageGuard {
    catalog_before: Option<BTreeSet<(i32, i64, i64)>>,
}

impl StorageGuard {
    fn validate(
        &mut self,
        conn: &duckdb::Connection,
        parsed: &parser::ParsedQuery,
    ) -> Result<(), DuckDbError> {
        for statement in &parsed.statements {
            match statement {
                Statement::Query(_) | Statement::Delete { .. } | Statement::Drop { .. } => {}
                Statement::CreateTable {
                    if_not_exists: true,
                    or_replace: false,
                    ..
                }
                | Statement::CreateView {
                    if_not_exists: true,
                    or_replace: false,
                    ..
                }
                | Statement::CreateIndex {
                    if_not_exists: true,
                    ..
                }
                | Statement::CreateSchema {
                    if_not_exists: true,
                    ..
                }
                | Statement::CreateSequence {
                    if_not_exists: true,
                    ..
                } => {
                    if self.catalog_before.is_none() {
                        self.catalog_before = Some(catalog_objects(conn)?);
                    }
                }
                // Includes transaction control: client COMMIT must never escape
                // the request-wide rollback boundary.
                _ => return Err(DuckDbError::StorageWouldGrow),
            }
        }
        Ok(())
    }

    fn finish(&self, conn: &duckdb::Connection) -> Result<(), DuckDbError> {
        if let Some(before) = &self.catalog_before {
            if !catalog_objects(conn)?.is_subset(before) {
                return Err(DuckDbError::StorageWouldGrow);
            }
        }
        Ok(())
    }
}

fn catalog_objects(conn: &duckdb::Connection) -> Result<BTreeSet<(i32, i64, i64)>, DuckDbError> {
    // Fully qualify built-ins so user macros/search_path cannot shadow them.
    // OIDs, rather than object counts, detect DROP + recreate under one name.
    let mut statement = conn
        .prepare(
            "SELECT 0, database_oid, table_oid FROM system.main.duckdb_tables()
             UNION ALL SELECT 1, database_oid, view_oid FROM system.main.duckdb_views()
             UNION ALL SELECT 2, database_oid, index_oid FROM system.main.duckdb_indexes()
             UNION ALL SELECT 3, database_oid, oid FROM system.main.duckdb_schemas()
             UNION ALL SELECT 4, database_oid, sequence_oid FROM system.main.duckdb_sequences()",
        )
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;
    let objects = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;
    objects
        .collect::<Result<_, _>>()
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))
}

fn validate_sql(
    conn: &duckdb::Connection,
    sql: &str,
    caveats: &Option<DuckDbCaveats>,
    ability: &str,
    storage_guard: &mut Option<&mut StorageGuard>,
) -> Result<parser::ParsedQuery, DuckDbError> {
    // Authorization and every caveat still precede storage admission.
    let parsed = parser::validate_sql(sql, caveats, ability)?;
    if let Some(guard) = storage_guard.as_deref_mut() {
        guard.validate(conn, &parsed)?;
    }
    Ok(parsed)
}

fn handle_message_without_growth(
    conn: &duckdb::Connection,
    request: &DuckDbRequest,
    caveats: &Option<DuckDbCaveats>,
    ability: &str,
    arrow_format: bool,
) -> Result<DuckDbExecutionResult, DuckDbError> {
    // The actor owns the connection throughout validation, catalog inspection,
    // and execution. Even non-transactional batches need this boundary so a
    // later growth refusal cannot retain earlier DELETE/DROP/schema effects.
    let transaction = conn
        .unchecked_transaction()
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;
    let mut guard = StorageGuard::default();
    let result = handle_message(
        &transaction,
        request,
        caveats,
        ability,
        arrow_format,
        Some(&mut guard),
    );
    match result.and_then(|result| guard.finish(&transaction).map(|()| result)) {
        Ok(result) => {
            transaction
                .commit()
                .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;
            Ok(result)
        }
        Err(error) => {
            transaction
                .rollback()
                .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;
            Err(error)
        }
    }
}

fn duckdb_value_to_param(v: &DuckDbValue) -> duckdb::types::Value {
    duckdb::types::Value::from(v)
}

fn row_to_duckdb_value(row: &duckdb::Row, idx: usize) -> Result<DuckDbValue, DuckDbError> {
    let value: duckdb::types::Value = row
        .get(idx)
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;
    Ok(DuckDbValue::from(value))
}

fn estimate_value_size(val: &DuckDbValue) -> usize {
    match val {
        DuckDbValue::Null => 4,
        DuckDbValue::Boolean(_) => 5,
        DuckDbValue::Integer(_) => 8,
        DuckDbValue::BigInt(_) => 20,
        DuckDbValue::Float(_) => 8,
        DuckDbValue::Double(_) => 8,
        DuckDbValue::Text(s) => s.len() + 2,
        DuckDbValue::Blob(b) => b.len() * 2,
        DuckDbValue::Date(s) => s.len() + 2,
        DuckDbValue::Timestamp(s) => s.len() + 2,
        DuckDbValue::List(items) => items.iter().map(estimate_value_size).sum::<usize>() + 2,
        DuckDbValue::Struct(fields) => {
            fields
                .iter()
                .map(|(k, v)| k.len() + estimate_value_size(v) + 4)
                .sum::<usize>()
                + 2
        }
    }
}

fn execute_query(
    conn: &duckdb::Connection,
    sql: &str,
    params: &[DuckDbValue],
) -> Result<QueryResponse, DuckDbError> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    let duckdb_params: Vec<duckdb::types::Value> =
        params.iter().map(duckdb_value_to_param).collect();
    let param_refs: Vec<&dyn duckdb::types::ToSql> = duckdb_params
        .iter()
        .map(|p| p as &dyn duckdb::types::ToSql)
        .collect();

    let mut query_rows = stmt
        .query(param_refs.as_slice())
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    // column_names() must be called after query() — the duckdb crate
    // only populates the schema once the statement has been executed.
    // Access via the Rows reference to avoid borrow conflict with stmt.
    let columns: Vec<String> = query_rows
        .as_ref()
        .map(|s| s.column_names())
        .unwrap_or_default();

    let mut rows = Vec::new();
    let mut size_estimate: usize = 0;

    while let Some(row) = query_rows
        .next()
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?
    {
        let mut values = Vec::new();
        for i in 0..columns.len() {
            let val = row_to_duckdb_value(row, i)?;
            size_estimate += estimate_value_size(&val);
            values.push(val);
        }
        rows.push(values);

        if size_estimate > MAX_RESPONSE_SIZE {
            return Err(DuckDbError::ResponseTooLarge(size_estimate as u64));
        }
    }

    let row_count = rows.len();
    Ok(QueryResponse {
        columns,
        rows,
        row_count,
    })
}

fn execute_query_arrow(
    conn: &duckdb::Connection,
    sql: &str,
    params: &[DuckDbValue],
) -> Result<Vec<u8>, DuckDbError> {
    let mut stmt = conn
        .prepare(sql)
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    let duckdb_params: Vec<duckdb::types::Value> =
        params.iter().map(duckdb_value_to_param).collect();
    let param_refs: Vec<&dyn duckdb::types::ToSql> = duckdb_params
        .iter()
        .map(|p| p as &dyn duckdb::types::ToSql)
        .collect();

    let arrow_result = stmt
        .query_arrow(param_refs.as_slice())
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    let schema = arrow_result.get_schema();
    let mut buf = Vec::new();

    {
        let mut writer = arrow::ipc::writer::StreamWriter::try_new(&mut buf, &schema)
            .map_err(|e| DuckDbError::Internal(format!("Arrow writer error: {}", e)))?;

        for batch in arrow_result {
            writer
                .write(&batch)
                .map_err(|e| DuckDbError::Internal(format!("Arrow write error: {}", e)))?;
        }
        writer
            .finish()
            .map_err(|e| DuckDbError::Internal(format!("Arrow finish error: {}", e)))?;
    }

    if buf.len() > MAX_RESPONSE_SIZE {
        return Err(DuckDbError::ResponseTooLarge(buf.len() as u64));
    }

    Ok(buf)
}

fn execute_statement(
    conn: &duckdb::Connection,
    sql: &str,
    params: &[DuckDbValue],
) -> Result<ExecuteResponse, DuckDbError> {
    let duckdb_params: Vec<duckdb::types::Value> =
        params.iter().map(duckdb_value_to_param).collect();
    let param_refs: Vec<&dyn duckdb::types::ToSql> = duckdb_params
        .iter()
        .map(|p| p as &dyn duckdb::types::ToSql)
        .collect();

    let changes = conn
        .execute(sql, param_refs.as_slice())
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    Ok(ExecuteResponse {
        changes: changes as u64,
    })
}

fn execute_batch(
    conn: &duckdb::Connection,
    statements: &[DuckDbStatement],
) -> Result<BatchResponse, DuckDbError> {
    let mut results = Vec::new();
    for stmt in statements {
        let result = execute_statement(conn, &stmt.sql, &stmt.params)?;
        results.push(result);
    }
    Ok(BatchResponse { results })
}

fn execute_batch_transactional(
    conn: &duckdb::Connection,
    statements: &[DuckDbStatement],
) -> Result<BatchResponse, DuckDbError> {
    conn.execute_batch("BEGIN TRANSACTION;")
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    let mut results = Vec::new();
    for stmt in statements {
        match execute_statement(conn, &stmt.sql, &stmt.params) {
            Ok(result) => results.push(result),
            Err(e) => {
                let _ = conn.execute_batch("ROLLBACK;");
                return Err(e);
            }
        }
    }

    conn.execute_batch("COMMIT;")
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

    Ok(BatchResponse { results })
}

#[cfg(test)]
mod tests {
    use super::super::caveats::PreparedStatement;
    use super::*;

    fn execute_request(sql: &str) -> DuckDbRequest {
        DuckDbRequest::Execute {
            sql: sql.to_string(),
            params: Vec::new(),
            schema: None,
        }
    }

    fn without_growth(
        conn: &duckdb::Connection,
        request: &DuckDbRequest,
    ) -> Result<DuckDbExecutionResult, DuckDbError> {
        handle_message_without_growth(conn, request, &None, "tinycloud.duckdb/write", false)
    }

    fn row_count(conn: &duckdb::Connection, table: &str) -> i64 {
        conn.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    #[test]
    fn full_database_allows_existing_schema_delete_and_drop() {
        let conn = storage::open_connection(&StorageMode::InMemory, "128MB").unwrap();
        conn.execute_batch(
            "CREATE TABLE \"Event.Log\" (id INTEGER);
             CREATE INDEX event_id ON \"Event.Log\" (id);
             INSERT INTO \"Event.Log\" VALUES (1), (2);",
        )
        .unwrap();
        let result = without_growth(
            &conn,
            &DuckDbRequest::Execute {
                schema: Some(vec![
                    "CREATE TABLE IF NOT EXISTS main.\"event.log\" (id INTEGER)".to_string(),
                    "CREATE INDEX IF NOT EXISTS event_id ON \"Event.Log\" (id)".to_string(),
                    "CREATE TABLE IF NOT EXISTS main.\"event.log\" AS SELECT 99 AS id".to_string(),
                ]),
                sql: "DELETE FROM \"Event.Log\" WHERE id = ?".to_string(),
                params: vec![DuckDbValue::Integer(1)],
            },
        )
        .unwrap();
        assert!(matches!(
            result.response,
            DuckDbResponse::Execute(ExecuteResponse { changes: 1 })
        ));
        assert_eq!(row_count(&conn, "\"Event.Log\""), 1);

        without_growth(&conn, &execute_request("DROP TABLE \"Event.Log\"")).unwrap();
        let tables: i64 = conn
            .query_row(
                "SELECT count(*) FROM duckdb_tables() WHERE NOT internal",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
    }

    #[test]
    fn full_database_refuses_rows_and_new_if_not_exists_objects() {
        let conn = storage::open_connection(&StorageMode::InMemory, "128MB").unwrap();
        conn.execute_batch("CREATE TABLE events (id INTEGER); INSERT INTO events VALUES (1)")
            .unwrap();
        let before = catalog_objects(&conn).unwrap();

        assert!(matches!(
            without_growth(&conn, &execute_request("INSERT INTO events VALUES (2)")),
            Err(DuckDbError::StorageWouldGrow)
        ));
        assert_eq!(row_count(&conn, "events"), 1);

        assert!(matches!(
            without_growth(
                &conn,
                &execute_request("CREATE TABLE IF NOT EXISTS added (id INTEGER)")
            ),
            Err(DuckDbError::StorageWouldGrow)
        ));
        assert_eq!(catalog_objects(&conn).unwrap(), before);

        assert!(matches!(
            without_growth(
                &conn,
                &execute_request("CREATE INDEX IF NOT EXISTS new_index ON events (id)")
            ),
            Err(DuckDbError::StorageWouldGrow)
        ));
        assert_eq!(catalog_objects(&conn).unwrap(), before);
        assert_eq!(row_count(&conn, "events"), 1);
    }

    #[test]
    fn full_database_rolls_back_drop_and_recreate_in_either_batch_mode() {
        for transactional in [false, true] {
            let conn = storage::open_connection(&StorageMode::InMemory, "128MB").unwrap();
            conn.execute_batch("CREATE TABLE events (id INTEGER); INSERT INTO events VALUES (1)")
                .unwrap();
            let before = catalog_objects(&conn).unwrap();
            let request = DuckDbRequest::Batch {
                statements: vec![
                    DuckDbStatement {
                        sql: "DELETE FROM events".to_string(),
                        params: Vec::new(),
                    },
                    DuckDbStatement {
                        sql: "DROP TABLE events".to_string(),
                        params: Vec::new(),
                    },
                    DuckDbStatement {
                        sql: "CREATE TABLE IF NOT EXISTS events (id INTEGER)".to_string(),
                        params: Vec::new(),
                    },
                ],
                transactional,
            };

            assert!(matches!(
                without_growth(&conn, &request),
                Err(DuckDbError::StorageWouldGrow)
            ));
            assert_eq!(catalog_objects(&conn).unwrap(), before);
            assert_eq!(row_count(&conn, "events"), 1);
        }
    }

    #[test]
    fn full_database_rolls_back_schema_mutations_and_rejects_transaction_escape() {
        let conn = storage::open_connection(&StorageMode::InMemory, "128MB").unwrap();
        conn.execute_batch("CREATE TABLE events (id INTEGER); INSERT INTO events VALUES (1)")
            .unwrap();
        let before = catalog_objects(&conn).unwrap();
        let request = DuckDbRequest::Execute {
            schema: Some(vec![
                "DROP TABLE events; CREATE TABLE IF NOT EXISTS events (id INTEGER)".to_string(),
            ]),
            sql: "DELETE FROM events".to_string(),
            params: Vec::new(),
        };
        assert!(matches!(
            without_growth(&conn, &request),
            Err(DuckDbError::StorageWouldGrow)
        ));
        assert_eq!(catalog_objects(&conn).unwrap(), before);
        assert_eq!(row_count(&conn, "events"), 1);

        let escape = DuckDbRequest::Execute {
            schema: Some(vec!["DELETE FROM events".to_string()]),
            sql: "COMMIT".to_string(),
            params: Vec::new(),
        };
        assert!(matches!(
            without_growth(&conn, &escape),
            Err(DuckDbError::StorageWouldGrow)
        ));
        assert_eq!(row_count(&conn, "events"), 1);
    }

    #[test]
    fn full_database_preserves_schema_caveats_and_prepared_statement_parameters() {
        let conn = storage::open_connection(&StorageMode::InMemory, "128MB").unwrap();
        conn.execute_batch(
            "CREATE TABLE events (id INTEGER);
             CREATE TABLE private (id INTEGER);
             INSERT INTO events VALUES (1), (2);",
        )
        .unwrap();
        let caveats = Some(DuckDbCaveats {
            tables: Some(vec!["events".to_string()]),
            statements: Some(vec![PreparedStatement {
                name: "remove".to_string(),
                sql: "DELETE FROM events WHERE id = ?".to_string(),
            }]),
            ..Default::default()
        });
        let request = DuckDbRequest::Execute {
            schema: Some(vec![
                "CREATE TABLE IF NOT EXISTS private (id INTEGER)".to_string()
            ]),
            sql: "DELETE FROM events".to_string(),
            params: Vec::new(),
        };
        assert!(matches!(
            handle_message_without_growth(
                &conn,
                &request,
                &caveats,
                "tinycloud.duckdb/write",
                false
            ),
            Err(DuckDbError::PermissionDenied(_))
        ));
        assert_eq!(row_count(&conn, "events"), 2);

        let result = handle_message_without_growth(
            &conn,
            &DuckDbRequest::ExecuteStatement {
                name: "remove".to_string(),
                params: vec![DuckDbValue::Integer(1)],
            },
            &caveats,
            "tinycloud.duckdb/write",
            false,
        )
        .unwrap();
        assert!(matches!(
            result.response,
            DuckDbResponse::Execute(ExecuteResponse { changes: 1 })
        ));
        assert_eq!(row_count(&conn, "events"), 1);
    }
}

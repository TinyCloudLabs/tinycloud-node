use std::path::PathBuf;
use std::sync::Arc;

use dashmap::DashMap;
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
        response_tx: oneshot::Sender<Result<DuckDbResponse, DuckDbError>>,
    },
    Export {
        response_tx: oneshot::Sender<Result<Vec<u8>, DuckDbError>>,
    },
}

#[derive(Clone)]
pub struct DatabaseHandle {
    tx: mpsc::Sender<DbMessage>,
}

impl DatabaseHandle {
    pub async fn execute(
        &self,
        request: DuckDbRequest,
        caveats: Option<DuckDbCaveats>,
        ability: String,
        arrow_format: bool,
    ) -> Result<DuckDbResponse, DuckDbError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage::Execute {
                request: Box::new(request),
                caveats,
                ability,
                arrow_format,
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
                            let _ = response_tx.send(Err(DuckDbError::Internal(format!("Failed to open: {}", e))));
                        }
                        DbMessage::Export { response_tx } => {
                            let _ = response_tx.send(Err(DuckDbError::Internal(format!("Failed to open: {}", e))));
                        }
                    }
                }
                databases.remove(&(space_id, db_name));
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
                    response_tx,
                } => {
                    let result = handle_message(
                        &conn,
                        &request,
                        &caveats,
                        &ability,
                        arrow_format,
                    );

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
            }
        }

        databases.remove(&(space_id.clone(), db_name.clone()));
        tracing::debug!(space=%space_id, db=%db_name, "Database actor shutting down");
    });

    DatabaseHandle { tx }
}

fn handle_export(
    conn: &duckdb::Connection,
    mode: &StorageMode,
    file_path: &PathBuf,
) -> Result<Vec<u8>, DuckDbError> {
    match mode {
        StorageMode::File(_) => {
            // File-backed: read the file directly
            std::fs::read(file_path).map_err(|e| DuckDbError::Internal(e.to_string()))
        }
        StorageMode::InMemory => {
            // In-memory: copy tables into a new file-backed database.
            // We can't use EXPORT/IMPORT DATABASE because enable_external_access=false
            // cannot be toggled at runtime.
            let temp_dir =
                tempfile::tempdir().map_err(|e| DuckDbError::Internal(e.to_string()))?;
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
) -> Result<DuckDbResponse, DuckDbError> {
    // No authorizer in DuckDB -- parser is the sole defense
    match request {
        DuckDbRequest::Query { sql, params } => {
            parser::validate_sql(sql, caveats, ability)?;
            if arrow_format {
                execute_query_arrow(conn, sql, params).map(DuckDbResponse::Arrow)
            } else {
                execute_query(conn, sql, params).map(DuckDbResponse::Query)
            }
        }
        DuckDbRequest::Execute {
            sql,
            params,
            schema,
        } => {
            // Schema init
            if let Some(schema_stmts) = schema {
                for stmt_sql in schema_stmts {
                    parser::validate_sql(stmt_sql, caveats, ability)?;
                    conn.execute_batch(stmt_sql)
                        .map_err(|e| DuckDbError::SchemaError(e.to_string()))?;
                }
            }

            parser::validate_sql(sql, caveats, ability)?;
            execute_statement(conn, sql, params).map(DuckDbResponse::Execute)
        }
        DuckDbRequest::Batch {
            statements,
            transactional,
        } => {
            for stmt in statements {
                parser::validate_sql(&stmt.sql, caveats, ability)?;
            }

            if *transactional {
                execute_batch_transactional(conn, statements)
            } else {
                execute_batch(conn, statements)
            }
            .map(DuckDbResponse::Batch)
        }
        DuckDbRequest::ExecuteStatement { name, params } => {
            let caveats_ref = caveats
                .as_ref()
                .ok_or_else(|| DuckDbError::InvalidStatement("No caveats found".to_string()))?;
            let prepared = caveats_ref.find_statement(name).ok_or_else(|| {
                DuckDbError::InvalidStatement(format!("Statement '{}' not found", name))
            })?;

            parser::validate_sql(&prepared.sql, caveats, ability)?;

            if prepared
                .sql
                .trim_start()
                .to_uppercase()
                .starts_with("SELECT")
            {
                execute_query(conn, &prepared.sql, params).map(DuckDbResponse::Query)
            } else {
                execute_statement(conn, &prepared.sql, params).map(DuckDbResponse::Execute)
            }
        }
        DuckDbRequest::Describe => {
            describe::describe_schema(conn, caveats).map(DuckDbResponse::Describe)
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

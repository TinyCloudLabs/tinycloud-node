use std::path::PathBuf;

use tokio::sync::{mpsc, oneshot};

use super::{
    caveats::DuckDbCaveats,
    describe,
    parser,
    storage::{self, StorageMode},
    types::*,
};

const MAX_RESPONSE_SIZE: usize = 10 * 1024 * 1024; // 10MB

struct DbMessage {
    request: DuckDbRequest,
    caveats: Option<DuckDbCaveats>,
    ability: String,
    response_tx: oneshot::Sender<Result<DuckDbResponse, DuckDbError>>,
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
    ) -> Result<DuckDbResponse, DuckDbError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.tx
            .send(DbMessage {
                request,
                caveats,
                ability,
                response_tx,
            })
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
        let mut conn = storage::open_connection(&mode, &max_memory_per_connection)
            .expect("Failed to open database");

        loop {
            // Block on receiving with timeout
            let msg =
                match rt.block_on(async { tokio::time::timeout(idle_timeout, rx.recv()).await }) {
                    Ok(Some(msg)) => msg,
                    Ok(None) => break, // Channel closed
                    Err(_) => break,   // Idle timeout
                };

            let result = handle_message(&conn, &msg.request, &msg.caveats, &msg.ability);

            // Post-write promotion check
            if result.is_ok() && matches!(mode, StorageMode::InMemory) {
                if let Ok(size) = storage::database_size(&conn) {
                    if size > memory_threshold {
                        match storage::promote_to_file(&conn, &file_path, &max_memory_per_connection)
                        {
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

            let _ = msg.response_tx.send(result);
        }

        tracing::debug!(space=%space_id, db=%db_name, "Database actor shutting down");
    });

    DatabaseHandle { tx }
}

fn handle_message(
    conn: &duckdb::Connection,
    request: &DuckDbRequest,
    caveats: &Option<DuckDbCaveats>,
    ability: &str,
) -> Result<DuckDbResponse, DuckDbError> {
    // No authorizer in DuckDB -- parser is the sole defense
    match request {
        DuckDbRequest::Query { sql, params } => {
            parser::validate_sql(sql, caveats, ability)?;
            execute_query(conn, sql, params).map(DuckDbResponse::Query)
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
            let caveats_ref = caveats.as_ref().ok_or_else(|| {
                DuckDbError::InvalidStatement("No caveats found".to_string())
            })?;
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
            describe::describe_schema(conn).map(DuckDbResponse::Describe)
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

    let columns: Vec<String> = stmt.column_names();

    let duckdb_params: Vec<duckdb::types::Value> =
        params.iter().map(duckdb_value_to_param).collect();
    let param_refs: Vec<&dyn duckdb::types::ToSql> = duckdb_params
        .iter()
        .map(|p| p as &dyn duckdb::types::ToSql)
        .collect();

    let mut rows = Vec::new();
    let mut size_estimate: usize = 0;

    let mut query_rows = stmt
        .query(param_refs.as_slice())
        .map_err(|e| DuckDbError::DuckDb(e.to_string()))?;

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

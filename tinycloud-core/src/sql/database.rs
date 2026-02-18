use std::path::PathBuf;

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
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(300); // 5 min

struct DbMessage {
    request: SqlRequest,
    caveats: Option<SqlCaveats>,
    ability: String,
    response_tx: oneshot::Sender<Result<SqlResponse, SqlError>>,
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
            .send(DbMessage {
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
}

pub fn spawn_actor(
    space_id: String,
    db_name: String,
    base_path: String,
    memory_threshold: u64,
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

            let result = handle_message(&conn, &msg.request, &msg.caveats, &msg.ability);

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

            let _ = msg.response_tx.send(result);
        }

        tracing::debug!(space=%space_id, db=%db_name, "Database actor shutting down");
    });

    DatabaseHandle { tx }
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

            parser::validate_sql(sql, caveats, ability)?;
            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let result = execute_statement(conn, sql, params);

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result.map(SqlResponse::Execute)
        }
        SqlRequest::Batch { statements } => {
            for stmt in statements {
                parser::validate_sql(&stmt.sql, caveats, ability)?;
            }

            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let mut results = Vec::new();
            for stmt in statements {
                match execute_statement(conn, &stmt.sql, &stmt.params) {
                    Ok(result) => results.push(result),
                    Err(e) => {
                        conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
                        return Err(e);
                    }
                }
            }

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            Ok(SqlResponse::Batch(BatchResponse { results }))
        }
        SqlRequest::ExecuteStatement { name, params } => {
            let caveats_ref = caveats
                .as_ref()
                .ok_or_else(|| SqlError::InvalidStatement("No caveats found".to_string()))?;
            let prepared = caveats_ref.find_statement(name).ok_or_else(|| {
                SqlError::InvalidStatement(format!("Statement '{}' not found", name))
            })?;

            parser::validate_sql(&prepared.sql, caveats, ability)?;

            let auth =
                authorizer::create_authorizer(caveats.clone(), ability.to_string(), is_admin);
            conn.authorizer(Some(auth));

            let result = if prepared
                .sql
                .trim_start()
                .to_uppercase()
                .starts_with("SELECT")
            {
                execute_query(conn, &prepared.sql, params).map(SqlResponse::Query)
            } else {
                execute_statement(conn, &prepared.sql, params).map(SqlResponse::Execute)
            };

            conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);

            result
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

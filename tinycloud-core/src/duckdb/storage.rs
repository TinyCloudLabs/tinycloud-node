use std::path::{Path, PathBuf};

use duckdb::{Config, Connection};

use super::{parser::validate_diagnostic_sql, types::DuckDbError};

#[derive(Debug, Clone)]
pub enum StorageMode {
    InMemory,
    File(PathBuf),
}

/// Open a database with the native diagnostic and external-access policy locked.
/// A missing path selects an in-memory database.
pub fn open_connection(path: Option<&Path>, max_memory: &str) -> Result<Connection, DuckDbError> {
    open_guarded_connection(path, Some(max_memory))
}

/// Open an offline snapshot/cache under the node's complete native admission
/// policy, including the stored-code audit. Offline identity tooling has no
/// trusted memory setting, so preserve DuckDB's native default rather than
/// inventing a node limit or reading operator configuration.
pub fn open_offline_connection(path: &Path) -> Result<Connection, DuckDbError> {
    open_guarded_connection(Some(path), None)
}

fn open_guarded_connection(
    path: Option<&Path>,
    max_memory: Option<&str>,
) -> Result<Connection, DuckDbError> {
    // External access must already be disabled during native open/WAL recovery.
    // Profiling and logging are disabled by default; their setters require a
    // live connection in DuckDB, so explicitly reset them before any catalog SQL.
    let config = Config::default()
        .enable_external_access(false)
        .map_err(|e| DuckDbError::Internal(e.to_string()))?;
    let conn = match path {
        None => Connection::open_in_memory_with_flags(config)
            .map_err(|e| DuckDbError::Internal(e.to_string()))?,
        Some(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| DuckDbError::Internal(e.to_string()))?;
            }
            Connection::open_with_flags(path, config)
                .map_err(|e| DuckDbError::Internal(e.to_string()))?
        }
    };

    apply_security_settings(&conn, max_memory)?;
    audit_stored_code(&conn)?;

    Ok(conn)
}

fn validate_max_memory(value: &str) -> Result<(), DuckDbError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || !trimmed.chars().next().unwrap().is_ascii_digit() {
        return Err(DuckDbError::Internal(format!(
            "Invalid max_memory: {}",
            value
        )));
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ' ')
    {
        return Err(DuckDbError::Internal(format!(
            "Invalid max_memory: {}",
            value
        )));
    }
    Ok(())
}

fn apply_security_settings(conn: &Connection, max_memory: Option<&str>) -> Result<(), DuckDbError> {
    if let Some(max_memory) = max_memory {
        validate_max_memory(max_memory)?;
    }

    // All operator configuration precedes the irreversible tenant-facing lock.
    // "no_output" alone still enables profiling, so reset it instead.
    conn.execute_batch(
        "RESET enable_profiling;\
         SET enable_logging = false;\
         SET enable_http_logging = false;\
         RESET log_query_path;\
         RESET profiling_output;\
         SET enable_external_access = false;\
         SET allow_unsigned_extensions = false;\
         SET checkpoint_threshold = '1TB';",
    )
    .map_err(|e| DuckDbError::Internal(format!("Failed to apply security settings: {}", e)))?;
    if let Some(max_memory) = max_memory {
        conn.execute_batch(&format!("SET max_memory = '{}';", max_memory))
            .map_err(|e| {
                DuckDbError::Internal(format!("Failed to apply security settings: {}", e))
            })?;
    }
    conn.execute_batch("SET lock_configuration = true;")
        .map_err(|e| DuckDbError::Internal(format!("Failed to apply security settings: {}", e)))?;
    Ok(())
}

fn audit_stored_code(conn: &Connection) -> Result<(), DuckDbError> {
    // Fully qualify native catalog functions so imported macros cannot run
    // during admission. Inspect every user definition, including indirect calls.
    //
    // Table DDL also contains native type syntax (for example INTEGER[3]) that
    // is not executable SQL. Audit the native catalog's typed executable fields
    // instead: column_default includes both defaults and generated expressions;
    // CHECK constraints expose their executable expression separately.
    for (catalog_sql, expression) in [
        (
            "SELECT sql FROM system.main.duckdb_views() WHERE NOT internal",
            false,
        ),
        (
            "SELECT column_default FROM system.main.duckdb_columns() \
             WHERE NOT internal AND column_default IS NOT NULL",
            true,
        ),
        (
            "SELECT c.expression FROM system.main.duckdb_constraints() AS c \
             JOIN system.main.duckdb_tables() AS t \
             ON c.database_oid = t.database_oid AND c.schema_oid = t.schema_oid \
             AND c.table_oid = t.table_oid \
             WHERE NOT t.internal AND c.constraint_type = 'CHECK'",
            true,
        ),
    ] {
        let mut stmt = conn.prepare(catalog_sql).map_err(|_| stored_code_error())?;
        let definitions = stmt
            .query_map([], |row| row.get::<_, Option<String>>(0))
            .map_err(|_| stored_code_error())?;
        for definition in definitions {
            let definition = definition
                .map_err(|_| stored_code_error())?
                .ok_or_else(stored_code_error)?;
            if expression {
                validate_diagnostic_sql(&format!("SELECT {}", definition))
                    .map_err(|_| stored_code_error())?;
            } else {
                validate_diagnostic_sql(&definition).map_err(|_| stored_code_error())?;
            }
        }
    }

    let mut stmt = conn
        .prepare(
            "SELECT function_type, macro_definition \
             FROM system.main.duckdb_functions() \
             WHERE NOT internal AND function_type IN ('macro', 'table_macro')",
        )
        .map_err(|_| stored_code_error())?;
    let definitions = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?))
        })
        .map_err(|_| stored_code_error())?;
    for definition in definitions {
        let (kind, definition) = definition.map_err(|_| stored_code_error())?;
        let definition = definition.ok_or_else(stored_code_error)?;
        if kind == "macro" {
            validate_diagnostic_sql(&format!("SELECT {}", definition))
                .map_err(|_| stored_code_error())?;
        } else {
            validate_diagnostic_sql(&definition).map_err(|_| stored_code_error())?;
        }
    }
    Ok(())
}

fn stored_code_error() -> DuckDbError {
    // Never include persisted SQL, object names, or native parser snippets.
    DuckDbError::PermissionDenied(
        "Stored database code cannot be admitted under the diagnostic policy".to_string(),
    )
}

pub fn database_size(conn: &Connection) -> Result<u64, DuckDbError> {
    let mut stmt = conn
        .prepare("SELECT SUM(total_blocks * block_size) FROM pragma_database_size()")
        .map_err(|e| DuckDbError::Internal(e.to_string()))?;

    let size: Result<Option<i64>, _> = stmt.query_row([], |row| row.get(0));
    match size {
        Ok(Some(s)) => Ok(s as u64),
        Ok(None) => Ok(0),
        Err(e) => Err(DuckDbError::Internal(e.to_string())),
    }
}

/// Promote an in-memory database through the same guarded file-open policy.
pub fn promote_to_file(
    conn: &Connection,
    path: &Path,
    max_memory: &str,
) -> Result<Connection, DuckDbError> {
    let file_conn = open_connection(Some(path), max_memory)?;

    // Copy tables from in-memory conn to file-backed conn
    copy_tables(conn, &file_conn)?;

    Ok(file_conn)
}

/// Copy all user tables and views from one connection to another.
/// Uses Arrow record batches for fast bulk transfer.
/// Audits all source executable definitions before copying any schema or rows.
pub fn copy_tables(src: &Connection, dest: &Connection) -> Result<(), DuckDbError> {
    audit_stored_code(src)?;

    // Get all user tables
    let mut stmt = src
        .prepare(
            "SELECT table_name FROM system.main.duckdb_tables() \
             WHERE schema_name = 'main' AND NOT internal",
        )
        .map_err(|e| DuckDbError::Internal(e.to_string()))?;

    let table_names: Vec<String> = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| DuckDbError::Internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DuckDbError::Internal(e.to_string()))?;

    for table in &table_names {
        // Get CREATE TABLE DDL
        let create_sql: String = src
            .query_row(
                &format!(
                    "SELECT sql FROM system.main.duckdb_tables() \
                     WHERE schema_name = 'main' AND table_name = '{}'",
                    table.replace('\'', "''")
                ),
                [],
                |row| row.get(0),
            )
            .map_err(|e| {
                DuckDbError::Internal(format!("Failed to get DDL for {}: {}", table, e))
            })?;

        dest.execute_batch(&create_sql).map_err(|e| {
            DuckDbError::Internal(format!("Failed to create table {}: {}", table, e))
        })?;

        // Bulk copy via Arrow record batches
        let mut read_stmt = src
            .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
            .map_err(|e| DuckDbError::Internal(e.to_string()))?;

        let arrow_result = read_stmt
            .query_arrow([])
            .map_err(|e| DuckDbError::Internal(e.to_string()))?;

        let mut appender = dest.appender(table).map_err(|e| {
            DuckDbError::Internal(format!("Failed to create appender for {}: {}", table, e))
        })?;

        for batch in arrow_result {
            appender.append_record_batch(batch).map_err(|e| {
                DuckDbError::Internal(format!("Failed to append batch for {}: {}", table, e))
            })?;
        }
    }

    // Copy views
    let mut view_stmt = src
        .prepare(
            "SELECT view_name, sql FROM system.main.duckdb_views() \
             WHERE schema_name = 'main' AND NOT internal",
        )
        .map_err(|e| DuckDbError::Internal(e.to_string()))?;

    let views: Vec<(String, String)> = view_stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| DuckDbError::Internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DuckDbError::Internal(e.to_string()))?;

    for (_, view_sql) in &views {
        validate_diagnostic_sql(view_sql).map_err(|_| stored_code_error())?;
        if let Err(e) = dest.execute_batch(view_sql) {
            tracing::warn!(error=%e, "failed to copy view during table copy");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_max_memory_valid() {
        assert!(validate_max_memory("128MB").is_ok());
        assert!(validate_max_memory("1GB").is_ok());
        assert!(validate_max_memory("256 MiB").is_ok());
        assert!(validate_max_memory("1024").is_ok());
    }

    #[test]
    fn test_validate_max_memory_invalid() {
        assert!(validate_max_memory("'; DROP TABLE users; --").is_err());
        assert!(validate_max_memory("").is_err());
        assert!(validate_max_memory("abc").is_err());
        assert!(validate_max_memory("128MB; malicious").is_err());
    }
}

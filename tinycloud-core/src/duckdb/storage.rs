use std::path::PathBuf;

use duckdb::Connection;

use super::types::DuckDbError;

#[derive(Debug, Clone)]
pub enum StorageMode {
    InMemory,
    File(PathBuf),
}

pub fn open_connection(mode: &StorageMode, max_memory: &str) -> Result<Connection, DuckDbError> {
    let conn = match mode {
        StorageMode::InMemory => {
            Connection::open_in_memory().map_err(|e| DuckDbError::Internal(e.to_string()))?
        }
        StorageMode::File(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| DuckDbError::Internal(e.to_string()))?;
            }
            Connection::open(path).map_err(|e| DuckDbError::Internal(e.to_string()))?
        }
    };

    apply_security_settings(&conn, max_memory)?;

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

pub fn apply_security_settings(conn: &Connection, max_memory: &str) -> Result<(), DuckDbError> {
    validate_max_memory(max_memory)?;

    conn.execute_batch(&format!(
        "SET enable_external_access = false;\
         SET allow_unsigned_extensions = false;\
         SET max_memory = '{}';",
        max_memory
    ))
    .map_err(|e| DuckDbError::Internal(format!("Failed to apply security settings: {}", e)))?;
    Ok(())
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

pub fn promote_to_file(
    conn: &Connection,
    path: &PathBuf,
    max_memory: &str,
) -> Result<Connection, DuckDbError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| DuckDbError::Internal(e.to_string()))?;
    }

    let file_conn = Connection::open(path).map_err(|e| DuckDbError::Internal(e.to_string()))?;
    apply_security_settings(&file_conn, max_memory)?;

    // Copy tables from in-memory conn to file-backed conn
    copy_tables(conn, &file_conn)?;

    Ok(file_conn)
}

/// Copy all user tables and views from one connection to another.
/// Uses Arrow record batches for fast bulk transfer.
pub fn copy_tables(src: &Connection, dest: &Connection) -> Result<(), DuckDbError> {
    // Get all user tables
    let mut stmt = src
        .prepare(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'main' AND table_type = 'BASE TABLE'",
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
                    "SELECT sql FROM duckdb_tables() WHERE table_name = '{}'",
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
        .prepare("SELECT view_name, sql FROM duckdb_views() WHERE schema_name = 'main'")
        .map_err(|e| DuckDbError::Internal(e.to_string()))?;

    let views: Vec<(String, String)> = view_stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| DuckDbError::Internal(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| DuckDbError::Internal(e.to_string()))?;

    for (name, view_sql) in &views {
        if let Err(e) = dest.execute_batch(view_sql) {
            tracing::warn!(view=%name, error=%e, "failed to copy view during table copy");
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

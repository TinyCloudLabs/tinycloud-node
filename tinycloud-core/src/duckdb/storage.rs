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

    let temp_dir = tempfile::tempdir().map_err(|e| DuckDbError::Internal(e.to_string()))?;
    let temp_path = temp_dir.path().to_string_lossy().to_string();

    // Temporarily enable external access for EXPORT DATABASE
    conn.execute_batch("SET enable_external_access = true;")
        .map_err(|e| {
            DuckDbError::Internal(format!(
                "Failed to enable external access for export: {}",
                e
            ))
        })?;

    let export_result = conn.execute_batch(&format!("EXPORT DATABASE '{}';", temp_path));

    // Always re-disable external access
    let _ = conn.execute_batch("SET enable_external_access = false;");

    export_result
        .map_err(|e| DuckDbError::Internal(format!("Failed to export database: {}", e)))?;

    let file_conn = Connection::open(path).map_err(|e| DuckDbError::Internal(e.to_string()))?;
    apply_security_settings(&file_conn, max_memory)?;

    file_conn
        .execute_batch(&format!("IMPORT DATABASE '{}';", temp_path))
        .map_err(|e| DuckDbError::Internal(format!("Failed to import database: {}", e)))?;

    Ok(file_conn)
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

use std::path::PathBuf;

use rusqlite::Connection;

use super::types::SqlError;

#[derive(Debug, Clone)]
pub enum StorageMode {
    InMemory,
    File(PathBuf),
}

pub fn open_connection(mode: &StorageMode) -> Result<Connection, SqlError> {
    let conn = match mode {
        StorageMode::InMemory => {
            Connection::open_in_memory().map_err(|e| SqlError::Internal(e.to_string()))?
        }
        StorageMode::File(path) => {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(|e| SqlError::Internal(e.to_string()))?;
            }
            Connection::open(path).map_err(|e| SqlError::Internal(e.to_string()))?
        }
    };

    // Enable WAL mode for file-backed databases
    if matches!(mode, StorageMode::File(_)) {
        conn.pragma_update(None, "journal_mode", "wal")
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    // Enable foreign keys
    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| SqlError::Internal(e.to_string()))?;

    Ok(conn)
}

pub fn database_size(conn: &Connection) -> Result<u64, SqlError> {
    let page_count: u64 = conn
        .pragma_query_value(None, "page_count", |row| row.get(0))
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    let page_size: u64 = conn
        .pragma_query_value(None, "page_size", |row| row.get(0))
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    Ok(page_count * page_size)
}

pub fn promote_to_file(conn: &Connection, path: &PathBuf) -> Result<Connection, SqlError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    let mut file_conn = Connection::open(path).map_err(|e| SqlError::Internal(e.to_string()))?;

    // Use SQLite backup API
    {
        let backup = rusqlite::backup::Backup::new(conn, &mut file_conn)
            .map_err(|e: rusqlite::Error| SqlError::Internal(e.to_string()))?;
        backup
            .run_to_completion(5, std::time::Duration::from_millis(250), None)
            .map_err(|e: rusqlite::Error| SqlError::Internal(e.to_string()))?;
    }

    // Enable WAL on the new file
    file_conn
        .pragma_update(None, "journal_mode", "wal")
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    file_conn
        .pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| SqlError::Internal(e.to_string()))?;

    Ok(file_conn)
}

use std::path::PathBuf;

use rusqlite::Connection;

use crate::request_telemetry::QueryTimer;

use super::durability::{create_dir_all_durable, set_synchronous, sync_dir, Synchronous};
use super::types::SqlError;

#[derive(Debug, Clone)]
pub enum StorageMode {
    InMemory,
    File(PathBuf),
}

pub fn open_connection(
    mode: &StorageMode,
    synchronous: Synchronous,
) -> Result<Connection, SqlError> {
    let conn = match mode {
        StorageMode::InMemory => {
            Connection::open_in_memory().map_err(|e| SqlError::Internal(e.to_string()))?
        }
        StorageMode::File(path) => {
            if let Some(parent) = path.parent() {
                create_dir_all_durable(parent).map_err(|e| SqlError::Internal(e.to_string()))?;
            }
            Connection::open(path).map_err(|e| SqlError::Internal(e.to_string()))?
        }
    };

    // Enable WAL mode for file-backed databases
    if matches!(mode, StorageMode::File(_)) {
        // Before the journal mode: the WAL switch is itself a write.
        set_synchronous(&conn, synchronous)?;
        {
            let _timer = QueryTimer::new();
            conn.pragma_update(None, "journal_mode", "wal")
                .map_err(|e| SqlError::Internal(e.to_string()))?;
        }
        {
            let _timer = QueryTimer::new();
            conn.pragma_update(None, "wal_autocheckpoint", 0)
                .map_err(|e| SqlError::Internal(e.to_string()))?;
        }
    }

    // Enable foreign keys
    {
        let _timer = QueryTimer::new();
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    Ok(conn)
}

/// Open the working copy of a store-master database (TC-1491 P4.2a): the file
/// must exist (it is never created here), runs in WAL mode with
/// auto-checkpoint off, and does **not** checkpoint when its connection
/// closes.
///
/// The WAL is where the newest acknowledged writes live until the uploader
/// has published them. A checkpoint-on-close (idle exit, shutdown, retire)
/// would fold them into the main file and delete the WAL behind the
/// uploader's back; `SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE` leaves both files as
/// they are. The only checkpoint a store-master database gets is the
/// explicit TRUNCATE the uploader runs under the operation lock (a rotation:
/// it publishes the new main file as a snapshot).
pub fn open_store_master_connection(
    mode: &StorageMode,
    synchronous: Synchronous,
) -> Result<Connection, SqlError> {
    let StorageMode::File(path) = mode else {
        return Err(SqlError::Internal(
            "a store-master database must be file-backed".into(),
        ));
    };
    if !path.is_file() {
        return Err(SqlError::Unavailable);
    }
    let conn = open_connection(mode, synchronous)?;
    conn.set_db_config(
        rusqlite::config::DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE,
        true,
    )
    .map_err(|e| SqlError::Internal(e.to_string()))?;
    Ok(conn)
}

pub fn database_size(conn: &Connection) -> Result<u64, SqlError> {
    let page_count: u64 = {
        let _timer = QueryTimer::new();
        conn.pragma_query_value(None, "page_count", |row| row.get(0))
            .map_err(|e| SqlError::Internal(e.to_string()))?
    };
    let page_size: u64 = {
        let _timer = QueryTimer::new();
        conn.pragma_query_value(None, "page_size", |row| row.get(0))
            .map_err(|e| SqlError::Internal(e.to_string()))?
    };
    Ok(page_count * page_size)
}

pub fn promote_to_file(
    conn: &Connection,
    path: &PathBuf,
    synchronous: Synchronous,
) -> Result<Connection, SqlError> {
    if let Some(parent) = path.parent() {
        create_dir_all_durable(parent).map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    // rusqlite appends the file path, which holds the space id, to open
    // errors. The caller logs this error, so keep only the SQLite code (TC-961).
    let mut file_conn = Connection::open(path).map_err(|e| {
        SqlError::Internal(format!(
            "opening the database file failed: {:?}",
            e.sqlite_error_code()
        ))
    })?;

    // The copy below is a write to the new file: sync it like any other.
    set_synchronous(&file_conn, synchronous)?;

    // Use SQLite backup API
    // Native backup and filesystem I/O are not SQL query attempts.
    {
        let backup = rusqlite::backup::Backup::new(conn, &mut file_conn)
            .map_err(|e: rusqlite::Error| SqlError::Internal(e.to_string()))?;
        // Single-step, unpaced copy (rusqlite rejects the sqlite "-1 = all
        // pages" sentinel, so use i32::MAX): the caller blocks the actor on
        // this promotion, and pacing (5 pages / 250ms) caps it at ~80KB/s
        // (tinycloud-node#112).
        backup
            .run_to_completion(i32::MAX, std::time::Duration::ZERO, None)
            .map_err(|e: rusqlite::Error| SqlError::Internal(e.to_string()))?;
    }

    // Enable WAL on the new file
    {
        let _timer = QueryTimer::new();
        file_conn
            .pragma_update(None, "journal_mode", "wal")
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }
    {
        let _timer = QueryTimer::new();
        file_conn
            .pragma_update(None, "wal_autocheckpoint", 0)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }
    {
        let _timer = QueryTimer::new();
        file_conn
            .pragma_update(None, "foreign_keys", "ON")
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    // SQLite syncs the file's contents but not the directory entry that
    // names it; without this a crash can lose the whole new database file.
    if let Some(parent) = path.parent() {
        sync_dir(parent).map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    Ok(file_conn)
}

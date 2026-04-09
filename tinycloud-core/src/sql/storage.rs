use std::path::{Path, PathBuf};

use rusqlite::{backup::Progress, Connection, DatabaseName, OpenFlags};

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

    configure_connection(&conn, matches!(mode, StorageMode::File(_)))?;

    Ok(conn)
}

pub fn export_snapshot(conn: &Connection) -> Result<Vec<u8>, SqlError> {
    let temp_dir = tempfile::tempdir().map_err(|e| SqlError::Internal(e.to_string()))?;
    let temp_path = temp_dir.path().join("export.db");

    let mut dest = Connection::open(&temp_path).map_err(|e| SqlError::Internal(e.to_string()))?;
    {
        let backup = rusqlite::backup::Backup::new(conn, &mut dest)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
        backup
            .run_to_completion(5, std::time::Duration::from_millis(250), None)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }
    drop(dest);

    std::fs::read(&temp_path).map_err(|e| SqlError::Internal(e.to_string()))
}

pub fn export_snapshot_from_path(path: &Path) -> Result<Vec<u8>, SqlError> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    export_snapshot(&conn)
}

pub fn import_snapshot(
    conn: &mut Connection,
    snapshot: &[u8],
    enable_wal: bool,
) -> Result<(), SqlError> {
    let temp_dir = tempfile::tempdir().map_err(|e| SqlError::Internal(e.to_string()))?;
    let temp_path = temp_dir.path().join("import.db");
    std::fs::write(&temp_path, snapshot).map_err(|e| SqlError::Internal(e.to_string()))?;

    conn.restore(DatabaseName::Main, &temp_path, None::<fn(Progress)>)
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    configure_connection(conn, enable_wal)?;

    Ok(())
}

pub fn import_snapshot_to_path(path: &Path, snapshot: &[u8]) -> Result<(), SqlError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    let mut conn = Connection::open(path).map_err(|e| SqlError::Internal(e.to_string()))?;
    import_snapshot(&mut conn, snapshot, true)?;

    Ok(())
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

    {
        let backup = rusqlite::backup::Backup::new(conn, &mut file_conn)
            .map_err(|e: rusqlite::Error| SqlError::Internal(e.to_string()))?;
        backup
            .run_to_completion(5, std::time::Duration::from_millis(250), None)
            .map_err(|e: rusqlite::Error| SqlError::Internal(e.to_string()))?;
    }

    configure_connection(&file_conn, true)?;

    Ok(file_conn)
}

fn configure_connection(conn: &Connection, enable_wal: bool) -> Result<(), SqlError> {
    if enable_wal {
        conn.pragma_update(None, "journal_mode", "wal")
            .map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    conn.pragma_update(None, "foreign_keys", "ON")
        .map_err(|e| SqlError::Internal(e.to_string()))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        export_snapshot, export_snapshot_from_path, import_snapshot, import_snapshot_to_path,
    };
    use crate::sql::storage::{open_connection, StorageMode};

    fn query_names(conn: &Connection) -> Vec<String> {
        let mut stmt = conn
            .prepare("SELECT name FROM items ORDER BY id")
            .expect("prepare query");
        let rows = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .expect("query rows");
        rows.map(|row| row.expect("row value")).collect()
    }

    use rusqlite::Connection;

    #[test]
    fn exports_and_imports_in_memory_snapshots() {
        let conn = open_connection(&StorageMode::InMemory).expect("open source database");
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
             INSERT INTO items (name) VALUES ('alpha'), ('beta');",
        )
        .expect("seed source database");

        let snapshot = export_snapshot(&conn).expect("export snapshot");
        let mut restored = open_connection(&StorageMode::InMemory).expect("open restore database");
        import_snapshot(&mut restored, &snapshot, false).expect("import snapshot");

        assert_eq!(query_names(&restored), vec!["alpha", "beta"]);
    }

    #[test]
    fn exports_file_backed_snapshots_via_sqlite() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("items.db");

        let conn = open_connection(&StorageMode::File(db_path.clone())).expect("open file db");
        conn.execute_batch(
            "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
             INSERT INTO items (name) VALUES ('gamma');",
        )
        .expect("seed file db");
        drop(conn);

        let snapshot = export_snapshot_from_path(&db_path).expect("export cold snapshot");
        let mut restored = open_connection(&StorageMode::InMemory).expect("open restore db");
        import_snapshot(&mut restored, &snapshot, false).expect("restore cold snapshot");

        assert_eq!(query_names(&restored), vec!["gamma"]);
    }

    #[test]
    fn imports_snapshots_into_file_paths() {
        let source = open_connection(&StorageMode::InMemory).expect("open source db");
        source
            .execute_batch(
                "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
                 INSERT INTO items (name) VALUES ('delta');",
            )
            .expect("seed source db");
        let snapshot = export_snapshot(&source).expect("export source snapshot");

        let temp_dir = tempfile::tempdir().expect("temp dir");
        let db_path = temp_dir.path().join("restored.db");
        import_snapshot_to_path(&db_path, &snapshot).expect("import to file path");

        let restored =
            open_connection(&StorageMode::File(db_path)).expect("open restored file database");
        assert_eq!(query_names(&restored), vec!["delta"]);
    }
}

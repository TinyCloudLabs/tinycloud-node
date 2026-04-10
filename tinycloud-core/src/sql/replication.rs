use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use rusqlite::hooks::{AuthContext, Authorization};
use rusqlite::session::{Changegroup, ConflictAction, ConflictType};
use rusqlite::{params, Connection, OptionalExtension};

use super::{
    storage::{self, StorageMode},
    types::SqlError,
};

pub const INTERNAL_REPLICATION_TABLE_PREFIX: &str = "__tinycloud_sql_replication_";
const REPLICATION_LOG_TABLE: &str = "__tinycloud_sql_replication_log";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlReplicationMode {
    Snapshot,
    Changeset,
}

impl SqlReplicationMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Changeset => "changeset",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SqlReplicationExport {
    pub mode: SqlReplicationMode,
    pub exported_until_seq: i64,
    pub snapshot_reason: Option<String>,
    pub snapshot: Vec<u8>,
    pub changeset: Vec<u8>,
    pub change_count: usize,
}

pub fn is_internal_table_name(name: &str) -> bool {
    let last_segment = name.rsplit('.').next().unwrap_or(name);
    let normalized = last_segment
        .trim_matches('"')
        .trim_matches('`')
        .trim_matches('[')
        .trim_matches(']')
        .to_ascii_lowercase();
    normalized.starts_with(INTERNAL_REPLICATION_TABLE_PREFIX)
}

pub fn append_changeset(conn: &Connection, changeset: &[u8]) -> Result<Option<i64>, SqlError> {
    if changeset.is_empty() {
        return Ok(None);
    }

    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    ensure_replication_log(conn)?;
    conn.execute(
        &format!(
            "INSERT INTO {REPLICATION_LOG_TABLE} (kind, changeset, reason, created_at) VALUES (?, ?, NULL, unixepoch())"
        ),
        params!["changeset", changeset],
    )
    .map_err(|e| SqlError::Internal(e.to_string()))?;

    Ok(Some(conn.last_insert_rowid()))
}

pub fn append_snapshot_barrier(conn: &Connection, reason: &str) -> Result<i64, SqlError> {
    conn.authorizer(None::<fn(AuthContext<'_>) -> Authorization>);
    ensure_replication_log(conn)?;
    conn.execute(
        &format!(
            "INSERT INTO {REPLICATION_LOG_TABLE} (kind, changeset, reason, created_at) VALUES (?, NULL, ?, unixepoch())"
        ),
        params!["snapshot", reason],
    )
    .map_err(|e| SqlError::Internal(e.to_string()))?;

    Ok(conn.last_insert_rowid())
}

pub fn export_replication(
    conn: &Connection,
    since_seq: Option<i64>,
) -> Result<SqlReplicationExport, SqlError> {
    if since_seq.is_none() {
        return Ok(SqlReplicationExport {
            mode: SqlReplicationMode::Snapshot,
            exported_until_seq: current_seq(conn)?,
            snapshot_reason: Some("initial-sync".to_string()),
            snapshot: storage::export_snapshot(conn)?,
            changeset: Vec::new(),
            change_count: 0,
        });
    }

    let since_seq = since_seq.unwrap_or(0);
    let exported_until_seq = current_seq(conn)?;

    if let Some(reason) = snapshot_barrier_since(conn, since_seq)? {
        return Ok(SqlReplicationExport {
            mode: SqlReplicationMode::Snapshot,
            exported_until_seq,
            snapshot_reason: Some(reason),
            snapshot: storage::export_snapshot(conn)?,
            changeset: Vec::new(),
            change_count: 0,
        });
    }

    let (changeset, change_count) = combined_changeset_since(conn, since_seq)?;
    Ok(SqlReplicationExport {
        mode: SqlReplicationMode::Changeset,
        exported_until_seq,
        snapshot_reason: None,
        snapshot: Vec::new(),
        changeset,
        change_count,
    })
}

pub fn export_replication_from_path(
    path: &Path,
    since_seq: Option<i64>,
) -> Result<SqlReplicationExport, SqlError> {
    let conn =
        storage::open_connection(&StorageMode::File(path.to_path_buf())).map_err(|e| match e {
            SqlError::Internal(_) => e,
            other => SqlError::Internal(other.to_string()),
        })?;
    export_replication(&conn, since_seq)
}

pub fn apply_changeset(conn: &Connection, changeset: &[u8]) -> Result<(), SqlError> {
    if changeset.is_empty() {
        return Ok(());
    }

    let mut input = changeset;
    conn.apply_strm(
        &mut input,
        Some(|table: &str| !is_internal_table_name(table)),
        |_conflict_type: ConflictType, _item| ConflictAction::SQLITE_CHANGESET_ABORT,
    )
    .map_err(|e| SqlError::Internal(e.to_string()))
}

pub fn apply_changeset_to_path(path: &Path, changeset: &[u8]) -> Result<(), SqlError> {
    let conn = storage::open_connection(&StorageMode::File(path.to_path_buf()))?;
    apply_changeset(&conn, changeset)
}

pub fn read_peer_cursor(
    base_path: &str,
    space_id: &str,
    db_name: &str,
    peer_url: &str,
) -> Result<Option<i64>, SqlError> {
    let path = cursor_state_path(base_path, space_id, db_name);
    let state = read_cursor_state(&path)?;
    Ok(state.get(peer_url).copied())
}

pub fn write_peer_cursor(
    base_path: &str,
    space_id: &str,
    db_name: &str,
    peer_url: &str,
    seq: i64,
) -> Result<(), SqlError> {
    let path = cursor_state_path(base_path, space_id, db_name);
    let mut state = read_cursor_state(&path)?;
    state.insert(peer_url.to_string(), seq);
    write_cursor_state(&path, &state)
}

fn combined_changeset_since(
    conn: &Connection,
    since_seq: i64,
) -> Result<(Vec<u8>, usize), SqlError> {
    if !replication_log_exists(conn)? {
        return Ok((Vec::new(), 0));
    }

    let mut stmt = conn
        .prepare(&format!(
            "SELECT changeset FROM {REPLICATION_LOG_TABLE} WHERE seq > ? AND kind = 'changeset' ORDER BY seq ASC"
        ))
        .map_err(|e| SqlError::Internal(e.to_string()))?;

    let mut rows = stmt
        .query(params![since_seq])
        .map_err(|e| SqlError::Internal(e.to_string()))?;

    let mut changegroup = Changegroup::new().map_err(|e| SqlError::Internal(e.to_string()))?;
    let mut change_count = 0usize;

    while let Some(row) = rows.next().map_err(|e| SqlError::Internal(e.to_string()))? {
        let changeset: Vec<u8> = row.get(0).map_err(|e| SqlError::Internal(e.to_string()))?;
        let mut input = changeset.as_slice();
        changegroup
            .add_stream(&mut input)
            .map_err(|e| SqlError::Internal(e.to_string()))?;
        change_count += 1;
    }

    if change_count == 0 {
        return Ok((Vec::new(), 0));
    }

    let mut output = Vec::new();
    changegroup
        .output_strm(&mut output)
        .map_err(|e| SqlError::Internal(e.to_string()))?;
    Ok((output, change_count))
}

fn snapshot_barrier_since(conn: &Connection, since_seq: i64) -> Result<Option<String>, SqlError> {
    if !replication_log_exists(conn)? {
        return Ok(None);
    }

    conn.query_row(
        &format!(
            "SELECT reason FROM {REPLICATION_LOG_TABLE} WHERE seq > ? AND kind = 'snapshot' ORDER BY seq ASC LIMIT 1"
        ),
        params![since_seq],
        |row| row.get::<_, String>(0),
    )
    .optional()
    .map_err(|e| SqlError::Internal(e.to_string()))
}

fn current_seq(conn: &Connection) -> Result<i64, SqlError> {
    if !replication_log_exists(conn)? {
        return Ok(0);
    }

    Ok(conn
        .query_row(
            &format!("SELECT COALESCE(MAX(seq), 0) FROM {REPLICATION_LOG_TABLE}"),
            [],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|e| SqlError::Internal(e.to_string()))?)
}

fn ensure_replication_log(conn: &Connection) -> Result<(), SqlError> {
    conn.execute_batch(&format!(
        "CREATE TABLE IF NOT EXISTS {REPLICATION_LOG_TABLE} (
            seq INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL CHECK(kind IN ('changeset', 'snapshot')),
            changeset BLOB,
            reason TEXT,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_{REPLICATION_LOG_TABLE}_kind_seq
            ON {REPLICATION_LOG_TABLE}(kind, seq);"
    ))
    .map_err(|e| SqlError::Internal(e.to_string()))
}

fn replication_log_exists(conn: &Connection) -> Result<bool, SqlError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?)",
        params![REPLICATION_LOG_TABLE],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value != 0)
    .map_err(|e| SqlError::Internal(e.to_string()))
}

fn cursor_state_path(base_path: &str, space_id: &str, db_name: &str) -> PathBuf {
    PathBuf::from(base_path)
        .join(space_id)
        .join(format!("{db_name}.replication-cursors.json"))
}

fn read_cursor_state(path: &Path) -> Result<BTreeMap<String, i64>, SqlError> {
    if !path.exists() {
        return Ok(BTreeMap::new());
    }

    let bytes = fs::read(path).map_err(|e| SqlError::Internal(e.to_string()))?;
    serde_json::from_slice(&bytes).map_err(|e| SqlError::Internal(e.to_string()))
}

fn write_cursor_state(path: &Path, state: &BTreeMap<String, i64>) -> Result<(), SqlError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| SqlError::Internal(e.to_string()))?;
    }

    let bytes = serde_json::to_vec_pretty(state).map_err(|e| SqlError::Internal(e.to_string()))?;
    let temp_path = path.with_extension("json.tmp");
    fs::write(&temp_path, bytes).map_err(|e| SqlError::Internal(e.to_string()))?;
    fs::rename(&temp_path, path).map_err(|e| SqlError::Internal(e.to_string()))
}

#[cfg(test)]
mod tests {
    use rusqlite::session::Session;

    use super::*;

    fn sample_changeset(conn: &Connection) -> Vec<u8> {
        conn.execute_batch("CREATE TABLE items (id TEXT PRIMARY KEY, label TEXT NOT NULL);")
            .expect("create table");
        let mut session = Session::new(conn).expect("session");
        session.attach(None).expect("attach");
        conn.execute(
            "INSERT INTO items (id, label) VALUES (?, ?)",
            params!["item-1", "camera"],
        )
        .expect("insert item");
        let mut changeset = Vec::new();
        session
            .changeset_strm(&mut changeset)
            .expect("changeset stream");
        changeset
    }

    #[test]
    fn exports_changesets_after_since_seq() {
        let conn = storage::open_connection(&StorageMode::InMemory).expect("connection");
        let changeset = sample_changeset(&conn);
        append_changeset(&conn, &changeset).expect("append changeset");

        let export = export_replication(&conn, Some(0)).expect("export changeset");
        assert_eq!(export.mode, SqlReplicationMode::Changeset);
        assert_eq!(export.exported_until_seq, 1);
        assert_eq!(export.change_count, 1);
        assert!(!export.changeset.is_empty());
        assert!(export.snapshot.is_empty());
    }

    #[test]
    fn falls_back_to_snapshot_after_barrier() {
        let conn = storage::open_connection(&StorageMode::InMemory).expect("connection");
        append_snapshot_barrier(&conn, "schema-change").expect("append barrier");

        let export = export_replication(&conn, Some(0)).expect("export snapshot");
        assert_eq!(export.mode, SqlReplicationMode::Snapshot);
        assert_eq!(export.snapshot_reason.as_deref(), Some("schema-change"));
        assert!(!export.snapshot.is_empty());
    }
}

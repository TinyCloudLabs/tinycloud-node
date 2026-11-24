//! The local working copy of a store-master SQL database (TC-1491 P4.2a,
//! design sections 5.3 and 12).
//!
//! Everything here is inert until a database's `sql_store_mode` row says
//! `store_master`; no cutover exists yet, so nothing in production reaches it.
//!
//! - **Sequence counter.** One reserved row, written in the same SQLite
//!   transaction as the write it counts ([`bump_seq`], called by the actor
//!   before COMMIT). A crash can therefore never reissue a `seq` with other
//!   content: the counter and the data are in the same WAL commit.
//! - **Reserved namespace.** Tables whose name starts with
//!   [`RESERVED_PREFIX`] are refused to user SQL by the authorizer, but only
//!   while the actor is store-master ([`names_reserved`]).
//! - **Checkpoint identity.** The manifest lineage anchor
//!   (`base_checkpoint_cid`) is, for a store-master database, the lowercase
//!   hex SHA-256 of the local main file (the checkpoint) at the moment it was
//!   published as a snapshot. The column keeps its meaning (the hash of the
//!   checkpoint bytes the snapshot object holds); only the bytes' origin
//!   changes from the Postgres artifact to the local file, because the
//!   Postgres artifact no longer moves. [`LocalFiles`] caches that hash by
//!   file identity so a commit never rehashes an unchanged file.
//! - **Pilot cap.** [`PILOT_CAP_BYTES`] (Sam, 2026-11-23): a store-master
//!   database whose checkpoint exceeds 64 MiB is refused by the source, which
//!   keeps the Postgres copy-back as the rollback.
//! - **Window.** [`WINDOW`] and [`WINDOW_BYTES`] (Sam, 2026-11-23): the
//!   store may lag the local file by 60 s or 8 MiB, whichever comes first.
//!   There is no wait-for-store on commit.
//!
//! No code here changes a database's mode, owner or epoch. A takeover of a
//! database after its owner is lost stays a manual operator action behind an
//! expired lease and a logged loss (P4.2c); nothing in this slice takes over.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use rusqlite::hooks::AuthAction;
use rusqlite::Connection;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use super::key::DbRef;
use super::mode::{read_mode, ModeError, StoreMode};
use super::shadow::DbKey;
use crate::database_artifacts::WalMark;
use crate::models::sql_store_mode as mode_row;
use crate::sql::durability::Synchronous;
use crate::sql::storage::{open_store_master_connection, StorageMode};
use crate::sql::types::SqlError;

/// The largest checkpoint a store-master database may have during the pilot.
pub const PILOT_CAP_BYTES: u64 = 64 * 1024 * 1024;

/// The store may lag the local file by this many bytes ...
pub const WINDOW_BYTES: u64 = 8 * 1024 * 1024;

/// ... or by this long, whichever comes first.
pub const WINDOW: Duration = Duration::from_secs(60);

/// A write is refused (retryable, nothing applied) once the WAL holds this
/// many bytes. The uploader rotates at [`WINDOW_BYTES`]; reaching this means
/// it is not keeping up, or never runs for this database (not allowlisted,
/// over the cap). It bounds the disk a stalled database can take.
pub const WAL_REFUSE_BYTES: u64 = 64 * 1024 * 1024;

/// A rotation is also taken by the commit path, not only by the uploader, once
/// the WAL holds this many bytes. It is the backstop for a database nobody
/// uploads (a space that is not allowlisted, or whose checkpoint is over the
/// cap): its WAL is folded in and truncated instead of growing to the refusal
/// above. The uploader rotates far earlier ([`rotation_threshold`]).
pub const WAL_BACKSTOP_BYTES: u64 = 48 * 1024 * 1024;

/// Every rotation publishes the whole main file as a snapshot, so the upload
/// cost of a write is the WAL it carries plus, once per rotation, the main
/// file. A rotation therefore waits until the WAL is at least
/// `main / SNAPSHOT_AMPLIFICATION_CAP`, which keeps the snapshot bytes at or
/// under that many times the bytes written (measured in the shadow tests).
pub const SNAPSHOT_AMPLIFICATION_CAP: u64 = 2;

/// The WAL size at which the uploader rotates a database whose main file is
/// `main_bytes`: the 8 MiB window for a small database, growing with the main
/// file up to half the pilot cap.
pub fn rotation_threshold(main_bytes: u64) -> u64 {
    (main_bytes / SNAPSHOT_AMPLIFICATION_CAP)
        .clamp(WINDOW_BYTES, PILOT_CAP_BYTES / SNAPSHOT_AMPLIFICATION_CAP)
}

/// The reserved counter table.
pub const SEQ_TABLE: &str = "tinycloud_internal_store_seq";

/// Every name under this prefix is the node's, not the user's (compared
/// ASCII-case-insensitively, as SQLite compares names).
pub const RESERVED_PREFIX: &str = "tinycloud_internal_";

/// Marks kept per database: the frontier's and the head's need only the last
/// two; a few more absorb a retried job.
const MARKS_KEPT: usize = 8;

/// Whether a checkpoint of `bytes` is within the pilot cap (inclusive).
pub fn within_pilot_cap(bytes: u64) -> bool {
    bytes <= PILOT_CAP_BYTES
}

/// Whether `name` is in the reserved namespace.
pub fn is_reserved_name(name: &str) -> bool {
    name.as_bytes()
        .get(..RESERVED_PREFIX.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(RESERVED_PREFIX.as_bytes()))
}

/// Whether a SQLite authorizer action touches the reserved namespace.
pub fn names_reserved(action: &AuthAction<'_>) -> bool {
    use AuthAction::*;
    match action {
        CreateIndex {
            index_name,
            table_name,
        }
        | CreateTempIndex {
            index_name,
            table_name,
        }
        | DropIndex {
            index_name,
            table_name,
        }
        | DropTempIndex {
            index_name,
            table_name,
        } => is_reserved_name(index_name) || is_reserved_name(table_name),
        CreateTrigger {
            trigger_name,
            table_name,
        }
        | CreateTempTrigger {
            trigger_name,
            table_name,
        }
        | DropTrigger {
            trigger_name,
            table_name,
        }
        | DropTempTrigger {
            trigger_name,
            table_name,
        } => is_reserved_name(trigger_name) || is_reserved_name(table_name),
        CreateTable { table_name }
        | CreateTempTable { table_name }
        | DropTable { table_name }
        | DropTempTable { table_name }
        | Delete { table_name }
        | Insert { table_name }
        | Read { table_name, .. }
        | Update { table_name, .. }
        | AlterTable { table_name, .. }
        | Analyze { table_name }
        | CreateVtable { table_name, .. }
        | DropVtable { table_name, .. } => is_reserved_name(table_name),
        CreateView { view_name }
        | CreateTempView { view_name }
        | DropView { view_name }
        | DropTempView { view_name } => is_reserved_name(view_name),
        Reindex { index_name } => is_reserved_name(index_name),
        // `PRAGMA table_info('name')` and friends name a table as the value.
        Pragma {
            pragma_value: Some(value),
            ..
        } => is_reserved_name(value),
        _ => false,
    }
}

fn sqlite(error: rusqlite::Error) -> SqlError {
    SqlError::Internal(error.to_string())
}

/// Whether any statement renames a table to a reserved name. SQLite's
/// authorizer sees only the OLD name of `ALTER TABLE .. RENAME TO ..`, so the
/// new name is judged here, on the parsed statement. (`temp.x` renamed to the
/// counter's name was accepted before this check.)
pub fn renames_to_reserved(statements: &[sqlparser::ast::Statement]) -> bool {
    use sqlparser::ast::{AlterTableOperation, Statement};
    statements.iter().any(|statement| match statement {
        Statement::AlterTable { operations, .. } => operations.iter().any(|op| match op {
            AlterTableOperation::RenameTable { table_name } => table_name
                .0
                .last()
                .is_some_and(|ident| is_reserved_name(&ident.value)),
            _ => false,
        }),
        _ => false,
    })
}

/// Every statement below names the counter in the `main` schema. An
/// unqualified name resolves to a TEMP table of the same name first, and a
/// connection's user SQL can create TEMP tables.
fn seq_table() -> String {
    format!("main.{SEQ_TABLE}")
}

/// Create the counter at `start_seq` (at cutover: the frozen Postgres
/// revision). Refuses to run twice and refuses `0`: the uploader's revisions
/// start at 1.
///
/// The column is checked to hold an integer. SQLite turns an overflowing
/// `seq + 1` into a REAL, which a later open could not read as the counter;
/// the check makes that update fail instead, and the write is rolled back.
pub fn init_seq(conn: &Connection, start_seq: u64) -> Result<(), SqlError> {
    let start = i64::try_from(start_seq)
        .ok()
        .filter(|seq| *seq >= 1)
        .ok_or_else(|| SqlError::Internal("store-master seq must start at 1 or more".into()))?;
    let table = seq_table();
    // A Postgres-mode database may already hold a table of this name (the
    // prefix is reserved only once a database is store-master), or be the
    // import of an export of one. Cutover must stop there, and say why: an
    // existing table is never adopted as the counter.
    let taken: i64 = conn
        .query_row(
            "SELECT count(*) FROM main.sqlite_master WHERE type = 'table' AND name = ?1 COLLATE NOCASE",
            [SEQ_TABLE],
            |r| r.get(0),
        )
        .map_err(sqlite)?;
    if taken != 0 {
        return Err(SqlError::Internal(format!(
            "the database already has a table named {SEQ_TABLE} (a user table, or an export of a \
             store-master database); drop it before cutover"
        )));
    }
    conn.execute_batch(&format!(
        "CREATE TABLE {table} (\
           id INTEGER PRIMARY KEY CHECK (id = 1), \
           seq INTEGER NOT NULL CHECK (typeof(seq) = 'integer' AND seq >= 1)\
         )"
    ))
    .map_err(sqlite)?;
    conn.execute(
        &format!("INSERT INTO {table} (id, seq) VALUES (1, ?1)"),
        [start],
    )
    .map_err(sqlite)?;
    Ok(())
}

/// The counter's value.
pub fn read_seq(conn: &Connection) -> Result<u64, SqlError> {
    let seq: i64 = conn
        .query_row(
            &format!("SELECT seq FROM {} WHERE id = 1", seq_table()),
            [],
            |r| r.get(0),
        )
        .map_err(sqlite)?;
    u64::try_from(seq).map_err(|_| SqlError::Internal("store-master seq is negative".into()))
}

/// Count one more write. Runs inside the write's transaction, before COMMIT,
/// with no authorizer installed. At `i64::MAX` it refuses (the transaction is
/// rolled back by the caller) instead of overflowing.
pub fn bump_seq(conn: &Connection) -> Result<(), SqlError> {
    bump(conn, None)
}

/// As [`bump_seq`], for a write whose counter was read as `expected` before
/// the user's SQL ran: it refuses unless the row still holds `expected`, so a
/// change to the counter by anything inside the transaction, whatever path it
/// took, fails the write instead of being counted.
pub fn bump_seq_from(conn: &Connection, expected: u64) -> Result<(), SqlError> {
    bump(conn, Some(expected))
}

fn bump(conn: &Connection, expected: Option<u64>) -> Result<(), SqlError> {
    let table = seq_table();
    let changed = match expected {
        None => conn.execute(
            &format!(
                "UPDATE {table} SET seq = seq + 1 WHERE id = 1 AND seq < {}",
                i64::MAX
            ),
            [],
        ),
        Some(expected) => {
            let expected = i64::try_from(expected)
                .map_err(|_| SqlError::Internal("store-master seq is out of range".into()))?;
            conn.execute(
                &format!(
                    "UPDATE {table} SET seq = seq + 1 WHERE id = 1 AND seq = ?1 AND seq < {}",
                    i64::MAX
                ),
                [expected],
            )
        }
    }
    .map_err(sqlite)?;
    if changed == 1 {
        return Ok(());
    }
    match (read_seq(conn), expected) {
        (Ok(seq), _) if i64::try_from(seq) == Ok(i64::MAX) => {
            Err(SqlError::Internal("store-master seq is exhausted".into()))
        }
        (Ok(seq), Some(expected)) if seq != expected => Err(SqlError::Internal(
            "store-master seq changed during the write".into(),
        )),
        _ => Err(SqlError::Internal("store-master seq row is missing".into())),
    }
}

/// Turn an existing local database file into a store-master working copy:
/// create the counter at `start_seq` and fold the WAL into the main file, so
/// the file's hash is the lineage anchor. The caller (the cutover job, P4.4)
/// holds the database's operation lock with no actor open.
pub fn init_working_copy(path: &Path, start_seq: u64) -> Result<(), SqlError> {
    let conn =
        open_store_master_connection(&StorageMode::File(path.to_path_buf()), Synchronous::Full)?;
    init_seq(&conn, start_seq)?;
    let busy: i64 = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(sqlite)?;
    if busy != 0 {
        return Err(SqlError::Internal("Database checkpoint is busy".into()));
    }
    Ok(())
}

/// The counter of the working copy at `path`, read without an actor. Fails
/// when the file is missing or was never initialised: such a database is
/// fenced, never created or re-seeded.
pub fn validate_working_copy(path: &Path) -> Result<u64, SqlError> {
    if !path.is_file() {
        return Err(SqlError::Unavailable);
    }
    let conn =
        open_store_master_connection(&StorageMode::File(path.to_path_buf()), Synchronous::Full)?;
    read_seq(&conn)
}

/// SHA-256 (lowercase hex) of a whole file.
pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// SHA-256 of the first `len` bytes of a file; `None` if it is shorter.
pub fn hash_prefix(path: &Path, len: u64) -> std::io::Result<Option<[u8; 32]>> {
    let file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut reader = file.take(len);
    let mut buffer = vec![0u8; 1 << 20];
    let mut seen = 0u64;
    loop {
        let read = reader.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        seen += read as u64;
    }
    Ok((seen == len).then(|| hasher.finalize().into()))
}

/// What the actor reports about its working copy, read right after a commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalState {
    /// The in-file counter.
    pub seq: u64,
    /// Length of the `-wal` file (0 when absent).
    pub wal_bytes: u64,
    /// Length of the main file, the checkpoint.
    pub main_bytes: u64,
}

/// Which database mode a request is served under. The one place the mode is
/// consulted: `None` gate (the default) means every database is served
/// exactly as before.
#[async_trait]
pub trait StoreMasterGate: Send + Sync {
    /// Whether the mode row says `store_master`. An error refuses the request
    /// (retryable); a node that cannot read the row never guesses.
    async fn is_store_master(&self, db: &DbRef<'_>) -> Result<bool, ModeError>;

    /// Every database whose mode row says `store_master`, for the uploader's
    /// startup and periodic recovery scan.
    async fn store_master_databases(&self) -> Result<Vec<DbKey>, ModeError>;
}

/// [`StoreMasterGate`] over the control database's `sql_store_mode`.
///
/// The row is read on every call: the cache with an invalidation spec is
/// P4.2c's. Not wired into the node runtime in P4.2a.
pub struct ControlModeGate {
    control: DatabaseConnection,
}

impl ControlModeGate {
    pub fn new(control: DatabaseConnection) -> Self {
        Self { control }
    }
}

#[async_trait]
impl StoreMasterGate for ControlModeGate {
    async fn is_store_master(&self, db: &DbRef<'_>) -> Result<bool, ModeError> {
        Ok(read_mode(&self.control, db)
            .await?
            .is_some_and(|row| row.mode == StoreMode::StoreMaster))
    }

    async fn store_master_databases(&self) -> Result<Vec<DbKey>, ModeError> {
        let rows = mode_row::Entity::find()
            .filter(mode_row::Column::Mode.eq(StoreMode::StoreMaster.as_str()))
            .all(&self.control)
            .await
            .map_err(|error| ModeError::Db(error.to_string()))?;
        Ok(rows.into_iter().map(|r| (r.space, r.db_id)).collect())
    }
}

/// Identity of a file as far as a cached hash may trust it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    len: u64,
    modified: Option<std::time::SystemTime>,
    inode: u64,
}

impl FileId {
    fn of(meta: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        let inode = std::os::unix::fs::MetadataExt::ino(meta);
        #[cfg(not(unix))]
        let inode = 0;
        Self {
            len: meta.len(),
            modified: meta.modified().ok(),
            inode,
        }
    }
}

/// Where the last successful publish of a database ended.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Published {
    cid: String,
    wal_end_bytes: u64,
}

#[derive(Default)]
struct Entry {
    cid: Option<(FileId, String)>,
    marks: Vec<WalMark>,
    published: Option<Published>,
}

/// Per-database memory of the local working copies: the checkpoint hash by
/// file identity, the WAL marks the source recorded, and where the last
/// publish ended. All of it is a cache: losing it (a restart) costs a rehash
/// and a cumulative segment instead of a delta, never correctness.
#[derive(Default)]
pub struct LocalFiles {
    entries: Mutex<HashMap<DbKey, Entry>>,
}

impl LocalFiles {
    fn with<T>(&self, key: &DbKey, f: impl FnOnce(&mut Entry) -> T) -> T {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(entries.entry(key.clone()).or_default())
    }

    /// The hash of the main file at `path`, rehashed only when its identity
    /// (length, mtime, inode) changed or [`Self::invalidate`] ran. Blocking:
    /// call from `spawn_blocking`.
    pub fn checkpoint_cid(&self, key: &DbKey, path: &Path) -> std::io::Result<String> {
        let id = FileId::of(&std::fs::metadata(path)?);
        if let Some(cid) = self.with(key, |e| {
            e.cid
                .as_ref()
                .filter(|(cached, _)| *cached == id)
                .map(|(_, cid)| cid.clone())
        }) {
            return Ok(cid);
        }
        let cid = hash_file(path)?;
        // The file may have moved while it was hashed; the next call sees a
        // different identity then.
        let after = FileId::of(&std::fs::metadata(path)?);
        if after == id {
            self.with(key, |e| e.cid = Some((id, cid.clone())));
        }
        Ok(cid)
    }

    /// Forget the cached hash (the main file is about to change or was
    /// replaced).
    pub fn invalidate(&self, key: &DbKey) {
        self.with(key, |e| e.cid = None);
    }

    /// Forget everything known about the databases of `space`: its working
    /// copies were deleted (a purge), and a space of the same id created later
    /// must not inherit a hash, a WAL mark or a published position.
    pub fn forget_space(&self, space: &str) {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|key, _| key.0 != space);
    }

    /// Whether anything is remembered about the databases of `space`.
    #[cfg(test)]
    pub fn knows_space(&self, space: &str) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .keys()
            .any(|key| key.0 == space)
    }

    /// Remember where the WAL of `mark.revision` ended.
    pub fn record_mark(&self, key: &DbKey, mark: WalMark) {
        self.with(key, |e| {
            e.marks.retain(|m| m.revision != mark.revision);
            e.marks.push(mark);
            if e.marks.len() > MARKS_KEPT {
                e.marks.remove(0);
            }
        });
    }

    /// The marks recorded for `revisions`.
    pub fn marks(&self, key: &DbKey, revisions: &[i64]) -> Vec<WalMark> {
        self.with(key, |e| {
            e.marks
                .iter()
                .filter(|m| revisions.contains(&m.revision))
                .cloned()
                .collect()
        })
    }

    /// A publish landed: its snapshot hash and the WAL bytes it carried.
    /// Databases this registry has never read are ignored, so a Postgres
    /// database's publish leaves no entry behind.
    pub fn set_published(&self, key: &DbKey, cid: &str, seq: u64) {
        let Ok(revision) = i64::try_from(seq) else {
            return;
        };
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(entry) = entries.get_mut(key) else {
            return;
        };
        let wal_end_bytes = entry
            .marks
            .iter()
            .find(|m| m.revision == revision && m.checkpoint_content_hash == cid)
            .map_or(0, |m| m.wal_end_bytes);
        entry.published = Some(Published {
            cid: cid.to_owned(),
            wal_end_bytes,
        });
    }

    /// Bytes the store is behind by, as far as this process knows: the WAL
    /// bytes past the last publish on the same checkpoint, or the whole
    /// checkpoint plus WAL when the checkpoint changed or nothing has been
    /// published since the process started.
    pub fn ahead_bytes(&self, key: &DbKey, cid: &str, wal_bytes: u64, main_bytes: u64) -> u64 {
        self.with(key, |e| match &e.published {
            Some(p) if p.cid == cid => wal_bytes.saturating_sub(p.wal_end_bytes),
            _ => main_bytes.saturating_add(wal_bytes),
        })
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) mod rig;

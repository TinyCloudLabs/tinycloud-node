//! The local working copy of a store-master SQL database (TC-1491 P4.2a,
//! design sections 5.3 and 12).
//!
//! Everything here is inert until a database's `sql_store_mode` row says
//! `store_master`; no cutover exists yet, so nothing in production reaches it.
//!
//! - **Sequence counter, bump-before-write.** The counter lives in its own
//!   file next to the database ([`seq_path`]), not in the database. The actor
//!   bumps it and fsyncs it ([`bump_seq`]) after a write's statements have
//!   run and BEFORE that write commits. SQLite cannot commit atomically
//!   across two files in WAL mode, so the counter and the data are never in
//!   one commit; the order is what keeps the invariant: **a `seq` is never
//!   reused for different bytes; gaps are allowed.** A crash after the bump
//!   and before the commit leaves the counter ahead of the data (a gap); a
//!   crash after the commit leaves both. The revision the uploader publishes
//!   is read from this file under the operation lock ([`read_seq`]).
//!   (Nothing in the database file is the node's: the counter is a separate
//!   file, so user SQL has no name to shadow, rename or read it by.)
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
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};

use super::key::DbRef;
use super::mode::{read_mode, ModeError, StoreMode};
use super::shadow::DbKey;
use crate::database_artifacts::WalMark;
use crate::models::sql_store_mode as mode_row;
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

/// Marks kept per database: the frontier's and the head's need only the last
/// two; a few more absorb a retried job.
const MARKS_KEPT: usize = 8;

/// Whether a checkpoint of `bytes` is within the pilot cap (inclusive).
pub fn within_pilot_cap(bytes: u64) -> bool {
    bytes <= PILOT_CAP_BYTES
}

/// The length of the WAL of the working copy at `main` through its last
/// COMMITTED frame, in bytes (0 when none).
///
/// The `-wal` file can be longer: a write that outgrows the page cache puts
/// frames into it before its COMMIT, and when it rolls back they stay in the
/// file as a dead tail until a checkpoint resets it. The size limits (the
/// backstop and the refusal), the rotation trigger and the bytes-behind figure
/// judge what is committed, never the file: a rolled-back spill is not data
/// anyone has to upload, and rotating (republishing the whole main file) over
/// it would only amplify.
///
/// Read from the WAL index SQLite keeps next to the file (`<main>-shm`,
/// documented at sqlite.org/walformat.html): its header holds the committed
/// frame count and the page size, 48 bytes read, no scan. When the index is
/// not there, unreadable, not two equal copies of an initialised header, or
/// names more than the file holds, the WAL is scanned instead
/// ([`committed_wal_len`](super::shadow::restore::committed_wal_len)).
pub fn committed_wal_bytes(main: &Path) -> std::io::Result<u64> {
    let mut wal = main.as_os_str().to_owned();
    wal.push("-wal");
    let wal = PathBuf::from(wal);
    if let Some(len) = wal_index_len(main) {
        let on_disk = match std::fs::metadata(&wal) {
            Ok(meta) => meta.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error),
        };
        if len <= on_disk {
            return Ok(len);
        }
    }
    super::shadow::restore::committed_wal_len(&wal)
}

/// The committed WAL length the WAL index header names, or `None` when the
/// header cannot be trusted. Layout (WalIndexHdr, native byte order, written
/// twice): version u32 = 3007000, unused u32, change counter u32, isInit u8,
/// bigEndCksum u8, page size u16 (1 = 65536), mxFrame u32, then more.
fn wal_index_len(main: &Path) -> Option<u64> {
    let mut shm = main.as_os_str().to_owned();
    shm.push("-shm");
    let mut index = std::fs::File::open(shm).ok()?;
    let mut both = [0u8; 96];
    index.read_exact(&mut both).ok()?;
    if both[..48] != both[48..] {
        return None;
    }
    let header = &both[..48];
    let word = |at: usize| u32::from_ne_bytes(header[at..at + 4].try_into().expect("4 bytes"));
    if word(0) != 3_007_000 || header[12] != 1 {
        return None;
    }
    let page = match u16::from_ne_bytes([header[14], header[15]]) {
        1 => 65_536,
        n => u64::from(n),
    };
    if !(512..=65_536).contains(&page) || !page.is_power_of_two() {
        return None;
    }
    Some(match u64::from(word(16)) {
        0 => 0,
        frames => 32 + frames * (24 + page),
    })
}

fn sqlite(error: rusqlite::Error) -> SqlError {
    SqlError::Internal(error.to_string())
}

/// Where the counter of the working copy whose main file is `main` lives.
pub fn seq_path(main: &Path) -> PathBuf {
    let mut path = main.as_os_str().to_owned();
    path.push(".seq");
    PathBuf::from(path)
}

/// The counter file is one 16-byte record: the counter (little-endian) and
/// the first 8 bytes of SHA-256 over a tag and the counter. A record that
/// does not check (a torn write, a hand edit) is refused, never repaired:
/// guessing a counter could reissue one.
const SEQ_RECORD_LEN: usize = 16;

fn seq_record(seq: u64) -> [u8; SEQ_RECORD_LEN] {
    let mut record = [0u8; SEQ_RECORD_LEN];
    record[..8].copy_from_slice(&seq.to_le_bytes());
    let digest = Sha256::new()
        .chain_update(b"tinycloud-store-seq-v1")
        .chain_update(seq.to_le_bytes())
        .finalize();
    record[8..].copy_from_slice(&digest[..8]);
    record
}

fn parse_seq_record(bytes: &[u8]) -> Result<u64, SqlError> {
    let bytes: &[u8; SEQ_RECORD_LEN] = bytes
        .try_into()
        .map_err(|_| SqlError::Internal("the store-master seq file has the wrong length".into()))?;
    let seq = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    if seq_record(seq) != *bytes {
        return Err(SqlError::Internal(
            "the store-master seq file does not check".into(),
        ));
    }
    Ok(seq)
}

fn io(error: std::io::Error) -> SqlError {
    SqlError::Internal(error.to_string())
}

fn seq_io(error: std::io::Error) -> SqlError {
    if error.kind() == std::io::ErrorKind::NotFound {
        SqlError::Internal("the store-master seq file is missing".into())
    } else {
        io(error)
    }
}

/// The counter of the working copy whose main file is `main`, read from its
/// seq file. Fails when the file is missing or does not check.
pub fn read_seq(main: &Path) -> Result<u64, SqlError> {
    let bytes = std::fs::read(seq_path(main)).map_err(seq_io)?;
    parse_seq_record(&bytes)
}

/// Count one more write (or rotation): move the counter forward by one and
/// fsync it (the file, then its directory), then return the new value. The
/// caller commits its write only after this returns. At `i64::MAX` it
/// refuses instead of overflowing (revisions are stored as signed integers
/// downstream).
///
/// The record is rewritten in place and synced with `fdatasync`; its length
/// never changes. It is 16 bytes, inside one sector, so a crash leaves the
/// old record or the new one; a torn one is refused by [`read_seq`], which
/// stops the database rather than reissue a revision. The directory is
/// synced too, so the file's entry is durable whatever happened to it
/// before (the bump itself changes no entry).
pub fn bump_seq(main: &Path) -> Result<u64, SqlError> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(seq_path(main))
        .map_err(seq_io)?;
    let mut bytes = Vec::with_capacity(SEQ_RECORD_LEN);
    file.read_to_end(&mut bytes).map_err(io)?;
    let seq = parse_seq_record(&bytes)?;
    if seq >= i64::MAX as u64 {
        return Err(SqlError::Internal("store-master seq is exhausted".into()));
    }
    let next = seq + 1;
    file.seek(SeekFrom::Start(0)).map_err(io)?;
    file.write_all(&seq_record(next)).map_err(io)?;
    file.sync_data().map_err(io)?;
    if let Some(parent) = main.parent() {
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(io)?;
    }
    Ok(next)
}

/// Turn an existing local database file into a store-master working copy:
/// fold the WAL into the main file, so the file's hash is the lineage anchor,
/// make that file (and its directory entry) durable, and only then create the
/// seq file at `start_seq` (at cutover: above the frozen Postgres revision),
/// atomically: a temp file, fsynced, linked into place. A crash mid-run leaves
/// no seq file or the whole one, and never a seq file in front of a main file
/// that was not yet on disk. Refuses `0` (the uploader's revisions start at 1)
/// and refuses to run twice. The caller (the cutover job, P4.4) holds the
/// database's operation lock with no actor open. Init expects that contract
/// and does not rely on it for its own counter: if two calls ever overlap, at
/// most one returns `Ok` (fails closed) and the counter is that call's
/// `start_seq`.
///
/// An `Err` returned after the link (the directory fsync failed) leaves the
/// seq file in place: a retry is refused with "already exists", so the caller
/// checks the counter with [`validate_working_copy`] after any such refusal
/// and requires it to be `>= SEED` (design 5.3), else it refuses.
pub fn init_working_copy(path: &Path, start_seq: u64) -> Result<(), SqlError> {
    let start = i64::try_from(start_seq)
        .ok()
        .filter(|seq| *seq >= 1)
        .ok_or_else(|| SqlError::Internal("store-master seq must start at 1 or more".into()))?;
    let conn = open_store_master_connection(&StorageMode::File(path.to_path_buf()))?;
    let busy: i64 = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .map_err(sqlite)?;
    if busy != 0 {
        return Err(SqlError::Internal("Database checkpoint is busy".into()));
    }
    // The seq file is the fence that lets this database be served. It must not
    // be durable before the file it fences: SQLite's checkpoint syncs the main
    // file under `synchronous=FULL`, but that is SQLite's business, so the
    // file and its directory are synced here, before the link, whatever the
    // pragma said.
    sync_file_and_directory(path)?;
    let seq = seq_path(path);
    // Written whole to a temp file, fsynced, then linked into place and the
    // directory fsynced: a crash leaves no seq file (the database stays fenced
    // and this can be run again) or the whole one, never a short one. The temp
    // name is this call's own (process, counter, random): another call, or a
    // file an earlier run died with, is never ours to remove or to link. A
    // leftover temp file is harmless (it is not the counter) and is not swept
    // here, because a sweep could remove a concurrent call's file. `hard_link`
    // refuses when the seq file exists, so a second run never replaces a
    // counter and the loser of a race sees `AlreadyExists`, never the
    // winner's number.
    static CALLS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let tmp = std::path::PathBuf::from(format!(
        "{}.tmp.{}.{}.{:016x}",
        seq.display(),
        std::process::id(),
        CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        rand::random::<u64>()
    ));
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .map_err(io)?;
    let linked = write_and_link(file, &tmp, &seq, start as u64);
    // Best effort, on success and on every failure after the temp file was
    // created: it is never the counter, and a leftover one is harmless. Its
    // removal is not why an `Err` is returned.
    let _ = std::fs::remove_file(&tmp);
    linked
}

/// Write the seq record into this call's temp file, fsync it, link it into
/// place as the seq file and fsync the directory, in that order. Once the link
/// succeeded the only error left is the directory fsync.
fn write_and_link(
    mut file: std::fs::File,
    tmp: &Path,
    seq: &Path,
    start: u64,
) -> Result<(), SqlError> {
    file.write_all(&seq_record(start)).map_err(io)?;
    file.sync_all().map_err(io)?;
    drop(file);
    std::fs::hard_link(tmp, seq).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            SqlError::Internal("the store-master seq file already exists".into())
        } else {
            io(error)
        }
    })?;
    #[cfg(test)]
    if FAIL_DIRECTORY_SYNC_AFTER_LINK.with(std::cell::Cell::take) {
        return Err(io(std::io::Error::other(
            "injected directory fsync failure",
        )));
    }
    sync_directory_of(seq)
}

#[cfg(test)]
thread_local! {
    /// Test fault: the next `init_working_copy` on this thread fails its
    /// directory fsync right after the seq file was linked.
    static FAIL_DIRECTORY_SYNC_AFTER_LINK: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// fsync `path` and the directory that holds it.
fn sync_file_and_directory(path: &Path) -> Result<(), SqlError> {
    std::fs::File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(io)?;
    sync_directory_of(path)
}

fn sync_directory_of(path: &Path) -> Result<(), SqlError> {
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)
            .and_then(|dir| dir.sync_all())
            .map_err(io)?;
    }
    Ok(())
}

/// The counter of the working copy at `path`, read without an actor. Fails
/// when the main file is missing or the counter was never initialised: such a
/// database is fenced, never created or re-seeded.
pub fn validate_working_copy(path: &Path) -> Result<u64, SqlError> {
    if !path.is_file() {
        return Err(SqlError::Unavailable);
    }
    read_seq(path)
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
    /// Length of the committed part of the `-wal` file (0 when absent or
    /// empty): [`committed_wal_bytes`], not the file's size.
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

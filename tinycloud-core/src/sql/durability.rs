//! Local commit durability and the reservation made before a write commits
//! (TC-1491, slice 1a). The contract, the invariants and what is and is not
//! guaranteed are in `docs/sql-local-durability.md`.

use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use super::types::SqlError;

/// `PRAGMA synchronous` for file-backed databases.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Default, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Synchronous {
    /// WAL fsync on every COMMIT: a commit that returned survives power loss
    /// (given a volume that honours flushes).
    #[default]
    Full,
    /// WAL fsync only at checkpoints: a power loss can drop the most recent
    /// commits. The rollback flag for `Full`.
    Normal,
}

impl Synchronous {
    pub fn pragma_value(self) -> &'static str {
        match self {
            Synchronous::Full => "FULL",
            Synchronous::Normal => "NORMAL",
        }
    }
}

/// Free space on the filesystem holding the SQL cache. A seam so tests can
/// exhaust it without filling a disk.
pub trait FreeSpace: Send + Sync {
    fn free_bytes(&self, path: &Path) -> std::io::Result<u64>;
}

/// `statvfs`: the bytes an unprivileged process can still allocate.
#[derive(Debug, Default)]
pub struct StatvfsFreeSpace;

impl FreeSpace for StatvfsFreeSpace {
    fn free_bytes(&self, path: &Path) -> std::io::Result<u64> {
        use std::os::unix::ffi::OsStrExt;
        let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        let mut stat = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `c_path` is a valid NUL-terminated string and `stat` is a
        // valid out-pointer; it is only read after statvfs reports success.
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), stat.as_mut_ptr()) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: statvfs succeeded, so it initialised the struct.
        let stat = unsafe { stat.assume_init() };
        // The field widths differ by platform (u32 on macOS).
        #[allow(clippy::unnecessary_cast)]
        let free = (stat.f_bavail as u64).saturating_mul(stat.f_frsize as u64);
        Ok(free)
    }
}

/// Why a reservation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationRefused {
    /// Free space minus every in-flight reservation and the reservation asked
    /// for would fall below the floor.
    Headroom,
    /// Free space could not be read; refusing is the conservative answer.
    Unknown,
}

/// The disk bytes in-flight writes of every database on this node still need.
/// One per node, shared by all actors, so two databases cannot each take the
/// same free bytes.
#[derive(Debug, Default)]
pub struct DiskBudget {
    held: Mutex<HashMap<String, u64>>,
}

impl DiskBudget {
    /// Set `key`'s reservation to `bytes` if the disk can still hold it next
    /// to everyone else's. Leaves the old reservation when refusing.
    pub fn reserve(
        &self,
        key: &str,
        bytes: u64,
        free_space: &dyn FreeSpace,
        dir: &Path,
        min_free_bytes: u64,
    ) -> Result<(), ReservationRefused> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        let others: u64 = held
            .iter()
            .filter(|(other, _)| other.as_str() != key)
            .map(|(_, bytes)| *bytes)
            .fold(0, u64::saturating_add);
        let free = free_space
            .free_bytes(dir)
            .map_err(|_| ReservationRefused::Unknown)?;
        let needed = others.saturating_add(bytes).saturating_add(min_free_bytes);
        if free < needed {
            return Err(ReservationRefused::Headroom);
        }
        held.insert(key.to_string(), bytes);
        Ok(())
    }

    /// Keep `bytes` held for `key` without a free-space check: the commit is
    /// done and its bytes are on disk.
    pub fn hold(&self, key: &str, bytes: u64) {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        if bytes == 0 {
            held.remove(key);
        } else {
            held.insert(key.to_string(), bytes);
        }
    }

    pub fn release(&self, key: &str) {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(key);
    }

    /// Bytes reserved by every database but `key`.
    pub fn reserved_excluding(&self, key: &str) -> u64 {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|(other, _)| other.as_str() != key)
            .map(|(_, bytes)| *bytes)
            .fold(0, u64::saturating_add)
    }

    /// Bytes currently reserved by all in-flight writes.
    pub fn reserved(&self) -> u64 {
        self.held
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .fold(0, |sum, bytes| sum.saturating_add(*bytes))
    }
}

/// Releases a database's reservation when the request's outcome is known.
pub struct ReservationGuard {
    budget: Arc<DiskBudget>,
    key: String,
}

impl ReservationGuard {
    pub fn new(budget: Arc<DiskBudget>, key: String) -> Self {
        Self { budget, key }
    }
}

impl Drop for ReservationGuard {
    fn drop(&mut self) {
        self.budget.release(&self.key);
    }
}

/// Test seams at the commit boundary. A seam only observes: the kill -9
/// tests abort the process from one.
#[derive(Clone, Default)]
pub struct CommitSeams {
    /// After every check passed, immediately before COMMIT.
    pub before_commit: Option<Arc<dyn Fn() + Send + Sync>>,
    /// After COMMIT returned (and, for `Full`, its fsync), before the actor
    /// answers.
    pub after_commit: Option<Arc<dyn Fn() + Send + Sync>>,
    /// Just before the actor sends its response.
    pub before_response: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl std::fmt::Debug for CommitSeams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommitSeams").finish_non_exhaustive()
    }
}

/// 0 turns the per-database cap off. Off by default: the limit is a product
/// decision (card `sql-storage-report-read`), set by config once decided.
pub const DEFAULT_MAX_DATABASE_BYTES: u64 = 0;
/// 0 turns the disk headroom check off (no reservation, no free-space reads).
/// Off by default for the same reason.
pub const DEFAULT_MIN_FREE_BYTES: u64 = 0;

/// Everything the actors need to make a commit durable and to refuse a write
/// that would not fit.
#[derive(Clone)]
pub struct DurabilityPolicy {
    pub synchronous: Synchronous,
    /// Per-database size cap, enforced by SQLite itself through
    /// `max_page_count`. 0 = no cap.
    pub max_database_bytes: u64,
    /// Free bytes that must remain after every in-flight write's worst case.
    /// 0 = the disk headroom check is off.
    pub min_free_bytes: u64,
    pub budget: Arc<DiskBudget>,
    pub free_space: Arc<dyn FreeSpace>,
    pub seams: CommitSeams,
}

impl Default for DurabilityPolicy {
    fn default() -> Self {
        Self {
            synchronous: Synchronous::Full,
            max_database_bytes: DEFAULT_MAX_DATABASE_BYTES,
            min_free_bytes: DEFAULT_MIN_FREE_BYTES,
            budget: Arc::new(DiskBudget::default()),
            free_space: Arc::new(StatvfsFreeSpace),
            seams: CommitSeams::default(),
        }
    }
}

impl std::fmt::Debug for DurabilityPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DurabilityPolicy")
            .field("synchronous", &self.synchronous)
            .field("max_database_bytes", &self.max_database_bytes)
            .field("min_free_bytes", &self.min_free_bytes)
            .finish_non_exhaustive()
    }
}

/// `fsync` a directory so the entries created or renamed in it survive a
/// crash. SQLite syncs the directory itself when it first creates a `-wal`
/// file (`UNIXFILE_DIRSYNC` in its unix VFS), but not for the main file.
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// `create_dir_all`, then make every directory it created durable: each new
/// directory and the existing directory that now holds the first of them.
pub fn create_dir_all_durable(path: &Path) -> std::io::Result<()> {
    let mut missing = Vec::new();
    let mut cursor = Some(path);
    while let Some(dir) = cursor {
        if dir.as_os_str().is_empty() || dir.exists() {
            break;
        }
        missing.push(dir);
        cursor = dir.parent();
    }
    if missing.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(path)?;
    for dir in missing.iter().rev() {
        sync_dir(dir)?;
        if let Some(parent) = dir.parent().filter(|p| !p.as_os_str().is_empty()) {
            sync_dir(parent)?;
        }
    }
    Ok(())
}

/// Apply `synchronous` to a file-backed connection.
pub fn set_synchronous(conn: &Connection, synchronous: Synchronous) -> Result<(), SqlError> {
    conn.pragma_update(None, "synchronous", synchronous.pragma_value())
        .map_err(|e| SqlError::Internal(e.to_string()))
}

/// Current heap bytes of this connection's page cache. Every page SQLite has
/// yet to write to the WAL at COMMIT is in it.
pub fn cache_used_bytes(conn: &Connection) -> u64 {
    let mut current: std::os::raw::c_int = 0;
    let mut high: std::os::raw::c_int = 0;
    // SAFETY: the handle is valid for the borrow of `conn`, and the two
    // out-pointers are valid for the call. `sqlite3_db_status` only reads the
    // connection's own counters.
    let rc = unsafe {
        rusqlite::ffi::sqlite3_db_status(
            conn.handle(),
            rusqlite::ffi::SQLITE_DBSTATUS_CACHE_USED,
            &mut current,
            &mut high,
            0,
        )
    };
    if rc != rusqlite::ffi::SQLITE_OK {
        // Unknown: the high-water mark is the largest it has been.
        return u64::try_from(high.max(0)).unwrap_or(0);
    }
    u64::try_from(current.max(0)).unwrap_or(0)
}

/// SQLite's per-frame WAL overhead.
pub const WAL_FRAME_HEADER_BYTES: u64 = 24;

/// Upper bound on the bytes COMMIT still appends to the WAL: one frame per
/// page in the cache. Dirty pages are a subset of cached pages, so this
/// bounds the writes of index, trigger, foreign-key, freelist and overflow
/// amplification alike, whatever the SQL payload was. A page dirtied twice
/// in one transaction still costs one frame.
pub fn unspilled_wal_bound(cache_used: u64, page_size: u64) -> u64 {
    if page_size == 0 {
        return cache_used;
    }
    cache_used
        .div_ceil(page_size)
        .saturating_mul(page_size + WAL_FRAME_HEADER_BYTES)
}

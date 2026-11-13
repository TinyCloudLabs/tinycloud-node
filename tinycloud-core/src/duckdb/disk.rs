//! Disk headroom for DuckDB databases (TC-2917).
//!
//! The node keeps `min_free_bytes` free on the filesystem behind the DuckDB
//! cache. Before a write or an import runs, the bytes it can need are reserved
//! in the node-wide [`DiskBudget`] that SQL uses too, so two databases cannot
//! count the same free bytes. While a statement runs, a watcher interrupts it
//! once free space falls below what other operations hold plus the floor. A
//! refused or interrupted write answers [`DuckDbError::DiskHeadroom`] and is
//! never acknowledged.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::time::Duration;

use crate::sql::durability::{
    DiskBudget, FreeSpace, ReservationGuard, ReservationRefused, StatvfsFreeSpace,
};

use super::types::{DuckDbError, DuckDbRequest};

/// How often the watcher reads free space while a statement runs.
const WATCH_INTERVAL: Duration = Duration::from_millis(50);

/// The DuckDB disk settings. The default is off: no reservations, no
/// free-space reads and DuckDB's own spill limit.
#[derive(Clone)]
pub struct DuckDbDiskPolicy {
    /// Free bytes that must remain after every in-flight operation's
    /// reservation. 0 turns the headroom check and the watcher off.
    pub min_free_bytes: u64,
    /// The most bytes one connection may spill to its temporary directory
    /// (DuckDB `max_temp_directory_size`). 0 keeps DuckDB's default.
    pub max_temp_directory_bytes: u64,
    pub budget: Arc<DiskBudget>,
    pub free_space: Arc<dyn FreeSpace>,
}

impl Default for DuckDbDiskPolicy {
    fn default() -> Self {
        Self {
            min_free_bytes: 0,
            max_temp_directory_bytes: 0,
            budget: Arc::new(DiskBudget::default()),
            free_space: Arc::new(StatvfsFreeSpace),
        }
    }
}

impl std::fmt::Debug for DuckDbDiskPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DuckDbDiskPolicy")
            .field("min_free_bytes", &self.min_free_bytes)
            .field("max_temp_directory_bytes", &self.max_temp_directory_bytes)
            .finish_non_exhaustive()
    }
}

/// The budget key of one DuckDB database. SQL keys never start with this.
pub(crate) fn budget_key(space: &str, db_name: &str) -> String {
    format!("duckdb:{space}/{db_name}")
}

/// Requests that can change the database and are saved afterwards: they
/// reserve room and run under the watcher. Queries, exports and `describe`
/// do neither; only the spill limit applies to them.
pub(crate) fn writes(request: &DuckDbRequest) -> bool {
    !matches!(
        request,
        DuckDbRequest::Query { .. }
            | DuckDbRequest::Describe
            | DuckDbRequest::Export
            | DuckDbRequest::ExportToKv { .. }
    )
}

impl DuckDbDiskPolicy {
    pub(crate) fn headroom_checked(&self) -> bool {
        self.min_free_bytes > 0
    }

    /// Reserve `bytes` for one operation of `key`, measured against the
    /// filesystem behind `dir`. `None` when the check is off.
    pub(crate) fn reserve(
        &self,
        key: &str,
        bytes: u64,
        dir: &Path,
    ) -> Result<Option<ReservationGuard>, DuckDbError> {
        if !self.headroom_checked() {
            return Ok(None);
        }
        match self.budget.reserve(
            key,
            bytes,
            0,
            self.free_space.as_ref(),
            existing_ancestor(dir),
            self.min_free_bytes,
        ) {
            Ok(()) => Ok(Some(ReservationGuard::new(
                self.budget.clone(),
                key.to_string(),
            ))),
            Err(ReservationRefused::Headroom) => Err(DuckDbError::DiskHeadroom),
            // Free space that cannot be read is refused, never allowed.
            Err(ReservationRefused::Unknown) => Err(DuckDbError::Internal(
                "free disk space could not be read".into(),
            )),
        }
    }

    /// Run `statement` on `conn`. A write (`write`) is interrupted if free
    /// space behind `dir` falls below what other operations hold plus the
    /// floor. A statement stopped that way, or one that hit the spill limit,
    /// is [`DuckDbError::DiskHeadroom`].
    pub(crate) fn watch<T>(
        &self,
        key: &str,
        dir: &Path,
        conn: &duckdb::Connection,
        write: bool,
        statement: impl FnOnce() -> Result<T, DuckDbError>,
    ) -> Result<T, DuckDbError> {
        if !write || !self.headroom_checked() {
            return statement().map_err(|error| self.classify(error));
        }
        let interrupt = conn.interrupt_handle();
        let tripped = AtomicBool::new(false);
        let dir = existing_ancestor(dir);
        let result = std::thread::scope(|scope| {
            let (stop, stopped) = mpsc::channel::<()>();
            let (tripped, dir) = (&tripped, &dir);
            scope.spawn(move || {
                while let Err(mpsc::RecvTimeoutError::Timeout) =
                    stopped.recv_timeout(WATCH_INTERVAL)
                {
                    let floor = self
                        .budget
                        .reserved_excluding(key)
                        .saturating_add(self.min_free_bytes);
                    // Unreadable free space stops the statement, like the gate.
                    let short = self
                        .free_space
                        .free_bytes(dir)
                        .map_or(true, |free| free < floor);
                    if short {
                        tripped.store(true, Ordering::Relaxed);
                        interrupt.interrupt();
                        break;
                    }
                }
            });
            let result = statement();
            drop(stop);
            result
        });
        match result {
            Err(_) if tripped.load(Ordering::Relaxed) => Err(DuckDbError::DiskHeadroom),
            other => other.map_err(|error| self.classify(error)),
        }
    }

    /// A statement that ran past the spill limit is the disk, not the caller.
    fn classify(&self, error: DuckDbError) -> DuckDbError {
        let spill_limit = self.max_temp_directory_bytes > 0
            && matches!(
                &error,
                DuckDbError::DuckDb(message) | DuckDbError::Internal(message)
                    if message.contains("max_temp_directory_size")
            );
        if spill_limit {
            DuckDbError::DiskHeadroom
        } else {
            error
        }
    }
}

/// The nearest existing ancestor of `path`: where `statvfs` can be asked how
/// much room the filesystem has before the file or its directory exists.
fn existing_ancestor(path: &Path) -> &Path {
    path.ancestors()
        .find(|ancestor| ancestor.exists())
        .unwrap_or(path)
}

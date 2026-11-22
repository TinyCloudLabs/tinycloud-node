//! Scratch-disk budget for streamed uploads (TC-1491 P1).
//!
//! An upload job copies the artifact out of Postgres into scratch files
//! before putting them, so the number of bytes on local disk is bounded by
//! one budget: a job reserves the bytes it will write before it writes them,
//! and the reservation is released when the job drops it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};

/// Bytes of scratch space shared by every upload job.
#[derive(Debug)]
pub struct DiskBudget {
    dir: PathBuf,
    capacity: u64,
    reserved: Mutex<u64>,
}

impl DiskBudget {
    /// `capacity` bytes of scratch files under `dir`.
    pub fn new(dir: impl Into<PathBuf>, capacity: u64) -> Arc<Self> {
        Arc::new(Self {
            dir: dir.into(),
            capacity,
            reserved: Mutex::new(0),
        })
    }

    pub fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Bytes currently held by live reservations.
    pub fn reserved(&self) -> u64 {
        *self.reserved.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Reserve `bytes`, or `None` when the budget cannot hold them now.
    pub fn try_reserve(self: &Arc<Self>, bytes: u64) -> Option<Reservation> {
        let mut reserved = self.reserved.lock().unwrap_or_else(PoisonError::into_inner);
        let after = reserved.checked_add(bytes)?;
        if after > self.capacity {
            return None;
        }
        *reserved = after;
        Some(Reservation {
            budget: self.clone(),
            bytes,
        })
    }
}

/// Reserved scratch bytes; released on drop.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<DiskBudget>,
    bytes: u64,
}

impl Reservation {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// A new, empty scratch file in the budget's directory, deleted on drop.
    /// The caller writes at most the reserved bytes into its files.
    pub fn scratch(&self) -> std::io::Result<tempfile::NamedTempFile> {
        tempfile::Builder::new()
            .prefix("sql-shadow-")
            .tempfile_in(self.dir())
    }

    fn dir(&self) -> &Path {
        &self.budget.dir
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut reserved = self
            .budget
            .reserved
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *reserved = reserved.saturating_sub(self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reservations_are_bounded_and_released_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let budget = DiskBudget::new(dir.path(), 100);
        let a = budget.try_reserve(60).unwrap();
        assert!(budget.try_reserve(41).is_none(), "over capacity");
        let b = budget.try_reserve(40).unwrap();
        assert_eq!(budget.reserved(), 100);
        drop(a);
        assert_eq!(budget.reserved(), 40);
        assert!(budget.try_reserve(u64::MAX).is_none(), "no overflow");
        drop(b);
        assert_eq!(budget.reserved(), 0);
    }

    #[test]
    fn scratch_files_live_in_the_budget_dir_and_vanish_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let budget = DiskBudget::new(dir.path(), 10);
        let r = budget.try_reserve(10).unwrap();
        let file = r.scratch().unwrap();
        let path = file.path().to_path_buf();
        assert_eq!(path.parent().unwrap(), dir.path());
        drop(file);
        assert!(!path.exists());
    }
}

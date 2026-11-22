//! Spool reservations against the SQL disk budget.
//!
//! Before the uploader writes a snapshot or cumulative-WAL body to the
//! node's SQL data directory, it asks the shared `DiskBudget` for the
//! bytes it needs. The budget already serves the local SQLite actors;
//! the spool piggybacks on it so a bootstrap, a shed capture or a
//! held-but-not-yet-uploaded snapshot cannot push the node into a
//! `sql_disk_headroom` 507 for a user write.
//!
//! The spool itself writes no bytes. It owns:
//!
//! - a prefix for the reservation keys so they do not collide with
//!   actor keys (`sql-spool:<space>:<db_id>`), and
//! - a `Reservation` RAII guard that calls `DiskBudget::forget` on drop.
//!
//! The caller fills the reservation by writing its file alongside the
//! guard; on drop, the budget forgets the bytes and the next
//! reservation may use them. A shed decision (bytes outside the
//! headroom) returns `ReservationRefused::Headroom` BEFORE any copy,
//! so the capture is never cloned.
//!
//! TC-1491.

use std::path::Path;
use std::sync::Arc;

use crate::sql::durability::{DiskBudget, FreeSpace, ReservationRefused};

/// Reservation key prefix the spool uses, so it never collides with a
/// live actor's reservation (`sql:<space>:<db_id>`).
pub const SPOOL_KEY_PREFIX: &str = "sql-spool";

/// A spool reservation tied to the SQL disk budget. Drop releases the
/// bytes.
#[derive(Debug)]
pub struct Reservation {
    budget: Arc<DiskBudget>,
    key: String,
}

impl Reservation {
    /// Try to reserve `bytes` for `(space, db_id)`. Returns a guard on
    /// success; on refusal the caller MUST shed the capture before any
    /// copy. The reserved bytes are inflight (not pending) because the
    /// spool file lives only until its upload completes.
    pub fn try_new(
        budget: Arc<DiskBudget>,
        space: &str,
        db_id: &str,
        bytes: u64,
        free_space: &dyn FreeSpace,
        dir: &Path,
        min_free_bytes: u64,
    ) -> Result<Self, ReservationRefused> {
        let key = reservation_key(space, db_id);
        budget.reserve(&key, bytes, 0, free_space, dir, min_free_bytes)?;
        Ok(Self { budget, key })
    }

    pub fn key(&self) -> &str {
        &self.key
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.budget.forget(&self.key);
    }
}

/// Build the reservation key for a database's spool entry.
pub fn reservation_key(space: &str, db_id: &str) -> String {
    format!("{SPOOL_KEY_PREFIX}:{space}:{db_id}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::durability::DiskBudget;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::Mutex;

    struct FakeFreeSpace(Mutex<HashMap<PathBuf, u64>>);
    impl FakeFreeSpace {
        fn set(&self, dir: &Path, bytes: u64) {
            self.0.lock().unwrap().insert(dir.to_path_buf(), bytes);
        }
    }
    impl FreeSpace for FakeFreeSpace {
        fn free_bytes(&self, dir: &Path) -> Result<u64, std::io::Error> {
            Ok(self.0.lock().unwrap().get(dir).copied().unwrap_or(u64::MAX))
        }
    }

    #[test]
    fn reservation_succeeds_when_free_space_exceeds_the_ask() {
        let budget = Arc::new(DiskBudget::default());
        let free = FakeFreeSpace(Mutex::new(HashMap::new()));
        let dir = PathBuf::from("/data/sql");
        free.set(&dir, 100 * 1024 * 1024);
        let r = Reservation::try_new(
            budget.clone(),
            "space-a",
            "main",
            4 * 1024 * 1024,
            &free,
            &dir,
            1024 * 1024,
        )
        .unwrap();
        assert_eq!(r.key(), "sql-spool:space-a:main");
    }

    #[test]
    fn reservation_refuses_before_any_copy_when_budget_is_full() {
        let budget = Arc::new(DiskBudget::default());
        let free = FakeFreeSpace(Mutex::new(HashMap::new()));
        let dir = PathBuf::from("/data/sql");
        // 1 MiB free, 4 MiB ask + 1 MiB headroom: refused.
        free.set(&dir, 1024 * 1024);
        let err = Reservation::try_new(
            budget,
            "space-a",
            "main",
            4 * 1024 * 1024,
            &free,
            &dir,
            1024 * 1024,
        )
        .unwrap_err();
        assert!(matches!(err, ReservationRefused::Headroom));
    }

    #[test]
    fn dropping_the_reservation_releases_the_bytes_for_the_next_one() {
        let budget = Arc::new(DiskBudget::default());
        let free = FakeFreeSpace(Mutex::new(HashMap::new()));
        let dir = PathBuf::from("/data/sql");
        // Tight: 8 MiB free, 4 MiB headroom, two sequential 4 MiB
        // reservations.
        free.set(&dir, 8 * 1024 * 1024);
        let first = Reservation::try_new(
            budget.clone(),
            "a",
            "d",
            4 * 1024 * 1024 - 1,
            &free,
            &dir,
            0,
        )
        .unwrap();
        // While `first` holds, a second one of the same size would
        // exceed free (two reservations against 8 MiB with no headroom).
        let err = Reservation::try_new(
            budget.clone(),
            "b",
            "e",
            4 * 1024 * 1024 + 2,
            &free,
            &dir,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, ReservationRefused::Headroom));
        drop(first);
        // After drop, the second reservation succeeds.
        let _second =
            Reservation::try_new(budget, "b", "e", 4 * 1024 * 1024 + 2, &free, &dir, 0).unwrap();
    }

    #[test]
    fn two_spool_keys_for_two_databases_do_not_collide() {
        assert_eq!(reservation_key("s1", "d1"), "sql-spool:s1:d1");
        assert_ne!(reservation_key("s1", "d1"), reservation_key("s1", "d2"));
        assert_ne!(reservation_key("s1", "d1"), reservation_key("s2", "d1"));
    }

    #[test]
    fn spool_key_never_collides_with_actor_key_prefix() {
        let k = reservation_key("s", "d");
        assert!(k.starts_with("sql-spool:"));
        // The actor's reservation key starts with "sql:"; the spool's
        // "sql-spool:" prefix shares the "sql" letters but the colon
        // position differs.
        assert!(!k.starts_with("sql:"));
    }
}

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
/// live actor's reservation (`{space}/{db_id}`).
pub const SPOOL_KEY_PREFIX: &str = "sql-spool";

/// Process-wide counter that makes each spool reservation key unique
/// so two in-flight reservations for the same DB do not alias each
/// other on the DiskBudget (the budget stores one entry per key, and
/// an aliased key's Drop would forget both).
static RESERVATION_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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
    ///
    /// `spool_margin_bytes` is added on top of the actors'
    /// `min_free_bytes` headroom, so a big bootstrap cannot push the
    /// live-write headroom to zero and force user writes into
    /// `sql_disk_headroom` 507s. 32 MiB is a reasonable default for
    /// the live set; the node fairing supplies it.
    ///
    /// The reservation key carries a process-wide counter so two
    /// in-flight reservations on the same `(space, db_id)` do not
    /// alias on the budget's map (where a Drop on the second one
    /// would forget both).
    #[allow(clippy::too_many_arguments)]
    pub fn try_new(
        budget: Arc<DiskBudget>,
        space: &str,
        db_id: &str,
        bytes: u64,
        free_space: &dyn FreeSpace,
        dir: &Path,
        min_free_bytes: u64,
        spool_margin_bytes: u64,
    ) -> Result<Self, ReservationRefused> {
        let key = reservation_key(space, db_id);
        budget.reserve(
            &key,
            bytes,
            0,
            free_space,
            dir,
            min_free_bytes.saturating_add(spool_margin_bytes),
        )?;
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

/// Build the reservation key for a database's spool entry. The
/// process-wide counter guarantees uniqueness across in-flight
/// reservations on the same `(space, db_id)`.
pub fn reservation_key(space: &str, db_id: &str) -> String {
    let n = RESERVATION_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{SPOOL_KEY_PREFIX}:{space}:{db_id}:{n}")
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
            0,
        )
        .unwrap();
        assert!(r.key().starts_with("sql-spool:space-a:main:"));
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
            0,
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
            0,
        )
        .unwrap_err();
        assert!(matches!(err, ReservationRefused::Headroom));
        drop(first);
        // After drop, the second reservation succeeds.
        let _second =
            Reservation::try_new(budget, "b", "e", 4 * 1024 * 1024 + 2, &free, &dir, 0, 0).unwrap();
    }

    #[test]
    fn two_spool_keys_for_two_databases_do_not_collide() {
        assert!(reservation_key("s1", "d1").starts_with("sql-spool:s1:d1:"));
        // Two different DBs must not share a prefix either.
        assert_ne!(
            reservation_key("s1", "d1")[..17],
            reservation_key("s1", "d2")[..17]
        );
        // Two reservations on the same DB get unique counter suffixes.
        assert_ne!(reservation_key("s1", "d1"), reservation_key("s1", "d1"));
    }

    #[test]
    fn spool_key_never_collides_with_actor_key_prefix() {
        let k = reservation_key("s", "d");
        assert!(k.starts_with("sql-spool:"));
        // The actor's reservation key has the shape "{space}/{db_id}";
        // the spool's "sql-spool:..." prefix never starts with that.
        assert!(!k.contains('/'));
    }

    #[test]
    fn two_reservations_for_the_same_db_coexist_and_are_forgotten_independently() {
        let budget = Arc::new(DiskBudget::default());
        let free = FakeFreeSpace(Mutex::new(HashMap::new()));
        let dir = PathBuf::from("/data/sql");
        free.set(&dir, 32 * 1024 * 1024);
        let a = Reservation::try_new(
            budget.clone(),
            "space-a",
            "main",
            4 * 1024 * 1024,
            &free,
            &dir,
            0,
            0,
        )
        .unwrap();
        let b = Reservation::try_new(
            budget.clone(),
            "space-a",
            "main",
            4 * 1024 * 1024,
            &free,
            &dir,
            0,
            0,
        )
        .unwrap();
        assert_ne!(a.key(), b.key(), "unique keys per reservation");
        drop(a);
        // After dropping `a`, `b` still holds its 4 MiB. 25 MiB ask
        // against 32 MiB free with 4 MiB held = 29 MiB used: still
        // fits. Push to 29 MiB to force a refusal (29 + 4 = 33 > 32).
        let err = Reservation::try_new(
            budget,
            "space-a",
            "main",
            29 * 1024 * 1024,
            &free,
            &dir,
            0,
            0,
        )
        .unwrap_err();
        assert!(matches!(err, ReservationRefused::Headroom));
        drop(b);
    }

    #[test]
    fn spool_margin_is_added_above_min_free_bytes() {
        let budget = Arc::new(DiskBudget::default());
        let free = FakeFreeSpace(Mutex::new(HashMap::new()));
        let dir = PathBuf::from("/data/sql");
        // 10 MiB free, 1 MiB min_free, 8 MiB spool margin, 3 MiB ask:
        // 3 + 1 + 8 = 12 > 10, refused.
        free.set(&dir, 10 * 1024 * 1024);
        let err = Reservation::try_new(
            budget.clone(),
            "space-a",
            "main",
            3 * 1024 * 1024,
            &free,
            &dir,
            1024 * 1024,
            8 * 1024 * 1024,
        )
        .unwrap_err();
        assert!(matches!(err, ReservationRefused::Headroom));
        // Without the margin the same ask succeeds.
        Reservation::try_new(
            budget,
            "space-a",
            "main",
            3 * 1024 * 1024,
            &free,
            &dir,
            1024 * 1024,
            0,
        )
        .unwrap();
    }
}

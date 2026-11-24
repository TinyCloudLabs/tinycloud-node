//! TC-4290: what the actor hands the save path as its WAL is the committed
//! prefix, never the raw file, and no committed frame means no WAL at all (the
//! caller then saves a whole checkpoint).

use super::*;
use crate::sql::store::shadow::restore::{check_wal, db_page_size, wal_path};
use tempfile::TempDir;

struct Live {
    _dir: TempDir,
    db: PathBuf,
    mode: StorageMode,
    conn: rusqlite::Connection,
}

/// A WAL-mode database that never checkpoints on its own, as the actor's.
fn live() -> Live {
    let dir = TempDir::new().unwrap();
    let db = dir.path().join("db");
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;
         CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB NOT NULL);
         INSERT INTO t (v) VALUES (zeroblob(4));",
    )
    .unwrap();
    Live {
        mode: StorageMode::File(db.clone()),
        _dir: dir,
        db,
        conn,
    }
}

impl Live {
    fn raw_wal(&self) -> Vec<u8> {
        std::fs::read(wal_path(&self.db)).unwrap()
    }

    fn small_commit(&self) {
        self.conn
            .execute("INSERT INTO t (v) VALUES (zeroblob(5))", [])
            .unwrap();
    }

    /// Dirty more pages than the default page cache holds, then roll back.
    fn spill_and_roll_back(&self) {
        let tx = self.conn.unchecked_transaction().unwrap();
        for _ in 0..4 {
            tx.execute("INSERT INTO t (v) VALUES (zeroblob(1000000))", [])
                .unwrap();
        }
        tx.rollback().unwrap();
    }

    fn assert_restorable(&self, wal: &[u8]) {
        let dir = TempDir::new().unwrap();
        let wal_file = dir.path().join("wal");
        std::fs::write(&wal_file, wal).unwrap();
        // The WAL is checked against the page size of the main file, which
        // the actor's own file has (the header is written at creation).
        let page_size = db_page_size(&self.db).unwrap_or(4096);
        check_wal(&wal_file, page_size).unwrap();
    }
}

#[test]
fn a_rolled_back_spill_is_cut_off_the_wal() {
    let live = live();
    live.spill_and_roll_back();
    live.small_commit();
    let raw = live.raw_wal();
    let page_size = 4096;
    let wal_file = wal_path(&live.db);
    assert!(
        check_wal(&wal_file, page_size).is_err(),
        "the raw WAL carries a tail that fails the checksum chain"
    );

    let wal = handle_wal(&live.mode, &live.db).unwrap().unwrap();
    assert!(wal.len() < raw.len());
    assert_eq!(wal, raw[..wal.len()]);
    live.assert_restorable(&wal);

    let snapshot = handle_wal_snapshot(&live.mode, &live.db, u64::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read(snapshot.path()).unwrap(), wal);
}

#[test]
fn a_clean_wal_is_sent_whole() {
    let live = live();
    live.small_commit();
    live.small_commit();
    let raw = live.raw_wal();
    assert_eq!(handle_wal(&live.mode, &live.db).unwrap().unwrap(), raw);
    let snapshot = handle_wal_snapshot(&live.mode, &live.db, u64::MAX)
        .unwrap()
        .unwrap();
    assert_eq!(std::fs::read(snapshot.path()).unwrap(), raw);
}

#[test]
fn a_bad_tail_after_a_commit_is_cut_at_that_commit() {
    let live = live();
    let first = live.raw_wal().len();
    live.small_commit();
    let mut raw = live.raw_wal();
    assert!(raw.len() > first);
    // A byte of the last frame's page goes wrong: its checksum no longer
    // holds, so only what precedes it is a committed prefix.
    let at = raw.len() - 10;
    raw[at] ^= 0xff;
    std::fs::write(wal_path(&live.db), &raw).unwrap();
    let wal = handle_wal(&live.mode, &live.db).unwrap().unwrap();
    assert_eq!(wal.len(), first);
    live.assert_restorable(&wal);
}

#[test]
fn a_wal_without_a_verifiable_commit_is_not_sent() {
    // Header damaged, and first frame damaged: no committed frame verifies.
    for damage in [16, 32 + 24 + 10] {
        let live = live();
        let mut raw = live.raw_wal();
        raw[damage] ^= 0xff;
        std::fs::write(wal_path(&live.db), &raw).unwrap();
        assert_eq!(handle_wal(&live.mode, &live.db).unwrap(), None);
        assert!(handle_wal_snapshot(&live.mode, &live.db, u64::MAX)
            .unwrap()
            .is_none());
    }
}

#[test]
fn an_absent_or_empty_wal_is_not_sent() {
    let live = live();
    std::fs::write(wal_path(&live.db), []).unwrap();
    assert_eq!(handle_wal(&live.mode, &live.db).unwrap(), None);
    assert!(handle_wal_snapshot(&live.mode, &live.db, u64::MAX)
        .unwrap()
        .is_none());
    std::fs::remove_file(wal_path(&live.db)).unwrap();
    assert_eq!(handle_wal(&live.mode, &live.db).unwrap(), None);
}

#[test]
fn the_raw_size_still_gates_the_snapshot() {
    let live = live();
    live.small_commit();
    let raw = live.raw_wal().len() as u64;
    assert!(handle_wal_snapshot(&live.mode, &live.db, raw)
        .unwrap()
        .is_none());
    assert!(handle_wal_snapshot(&live.mode, &live.db, raw + 1)
        .unwrap()
        .is_some());
}

//! TC-1491 P4.2a: the constants, the in-file counter and the reserved
//! namespace, without a service or an actor.

use super::*;
use rusqlite::hooks::TransactionOperation;

fn working_copy(start_seq: u64) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "journal_mode", "wal").unwrap();
        conn.execute_batch("CREATE TABLE items (v TEXT)").unwrap();
    }
    init_working_copy(&path, start_seq).unwrap();
    (dir, path)
}

#[test]
fn the_pilot_cap_is_64_mib_and_inclusive() {
    assert_eq!(PILOT_CAP_BYTES, 64 * 1024 * 1024);
    assert!(within_pilot_cap(0));
    assert!(within_pilot_cap(PILOT_CAP_BYTES - 1));
    assert!(within_pilot_cap(PILOT_CAP_BYTES));
    assert!(!within_pilot_cap(PILOT_CAP_BYTES + 1));
    assert!(!within_pilot_cap(u64::MAX));
}

#[test]
fn the_window_is_60_seconds_or_8_mib() {
    assert_eq!(WINDOW, Duration::from_secs(60));
    assert_eq!(WINDOW_BYTES, 8 * 1024 * 1024);
}

#[test]
fn reserved_names_are_the_prefix_in_any_case_and_nothing_shorter() {
    assert!(is_reserved_name(SEQ_TABLE));
    assert!(is_reserved_name("tinycloud_internal_anything"));
    assert!(is_reserved_name("TINYCLOUD_INTERNAL_X"));
    assert!(is_reserved_name("Tinycloud_Internal_"));
    assert!(!is_reserved_name("tinycloud_internal"));
    assert!(!is_reserved_name("tinycloud_"));
    assert!(!is_reserved_name("items"));
    assert!(!is_reserved_name(""));
    // A multi-byte name shorter than the prefix in bytes must not panic.
    assert!(!is_reserved_name("é"));
}

#[test]
fn every_action_that_names_a_reserved_table_is_caught() {
    let t = SEQ_TABLE;
    let hit = [
        AuthAction::Read {
            table_name: t,
            column_name: "seq",
        },
        AuthAction::Update {
            table_name: t,
            column_name: "seq",
        },
        AuthAction::Insert { table_name: t },
        AuthAction::Delete { table_name: t },
        AuthAction::DropTable { table_name: t },
        AuthAction::CreateTable { table_name: t },
        AuthAction::CreateTempTable { table_name: t },
        AuthAction::AlterTable {
            database_name: "main",
            table_name: t,
        },
        AuthAction::CreateIndex {
            index_name: "i",
            table_name: t,
        },
        AuthAction::CreateTrigger {
            trigger_name: "g",
            table_name: t,
        },
        AuthAction::CreateView { view_name: t },
        AuthAction::Analyze { table_name: t },
        AuthAction::Reindex { index_name: t },
        AuthAction::Pragma {
            pragma_name: "table_info",
            pragma_value: Some(t),
        },
    ];
    for action in &hit {
        assert!(names_reserved(action), "{action:?}");
    }
    let miss = [
        AuthAction::Read {
            table_name: "items",
            column_name: "v",
        },
        AuthAction::Select,
        AuthAction::Transaction {
            operation: TransactionOperation::Begin,
        },
        AuthAction::Pragma {
            pragma_name: "table_info",
            pragma_value: Some("items"),
        },
        AuthAction::Pragma {
            pragma_name: "foreign_keys",
            pragma_value: None,
        },
    ];
    for action in &miss {
        assert!(!names_reserved(action), "{action:?}");
    }
}

#[test]
fn the_counter_starts_at_one_or_more_and_cannot_be_created_twice() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    let conn = Connection::open(&path).unwrap();
    assert!(init_seq(&conn, 0).is_err(), "seq 0 is not a revision");
    init_seq(&conn, 7).unwrap();
    assert_eq!(read_seq(&conn).unwrap(), 7);
    assert!(init_seq(&conn, 9).is_err(), "never re-seeded");
    assert_eq!(read_seq(&conn).unwrap(), 7);
}

#[test]
fn bump_counts_inside_the_callers_transaction_and_rolls_back_with_it() {
    let (_dir, path) = working_copy(10);
    let conn = open_store_master_connection(&StorageMode::File(path), Synchronous::Full).unwrap();
    conn.execute_batch("BEGIN").unwrap();
    conn.execute("INSERT INTO items (v) VALUES ('a')", [])
        .unwrap();
    bump_seq(&conn).unwrap();
    assert_eq!(read_seq(&conn).unwrap(), 11);
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(
        read_seq(&conn).unwrap(),
        10,
        "the counter rolls back with its write"
    );
    let rows: i64 = conn
        .query_row("SELECT count(*) FROM items", [], |r| r.get(0))
        .unwrap();
    assert_eq!(rows, 0);
}

#[test]
fn the_check_constraints_refuse_a_zero_or_second_row() {
    let (_dir, path) = working_copy(3);
    let conn = open_store_master_connection(&StorageMode::File(path), Synchronous::Full).unwrap();
    assert!(conn
        .execute(&format!("UPDATE {SEQ_TABLE} SET seq = 0"), [])
        .is_err());
    assert!(conn
        .execute(
            &format!("INSERT INTO {SEQ_TABLE} (id, seq) VALUES (2, 9)"),
            []
        )
        .is_err());
}

#[test]
fn init_working_copy_folds_the_wal_so_the_file_hash_is_the_anchor() {
    let (_dir, path) = working_copy(5);
    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0);
    // Everything is in the main file: a plain copy of it alone is the database.
    let copy = path.with_extension("copy");
    std::fs::copy(&path, &copy).unwrap();
    let conn = Connection::open(&copy).unwrap();
    assert_eq!(read_seq(&conn).unwrap(), 5);
    let items: i64 = conn
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE name = 'items'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(items, 1);
}

#[test]
fn a_missing_or_uninitialised_file_is_never_created_or_adopted() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("gone.db");
    assert!(matches!(
        validate_working_copy(&missing),
        Err(SqlError::Unavailable)
    ));
    assert!(!missing.exists(), "nothing was created");
    let plain = dir.path().join("plain.db");
    Connection::open(&plain)
        .unwrap()
        .execute_batch("CREATE TABLE items (v TEXT)")
        .unwrap();
    assert!(validate_working_copy(&plain).is_err(), "no counter");
}

#[test]
fn a_store_master_connection_leaves_the_wal_when_it_closes() {
    let (_dir, path) = working_copy(1);
    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    {
        let conn =
            open_store_master_connection(&StorageMode::File(path.clone()), Synchronous::Full)
                .unwrap();
        conn.execute("INSERT INTO items (v) VALUES ('a')", [])
            .unwrap();
        bump_seq(&conn).unwrap();
    }
    let len = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    assert!(len > 0, "closing did not checkpoint and delete the WAL");
    assert_eq!(validate_working_copy(&path).unwrap(), 2);
}

#[test]
fn the_checkpoint_hash_is_cached_by_file_identity_and_follows_the_file() {
    let (_dir, path) = working_copy(1);
    let files = LocalFiles::default();
    let key: DbKey = ("s".into(), "d".into());
    let first = files.checkpoint_cid(&key, &path).unwrap();
    assert_eq!(first, hash_file(&path).unwrap());
    assert_eq!(files.checkpoint_cid(&key, &path).unwrap(), first);
    // A checkpoint changes the main file: a new length or mtime, a new hash.
    {
        let conn =
            open_store_master_connection(&StorageMode::File(path.clone()), Synchronous::Full)
                .unwrap();
        conn.execute("INSERT INTO items (v) VALUES (zeroblob(100000))", [])
            .unwrap();
        bump_seq(&conn).unwrap();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
    }
    let second = files.checkpoint_cid(&key, &path).unwrap();
    assert_ne!(second, first);
    assert_eq!(second, hash_file(&path).unwrap());
}

#[test]
fn ahead_bytes_counts_the_wal_since_the_publish_or_everything_when_unknown() {
    let files = LocalFiles::default();
    let key: DbKey = ("s".into(), "d".into());
    // Nothing published in this process: the whole checkpoint and WAL.
    assert_eq!(files.ahead_bytes(&key, "a", 300, 1000), 1300);
    files.record_mark(
        &key,
        WalMark {
            revision: 4,
            checkpoint_content_hash: "a".into(),
            wal_end_bytes: 200,
            wal_prefix_sha256: [0; 32],
        },
    );
    files.set_published(&key, "a", 4);
    assert_eq!(files.ahead_bytes(&key, "a", 300, 1000), 100);
    assert_eq!(files.ahead_bytes(&key, "a", 200, 1000), 0);
    // A new checkpoint: the store has none of it.
    assert_eq!(files.ahead_bytes(&key, "b", 50, 2000), 2050);
}

#[test]
fn marks_are_kept_per_revision_and_bounded() {
    let files = LocalFiles::default();
    let key: DbKey = ("s".into(), "d".into());
    for revision in 1..=20 {
        files.record_mark(
            &key,
            WalMark {
                revision,
                checkpoint_content_hash: "a".into(),
                wal_end_bytes: revision as u64,
                wal_prefix_sha256: [0; 32],
            },
        );
    }
    let all: Vec<i64> = (1..=20).collect();
    let kept = files.marks(&key, &all);
    assert_eq!(kept.len(), MARKS_KEPT);
    assert_eq!(kept.last().unwrap().revision, 20);
    // A revision recorded again replaces its mark.
    files.record_mark(
        &key,
        WalMark {
            revision: 20,
            checkpoint_content_hash: "b".into(),
            wal_end_bytes: 99,
            wal_prefix_sha256: [1; 32],
        },
    );
    let again = files.marks(&key, &[20]);
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].wal_end_bytes, 99);
}

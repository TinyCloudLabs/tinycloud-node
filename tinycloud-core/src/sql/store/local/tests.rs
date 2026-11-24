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

#[test]
fn a_temp_table_named_like_the_counter_does_not_shadow_it() {
    let (_dir, path) = working_copy(10);
    let conn =
        open_store_master_connection(&StorageMode::File(path.clone()), Synchronous::Full).unwrap();
    conn.execute_batch(&format!(
        "CREATE TEMP TABLE {SEQ_TABLE} (id INTEGER PRIMARY KEY, seq INTEGER); \
         INSERT INTO temp.{SEQ_TABLE} VALUES (1, 3);"
    ))
    .unwrap();
    assert_eq!(
        read_seq(&conn).unwrap(),
        10,
        "the file's counter, not temp's"
    );
    bump_seq(&conn).unwrap();
    assert_eq!(read_seq(&conn).unwrap(), 11);
    let temp: i64 = conn
        .query_row(&format!("SELECT seq FROM temp.{SEQ_TABLE}"), [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(temp, 3, "the temp table is the user's and is left alone");
    assert_eq!(read_seq(&Connection::open(&path).unwrap()).unwrap(), 11);
}

#[test]
fn a_rename_to_a_reserved_name_is_found_in_the_statement() {
    use sqlparser::dialect::SQLiteDialect;
    use sqlparser::parser::Parser;
    let parse = |sql: &str| Parser::parse_sql(&SQLiteDialect {}, sql).unwrap();
    for sql in [
        "ALTER TABLE temp.x RENAME TO tinycloud_internal_store_seq",
        "ALTER TABLE x RENAME TO TinyCloud_Internal_mine",
        "ALTER TABLE x RENAME TO \"tinycloud_internal_a\"",
        "ALTER TABLE main.x RENAME TO `TINYCLOUD_INTERNAL_b`",
    ] {
        assert!(renames_to_reserved(&parse(sql)), "{sql}");
    }
    for sql in [
        "ALTER TABLE x RENAME TO y",
        "ALTER TABLE x RENAME TO tinycloud_mine",
        "ALTER TABLE x ADD COLUMN tinycloud_internal_c INTEGER",
        "SELECT 1",
    ] {
        assert!(!renames_to_reserved(&parse(sql)), "{sql}");
    }
}

#[test]
fn a_counter_at_the_top_refuses_the_next_write_instead_of_overflowing() {
    let top = i64::MAX as u64;
    let (_dir, path) = working_copy(top - 1);
    let conn =
        open_store_master_connection(&StorageMode::File(path.clone()), Synchronous::Full).unwrap();
    bump_seq(&conn).unwrap();
    assert_eq!(read_seq(&conn).unwrap(), top);

    let error = bump_seq(&conn).unwrap_err();
    assert!(error.to_string().contains("exhausted"), "{error}");
    assert_eq!(read_seq(&conn).unwrap(), top, "still an integer, unchanged");
    // Nothing, not even a hand-written update, can turn it into a REAL.
    assert!(conn
        .execute(&format!("UPDATE main.{SEQ_TABLE} SET seq = seq + 1"), [])
        .is_err());
    drop(conn);
    assert_eq!(validate_working_copy(&path).unwrap(), top, "it still opens");
}

#[test]
fn a_write_whose_counter_was_changed_inside_its_transaction_is_refused() {
    let (_dir, path) = working_copy(10);
    let conn =
        open_store_master_connection(&StorageMode::File(path.clone()), Synchronous::Full).unwrap();

    // The counter as the request saw it at BEGIN: the bump is exactly +1.
    let before = read_seq(&conn).unwrap();
    bump_seq_from(&conn, before).unwrap();
    assert_eq!(read_seq(&conn).unwrap(), before + 1);

    // Something moved the row between BEGIN and the bump, by any path: the
    // write is refused, and the row is left as it was found.
    conn.execute_batch("BEGIN").unwrap();
    let before = read_seq(&conn).unwrap();
    conn.execute(&format!("UPDATE main.{SEQ_TABLE} SET seq = seq + 5"), [])
        .unwrap();
    let error = bump_seq_from(&conn, before).unwrap_err();
    assert!(error.to_string().contains("changed during"), "{error}");
    conn.execute_batch("ROLLBACK").unwrap();
    assert_eq!(read_seq(&conn).unwrap(), before, "the rollback undoes it");

    // A deleted row is its own error, not a silent success.
    conn.execute_batch("BEGIN").unwrap();
    conn.execute(&format!("DELETE FROM main.{SEQ_TABLE}"), [])
        .unwrap();
    assert!(bump_seq_from(&conn, before).is_err());
    conn.execute_batch("ROLLBACK").unwrap();
}

#[test]
fn a_space_that_is_forgotten_takes_every_database_of_it_and_no_other() {
    let files = LocalFiles::default();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("f");
    std::fs::write(&path, b"x").unwrap();
    let purged: DbKey = ("purged".into(), "a".into());
    let purged_too: DbKey = ("purged".into(), "b".into());
    let kept: DbKey = ("kept".into(), "a".into());
    for key in [&purged, &purged_too, &kept] {
        files.checkpoint_cid(key, &path).unwrap();
        files.record_mark(
            key,
            WalMark {
                revision: 1,
                checkpoint_content_hash: "c".into(),
                wal_end_bytes: 1,
                wal_prefix_sha256: [0; 32],
            },
        );
    }
    assert!(files.knows_space("purged") && files.knows_space("kept"));

    files.forget_space("purged");
    assert!(!files.knows_space("purged"));
    assert!(files.marks(&purged, &[1]).is_empty());
    assert!(files.marks(&purged_too, &[1]).is_empty());
    assert_eq!(
        files.marks(&kept, &[1]).len(),
        1,
        "a neighbour is untouched"
    );
}

#[test]
fn a_rotation_waits_for_a_wal_in_proportion_to_the_main_file_within_bounds() {
    // Small databases keep the 8 MiB window.
    assert_eq!(rotation_threshold(0), WINDOW_BYTES);
    assert_eq!(rotation_threshold(10 * 1024 * 1024), WINDOW_BYTES);
    // Then half the main file, so a snapshot is at most 2x what was written.
    assert_eq!(rotation_threshold(30 * 1024 * 1024), 15 * 1024 * 1024);
    // And never more than half the cap, so the backstop and the refusal
    // above it stay out of the uploader's way.
    assert_eq!(rotation_threshold(PILOT_CAP_BYTES), PILOT_CAP_BYTES / 2);
    assert_eq!(rotation_threshold(u64::MAX), PILOT_CAP_BYTES / 2);
    assert!(rotation_threshold(u64::MAX) < WAL_BACKSTOP_BYTES);
    const { assert!(WAL_BACKSTOP_BYTES < WAL_REFUSE_BYTES) };
}

#[test]
fn a_database_that_already_has_a_table_of_the_counters_name_is_not_cut_over() {
    // A Postgres-mode database can hold such a table (the prefix is reserved
    // only for store-master), or be the import of an export of one.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    {
        let conn = Connection::open(&path).unwrap();
        conn.pragma_update(None, "journal_mode", "wal").unwrap();
        conn.execute_batch(&format!(
            "CREATE TABLE \"{}\" (id INTEGER PRIMARY KEY, seq INTEGER); \
             INSERT INTO \"{}\" VALUES (1, 999)",
            SEQ_TABLE.to_uppercase(),
            SEQ_TABLE.to_uppercase()
        ))
        .unwrap();
    }
    let error = init_working_copy(&path, 10).unwrap_err();
    assert!(
        error.to_string().contains("already has a table named"),
        "{error}"
    );
    // Nothing was adopted or touched.
    let conn = Connection::open(&path).unwrap();
    let planted: i64 = conn
        .query_row(
            &format!("SELECT seq FROM \"{}\"", SEQ_TABLE.to_uppercase()),
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(planted, 999);
}

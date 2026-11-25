//! TC-1491 P4.2a: the constants and the file-backed counter (bump-before-write),
//! without a service or an actor.

use super::*;
use rusqlite::Connection;

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
fn the_counter_starts_at_one_or_more_and_cannot_be_created_twice() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE items (v TEXT)")
        .unwrap();
    assert!(
        init_working_copy(&path, 0).is_err(),
        "seq 0 is not a revision"
    );
    assert!(!seq_path(&path).exists(), "a refused start leaves nothing");
    init_working_copy(&path, 7).unwrap();
    assert_eq!(read_seq(&path).unwrap(), 7);
    assert!(init_working_copy(&path, 9).is_err(), "never re-seeded");
    assert_eq!(read_seq(&path).unwrap(), 7);
}

#[test]
fn bump_moves_the_counter_by_one_in_its_own_file_and_leaves_the_database_alone() {
    let (_dir, path) = working_copy(10);
    let main_before = hash_file(&path).unwrap();
    assert_eq!(bump_seq(&path).unwrap(), 11);
    assert_eq!(bump_seq(&path).unwrap(), 12);
    assert_eq!(read_seq(&path).unwrap(), 12);
    assert_eq!(
        std::fs::metadata(seq_path(&path)).unwrap().len(),
        SEQ_RECORD_LEN as u64,
        "the record never grows"
    );
    assert_eq!(
        hash_file(&path).unwrap(),
        main_before,
        "the data is not touched"
    );
    // The database holds nothing of the node's.
    let conn = Connection::open(&path).unwrap();
    let names: Vec<String> = conn
        .prepare("SELECT name FROM sqlite_master ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(names, ["items"]);
}

#[test]
fn a_counter_file_that_does_not_check_is_refused_and_not_repaired() {
    let (_dir, path) = working_copy(10);
    let seq = seq_path(&path);
    let good = std::fs::read(&seq).unwrap();

    let mut flipped = good.clone();
    flipped[0] ^= 1; // a different counter under the old check
    let mut torn = good.clone();
    torn[12] ^= 0xff; // the check half torn
    for (what, bytes) in [
        ("a changed counter", flipped),
        ("a torn check", torn),
        ("a short file", good[..8].to_vec()),
        ("an empty file", Vec::new()),
        ("a long file", [good.clone(), vec![0]].concat()),
    ] {
        std::fs::write(&seq, &bytes).unwrap();
        assert!(read_seq(&path).is_err(), "{what}");
        assert!(bump_seq(&path).is_err(), "{what}");
        assert!(validate_working_copy(&path).is_err(), "{what}");
        assert_eq!(std::fs::read(&seq).unwrap(), bytes, "{what}: left as found");
    }
    std::fs::remove_file(&seq).unwrap();
    assert!(read_seq(&path).is_err() && bump_seq(&path).is_err());
    assert!(
        !seq.exists(),
        "a missing counter is never created by a bump"
    );
}

#[test]
fn a_counter_at_the_top_refuses_the_next_bump_instead_of_overflowing() {
    let top = i64::MAX as u64;
    let (_dir, path) = working_copy(top - 1);
    assert_eq!(bump_seq(&path).unwrap(), top);
    let error = bump_seq(&path).unwrap_err();
    assert!(error.to_string().contains("exhausted"), "{error}");
    assert_eq!(validate_working_copy(&path).unwrap(), top, "unchanged");
}

#[test]
fn init_working_copy_folds_the_wal_so_the_file_hash_is_the_anchor() {
    let (_dir, path) = working_copy(5);
    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    assert_eq!(std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0), 0);
    // Everything is in the main file: a plain copy of it alone is the database.
    // (The counter is not in it: it is the seq file beside it.)
    let copy = path.with_extension("copy");
    std::fs::copy(&path, &copy).unwrap();
    let conn = Connection::open(&copy).unwrap();
    assert_eq!(read_seq(&path).unwrap(), 5);
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
        bump_seq(&path).unwrap();
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
        bump_seq(&path).unwrap();
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

/// The three files of a working copy at one instant, as a crash leaves them:
/// the next open replays the WAL and ignores whatever was not committed.
fn crash_image(path: &std::path::Path, to: &std::path::Path) -> std::path::PathBuf {
    std::fs::create_dir_all(to).unwrap();
    let image = to.join("main.db");
    std::fs::copy(path, &image).unwrap();
    let wal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    if wal.exists() {
        std::fs::copy(&wal, format!("{}-wal", image.display())).unwrap();
    }
    std::fs::copy(seq_path(path), seq_path(&image)).unwrap();
    image
}

fn recovered(image: &std::path::Path) -> (u64, i64) {
    let rows = Connection::open(image)
        .unwrap()
        .query_row("SELECT count(*) FROM items", [], |r| r.get(0))
        .unwrap();
    (read_seq(image).unwrap(), rows)
}

#[test]
fn a_crash_at_each_step_of_one_write_leaves_a_gap_at_worst_and_no_reused_seq() {
    let (dir, path) = working_copy(10);
    let conn =
        open_store_master_connection(&StorageMode::File(path.clone()), Synchronous::Full).unwrap();
    // A small page cache, so the uncommitted write spills into the WAL: a
    // crash in the middle of a write leaves uncommitted frames behind.
    conn.pragma_update(None, "cache_size", 10).unwrap();
    let images = dir.path().join("images");

    // The order the actor follows: statements, bump (fsynced), commit.
    conn.execute_batch("BEGIN").unwrap();
    conn.execute("INSERT INTO items (v) VALUES (zeroblob(2000000))", [])
        .unwrap();
    let mid_write = crash_image(&path, &images.join("mid"));
    bump_seq(&path).unwrap();
    let bumped = crash_image(&path, &images.join("bumped"));
    conn.execute_batch("COMMIT").unwrap();
    let committed = crash_image(&path, &images.join("committed"));

    let wal_of = |image: &std::path::Path| {
        std::fs::metadata(format!("{}-wal", image.display()))
            .map(|m| m.len())
            .unwrap_or(0)
    };
    assert!(
        wal_of(&mid_write) > 0,
        "the write had spilled uncommitted frames into the WAL"
    );
    // Crash mid-write, before the bump: nothing of the write, counter as was.
    assert_eq!(recovered(&mid_write), (10, 0));
    // Crash after the bump, before the commit: the data is as it was, the
    // counter is one ahead. A gap.
    assert_eq!(recovered(&bumped), (11, 0));
    // Crash after the commit: the data and its counter.
    assert_eq!(recovered(&committed), (11, 1));

    // Restart from the gap: the next write gets 12. 11 is never issued for
    // different bytes (here it never names any bytes at all).
    let after_gap =
        open_store_master_connection(&StorageMode::File(bumped.clone()), Synchronous::Full)
            .unwrap();
    after_gap.execute_batch("BEGIN").unwrap();
    after_gap
        .execute("INSERT INTO items (v) VALUES ('next')", [])
        .unwrap();
    assert_eq!(bump_seq(&bumped).unwrap(), 12);
    after_gap.execute_batch("COMMIT").unwrap();
    assert_eq!(recovered(&bumped), (12, 1));
}

#[test]
fn a_store_master_connection_is_always_synchronous_full() {
    // RED FORM (9e38f2b0): the function takes the node's policy, and a node
    // configured with `normal` gets NORMAL. At the fix the function takes no
    // policy; the test there is the same without the argument.
    let (_dir, path) = working_copy(1);
    let conn = open_store_master_connection(&StorageMode::File(path), Synchronous::Normal).unwrap();
    let level: i64 = conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .unwrap();
    assert_eq!(level, 2, "FULL");
}

#[test]
fn creating_the_seq_file_leaves_no_temp_file_and_a_leftover_one_is_never_the_counter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE items (v TEXT)")
        .unwrap();
    // What an `init_working_copy` that died before the link leaves.
    let tmp = std::path::PathBuf::from(format!("{}.tmp", seq_path(&path).display()));
    std::fs::write(&tmp, b"short").unwrap();
    assert!(read_seq(&path).is_err(), "a temp file is not a counter");
    assert!(validate_working_copy(&path).is_err());
    assert!(!seq_path(&path).exists());

    init_working_copy(&path, 5).unwrap();
    assert_eq!(read_seq(&path).unwrap(), 5);
    assert!(!tmp.exists(), "the leftover is replaced and removed");
    assert_eq!(
        std::fs::read(seq_path(&path)).unwrap().len(),
        SEQ_RECORD_LEN
    );

    // A second run refuses, keeps the counter and leaves no temp file.
    assert!(init_working_copy(&path, 9).is_err());
    assert_eq!(read_seq(&path).unwrap(), 5);
    assert!(!tmp.exists());
}

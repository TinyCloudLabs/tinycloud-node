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
        let conn = open_store_master_connection(&StorageMode::File(path.clone())).unwrap();
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
        let conn = open_store_master_connection(&StorageMode::File(path.clone())).unwrap();
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
    let conn = open_store_master_connection(&StorageMode::File(path.clone())).unwrap();
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
    let after_gap = open_store_master_connection(&StorageMode::File(bumped.clone())).unwrap();
    after_gap.execute_batch("BEGIN").unwrap();
    after_gap
        .execute("INSERT INTO items (v) VALUES ('next')", [])
        .unwrap();
    assert_eq!(bump_seq(&bumped).unwrap(), 12);
    after_gap.execute_batch("COMMIT").unwrap();
    assert_eq!(recovered(&bumped), (12, 1));
}

/// The committed WAL length by the frame scan, the reference the index read
/// must agree with.
fn scanned(main: &std::path::Path) -> u64 {
    crate::sql::store::shadow::restore::committed_wal_len(&std::path::PathBuf::from(format!(
        "{}-wal",
        main.display()
    )))
    .unwrap()
}

#[test]
fn the_committed_wal_length_is_what_the_frame_scan_finds_and_not_the_file_length() {
    let (_dir, path) = working_copy(10);
    let conn = open_store_master_connection(&StorageMode::File(path.clone())).unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    conn.pragma_update(None, "cache_size", 10).unwrap();
    let file_len = || {
        std::fs::metadata(format!("{}-wal", path.display()))
            .unwrap()
            .len()
    };

    assert_eq!(committed_wal_bytes(&path).unwrap(), scanned(&path));
    conn.execute("INSERT INTO items (v) VALUES ('a')", [])
        .unwrap();
    let one_commit = committed_wal_bytes(&path).unwrap();
    assert!(one_commit > 0);
    assert_eq!(one_commit, scanned(&path));

    // A write that spills into the WAL and rolls back: the file grows, what is
    // committed does not.
    conn.execute_batch("BEGIN").unwrap();
    conn.execute("INSERT INTO items (v) VALUES (zeroblob(2000000))", [])
        .unwrap();
    assert_eq!(
        committed_wal_bytes(&path).unwrap(),
        one_commit,
        "an open write is not committed"
    );
    conn.execute_batch("ROLLBACK").unwrap();
    assert!(
        file_len() > one_commit + 1024 * 1024,
        "the dead tail is in the file"
    );
    assert_eq!(committed_wal_bytes(&path).unwrap(), one_commit);
    assert_eq!(scanned(&path), one_commit);

    // The next commit overwrites the start of the tail; the file does not
    // shrink, the committed length moves by that commit only.
    conn.execute("INSERT INTO items (v) VALUES ('b')", [])
        .unwrap();
    let two_commits = committed_wal_bytes(&path).unwrap();
    assert!(two_commits > one_commit);
    assert!(two_commits < one_commit + 64 * 1024);
    assert_eq!(two_commits, scanned(&path));

    let busy: i64 = conn
        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |row| row.get(0))
        .unwrap();
    assert_eq!(busy, 0);
    assert_eq!(committed_wal_bytes(&path).unwrap(), 0);
}

#[test]
fn without_a_usable_wal_index_the_committed_length_is_scanned() {
    let (dir, path) = working_copy(10);
    let conn = open_store_master_connection(&StorageMode::File(path.clone())).unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    conn.pragma_update(None, "cache_size", 10).unwrap();
    conn.execute("INSERT INTO items (v) VALUES ('a')", [])
        .unwrap();
    conn.execute_batch("BEGIN").unwrap();
    conn.execute("INSERT INTO items (v) VALUES (zeroblob(2000000))", [])
        .unwrap();
    conn.execute_batch("ROLLBACK").unwrap();
    let committed = committed_wal_bytes(&path).unwrap();

    // A copy of the files has no index at all.
    let image = crash_image(&path, &dir.path().join("no-index"));
    assert_eq!(committed_wal_bytes(&image).unwrap(), committed);

    // An index that is not an initialised header, a header whose two copies
    // differ, and one that names more frames than the file holds are not
    // believed.
    let shm = std::path::PathBuf::from(format!("{}-shm", image.display()));
    let real = std::fs::read(format!("{}-shm", path.display())).unwrap();
    std::fs::write(&shm, [0u8; 96]).unwrap();
    assert_eq!(committed_wal_bytes(&image).unwrap(), committed);
    let mut torn = real.clone();
    torn[60] ^= 0xff;
    std::fs::write(&shm, &torn).unwrap();
    assert_eq!(committed_wal_bytes(&image).unwrap(), committed);
    let mut long = real;
    long[16..20].copy_from_slice(&u32::MAX.to_ne_bytes());
    long[64..68].copy_from_slice(&u32::MAX.to_ne_bytes());
    std::fs::write(&shm, &long).unwrap();
    assert_eq!(committed_wal_bytes(&image).unwrap(), committed);
}

/// The WAL index header is written twice and only believed when both copies
/// are equal. A damaged copy that names FEWER frames than the file holds would
/// pass every other check, so each copy is damaged on its own: trusting
/// either one alone gives the wrong length.
#[test]
fn a_wal_index_whose_two_header_copies_disagree_is_believed_in_neither_direction() {
    let (dir, path) = working_copy(10);
    let conn = open_store_master_connection(&StorageMode::File(path.clone())).unwrap();
    conn.pragma_update(None, "wal_autocheckpoint", 0).unwrap();
    conn.execute("INSERT INTO items (v) VALUES ('a')", [])
        .unwrap();
    let committed = committed_wal_bytes(&path).unwrap();
    assert!(committed > 0);

    let image = crash_image(&path, &dir.path().join("two-copies"));
    let shm = std::path::PathBuf::from(format!("{}-shm", image.display()));
    let real = std::fs::read(format!("{}-shm", path.display())).unwrap();
    assert_eq!(real[..48], real[48..96], "the header is written twice");
    std::fs::write(&shm, &real[..96]).unwrap();
    assert_eq!(
        committed_wal_bytes(&image).unwrap(),
        committed,
        "both whole"
    );
    for (copy, at) in [("first", 0usize), ("second", 48)] {
        let mut damaged = real[..96].to_vec();
        damaged[at + 16..at + 20].copy_from_slice(&0u32.to_ne_bytes());
        std::fs::write(&shm, &damaged).unwrap();
        assert_eq!(
            committed_wal_bytes(&image).unwrap(),
            committed,
            "only the {copy} copy names no frames: scanned, not believed"
        );
    }
}

#[test]
fn a_store_master_connection_is_always_synchronous_full() {
    // `open_store_master_connection` takes no policy: a power loss must not
    // drop a commit already published at seq S, so NORMAL is not an option.
    let (_dir, path) = working_copy(1);
    let conn = open_store_master_connection(&StorageMode::File(path)).unwrap();
    let level: i64 = conn
        .query_row("PRAGMA synchronous", [], |row| row.get(0))
        .unwrap();
    assert_eq!(level, 2, "FULL");
}

#[test]
fn a_leftover_temp_file_is_never_the_counter_and_a_run_leaves_none_of_its_own() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE items (v TEXT)")
        .unwrap();
    // What an `init_working_copy` that died before the link leaves. It is not
    // the counter, and a later run neither reads, links nor removes it.
    let leftover = std::path::PathBuf::from(format!(
        "{}.tmp.1.0.0000000000000000",
        seq_path(&path).display()
    ));
    std::fs::write(&leftover, b"short").unwrap();
    assert!(read_seq(&path).is_err(), "a temp file is not a counter");
    assert!(validate_working_copy(&path).is_err());
    assert!(!seq_path(&path).exists());
    let temp_files = || -> Vec<std::path::PathBuf> {
        std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|file| file.to_string_lossy().contains(".seq.tmp"))
            .collect()
    };

    init_working_copy(&path, 5).unwrap();
    assert_eq!(read_seq(&path).unwrap(), 5);
    assert_eq!(
        temp_files(),
        vec![leftover.clone()],
        "the run's own temp file is gone; the dead run's is not ours to remove"
    );
    assert_eq!(
        std::fs::read(seq_path(&path)).unwrap().len(),
        SEQ_RECORD_LEN
    );

    // A second run refuses, keeps the counter and leaves no temp file of its own.
    assert!(init_working_copy(&path, 9).is_err());
    assert_eq!(read_seq(&path).unwrap(), 5);
    assert_eq!(temp_files(), vec![leftover]);
}

/// Two `init_working_copy` calls on one database at once (the caller should
/// not, but nothing else stops it): exactly one wins, every other call is
/// refused, and the counter on disk is the winner's `start_seq`. A call that
/// returned `Ok` with another call's number would be a cutover that believes
/// it seeded the counter at a revision it did not.
#[test]
fn concurrent_inits_leave_one_winner_and_the_counter_is_the_winners() {
    const CALLERS: u64 = 6;
    for round in 0..100 {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("main.db");
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE items (v TEXT)")
            .unwrap();
        let start = std::sync::Arc::new(std::sync::Barrier::new(CALLERS as usize));
        let results: Vec<(u64, bool)> = (0..CALLERS)
            .map(|caller| {
                let (path, start) = (path.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    (caller, init_working_copy(&path, 100 + caller).is_ok())
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .collect();
        let winners: Vec<u64> = results
            .iter()
            .filter(|(_, ok)| *ok)
            .map(|(caller, _)| *caller)
            .collect();
        assert_eq!(
            winners.len(),
            1,
            "round {round}: exactly one init may return Ok, got {winners:?}"
        );
        assert_eq!(
            read_seq(&path).unwrap(),
            100 + winners[0],
            "round {round}: the counter is the winner's start_seq"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains(".seq.tmp"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "round {round}: temp files {leftovers:?}"
        );
    }
}

/// A main file that is not there is not made into a working copy: init
/// creates neither the main file nor the seq file, so nothing is served from a
/// path that never held the database. (The order "main file durable before the
/// seq file is linked" is not observable from a test without a power cut; it
/// is read from `init_working_copy`: `sync_file_and_directory(path)` runs
/// before the temp file is created. A 0-byte file that does exist is a valid
/// empty SQLite database that init cannot tell from one that lost its content:
/// the design's P4.4 rule checks the main file's hash against the artifact's
/// `checkpoint_content_hash` before the flip.)
#[test]
fn init_on_a_missing_main_file_creates_neither_the_main_file_nor_a_counter() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    assert!(matches!(
        init_working_copy(&path, 5),
        Err(SqlError::Unavailable)
    ));
    assert!(!path.exists(), "no main file was created");
    assert!(!seq_path(&path).exists(), "no counter was created");
    assert!(validate_working_copy(&path).is_err());
}

/// The directory fsync after the link fails (injected): init returns `Err`
/// with the seq file already in place, and leaves no temp file of its own. A
/// retried init is refused with "already exists" and the counter on disk is
/// still the first call's `start_seq`, which `validate_working_copy` reads
/// (the P4.4 rule: validate after any "already exists").
#[test]
fn a_retry_after_a_failed_directory_fsync_is_refused_and_the_counter_is_the_first_calls() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("main.db");
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE items (v TEXT)")
        .unwrap();

    FAIL_DIRECTORY_SYNC_AFTER_LINK.with(|fail| fail.set(true));
    assert!(
        init_working_copy(&path, 7).is_err(),
        "the directory fsync failed"
    );
    assert_eq!(read_seq(&path).unwrap(), 7, "the seq file was linked");

    match init_working_copy(&path, 7) {
        Err(SqlError::Internal(message)) => assert!(
            message.contains("already exists"),
            "a clear refusal, got {message:?}"
        ),
        other => panic!("a retry must be refused, got {other:?}"),
    }
    assert_eq!(validate_working_copy(&path).unwrap(), 7);
    let temp_files: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".seq.tmp"))
        .collect();
    assert!(temp_files.is_empty(), "temp files {temp_files:?}");
}

//! TC-1491 P4.2a: the store-master half of the SQL service.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;

use rusqlite::Connection;

use crate::sql::authority::DdlPolicy;
use crate::sql::database::{spawn_actor, GrowthPolicy};
use crate::sql::durability::{CommitSeams, DurabilityPolicy};
use crate::sql::service::SqlService;
use crate::sql::store::key::DbRef;
use crate::sql::store::local::rig::{count, insert, query, run, ProbeSink, Rig, DB};
use crate::sql::store::local::{
    hash_file, read_seq, seq_path, validate_working_copy, StoreMasterGate, PILOT_CAP_BYTES,
    WAL_BACKSTOP_BYTES, WAL_REFUSE_BYTES, WINDOW_BYTES,
};
use crate::sql::store::mode::ModeError;
use crate::sql::store::policy::SpaceAllowlist;
use crate::sql::store::shadow::metrics::NoopMetrics;
use crate::sql::store::shadow::NoticeBoard;
use crate::sql::types::SqlRequest;
use crate::sql::types::{SqlError, SqlValue};

fn plain() -> DurabilityPolicy {
    DurabilityPolicy::default()
}

fn key(rig: &Rig) -> (String, String) {
    (rig.space.to_string(), DB.to_string())
}

/// The counter and the row count of a database image copied at an instant, as
/// SQLite recovers them on the next open (a crash at that instant). The
/// counter is the image's seq file.
fn recovered(dir: &Path) -> (u64, i64) {
    let main = dir.join("main.db");
    let rows = Connection::open(&main)
        .unwrap()
        .query_row("SELECT count(*) FROM items", [], |r| r.get(0))
        .unwrap();
    (read_seq(&main).unwrap(), rows)
}

/// Copy the main file, the WAL and the seq file of `main` into `dir`, the way
/// a crash at this instant leaves them.
fn crash_image(main: &Path, dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::copy(main, dir.join("main.db")).unwrap();
    let wal = PathBuf::from(format!("{}-wal", main.display()));
    if wal.exists() {
        std::fs::copy(&wal, dir.join("main.db-wal")).unwrap();
    }
    std::fs::copy(seq_path(main), dir.join("main.db.seq")).unwrap();
}

type Images = Arc<Mutex<Vec<(&'static str, PathBuf)>>>;

/// A policy whose two commit seams take a crash image each: `before` runs
/// after the write's statements and its counter bump, immediately before
/// COMMIT; `after` runs immediately after it.
fn crash_policy(rig: &Rig, out: &Path) -> (DurabilityPolicy, Images) {
    let taken = Arc::new(Mutex::new(Vec::<(&'static str, PathBuf)>::new()));
    let n = Arc::new(AtomicUsize::new(0));
    let snapshot = |label: &'static str| {
        let main = rig.main_path();
        let (out, taken, n) = (out.to_path_buf(), taken.clone(), n.clone());
        Arc::new(move || {
            let dir = out.join(format!("{}-{label}", n.fetch_add(1, Ordering::SeqCst)));
            crash_image(&main, &dir);
            taken.lock().unwrap().push((label, dir));
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let policy = DurabilityPolicy {
        seams: CommitSeams {
            before_commit: Some(snapshot("before")),
            after_commit: Some(snapshot("after")),
            before_response: None,
        },
        ..DurabilityPolicy::default()
    };
    (policy, taken)
}

/// A rig whose working copy is a crash image: the main file, WAL and seq file
/// are put in place as they were, nothing else (no shm, no hydration).
async fn rig_from_image(name: &str, image: &Path) -> Rig {
    let rig = Rig::new(name).await;
    let main = rig.main_path();
    std::fs::create_dir_all(main.parent().unwrap()).unwrap();
    std::fs::copy(image.join("main.db"), &main).unwrap();
    if image.join("main.db-wal").exists() {
        std::fs::copy(image.join("main.db-wal"), rig.wal_path()).unwrap();
    }
    std::fs::copy(image.join("main.db.seq"), seq_path(&main)).unwrap();
    rig.make_store_master().await;
    rig
}

#[tokio::test]
async fn every_write_counts_once_and_a_read_does_not() {
    let rig = Rig::new("seq-counts").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let sink = Arc::new(ProbeSink::default());
    let service = rig.service(sink.clone(), plain());

    insert(&service, &rig.space, "a").await.unwrap();
    insert(&service, &rig.space, "b").await.unwrap();
    assert_eq!(count(&service, &rig.space).await, 2);
    insert(&service, &rig.space, "c").await.unwrap();

    let seqs: Vec<i64> = sink.notices().iter().map(|n| n.seq).collect();
    assert_eq!(
        seqs,
        [11, 12, 13],
        "one notice per write, none for the read"
    );
    assert_eq!(validate_working_copy(&rig.main_path()).unwrap(), 13);
}

#[tokio::test]
async fn a_rejected_write_leaves_the_counter_and_the_data_alone() {
    let rig = Rig::new("seq-rollback").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let sink = Arc::new(ProbeSink::default());
    let service = rig.service(sink.clone(), plain());

    insert(&service, &rig.space, "a").await.unwrap();
    // NOT NULL violation: the statement fails, the transaction rolls back.
    assert!(
        run(&service, &rig.space, "INSERT INTO items (v) VALUES (NULL)")
            .await
            .is_err()
    );
    // A batch whose last statement fails undoes the ones before it too.
    assert!(run(
        &service,
        &rig.space,
        "INSERT INTO items (v) VALUES ('x'); INSERT INTO items (v) VALUES (NULL)"
    )
    .await
    .is_err());

    assert_eq!(count(&service, &rig.space).await, 1);
    assert_eq!(validate_working_copy(&rig.main_path()).unwrap(), 11);
    insert(&service, &rig.space, "b").await.unwrap();
    assert_eq!(
        sink.notices().last().map(|n| n.seq),
        Some(12),
        "the failed writes consumed no seq"
    );
}

#[tokio::test]
async fn a_restart_continues_the_counter_and_never_reissues_a_seq() {
    let rig = Rig::new("seq-restart").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let first = Arc::new(ProbeSink::default());
    {
        let service = rig.service(first.clone(), plain());
        for v in ["a", "b", "c"] {
            insert(&service, &rig.space, v).await.unwrap();
        }
    }
    // A new service on the same directory: new actor, new registry, nothing
    // carried in memory (the process died).
    let second = Arc::new(ProbeSink::default());
    let service = rig.service(second.clone(), plain());
    assert_eq!(
        count(&service, &rig.space).await,
        3,
        "acknowledged writes are all there"
    );
    insert(&service, &rig.space, "d").await.unwrap();

    let mut all: Vec<i64> = first.notices().iter().map(|n| n.seq).collect();
    all.extend(second.notices().iter().map(|n| n.seq));
    assert_eq!(all, [11, 12, 13, 14], "contiguous, each seq issued once");
}

#[tokio::test]
async fn the_counter_is_bumped_and_on_disk_before_its_write_commits() {
    // (1) The order. At the before-commit seam the seq file already holds the
    // write's number while the write is not yet in the database; at the
    // after-commit seam both are. The fsync itself is a `sync_data` in
    // `bump_seq` (read from the code, not observable from here).
    let rig = Rig::new("seq-order").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;

    let seen = Arc::new(Mutex::new(Vec::<(&'static str, u64)>::new()));
    let probe = |label: &'static str| {
        let (main, seen) = (rig.main_path(), seen.clone());
        Arc::new(move || {
            let rows: i64 = Connection::open(&main)
                .unwrap()
                .query_row("SELECT count(*) FROM items", [], |r| r.get(0))
                .unwrap();
            seen.lock()
                .unwrap()
                .push((label, read_seq(&main).unwrap() * 1000 + rows as u64));
        }) as Arc<dyn Fn() + Send + Sync>
    };
    let policy = DurabilityPolicy {
        seams: CommitSeams {
            before_commit: Some(probe("before")),
            after_commit: Some(probe("after")),
            before_response: None,
        },
        ..DurabilityPolicy::default()
    };
    let service = rig.service(Arc::new(ProbeSink::default()), policy);
    for v in ["a", "b"] {
        insert(&service, &rig.space, v).await.unwrap();
    }
    // counter * 1000 + rows visible to another connection
    assert_eq!(
        *seen.lock().unwrap(),
        [
            ("before", 11_000), // bumped to 11, no row yet
            ("after", 11_001),  // committed
            ("before", 12_001),
            ("after", 12_002),
        ]
    );
}

#[tokio::test]
async fn a_crash_after_the_bump_and_before_the_write_commits_leaves_a_gap_and_no_reuse() {
    let rig = Rig::new("seq-crash-gap").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let out = tempfile::tempdir().unwrap();
    let (policy, taken) = crash_policy(&rig, out.path());
    let service = rig.service(Arc::new(ProbeSink::default()), policy);
    for v in ["a", "b", "c"] {
        insert(&service, &rig.space, v).await.unwrap();
    }
    assert_eq!(count(&service, &rig.space).await, 3);

    let taken = taken.lock().unwrap().clone();
    assert_eq!(
        taken.len(),
        6,
        "a before and an after per write, none for the read"
    );
    let before: Vec<&PathBuf> = taken
        .iter()
        .filter(|(l, _)| *l == "before")
        .map(|(_, d)| d)
        .collect();
    for (i, dir) in before.iter().enumerate() {
        let write = i as u64 + 1;
        // The write is not there; its number already is: one ahead, a gap.
        assert_eq!(
            recovered(dir),
            (10 + write, write as i64 - 1),
            "crash before commit {write}"
        );
    }

    // Restart on the second crash image (rows a; counter already at 12). The
    // next write must not be numbered 12: that number was taken by the write
    // that never committed. It gets 13.
    let restarted = rig_from_image("seq-crash-gap-restart", before[1]).await;
    let sink = Arc::new(ProbeSink::default());
    let service = restarted.service(sink.clone(), plain());
    assert_eq!(count(&service, &restarted.space).await, 1);
    insert(&service, &restarted.space, "next").await.unwrap();
    assert_eq!(sink.notices().last().unwrap().seq, 13, "12 is not reissued");
    assert_eq!(count(&service, &restarted.space).await, 2);
    assert_eq!(validate_working_copy(&restarted.main_path()).unwrap(), 13);
}

#[tokio::test]
async fn a_crash_after_the_commit_has_the_data_and_its_counter_together() {
    let rig = Rig::new("seq-crash-after").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let out = tempfile::tempdir().unwrap();
    let (policy, taken) = crash_policy(&rig, out.path());
    let service = rig.service(Arc::new(ProbeSink::default()), policy);
    for v in ["a", "b", "c"] {
        insert(&service, &rig.space, v).await.unwrap();
    }
    let after: Vec<PathBuf> = taken
        .lock()
        .unwrap()
        .iter()
        .filter(|(l, _)| *l == "after")
        .map(|(_, d)| d.clone())
        .collect();
    assert_eq!(after.len(), 3);
    for (i, dir) in after.iter().enumerate() {
        let write = i as u64 + 1;
        assert_eq!(
            recovered(dir),
            (10 + write, write as i64),
            "crash after commit {write}"
        );
    }
    // And a restart on one of them continues from its counter.
    let restarted = rig_from_image("seq-crash-after-restart", &after[1]).await;
    let sink = Arc::new(ProbeSink::default());
    let service = restarted.service(sink.clone(), plain());
    insert(&service, &restarted.space, "next").await.unwrap();
    assert_eq!(sink.notices().last().unwrap().seq, 13);
    assert_eq!(count(&service, &restarted.space).await, 3);
}

#[tokio::test]
async fn a_crash_in_the_middle_of_a_write_leaves_the_data_as_it_was_and_no_reuse() {
    let rig = Rig::new("seq-crash-mid").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let out = tempfile::tempdir().unwrap();
    let (policy, taken) = crash_policy(&rig, out.path());
    let service = rig.service(Arc::new(ProbeSink::default()), policy);
    insert(&service, &rig.space, "small").await.unwrap();

    // A write larger than the page cache: its pages are in the WAL before it
    // commits, so the image taken just before COMMIT holds uncommitted frames
    // (a crash in the middle of the write).
    run(
        &service,
        &rig.space,
        "INSERT INTO items (v) VALUES (zeroblob(6000000))",
    )
    .await
    .unwrap();
    let taken = taken.lock().unwrap().clone();
    let (label, mid) = &taken[2];
    assert_eq!(*label, "before");
    let committed_wal = std::fs::metadata(taken[1].1.join("main.db-wal"))
        .unwrap()
        .len();
    let mid_wal = std::fs::metadata(mid.join("main.db-wal")).unwrap().len();
    assert!(
        mid_wal > committed_wal + 1_000_000,
        "the write's pages are already in the WAL ({mid_wal} vs {committed_wal})"
    );
    // Recovery drops the uncommitted frames: one row, the counter one ahead.
    assert_eq!(recovered(mid), (12, 1));

    // A restart numbers its next write 13.
    let restarted = rig_from_image("seq-crash-mid-restart", mid).await;
    let sink = Arc::new(ProbeSink::default());
    let service = restarted.service(sink.clone(), plain());
    insert(&service, &restarted.space, "next").await.unwrap();
    assert_eq!(sink.notices().last().unwrap().seq, 13);
    assert_eq!(count(&service, &restarted.space).await, 2);
}

#[tokio::test]
async fn the_seq_a_notice_carries_is_read_from_the_seq_file() {
    // (2) The revision handed on comes from the file, not from memory: a
    // counter moved from outside is what the next notice reports.
    let rig = Rig::new("seq-from-file").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let sink = Arc::new(ProbeSink::default());
    let service = rig.service(sink.clone(), plain());
    insert(&service, &rig.space, "a").await.unwrap();
    assert_eq!(sink.notices().last().unwrap().seq, 11);

    for _ in 0..3 {
        crate::sql::store::local::bump_seq(&rig.main_path()).unwrap();
    }
    insert(&service, &rig.space, "b").await.unwrap();
    assert_eq!(sink.notices().last().unwrap().seq, 15);
}

#[tokio::test]
async fn closing_an_idle_actor_neither_checkpoints_nor_deletes_the_wal() {
    let rig = Rig::new("idle-exit").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());
    insert(&service, &rig.space, "a").await.unwrap();
    insert(&service, &rig.space, "b").await.unwrap();

    let main_before = hash_file(&rig.main_path()).unwrap();
    let wal_before = std::fs::read(rig.wal_path()).unwrap();
    assert!(!wal_before.is_empty());
    // What the idle timeout does: the actor leaves and drops its connection.
    let handle = service.databases.get(&key(&rig)).unwrap().clone();
    handle.shutdown().await.unwrap();

    assert_eq!(hash_file(&rig.main_path()).unwrap(), main_before);
    assert_eq!(std::fs::read(rig.wal_path()).unwrap(), wal_before);
    // The next request restarts the actor on the same files.
    assert_eq!(count(&service, &rig.space).await, 2);
}

#[tokio::test]
async fn a_store_master_database_never_touches_the_postgres_artifact() {
    let rig = Rig::new("no-pg").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());
    insert(&service, &rig.space, "a").await.unwrap();
    assert_eq!(count(&service, &rig.space).await, 1);
    service.export(&rig.space, DB).await.unwrap();

    use crate::database_artifacts::DatabaseArtifactRepository;
    assert!(rig
        .repo
        .load_meta("sql", &rig.space.to_string(), DB)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn a_missing_working_copy_is_unavailable_and_is_never_created() {
    let rig = Rig::new("no-file").await;
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());
    assert!(matches!(
        insert(&service, &rig.space, "a").await,
        Err(SqlError::Unavailable)
    ));
    assert!(matches!(
        query(&service, &rig.space, "SELECT 1").await,
        Err(SqlError::Unavailable)
    ));
    assert!(!rig.main_path().exists(), "nothing was created or hydrated");
}

#[tokio::test]
async fn a_file_without_the_counter_is_refused_not_adopted() {
    let rig = Rig::new("no-counter").await;
    let path = rig.main_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    Connection::open(&path)
        .unwrap()
        .execute_batch("CREATE TABLE items (v TEXT NOT NULL)")
        .unwrap();
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());
    assert!(insert(&service, &rig.space, "a").await.is_err());
}

#[tokio::test]
async fn a_user_table_with_the_old_counters_name_is_an_ordinary_table() {
    // The counter is not in the database, so no name is the node's.
    let rig = Rig::new("no-reserved").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let sink = Arc::new(ProbeSink::default());
    let service = rig.service(sink.clone(), plain());
    insert(&service, &rig.space, "a").await.unwrap();

    run(
        &service,
        &rig.space,
        "CREATE TABLE tinycloud_internal_store_seq (id INTEGER PRIMARY KEY, seq INTEGER)",
    )
    .await
    .unwrap();
    run(
        &service,
        &rig.space,
        "INSERT INTO tinycloud_internal_store_seq VALUES (1, 99)",
    )
    .await
    .unwrap();
    run(
        &service,
        &rig.space,
        "UPDATE tinycloud_internal_store_seq SET seq = 1000",
    )
    .await
    .unwrap();
    // Three more writes, counted by the file and by nothing the user holds.
    assert_eq!(validate_working_copy(&rig.main_path()).unwrap(), 14);
    assert_eq!(sink.notices().last().unwrap().seq, 14);
}

#[tokio::test]
async fn user_sql_cannot_reach_or_replace_the_seq_file() {
    // The seq file is not a database the user can open or write: ATTACH and
    // VACUUM INTO (the two ways SQL names a file) are refused, whatever the
    // ability, and the file is byte for byte as it was.
    let rig = Rig::new("seq-unreachable").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());
    insert(&service, &rig.space, "a").await.unwrap();
    let seq = seq_path(&rig.main_path());
    let before = std::fs::read(&seq).unwrap();
    let name = seq.display();
    let relative = seq.file_name().unwrap().to_string_lossy().to_string();

    for sql in [
        format!("ATTACH DATABASE '{name}' AS s"),
        format!("ATTACH '{relative}' AS s"),
        format!("VACUUM INTO '{name}'"),
        format!("VACUUM main INTO '{name}'"),
        format!("VACUUM INTO '{relative}'"),
    ] {
        let result = run(&service, &rig.space, &sql).await;
        let queried = query(&service, &rig.space, &sql).await;
        assert!(
            result.is_err() && queried.is_err(),
            "{sql}: {result:?} {queried:?}"
        );
        assert_eq!(std::fs::read(&seq).unwrap(), before, "{sql}");
    }
    insert(&service, &rig.space, "b").await.unwrap();
    assert_eq!(read_seq(&rig.main_path()).unwrap(), 12);
}

#[tokio::test]
async fn no_database_or_space_name_makes_a_path_that_is_another_ones_seq_file() {
    // A database's seq file is `<name>.db.seq`; every file of a database is
    // `<name>.db`, `<name>.db-wal`, `<name>.db-shm` or `<name>.db.seq`, so
    // these four never meet across names, however the names are built.
    let rig = Rig::new("seq-names").await;
    let names = [
        "x",
        "x.db",
        "x.db.seq",
        "x.seq",
        "x-wal",
        "x.db-wal",
        "x.db-shm",
        "x.db.db",
        "x.db.db.seq",
        "main",
        "main.db",
    ];
    let service = rig.service(Arc::new(ProbeSink::default()), plain());
    let mut seen = std::collections::HashMap::new();
    for name in names {
        let (main, wal) = service.local_paths(&rig.space, name);
        let shm = PathBuf::from(format!("{}-shm", main.display()));
        let seq = seq_path(&main);
        for (kind, path) in [("main", main), ("wal", wal), ("shm", shm), ("seq", seq)] {
            if let Some(other) = seen.insert(path.clone(), format!("{name} {kind}")) {
                panic!("{} is both {other} and {name} {kind}", path.display());
            }
        }
        // And always beside its database, never in another directory.
        assert_eq!(
            seq_path(&service.local_paths(&rig.space, name).0).parent(),
            service.local_paths(&rig.space, name).0.parent()
        );
    }
    assert_eq!(seen.len(), names.len() * 4);
}

#[tokio::test]
async fn a_missing_or_damaged_seq_file_refuses_every_write_and_is_never_reset() {
    // The two files disagree about whether the database exists: a main file
    // with no usable seq file. Every write is refused and rolled back, a
    // cold start refuses to open the database at all, and nothing is
    // recreated, repaired or reset to a number: the file stays as found.
    let rig = Rig::new("seq-damaged").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());
    insert(&service, &rig.space, "a").await.unwrap();
    let seq = seq_path(&rig.main_path());
    let good = std::fs::read(&seq).unwrap();

    for damage in [Some(vec![0u8; 5]), Some(vec![0u8; 16]), None] {
        match &damage {
            Some(bytes) => std::fs::write(&seq, bytes).unwrap(),
            None => std::fs::remove_file(&seq).unwrap(),
        }
        assert!(
            insert(&service, &rig.space, "x").await.is_err(),
            "a running actor, {damage:?}"
        );
        let cold = rig.service(Arc::new(ProbeSink::default()), plain());
        assert!(
            insert(&cold, &rig.space, "x").await.is_err(),
            "cold, {damage:?}"
        );
        assert!(query(&cold, &rig.space, "SELECT count(*) FROM items")
            .await
            .is_err());
        match &damage {
            Some(bytes) => assert_eq!(&std::fs::read(&seq).unwrap(), bytes),
            None => assert!(!seq.exists(), "never recreated"),
        }
    }

    // Put the real file back: nothing was committed meanwhile, and the
    // counter carries on from where it was.
    std::fs::write(&seq, &good).unwrap();
    assert_eq!(count(&service, &rig.space).await, 1);
    insert(&service, &rig.space, "b").await.unwrap();
    assert_eq!(read_seq(&rig.main_path()).unwrap(), 12);
}

#[tokio::test]
async fn without_a_gate_or_a_mode_row_a_database_is_served_as_before() {
    use crate::database_artifacts::DatabaseArtifactRepository;

    // No gate at all (the default): the reserved prefix is an ordinary name
    // and the durable artifact is Postgres's.
    let rig = Rig::new("pg-default").await;
    let service = SqlService::new(rig.base(), 0, rig.repo.clone()).with_ddl_policy(DdlPolicy::Log);
    run(
        &service,
        &rig.space,
        "CREATE TABLE tinycloud_internal_mine (a INTEGER)",
    )
    .await
    .unwrap();
    run(
        &service,
        &rig.space,
        "INSERT INTO tinycloud_internal_mine (a) VALUES (1)",
    )
    .await
    .unwrap();
    assert!(rig
        .repo
        .load_meta("sql", &rig.space.to_string(), DB)
        .await
        .unwrap()
        .is_some());

    // A gate whose rows say nothing about this database: the same.
    let rig = Rig::new("pg-gated").await;
    let service = SqlService::new(rig.base(), 0, rig.repo.clone())
        .with_ddl_policy(DdlPolicy::Log)
        .with_store_master_gate(rig.gate());
    run(
        &service,
        &rig.space,
        "CREATE TABLE tinycloud_internal_mine (a INTEGER)",
    )
    .await
    .unwrap();
    assert!(matches!(
        query(
            &service,
            &rig.space,
            "SELECT count(*) FROM tinycloud_internal_mine"
        )
        .await
        .unwrap()[0][0],
        SqlValue::Integer(0)
    ));
    assert!(rig
        .repo
        .load_meta("sql", &rig.space.to_string(), DB)
        .await
        .unwrap()
        .is_some());
}

#[tokio::test]
async fn the_byte_window_is_reported_with_each_commit_and_marks_the_database_urgent() {
    let rig = Rig::new("window").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let board = Arc::new(NoticeBoard::new(
        SpaceAllowlist::new([rig.space.to_string()]),
        Arc::new(NoopMetrics),
    ));
    let service = rig.service(board.clone(), plain());

    insert(&service, &rig.space, "small").await.unwrap();
    assert!(
        board.take_urgent().is_empty(),
        "a small write is not urgent"
    );
    let head = board.take().remove(&key(&rig)).unwrap();
    assert_eq!(head.revision, 11);
    assert_eq!(head.cid, hash_file(&rig.main_path()).unwrap());

    // One write that carries more than the 8 MiB window into the WAL.
    let big = (WINDOW_BYTES + 1024 * 1024) as i64;
    run(
        &service,
        &rig.space,
        &format!("INSERT INTO items (v) VALUES (zeroblob({big}))"),
    )
    .await
    .unwrap();
    assert!(board.take_urgent().contains(&key(&rig)));
    assert_eq!(board.take().remove(&key(&rig)).unwrap().revision, 12);
}

#[tokio::test]
async fn a_temp_table_cannot_stand_in_for_the_counter() {
    let rig = Rig::new("temp-shadow").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let sink = Arc::new(ProbeSink::default());
    let service = rig.service(sink.clone(), plain());
    insert(&service, &rig.space, "a").await.unwrap();

    // The exact statements of the review: temp.x holds a made-up seq of 3 and
    // is renamed to the counter's name, so an unqualified lookup would find it.
    let _ = run(
        &service,
        &rig.space,
        "CREATE TEMP TABLE x(id INTEGER PRIMARY KEY, seq INTEGER)",
    )
    .await;
    let _ = run(&service, &rig.space, "INSERT INTO temp.x VALUES(1,3)").await;
    // With the counter in its own file this statement is just a rename of a
    // temp table; it is neither refused nor able to reach the counter.
    let _ = run(
        &service,
        &rig.space,
        "ALTER TABLE temp.x RENAME TO tinycloud_internal_store_seq",
    )
    .await;
    insert(&service, &rig.space, "b").await.unwrap();

    // Statements that only touch temp tables are not counted, so a notice can
    // repeat a seq; none may carry temp's 3, and the last is the second write.
    let seqs: Vec<i64> = sink.notices().iter().map(|n| n.seq).collect();
    assert!(seqs.iter().all(|s| (11..=12).contains(s)), "{seqs:?}");
    assert_eq!(
        seqs.last(),
        Some(&12),
        "the file's counter, whatever temp holds"
    );
    assert_eq!(validate_working_copy(&rig.main_path()).unwrap(), 12);
}

#[tokio::test]
async fn a_write_at_the_top_of_the_counter_is_refused_and_the_file_still_opens() {
    let rig = Rig::new("seq-top").await;
    rig.create_working_copy(i64::MAX as u64 - 1);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());

    insert(&service, &rig.space, "a").await.unwrap();
    assert!(insert(&service, &rig.space, "b").await.is_err());
    assert_eq!(
        count(&service, &rig.space).await,
        1,
        "the refused write left no row"
    );
    assert_eq!(
        validate_working_copy(&rig.main_path()).unwrap(),
        i64::MAX as u64
    );
}

#[tokio::test]
async fn a_write_is_refused_once_the_wal_holds_64_mib_and_resumes_after_a_rotation() {
    let rig = Rig::new("wal-refuse").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());

    // A reader holding an old snapshot keeps the checkpoint busy, so the
    // commit path's backstop rotation cannot truncate (and does not fail the
    // write that asked for it). Nothing else drains this WAL: no uploader.
    insert(&service, &rig.space, "first").await.unwrap();
    let reader = Connection::open(rig.main_path()).unwrap();
    reader
        .execute_batch("BEGIN; SELECT count(*) FROM items")
        .unwrap();
    let big = (WAL_REFUSE_BYTES + 1024 * 1024) as i64;
    run(
        &service,
        &rig.space,
        &format!("INSERT INTO items (v) VALUES (zeroblob({big}))"),
    )
    .await
    .unwrap();
    assert!(std::fs::metadata(rig.wal_path()).unwrap().len() >= WAL_REFUSE_BYTES);

    let refused = insert(&service, &rig.space, "more").await;
    assert!(
        matches!(refused, Err(SqlError::DiskHeadroom)),
        "{refused:?}"
    );
    assert_eq!(count(&service, &rig.space).await, 2, "reads still work");
    let refused_at = validate_working_copy(&rig.main_path()).unwrap();

    drop(reader);
    let handle = service.local_handle(&rig.space, DB).await.unwrap();
    handle.rotate().await.unwrap();
    insert(&service, &rig.space, "after").await.unwrap();
    assert_eq!(count(&service, &rig.space).await, 3);
    assert!(
        validate_working_copy(&rig.main_path()).unwrap() > refused_at,
        "the refused write did not count"
    );
}

/// A gate with a mode per database name, and a switch that makes every read
/// of it fail.
#[derive(Default)]
struct SwitchGate {
    modes: Mutex<HashMap<String, bool>>,
    down: AtomicBool,
}

impl SwitchGate {
    fn with(modes: &[(&str, bool)]) -> Arc<Self> {
        Arc::new(Self {
            modes: Mutex::new(modes.iter().map(|(n, m)| (n.to_string(), *m)).collect()),
            down: AtomicBool::new(false),
        })
    }
    fn set(&self, name: &str, mode: bool) {
        self.modes.lock().unwrap().insert(name.to_string(), mode);
    }
    fn set_down(&self, down: bool) {
        self.down.store(down, Ordering::SeqCst);
    }
}

#[async_trait]
impl StoreMasterGate for SwitchGate {
    async fn is_store_master(&self, db: &DbRef<'_>) -> Result<bool, ModeError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(ModeError::Db("the control database is down".into()));
        }
        Ok(*self.modes.lock().unwrap().get(db.db_id).unwrap_or(&false))
    }
    async fn store_master_databases(
        &self,
    ) -> Result<Vec<crate::sql::store::shadow::DbKey>, ModeError> {
        Ok(Vec::new())
    }
}

fn switched(rig: &Rig, sink: Arc<ProbeSink>, gate: Arc<SwitchGate>) -> SqlService {
    SqlService::new(rig.base(), 0, rig.repo.clone())
        .with_ddl_policy(DdlPolicy::Log)
        .with_shadow(sink)
        .with_store_master_gate(gate)
}

async fn run_on(service: &SqlService, rig: &Rig, db: &str, sql: &str) -> Result<(), SqlError> {
    service
        .execute(
            &rig.space,
            db,
            SqlRequest::Execute {
                sql: sql.to_owned(),
                params: vec![],
                schema: None,
            },
            None,
            "tinycloud.sql/admin".into(),
        )
        .await
        .map(|_| ())
}

#[tokio::test]
async fn a_write_path_truncates_the_wal_of_a_database_nobody_uploads() {
    // No uploader and no allowlist entry: nothing but the commit path can
    // shrink this WAL. The checkpoint ends past the pilot cap, so the same
    // run is the over-the-cap case: such a database is not published, and
    // must not take the disk either.
    let rig = Rig::new("backstop").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let sink = Arc::new(ProbeSink::default());
    let service = rig.service(sink.clone(), plain());

    let blob = 25 * 1024 * 1024;
    let mut max_wal = 0;
    for n in 1..=4 {
        run(
            &service,
            &rig.space,
            &format!("INSERT INTO items (v) VALUES (zeroblob({blob}))"),
        )
        .await
        .unwrap();
        let wal = std::fs::metadata(rig.wal_path()).map_or(0, |m| m.len());
        max_wal = max_wal.max(wal);
        if n % 2 == 0 {
            assert_eq!(wal, 0, "write {n}: the WAL was folded in and truncated");
        } else {
            assert!(wal > 0 && wal < WAL_BACKSTOP_BYTES, "write {n}: {wal}");
        }
    }
    assert!(max_wal < WAL_BACKSTOP_BYTES);
    let main = std::fs::metadata(rig.main_path()).unwrap().len();
    assert!(main > PILOT_CAP_BYTES, "over the cap: {main}");
    assert_eq!(count(&service, &rig.space).await, 4, "nothing was lost");
    // Two writes per rotation: 10 -> 11, 12, rotation 13 -> 14, 15, 16.
    assert_eq!(validate_working_copy(&rig.main_path()).unwrap(), 16);
    // What the uploader is told follows the rotation, not the stale WAL.
    let last = sink.notices().pop().unwrap();
    assert_eq!((last.seq, last.ahead_bytes), (16, main));
}

#[tokio::test]
async fn a_database_with_a_live_actor_is_still_served_when_the_mode_cannot_be_read() {
    let rig = Rig::new("gate-down").await;
    rig.create_working_copy(10);
    let gate = SwitchGate::with(&[(DB, true), ("pg", false)]);
    let service = switched(&rig, Arc::new(ProbeSink::default()), gate.clone());

    // One database of each mode, both warm.
    insert(&service, &rig.space, "a").await.unwrap();
    run_on(&service, &rig, "pg", "CREATE TABLE t (a INTEGER)")
        .await
        .unwrap();
    run_on(&service, &rig, "pg", "INSERT INTO t (a) VALUES (1)")
        .await
        .unwrap();

    gate.set_down(true);
    insert(&service, &rig.space, "b").await.unwrap();
    assert_eq!(count(&service, &rig.space).await, 2);
    run_on(&service, &rig, "pg", "INSERT INTO t (a) VALUES (2)")
        .await
        .unwrap();

    // A database with no actor would have to be opened without knowing its
    // mode: refused, retryable, and nothing is created for it.
    let cold = run_on(&service, &rig, "cold", "CREATE TABLE t (a INTEGER)").await;
    assert!(matches!(cold, Err(SqlError::Unavailable)), "{cold:?}");
    assert!(!rig.main_path().with_file_name("cold.db").exists());

    gate.set_down(false);
    run_on(&service, &rig, "cold", "CREATE TABLE t (a INTEGER)")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_publication_command_on_a_store_master_database_is_refused_not_saved_to_postgres() {
    use crate::database_artifacts::DatabaseArtifactRepository;
    use crate::sql::publication::DATABASE as PUBLICATION;

    let rig = Rig::new("publication").await;
    let gate = SwitchGate::with(&[(PUBLICATION, true)]);
    let service = switched(&rig, Arc::new(ProbeSink::default()), gate);
    let space = rig.space.to_string();

    for operation in ["activate", "reserve", "stage", "publish", "delete", "purge"] {
        let refused = service
            .meeting_publication(
                &rig.space,
                serde_json::json!({"contractVersion": 3, "operation": operation}),
            )
            .await;
        assert!(
            matches!(refused, Err(SqlError::InvalidStatement(_))),
            "{operation}: {refused:?}"
        );
    }
    assert!(
        rig.repo
            .load_meta("sql", &space, PUBLICATION)
            .await
            .unwrap()
            .is_none(),
        "no artifact was written for it"
    );
    assert!(
        !service
            .databases
            .contains_key(&(space, PUBLICATION.to_string())),
        "no actor was opened for it"
    );
}

#[tokio::test]
async fn a_purge_deletes_the_working_copy_and_everything_the_uploader_remembers_of_it() {
    let rig = Rig::new("purge").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());
    insert(&service, &rig.space, "a").await.unwrap();
    let space = rig.space.to_string();
    assert!(service.local_files().knows_space(&space));
    assert!(service.databases.contains_key(&key(&rig)));

    service.drain_and_evict_space(&rig.space).await.unwrap();

    assert!(!rig.main_path().exists() && !rig.wal_path().exists());
    assert!(!service.databases.contains_key(&key(&rig)), "actor closed");
    assert!(
        !service.local_files().knows_space(&space),
        "a space created later under this id inherits no hash, mark or position"
    );
    // Nothing brings it back: a request is unavailable and creates no file.
    let after = insert(&service, &rig.space, "b").await;
    assert!(matches!(after, Err(SqlError::Unavailable)), "{after:?}");
    assert!(!rig.main_path().exists());
}

#[tokio::test]
async fn replacing_an_actor_that_checkpoints_on_close_moves_the_counter_past_what_it_changed() {
    let rig = Rig::new("replace").await;
    rig.create_working_copy(10);
    let gate = SwitchGate::with(&[(DB, false)]);
    let sink = Arc::new(ProbeSink::default());
    let service = switched(&rig, sink.clone(), gate.clone());

    // The cutover left the counter in the file, but an actor opened while
    // Postgres was master is still serving it (P4.4 closes it first; this is
    // the order it must not be able to get wrong). It writes, and on close it
    // will fold its WAL into the main file with no counter bump.
    let old = spawn_actor(
        rig.space.to_string(),
        DB.to_string(),
        rig.base(),
        0,
        service.databases.clone(),
    );
    service.databases.insert(key(&rig), old.clone());
    old.execute_authorized(
        SqlRequest::Execute {
            sql: "INSERT INTO items (v) VALUES ('old')".into(),
            params: vec![],
            schema: None,
        },
        None,
        "tinycloud.sql/admin".into(),
        GrowthPolicy::Allow,
    )
    .await
    .unwrap();
    assert_eq!(read_seq(&rig.main_path()).unwrap(), 10, "it does not count");

    gate.set(DB, true);
    insert(&service, &rig.space, "new").await.unwrap();

    assert_eq!(count(&service, &rig.space).await, 2, "nothing was lost");
    assert!(service.databases.get(&key(&rig)).unwrap().is_store_master());
    // 10: the old actor's close changed the file; 11: the settle that
    // accounts for it; 12: the write.
    assert_eq!(validate_working_copy(&rig.main_path()).unwrap(), 12);
    assert_eq!(sink.notices().last().unwrap().seq, 12);
    let wal = std::fs::metadata(rig.wal_path()).map_or(0, |m| m.len());
    assert!(wal > 0, "the write after the settle is in the WAL");
}

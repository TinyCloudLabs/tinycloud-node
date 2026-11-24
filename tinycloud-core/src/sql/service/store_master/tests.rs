//! TC-1491 P4.2a: the store-master half of the SQL service.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use rusqlite::Connection;

use crate::sql::authority::DdlPolicy;
use crate::sql::durability::{CommitSeams, DurabilityPolicy};
use crate::sql::service::SqlService;
use crate::sql::store::local::rig::{count, insert, query, run, ProbeSink, Rig, DB};
use crate::sql::store::local::{hash_file, read_seq, validate_working_copy, WINDOW_BYTES};
use crate::sql::store::policy::SpaceAllowlist;
use crate::sql::store::shadow::metrics::NoopMetrics;
use crate::sql::store::shadow::NoticeBoard;
use crate::sql::types::{SqlError, SqlValue};

fn plain() -> DurabilityPolicy {
    DurabilityPolicy::default()
}

fn key(rig: &Rig) -> (String, String) {
    (rig.space.to_string(), DB.to_string())
}

/// The counter and the row count of a database file copied at an instant, as
/// SQLite recovers them on the next open (a crash at that instant).
fn recovered(dir: &Path) -> (u64, i64) {
    let conn = Connection::open(dir.join("main.db")).unwrap();
    let seq = read_seq(&conn).unwrap();
    let rows = conn
        .query_row("SELECT count(*) FROM items", [], |r| r.get(0))
        .unwrap();
    (seq, rows)
}

#[tokio::test]
async fn every_write_counts_once_in_its_own_transaction_and_a_read_does_not() {
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
async fn a_crash_at_any_commit_boundary_never_splits_the_counter_from_its_data() {
    let rig = Rig::new("seq-crash").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;

    let out = tempfile::tempdir().unwrap();
    let taken = Arc::new(Mutex::new(Vec::<(&'static str, PathBuf)>::new()));
    let n = Arc::new(AtomicUsize::new(0));
    let snapshot = |label: &'static str| {
        let (main, wal) = (rig.main_path(), rig.wal_path());
        let (out, taken, n) = (out.path().to_path_buf(), taken.clone(), n.clone());
        Arc::new(move || {
            let dir = out.join(format!("{}-{label}", n.fetch_add(1, Ordering::SeqCst)));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::copy(&main, dir.join("main.db")).unwrap();
            if wal.exists() {
                std::fs::copy(&wal, dir.join("main.db-wal")).unwrap();
            }
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
    for (i, (label, dir)) in taken.iter().enumerate() {
        let write = (i / 2) as u64 + 1;
        let (seq, rows) = recovered(dir);
        assert_eq!(
            seq as i64 - 10,
            rows,
            "{label} write {write}: the counter and the rows agree"
        );
        let expected = if *label == "before" { write - 1 } else { write };
        assert_eq!(seq, 10 + expected, "{label} write {write}");
    }
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
async fn user_sql_cannot_read_change_or_drop_the_counter_even_as_admin() {
    let rig = Rig::new("hidden").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), plain());
    insert(&service, &rig.space, "a").await.unwrap();

    for sql in [
        "SELECT * FROM tinycloud_internal_store_seq",
        "SELECT seq FROM TINYCLOUD_INTERNAL_STORE_SEQ",
        "SELECT count(*) FROM main.tinycloud_internal_store_seq",
        "PRAGMA table_info(tinycloud_internal_store_seq)",
    ] {
        assert!(query(&service, &rig.space, sql).await.is_err(), "{sql}");
    }
    for sql in [
        "UPDATE tinycloud_internal_store_seq SET seq = 1",
        "UPDATE tinycloud_internal_store_seq SET seq = seq + 100",
        "DELETE FROM tinycloud_internal_store_seq",
        "INSERT INTO tinycloud_internal_store_seq (id, seq) VALUES (2, 5)",
        "DROP TABLE tinycloud_internal_store_seq",
        "ALTER TABLE tinycloud_internal_store_seq RENAME TO elsewhere",
        "CREATE TABLE tinycloud_internal_mine (a INTEGER)",
        "CREATE INDEX tinycloud_internal_ix ON items (v)",
    ] {
        assert!(run(&service, &rig.space, sql).await.is_err(), "{sql}");
    }
    // A trigger that reaches for the counter is refused when it is created or
    // when it fires: either way the counter is not changed by it.
    let _ = run(
        &service,
        &rig.space,
        "CREATE TRIGGER sneaky AFTER INSERT ON items BEGIN \
         UPDATE tinycloud_internal_store_seq SET seq = 99; END",
    )
    .await;
    let _ = insert(&service, &rig.space, "b").await;

    let seq = validate_working_copy(&rig.main_path()).unwrap();
    assert!(
        (11..=12).contains(&seq),
        "only real writes moved the counter, it is {seq}"
    );
    assert_ne!(seq, 99);
    // Ordinary user tables are untouched by the rule.
    assert!(query(&service, &rig.space, "SELECT count(*) FROM items")
        .await
        .is_ok());
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

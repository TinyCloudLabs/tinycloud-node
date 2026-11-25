//! TC-1491 P4.2a: the local-file source, end to end through the real
//! scheduler, the in-memory store and the restore check.

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use super::*;
use crate::sql::durability::{CommitSeams, DurabilityPolicy};
use crate::sql::store::key::{DbRef, Lineage, ObjectKey};
use crate::sql::store::local::rig::{count, insert, run, ProbeSink, Rig, DB};
use crate::sql::store::local::{
    hash_file, PILOT_CAP_BYTES, WAL_REFUSE_BYTES, WINDOW, WINDOW_BYTES,
};
use crate::sql::store::manifest::{DbSqlManifest, Frontier, SqlManifest};
use crate::sql::store::memory::MemorySqlObjectStore;
use crate::sql::store::object::{
    ObjectMeta, ObjectRange, PutOutcome, SqlObjectStore, SqlStoreError,
};
use crate::sql::store::policy::SpaceAllowlist;
use crate::sql::store::shadow::budget::DiskBudget;
use crate::sql::store::shadow::machine::{
    plan_delta, step, BlockReason, Command, DbMachine, Event, Phase, Policy,
};
use crate::sql::store::shadow::metrics::{
    NoopMetrics, NoticeResult, PublishResult, RestoreResult, ShadowMetrics, UploadResult,
};
use crate::sql::store::shadow::restore::{check_database, RestoreDeps};
use crate::sql::store::shadow::scheduler::{spawn, SchedulerConfig, SchedulerHandle, ShadowDeps};
use crate::sql::store::shadow::NoticeBoard;
use crate::storage::ByteRangeSpec;

fn config(interval: Duration) -> SchedulerConfig {
    SchedulerConfig {
        policy: Policy {
            interval,
            backoff_base: Duration::from_millis(10),
            backoff_max: Duration::from_millis(50),
        },
        tick: Duration::from_millis(5),
        scan_every: Duration::from_secs(3600),
        scan_page: 2,
        delta_min_wal_bytes: 0,
        ..SchedulerConfig::default()
    }
}

fn board(rig: &Rig) -> Arc<NoticeBoard> {
    Arc::new(NoticeBoard::new(
        SpaceAllowlist::new([rig.space.to_string()]),
        Arc::new(NoopMetrics),
    ))
}

fn start(
    rig: &Rig,
    source: Arc<LocalFileSource>,
    store: Arc<dyn SqlObjectStore>,
    board: Arc<NoticeBoard>,
    scratch: &Path,
    interval: Duration,
) -> SchedulerHandle {
    spawn(
        ShadowDeps {
            control: rig.control.clone(),
            manifest: Arc::new(DbSqlManifest::new(rig.control.clone())),
            store,
            source,
            disk: DiskBudget::new(scratch, 512 * 1024 * 1024),
            board,
            metrics: Arc::new(NoopMetrics),
        },
        config(interval),
    )
}

fn source(rig: &Rig, service: &SqlService) -> Arc<LocalFileSource> {
    Arc::new(LocalFileSource::new(service.clone(), rig.gate()))
}

async fn frontier_at(rig: &Rig, seq: u64) -> Frontier {
    let manifest = DbSqlManifest::new(rig.control.clone());
    let space = rig.space.to_string();
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let db = DbRef {
                space: &space,
                db_id: DB,
            };
            if let Some(f) = manifest.current(&db).await.unwrap() {
                if f.last_seq >= seq {
                    return f;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the frontier never reached seq {seq}"))
}

async fn frontier_now(rig: &Rig) -> Option<Frontier> {
    let space = rig.space.to_string();
    DbSqlManifest::new(rig.control.clone())
        .current(&DbRef {
            space: &space,
            db_id: DB,
        })
        .await
        .unwrap()
}

/// The restore of the published frontier equals the local file at the same
/// revision (the restore check, with the local file where Postgres was).
async fn assert_restore_equals_local(
    rig: &Rig,
    source: Arc<LocalFileSource>,
    store: Arc<dyn SqlObjectStore>,
    scratch: &Path,
) {
    let space = rig.space.to_string();
    let report = check_database(
        &RestoreDeps {
            control: rig.control.clone(),
            store,
            source,
            disk: DiskBudget::new(scratch, 512 * 1024 * 1024),
            metrics: Arc::new(NoopMetrics),
        },
        &DbRef {
            space: &space,
            db_id: DB,
        },
    )
    .await;
    assert_eq!(report.result, RestoreResult::Ok, "{report:?}");
}

// ---- the 60 s and 8 MiB triggers -----------------------------------------

fn head(revision: i64, cid: &str) -> Head {
    Head {
        revision,
        cid: cid.into(),
    }
}

fn uploads(commands: &[Command]) -> usize {
    commands
        .iter()
        .filter(|c| matches!(c, Command::Upload { .. }))
        .count()
}

#[test]
fn the_default_upload_interval_is_the_60_second_window() {
    assert_eq!(Policy::default().interval, WINDOW);
}

#[test]
fn a_dirty_database_uploads_at_60_seconds_and_not_before() {
    let policy = Policy::default();
    let t0 = Instant::now();
    let mut m = DbMachine::new(None);
    step(&mut m, Event::Notified(head(11, "a")), t0, &policy);
    assert!(matches!(m.phase, Phase::Dirty { .. }));
    let early = step(
        &mut m,
        Event::Tick { permit: true },
        t0 + Duration::from_secs(59),
        &policy,
    );
    assert_eq!(uploads(&early), 0, "59 s: not yet");
    let due = step(
        &mut m,
        Event::Tick { permit: true },
        t0 + Duration::from_secs(60),
        &policy,
    );
    assert_eq!(uploads(&due), 1, "60 s: due");
}

#[test]
fn reaching_the_byte_window_makes_a_dirty_database_due_at_once() {
    let policy = Policy::default();
    let t0 = Instant::now();
    let mut m = DbMachine::new(None);
    step(&mut m, Event::Notified(head(11, "a")), t0, &policy);
    m.expedite(t0, &policy);
    let out = step(&mut m, Event::Tick { permit: true }, t0, &policy);
    assert_eq!(
        uploads(&out),
        1,
        "8 MiB ahead: no waiting for the 60 s tick"
    );
}

#[test]
fn the_byte_window_does_not_lift_a_block_or_a_backoff() {
    let policy = Policy::default();
    let t0 = Instant::now();

    let mut blocked = DbMachine::new(None);
    blocked.phase = Phase::Blocked {
        reason: BlockReason::Regressed,
    };
    blocked.expedite(t0, &policy);
    assert_eq!(
        blocked.phase,
        Phase::Blocked {
            reason: BlockReason::Regressed
        }
    );

    let until = t0 + Duration::from_secs(30);
    let mut backing_off = DbMachine::new(None);
    backing_off.phase = Phase::Backoff { until, attempts: 2 };
    backing_off.expedite(t0, &policy);
    assert_eq!(backing_off.phase, Phase::Backoff { until, attempts: 2 });

    let mut clean = DbMachine::new(None);
    clean.expedite(t0, &policy);
    assert_eq!(clean.phase, Phase::Clean);
}

#[tokio::test]
async fn the_8_mib_trigger_uploads_now_and_the_60_s_window_holds_a_small_write_back() {
    let rig = Rig::new("trigger-e2e").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let scratch = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySqlObjectStore::default());
    // The interval is an hour: only the byte window can make an upload due.
    let uploader = start(
        &rig,
        source(&rig, &service),
        store.clone(),
        board,
        scratch.path(),
        Duration::from_secs(3600),
    );

    insert(&service, &rig.space, "small").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        frontier_now(&rig).await.is_none(),
        "a small write waits for the window"
    );

    run(
        &service,
        &rig.space,
        &format!(
            "INSERT INTO items (v) VALUES (zeroblob({}))",
            WINDOW_BYTES + 1024 * 1024
        ),
    )
    .await
    .unwrap();
    // 8 MiB ahead: published without waiting. The WAL passed the window, so
    // the uploader rotated first: one more revision (13), a new checkpoint.
    let frontier = frontier_at(&rig, 13).await;
    assert_eq!(frontier.last_seq, 13);

    insert(&service, &rig.space, "after").await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        frontier_now(&rig).await.unwrap().last_seq,
        13,
        "a small write after the publish waits for the window again"
    );
    uploader.drain(Duration::from_secs(5)).await;
}

// ---- the 64 MiB pilot cap -------------------------------------------------

#[tokio::test]
async fn a_checkpoint_of_exactly_64_mib_is_read_and_one_byte_more_is_refused() {
    let rig = Rig::new("cap").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), DurabilityPolicy::default());
    let source = source(&rig, &service);
    let space = rig.space.to_string();
    let db = DbRef {
        space: &space,
        db_id: DB,
    };

    let set_len = |len: u64| {
        std::fs::OpenOptions::new()
            .write(true)
            .open(rig.main_path())
            .unwrap()
            .set_len(len)
            .unwrap();
    };
    set_len(PILOT_CAP_BYTES);
    let at_cap = source.head(&db).await.unwrap().unwrap();
    assert_eq!(at_cap.checkpoint_bytes, PILOT_CAP_BYTES);

    set_len(PILOT_CAP_BYTES + 1);
    assert!(matches!(source.head(&db).await, Err(SourceError::TooLarge)));
    // The refusal also covers the byte reads.
    let scratch = tempfile::tempdir().unwrap();
    let mut file = tokio::fs::File::from_std(tempfile::tempfile_in(scratch.path()).unwrap());
    assert!(matches!(
        source.checkpoint_to(&db, &at_cap.cid, &mut file).await,
        Err(SourceError::TooLarge)
    ));
    // And the recovery scan lists nothing it could not publish.
    assert!(source.local_heads().await.is_empty());
}

// ---- restore equals the local file ----------------------------------------

#[tokio::test]
async fn what_was_committed_is_published_and_the_restore_equals_the_local_file() {
    let rig = Rig::new("publish").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let scratch = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySqlObjectStore::default());
    let source = source(&rig, &service);
    let uploader = start(
        &rig,
        source.clone(),
        store.clone(),
        board,
        scratch.path(),
        Duration::ZERO,
    );

    for v in ["a", "b"] {
        insert(&service, &rig.space, v).await.unwrap();
    }
    frontier_at(&rig, 12).await;
    assert_restore_equals_local(&rig, source.clone(), store.clone(), scratch.path()).await;

    for v in ["c", "d", "e"] {
        insert(&service, &rig.space, v).await.unwrap();
    }
    let frontier = frontier_at(&rig, 15).await;
    assert_eq!(frontier.last_seq, 15);
    assert_restore_equals_local(&rig, source, store, scratch.path()).await;
    uploader.drain(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_delta_is_exactly_the_wal_bytes_between_two_heads() {
    let rig = Rig::new("delta").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), DurabilityPolicy::default());
    let source = source(&rig, &service);
    let space = rig.space.to_string();
    let db = DbRef {
        space: &space,
        db_id: DB,
    };

    insert(&service, &rig.space, "a").await.unwrap();
    let first = source.head(&db).await.unwrap().unwrap();
    insert(&service, &rig.space, "b").await.unwrap();
    insert(&service, &rig.space, "c").await.unwrap();
    let second = source.head(&db).await.unwrap().unwrap();
    assert_eq!((first.revision, second.revision), (11, 13));
    assert_eq!(first.cid, second.cid, "the WAL grew on one checkpoint");

    let have = Frontier {
        lineage: Lineage::random(),
        epoch: 1,
        revision: 1,
        base_snapshot_key: String::new(),
        base_seq: 0,
        base_checkpoint_cid: first.cid.clone(),
        last_seq: 11,
        publish_id: String::new(),
        published_at: String::new(),
        frontier_bytes: 0,
    };
    let marks = source.wal_marks(&db, &[11, 13]).await.unwrap();
    let plan = plan_delta(&have, &second, &marks, 0).expect("both marks are known");

    let wal = std::fs::read(rig.wal_path()).unwrap();
    assert_eq!(wal.len() as u64, second.delta_bytes);
    let scratch = tempfile::tempdir().unwrap();
    let mut file = tokio::fs::File::from_std(tempfile::tempfile_in(scratch.path()).unwrap());
    let copied = source
        .wal_delta_to(&db, &second.head(), &plan, &mut file)
        .await
        .unwrap()
        .expect("the marks describe this WAL");

    let slice = &wal[plan.start.wal_end_bytes as usize..plan.end.wal_end_bytes as usize];
    assert_eq!(copied.bytes, slice.len() as u64);
    let digest: [u8; 32] = Sha256::digest(slice).into();
    assert_eq!(copied.sha256, digest);
    let mut written = Vec::new();
    file.rewind().await.unwrap();
    file.read_to_end(&mut written).await.unwrap();
    assert_eq!(written, slice);
}

#[tokio::test]
async fn a_wal_reset_between_publishes_becomes_a_new_snapshot_never_a_wrong_delta() {
    let rig = Rig::new("wal-reset").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let board = board(&rig);
    // An SQLite auto-checkpoint resets the WAL inside the commit that fills
    // it. The seam does the same, right after COMMIT, when armed.
    let reset_next = Arc::new(AtomicBool::new(false));
    let main_path = rig.main_path();
    let armed = reset_next.clone();
    let policy = DurabilityPolicy {
        seams: CommitSeams {
            after_commit: Some(Arc::new(move || {
                if armed.swap(false, Ordering::SeqCst) {
                    let conn = Connection::open(&main_path).unwrap();
                    let busy: i64 = conn
                        .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))
                        .unwrap();
                    assert_eq!(busy, 0);
                }
            })),
            ..CommitSeams::default()
        },
        ..DurabilityPolicy::default()
    };
    let service = rig.service(board.clone(), policy);
    let scratch = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySqlObjectStore::default());
    let source = source(&rig, &service);
    let uploader = start(
        &rig,
        source.clone(),
        store.clone(),
        board,
        scratch.path(),
        Duration::ZERO,
    );

    insert(&service, &rig.space, "a").await.unwrap();
    let before = frontier_at(&rig, 11).await;

    reset_next.store(true, Ordering::SeqCst);
    insert(&service, &rig.space, "b").await.unwrap();
    assert_eq!(
        std::fs::metadata(rig.wal_path()).unwrap().len(),
        0,
        "the WAL was reset by the commit"
    );

    let after = frontier_at(&rig, 12).await;
    assert_ne!(
        after.base_checkpoint_cid, before.base_checkpoint_cid,
        "the changed checkpoint was published as a snapshot"
    );
    assert_restore_equals_local(&rig, source.clone(), store.clone(), scratch.path()).await;

    // And the chain carries on from the new snapshot.
    insert(&service, &rig.space, "c").await.unwrap();
    frontier_at(&rig, 13).await;
    assert_restore_equals_local(&rig, source, store, scratch.path()).await;
    uploader.drain(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn a_full_wal_is_rotated_into_a_new_snapshot_at_a_new_revision() {
    let rig = Rig::new("rotate").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), DurabilityPolicy::default());
    let source = source(&rig, &service);
    let space = rig.space.to_string();
    let db = DbRef {
        space: &space,
        db_id: DB,
    };

    insert(&service, &rig.space, "a").await.unwrap();
    let small = source.head(&db).await.unwrap().unwrap();
    assert_eq!(small.revision, 11);
    assert!(small.has_delta, "a small WAL is read as it is");

    run(
        &service,
        &rig.space,
        &format!(
            "INSERT INTO items (v) VALUES (zeroblob({}))",
            WINDOW_BYTES + 1024 * 1024
        ),
    )
    .await
    .unwrap();
    let rotated = source.head(&db).await.unwrap().unwrap();
    assert_eq!(rotated.revision, 13, "the write (12) and the rotation (13)");
    assert!(!rotated.has_delta);
    assert_eq!(std::fs::metadata(rig.wal_path()).unwrap().len(), 0);
    assert_ne!(rotated.cid, small.cid);
    assert_eq!(rotated.cid, hash_file(&rig.main_path()).unwrap());
    // Asking again does not rotate again.
    assert_eq!(source.head(&db).await.unwrap().unwrap().revision, 13);
    assert_eq!(count(&service, &rig.space).await, 2);
}

#[tokio::test]
async fn a_restart_publishes_what_was_committed_before_it_without_a_new_write() {
    let rig = Rig::new("restart-publish").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let scratch = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySqlObjectStore::default());

    // First life: two writes published, then a third committed and the
    // process dies before the uploader heard of it.
    {
        let board = board(&rig);
        let service = rig.service(board.clone(), DurabilityPolicy::default());
        let uploader = start(
            &rig,
            source(&rig, &service),
            store.clone(),
            board,
            scratch.path(),
            Duration::ZERO,
        );
        for v in ["a", "b"] {
            insert(&service, &rig.space, v).await.unwrap();
        }
        frontier_at(&rig, 12).await;
        uploader.drain(Duration::from_secs(5)).await;
        insert(&service, &rig.space, "c").await.unwrap();
    }
    assert_eq!(frontier_now(&rig).await.unwrap().last_seq, 12);

    // Second life: nothing in memory. The recovery scan finds seq 13 on disk.
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let source = source(&rig, &service);
    let uploader = start(
        &rig,
        source.clone(),
        store.clone(),
        board,
        scratch.path(),
        Duration::ZERO,
    );
    let frontier = frontier_at(&rig, 13).await;
    assert_eq!(frontier.last_seq, 13);
    assert_restore_equals_local(&rig, source, store, scratch.path()).await;
    // The counter carries on: no seq of the first life is reissued.
    insert(&service, &rig.space, "d").await.unwrap();
    frontier_at(&rig, 14).await;
    uploader.drain(Duration::from_secs(5)).await;
}

// ---- no lock across the PUT -------------------------------------------------

/// A store that, inside every `put_file`, runs a write on the database the
/// upload is for. If the uploader held the operation lock across the PUT the
/// write could not start until the PUT returned, which waits for the write:
/// it would time out.
struct WritesDuringPut {
    inner: MemorySqlObjectStore,
    service: SqlService,
    space: tinycloud_auth::resource::SpaceId,
    outcomes: Mutex<Vec<bool>>,
}

#[async_trait]
impl SqlObjectStore for WritesDuringPut {
    async fn put_file(
        &self,
        key: &ObjectKey,
        path: &Path,
        size: u64,
    ) -> Result<PutOutcome, SqlStoreError> {
        let wrote = tokio::time::timeout(
            Duration::from_secs(5),
            insert(&self.service, &self.space, "during-put"),
        )
        .await;
        self.outcomes
            .lock()
            .unwrap()
            .push(matches!(wrote, Ok(Ok(_))));
        self.inner.put_file(key, path, size).await
    }

    async fn get_to_file(
        &self,
        key: &ObjectKey,
        path: &Path,
        max_bytes: u64,
    ) -> Result<Option<ObjectMeta>, SqlStoreError> {
        self.inner.get_to_file(key, path, max_bytes).await
    }

    async fn get_range(
        &self,
        key: &ObjectKey,
        range: ByteRangeSpec,
    ) -> Result<Option<ObjectRange>, SqlStoreError> {
        self.inner.get_range(key, range).await
    }

    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError> {
        self.inner.head(key).await
    }
}

#[tokio::test]
async fn no_operation_lock_is_held_while_the_store_is_written() {
    let rig = Rig::new("no-lock-over-put").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let store = Arc::new(WritesDuringPut {
        inner: MemorySqlObjectStore::default(),
        service: service.clone(),
        space: rig.space.clone(),
        outcomes: Mutex::default(),
    });
    let scratch = tempfile::tempdir().unwrap();
    let uploader = start(
        &rig,
        source(&rig, &service),
        store.clone(),
        board,
        scratch.path(),
        Duration::ZERO,
    );

    insert(&service, &rig.space, "a").await.unwrap();
    frontier_at(&rig, 11).await;

    let outcomes = store.outcomes.lock().unwrap().clone();
    assert!(!outcomes.is_empty(), "the store was written to");
    assert!(
        outcomes.iter().all(|ok| *ok),
        "a write ran to completion in the middle of every PUT: {outcomes:?}"
    );
    uploader.drain(Duration::from_secs(5)).await;
}

// ---- a WAL that cannot be published still stays bounded ---------------------

#[tokio::test]
async fn a_database_over_the_cap_still_has_its_wal_rotated() {
    let rig = Rig::new("over-cap-rotates").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), DurabilityPolicy::default());
    let source = source(&rig, &service);
    let space = rig.space.to_string();
    let db = DbRef {
        space: &space,
        db_id: DB,
    };

    // One write takes the checkpoint over the cap once it is rotated in.
    run(
        &service,
        &rig.space,
        &format!(
            "INSERT INTO items (v) VALUES (zeroblob({}))",
            PILOT_CAP_BYTES + 1024 * 1024
        ),
    )
    .await
    .unwrap();
    assert!(matches!(source.head(&db).await, Err(SourceError::TooLarge)));
    assert_eq!(std::fs::metadata(rig.wal_path()).unwrap().len(), 0);
    assert!(std::fs::metadata(rig.main_path()).unwrap().len() > PILOT_CAP_BYTES);

    // The database cannot be published, but its WAL must not pile up: the
    // next WAL that reaches the rotation size for this checkpoint is folded
    // in even though the cap refuses the database.
    let main = std::fs::metadata(rig.main_path()).unwrap().len();
    let full = rotation_threshold(main) + 1024 * 1024;
    run(
        &service,
        &rig.space,
        &format!("INSERT INTO items (v) VALUES (zeroblob({full}))"),
    )
    .await
    .unwrap();
    assert!(std::fs::metadata(rig.wal_path()).unwrap().len() >= rotation_threshold(main));
    assert!(matches!(source.head(&db).await, Err(SourceError::TooLarge)));
    assert_eq!(std::fs::metadata(rig.wal_path()).unwrap().len(), 0);
    assert_eq!(count(&service, &rig.space).await, 2);
}

#[tokio::test]
async fn a_rolled_back_write_is_not_published_and_the_restore_still_equals_the_local_file() {
    let rig = Rig::new("rolled-back").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let scratch = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySqlObjectStore::default());
    let source = source(&rig, &service);
    let space = rig.space.to_string();
    let db = DbRef {
        space: &space,
        db_id: DB,
    };
    insert(&service, &rig.space, "a").await.unwrap();
    let before = source.head(&db).await.unwrap().unwrap();

    // A write that spills past SQLite's page cache (about 2 MiB) and then
    // fails on its second row: dirty pages are written into the WAL file
    // before the rollback. It stays under the 8 MiB window, so no rotation.
    assert!(run(
        &service,
        &rig.space,
        "INSERT INTO items (v) VALUES (zeroblob(4194304)), (NULL)",
    )
    .await
    .is_err());
    let raw = std::fs::metadata(rig.wal_path()).unwrap().len();
    assert!(
        raw > before.delta_bytes + 1024 * 1024,
        "the rolled-back frames are in the file ({raw} bytes)"
    );

    // None of it is committed, so none of it is the delta.
    let after = source.head(&db).await.unwrap().unwrap();
    assert_eq!(after.revision, before.revision, "nothing was committed");
    assert_eq!(after.delta_bytes, before.delta_bytes);
    assert_eq!(count(&service, &rig.space).await, 1);

    let uploader = start(
        &rig,
        source.clone(),
        store.clone(),
        board,
        scratch.path(),
        Duration::ZERO,
    );
    insert(&service, &rig.space, "b").await.unwrap();
    frontier_at(&rig, 12).await;
    assert_restore_equals_local(&rig, source, store, scratch.path()).await;
    uploader.drain(Duration::from_secs(5)).await;
}

// ---- the mode is read under the operation lock ----------------------------------

/// Says `store_master` for the first read and `not` for every one after it:
/// the router's read, then a cutover or rollback that moved the mode before
/// the source took the lock.
#[derive(Default)]
struct FlipsAfterTheFirstRead {
    reads: std::sync::atomic::AtomicUsize,
}

#[async_trait]
impl StoreMasterGate for FlipsAfterTheFirstRead {
    async fn is_store_master(
        &self,
        _db: &DbRef<'_>,
    ) -> Result<bool, crate::sql::store::mode::ModeError> {
        Ok(self.reads.fetch_add(1, Ordering::SeqCst) == 0)
    }
    async fn store_master_databases(
        &self,
    ) -> Result<Vec<crate::sql::store::shadow::DbKey>, crate::sql::store::mode::ModeError> {
        Ok(Vec::new())
    }
}

#[tokio::test]
async fn a_database_whose_mode_moved_after_the_routing_read_is_not_read_as_store_master() {
    let rig = Rig::new("mode-under-lock").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), DurabilityPolicy::default());
    insert(&service, &rig.space, "a").await.unwrap();
    let source = Arc::new(LocalFileSource::new(
        service.clone(),
        Arc::new(FlipsAfterTheFirstRead::default()),
    ));
    let space = rig.space.to_string();
    let db = DbRef {
        space: &space,
        db_id: DB,
    };

    // What the router saw, without the lock.
    assert!(source.is_local(&db).await.unwrap());
    // What the source sees once it holds the lock: the mode moved, so it
    // reads nothing from the working copy.
    assert!(matches!(source.head(&db).await, Err(SourceError::MovedOn)));
    let scratch = tempfile::tempdir().unwrap();
    let mut file = tokio::fs::File::create(scratch.path().join("out"))
        .await
        .unwrap();
    let cid = hash_file(&rig.main_path()).unwrap();
    assert!(matches!(
        source.checkpoint_to(&db, &cid, &mut file).await,
        Err(SourceError::MovedOn)
    ));
    assert_eq!(
        file.metadata().await.unwrap().len(),
        0,
        "nothing was copied"
    );
}

// ---- upload amplification ----------------------------------------------------------

/// Counts the bytes of every object the store accepts.
struct CountingStore {
    inner: MemorySqlObjectStore,
    bytes: std::sync::atomic::AtomicU64,
}

#[async_trait]
impl SqlObjectStore for CountingStore {
    async fn put_file(
        &self,
        key: &ObjectKey,
        path: &Path,
        size: u64,
    ) -> Result<PutOutcome, SqlStoreError> {
        let outcome = self.inner.put_file(key, path, size).await?;
        if matches!(outcome, PutOutcome::Created) {
            self.bytes.fetch_add(size, Ordering::SeqCst);
        }
        Ok(outcome)
    }
    async fn get_to_file(
        &self,
        key: &ObjectKey,
        path: &Path,
        max_bytes: u64,
    ) -> Result<Option<ObjectMeta>, SqlStoreError> {
        self.inner.get_to_file(key, path, max_bytes).await
    }
    async fn get_range(
        &self,
        key: &ObjectKey,
        range: ByteRangeSpec,
    ) -> Result<Option<ObjectRange>, SqlStoreError> {
        self.inner.get_range(key, range).await
    }
    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError> {
        self.inner.head(key).await
    }
}

fn local_seq(rig: &Rig) -> u64 {
    crate::sql::store::local::read_seq(&rig.main_path()).unwrap()
}

/// Waits until the frontier has reached the counter and the counter holds
/// still (the uploader's own rotations move it).
async fn published_up_to_the_counter(rig: &Rig) {
    loop {
        let frontier = frontier_at(rig, local_seq(rig)).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if frontier.last_seq == local_seq(rig) {
            return;
        }
    }
}

/// Bytes the store accepted per byte written, for a database whose checkpoint
/// is `main_mib` when the writes start and which then takes `write_mib` of
/// 1 MiB commits, uploaded by the real scheduler as they arrive.
async fn upload_amplification(main_mib: u64, write_mib: u64) -> f64 {
    let rig = Rig::new("amplification").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let store = Arc::new(CountingStore {
        inner: MemorySqlObjectStore::default(),
        bytes: Default::default(),
    });
    let scratch = tempfile::tempdir().unwrap();
    let uploader = start(
        &rig,
        source(&rig, &service),
        store.clone(),
        board,
        scratch.path(),
        Duration::ZERO,
    );
    run(
        &service,
        &rig.space,
        &format!(
            "INSERT INTO items (v) VALUES (zeroblob({}))",
            main_mib * 1024 * 1024
        ),
    )
    .await
    .unwrap();
    published_up_to_the_counter(&rig).await;

    store.bytes.store(0, Ordering::SeqCst);
    for _ in 0..write_mib {
        run(
            &service,
            &rig.space,
            "INSERT INTO items (v) VALUES (zeroblob(1048576))",
        )
        .await
        .unwrap();
    }
    published_up_to_the_counter(&rig).await;
    uploader.drain(Duration::from_secs(5)).await;
    store.bytes.load(Ordering::SeqCst) as f64 / (write_mib * 1024 * 1024) as f64
}

#[tokio::test]
async fn the_bytes_uploaded_per_byte_written_stay_within_the_cap() {
    // A 24 MiB checkpoint taking 32 MiB of writes (it stays under the 64 MiB
    // cap throughout): with a rotation every 8 MiB (the window) each rotation
    // would upload the whole checkpoint again.
    let measured = upload_amplification(24, 32).await;
    eprintln!("MEASURED upload amplification, 24 MiB checkpoint, 32 MiB written: {measured:.2}x");
    // A rotation folds in at least `main / 2` of WAL and uploads `main + WAL`,
    // at most 3x that WAL; the WAL itself is uploaded once more as deltas.
    assert!(measured <= 4.5, "{measured:.2}x");
}

#[tokio::test]
async fn a_large_checkpoint_waits_for_proportionally_more_wal_before_it_is_rotated() {
    let rig = Rig::new("rotation-size").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), DurabilityPolicy::default());
    let source = source(&rig, &service);
    let space = rig.space.to_string();
    let db = DbRef {
        space: &space,
        db_id: DB,
    };
    let mib = 1024 * 1024;
    let write = |mib_count: u64| {
        let (service, space) = (service.clone(), rig.space.clone());
        async move {
            run(
                &service,
                &space,
                &format!(
                    "INSERT INTO items (v) VALUES (zeroblob({}))",
                    mib_count * 1024 * 1024
                ),
            )
            .await
            .unwrap();
        }
    };

    // Grow the checkpoint to about 24 MiB: one rotation, as for any database.
    write(24).await;
    let base = source.head(&db).await.unwrap().unwrap();
    assert!(!base.has_delta && base.checkpoint_bytes > 24 * mib);
    let threshold = rotation_threshold(base.checkpoint_bytes);
    assert!(threshold > 12 * mib && threshold < 13 * mib, "{threshold}");

    // 10 MiB is past the 8 MiB window, but a snapshot of this checkpoint
    // would be 3x what was written: not yet. The delta is published instead.
    write(10).await;
    let before = source.head(&db).await.unwrap().unwrap();
    assert_eq!(before.revision, base.revision + 1, "no rotation");
    assert!(before.has_delta && before.delta_bytes > 10 * mib);

    // Past half the checkpoint it is.
    write(4).await;
    let after = source.head(&db).await.unwrap().unwrap();
    assert_eq!(
        after.revision,
        before.revision + 2,
        "the write and a rotation"
    );
    assert!(!after.has_delta);
}

#[tokio::test]
async fn the_published_head_is_the_seq_file_read_under_the_lock() {
    // (2) The revision the uploader publishes is the one in the seq file when
    // it looks, not one an actor remembers: moving the file from outside moves
    // the head, and the bytes (cid) it is published with are the file's.
    let rig = Rig::new("head-from-file").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), DurabilityPolicy::default());
    let source = source(&rig, &service);
    let space = rig.space.to_string();
    let db = DbRef {
        space: &space,
        db_id: DB,
    };
    insert(&service, &rig.space, "a").await.unwrap();
    let first = source.head(&db).await.unwrap().unwrap();
    assert_eq!(first.revision, 11);
    assert_eq!(first.revision as u64, local_seq(&rig));

    for _ in 0..4 {
        crate::sql::store::local::bump_seq(&rig.main_path()).unwrap();
    }
    let second = source.head(&db).await.unwrap().unwrap();
    assert_eq!(second.revision, 15, "the file says 15");
    assert_eq!(second.cid, first.cid, "the same bytes, a later number");
}

#[tokio::test]
async fn the_seq_file_is_read_and_written_only_under_the_operation_lock() {
    // (3) While someone else holds the operation lock, neither a write (which
    // bumps the file) nor the uploader's head (which reads it) touches it:
    // both wait, and the file is as it was. Released, both go through.
    let rig = Rig::new("seq-under-lock").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let service = rig.service(Arc::new(ProbeSink::default()), DurabilityPolicy::default());
    let source = source(&rig, &service);
    let space = rig.space.to_string();
    let db = DbRef {
        space: &space,
        db_id: DB,
    };
    insert(&service, &rig.space, "a").await.unwrap();
    let seq = crate::sql::store::local::seq_path(&rig.main_path());
    let before = std::fs::read(&seq).unwrap();

    let guard = service.lock_local(&rig.space, DB).await.unwrap();
    let wait = Duration::from_millis(300);
    assert!(
        tokio::time::timeout(wait, insert(&service, &rig.space, "b"))
            .await
            .is_err()
    );
    assert_eq!(
        std::fs::read(&seq).unwrap(),
        before,
        "no bump under a held lock"
    );
    assert!(tokio::time::timeout(wait, source.head(&db)).await.is_err());
    assert_eq!(std::fs::read(&seq).unwrap(), before);
    drop(guard);

    insert(&service, &rig.space, "b").await.unwrap();
    assert_eq!(source.head(&db).await.unwrap().unwrap().revision, 12);
}

// ---- two files that disagree: the uploader refuses, it does not guess ------------

/// Remembers the reasons a database was blocked for.
#[derive(Default)]
struct Blocks(Mutex<Vec<&'static str>>);

impl ShadowMetrics for Blocks {
    fn notice(&self, _: NoticeResult) {}
    fn upload(&self, _: &'static str, _: UploadResult, _: u64) {}
    fn publish(&self, _: PublishResult) {}
    fn blocked(&self, reason: &'static str) {
        self.0.lock().unwrap().push(reason);
    }
    fn regressed(&self) {}
    fn owner_marker(&self, _: &'static str) {}
    fn dirty_databases(&self, _: u64) {}
    fn oldest_dirty_age_seconds(&self, _: f64) {}
    fn inflight_bytes(&self, _: u64) {}
    fn breaker_open(&self, _: bool) {}
    fn record_cycle_seconds(&self, _: &'static str, _: f64) {}
}

/// A volume whose seq file went back to an older copy while the main file
/// and the store moved on: three writes published (11, 12, 13), the seq file
/// put back to what it held after `rewind_to`, a fourth write.
async fn after_the_seq_file_went_back(rewind_to: u64) -> (Vec<&'static str>, Frontier) {
    let rig = Rig::new("seq-went-back").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let scratch = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySqlObjectStore::default());
    let seq = crate::sql::store::local::seq_path(&rig.main_path());
    let mut records = Vec::new();
    {
        let board = board(&rig);
        let service = rig.service(board.clone(), DurabilityPolicy::default());
        let uploader = start(
            &rig,
            source(&rig, &service),
            store.clone(),
            board,
            scratch.path(),
            Duration::ZERO,
        );
        for v in ["a", "b", "c"] {
            insert(&service, &rig.space, v).await.unwrap();
            records.push(std::fs::read(&seq).unwrap());
            frontier_at(&rig, local_seq(&rig)).await;
        }
        uploader.drain(Duration::from_secs(5)).await;
    }
    assert_eq!(frontier_now(&rig).await.unwrap().last_seq, 13);
    std::fs::write(&seq, &records[rewind_to as usize - 11]).unwrap();

    let blocks = Arc::new(Blocks::default());
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let uploader = spawn(
        ShadowDeps {
            control: rig.control.clone(),
            manifest: Arc::new(DbSqlManifest::new(rig.control.clone())),
            store,
            source: source(&rig, &service),
            disk: DiskBudget::new(scratch.path(), 512 * 1024 * 1024),
            board,
            metrics: blocks.clone(),
        },
        config(Duration::ZERO),
    );
    insert(&service, &rig.space, "d").await.unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    uploader.drain(Duration::from_secs(5)).await;
    let seen = blocks.0.lock().unwrap().clone();
    (seen, frontier_now(&rig).await.unwrap())
}

#[tokio::test]
async fn a_seq_file_older_than_the_published_frontier_blocks_the_database_and_publishes_nothing() {
    // The fourth write is numbered 12 again, a number the store already holds
    // for other bytes. The uploader sees a revision below its frontier and
    // blocks the database (`regressed`); the frontier does not move.
    let (blocks, frontier) = after_the_seq_file_went_back(11).await;
    assert_eq!(blocks, ["regressed"]);
    assert_eq!(frontier.last_seq, 13);
}

#[tokio::test]
async fn a_main_file_older_than_its_seq_file_is_numbered_forward_and_the_store_converges() {
    // The other direction: the main file and WAL come back from an older
    // backup while the seq file stays ahead. Numbers are never reused (the
    // gap is allowed), the next write is 14, and the restore of what the
    // store then holds equals the local file.
    let rig = Rig::new("main-went-back").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let scratch = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySqlObjectStore::default());
    let backup = tempfile::tempdir().unwrap();
    {
        let board = board(&rig);
        let service = rig.service(board.clone(), DurabilityPolicy::default());
        let uploader = start(
            &rig,
            source(&rig, &service),
            store.clone(),
            board,
            scratch.path(),
            Duration::ZERO,
        );
        insert(&service, &rig.space, "a").await.unwrap();
        std::fs::copy(rig.main_path(), backup.path().join("main.db")).unwrap();
        std::fs::copy(rig.wal_path(), backup.path().join("main.db-wal")).unwrap();
        for v in ["b", "c"] {
            insert(&service, &rig.space, v).await.unwrap();
        }
        frontier_at(&rig, 13).await;
        uploader.drain(Duration::from_secs(5)).await;
        // The old actor must be gone before its files are put back.
        service.stop_actor(&rig.space, DB).await;
    }
    std::fs::copy(backup.path().join("main.db"), rig.main_path()).unwrap();
    std::fs::copy(backup.path().join("main.db-wal"), rig.wal_path()).unwrap();
    let _ = std::fs::remove_file(format!("{}-shm", rig.main_path().display()));
    assert_eq!(local_seq(&rig), 13, "the seq file did not go back");

    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let source = source(&rig, &service);
    let uploader = start(
        &rig,
        source.clone(),
        store.clone(),
        board,
        scratch.path(),
        Duration::ZERO,
    );
    assert_eq!(count(&service, &rig.space).await, 1, "the older rows");
    insert(&service, &rig.space, "d").await.unwrap();
    assert_eq!(local_seq(&rig), 14);
    frontier_at(&rig, 14).await;
    assert_restore_equals_local(&rig, source, store, scratch.path()).await;
    uploader.drain(Duration::from_secs(5)).await;
}

// ---- the WAL bound and the rotation trigger judge what is committed ------------------

fn start_with_metrics(
    rig: &Rig,
    source: Arc<LocalFileSource>,
    store: Arc<dyn SqlObjectStore>,
    board: Arc<NoticeBoard>,
    scratch: &Path,
    metrics: Arc<dyn ShadowMetrics>,
    daily_upload_byte_budget: u64,
) -> SchedulerHandle {
    spawn(
        ShadowDeps {
            control: rig.control.clone(),
            manifest: Arc::new(DbSqlManifest::new(rig.control.clone())),
            store,
            source,
            disk: DiskBudget::new(scratch, 512 * 1024 * 1024),
            board,
            metrics,
        },
        SchedulerConfig {
            daily_upload_byte_budget,
            ..config(Duration::ZERO)
        },
    )
}

/// What a database that is stuck in a scheduler state must still do: take a
/// write after a rolled-back 70 MiB spill (the file's tail alone is past the
/// refusal bound), and take an honest insert over the bound and the writes
/// after it, with nobody asking the source for a head in between.
async fn writes_keep_working_after_a_spill_and_an_insert_over_the_bound(
    service: &SqlService,
    rig: &Rig,
) {
    let rows = count(service, &rig.space).await;
    let spill = WAL_REFUSE_BYTES + 6 * 1024 * 1024;
    assert!(run(
        service,
        &rig.space,
        &format!("INSERT INTO items (v) VALUES (zeroblob({spill})), (NULL)"),
    )
    .await
    .is_err());
    assert!(
        std::fs::metadata(rig.wal_path()).unwrap().len() >= WAL_REFUSE_BYTES,
        "the dead tail is past the bound"
    );
    tokio::time::sleep(Duration::from_millis(300)).await;
    for v in ["b", "c", "d"] {
        insert(service, &rig.space, v).await.unwrap();
    }
    run(
        service,
        &rig.space,
        &format!(
            "INSERT INTO items (v) VALUES (zeroblob({}))",
            WAL_REFUSE_BYTES + 1024 * 1024
        ),
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;
    for v in ["e", "f", "g"] {
        insert(service, &rig.space, v).await.unwrap();
    }
    assert_eq!(count(service, &rig.space).await, rows + 7);
}

#[tokio::test]
async fn writes_keep_working_after_a_spill_with_the_database_clean() {
    let rig = Rig::new("lockout-clean").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let scratch = tempfile::tempdir().unwrap();
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let blocks = Arc::new(Blocks::default());
    let uploader = start_with_metrics(
        &rig,
        source(&rig, &service),
        Arc::new(MemorySqlObjectStore::default()),
        board,
        scratch.path(),
        blocks.clone(),
        0,
    );
    insert(&service, &rig.space, "a").await.unwrap();
    frontier_at(&rig, 11).await;
    // Published and idle: Clean, nothing blocked. (The honest insert over the
    // bound below takes the checkpoint over the cap, so the database ends up
    // blocked as too large; that is not what this test is about.)
    assert!(blocks.0.lock().unwrap().is_empty());
    writes_keep_working_after_a_spill_and_an_insert_over_the_bound(&service, &rig).await;
    uploader.drain(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn writes_keep_working_after_a_spill_with_the_database_over_the_cap() {
    let rig = Rig::new("lockout-too-large").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let scratch = tempfile::tempdir().unwrap();
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let blocks = Arc::new(Blocks::default());
    run(
        &service,
        &rig.space,
        &format!(
            "INSERT INTO items (v) VALUES (zeroblob({}))",
            PILOT_CAP_BYTES + 1024 * 1024
        ),
    )
    .await
    .unwrap();
    let uploader = start_with_metrics(
        &rig,
        source(&rig, &service),
        Arc::new(MemorySqlObjectStore::default()),
        board,
        scratch.path(),
        blocks.clone(),
        0,
    );
    insert(&service, &rig.space, "a").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(blocks.0.lock().unwrap().first(), Some(&"too_large"));
    writes_keep_working_after_a_spill_and_an_insert_over_the_bound(&service, &rig).await;
    uploader.drain(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn writes_keep_working_after_a_spill_with_the_daily_budget_spent() {
    let rig = Rig::new("lockout-daily-budget").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let scratch = tempfile::tempdir().unwrap();
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let blocks = Arc::new(Blocks::default());
    let uploader = start_with_metrics(
        &rig,
        source(&rig, &service),
        Arc::new(MemorySqlObjectStore::default()),
        board,
        scratch.path(),
        blocks.clone(),
        1,
    );
    insert(&service, &rig.space, "a").await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(blocks.0.lock().unwrap().first(), Some(&"daily_budget"));
    writes_keep_working_after_a_spill_and_an_insert_over_the_bound(&service, &rig).await;
    uploader.drain(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn writes_keep_working_after_a_spill_with_the_database_blocked_as_regressed() {
    let rig = Rig::new("lockout-regressed").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let scratch = tempfile::tempdir().unwrap();
    let store = Arc::new(MemorySqlObjectStore::default());
    let seq = crate::sql::store::local::seq_path(&rig.main_path());
    let mut older = Vec::new();
    {
        let board = board(&rig);
        let service = rig.service(board.clone(), DurabilityPolicy::default());
        let uploader = start(
            &rig,
            source(&rig, &service),
            store.clone(),
            board,
            scratch.path(),
            Duration::ZERO,
        );
        for v in ["a", "b"] {
            insert(&service, &rig.space, v).await.unwrap();
            older.push(std::fs::read(&seq).unwrap());
        }
        frontier_at(&rig, 12).await;
        uploader.drain(Duration::from_secs(5)).await;
    }
    // The seq file goes back to its first value; the next start finds the
    // main file ahead of the frontier's counter and blocks the database.
    std::fs::write(&seq, &older[0]).unwrap();
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let blocks = Arc::new(Blocks::default());
    let uploader = start_with_metrics(
        &rig,
        source(&rig, &service),
        store,
        board,
        scratch.path(),
        blocks.clone(),
        0,
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(blocks.0.lock().unwrap().first(), Some(&"regressed"));
    writes_keep_working_after_a_spill_and_an_insert_over_the_bound(&service, &rig).await;
    uploader.drain(Duration::from_secs(5)).await;
}

/// What a database with a `main_mib` checkpoint costs the store when, `rounds`
/// times, a write spills `spill_mib` of rolled-back frames into the WAL and a
/// one-row write commits: the bytes the store accepted, and how far the
/// counter moved. Real scheduler at the 60 s window.
async fn cost_of_rolled_back_spills(main_mib: u64, spill_mib: u64, rounds: u64) -> (u64, u64) {
    let rig = Rig::new("rolled-back-cost").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let board = board(&rig);
    let service = rig.service(board.clone(), DurabilityPolicy::default());
    let store = Arc::new(CountingStore {
        inner: MemorySqlObjectStore::default(),
        bytes: Default::default(),
    });
    let scratch = tempfile::tempdir().unwrap();
    let uploader = start(
        &rig,
        source(&rig, &service),
        store.clone(),
        board,
        scratch.path(),
        WINDOW,
    );
    run(
        &service,
        &rig.space,
        &format!(
            "INSERT INTO items (v) VALUES (zeroblob({}))",
            main_mib * 1024 * 1024
        ),
    )
    .await
    .unwrap();
    published_up_to_the_counter(&rig).await;

    store.bytes.store(0, Ordering::SeqCst);
    let seq_before = local_seq(&rig);
    for round in 0..rounds {
        assert!(run(
            &service,
            &rig.space,
            &format!(
                "INSERT INTO items (v) VALUES (zeroblob({})), (NULL)",
                spill_mib * 1024 * 1024
            ),
        )
        .await
        .is_err());
        assert!(
            std::fs::metadata(rig.wal_path()).unwrap().len() >= spill_mib * 1024 * 1024 / 2,
            "the spill is in the file"
        );
        insert(&service, &rig.space, &format!("r{round}"))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    uploader.drain(Duration::from_secs(5)).await;
    (
        store.bytes.load(Ordering::SeqCst),
        local_seq(&rig) - seq_before,
    )
}

#[tokio::test]
async fn a_rolled_back_spill_neither_rotates_nor_skips_the_window_nor_republishes_the_checkpoint() {
    // A 24 MiB checkpoint (rotation size 12 MiB) and 16 MiB of rolled-back
    // frames per round, then one row. Counted by the file, each round was a
    // rotation: a whole 24 MiB snapshot and a window skipped, every round.
    let (bytes, counter_moved) = cost_of_rolled_back_spills(24, 16, 4).await;
    eprintln!(
        "MEASURED, 24 MiB checkpoint, 4 rounds of a 16 MiB rolled-back spill + 1 row: \
         {bytes} bytes uploaded, counter moved {counter_moved}"
    );
    assert_eq!(counter_moved, 4, "one number per write, no rotation");
    assert!(
        bytes < 1024 * 1024,
        "{bytes} bytes uploaded: the checkpoint was republished"
    );
}

#[tokio::test]
async fn the_reviewers_two_amplification_cases_upload_nothing_for_the_rolled_back_bytes() {
    // Bobbie's probes against 9e38f2b0: a 24 MiB checkpoint with a 17 MiB
    // rolled-back spill before each of 5 one-row commits (126 MB uploaded,
    // against 20 KB without the spill), and a 60 MiB checkpoint with a 36 MiB
    // spill (315 MB).
    for (main, spill, rounds) in [(24, 17, 5), (60, 36, 2)] {
        let (bytes, counter_moved) = cost_of_rolled_back_spills(main, spill, rounds).await;
        eprintln!(
            "MEASURED, {main} MiB checkpoint, {rounds} rounds of a {spill} MiB rolled-back \
             spill + 1 row: {bytes} bytes uploaded, counter moved {counter_moved}"
        );
        assert_eq!(counter_moved, rounds, "one number per write, no rotation");
        assert!(
            bytes < 1024 * 1024,
            "{bytes} bytes uploaded for {main}/{spill}: the checkpoint was republished"
        );
    }
}

#[tokio::test]
async fn the_recovery_scan_does_not_read_the_whole_wal_of_every_database() {
    // 40 MiB committed. The recovery scan asks every store-master database for
    // its head under that database's operation lock; the head is a counter and
    // a checkpoint hash and needs no WAL bytes. Reading the WAL (a scan of
    // 40 MiB, with a write waiting on the lock) separates tens of ms from
    // about 1 ms per call: the median of 15 calls must stay under 10 ms.
    let rig = Rig::new("scan-is-light").await;
    rig.create_working_copy(10);
    rig.make_store_master().await;
    let board = board(&rig);
    let service = rig.service(board, DurabilityPolicy::default());
    let source = source(&rig, &service);
    run(
        &service,
        &rig.space,
        &format!(
            "INSERT INTO items (v) VALUES (zeroblob({}))",
            40 * 1024 * 1024
        ),
    )
    .await
    .unwrap();
    assert!(std::fs::metadata(rig.wal_path()).unwrap().len() >= 40 * 1024 * 1024);
    let mut times = Vec::new();
    for _ in 0..15 {
        let started = Instant::now();
        let heads = source.local_heads().await;
        times.push(started.elapsed());
        assert_eq!(heads.len(), 1);
    }
    times.sort();
    eprintln!(
        "MEDIAN local_heads beside a 40 MiB WAL: {:?} (all: {times:?})",
        times[7]
    );
    assert!(
        times[7] < Duration::from_millis(10),
        "median {:?}: the scan reads the whole WAL",
        times[7]
    );
}

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
use crate::sql::store::local::{hash_file, PILOT_CAP_BYTES, WINDOW, WINDOW_BYTES};
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
use crate::sql::store::shadow::metrics::{NoopMetrics, RestoreResult};
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
    // next full WAL is folded in even though the cap refuses the database.
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
    assert!(std::fs::metadata(rig.wal_path()).unwrap().len() >= WINDOW_BYTES);
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

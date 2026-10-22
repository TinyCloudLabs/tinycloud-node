//! TC-822: hydrating a large artifact streams it in slices, so the Rust heap
//! the node holds for it does not grow with the artifact.
//!
//! The row is inserted with `zeroblob` (no 256 MiB buffer in the test) and its
//! hash is computed incrementally. A tracking allocator records the peak heap
//! growth during the read. SQLite's own `substr(blob, ..)` materialises the
//! blob inside the SQLite library (C allocator, not counted here); the
//! Postgres equivalent is measured separately (see the PR).

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
use tinycloud_core::{
    database_artifacts::{
        read_artifact, CacheFileSink, SeaOrmDatabaseArtifactRepository, ARTIFACT_CHUNK_BYTES,
    },
    hash::Blake3Hasher,
    migrations::Migrator,
    sea_orm_migration::MigratorTrait,
};

struct Tracking;
static CURRENT: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for Tracking {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = System.alloc(layout);
        if !ptr.is_null() {
            let now = CURRENT.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(now, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        System.dealloc(ptr, layout);
        CURRENT.fetch_sub(layout.size(), Ordering::Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let new = System.realloc(ptr, layout, new_size);
        if !new.is_null() {
            if new_size >= layout.size() {
                let now = CURRENT.fetch_add(new_size - layout.size(), Ordering::Relaxed) + new_size
                    - layout.size();
                PEAK.fetch_max(now, Ordering::Relaxed);
            } else {
                CURRENT.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        new
    }
}

#[global_allocator]
static ALLOC: Tracking = Tracking;

const ARTIFACT_BYTES: usize = 256 * 1024 * 1024;

#[tokio::test]
async fn a_256_mib_artifact_hydrates_with_a_bounded_heap() {
    let dir = tempfile::tempdir().unwrap();
    let mut options = ConnectOptions::new(format!(
        "sqlite:{}?mode=rwc",
        dir.path().join("caps.db").display()
    ));
    options.max_connections(1);
    let conn = Database::connect(options).await.unwrap();
    Migrator::up(&conn, None).await.unwrap();

    let mut hasher = Blake3Hasher::new();
    let zeros = vec![0_u8; ARTIFACT_CHUNK_BYTES];
    for _ in 0..ARTIFACT_BYTES / ARTIFACT_CHUNK_BYTES {
        hasher.update(&zeros);
    }
    drop(zeros);
    let hash = hasher.finalize().to_cid(0x55).to_string();
    conn.execute(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO database_artifact (service, space, name, revision, content_hash, payload, \
         size_bytes, backend, storage_mode, created_at, updated_at, checkpoint_size_bytes, \
         checkpoint_content_hash, delta_payload, delta_content_hash, delta_size_bytes) \
         VALUES ('sql', 'space', 'big', 1, ?, zeroblob(?), ?, 'storage.database', \
         'database-blob', 'now', 'now', ?, ?, NULL, NULL, 0)",
        [
            hash.clone().into(),
            (ARTIFACT_BYTES as i64).into(),
            (ARTIFACT_BYTES as i64).into(),
            (ARTIFACT_BYTES as i64).into(),
            hash.into(),
        ],
    ))
    .await
    .unwrap();

    let repo = SeaOrmDatabaseArtifactRepository::new(conn);
    let cache = tempfile::tempdir().unwrap();
    let mut sink = CacheFileSink::new(
        "sql",
        "space/big".to_string(),
        cache.path().join("big.db"),
        cache.path().join("big.db-wal"),
        |_| true,
        |_| true,
    );

    let baseline = CURRENT.load(Ordering::Relaxed);
    PEAK.store(baseline, Ordering::Relaxed);
    let meta = read_artifact(&repo, "sql", "space", "big", &mut sink)
        .await
        .unwrap()
        .expect("the artifact exists");
    let growth = PEAK.load(Ordering::Relaxed).saturating_sub(baseline);
    sink.commit().await.unwrap();

    assert_eq!(meta.checkpoint_size_bytes as usize, ARTIFACT_BYTES);
    assert_eq!(
        std::fs::metadata(cache.path().join("big.db"))
            .unwrap()
            .len() as usize,
        ARTIFACT_BYTES
    );
    // A few slice-sized buffers (row decode, copy, write), never the artifact.
    assert!(
        growth < 6 * ARTIFACT_CHUNK_BYTES,
        "heap grew {} MiB hydrating a {} MiB artifact",
        growth >> 20,
        ARTIFACT_BYTES >> 20
    );
}

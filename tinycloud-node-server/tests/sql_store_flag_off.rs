//! Flag-off and allowlist-empty guarantees for the SQL-store shadow
//! wiring. The uploader's integration gate has three fail-closed states,
//! each tested here:
//!
//! 1. `enabled = false` → `maybe_build` returns `None`: no `ShadowHandle`,
//!    no task, no scratch dir, no owner-marker IO call, and the runtime
//!    future (object store, artifact source) is never polled.
//!    `SqlService.shadow` stays `NoopSink` and SQL writes commit as they
//!    always have.
//! 2. `enabled = true, spaces = []` → still `None`, still no IO call. This
//!    is the user-facing live state once a later release lifts the
//!    build-level refusal; the flag can be edited to `true` but the
//!    allowlist stays empty by default, so an operator explicitly chooses
//!    which space uploads.
//! 3. `enabled = true, spaces = ["<allowed>"]` → a handle is built, the
//!    owner marker is written exactly once, and the scheduler runs until
//!    the handle drains.
//!
//! TC-1491.
//!
//! The actual object-store backend is faked by the `FakeIo` used in the
//! `sql_store` module tests; we re-exercise the same construction entry
//! point here, as an integration test, to pin that the API survives at
//! least one external user.

use std::future::Future;
use std::pin::Pin;
use std::sync::{atomic::AtomicUsize, Arc, Mutex};
use std::time::Duration;

use tinycloud::sql_store::{maybe_build, OwnerMarkerIo, ShadowBuildError, ShadowRuntime};
use tinycloud_core::database_artifacts::SeaOrmDatabaseArtifactRepository;
use tinycloud_core::migrations::Migrator;
use tinycloud_core::sea_orm::{ConnectOptions, Database};
use tinycloud_core::sea_orm_migration::MigratorTrait;
use tinycloud_core::sql::store::{
    shadow::{metrics::NoopMetrics, scheduler::SchedulerConfig},
    MemorySqlObjectStore, SpaceAllowlist,
};

const SPACE: &str = "tinycloud:pkh:eip155:1:0xAb://default";

#[derive(Default)]
struct FakeIo {
    marker: Mutex<Option<Vec<u8>>>,
    loads: AtomicUsize,
    puts: AtomicUsize,
}

impl FakeIo {
    fn new() -> Self {
        Self::default()
    }
    fn loads(&self) -> usize {
        self.loads.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn puts(&self) -> usize {
        self.puts.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl OwnerMarkerIo for FakeIo {
    fn load_marker_body<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, ShadowBuildError>> + Send + 'a>> {
        let body = self.marker.lock().unwrap().clone();
        self.loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move { Ok(body) })
    }
    fn write_marker<'a>(
        &'a self,
        body: Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<(), ShadowBuildError>> + Send + 'a>> {
        let marker = &self.marker;
        let puts = &self.puts;
        Box::pin(async move {
            let mut current = marker.lock().unwrap();
            if let Some(existing) = current.as_ref() {
                if existing == &body {
                    return Ok(());
                }
                return Err(ShadowBuildError::OwnerMarkerMismatch);
            }
            *current = Some(body);
            puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}

/// One connection, so the scheduler sees the same in-memory database.
async fn fresh_conn() -> tinycloud_core::sea_orm::DatabaseConnection {
    let mut options = ConnectOptions::new("sqlite::memory:".to_string());
    options.max_connections(1).sqlx_logging(false);
    let conn = Database::connect(options).await.unwrap();
    Migrator::up(&conn, None).await.unwrap();
    conn
}

fn allow(spaces: &[&str]) -> SpaceAllowlist {
    SpaceAllowlist::new(spaces.iter().map(|s| s.to_string()))
}

/// The runtime future of an off gate: polling it fails the test.
async fn never() -> Result<ShadowRuntime, ShadowBuildError> {
    panic!("the runtime is built only when the gate is on")
}

/// An in-memory object store and the artifact repository over `conn`.
fn runtime(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    scratch: &tempfile::TempDir,
) -> impl Future<Output = Result<ShadowRuntime, ShadowBuildError>> {
    let runtime = ShadowRuntime {
        store: Arc::new(MemorySqlObjectStore::default()),
        artifacts: Arc::new(SeaOrmDatabaseArtifactRepository::new(conn.clone())),
        scratch_dir: scratch.path().join("shadow"),
        scratch_bytes: 1 << 20,
        scheduler: SchedulerConfig::default(),
        metrics: Arc::new(NoopMetrics),
    };
    async move { Ok(runtime) }
}

#[tokio::test]
async fn flag_off_builds_no_handle_and_never_touches_the_object_store() {
    let conn = fresh_conn().await;
    let io = FakeIo::new();
    let handle = maybe_build(false, allow(&[SPACE]), &conn, &io, never())
        .await
        .unwrap();
    assert!(
        handle.is_none(),
        "disabled flag must not build a ShadowHandle"
    );
    assert_eq!(io.loads(), 0, "no HEAD against sql/v1/_owner/v1");
    assert_eq!(io.puts(), 0, "no PUT against sql/v1/_owner/v1");
}

#[tokio::test]
async fn enabled_with_empty_allowlist_builds_no_handle_and_never_touches_the_object_store() {
    let conn = fresh_conn().await;
    let io = FakeIo::new();
    // enabled=true but the allowlist is empty: still off.
    let handle = maybe_build(true, allow(&[]), &conn, &io, never())
        .await
        .unwrap();
    assert!(
        handle.is_none(),
        "empty allowlist must not build a ShadowHandle even when enabled"
    );
    assert_eq!(io.loads(), 0);
    assert_eq!(io.puts(), 0);
}

#[tokio::test]
async fn enabled_with_a_space_builds_a_handle_and_writes_the_marker_exactly_once() {
    let conn = fresh_conn().await;
    let io = FakeIo::new();
    let scratch = tempfile::tempdir().unwrap();
    let handle = maybe_build(true, allow(&[SPACE]), &conn, &io, runtime(&conn, &scratch))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(io.loads(), 1);
    assert_eq!(io.puts(), 1);
    // The marker body is the hex store_id, 32 characters, ascii.
    assert_eq!(
        io.marker.lock().unwrap().as_deref(),
        Some(handle.owner.as_str().as_bytes())
    );
    assert!(scratch.path().join("shadow").is_dir());
    // Nothing to upload: the drain reports no database and no stuck job.
    let report = handle.drain(Duration::from_secs(5)).await;
    assert_eq!(report.abandoned_jobs, 0);
    assert!(report.databases.is_empty(), "{report:?}");
}

#[tokio::test]
async fn second_boot_keeps_the_same_owner_and_writes_the_marker_no_more() {
    let conn = fresh_conn().await;
    let io = FakeIo::new();
    let scratch = tempfile::tempdir().unwrap();
    let first = maybe_build(true, allow(&[SPACE]), &conn, &io, runtime(&conn, &scratch))
        .await
        .unwrap()
        .unwrap();
    let first_owner = first.owner.clone();
    first.drain(Duration::from_secs(5)).await;
    let second = maybe_build(true, allow(&[SPACE]), &conn, &io, runtime(&conn, &scratch))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        first_owner, second.owner,
        "store_id must persist across boots"
    );
    assert_eq!(io.puts(), 1, "marker is written exactly once");
    // Two boots, two HEADs.
    assert_eq!(io.loads(), 2);
    second.drain(Duration::from_secs(5)).await;
}

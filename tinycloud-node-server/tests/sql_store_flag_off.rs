//! TC-1491 PR C flag-off / allowlist-empty guarantees (contract §5.3, F1/F2).
//!
//! The uploader's integration gate has three fail-closed states, each tested
//! here:
//!
//! 1. `enabled = false` → `maybe_build` returns `None`; no `ShadowHandle`,
//!    no task, no spool dir, no owner-marker IO call. `SqlService.shadow`
//!    stays `NoopSink` and SQL writes commit as they always have.
//! 2. `enabled = true, spaces = []` → still `None`, still no IO call. This
//!    is the user-facing live state once PR D lifts the m2 refusal; the
//!    flag can be edited to `true` but the allowlist stays empty by
//!    default, so an operator explicitly chooses which space uploads.
//! 3. `enabled = true, spaces = ["<allowed>"]` → a handle IS built AND the
//!    owner marker is written exactly once. The sink in PR C is still the
//!    `NoopSink` (the uploader run loop lives in a later milestone), so
//!    the capture hook still sees `wants() == false` for every space.
//!    What this test proves is the *construction* gate.
//!
//! The actual object-store backend is faked by the `FakeIo` used in the
//! `sql_store` module tests; we re-exercise the same construction entry
//! point here, as an integration test, to pin that the API survives at
//! least one external user.

use std::sync::{atomic::AtomicUsize, Mutex};

use tinycloud::sql_store::{maybe_build, OwnerMarkerIo, ShadowBuildError};
use tinycloud_core::migrations::Migrator;
use tinycloud_core::sea_orm::{ConnectOptions, Database};
use tinycloud_core::sea_orm_migration::MigratorTrait;

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
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Option<Vec<u8>>, ShadowBuildError>> + Send + 'a,
        >,
    > {
        let body = self.marker.lock().unwrap().clone();
        self.loads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Box::pin(async move { Ok(body) })
    }
    fn write_marker<'a>(
        &'a self,
        body: Vec<u8>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), ShadowBuildError>> + Send + 'a>,
    > {
        let marker = &self.marker;
        let puts = &self.puts;
        Box::pin(async move {
            let mut current = marker.lock().unwrap();
            *current = Some(body);
            puts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}

async fn fresh_conn() -> tinycloud_core::sea_orm::DatabaseConnection {
    let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .unwrap();
    Migrator::up(&conn, None).await.unwrap();
    conn
}

#[tokio::test]
async fn flag_off_builds_no_handle_and_never_touches_the_object_store() {
    let conn = fresh_conn().await;
    let io = FakeIo::new();
    let handle = maybe_build(false, true, &conn, &io).await.unwrap();
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
    // enabled=true but allowlist_empty=true: still off.
    let handle = maybe_build(true, true, &conn, &io).await.unwrap();
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
    let handle = maybe_build(true, false, &conn, &io).await.unwrap().unwrap();
    assert_eq!(io.loads(), 1);
    assert_eq!(io.puts(), 1);
    // The marker body is the hex store_id, 32 characters, ascii.
    assert_eq!(
        io.marker.lock().unwrap().as_deref(),
        Some(handle.owner.as_str().as_bytes())
    );
}

#[tokio::test]
async fn second_boot_keeps_the_same_owner_and_writes_the_marker_no_more() {
    let conn = fresh_conn().await;
    let io = FakeIo::new();
    let first = maybe_build(true, false, &conn, &io).await.unwrap().unwrap();
    let second = maybe_build(true, false, &conn, &io).await.unwrap().unwrap();
    assert_eq!(
        first.owner, second.owner,
        "store_id must persist across boots"
    );
    assert_eq!(io.puts(), 1, "marker is written exactly once");
    // Two boots, two HEADs.
    assert_eq!(io.loads(), 2);
}

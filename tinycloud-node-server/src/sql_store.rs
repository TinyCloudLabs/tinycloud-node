//! Runtime wiring for the SQL-store shadow uploader.
//!
//! This module is the single integration seam between the shadow uploader
//! (lives in `tinycloud-core::sql::store::shadow`) and the node's runtime.
//! It builds a [`ShadowHandle`] only when `[sql_store] enabled` is true and
//! at least one space is in the allowlist; otherwise it returns `None` and
//! the node pays nothing: no owner-marker IO, no object store, no task.
//!
//! Ships off. Uploading databases unencrypted is not cleared yet, and the
//! restore check (TC-1491 P2) does not exist yet, so
//! `SqlStoreConfig::validate_for_database` keeps its terminating
//! `"sql_store is not available in this build"` refusal in this build. The
//! acceptance tests exercise this module directly, bypassing that gate.
//!
//! Composition:
//! - `SqlObjectStore` is built from `BlockStorage::{Local,S3}` the same way
//!   `space_purge_executor::PurgeSqlObjects` does: the S3 branch uses the
//!   block store's bucket and client; the local branch roots at
//!   `{datadir}/sql-store`.
//! - The owner marker (`sql/v1/_owner/v1`) is checked against the
//!   `sql_store_owner` row at boot before the first uploader cycle. A
//!   mismatch is a `ConfigError::OwnerMarkerMismatch` and refuses the
//!   start: once written, every future enable of this bucket and prefix
//!   must present the same `store_id`.
//! - The sink is a [`NoticeBoard`]: the save hook's metadata-only notices
//!   land there, and the scheduler task (`shadow::scheduler`) drains them,
//!   runs the startup lag scan (which bootstraps every allowlisted database
//!   without a frontier) and uploads from Postgres through
//!   [`PgArtifactSource`].
//! - [`ShadowHandle::drain`] stops scheduling at shutdown, waits for
//!   in-flight uploads up to a deadline, and reports each database's
//!   frontier against the newest revision the uploader learned of.
//!
//! TC-1491.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use std::future::Future;
use std::pin::Pin;

use tinycloud_core::database_artifacts::DatabaseArtifactRepository;
use tinycloud_core::sql::store::{
    shadow::{
        budget::DiskBudget,
        metrics::ShadowMetrics,
        owner::{self, BootOutcome, OwnerMarkerError, StoreId, OWNER_OBJECT_KEY},
        scheduler::{self, DrainReport, SchedulerConfig, SchedulerHandle, ShadowDeps},
        source::PgArtifactSource,
        NoticeBoard,
    },
    DbSqlManifest, ShadowSink, SpaceAllowlist, SqlObjectStore,
};

/// Everything the runtime holds to keep the shadow uploader alive for the
/// process's lifetime: the [`ShadowSink`] wired into `SqlService`, the
/// resolved owner-marker identity, and the scheduler task. Dropping the
/// handle without [`Self::drain`] aborts the task.
pub struct ShadowHandle {
    pub sink: Arc<dyn ShadowSink>,
    pub owner: StoreId,
    scheduler: SchedulerHandle,
}

impl ShadowHandle {
    /// A shallow clone of the sink Arc, for `SqlService::with_shadow`.
    pub fn sink(&self) -> Arc<dyn ShadowSink> {
        Arc::clone(&self.sink)
    }

    /// Stop scheduling, give in-flight uploads up to `deadline`
    /// (`[sql_store] drain_secs`), and report each database's `last_seq`
    /// against its target revision.
    pub async fn drain(self, deadline: Duration) -> DrainReport {
        self.scheduler.drain(deadline).await
    }
}

/// What the uploader runs on. Built only after the gate passed and the
/// owner marker paired (`maybe_build` awaits it then, never before).
pub struct ShadowRuntime {
    pub store: Arc<dyn SqlObjectStore>,
    /// The repository `SqlService` saves through; the upload jobs read the
    /// checkpoint and WAL from it.
    pub artifacts: Arc<dyn DatabaseArtifactRepository>,
    /// Scratch files for streamed uploads (created if missing).
    pub scratch_dir: PathBuf,
    /// Bytes the scratch files may hold at once (`[sql_store] spool_cap`).
    pub scratch_bytes: u64,
    pub scheduler: SchedulerConfig,
    pub metrics: Arc<dyn ShadowMetrics>,
}

/// Reasons the shadow handle refused to start. Mapped onto the node's
/// `anyhow::Error` at `resolve_runtime`; the Display never contains the
/// marker body or the store ID.
#[derive(Debug, thiserror::Error)]
pub enum ShadowBuildError {
    /// The control-DB row and the bucket object disagree on the store ID.
    /// Refuse to start. Public message does not log the body.
    #[error("sql_store owner marker mismatch")]
    OwnerMarkerMismatch,
    /// The control-DB row is absent but the marker is present (control DB
    /// wiped but bucket retained). Refuse to start.
    #[error("sql_store owner row is missing but the marker is present")]
    OwnerRowMissingMarkerPresent,
    #[error("sql_store owner marker system error: {0}")]
    System(String),
    #[error("sql_store owner marker database error: {0}")]
    Database(#[from] tinycloud_core::sea_orm::DbErr),
}

impl From<OwnerMarkerError> for ShadowBuildError {
    fn from(err: OwnerMarkerError) -> Self {
        match err {
            OwnerMarkerError::Mismatch => Self::OwnerMarkerMismatch,
            OwnerMarkerError::RowMissingMarkerPresent => Self::OwnerRowMissingMarkerPresent,
            OwnerMarkerError::Malformed => Self::System("control-DB store_id is malformed".into()),
            OwnerMarkerError::Database(e) => Self::Database(e),
            OwnerMarkerError::System(e) => Self::System(e),
        }
    }
}

/// What the owner-marker boot pairing needs from the object store, abstracted
/// so this module can be tested without a real S3 client. In production the
/// closure types are `S3SqlObjectStore` and `FsSqlObjectStore`, which
/// both implement `SqlObjectStore`.
///
/// The two operations the pairing uses are HEAD (does the marker object
/// exist, and if so with what body) and PUT (write the marker body once,
/// never replace).
///
/// Result type the [`OwnerMarkerIo::load_marker_body`] future resolves to.
type LoadMarkerFut<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, ShadowBuildError>> + Send + 'a>>;
/// Result type the [`OwnerMarkerIo::write_marker`] future resolves to.
type WriteMarkerFut<'a> = Pin<Box<dyn Future<Output = Result<(), ShadowBuildError>> + Send + 'a>>;

pub trait OwnerMarkerIo {
    /// Return the marker object's body if it exists; `None` if absent.
    fn load_marker_body<'a>(&'a self) -> LoadMarkerFut<'a>;

    /// Write `body` to the marker object exactly once, with a create-once
    /// (`If-None-Match: *`) write. If the object exists with a different body the
    /// implementation must return `ShadowBuildError::OwnerMarkerMismatch`;
    /// if it exists with the same body it may return `Ok(())` (the pairing
    /// still holds). An unconditional PUT would silently overwrite a
    /// concurrent writer's claim, which is exactly the TOCTOU the marker
    /// exists to prevent.
    fn write_marker<'a>(&'a self, body: Vec<u8>) -> WriteMarkerFut<'a>;
}

/// Pair the control-DB row with the bucket marker.
///
/// Call this before any uploader cycle. A mismatch returns
/// `ShadowBuildError::OwnerMarkerMismatch` and the caller refuses the
/// node start.
///
/// Sequence (HEAD first, then insert if needed: an early row-insert hides
/// the row-absent + marker-present state):
/// 1. HEAD the bucket marker.
/// 2. Load the control-DB row.
/// 3. If the row is absent and the marker is present, refuse to start
///    (`RowMissingMarkerPresent`): the control DB was wiped and the bucket
///    is still owned by a (possibly different) node.
/// 4. If both are absent, mint a fresh candidate, insert the row, then
///    create the marker once with that body.
/// 5. If both are present, compare: match returns `Ok`, mismatch refuses.
/// 6. If the row is present and the marker is absent (fresh bucket,
///    retained control DB), create the marker once with the row's ID.
///
/// This function does not log the store ID or the marker body. The caller
/// obtains a `StoreId` on success; the metric `sql_store_owner_marker_total`
/// records the outcome (`ok` / `wrote` / `mismatch` / `row_missing`).
pub async fn pair_owner_marker<I: OwnerMarkerIo>(
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    io: &I,
) -> Result<StoreId, ShadowBuildError> {
    let body = io.load_marker_body().await?;
    let row = owner::load_owner_row(conn).await?;
    match (row, body) {
        (Some(id), Some(body)) => {
            match owner::compare(Some(&id), Some(&body))? {
                BootOutcome::Ok(id) => Ok(id),
                // `compare` already short-circuits `Some, Some` with Ok or
                // Mismatch; `Write` is unreachable here but handled for
                // totality.
                BootOutcome::Write(id) => {
                    io.write_marker(id.as_body()).await?;
                    Ok(id)
                }
            }
        }
        (None, Some(_)) => Err(ShadowBuildError::OwnerRowMissingMarkerPresent),
        (Some(id), None) => {
            // Fresh bucket, retained control DB: write the marker with the
            // recorded ID. `write_marker` must reject a concurrent write
            // that stored a different body.
            io.write_marker(id.as_body()).await?;
            Ok(id)
        }
        (None, None) => {
            // First enable on both sides: mint, insert, then write.
            let candidate = StoreId::random();
            let id = owner::insert_or_load_owner_row(conn, &candidate).await?;
            io.write_marker(id.as_body()).await?;
            Ok(id)
        }
    }
}

/// The `sql/v1/_owner/v1` key used by the boot pairing; re-exported for the
/// node-server backends so they do not have to depend on the `shadow`
/// module directly.
pub const OWNER_MARKER_KEY: &str = OWNER_OBJECT_KEY;

/// Build the shadow handle if the flag and the allowlist permit; return
/// `None` otherwise. Used by `resolve_runtime`.
///
/// Off (`enabled` false or an empty allowlist) touches nothing: no marker
/// IO, and `runtime` is dropped unpolled, so whatever it would open (the S3
/// probe, the scratch directory) is never opened. On, it pairs the owner
/// marker (a mismatch refuses the start), then awaits `runtime`, wires a
/// [`NoticeBoard`] as the sink and spawns the scheduler on the current
/// tokio runtime. `conn` is the control database: the manifest, and the
/// artifact rows the lag scan joins it with, live there.
pub async fn maybe_build<I, R>(
    enabled: bool,
    allowlist: SpaceAllowlist,
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    io: &I,
    runtime: R,
) -> Result<Option<ShadowHandle>, ShadowBuildError>
where
    I: OwnerMarkerIo,
    R: Future<Output = Result<ShadowRuntime, ShadowBuildError>>,
{
    if !enabled || allowlist.is_empty() {
        return Ok(None);
    }
    let owner = pair_owner_marker(conn, io).await?;
    let runtime = runtime.await?;
    std::fs::create_dir_all(&runtime.scratch_dir).map_err(|e| {
        ShadowBuildError::System(format!("sql_store scratch directory: {:?}", e.kind()))
    })?;
    let board = Arc::new(NoticeBoard::new(allowlist, runtime.metrics.clone()));
    let scheduler = scheduler::spawn(
        ShadowDeps {
            control: conn.clone(),
            manifest: Arc::new(DbSqlManifest::new(conn.clone())),
            store: runtime.store,
            source: Arc::new(PgArtifactSource::new(runtime.artifacts)),
            disk: DiskBudget::new(runtime.scratch_dir, runtime.scratch_bytes),
            board: board.clone(),
            metrics: runtime.metrics,
        },
        runtime.scheduler,
    );
    Ok(Some(ShadowHandle {
        sink: board,
        owner,
        scheduler,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tinycloud_core::migrations::Migrator;
    use tinycloud_core::sea_orm::{ConnectOptions, Database};
    use tinycloud_core::sea_orm_migration::MigratorTrait;

    /// Fake IO: holds the current marker body + a put count.
    #[derive(Default)]
    struct FakeIo {
        marker: Mutex<Option<Vec<u8>>>,
        puts: std::sync::atomic::AtomicUsize,
    }

    impl FakeIo {
        fn new() -> Self {
            Self::default()
        }
        fn with_body(body: Vec<u8>) -> Self {
            Self {
                marker: Mutex::new(Some(body)),
                puts: Default::default(),
            }
        }
        fn puts(&self) -> usize {
            self.puts.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl OwnerMarkerIo for FakeIo {
        fn load_marker_body<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>, ShadowBuildError>> + Send + 'a>>
        {
            let body = self.marker.lock().unwrap().clone();
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
                        // Same body: idempotent under a create-once write.
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

    async fn fresh_conn() -> tinycloud_core::sea_orm::DatabaseConnection {
        let conn = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&conn, None).await.unwrap();
        conn
    }

    #[tokio::test]
    async fn first_enable_writes_both_row_and_marker() {
        let conn = fresh_conn().await;
        let io = FakeIo::new();
        let id = pair_owner_marker(&conn, &io).await.unwrap();
        assert_eq!(io.puts(), 1);
        assert_eq!(
            io.marker.lock().unwrap().as_deref(),
            Some(id.as_str().as_bytes())
        );
    }

    #[tokio::test]
    async fn second_boot_with_matching_marker_writes_nothing_new() {
        let conn = fresh_conn().await;
        let io = FakeIo::new();
        let id = pair_owner_marker(&conn, &io).await.unwrap();
        let id_again = pair_owner_marker(&conn, &io).await.unwrap();
        assert_eq!(id, id_again);
        assert_eq!(io.puts(), 1, "marker is written exactly once across boots");
    }

    #[tokio::test]
    async fn mismatched_marker_refuses_to_start() {
        // First enable: both row and marker are written.
        let conn = fresh_conn().await;
        let io = FakeIo::new();
        let _ = pair_owner_marker(&conn, &io).await.unwrap();
        // Simulate a bucket swap: the marker body now points at a different
        // store ID while the control-DB row is still the original.
        let different_id = StoreId::parse("00000000000000000000000000000001").unwrap();
        *io.marker.lock().unwrap() = Some(different_id.as_str().as_bytes().to_vec());
        let err = pair_owner_marker(&conn, &io).await.unwrap_err();
        assert!(matches!(err, ShadowBuildError::OwnerMarkerMismatch));
        let msg = err.to_string();
        assert_eq!(msg, "sql_store owner marker mismatch");
        assert!(!msg.contains('0'));
    }

    #[tokio::test]
    async fn row_absent_marker_present_refuses_to_start() {
        // Control DB wiped, bucket kept: there is no row, but the marker
        // claims ownership. Refuse before the uploader starts.
        let conn = fresh_conn().await;
        let foreign = StoreId::parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let io = FakeIo::with_body(foreign.as_str().as_bytes().to_vec());
        let err = pair_owner_marker(&conn, &io).await.unwrap_err();
        assert!(matches!(
            err,
            ShadowBuildError::OwnerRowMissingMarkerPresent
        ));
    }

    /// The runtime future of an off gate: never polled.
    async fn never() -> Result<ShadowRuntime, ShadowBuildError> {
        panic!("the runtime is built only when the gate is on")
    }

    fn allow(spaces: &[&str]) -> SpaceAllowlist {
        SpaceAllowlist::new(spaces.iter().map(|s| s.to_string()))
    }

    #[tokio::test]
    async fn disabled_flag_builds_no_handle_and_touches_no_io() {
        let conn = fresh_conn().await;
        let io = FakeIo::new();
        let handle = maybe_build(false, allow(&["tinycloud:x"]), &conn, &io, never())
            .await
            .unwrap();
        assert!(handle.is_none());
        assert_eq!(io.puts(), 0);
    }

    #[tokio::test]
    async fn empty_allowlist_builds_no_handle_and_touches_no_io() {
        let conn = fresh_conn().await;
        let io = FakeIo::new();
        let handle = maybe_build(true, allow(&[]), &conn, &io, never())
            .await
            .unwrap();
        assert!(handle.is_none());
        assert_eq!(io.puts(), 0);
    }

    const SPACE: &str = "tinycloud:pkh:eip155:1:0xAb://default";

    #[tokio::test]
    async fn enabled_with_non_empty_allowlist_bootstraps_and_drains_caught_up() {
        use tinycloud_core::database_artifacts::{
            ArtifactExpectation, SeaOrmDatabaseArtifactRepository,
        };
        use tinycloud_core::sql::store::shadow::metrics::NoopMetrics;
        use tinycloud_core::sql::store::{DbRef, MemorySqlObjectStore, SqlManifest};

        // One connection: every user sees the same in-memory database.
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let artifacts = Arc::new(SeaOrmDatabaseArtifactRepository::new(conn.clone()));
        let saved = artifacts
            .save(
                "sql",
                SPACE,
                "main",
                bytes::Bytes::from_static(b"checkpoint"),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let store = Arc::new(MemorySqlObjectStore::default());
        let scratch = tempfile::tempdir().unwrap();
        let io = FakeIo::new();
        let runtime = ShadowRuntime {
            store: store.clone(),
            artifacts,
            scratch_dir: scratch.path().join("shadow"),
            scratch_bytes: 1 << 20,
            scheduler: SchedulerConfig {
                policy: tinycloud_core::sql::store::shadow::machine::Policy {
                    interval: Duration::ZERO,
                    ..Default::default()
                },
                tick: Duration::from_millis(5),
                ..SchedulerConfig::default()
            },
            metrics: Arc::new(NoopMetrics),
        };
        let handle = maybe_build(true, allow(&[SPACE]), &conn, &io, async { Ok(runtime) })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(io.puts(), 1);
        assert_eq!(
            io.marker.lock().unwrap().as_deref(),
            Some(handle.owner.as_str().as_bytes())
        );
        // The startup lag scan bootstraps the database with no notice.
        let manifest = DbSqlManifest::new(conn.clone());
        let db = DbRef {
            space: SPACE,
            db_id: "main",
        };
        let frontier = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(f) = manifest.current(&db).await.unwrap() {
                    return f;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the startup scan bootstraps the database");
        assert_eq!(frontier.last_seq, saved.revision as u64);
        assert_eq!(frontier.base_checkpoint_cid, saved.checkpoint_content_hash);
        assert_eq!(
            store.bytes(&frontier.base_snapshot_key).unwrap(),
            b"checkpoint"
        );
        let report = handle.drain(Duration::from_secs(5)).await;
        assert_eq!(report.abandoned_jobs, 0);
        assert!(report.databases.iter().all(|d| d.caught_up()), "{report:?}");
    }

    #[tokio::test]
    async fn owner_marker_key_matches_the_contract() {
        assert_eq!(OWNER_MARKER_KEY, "sql/v1/_owner/v1");
    }
}

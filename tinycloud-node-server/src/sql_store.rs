//! Runtime wiring for the SQL-store shadow uploader.
//!
//! This module is the single integration seam between the shadow uploader
//! (lives in `tinycloud-core::sql::store::shadow`) and the node's runtime.
//! It builds a [`ShadowHandle`] only when `[sql_store] enabled` is true and
//! at least one space is in the allowlist; otherwise it returns `None` and
//! the node pays nothing.
//!
//! Ships off. The shutdown drain and catch-up path are not implemented yet,
//! which is a known break for any database the uploader has not already
//! captured. Uploading databases unencrypted is not cleared yet, so the
//! build-level gate refuses to enable the store until a later change lifts
//! both.
//!
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
//! - The shadow sink itself is `NoopSink` until the uploader run loop
//!   lands. That lets the node wiring exist and be tested on its own
//!   merits without coupling the integration gate to uploader iteration.
//!
//! TC-1491.

use std::sync::Arc;

use std::future::Future;
use std::pin::Pin;

use tinycloud_core::sql::store::{
    shadow::{
        ingress::IngressSink,
        owner::{self, BootOutcome, OwnerMarkerError, StoreId, OWNER_OBJECT_KEY},
        runloop::RunState,
    },
    ShadowSink,
};

/// Everything the runtime holds to keep the shadow uploader alive for the
/// process's lifetime. The handle's `Drop` releases every background task.
///
/// Carries the [`ShadowSink`] wired into `SqlService`, the resolved
/// owner-marker identity, the [`RunState`] the uploader keeps, and the
/// scratch directory the bootstrap writes its temp SQLite file under.
/// The scratch directory MUST live under the node's SQL data
/// directory so a bootstrap of a large database counts against the
/// 1a `DiskBudget` and the node's configured minimum free headroom.
pub struct ShadowHandle {
    pub sink: Arc<dyn ShadowSink>,
    pub owner: StoreId,
    pub run_state: Arc<RunState>,
    pub scratch_dir: std::path::PathBuf,
}

impl ShadowHandle {
    /// A shallow clone of the sink Arc, for `SqlService::with_shadow`.
    pub fn sink(&self) -> Arc<dyn ShadowSink> {
        Arc::clone(&self.sink)
    }
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

    /// Write `body` to the marker object exactly once, using `put_if_absent`
    /// semantics. If the object exists with a different body the
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
///    `put_if_absent` the marker with that body.
/// 5. If both are present, compare: match returns `Ok`, mismatch refuses.
/// 6. If the row is present and the marker is absent (fresh bucket,
///    retained control DB), `put_if_absent` the marker with the row's ID.
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

/// Build the shadow uploader handle if the flag and the allowlist
/// permit; return `None` otherwise. Used by `resolve_runtime`.
///
/// On a non-empty allowlist this function does three things:
///
/// 1. Pairs the owner marker. A mismatch refuses the start.
/// 2. Allocates a [`RunState`] carrying the per-DB state map, the
///    node-wide publish-cycle semaphore, the Postgres-concurrency
///    semaphore and the allowlist. The capture hook writes into this
///    through the returned [`IngressSink`].
/// 3. Creates the scratch directory under the node's SQL data
///    directory so bootstrap, catch-up and restore operations charge
///    their disk bytes to the 1a `DiskBudget`.
///
/// The returned handle is wired into `SqlService::with_shadow` at the
/// caller's `resolve_runtime` seam. The timer loop that drives the
/// uploader off `run_state` arrives in a sibling commit.
pub async fn maybe_build<I: OwnerMarkerIo>(
    enabled: bool,
    allowlist_empty: bool,
    conn: &tinycloud_core::sea_orm::DatabaseConnection,
    io: &I,
    config: MaybeBuildConfig<'_>,
) -> Result<Option<ShadowHandle>, ShadowBuildError> {
    if !enabled || allowlist_empty {
        return Ok(None);
    }
    let owner = pair_owner_marker(conn, io).await?;
    let scratch_dir = config.sql_data_dir.join("sql-store-scratch");
    std::fs::create_dir_all(&scratch_dir)
        .map_err(|e| ShadowBuildError::System(format!("create scratch dir: {e}")))?;
    let allowlist: std::collections::BTreeSet<String> =
        config.allowlist.iter().map(|s| s.to_string()).collect();
    let run_state = Arc::new(RunState::new(
        config.node_concurrency,
        config.pg_concurrency,
        allowlist,
    ));
    let sink: Arc<dyn ShadowSink> = Arc::new(IngressSink::new(Arc::clone(&run_state)));
    Ok(Some(ShadowHandle {
        sink,
        owner,
        run_state,
        scratch_dir,
    }))
}

/// Inputs to [`maybe_build`] besides the flag and the IO. The node's
/// `resolve_runtime` fills these from `[sql_store]` and the resolved
/// storage configuration.
pub struct MaybeBuildConfig<'a> {
    /// `{datadir}/sql` typically. Scratch lives at
    /// `{sql_data_dir}/sql-store-scratch`.
    pub sql_data_dir: &'a std::path::Path,
    pub allowlist: &'a [String],
    pub node_concurrency: usize,
    pub pg_concurrency: usize,
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
                        // Same body: idempotent under put_if_absent.
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

    fn test_config() -> MaybeBuildConfig<'static> {
        use std::path::Path;
        use std::sync::OnceLock;
        // Keep the TempDir alive for the process so the path stays valid.
        static SCRATCH: OnceLock<tempfile::TempDir> = OnceLock::new();
        static ALLOWLIST: OnceLock<Vec<String>> = OnceLock::new();
        let scratch = SCRATCH.get_or_init(|| tempfile::TempDir::new().unwrap());
        let allowlist = ALLOWLIST.get_or_init(|| vec!["tc:test".into()]);
        MaybeBuildConfig {
            sql_data_dir: scratch.path() as &Path,
            allowlist: allowlist.as_slice(),
            node_concurrency: 8,
            pg_concurrency: 2,
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

    #[tokio::test]
    async fn disabled_flag_builds_no_handle_and_touches_no_io() {
        let conn = fresh_conn().await;
        let io = FakeIo::new();
        let handle = maybe_build(false, true, &conn, &io, test_config())
            .await
            .unwrap();
        assert!(handle.is_none());
        assert_eq!(io.puts(), 0);
    }

    #[tokio::test]
    async fn empty_allowlist_builds_no_handle_and_touches_no_io() {
        let conn = fresh_conn().await;
        let io = FakeIo::new();
        let handle = maybe_build(true, true, &conn, &io, test_config())
            .await
            .unwrap();
        assert!(handle.is_none());
        assert_eq!(io.puts(), 0);
    }

    #[tokio::test]
    async fn enabled_with_non_empty_allowlist_builds_a_handle_and_writes_marker() {
        let conn = fresh_conn().await;
        let io = FakeIo::new();
        let handle = maybe_build(true, false, &conn, &io, test_config())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(io.puts(), 1);
        assert_eq!(
            io.marker.lock().unwrap().as_deref(),
            Some(handle.owner.as_str().as_bytes())
        );
    }

    #[tokio::test]
    async fn owner_marker_key_matches_the_contract() {
        assert_eq!(OWNER_MARKER_KEY, "sql/v1/_owner/v1");
    }
}

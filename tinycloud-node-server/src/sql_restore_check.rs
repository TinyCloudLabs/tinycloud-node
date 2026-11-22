//! `tinycloud node sql-store restore-check` (TC-1491 P2): the restore check
//! over a sample of the allowlisted databases.
//!
//! The check itself lives in `tinycloud_core::sql::store::shadow::restore`:
//! per database it restores the published frontier into scratch, replays it,
//! runs `integrity_check`, and compares the SHA-256 of the materialised file
//! with Postgres's artifact at the same revision. This module wires it to the
//! node's configuration: the control database, the SQL object store of the
//! configured block backend, the Postgres artifact repository, a scratch
//! budget, and Prometheus metrics written as a node-exporter textfile.
//!
//! The command reads `[sql_store] spaces` as the allowlist whether or not the
//! store is enabled; it never needs (and the build still refuses)
//! `[sql_store] enabled`. It writes nothing outside its scratch directory and
//! the metrics file.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};
use rand::{rngs::StdRng, SeedableRng};
use tinycloud_core::database_artifacts::{chunks::ChunkLimits, SeaOrmDatabaseArtifactRepository};
use tinycloud_core::sql::store::{
    shadow::{
        budget::DiskBudget,
        metrics::{
            RestoreMetrics, RestoreResult, RESTORE_CHECKS_TOTAL, RESTORE_CHECK_SECONDS,
            RESTORE_SEGMENTS_UNVERIFIED_TOTAL,
        },
        restore::{check_databases, sample_databases, RestoreDeps, RunReport},
        source::PgArtifactSource,
    },
    SqlObjectStore,
};

use crate::config::Config;
use crate::space_purge_executor::PurgeSqlObjects;

/// Manifest ids read per page while sampling.
const SAMPLE_PAGE: u64 = 500;

/// What the command was asked to do.
#[derive(Debug, Clone)]
pub struct RestoreCheckOptions {
    /// Databases to check, chosen uniformly over the allowlisted spaces.
    pub sample: usize,
    /// Seed for the sample; `None` draws one from the OS.
    pub seed: Option<u64>,
    /// Where the scratch copies go.
    pub scratch_dir: PathBuf,
    /// Bytes the scratch copies may hold at once.
    pub scratch_bytes: u64,
    /// Prometheus textfile to write the run's metrics to.
    pub metrics_file: Option<PathBuf>,
}

/// Run the check against the node's configured databases and stores.
pub async fn run(config: &Config, options: &RestoreCheckOptions) -> Result<RunReport> {
    let spaces = &config.sql_store.spaces;
    anyhow::ensure!(
        !spaces.is_empty(),
        "[sql_store] spaces is empty: no database is allowlisted for the restore check"
    );
    let conn = crate::connect_database(config).await?;
    let store: Arc<dyn SqlObjectStore> = match PurgeSqlObjects::open(&config.storage).await? {
        PurgeSqlObjects::S3(store) => Arc::new(store),
        PurgeSqlObjects::FileSystem(store) => Arc::new(store),
    };
    let sql = &config.storage.sql;
    let artifacts = SeaOrmDatabaseArtifactRepository::new(conn.clone())
        .with_max_read_bytes(sql.max_artifact_read_bytes.as_u64())
        .with_chunk_limits(sql.chunked_artifacts.then_some(ChunkLimits {
            artifact_bytes: sql.chunked_artifact_max_bytes,
            account_bytes: sql.chunked_account_max_bytes,
        }));
    std::fs::create_dir_all(&options.scratch_dir)
        .with_context(|| format!("scratch directory {}", options.scratch_dir.display()))?;
    let metrics = Arc::new(PrometheusRestoreMetrics::new()?);
    let deps = RestoreDeps {
        control: conn.sea_orm_connection().clone(),
        store,
        source: Arc::new(PgArtifactSource::new(Arc::new(artifacts))),
        disk: DiskBudget::new(options.scratch_dir.clone(), options.scratch_bytes),
        metrics: metrics.clone(),
    };
    let report = check_sample(&deps, spaces, options.sample, options.seed).await?;
    if let Some(path) = &options.metrics_file {
        metrics.write_textfile(path)?;
    }
    Ok(report)
}

/// Sample up to `sample` databases from `spaces` and check each.
pub async fn check_sample(
    deps: &RestoreDeps,
    spaces: &[String],
    sample: usize,
    seed: Option<u64>,
) -> Result<RunReport> {
    let mut rng = match seed {
        Some(seed) => StdRng::seed_from_u64(seed),
        None => StdRng::from_entropy(),
    };
    let databases = sample_databases(&deps.control, spaces, sample, SAMPLE_PAGE, &mut rng)
        .await
        .context("sampling the manifest")?;
    Ok(check_databases(deps, &databases).await)
}

/// The run's metrics in a registry of their own (the CLI is not the server
/// and has no `/metrics`); written out as a node-exporter textfile.
pub struct PrometheusRestoreMetrics {
    registry: Registry,
    checks: IntCounterVec,
    segments_unverified: IntCounter,
    seconds: Histogram,
}

impl PrometheusRestoreMetrics {
    pub fn new() -> Result<Self> {
        let checks = IntCounterVec::new(
            Opts::new(
                RESTORE_CHECKS_TOTAL,
                "SQL-store restore checks by result (ok, mismatch, not_comparable, unreadable).",
            ),
            &["result"],
        )?;
        for result in RestoreResult::ALL {
            checks.with_label_values(&[result.label()]);
        }
        let segments_unverified = IntCounter::new(
            RESTORE_SEGMENTS_UNVERIFIED_TOTAL,
            "Segments a checked frontier needs that the restore check did not verify.",
        )?;
        let seconds = Histogram::with_opts(
            HistogramOpts::new(
                RESTORE_CHECK_SECONDS,
                "Seconds one database's restore check took.",
            )
            .buckets(vec![0.1, 0.5, 1.0, 5.0, 15.0, 60.0, 300.0, 900.0]),
        )?;
        let registry = Registry::new();
        registry.register(Box::new(checks.clone()))?;
        registry.register(Box::new(segments_unverified.clone()))?;
        registry.register(Box::new(seconds.clone()))?;
        Ok(Self {
            registry,
            checks,
            segments_unverified,
            seconds,
        })
    }

    /// The metrics in the Prometheus text format.
    pub fn encode(&self) -> Result<String> {
        let mut out = Vec::new();
        TextEncoder::new().encode(&self.registry.gather(), &mut out)?;
        Ok(String::from_utf8(out)?)
    }

    /// Write [`Self::encode`] to `path` through a temporary file and a rename,
    /// so a collector never reads half a file.
    pub fn write_textfile(&self, path: &Path) -> Result<()> {
        let mut temp = path.as_os_str().to_owned();
        temp.push(".tmp");
        let temp = PathBuf::from(temp);
        std::fs::write(&temp, self.encode()?)
            .with_context(|| format!("metrics file {}", temp.display()))?;
        std::fs::rename(&temp, path).with_context(|| format!("metrics file {}", path.display()))?;
        Ok(())
    }
}

impl RestoreMetrics for PrometheusRestoreMetrics {
    fn restore_check(&self, result: RestoreResult, segments_unverified: u64, seconds: f64) {
        self.checks.with_label_values(&[result.label()]).inc();
        self.segments_unverified.inc_by(segments_unverified);
        self.seconds.observe(seconds);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tinycloud_core::database_artifacts::{ArtifactExpectation, DatabaseArtifactRepository};
    use tinycloud_core::migrations::Migrator;
    use tinycloud_core::sea_orm::{ConnectOptions, Database, DatabaseConnection};
    use tinycloud_core::sea_orm_migration::MigratorTrait;
    use tinycloud_core::sql::store::{
        shadow::{
            machine::Policy,
            metrics::NoopMetrics,
            scheduler::{self, SchedulerConfig, ShadowDeps},
            NoticeBoard,
        },
        DbRef, DbSqlManifest, MemorySqlObjectStore, SpaceAllowlist, SqlManifest,
    };

    const SPACE: &str = "tinycloud:pkh:eip155:1:0xAb://default";

    /// A SQLite checkpoint and the cumulative WAL of later commits, made the
    /// way the node makes them (WAL mode, autocheckpoint off, TRUNCATE).
    fn sqlite_artifact() -> (Vec<u8>, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("live.db");
        let conn = rusqlite::Connection::open(&path).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA wal_autocheckpoint = 0;
             CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL);
             INSERT INTO t (v) VALUES ('one');",
        )
        .unwrap();
        conn.query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| {
            r.get::<_, i64>(0)
        })
        .unwrap();
        let checkpoint = std::fs::read(&path).unwrap();
        for v in ["two", "three"] {
            conn.execute("INSERT INTO t (v) VALUES (?1)", [v]).unwrap();
        }
        let mut wal = path.as_os_str().to_owned();
        wal.push("-wal");
        (checkpoint, std::fs::read(PathBuf::from(wal)).unwrap())
    }

    struct Rig {
        conn: DatabaseConnection,
        artifacts: Arc<SeaOrmDatabaseArtifactRepository>,
        store: Arc<MemorySqlObjectStore>,
        scratch: tempfile::TempDir,
    }

    async fn rig() -> Rig {
        // One connection: every user sees the same in-memory database.
        let mut options = ConnectOptions::new("sqlite::memory:".to_string());
        options.max_connections(1).sqlx_logging(false);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        Rig {
            artifacts: Arc::new(SeaOrmDatabaseArtifactRepository::new(conn.clone())),
            conn,
            store: Arc::new(MemorySqlObjectStore::default()),
            scratch: tempfile::tempdir().unwrap(),
        }
    }

    impl Rig {
        /// Save a checkpoint plus WAL for `db_id` in Postgres's place and run
        /// the uploader until its frontier is at the saved revision.
        async fn shadowed(&self, db_id: &str) -> i64 {
            let (checkpoint, wal) = sqlite_artifact();
            let base = self
                .artifacts
                .save(
                    "sql",
                    SPACE,
                    db_id,
                    bytes::Bytes::from(checkpoint),
                    ArtifactExpectation::Absent,
                )
                .await
                .unwrap();
            let head = self
                .artifacts
                .save_delta(
                    "sql",
                    SPACE,
                    db_id,
                    bytes::Bytes::from(wal),
                    ArtifactExpectation::Derived {
                        revision: base.revision,
                        checkpoint_content_hash: base.checkpoint_content_hash,
                    },
                )
                .await
                .unwrap();
            let upload_scratch = tempfile::tempdir().unwrap();
            let handle = scheduler::spawn(
                ShadowDeps {
                    control: self.conn.clone(),
                    manifest: Arc::new(DbSqlManifest::new(self.conn.clone())),
                    store: self.store.clone(),
                    source: Arc::new(PgArtifactSource::new(self.artifacts.clone())),
                    disk: DiskBudget::new(upload_scratch.path(), 1 << 24),
                    board: Arc::new(NoticeBoard::new(
                        SpaceAllowlist::new([SPACE.to_string()]),
                        Arc::new(NoopMetrics),
                    )),
                    metrics: Arc::new(NoopMetrics),
                },
                SchedulerConfig {
                    policy: Policy {
                        interval: Duration::ZERO,
                        ..Default::default()
                    },
                    tick: Duration::from_millis(5),
                    ..SchedulerConfig::default()
                },
            );
            let manifest = DbSqlManifest::new(self.conn.clone());
            let db = DbRef {
                space: SPACE,
                db_id,
            };
            tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    if let Some(f) = manifest.current(&db).await.unwrap() {
                        if f.last_seq >= head.revision as u64 {
                            return;
                        }
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .expect("the uploader reaches the saved revision");
            handle.drain(Duration::from_secs(5)).await;
            head.revision
        }

        fn deps(&self, metrics: Arc<PrometheusRestoreMetrics>) -> RestoreDeps {
            RestoreDeps {
                control: self.conn.clone(),
                store: self.store.clone(),
                source: Arc::new(PgArtifactSource::new(self.artifacts.clone())),
                disk: DiskBudget::new(self.scratch.path(), 1 << 24),
                metrics,
            }
        }
    }

    #[tokio::test]
    async fn a_sampled_run_reports_and_counts_each_database() {
        let rig = rig().await;
        rig.shadowed("main").await;
        rig.shadowed("second").await;
        // Postgres moves past the second database's frontier.
        let head = rig
            .artifacts
            .load_meta("sql", SPACE, "second")
            .await
            .unwrap()
            .unwrap();
        let (_, wal) = sqlite_artifact();
        rig.artifacts
            .save_delta(
                "sql",
                SPACE,
                "second",
                bytes::Bytes::from(wal),
                ArtifactExpectation::Derived {
                    revision: head.revision,
                    checkpoint_content_hash: head.checkpoint_content_hash,
                },
            )
            .await
            .unwrap();
        let metrics = Arc::new(PrometheusRestoreMetrics::new().unwrap());
        let report = check_sample(
            &rig.deps(metrics.clone()),
            &[SPACE.to_string()],
            10,
            Some(1),
        )
        .await
        .unwrap();
        assert_eq!(
            (
                report.sampled,
                report.ok,
                report.not_comparable,
                report.mismatch,
                report.unreadable
            ),
            (2, 1, 1, 0, 0),
            "{report:?}"
        );
        assert!(report.passed(), "not_comparable does not fail the run");
        assert_eq!(report.segments_unverified, 1);

        // The JSON report: verdicts and reasons, no payload.
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["databases"][0]["db_id"], "main");
        assert_eq!(json["databases"][0]["result"], "ok");
        assert_eq!(json["databases"][1]["result"], "not_comparable");

        // The textfile.
        let file = rig.scratch.path().join("restore.prom");
        metrics.write_textfile(&file).unwrap();
        let text = std::fs::read_to_string(&file).unwrap();
        for line in [
            "sql_store_restore_checks_total{result=\"ok\"} 1",
            "sql_store_restore_checks_total{result=\"not_comparable\"} 1",
            "sql_store_restore_checks_total{result=\"mismatch\"} 0",
            "sql_store_restore_checks_total{result=\"unreadable\"} 0",
            "sql_store_restore_segments_unverified_total 1",
            "sql_store_restore_check_seconds_count 2",
        ] {
            assert!(text.lines().any(|l| l == line), "{line} missing:\n{text}");
        }
        assert!(!text.contains(SPACE) && !text.contains("main"));
    }

    #[tokio::test]
    async fn the_sample_size_bounds_the_run() {
        let rig = rig().await;
        rig.shadowed("a").await;
        rig.shadowed("b").await;
        rig.shadowed("c").await;
        let metrics = Arc::new(PrometheusRestoreMetrics::new().unwrap());
        let report = check_sample(&rig.deps(metrics), &[SPACE.to_string()], 2, Some(9))
            .await
            .unwrap();
        assert_eq!((report.sampled, report.ok), (2, 2), "{report:?}");
    }
}

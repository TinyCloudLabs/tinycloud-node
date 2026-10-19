//! Shared helpers for tinycloud-core's own tests.

/// Resolve the PostgreSQL URL that the `postgres_*` regressions run against.
///
/// TC-381: these tests used to `return` silently whenever
/// `TINYCLOUD_TEST_POSTGRES_URL` was unset. Combined with a CI command that
/// filtered on the name `postgres_` — and libtest exiting 0 when a filter
/// matches nothing — the whole PostgreSQL job could report green having
/// asserted nothing at all, twice over. A test that no-ops in silence is worse
/// than no test, because it manufactures confidence.
///
/// So: skipping stays available locally, where not everyone wants to run a
/// PostgreSQL server just to `cargo test`, but in CI (`CI` is always set by
/// GitHub Actions) a missing URL is a hard failure rather than a shrug.
pub(crate) fn postgres_test_url(test: &str) -> Option<String> {
    match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            if std::env::var_os("CI").is_some() {
                panic!(
                    "{test} requires TINYCLOUD_TEST_POSTGRES_URL, which is unset (or empty) in CI. \
                     This test must not be allowed to skip on CI — see TC-381. Check the \
                     `postgres` service container and the `env:` block in .github/workflows/rust.yml."
                );
            }
            eprintln!(
                "skipping {test}: TINYCLOUD_TEST_POSTGRES_URL is unset (set it to run this \
                 locally; it is mandatory in CI)"
            );
            None
        }
    }
}

/// A migrated connection to a throwaway schema on the
/// `TINYCLOUD_TEST_POSTGRES_URL` database (`search_path` is that schema). The
/// schema is dropped when this goes out of scope, including while a failed
/// assertion unwinds. `Drop` cannot await, so the drop runs on its own thread
/// and runtime and is joined before the test returns.
pub(crate) struct PostgresTestSchema {
    pub(crate) conn: sea_orm::DatabaseConnection,
    url: String,
    schema: String,
}

impl PostgresTestSchema {
    /// `None` (skip) only where `postgres_test_url` allows it: never in CI.
    pub(crate) async fn new(test: &str) -> Option<Self> {
        Self::migrated_through(test, None).await
    }

    /// Like [`Self::new`], but applies only the first `steps` migrations
    /// (all of them when `None`), so a test can start from an older release's
    /// schema.
    pub(crate) async fn migrated_through(test: &str, steps: Option<u32>) -> Option<Self> {
        use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
        use sea_orm_migration::MigratorTrait;

        let url = postgres_test_url(test)?;
        // Two tests of one process can read the same clock tick, so the name also
        // carries a process-wide counter.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let schema = format!(
            "tc_test_{}_{}_{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let admin = Database::connect(sea_orm::ConnectOptions::new(url.clone()))
            .await
            .expect("connect to PostgreSQL test database");
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .expect("create isolated test schema");
        admin.close().await.expect("close admin connection");
        let mut fixture = Self {
            conn: Default::default(),
            url,
            schema,
        };
        fixture.conn = fixture.connect(4).await;
        crate::migrations::Migrator::up(&fixture.conn, steps)
            .await
            .expect("migrate isolated test schema");
        Some(fixture)
    }

    /// Another pool of `max_connections` on the same isolated schema.
    pub(crate) async fn connect(&self, max_connections: u32) -> sea_orm::DatabaseConnection {
        let mut options = sea_orm::ConnectOptions::new(self.url.clone());
        options
            .max_connections(max_connections)
            .sqlx_logging(false)
            .set_schema_search_path(self.schema.clone());
        sea_orm::Database::connect(options)
            .await
            .expect("connect to isolated test schema")
    }
}

impl Drop for PostgresTestSchema {
    fn drop(&mut self) {
        use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};

        let (url, schema) = (self.url.clone(), self.schema.clone());
        let dropped = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("schema drop runtime")
                .block_on(async move {
                    Database::connect(ConnectOptions::new(url))
                        .await?
                        .execute(Statement::from_string(
                            DbBackend::Postgres,
                            format!("DROP SCHEMA IF EXISTS {schema} CASCADE"),
                        ))
                        .await
                        .map(|_| ())
                })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!("failed to drop isolated test schema {}", self.schema);
        }
    }
}

pub(crate) mod did_resolution {
    include!("../tests/support/did_resolution.rs");
}

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
        use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};
        use sea_orm_migration::MigratorTrait;

        let url = postgres_test_url(test)?;
        let schema = format!(
            "tc_test_{}_{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let admin = Database::connect(ConnectOptions::new(url.clone()))
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
        let mut options = ConnectOptions::new(url.clone());
        options
            .max_connections(4)
            .sqlx_logging(false)
            .set_schema_search_path(schema.clone());
        let conn = Database::connect(options)
            .await
            .expect("connect to isolated test schema");
        let fixture = Self { conn, url, schema };
        crate::migrations::Migrator::up(&fixture.conn, None)
            .await
            .expect("migrate isolated test schema");
        Some(fixture)
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

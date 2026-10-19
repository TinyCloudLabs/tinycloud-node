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

/// A name no other fixture of this run has: the clock alone is not enough,
/// two tests starting together can read the same instant (a duplicate
/// `CREATE DATABASE` / `CREATE SCHEMA` fails the test), so a process-wide
/// counter breaks the tie.
fn unique_name(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    format!(
        "{prefix}_{}_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
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
        let schema = unique_name("tc_test");
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

/// A migrated connection to a throwaway DATABASE on the server behind
/// `TINYCLOUD_TEST_POSTGRES_URL`, dropped (with its sessions) when this goes
/// out of scope.
///
/// Use this instead of [`PostgresTestSchema`] for tests that run
/// `CREATE INDEX CONCURRENTLY`, or that hold a transaction open while one
/// runs. That statement waits for every open transaction of its *database*
/// that predates its snapshots, whatever schema they work in: in the shared
/// test database it queues behind the other tests' long migration
/// transactions (and they behind it, under enough parallelism), which looks
/// like a hang. A database of its own can only wait on its own test.
pub(crate) struct PostgresTestDatabase {
    pub(crate) conn: sea_orm::DatabaseConnection,
    admin_url: String,
    url: String,
    name: String,
}

impl PostgresTestDatabase {
    /// Like [`PostgresTestSchema::migrated_through`], in a database of its own.
    pub(crate) async fn migrated_through(test: &str, steps: Option<u32>) -> Option<Self> {
        use sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
        use sea_orm_migration::MigratorTrait;

        let admin_url = postgres_test_url(test)?;
        let name = unique_name("tc_test_db");
        let admin = Database::connect(sea_orm::ConnectOptions::new(admin_url.clone()))
            .await
            .expect("connect to PostgreSQL test server");
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE DATABASE {name}"),
            ))
            .await
            .expect("create isolated test database");
        admin.close().await.expect("close admin connection");
        let mut fixture = Self {
            conn: Default::default(),
            url: url_with_database(&admin_url, &name),
            admin_url,
            name,
        };
        fixture.conn = fixture.connect(4).await;
        crate::migrations::Migrator::up(&fixture.conn, steps)
            .await
            .expect("migrate isolated test database");
        Some(fixture)
    }

    /// The database's name; unique per fixture, so usable in cluster-wide
    /// names such as roles.
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// Another pool of `max_connections` on the same isolated database.
    pub(crate) async fn connect(&self, max_connections: u32) -> sea_orm::DatabaseConnection {
        let mut options = sea_orm::ConnectOptions::new(self.url.clone());
        options.max_connections(max_connections).sqlx_logging(false);
        sea_orm::Database::connect(options)
            .await
            .expect("connect to isolated test database")
    }
}

impl Drop for PostgresTestDatabase {
    fn drop(&mut self) {
        use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement};

        let (url, name) = (self.admin_url.clone(), self.name.clone());
        let dropped = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("database drop runtime")
                .block_on(async move {
                    Database::connect(ConnectOptions::new(url))
                        .await?
                        .execute(Statement::from_string(
                            DbBackend::Postgres,
                            format!("DROP DATABASE IF EXISTS {name} WITH (FORCE)"),
                        ))
                        .await
                        .map(|_| ())
                })
        })
        .join();
        if !matches!(dropped, Ok(Ok(()))) {
            eprintln!("failed to drop isolated test database {}", self.name);
        }
    }
}

/// `url` with its database name replaced, keeping credentials and query.
fn url_with_database(url: &str, database: &str) -> String {
    let authority_end = url
        .find("://")
        .and_then(|scheme| url[scheme + 3..].find('/').map(|slash| scheme + 3 + slash))
        .expect("TINYCLOUD_TEST_POSTGRES_URL names a database");
    let query = url[authority_end..]
        .find('?')
        .map_or("", |at| &url[authority_end + at..]);
    format!("{}/{database}{query}", &url[..authority_end])
}

/// Typed log events captured from the `tracing` calls a test makes.
///
/// A thread-scoped subscriber can miss events while other threads of this
/// parallel test process register the same callsites, so this installs one
/// process-wide subscriber (first use) that records the WARN and ERROR
/// events carrying an `event` field. Nothing else in the library's tests
/// installs a subscriber. [`capture_events`] serializes its callers, so a
/// test sees only the events of its own run.
pub(crate) mod events {
    use std::sync::{Arc, Mutex, OnceLock};
    use tracing_subscriber::{filter::LevelFilter, layer::SubscriberExt, Layer};

    #[derive(Clone, Debug)]
    pub(crate) struct CapturedEvent {
        pub(crate) level: tracing::Level,
        /// The `event` field.
        pub(crate) event: String,
        /// The log message.
        pub(crate) message: String,
        /// Every other field, rendered, for tests that look for leaked data.
        pub(crate) fields: String,
    }

    #[derive(Default)]
    struct Fields {
        event: Option<String>,
        message: String,
        others: String,
    }

    impl tracing::field::Visit for Fields {
        fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
            if field.name() == "event" {
                self.event = Some(value.to_string());
            } else {
                self.record_debug(field, &value);
            }
        }
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.message = format!("{value:?}");
            } else {
                self.others
                    .push_str(&format!("{}={value:?} ", field.name()));
            }
        }
    }

    struct Capture(Arc<Mutex<Vec<CapturedEvent>>>);

    impl<S: tracing::Subscriber> Layer<S> for Capture {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let mut fields = Fields::default();
            event.record(&mut fields);
            if let Some(name) = fields.event {
                self.0.lock().unwrap().push(CapturedEvent {
                    level: *event.metadata().level(),
                    event: name,
                    message: fields.message,
                    fields: fields.others,
                });
            }
        }
    }

    static STORE: OnceLock<Arc<Mutex<Vec<CapturedEvent>>>> = OnceLock::new();
    static ONE_CAPTURE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Run `run`, and return its output with the captured events whose
    /// `event` starts with `prefix`, in order.
    pub(crate) async fn capture_events<F: std::future::Future>(
        prefix: &str,
        run: F,
    ) -> (F::Output, Vec<CapturedEvent>) {
        let _alone = ONE_CAPTURE_AT_A_TIME.lock().await;
        let store = STORE.get_or_init(|| {
            let store = Arc::new(Mutex::new(Vec::new()));
            tracing::subscriber::set_global_default(
                tracing_subscriber::registry()
                    .with(Capture(store.clone()).with_filter(LevelFilter::WARN)),
            )
            .expect("another tracing subscriber is already the process default");
            store
        });
        store.lock().unwrap().clear();
        let output = run.await;
        let captured = store
            .lock()
            .unwrap()
            .drain(..)
            .filter(|event| event.event.starts_with(prefix))
            .collect();
        (output, captured)
    }
}

pub(crate) mod did_resolution {
    include!("../tests/support/did_resolution.rs");
}

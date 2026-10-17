use std::sync::Arc;

use dashmap::DashMap;
use tinycloud_core::keys::StaticSecret;
use tinycloud_core::request_telemetry::{scope, RequestContext};
use tinycloud_core::sql::database::{spawn_actor, DatabaseHandle, GrowthPolicy};
use tinycloud_core::sql::types::{SqlError, SqlRequest};
use tinycloud_core::telemetry::Pseudonymizer;

fn request(id: &str) -> Arc<RequestContext> {
    RequestContext::new(
        id.parse().unwrap(),
        Arc::new(Pseudonymizer::new(
            &StaticSecret::new(vec![29; 32]).unwrap(),
        )),
    )
}

fn query(sql: &str) -> SqlRequest {
    SqlRequest::Query {
        sql: sql.into(),
        params: vec![],
        max_rows: None,
        max_bytes: None,
    }
}

async fn execute(actor: &DatabaseHandle, sql: &str) -> Result<(), SqlError> {
    actor
        .execute(
            query(sql),
            None,
            "tinycloud.sql/read".into(),
            GrowthPolicy::Allow,
        )
        .await
        .map(|_| ())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sqlite_actor_attributes_each_message_and_prepare_failure_to_its_request() {
    let directory = tempfile::tempdir().unwrap();
    let actor = spawn_actor(
        "telemetry".into(),
        "requests".into(),
        directory.path().to_str().unwrap().into(),
        u64::MAX,
        Arc::new(DashMap::new()),
    );
    // Warm the connection without a context, so connection setup is not part
    // of either request and the actor must not retain a creator's context.
    execute(&actor, "SELECT 0").await.unwrap();
    let first = request("11111111-1111-4111-8111-111111111111");
    let second = request("22222222-2222-4222-8222-222222222222");
    let first_work = scope(Arc::clone(&first), async {
        execute(&actor, "SELECT 1").await.unwrap();
        tokio::task::yield_now().await;
        execute(&actor, "SELECT * FROM absent_table")
            .await
            .expect_err("a valid statement that fails SQLite prepare still counts");
    });
    let second_work = scope(Arc::clone(&second), async {
        execute(&actor, "SELECT 2").await.unwrap();
        execute(&actor, "SELECT 3").await.unwrap();
    });
    futures::future::join(first_work, second_work).await;
    // Each success includes its SQL plus two real size-check PRAGMAs.
    assert_eq!(first.snapshot().query_count, 4);
    assert_eq!(second.snapshot().query_count, 6);
    assert!(first.snapshot().query_time_ns > 0);
    assert!(second.snapshot().query_time_ns > 0);
    assert_eq!(first.snapshot().pool_wait_ns, 0);
    assert_eq!(second.snapshot().pool_wait_ns, 0);
    let before = first.snapshot();
    execute(&actor, "SELECT 4").await.unwrap();
    assert_eq!(first.snapshot().query_count, before.query_count);
    assert_eq!(first.snapshot().query_time_ns, before.query_time_ns);
    drop(actor);
}

#[tokio::test]
async fn sqlite_rejects_before_prepare_without_counting_a_query() {
    let directory = tempfile::tempdir().unwrap();
    let actor = spawn_actor(
        "telemetry".into(),
        "validation".into(),
        directory.path().to_str().unwrap().into(),
        u64::MAX,
        Arc::new(DashMap::new()),
    );
    execute(&actor, "SELECT 0").await.unwrap();
    let context = request("33333333-3333-4333-8333-333333333333");
    scope(Arc::clone(&context), async {
        let error = actor
            .execute(
                SqlRequest::Query {
                    sql: "SELECT 1".into(),
                    params: vec![],
                    max_rows: Some(0),
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".into(),
                GrowthPolicy::Allow,
            )
            .await
            .unwrap_err();
        assert!(matches!(error, SqlError::InvalidStatement(_)));
        execute(&actor, "CREATE TABLE forbidden (value INTEGER)")
            .await
            .expect_err("read permission is rejected before SQLite prepare");
    })
    .await;
    assert_eq!(context.snapshot().query_count, 0);
    assert_eq!(context.snapshot().query_time_ns, 0);
    assert_eq!(context.snapshot().pool_wait_ns, 0);
    drop(actor);
}

#[tokio::test]
async fn sqlite_export_native_backup_is_not_a_sql_query_but_checkpoint_is() {
    let directory = tempfile::tempdir().unwrap();
    let actor = spawn_actor(
        "telemetry".into(),
        "maintenance".into(),
        directory.path().to_str().unwrap().into(),
        0,
        Arc::new(DashMap::new()),
    );
    actor
        .execute(
            SqlRequest::Execute {
                sql: "CREATE TABLE data (value INTEGER)".into(),
                schema: None,
                params: vec![],
            },
            None,
            "tinycloud.sql/admin".into(),
            GrowthPolicy::Allow,
        )
        .await
        .unwrap();
    let export = request("44444444-4444-4444-8444-444444444444");
    scope(Arc::clone(&export), actor.export()).await.unwrap();
    assert_eq!(export.snapshot().query_count, 0);
    assert_eq!(export.snapshot().query_time_ns, 0);
    let checkpoint = request("55555555-5555-4555-8555-555555555555");
    scope(Arc::clone(&checkpoint), actor.checkpoint())
        .await
        .unwrap();
    assert_eq!(checkpoint.snapshot().query_count, 1);
    assert!(checkpoint.snapshot().query_time_ns > 0);
    drop(actor);
}

#[tokio::test]
async fn sqlite_counts_schema_execution_errors_and_guard_controls() {
    let directory = tempfile::tempdir().unwrap();
    let actor = spawn_actor(
        "telemetry".into(),
        "controls".into(),
        directory.path().to_str().unwrap().into(),
        u64::MAX,
        Arc::new(DashMap::new()),
    );
    execute(&actor, "SELECT 0").await.unwrap();
    let context = request("99999999-9999-4999-8999-999999999999");
    scope(Arc::clone(&context), async {
        actor
            .execute(
                SqlRequest::Execute {
                    sql: "INSERT INTO data VALUES (1)".into(),
                    params: vec![],
                    schema: Some(vec!["CREATE TABLE data (value INTEGER UNIQUE)".into()]),
                },
                None,
                "tinycloud.sql/admin".into(),
                GrowthPolicy::Allow,
            )
            .await
            .unwrap();
    })
    .await;
    assert_eq!(context.snapshot().query_count, 4);
    let failed = request("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    scope(Arc::clone(&failed), async {
        actor
            .execute(
                SqlRequest::Execute {
                    sql: "INSERT INTO data VALUES (1)".into(),
                    params: vec![],
                    schema: None,
                },
                None,
                "tinycloud.sql/write".into(),
                GrowthPolicy::Allow,
            )
            .await
            .expect_err("a constraint failure is an execution attempt");
    })
    .await;
    assert_eq!(failed.snapshot().query_count, 1);
    assert!(failed.snapshot().query_time_ns > 0);
    let guarded = request("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    scope(
        Arc::clone(&guarded),
        actor.execute(
            query("SELECT value FROM data"),
            None,
            "tinycloud.sql/read".into(),
            GrowthPolicy::Forbid,
        ),
    )
    .await
    .unwrap();
    // Before/after page_count, savepoint/release, query, and size PRAGMAs.
    assert_eq!(guarded.snapshot().query_count, 7);
    assert!(guarded.snapshot().query_time_ns > 0);
    drop(actor);
}

#[cfg(feature = "duckdb")]
mod duckdb_tests {
    use super::*;
    use tinycloud_core::duckdb::database::{spawn_actor, DatabaseHandle};
    use tinycloud_core::duckdb::types::{DuckDbError, DuckDbRequest};

    async fn execute(actor: &DatabaseHandle, sql: &str) -> Result<(), DuckDbError> {
        actor
            .execute(
                DuckDbRequest::Query {
                    sql: sql.into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/read".into(),
                false,
                false,
            )
            .await
            .map(|_| ())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn duckdb_actor_isolates_messages_and_counts_prepare_errors() {
        let directory = tempfile::tempdir().unwrap();
        let actor = spawn_actor(
            "telemetry".into(),
            "requests".into(),
            directory.path().to_str().unwrap().into(),
            u64::MAX,
            1,
            "128MB".into(),
            Arc::new(DashMap::new()),
        );
        execute(&actor, "SELECT 0").await.unwrap();
        let first = request("66666666-6666-4666-8666-666666666666");
        let second = request("77777777-7777-4777-8777-777777777777");
        futures::future::join(
            scope(Arc::clone(&first), async {
                execute(&actor, "SELECT 1").await.unwrap();
                execute(&actor, "SELECT * FROM absent_table")
                    .await
                    .unwrap_err();
            }),
            scope(Arc::clone(&second), async {
                execute(&actor, "SELECT 2").await.unwrap();
                execute(&actor, "SELECT 3").await.unwrap();
            }),
        )
        .await;
        // Each successful query also executes the real database-size query.
        assert_eq!(first.snapshot().query_count, 3);
        assert_eq!(second.snapshot().query_count, 4);
        assert!(first.snapshot().query_time_ns > 0);
        assert!(second.snapshot().query_time_ns > 0);
        assert_eq!(first.snapshot().pool_wait_ns, 0);
        let before = second.snapshot();
        execute(&actor, "SELECT 4").await.unwrap();
        assert_eq!(second.snapshot().query_count, before.query_count);
        assert_eq!(second.snapshot().query_time_ns, before.query_time_ns);
        drop(actor);
    }

    #[tokio::test]
    async fn duckdb_parser_validation_does_not_count_sql() {
        let directory = tempfile::tempdir().unwrap();
        let actor = spawn_actor(
            "telemetry".into(),
            "validation".into(),
            directory.path().to_str().unwrap().into(),
            u64::MAX,
            1,
            "128MB".into(),
            Arc::new(DashMap::new()),
        );
        execute(&actor, "SELECT 0").await.unwrap();
        let context = request("88888888-8888-4888-8888-888888888888");
        scope(Arc::clone(&context), async {
            execute(&actor, "CREATE TABLE forbidden (value INTEGER)")
                .await
                .expect_err("read permission is rejected before DuckDB prepare");
        })
        .await;
        assert_eq!(context.snapshot().query_count, 0);
        assert_eq!(context.snapshot().query_time_ns, 0);
        drop(actor);
    }

    #[tokio::test]
    async fn duckdb_counts_arrow_describe_and_transaction_controls() {
        use tinycloud_core::duckdb::types::DuckDbStatement;

        let directory = tempfile::tempdir().unwrap();
        let actor = spawn_actor(
            "telemetry".into(),
            "controls".into(),
            directory.path().to_str().unwrap().into(),
            u64::MAX,
            1,
            "128MB".into(),
            Arc::new(DashMap::new()),
        );
        actor
            .execute(
                DuckDbRequest::Execute {
                    sql: "CREATE TABLE data (value INTEGER)".into(),
                    params: vec![],
                    schema: None,
                },
                None,
                "tinycloud.duckdb/admin".into(),
                false,
                false,
            )
            .await
            .unwrap();
        let describe = request("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
        scope(
            Arc::clone(&describe),
            actor.execute(
                DuckDbRequest::Describe,
                None,
                "tinycloud.duckdb/read".into(),
                false,
                false,
            ),
        )
        .await
        .unwrap();
        // Tables, columns for data, views, post-success size.
        assert_eq!(describe.snapshot().query_count, 4);
        let arrow = request("dddddddd-dddd-4ddd-8ddd-dddddddddddd");
        scope(
            Arc::clone(&arrow),
            actor.execute(
                DuckDbRequest::Query {
                    sql: "SELECT 1".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/read".into(),
                true,
                false,
            ),
        )
        .await
        .unwrap();
        assert_eq!(arrow.snapshot().query_count, 2);
        assert!(arrow.snapshot().query_time_ns > 0);
        let failed = request("eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee");
        scope(
            Arc::clone(&failed),
            actor.execute(
                DuckDbRequest::Batch {
                    statements: vec![
                        DuckDbStatement {
                            sql: "INSERT INTO data VALUES (1)".into(),
                            params: vec![],
                        },
                        DuckDbStatement {
                            sql: "INSERT INTO absent_table VALUES (1)".into(),
                            params: vec![],
                        },
                    ],
                    transactional: true,
                },
                None,
                "tinycloud.duckdb/admin".into(),
                false,
                false,
            ),
        )
        .await
        .unwrap_err();
        // BEGIN, successful insert, failed insert prepare, ROLLBACK.
        assert_eq!(failed.snapshot().query_count, 4);
        assert!(failed.snapshot().query_time_ns > 0);
        let guarded = request("ffffffff-ffff-4fff-8fff-ffffffffffff");
        scope(
            Arc::clone(&guarded),
            actor.execute(
                DuckDbRequest::Query {
                    sql: "SELECT 1".into(),
                    params: vec![],
                },
                None,
                "tinycloud.duckdb/read".into(),
                false,
                true,
            ),
        )
        .await
        .unwrap();
        // Native BEGIN/COMMIT, query, post-success size.
        assert_eq!(guarded.snapshot().query_count, 4);
        drop(actor);
    }

    #[tokio::test]
    async fn duckdb_export_counts_checkpoint_but_not_wal_filesystem_reads() {
        let directory = tempfile::tempdir().unwrap();
        // Pre-create a file database rather than depending on DuckDB's
        // checkpoint-oriented in-memory block count triggering promotion.
        let database_path = directory.path().join("telemetry/export.duckdb");
        std::fs::create_dir_all(database_path.parent().unwrap()).unwrap();
        let connection = duckdb::Connection::open(&database_path).unwrap();
        connection
            .execute_batch("CREATE TABLE data (value INTEGER)")
            .unwrap();
        drop(connection);
        let actor = spawn_actor(
            "telemetry".into(),
            "export".into(),
            directory.path().to_str().unwrap().into(),
            0,
            1,
            "128MB".into(),
            Arc::new(DashMap::new()),
        );
        execute(&actor, "SELECT 0").await.unwrap();
        let export = request("12345678-1234-4234-8234-123456789abc");
        scope(Arc::clone(&export), actor.export()).await.unwrap();
        assert_eq!(export.snapshot().query_count, 1);
        assert!(export.snapshot().query_time_ns > 0);
        let wal = request("12345678-1234-4234-8234-123456789abd");
        scope(Arc::clone(&wal), actor.wal()).await.unwrap();
        assert_eq!(wal.snapshot().query_count, 0);
        assert_eq!(wal.snapshot().query_time_ns, 0);
        drop(actor);
    }
}

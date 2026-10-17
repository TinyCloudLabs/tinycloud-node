use std::future::{poll_fn, Future};
use std::sync::Arc;
use std::task::Poll;
use std::time::Duration;

use futures as futures_util;
use futures_util::TryStreamExt;
use sea_orm::sqlx;
use sqlx::sqlite::SqlitePoolOptions;
use sqlx::{Connection, Executor, SqlitePool};
use sqlx_core::connection::LogSettings;
use sqlx_core::logger::QueryLogger;
use sqlx_core::request_telemetry::{current, enter, scope, Metrics};

fn run(future: impl Future<Output = ()>) {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(future);
}

async fn pool(max_connections: u32) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(max_connections)
        .min_connections(1)
        .test_before_acquire(true)
        .connect("sqlite::memory:")
        .await
        .unwrap()
}

#[test]
fn scope_restores_nested_and_pending_context() {
    run(async {
        let outer = Arc::new(Metrics::default());
        let inner = Arc::new(Metrics::default());
        let _outer = enter(Some(Arc::clone(&outer)));
        {
            let mut pending = std::pin::pin!(scope(Arc::clone(&inner), async {
                assert!(Arc::ptr_eq(&current().unwrap(), &inner));
                std::future::pending::<()>().await;
            }));
            poll_fn(|cx| {
                assert!(pending.as_mut().poll(cx).is_pending());
                assert!(Arc::ptr_eq(&current().unwrap(), &outer));
                Poll::Ready(())
            })
            .await;
        }
        assert!(Arc::ptr_eq(&current().unwrap(), &outer));
        {
            let _clear = enter(None);
            assert!(current().is_none());
        }
        assert!(Arc::ptr_eq(&current().unwrap(), &outer));
    });
    assert!(current().is_none());
}

#[test]
fn scope_survives_cross_thread_poll_migration() {
    let metrics = Arc::new(Metrics::default());
    let expected = Arc::clone(&metrics);
    let mut polls = 0;
    let mut future = Box::pin(scope(
        metrics,
        poll_fn(move |_| {
            assert!(Arc::ptr_eq(&current().unwrap(), &expected));
            polls += 1;
            if polls == 1 {
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        }),
    ));
    future = std::thread::spawn(move || {
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(future.as_mut().poll(&mut cx).is_pending());
        assert!(current().is_none());
        future
    })
    .join()
    .unwrap();
    std::thread::spawn(move || {
        let mut cx = std::task::Context::from_waker(futures_util::task::noop_waker_ref());
        assert!(future.as_mut().poll(&mut cx).is_ready());
        assert!(current().is_none());
    })
    .join()
    .unwrap();
    assert!(current().is_none());
}

#[test]
fn query_logger_records_once_on_drop_not_finish() {
    let metrics = Arc::new(Metrics::default());
    {
        let _scope = enter(Some(Arc::clone(&metrics)));
        let logger = QueryLogger::new("SELECT 'must never enter metrics'", LogSettings::default());
        logger.finish();
        logger.finish();
        assert_eq!(metrics.snapshot().query_count, 0);
        drop(logger);
    }
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.query_count, 1);
    assert!(snapshot.query_time_ns > 0);
    assert_eq!(snapshot.pool_wait_ns, 0);
    let logger = QueryLogger::new("SELECT 1", LogSettings::default());
    drop(logger);
    assert_eq!(metrics.snapshot().query_count, 1);
}

#[test]
fn paused_query_timer_excludes_formatting_without_counting_extra_queries() {
    let metrics = Arc::new(Metrics::default());
    let _scope = enter(Some(Arc::clone(&metrics)));
    let wall = std::time::Instant::now();
    let mut timer = sqlx_core::request_telemetry::QueryTimer::new();
    timer.pause();
    timer.pause();
    let paused = std::time::Instant::now();
    std::thread::sleep(Duration::from_millis(30));
    let pause_duration = paused.elapsed();
    timer.resume();
    timer.resume();
    timer.pause();
    drop(timer);
    let snapshot = metrics.snapshot();
    assert_eq!(snapshot.query_count, 1);
    assert!(snapshot.query_time_ns > 0);
    // The paused interval must be excluded even if this shared host stalls
    // before pause/resume; no assumed upper bound on scheduler latency.
    assert!(
        u128::from(snapshot.query_time_ns)
            <= wall.elapsed().saturating_sub(pause_duration).as_nanos()
    );
}

#[test]
fn real_pooled_success_and_failures_count_at_execution_boundary() {
    run(async {
        let pool = pool(1).await;
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            pool.execute("SELECT 1").await.unwrap();
            assert!(pool
                .execute("SELECT * FROM nonexistent_private_table")
                .await
                .is_err());
            assert!(pool.execute("SELECT \0").await.is_err());
        })
        .await;
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.query_count, 3);
        assert!(snapshot.query_time_ns > 0);
        assert!(snapshot.pool_wait_ns > 0);
        pool.execute("SELECT 2").await.unwrap();
        assert_eq!(metrics.snapshot().query_count, 3);
        pool.close().await;
    });
}

#[test]
fn nonblocking_pool_acquisition_is_measured_without_creating_queries() {
    run(async {
        let pool = pool(1).await;
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            let held = pool.try_acquire().unwrap();
            assert!(pool.try_acquire().is_none());
            assert!(metrics.snapshot().pool_wait_ns > 0);
            assert_eq!(metrics.snapshot().query_count, 0);
            drop(held);
        })
        .await;
        pool.close().await;
    });
}

#[test]
fn connection_initialization_and_health_checks_are_not_user_queries() {
    run(async {
        let pool = pool(2).await;
        let held = pool.acquire().await.unwrap();
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            let mut connection = pool.acquire().await.unwrap();
            assert_eq!(metrics.snapshot().query_count, 0);
            assert_eq!(metrics.snapshot().query_time_ns, 0);
            connection.ping().await.unwrap();
            assert_eq!(metrics.snapshot().query_count, 0);
            connection.execute("SELECT 1").await.unwrap();
        })
        .await;
        assert_eq!(metrics.snapshot().query_count, 1);
        assert!(metrics.snapshot().pool_wait_ns > 0);
        drop(held);
        pool.close().await;
    });
}

#[test]
fn acquired_connections_and_nested_transaction_control_are_counted() {
    run(async {
        let pool = pool(1).await;
        let mut connection = pool.acquire().await.unwrap();
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            connection.execute("SELECT 1").await.unwrap();
            let mut transaction = connection.begin().await.unwrap();
            transaction.execute("SELECT 2").await.unwrap();
            let mut nested = transaction.begin().await.unwrap();
            assert!(nested
                .execute("SELECT * FROM missing_transaction_table")
                .await
                .is_err());
            nested.rollback().await.unwrap();
            transaction.commit().await.unwrap();
        })
        .await;
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.query_count, 7);
        assert!(snapshot.query_time_ns > 0);
        assert_eq!(snapshot.pool_wait_ns, 0);
        drop(connection);
        pool.close().await;
    });
}

#[test]
fn failed_begin_counts_but_invalid_nested_begin_and_detached_rollback_do_not() {
    run(async {
        let pool = pool(1).await;
        let mut connection = pool.acquire().await.unwrap();
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            assert!(connection
                .begin_with("INVALID PRIVATE BEGIN")
                .await
                .is_err());
            assert_eq!(metrics.snapshot().query_count, 1);
            let mut transaction = connection.begin().await.unwrap();
            assert!(transaction.begin_with("BEGIN").await.is_err());
            assert_eq!(metrics.snapshot().query_count, 2);
            transaction.execute("SELECT 1").await.unwrap();
            drop(transaction);
        })
        .await;
        // Flush the preceding detached rollback on the same worker.
        connection.execute("SELECT 1").await.unwrap();
        assert_eq!(metrics.snapshot().query_count, 3);
        drop(connection);
        pool.close().await;
    });
}

#[test]
fn blocked_acquisition_is_not_query_execution_time() {
    run(async {
        let pool = pool(1).await;
        let held = pool.acquire().await.unwrap();
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            let mut acquire = std::pin::pin!(pool.acquire());
            poll_fn(|cx| {
                assert!(acquire.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            tokio::time::sleep(Duration::from_millis(40)).await;
            drop(held);
            let mut connection = acquire.await.unwrap();
            let before_query = metrics.snapshot();
            assert!(before_query.pool_wait_ns >= 30_000_000);
            assert_eq!(before_query.query_count, 0);
            assert_eq!(before_query.query_time_ns, 0);
            connection.execute("SELECT 1").await.unwrap();
        })
        .await;
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.query_count, 1);
        assert!(snapshot.query_time_ns > 0);
        pool.close().await;
    });
}

#[test]
fn cancelled_and_failed_acquisitions_record_wait_without_queries() {
    run(async {
        let pool = pool(1).await;
        let held = pool.acquire().await.unwrap();
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            let acquire = pool.acquire();
            let mut acquire = std::pin::pin!(acquire);
            poll_fn(|cx| {
                assert!(acquire.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            tokio::time::sleep(Duration::from_millis(30)).await;
        })
        .await;
        assert!(metrics.snapshot().pool_wait_ns >= 20_000_000);
        assert_eq!(metrics.snapshot().query_count, 0);
        assert_eq!(metrics.snapshot().query_time_ns, 0);
        drop(held);
        pool.close().await;
        scope(Arc::clone(&metrics), async {
            assert!(pool.acquire().await.is_err());
        })
        .await;
        assert_eq!(metrics.snapshot().query_count, 0);
    });
}

#[test]
fn timed_out_acquisition_and_no_database_request_have_no_query_count() {
    run(async {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(40))
            .connect("sqlite::memory:")
            .await
            .unwrap();
        let held = pool.acquire().await.unwrap();
        let timeout = Arc::new(Metrics::default());
        scope(Arc::clone(&timeout), async {
            assert!(matches!(
                pool.acquire().await,
                Err(sqlx::Error::PoolTimedOut)
            ));
        })
        .await;
        assert!(timeout.snapshot().pool_wait_ns >= 30_000_000);
        assert_eq!(timeout.snapshot().query_count, 0);
        assert_eq!(timeout.snapshot().query_time_ns, 0);
        let no_database = Arc::new(Metrics::default());
        scope(Arc::clone(&no_database), async {
            tokio::task::yield_now().await;
        })
        .await;
        assert_eq!(no_database.snapshot().pool_wait_ns, 0);
        assert_eq!(no_database.snapshot().query_count, 0);
        assert_eq!(no_database.snapshot().query_time_ns, 0);
        drop(held);
        pool.close().await;
    });
}

#[test]
fn concurrent_requests_are_isolated_on_one_sqlite_worker() {
    run(async {
        let pool = pool(1).await;
        let first = Arc::new(Metrics::default());
        let second = Arc::new(Metrics::default());
        let first_request = scope(Arc::clone(&first), async {
            for _ in 0..3 {
                pool.execute("SELECT 1").await.unwrap();
                tokio::task::yield_now().await;
            }
        });
        let second_request = scope(Arc::clone(&second), async {
            for _ in 0..5 {
                assert!(pool
                    .execute("SELECT * FROM isolated_missing_table")
                    .await
                    .is_err());
                tokio::task::yield_now().await;
            }
        });
        futures_util::future::join(first_request, second_request).await;
        assert!(current().is_none());
        assert_eq!(first.snapshot().query_count, 3);
        assert_eq!(second.snapshot().query_count, 5);
        pool.execute("SELECT 1").await.unwrap();
        assert_eq!(first.snapshot().query_count, 3);
        assert_eq!(second.snapshot().query_count, 5);
        pool.close().await;
    });
}

#[test]
fn cancelled_sql_stream_finishes_once_on_worker_without_leaking_context() {
    run(async {
        let pool = pool(1).await;
        let mut connection = pool.acquire().await.unwrap();
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            let mut rows = sqlx::query(
                "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<100000) SELECT x FROM n",
            )
            .fetch(&mut *connection);
            assert!(rows.try_next().await.unwrap().is_some());
            drop(rows);
        })
        .await;
        // Same worker must finish the cancelled stream before this unscoped query.
        connection.execute("SELECT 1").await.unwrap();
        assert_eq!(metrics.snapshot().query_count, 1);
        assert!(metrics.snapshot().query_time_ns > 0);
        assert_eq!(metrics.snapshot().pool_wait_ns, 0);
        drop(connection);
        pool.close().await;
    });
}

#[cfg(feature = "postgres")]
fn postgres_test_url(test: &str) -> Option<String> {
    // Match test_support's local-skip/CI-required policy without exposing the URL.
    match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            if std::env::var_os("CI").is_some() {
                panic!("{test} requires TINYCLOUD_TEST_POSTGRES_URL in CI");
            }
            eprintln!("skipping {test}: TINYCLOUD_TEST_POSTGRES_URL is unset (mandatory in CI)");
            None
        }
    }
}

#[cfg(feature = "postgres")]
#[test]
fn postgres_transaction_boundaries_count_each_attempt_once() {
    let Some(url) = postgres_test_url("postgres_transaction_boundaries_count_each_attempt_once")
    else {
        return;
    };
    run(async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .connect(&url)
            .await
            .unwrap();
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            let mut transaction = pool.begin().await.unwrap();
            assert_eq!(metrics.snapshot().query_count, 1, "raw PostgreSQL BEGIN");
            transaction.execute("SELECT 1").await.unwrap();
            assert_eq!(metrics.snapshot().query_count, 2);
            assert!(transaction.begin_with("BEGIN").await.is_err());
            assert_eq!(metrics.snapshot().query_count, 2, "validation is not SQL");
            let mut nested = transaction.begin().await.unwrap();
            assert_eq!(metrics.snapshot().query_count, 3, "raw SAVEPOINT");
            nested.execute("SELECT 2").await.unwrap();
            nested.commit().await.unwrap();
            assert_eq!(metrics.snapshot().query_count, 5, "RELEASE SAVEPOINT");
            assert!(transaction.execute("SELECT 1 / 0").await.is_err());
            assert_eq!(metrics.snapshot().query_count, 6, "failed query counts");
            transaction.rollback().await.unwrap();
            assert_eq!(metrics.snapshot().query_count, 7, "explicit ROLLBACK");
            let mut committed = pool.begin().await.unwrap();
            assert_eq!(metrics.snapshot().query_count, 8, "second BEGIN");
            committed.execute("SELECT 3").await.unwrap();
            committed.commit().await.unwrap();
            assert_eq!(metrics.snapshot().query_count, 10, "explicit COMMIT");
            assert!(pool.begin_with("INVALID TELEMETRY BEGIN").await.is_err());
            assert_eq!(metrics.snapshot().query_count, 11, "failed raw BEGIN");
        })
        .await;
        assert_eq!(metrics.snapshot().query_count, 11);
        assert!(metrics.snapshot().query_time_ns > 0);
        assert!(metrics.snapshot().pool_wait_ns > 0);
        pool.execute("SELECT 4").await.unwrap();
        assert_eq!(metrics.snapshot().query_count, 11);
        pool.close().await;
    });
}

#[cfg(feature = "postgres")]
#[test]
fn postgres_pool_exhaustion_failure_records_wait_without_queries() {
    let Some(url) =
        postgres_test_url("postgres_pool_exhaustion_failure_records_wait_without_queries")
    else {
        return;
    };
    run(async {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            // This budget also covers cold TCP/SCRAM setup before request scope.
            .acquire_timeout(Duration::from_secs(5))
            .connect(&url)
            .await
            .unwrap();
        let held = pool.acquire().await.unwrap();
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            assert!(matches!(pool.begin().await, Err(sqlx::Error::PoolTimedOut)));
        })
        .await;
        assert!(metrics.snapshot().pool_wait_ns >= 4_000_000_000);
        assert_eq!(metrics.snapshot().query_count, 0);
        assert_eq!(metrics.snapshot().query_time_ns, 0);
        drop(held);
        pool.close().await;
        scope(Arc::clone(&metrics), async {
            assert!(matches!(pool.begin().await, Err(sqlx::Error::PoolClosed)));
        })
        .await;
        assert_eq!(metrics.snapshot().query_count, 0);
        assert_eq!(metrics.snapshot().query_time_ns, 0);
    });
}

#[cfg(feature = "postgres")]
#[test]
fn sea_orm_postgres_begin_uses_the_same_driver_boundary_as_sqlx() {
    use sea_orm::{ConnectionTrait, Database, DbBackend, Statement, TransactionTrait};
    let Some(url) =
        postgres_test_url("sea_orm_postgres_begin_uses_the_same_driver_boundary_as_sqlx")
    else {
        return;
    };
    run(async {
        let connection = Database::connect(url).await.unwrap();
        let metrics = Arc::new(Metrics::default());
        scope(Arc::clone(&metrics), async {
            let transaction = connection.begin().await.unwrap();
            assert_eq!(
                metrics.snapshot().query_count,
                1,
                "SeaORM calls the driver directly"
            );
            transaction
                .query_one(Statement::from_string(DbBackend::Postgres, "SELECT 1"))
                .await
                .unwrap();
            let nested = transaction.begin().await.unwrap();
            nested.rollback().await.unwrap();
            transaction.commit().await.unwrap();
        })
        .await;
        assert_eq!(metrics.snapshot().query_count, 5);
        assert!(metrics.snapshot().pool_wait_ns > 0);
        assert!(metrics.snapshot().query_time_ns > 0);
        connection.close().await.unwrap();
    });
}

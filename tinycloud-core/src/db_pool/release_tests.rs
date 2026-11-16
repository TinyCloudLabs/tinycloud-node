//! TC-2954: the pool never hands a borrower a connection that is still inside
//! a transaction. If it did, the borrower's autocommit writes would run inside
//! that transaction: acknowledged, then lost when it ends without a commit.

use sea_orm::sqlx::{self, postgres::PgPoolOptions, Executor, PgPool};
use sea_orm::TransactionTrait;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::request_cancel::{run_with_deadline, DeadlineExceeded};
use crate::test_support::PostgresTestSchema;

/// A one-connection pool on the fixture's schema that, like the node's, does
/// not ping a connection before handing it out.
async fn single_connection_pool(fixture: &PostgresTestSchema) -> PgPool {
    let admin = fixture.conn.get_postgres_connection_pool();
    admin
        .execute("CREATE TABLE acknowledged_write (id INTEGER PRIMARY KEY)")
        .await
        .unwrap();
    let schema: String = sqlx::query_scalar("SELECT current_schema()")
        .fetch_one(admin)
        .await
        .unwrap();
    let options = admin
        .connect_options()
        .as_ref()
        .clone()
        .options([("search_path", schema)]);
    PgPoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .connect_with(options)
        .await
        .unwrap()
}

async fn backend_pid<'c>(executor: impl Executor<'c, Database = sqlx::Postgres>) -> i32 {
    sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(executor)
        .await
        .unwrap()
}

#[derive(Debug, PartialEq)]
struct NextBorrower {
    pid: i32,
    /// `pg_stat_activity.state` of its backend when it got the connection.
    state: String,
    /// Its acknowledged autocommit insert is still there after the pool closes.
    write_survived: bool,
}

/// The next borrower inserts a row and gets its acknowledgement; then the
/// pool closes, which ends any transaction left open on its connection.
async fn next_borrower_writes(pool: &PgPool, admin: &PgPool) -> NextBorrower {
    let mut conn = pool.acquire().await.unwrap();
    let pid = backend_pid(&mut *conn).await;
    let state = sqlx::query_scalar("SELECT state FROM pg_stat_activity WHERE pid = $1")
        .bind(pid)
        .fetch_one(admin)
        .await
        .unwrap();
    let inserted = sqlx::query("INSERT INTO acknowledged_write VALUES (1)")
        .execute(&mut *conn)
        .await
        .unwrap()
        .rows_affected();
    assert_eq!(inserted, 1, "the insert was acknowledged");
    drop(conn);
    pool.close().await;
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM acknowledged_write")
        .fetch_one(admin)
        .await
        .unwrap();
    NextBorrower {
        pid,
        state,
        write_survived: rows == 1,
    }
}

/// A request deadline that drops the handler while its `BEGIN` is in flight
/// rolls that transaction back. The connection stays usable and goes back to
/// the pool outside any transaction; it is not discarded and replaced.
#[tokio::test]
async fn postgres_a_deadline_during_begin_returns_the_connection_outside_a_transaction() {
    let Some(fixture) = PostgresTestSchema::new(
        "postgres_a_deadline_during_begin_returns_the_connection_outside_a_transaction",
    )
    .await
    else {
        return;
    };
    let admin = fixture.conn.get_postgres_connection_pool();
    let pool = single_connection_pool(&fixture).await;
    let pid = backend_pid(&pool).await;

    // The sleep keeps the BEGIN round trip in flight past the deadline, as a
    // slow database link does.
    let cut = run_with_deadline(Some(Duration::from_millis(100)), async {
        pool.begin_with("BEGIN; SELECT pg_sleep(0.4)")
            .await
            .map(drop)
    })
    .await;
    assert_eq!(cut.err(), Some(DeadlineExceeded));

    assert_eq!(
        next_borrower_writes(&pool, admin).await,
        NextBorrower {
            pid,
            state: "idle".into(),
            write_survived: true,
        }
    );
}

/// A TCP proxy to `upstream` that delays each server-to-client chunk by
/// `delay_ms` while it is non-zero, as a slow database link does. Returns its
/// port.
async fn delaying_proxy(upstream: (String, u16), delay_ms: Arc<AtomicU64>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((client, _)) = listener.accept().await {
            let server = tokio::net::TcpStream::connect((upstream.0.as_str(), upstream.1))
                .await
                .unwrap();
            let (mut client_read, mut client_write) = client.into_split();
            let (mut server_read, mut server_write) = server.into_split();
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut client_read, &mut server_write).await;
            });
            let delay_ms = Arc::clone(&delay_ms);
            tokio::spawn(async move {
                let mut buf = vec![0; 64 * 1024];
                while let Ok(n @ 1..) = server_read.read(&mut buf).await {
                    let delay = delay_ms.load(Ordering::SeqCst);
                    if delay > 0 {
                        tokio::time::sleep(Duration::from_millis(delay)).await;
                    }
                    if client_write.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
}

/// The node's own path: a SeaORM transaction whose `BEGIN` reply is still on
/// a slow link when the request deadline cuts it. The connection goes back
/// to the pool outside any transaction and the next borrower's write stays.
#[tokio::test]
async fn postgres_a_deadline_during_a_sea_orm_begin_returns_the_connection_outside_a_transaction() {
    let Some(fixture) = PostgresTestSchema::new(
        "postgres_a_deadline_during_a_sea_orm_begin_returns_the_connection_outside_a_transaction",
    )
    .await
    else {
        return;
    };
    let admin = fixture.conn.get_postgres_connection_pool();
    let direct = single_connection_pool(&fixture).await;
    let options = direct.connect_options().as_ref().clone();
    direct.close().await;
    let delay_ms = Arc::new(AtomicU64::new(0));
    let port = delaying_proxy(
        (options.get_host().to_owned(), options.get_port()),
        Arc::clone(&delay_ms),
    )
    .await;
    let pool = PgPoolOptions::new()
        .max_connections(1)
        .test_before_acquire(false)
        .connect_with(options.host("127.0.0.1").port(port))
        .await
        .unwrap();
    let pid = backend_pid(&pool).await;
    let db = sea_orm::SqlxPostgresConnector::from_sqlx_postgres_pool(pool.clone());
    // Only once the connection is back in the pool, so the deadline cuts the
    // BEGIN and not the acquire waiting for the release ping.
    while pool.num_idle() == 0 {
        tokio::task::yield_now().await;
    }

    delay_ms.store(300, Ordering::SeqCst);
    let cut = run_with_deadline(Some(Duration::from_millis(100)), async {
        db.begin().await.map(drop)
    })
    .await;
    assert_eq!(cut.err(), Some(DeadlineExceeded));
    delay_ms.store(0, Ordering::SeqCst);

    assert_eq!(
        next_borrower_writes(&pool, admin).await,
        NextBorrower {
            pid,
            state: "idle".into(),
            write_survived: true,
        }
    );
}

/// A connection whose session is still inside a transaction when it is
/// released is closed instead of pooled, whatever left that transaction open.
#[tokio::test]
async fn postgres_a_connection_released_inside_a_transaction_is_closed() {
    let Some(fixture) =
        PostgresTestSchema::new("postgres_a_connection_released_inside_a_transaction_is_closed")
            .await
    else {
        return;
    };
    let admin = fixture.conn.get_postgres_connection_pool();
    let pool = single_connection_pool(&fixture).await;
    let mut conn = pool.acquire().await.unwrap();
    let leaked = backend_pid(&mut *conn).await;
    // A transaction sqlx does not track, so no drop guard ends it.
    conn.execute("BEGIN").await.unwrap();
    drop(conn);

    let next = next_borrower_writes(&pool, admin).await;
    assert_eq!(
        (next.pid == leaked, next.state.as_str(), next.write_survived),
        (false, "idle", true),
        "(pooled again, state, write survived)"
    );
}

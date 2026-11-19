use sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement, TransactionTrait};
use std::time::Duration;
use time::OffsetDateTime;
use tinycloud_core::{
    migrations::Migrator,
    policy_authority::{AuthorityStatusObservation, DatabaseAuthorityStore},
    sea_orm_migration::MigratorTrait,
};

#[tokio::test]
async fn postgres_policy_status_writer_waits_for_gc_before_reading_authority_rows() {
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").unwrap();
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "purge_policy_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let gc = db.begin().await.unwrap();
    tinycloud_core::space_purge_records::lock(&gc)
        .await
        .unwrap();
    let store = DatabaseAuthorityStore::new(db.clone());
    let tx = db.begin().await.unwrap();
    let pid: i32 = tx
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            "SELECT pg_backend_pid() AS pid",
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "pid")
        .unwrap();
    let writing = tokio::spawn(async move {
        let now = OffsetDateTime::now_utc();
        let result = store
            .apply_status_in_transaction(
                &tx,
                "missing-authority",
                &AuthorityStatusObservation {
                    checked_at: now,
                    sequence: 1,
                    revoked_at: Some(now),
                    fresh_until: now + time::Duration::seconds(30),
                },
                now,
            )
            .await;
        tx.rollback().await.unwrap();
        result
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let row = admin.query_one(Statement::from_sql_and_values(DbBackend::Postgres,
                "SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND NOT granted) AS waiting",
                [pid.into()])).await.unwrap().unwrap();
            if row.try_get::<bool>("", "waiting").unwrap() { break; }
            assert!(!writing.is_finished(), "policy row lookup bypassed GC lock");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    gc.commit().await.unwrap();
    // Only after GC releases the graph may the missing authority be observed.
    assert!(tokio::time::timeout(Duration::from_secs(5), writing)
        .await
        .unwrap()
        .unwrap()
        .is_err());
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

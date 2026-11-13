use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DatabaseTransaction, TransactionTrait,
};
use tinycloud_core::space_purge_worker::{advance, claim, renew, retry};

async fn transaction(db: &DatabaseConnection, schema: &str) -> DatabaseTransaction {
    let tx = db.begin().await.unwrap();
    tx.execute_unprepared(&format!("SET LOCAL search_path TO {schema}"))
        .await
        .unwrap();
    tx
}

#[tokio::test]
async fn postgres_purge_claim_resume_and_stale_token() {
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let db = Database::connect(url).await.unwrap();
    let schema = format!(
        "purge_worker_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    db.execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let tx = transaction(&db, &schema).await;
    // Queue columns consumed by the worker, using the API builder's concrete types.
    tx.execute_unprepared(
        "CREATE TABLE space_purge_job (
        purge_id TEXT PRIMARY KEY, space TEXT, phase TEXT NOT NULL,
        fence_generation BIGINT NOT NULL, accepted_at TIMESTAMPTZ NOT NULL,
        updated_at TIMESTAMPTZ NOT NULL, next_attempt_at TIMESTAMPTZ NOT NULL,
        attempt_count BIGINT NOT NULL DEFAULT 0, last_error_code TEXT,
        lease_token TEXT, lease_until TIMESTAMPTZ)",
    )
    .await
    .unwrap();
    tx.execute_unprepared(
        "INSERT INTO space_purge_job
        (purge_id,space,phase,fence_generation,accepted_at,updated_at,next_attempt_at)
        VALUES ('a','tinycloud:key:test:a','drain',1,now(),now(),now()),
               ('b','tinycloud:key:test:b','drain',1,now(),now(),now())",
    )
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let first = transaction(&db, &schema).await;
    let old = claim(&first, "00000000-0000-4000-8000-000000000001")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(old.purge_id, "a");
    // Another transaction skips the locked first row rather than blocking.
    let second = transaction(&db, &schema).await;
    let other = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        claim(&second, "00000000-0000-4000-8000-000000000002"),
    )
    .await
    .unwrap()
    .unwrap()
    .unwrap();
    assert_eq!(other.purge_id, "b");
    second.commit().await.unwrap();
    first.commit().await.unwrap();

    let tx = transaction(&db, &schema).await;
    assert!(claim(&tx, "00000000-0000-4000-8000-000000000003")
        .await
        .unwrap()
        .is_none());
    assert!(renew(&tx, &old).await.unwrap());
    // Simulate process death and lease expiry without a wall-clock sleep.
    tx.execute_unprepared("UPDATE space_purge_job SET lease_until=clock_timestamp()-INTERVAL '1 second' WHERE purge_id='a'").await.unwrap();
    assert!(!renew(&tx, &old).await.unwrap());
    assert!(!advance(&tx, &old).await.unwrap());
    tx.commit().await.unwrap();

    let tx = transaction(&db, &schema).await;
    let resumed = claim(&tx, "00000000-0000-4000-8000-000000000004")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(resumed.purge_id, old.purge_id);
    assert_eq!(resumed.phase, "drain");
    assert!(!advance(&tx, &old).await.unwrap());
    assert!(!retry(&tx, &old, "storage_unavailable").await.unwrap());
    assert!(advance(&tx, &resumed).await.unwrap());
    tx.commit().await.unwrap();

    let tx = transaction(&db, &schema).await;
    let database = claim(&tx, "00000000-0000-4000-8000-000000000005")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(database.phase, "database");
    assert!(retry(&tx, &database, "database_unavailable").await.unwrap());
    assert!(claim(&tx, "00000000-0000-4000-8000-000000000006")
        .await
        .unwrap()
        .is_none());
    tx.commit().await.unwrap();
    db.execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

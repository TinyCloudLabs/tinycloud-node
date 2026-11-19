use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use tinycloud_core::{
    migrations::Migrator, sea_orm_migration::MigratorTrait, space_purge_ledger::LedgerKeys,
    space_purge_prefix_repair as repair,
};
async fn leases(db: &DatabaseConnection) {
    Migrator::up(db, None).await.unwrap();
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![4; 32])]),
    )
    .unwrap();
    let record = keys
        .sign(
            "test",
            "space",
            &[3; 32],
            "00000000-0000-4000-8000-000000000001",
            "purging",
            1,
        )
        .unwrap();
    let record = keys
        .with_prefixes(
            record,
            vec![keys
                .prefix_hmac("test", "sql-filesystem", "sql/v1/test/")
                .unwrap()],
        )
        .unwrap();
    let path = record.object_key().unwrap();
    let prefix = &record.prefixes[0];
    repair::enqueue(db, &keys, &record).await.unwrap();
    repair::enqueue(db, &keys, &record).await.unwrap();
    let a = uuid::Uuid::new_v4().to_string();
    let b = uuid::Uuid::new_v4().to_string();
    let (first, second) = tokio::join!(
        repair::claim(db, &a, &path, &prefix.store_kind, &prefix.prefix_hmac),
        repair::claim(db, &b, &path, &prefix.store_kind, &prefix.prefix_hmac)
    );
    let claims: Vec<_> = [first.unwrap(), second.unwrap()]
        .into_iter()
        .flatten()
        .collect();
    assert_eq!(claims.len(), 1);
    let old = &claims[0];
    assert!(repair::renew(db, old).await.unwrap());
    db.execute(Statement::from_string(
        DbBackend::Postgres,
        "UPDATE space_purge_prefix_repair SET lease_until=clock_timestamp()-INTERVAL '1 second'",
    ))
    .await
    .unwrap();
    let next = repair::claim(
        db,
        &uuid::Uuid::new_v4().to_string(),
        &path,
        &prefix.store_kind,
        &prefix.prefix_hmac,
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!repair::complete(db, old).await.unwrap());
    assert!(!repair::renew(db, old).await.unwrap());
    assert!(repair::complete(db, &next).await.unwrap());
    assert!(!repair::complete(db, &next).await.unwrap());
    // A restored prefix creates another repair, never downgrades old history.
    repair::enqueue(db, &keys, &record).await.unwrap();
    let restored = repair::claim(
        db,
        &uuid::Uuid::new_v4().to_string(),
        &path,
        &prefix.store_kind,
        &prefix.prefix_hmac,
    )
    .await
    .unwrap()
    .unwrap();
    assert_ne!(restored.repair_id, next.repair_id);
    assert!(repair::release(db, &restored).await.unwrap());
}
#[tokio::test]
async fn postgres_opaque_repairs_reject_stale_leases_and_preserve_monotonic_history() {
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").expect("isolated PostgreSQL test URL");
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "prefix_repair_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    leases(&db).await;
    db.close().await.unwrap();
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .unwrap();
}

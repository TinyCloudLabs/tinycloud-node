use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, EntityTrait,
    Statement, TransactionTrait,
};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use tinycloud_core::{
    migrations::Migrator, models::space_purge_ledger_copy, sea_orm_migration::MigratorTrait,
    space_purge_ledger::LedgerKeys,
};
async fn evidence(db: &DatabaseConnection) {
    Migrator::up(db, None).await.unwrap();
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![9; 32])]),
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
    let bytes = record.to_bytes().unwrap();
    let tx = db.begin().await.unwrap();
    tinycloud_core::space_purge_ledger_copy::retain(
        &tx,
        &keys,
        &path,
        &bytes,
        OffsetDateTime::now_utc(),
    )
    .await
    .unwrap();
    tx.rollback().await.unwrap();
    assert!(space_purge_ledger_copy::Entity::find_by_id(&path)
        .one(db)
        .await
        .unwrap()
        .is_none());
    for _ in 0..2 {
        tinycloud_core::space_purge_ledger_copy::retain(
            db,
            &keys,
            &path,
            &bytes,
            OffsetDateTime::now_utc(),
        )
        .await
        .unwrap();
    }
    let stored = space_purge_ledger_copy::Entity::find_by_id(&path)
        .one(db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(stored.body, bytes);
    assert_eq!(
        keys.verify(&path, &stored.body).unwrap().prefixes,
        record.prefixes
    );
    let mut conflicting = record.clone();
    conflicting.timestamp = 2;
    assert!(tinycloud_core::space_purge_ledger_copy::retain(
        db,
        &keys,
        &path,
        &conflicting.to_bytes().unwrap(),
        OffsetDateTime::now_utc()
    )
    .await
    .is_err());
    let other = keys
        .sign(
            "test",
            "space",
            &[3; 32],
            "00000000-0000-4000-8000-000000000002",
            "purging",
            1,
        )
        .unwrap();
    assert!(tinycloud_core::space_purge_ledger_copy::retain(
        db,
        &keys,
        &path,
        &other.to_bytes().unwrap(),
        OffsetDateTime::now_utc()
    )
    .await
    .is_err());
    assert_eq!(
        space_purge_ledger_copy::Entity::find_by_id(path)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .body,
        bytes
    );
}
#[tokio::test]
async fn sqlite_retains_immutable_authenticated_acceptance_bytes() {
    evidence(&Database::connect("sqlite::memory:").await.unwrap()).await;
}
#[tokio::test]
async fn postgres_retains_immutable_authenticated_acceptance_bytes() {
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").expect("isolated PostgreSQL test URL");
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "ledger_copy_{}_{}",
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
    evidence(&db).await;
    db.close().await.unwrap();
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .unwrap();
}

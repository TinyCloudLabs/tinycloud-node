use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
    TransactionTrait,
};
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    database_artifacts::{
        ArtifactExpectation, DatabaseArtifactError, DatabaseArtifactRepository,
        SeaOrmDatabaseArtifactRepository,
    },
    migrations::Migrator,
    sea_orm_migration::MigratorTrait,
    space_purge_fence::SpacePurgeFence,
    space_purge_ledger::LedgerKeys,
};
fn context() -> (Arc<LedgerKeys>, Arc<SpacePurgeFence>, SpaceId) {
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![11; 32])]),
        )
        .unwrap(),
    );
    let fence = Arc::new(SpacePurgeFence::new(keys.clone()));
    fence.set_serving_ready(true);
    (
        keys,
        fence,
        "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:sql"
            .parse()
            .unwrap(),
    )
}
async fn rejects_after_fence(db: &DatabaseConnection) {
    let (keys, fence, space) = context();
    let raw = space.to_string();
    let repo = SeaOrmDatabaseArtifactRepository::new(db.clone())
        .with_space_purge_fence(Some(fence.clone()));
    repo.save(
        "sql",
        &raw,
        "main",
        vec![1; 10],
        ArtifactExpectation::Absent,
    )
    .await
    .unwrap();
    let tx = db.begin().await.unwrap();
    let digest = keys.target_hmac("test", "space", &raw).unwrap();
    fence
        .fence_hmac(&tx, "space", "test", &digest)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(matches!(
        repo.load_meta("sql", &raw, "main").await,
        Err(DatabaseArtifactError::SpaceDeleted)
    ));
    assert!(matches!(
        repo.save("sql", &raw, "main", vec![2; 10], ArtifactExpectation::Any)
            .await,
        Err(DatabaseArtifactError::SpaceDeleted)
    ));
    assert!(matches!(
        repo.save_delta("sql", &raw, "main", vec![3; 10], ArtifactExpectation::Any)
            .await,
        Err(DatabaseArtifactError::SpaceDeleted)
    ));
    let unrestricted = SeaOrmDatabaseArtifactRepository::new(db.clone());
    let meta = unrestricted
        .load_meta("sql", &raw, "main")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(meta.revision, 1);
}
#[tokio::test]
async fn artifact_checkpoint_delta_and_reads_refuse_a_permanent_sqlite_fence() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    rejects_after_fence(&db).await;
}
#[tokio::test]
async fn postgres_artifact_save_cannot_cross_an_accepted_fence() {
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").unwrap();
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "purge_artifact_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
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
    Migrator::up(&db, None).await.unwrap();
    let (keys, fence, space) = context();
    let raw = space.to_string();
    let repo = Arc::new(
        SeaOrmDatabaseArtifactRepository::new(db.clone())
            .with_space_purge_fence(Some(fence.clone())),
    );
    repo.save(
        "sql",
        &raw,
        "main",
        vec![1; 10],
        ArtifactExpectation::Absent,
    )
    .await
    .unwrap();
    let tx = db.begin().await.unwrap();
    let digest = keys.target_hmac("test", "space", &raw).unwrap();
    fence
        .fence_hmac(&tx, "space", "test", &digest)
        .await
        .unwrap();
    let writer = repo.clone();
    let target = raw.clone();
    let mut writing = tokio::spawn(async move {
        writer
            .save(
                "sql",
                &target,
                "main",
                vec![2; 10],
                ArtifactExpectation::Any,
            )
            .await
    });
    assert!(
        tokio::time::timeout(Duration::from_millis(50), &mut writing)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert!(matches!(
        writing.await.unwrap(),
        Err(DatabaseArtifactError::SpaceDeleted)
    ));
    assert_eq!(
        SeaOrmDatabaseArtifactRepository::new(db.clone())
            .load_meta("sql", &raw, "main")
            .await
            .unwrap()
            .unwrap()
            .revision,
        1
    );
    db.close().await.unwrap();
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .unwrap();
}

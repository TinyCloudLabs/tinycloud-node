use tinycloud_core::{
    migrations::Migrator,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement},
    sea_orm_migration::MigratorTrait,
    space_purge_worker::{claim, claim_specific},
};

#[tokio::test]
async fn postgres_specific_claim_selects_only_requested_unleased_job() {
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "purge_specific_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    for (id, space) in [("a", "tinycloud:key:test:a"), ("b", "tinycloud:key:test:b")] {
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO space_purge_job(purge_id,space,tombstone_hmac,hmac_key_id,owner_hmac,accepted_at,phase,fence_generation,updated_at,next_attempt_at,attempt_count)
             VALUES($1,$2,$3,'test',$3,now(),'drain',1,now(),now(),0)",[id.into(),space.into(),vec![1u8;32].into()])).await.unwrap();
    }
    assert!(
        claim_specific(&db, "00000000-0000-4000-8000-000000000001", "missing")
            .await
            .unwrap()
            .is_none()
    );
    let selected = claim_specific(&db, "00000000-0000-4000-8000-000000000002", "b")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(selected.purge_id, "b");
    assert!(
        claim_specific(&db, "00000000-0000-4000-8000-000000000003", "b")
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        claim(&db, "00000000-0000-4000-8000-000000000004")
            .await
            .unwrap()
            .unwrap()
            .purge_id,
        "a"
    );
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

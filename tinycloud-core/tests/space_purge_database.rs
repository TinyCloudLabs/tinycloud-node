use tinycloud_core::{
    database_artifacts::{
        ArtifactExpectation, DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository,
    },
    migrations::Migrator,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement, TransactionTrait},
    sea_orm_migration::MigratorTrait,
    space_purge_database::delete_sql_and_hook_rows,
    space_purge_worker::claim,
};

#[tokio::test]
async fn postgres_leaf_cleanup_is_exact_space_transactional_and_idempotent() {
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "purge_leaves_{}",
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
    let target = "tinycloud:key:test:a_b";
    let neighbour = "tinycloud:key:test:aXb";
    let repo = SeaOrmDatabaseArtifactRepository::new(db.clone());
    for (space, id) in [(target, "target"), (neighbour, "neighbour")] {
        repo.save(
            "sql",
            space,
            "main",
            b"checkpoint".to_vec(),
            ArtifactExpectation::Absent,
        )
        .await
        .unwrap();
        db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "UPDATE database_artifact SET delta_payload=$1 WHERE space=$2",
            [b"wal-delta".to_vec().into(), space.into()],
        ))
        .await
        .unwrap();
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO hook_subscription(id,subscriber_did,space_id,target_service,callback_url,encrypted_secret,encrypted_secret_format,secret_key_id,active,created_at)
             VALUES($1,'did:key:test',$2,'kv','https://example.invalid/hook',$3,0,'test',true,'2026-11-12T00:00:00Z')",
            [id.into(),space.into(),b"synthetic".to_vec().into()])).await.unwrap();
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO hook_delivery(id,subscription_id,event_id,payload_json,status,attempts,created_at)
             VALUES($1,$1,'event','{}','pending',0,'2026-11-12T00:00:00Z')",[id.into()])).await.unwrap();
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO signed_kv_ticket(id,issuer_did,subject_did,space_id,path,service,ability,created_at,expires_at)
             VALUES($1,'did:key:test','did:key:test',$2,'key','kv','tinycloud.kv/get','2026-11-12T00:00:00Z','2026-11-12T00:05:00Z')",[id.into(),space.into()])).await.unwrap();
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO database_alias(service,space,logical_name,physical_name) VALUES('sql',$1,'logical','main')",[space.into()])).await.unwrap();
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO database_legacy_artifact(service,space,physical_name) VALUES('sql',$1,'legacy')",[space.into()])).await.unwrap();
        db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO meeting_legacy_write_guard(space,frozen,generation) VALUES($1,true,1)",
            [space.into()],
        ))
        .await
        .unwrap();
    }
    db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO space_purge_job(purge_id,space,tombstone_hmac,hmac_key_id,owner_hmac,accepted_at,phase,fence_generation,updated_at,next_attempt_at,attempt_count)
         VALUES('purge',$1,$2,'test',$2,now(),'database',1,now(),now(),0)",[target.into(),vec![1u8;32].into()])).await.unwrap();
    let job = claim(&db, "00000000-0000-4000-8000-000000000001")
        .await
        .unwrap()
        .unwrap();
    let tx = db.begin().await.unwrap();
    let mut wrong = job.clone();
    wrong.space = neighbour.into();
    assert!(delete_sql_and_hook_rows(&tx, &wrong).await.is_err());
    tx.rollback().await.unwrap();
    let tx = db.begin().await.unwrap();
    assert_eq!(delete_sql_and_hook_rows(&tx, &job).await.unwrap(), 7);
    tx.rollback().await.unwrap();
    assert!(repo
        .load_meta("sql", target, "main")
        .await
        .unwrap()
        .is_some());
    let tx = db.begin().await.unwrap();
    assert_eq!(delete_sql_and_hook_rows(&tx, &job).await.unwrap(), 7);
    assert_eq!(delete_sql_and_hook_rows(&tx, &job).await.unwrap(), 0);
    tx.commit().await.unwrap();
    assert!(repo
        .load_meta("sql", target, "main")
        .await
        .unwrap()
        .is_none());
    assert!(repo
        .load_meta("sql", neighbour, "main")
        .await
        .unwrap()
        .is_some());
    for table in ["hook_subscription", "hook_delivery", "signed_kv_ticket"] {
        let count = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                format!("SELECT count(*) AS n FROM {table} WHERE id='neighbour'"),
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(count.try_get::<i64>("", "n").unwrap(), 1);
    }
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

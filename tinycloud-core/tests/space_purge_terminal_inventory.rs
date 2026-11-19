use std::collections::BTreeMap;
use tinycloud_core::{
    migrations::Migrator,
    sea_orm::{ConnectOptions, ConnectionTrait, Database, DbBackend, Statement},
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::LedgerKeys,
    space_purge_worker::{claim_specific, complete},
};

#[tokio::test]
async fn postgres_inventory_survives_failed_completion_and_clears_only_exact_space() {
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!("purge_inventory_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let a = "tinycloud:key:test:inventory";
    let b = "tinycloud:key:test:inventory-neighbor";
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )
    .unwrap();
    for space in [a, b] {
        db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO space(id) VALUES($1)",
            [space.into()],
        ))
        .await
        .unwrap();
        for sql in [
            "INSERT INTO kv_blob_generation(space,value,generation) VALUES($1,$2,1)",
            "INSERT INTO kv_orphan_candidate(space,value,generation,created_at) VALUES($1,$2,1,now())",
            "INSERT INTO kv_orphan_attempt(space,value,attempt_id,generation,created_at) VALUES($1,$2,'upload',1,now())",
        ] {
            db.execute(Statement::from_sql_and_values(DbBackend::Postgres,sql,[space.into(),vec![1u8;32].into()])).await.unwrap();
        }
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO sql_store_manifest(space,db_id,lineage,epoch,revision,base_snapshot_key,base_seq,base_checkpoint_cid,last_seq,publish_id,published_at,frontier_bytes) VALUES($1,'db','lineage',1,1,'key',0,'checkpoint',0,'publish','now',1)",[space.into()])).await.unwrap();
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
            "INSERT INTO sql_store_object(space,db_id,lineage,kind,base_seq,from_seq,to_seq,content_hash,format,key,bytes,state,created_at) VALUES($1,'db','lineage','snap',0,0,0,'hash','raw','key',1,'published','now')",[space.into()])).await.unwrap();
    }
    let purge_id = uuid::Uuid::new_v4().to_string();
    let digest = keys.target_hmac("test", "space", a).unwrap();
    db.execute(Statement::from_sql_and_values(DbBackend::Postgres,
        "INSERT INTO space_purge_job(purge_id,space,tombstone_hmac,hmac_key_id,owner_hmac,accepted_at,phase,fence_generation,updated_at,next_attempt_at,attempt_count) VALUES($3,$1,$2,'test',$2,now(),'objects',1,now(),now(),0)",[a.into(),digest.clone().into(),purge_id.clone().into()])).await.unwrap();
    let job = claim_specific(&db, &uuid::Uuid::new_v4().to_string(), &purge_id)
        .await
        .unwrap()
        .unwrap();
    let record = keys
        .sign(
            "test",
            "space",
            &digest,
            &purge_id,
            "complete",
            time::OffsetDateTime::now_utc().unix_timestamp(),
        )
        .unwrap();
    db.execute_unprepared("CREATE TABLE inventory_blocker(space TEXT REFERENCES space(id))")
        .await
        .unwrap();
    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO inventory_blocker(space) VALUES($1)",
        [a.into()],
    ))
    .await
    .unwrap();
    assert!(complete(&db, &job, &keys, &record).await.is_err());
    for table in [
        "kv_blob_generation",
        "kv_orphan_candidate",
        "kv_orphan_attempt",
        "sql_store_object",
        "sql_store_manifest",
    ] {
        let count: i64 = db
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                format!("SELECT count(*) AS n FROM {table}"),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "n")
            .unwrap();
        assert_eq!(count, 2);
    }
    db.execute_unprepared("DROP TABLE inventory_blocker")
        .await
        .unwrap();
    assert!(complete(&db, &job, &keys, &record).await.unwrap());
    for table in [
        "kv_blob_generation",
        "kv_orphan_candidate",
        "kv_orphan_attempt",
        "sql_store_object",
        "sql_store_manifest",
    ] {
        let rows = db
            .query_all(Statement::from_string(
                DbBackend::Postgres,
                format!("SELECT space FROM {table}"),
            ))
            .await
            .unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].try_get::<String>("", "space").unwrap(), b);
    }
    assert!(!complete(&db, &job, &keys, &record).await.unwrap());
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

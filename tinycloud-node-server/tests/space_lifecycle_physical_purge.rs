use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud::{
    space_lifecycle::{
        list_my_spaces, purge_space, purge_status, retire_owner, LifecycleRuntime, PurgeResponse,
    },
    space_purge_executor::{PhaseOutcome, SpacePurgeExecutor, SqlPurgeStore},
    storage::{
        file_system::FileSystemConfig,
        purge_ledger::PurgeLedgerStore,
        sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore},
    },
    BlockStores,
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    database_artifacts::SeaOrmDatabaseArtifactRepository,
    migrations::Migrator,
    models::{space, space_purge_job},
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database, EntityTrait,
    },
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::LedgerKeys,
    space_purge_worker::claim_specific,
    sql::{SqlRequest, SqlService},
    storage::{either::Either, StorageConfig},
};

fn signed(
    key: &JWK,
    owner: &str,
    action: &str,
    resource: &str,
    now: OffsetDateTime,
) -> (String, String) {
    let id = uuid::Uuid::new_v4().to_string();
    let issued = now.unix_timestamp() as f64;
    let invocation = make_invocation_from_uris(
        [(resource.parse().unwrap(), [action.parse().unwrap()])],
        &Cid::default(),
        key,
        &format!("{owner}#blockchainAccountId"),
        issued + 300.0,
        InvocationOptions {
            not_before: Some(issued),
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: Some(vec![
                serde_json::json!({"idempotency_key":id,"hostId":"host-test"}),
            ]),
            proof: Some(vec![]),
        },
    )
    .unwrap();
    (invocation.encode().unwrap(), id)
}

#[tokio::test]
async fn postgres_owner_http_retirement_and_purge_physically_remove_only_the_target() {
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").unwrap();
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!("lifecycle_physical_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let blocks_root = root.path().join("blocks");
    let cache_root = root.path().join("cache");
    let sql_root = root.path().join("sql-objects");
    let blocks: BlockStores = Either::B(FileSystemConfig::new(&blocks_root).open().await.unwrap());
    let sql_store = FsSqlObjectStore::open(sql_root.clone(), &blocks_root).unwrap();
    let sql = SqlService::new(
        cache_root.to_string_lossy().into_owned(),
        0,
        Arc::new(SeaOrmDatabaseArtifactRepository::new(db.clone())),
    );
    let mut owner_key = JWK::generate_secp256k1();
    owner_key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS
        .generate(&owner_key, "pkh:eip155")
        .unwrap()
        .to_string();
    let target: SpaceId = format!("tinycloud:{}:app", &owner[4..]).parse().unwrap();
    let neighbor: SpaceId = "tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:app"
        .parse()
        .unwrap();
    for id in [&target, &neighbor] {
        space::ActiveModel {
            id: Set(id.clone().into()),
        }
        .insert(&db)
        .await
        .unwrap();
        sql.execute(
            id,
            "main",
            SqlRequest::Execute {
                sql: "CREATE TABLE entries(id INTEGER)".into(),
                params: vec![],
                schema: None,
            },
            None,
            "tinycloud.sql/admin".into(),
        )
        .await
        .unwrap();
        let kv = blocks_root.join(id.suffix()).join(id.name().as_str());
        std::fs::create_dir_all(&kv).unwrap();
        std::fs::write(kv.join("sentinel"), b"private kv bytes").unwrap();
        let objects = sql_root
            .join(SqlPhysicalPrefix::for_space(id).as_str())
            .join("db/lineage/snap");
        std::fs::create_dir_all(&objects).unwrap();
        std::fs::write(objects.join("sentinel"), b"private SQL bytes").unwrap();
    }
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![19; 32])]),
        )
        .unwrap(),
    );
    let ledger: Arc<dyn PurgeLedgerStore> = match &blocks {
        Either::B(store) => Arc::new(store.clone()),
        Either::A(_) => unreachable!(),
    };
    // Exercise the real five-minute worker grace without sleeping or changing
    // accepted DB rows: the trusted controller clock models earlier acceptance.
    let accepted_time = OffsetDateTime::now_utc() - time::Duration::minutes(6);
    let runtime = LifecycleRuntime::new(
        db.clone().into(),
        keys.clone(),
        ledger.clone(),
        "host-test".into(),
    )
    .unwrap()
    .with_storage_layout(
        tinycloud::space_lifecycle::PurgeStorageLayout::new(
            tinycloud::storage::purge_reconcile::PrefixStoreKind::KvFileSystem,
            tinycloud::storage::purge_reconcile::PrefixStoreKind::SqlFileSystem,
            false,
        )
        .unwrap(),
    )
    .with_clock(Arc::new(move || accepted_time));
    runtime.verify_ledger().await.unwrap();
    let fence = runtime.fence.clone();
    let client = Client::tracked(rocket::build().manage(runtime).mount(
        "/",
        rocket::routes![retire_owner, list_my_spaces, purge_space, purge_status],
    ))
    .await
    .unwrap();
    let (jwt, id) = signed(
        &owner_key,
        &owner,
        "tinycloud.space/retire-owner",
        &owner,
        accepted_time,
    );
    let response = client
        .post("/space/retire-owner")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt))
        .header(Header::new("Idempotency-Key", id))
        .json(&serde_json::json!({"version":1,"owner_did":owner}))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Accepted);
    assert_eq!(
        response.into_json::<serde_json::Value>().await.unwrap()["hostId"],
        "host-test"
    );
    let (jwt, id) = signed(
        &owner_key,
        &owner,
        "tinycloud.space/list",
        &owner,
        accepted_time,
    );
    let response = client
        .post("/space/list")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt))
        .header(Header::new("Idempotency-Key", id))
        .json(&serde_json::json!({"version":1,"ownerDid":owner,"cursor":null}))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(
        response.into_json::<serde_json::Value>().await.unwrap()["spaces"],
        serde_json::json!([target.to_string()])
    );
    let resource = format!("{target}/space");
    let (jwt, id) = signed(
        &owner_key,
        &owner,
        "tinycloud.space/delete",
        &resource,
        accepted_time,
    );
    let response = client
        .post("/space/purge")
        .header(ContentType::JSON)
        .header(Header::new("Authorization", jwt))
        .header(Header::new("Idempotency-Key", id))
        .json(&serde_json::json!({"version":1,"space_id":target.to_string()}))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Accepted);
    let accepted = response.into_json::<PurgeResponse>().await.unwrap();
    assert_eq!(accepted.state, "purging");
    let drain = fence.drain(&db, &target).await.unwrap();
    let executor = SpacePurgeExecutor {
        db: &db,
        blocks: &blocks,
        sql: &sql,
        #[cfg(feature = "duckdb")]
        duckdb: None,
        sql_objects: Some(SqlPurgeStore::FileSystem(&sql_store)),
        keys: &keys,
        encryption: None,
    };
    let mut complete = false;
    for _ in 0..12 {
        let job = claim_specific(&db, &uuid::Uuid::new_v4().to_string(), &accepted.purge_id)
            .await
            .unwrap()
            .unwrap();
        match executor.execute_claimed(&job, &drain).await.unwrap() {
            PhaseOutcome::Advanced | PhaseOutcome::MoreObjects => {}
            PhaseOutcome::Complete => {
                complete = true;
                break;
            }
            other => panic!("unexpected purge phase outcome: {other:?}"),
        }
    }
    assert!(complete);
    drop(drain);
    assert!(!blocks_root
        .join(target.suffix())
        .join(target.name().as_str())
        .exists());
    assert!(!sql_root
        .join(SqlPhysicalPrefix::for_space(&target).as_str())
        .exists());
    assert!(!cache_root.join(target.to_string()).exists());
    assert_eq!(
        std::fs::read(
            blocks_root
                .join(neighbor.suffix())
                .join(neighbor.name().as_str())
                .join("sentinel")
        )
        .unwrap(),
        b"private kv bytes"
    );
    assert!(sql.export(&neighbor, "main").await.is_ok());
    let job = space_purge_job::Entity::find_by_id(&accepted.purge_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.phase, "complete");
    assert!(job.space.is_none());
    let (jwt, id) = signed(
        &owner_key,
        &owner,
        "tinycloud.space/delete",
        &resource,
        accepted_time,
    );
    let response = client.post("/space/purge/status").header(ContentType::JSON).header(Header::new("Authorization", jwt))
        .header(Header::new("Idempotency-Key", id)).json(&serde_json::json!({"version":1,"space_id":target.to_string(),"purge_id":accepted.purge_id})).dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let status = response.into_json::<PurgeResponse>().await.unwrap();
    assert_eq!(status.state, "complete");
    assert_eq!(status.host_id, "host-test");
    let records = ledger.list_purge_records().await.unwrap();
    assert_eq!(records.len(), 3);
    for path in records {
        keys.verify(
            &path,
            &ledger.read_purge_record(&path).await.unwrap().unwrap(),
        )
        .unwrap();
    }
    sql.drain_and_evict_space(&neighbor).await.unwrap();
    drop(client);
    drop(sql);
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

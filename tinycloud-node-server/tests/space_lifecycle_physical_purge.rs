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
    space_purge_executor::{
        PhaseOutcome, PurgeSqlObjects, PurgeStores, SpacePurgeExecutor, SqlPurgeStore,
    },
    space_purge_owner_erasure::{erase_retired_owners, publish_erased, OwnerErasureReport},
    storage::{
        file_system::FileSystemConfig,
        purge_ledger::{FsPurgeLedger, PurgeLedger, PurgeLedgerStore},
        sql_object::{purge::SqlPhysicalPrefix, FsSqlObjectStore},
    },
    BlockStores,
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    identity::canonicalize_did,
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    database_artifacts::SeaOrmDatabaseArtifactRepository,
    encryption_network::deletion_ledger::{DeletionLedger, Intent, LedgerKey, Record},
    migrations::Migrator,
    models::{space, space_purge_job, space_retirement},
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, DbBackend, EntityTrait, Statement,
    },
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::{owner_object_key, LedgerKeys},
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

const ENCRYPTION_TABLES: [&str; 5] = [
    "encryption_network",
    "encryption_network_key",
    "encryption_network_member",
    "encryption_ceremony",
    "encryption_audit",
];

/// One row per encryption table for `owner`'s `default` network.
async fn insert_network(db: &DatabaseConnection, owner: &str) -> String {
    let network = format!("urn:tinycloud:encryption:{owner}:default");
    for (sql, owned) in [
        ("INSERT INTO encryption_network(network_id,owner_did,name,alg,key_version,public_key,state,threshold_n,threshold_t,key_backend,created_at,updated_at)
          VALUES($1,$2,'default','test',1,'\\x01','active',1,1,'local','now','now')", true),
        ("INSERT INTO encryption_network_key(network_id,key_path,kind,state,public_key,created_at,updated_at)
          VALUES($1,'key','test','active','\\x01','now','now')", false),
        ("INSERT INTO encryption_network_member(network_id,node_id,role,share_index,joined_at)
          VALUES($1,'node','member',1,'now')", false),
        ("INSERT INTO encryption_ceremony(ceremony_id,network_id,kind,state,started_at)
          VALUES($1||'#ceremony',$1,'test','complete','now')", false),
        ("INSERT INTO encryption_audit(request_hash,requester,network_id,node_id,outcome,decided_at)
          VALUES($1||'#audit',$2,$1,'node','ok','now')", true),
    ] {
        let mut values = vec![network.clone().into()];
        if owned {
            values.push(owner.into());
        }
        db.execute(Statement::from_sql_and_values(DbBackend::Postgres, sql, values))
            .await
            .unwrap();
    }
    network
}

/// Rows of `network` per table, in [`ENCRYPTION_TABLES`] order.
async fn network_rows(db: &DatabaseConnection, network: &str) -> [i64; 5] {
    let mut rows = [0; 5];
    for (n, table) in ENCRYPTION_TABLES.into_iter().enumerate() {
        rows[n] = db
            .query_one(Statement::from_sql_and_values(
                DbBackend::Postgres,
                format!("SELECT count(*) AS n FROM {table} WHERE network_id=$1"),
                [network.into()],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap();
    }
    rows
}

/// A `deletions.jsonl` holding one settled key delete per network.
fn deletions_with(dir: &std::path::Path, networks: &[&str]) -> Arc<DeletionLedger> {
    let ledger = DeletionLedger::open(&dir.join("deletions.jsonl")).unwrap();
    for (n, network) in networks.iter().enumerate() {
        let op = format!("op-{n}");
        ledger
            .append(&Record::Intent(Intent {
                op: op.clone(),
                network_id: (*network).to_owned(),
                keys: vec![LedgerKey {
                    key_path: "key".into(),
                    key_version: 1,
                }],
                deleted_at: "2026-11-19T00:00:00Z".into(),
            }))
            .unwrap();
        ledger.append(&Record::committed(&op)).unwrap();
    }
    Arc::new(ledger)
}

fn ledger_names(ledger: &DeletionLedger, network: &str) -> bool {
    String::from_utf8(std::fs::read(ledger.path()).unwrap())
        .unwrap()
        .contains(network)
}

/// The stores reconcile runs against, over the test's `blocks` and
/// `sql-objects` directories.
async fn reconcile_stores(
    root: &std::path::Path,
    sql: &SqlService,
    ledger: &Arc<PurgeLedger>,
    deletions: &Arc<DeletionLedger>,
) -> PurgeStores {
    let blocks_root = root.join("blocks");
    PurgeStores {
        blocks: Either::B(FileSystemConfig::new(&blocks_root).open().await.unwrap()),
        ledger: ledger.clone(),
        sql: sql.clone(),
        #[cfg(feature = "duckdb")]
        duckdb: None,
        sql_objects: PurgeSqlObjects::FileSystem(
            FsSqlObjectStore::open(root.join("sql-objects"), &blocks_root).unwrap(),
        ),
        encryption: None,
        deletions: Some(deletions.clone()),
    }
}

// test-ruling: TC-2871 ledger out of the data bucket (Naomi 11-18): the runtime
// and the executor share one ledger in its own directory, apart from `blocks`.
// test-ruling: TC-2871 option A (Naomi 11-19): a crash after the `erased`
// record is published leaves the rows; reconcile deletes and prunes them,
// and a neighbor that is not retired keeps its rows and gets no record.
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
    let purge_ledger = Arc::new(PurgeLedger::Local(
        FsPurgeLedger::new(root.path().join("purge-ledger")).unwrap(),
    ));
    let ledger: Arc<dyn PurgeLedgerStore> = purge_ledger.clone();
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
    let reconciler = runtime.clone();
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
        ledger: &purge_ledger,
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

    // Crash after step (a): the `erased` record is published, the rows are
    // not yet deleted. Reconcile deletes and prunes them through the record;
    // the neighbor, never retired, keeps its rows and gets no record.
    let canonical = canonicalize_did(&owner).unwrap();
    let network = insert_network(&db, &canonical).await;
    let neighbor_network = insert_network(
        &db,
        "did:pkh:eip155:1:0x2222222222222222222222222222222222222222",
    )
    .await;
    let deletions = deletions_with(root.path(), &[&network, &neighbor_network]);
    let retirement = space_retirement::Entity::find()
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let retired_path = owner_object_key(
        &retirement.hmac_key_id,
        &hex::encode(&retirement.owner_hmac),
        "retired",
    )
    .unwrap();
    let retired = keys
        .verify(
            &retired_path,
            &ledger
                .read_purge_record(&retired_path)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    let erased = keys
        .erasure_from_retirement(&retired, OffsetDateTime::now_utc().unix_timestamp())
        .unwrap();
    publish_erased(&*ledger, &keys, &erased).await.unwrap();
    assert_eq!(network_rows(&db, &network).await, [1; 5]);
    let stores = reconcile_stores(root.path(), &sql, &purge_ledger, &deletions).await;
    let report = reconciler.reconcile(&stores).await.unwrap();
    assert_eq!(
        report.owner_retirements, 1,
        "an erased record is no retirement"
    );
    assert_eq!(
        (
            report.owners_erased_redeleted,
            report.owners_pruned,
            report.blocked_rows_present
        ),
        (1, 1, 0)
    );
    assert_eq!(network_rows(&db, &network).await, [0; 5]);
    assert!(!ledger_names(&deletions, &network));
    assert_eq!(network_rows(&db, &neighbor_network).await, [1; 5]);
    assert!(ledger_names(&deletions, &neighbor_network));
    assert_eq!(
        erase_retired_owners(&db, &*purge_ledger, &keys, Some(&deletions))
            .await
            .unwrap(),
        OwnerErasureReport::default()
    );
    assert_eq!(
        ledger.list_purge_records().await.unwrap().len(),
        4,
        "one erased record, none for the neighbor"
    );
    drop(stores);
    sql.drain_and_evict_space(&neighbor).await.unwrap();
    drop(client);
    drop(sql);
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

// Regression: a space ID keeps its creator's address casing, so the purge
// job's owner digest must cover the canonical owner DID. Otherwise it never
// matches the retirement's, and a retired owner's encryption networks survive
// the purge of their last space.
// test-ruling: TC-2871 option A (Naomi 11-19): the purge keeps the networks;
// the owner-erasure step publishes the `erased` record, deletes every
// encryption row (audit included) and prunes `deletions.jsonl`, and reconcile
// deletes restored rows again.
#[tokio::test]
async fn postgres_retired_owner_purge_of_lowercase_address_space_deletes_owner_networks() {
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").unwrap();
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!("lifecycle_owner_case_{}", uuid::Uuid::new_v4().simple());
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
    let sql_root = root.path().join("sql-objects");
    let blocks: BlockStores = Either::B(FileSystemConfig::new(&blocks_root).open().await.unwrap());
    let sql_store = FsSqlObjectStore::open(sql_root.clone(), &blocks_root).unwrap();
    let sql = SqlService::new(
        root.path().join("cache").to_string_lossy().into_owned(),
        0,
        Arc::new(SeaOrmDatabaseArtifactRepository::new(db.clone())),
    );
    let mut owner_key = JWK::generate_secp256k1();
    owner_key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS
        .generate(&owner_key, "pkh:eip155")
        .unwrap()
        .to_string();
    let canonical = canonicalize_did(&owner).unwrap();
    let lowercase = canonical.to_lowercase();
    assert_ne!(lowercase, canonical, "the address must carry EIP-55 case");
    let target: SpaceId = format!("tinycloud:{}:app", &lowercase[4..])
        .parse()
        .unwrap();
    space::ActiveModel {
        id: Set(target.clone().into()),
    }
    .insert(&db)
    .await
    .unwrap();
    let network = insert_network(&db, &canonical).await;
    let other_network =
        "urn:tinycloud:encryption:did:pkh:eip155:1:0x2222222222222222222222222222222222222222:default";
    let deletions = deletions_with(root.path(), &[&network, other_network]);
    let keys = Arc::new(
        LedgerKeys::new(
            "test".into(),
            BTreeMap::from([("test".into(), vec![19; 32])]),
        )
        .unwrap(),
    );
    let purge_ledger = Arc::new(PurgeLedger::Local(
        FsPurgeLedger::new(root.path().join("purge-ledger")).unwrap(),
    ));
    let ledger: Arc<dyn PurgeLedgerStore> = purge_ledger.clone();
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
    let reconciler = runtime.clone();
    let client = Client::tracked(
        rocket::build()
            .manage(runtime)
            .mount("/", rocket::routes![retire_owner, purge_space]),
    )
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
    drop(response);
    let (jwt, id) = signed(
        &owner_key,
        &owner,
        "tinycloud.space/delete",
        &format!("{target}/space"),
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
    let job = space_purge_job::Entity::find_by_id(&accepted.purge_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        job.owner_hmac,
        keys.target_hmac(&job.hmac_key_id, "owner", &canonical)
            .unwrap()
    );
    let drain = fence.drain(&db, &target).await.unwrap();
    let executor = SpacePurgeExecutor {
        db: &db,
        blocks: &blocks,
        ledger: &purge_ledger,
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
    assert_eq!(
        network_rows(&db, &network).await,
        [1; 5],
        "purges keep rows"
    );

    // (a) record, (b) rows, (c) prune: the owner is erased once.
    let report = erase_retired_owners(&db, &*purge_ledger, &keys, Some(&deletions))
        .await
        .unwrap();
    assert_eq!(
        report,
        OwnerErasureReport {
            owners_erased: 1,
            owners_rows_deleted: 1,
            owners_pruned: 1,
            blocked_rows_present: 0,
        }
    );
    let erased_path = owner_object_key("test", &hex::encode(&job.owner_hmac), "erased").unwrap();
    let erased = keys
        .verify(
            &erased_path,
            &ledger
                .read_purge_record(&erased_path)
                .await
                .unwrap()
                .unwrap(),
        )
        .unwrap();
    assert_eq!(
        (erased.kind.as_str(), erased.state.as_str()),
        ("owner", "erased")
    );
    assert_eq!(network_rows(&db, &network).await, [0; 5], "audit included");
    assert!(!ledger_names(&deletions, &network));
    assert!(ledger_names(&deletions, other_network), "other owner kept");
    assert_eq!(
        erase_retired_owners(&db, &*purge_ledger, &keys, Some(&deletions))
            .await
            .unwrap(),
        OwnerErasureReport::default()
    );

    // A restore brings the rows back; reconcile deletes them again through
    // the `erased` record, and a second pass finds nothing.
    insert_network(&db, &canonical).await;
    let stores = reconcile_stores(root.path(), &sql, &purge_ledger, &deletions).await;
    let report = reconciler.reconcile(&stores).await.unwrap();
    assert_eq!(
        (report.owners_erased_redeleted, report.blocked_rows_present),
        (1, 0)
    );
    assert_eq!(network_rows(&db, &network).await, [0; 5]);
    let report = reconciler.reconcile(&stores).await.unwrap();
    assert_eq!(
        (
            report.owners_erased_redeleted,
            report.owners_pruned,
            report.blocked_rows_present
        ),
        (0, 0, 0)
    );
    drop(stores);
    drop(client);
    drop(sql);
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

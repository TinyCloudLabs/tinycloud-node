use std::{collections::BTreeMap, io::Write};
use tinycloud_core::{
    database_artifacts::{
        chunks::{ChunkLimits, CHUNK_BYTES},
        ArtifactExpectation, DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository,
    },
    migrations::Migrator,
    sea_orm::{
        ConnectOptions, ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement,
        TransactionTrait, Value,
    },
    sea_orm_migration::MigratorTrait,
    space_purge_database::{delete_sql_and_hook_rows, reap_artifact_parts},
    space_purge_ledger::LedgerKeys,
    space_purge_worker::{advance, claim, claim_specific, complete},
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
        db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "INSERT INTO sql_database(space,name,created_at) VALUES($1,'main',now())",
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
    assert_eq!(delete_sql_and_hook_rows(&tx, &job).await.unwrap(), 8);
    tx.rollback().await.unwrap();
    assert!(repo
        .load_meta("sql", target, "main")
        .await
        .unwrap()
        .is_some());
    let tx = db.begin().await.unwrap();
    assert_eq!(delete_sql_and_hook_rows(&tx, &job).await.unwrap(), 8);
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
    let remaining = db
        .query_all(Statement::from_string(
            DbBackend::Postgres,
            "SELECT space FROM sql_database",
        ))
        .await
        .unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(
        remaining[0].try_get::<String>("", "space").unwrap(),
        neighbour
    );
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

const OWNER: &str = "did:pkh:eip155:1:0x0000000000000000000000000000000000000001";
const TARGET: &str = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:target";
const KEPT: &str = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:kept";
const OTHER_OWNER: &str = "did:pkh:eip155:1:0x0000000000000000000000000000000000000002";
const OTHER: &str = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000002:other";
const LATER: &str = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:later";
const LAST: &str = "tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:last";

fn snapshot(bytes: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    file
}

async fn exec(db: &DatabaseConnection, sql: &str, values: Vec<Value>) {
    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        values,
    ))
    .await
    .unwrap();
}

async fn int(db: &DatabaseConnection, sql: &str, values: Vec<Value>) -> i64 {
    db.query_one(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        values,
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get("", "n")
    .unwrap()
}

/// (chunks, parts, space-owner rows) naming `space`.
async fn artifact_rows(db: &DatabaseConnection, space: &str) -> (i64, i64, i64) {
    let mut rows = [0; 3];
    for (n, table) in ["artifact_chunk", "artifact_part", "artifact_space_owner"]
        .into_iter()
        .enumerate()
    {
        rows[n] = int(
            db,
            &format!("SELECT count(*) AS n FROM {table} WHERE space=$1"),
            vec![space.into()],
        )
        .await;
    }
    (rows[0], rows[1], rows[2])
}

/// One row per encryption-network table for a network of `owner`.
async fn network(db: &DatabaseConnection, owner: &str) {
    let id = format!("urn:tinycloud:encryption:{owner}:default");
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
        let mut values = vec![id.clone().into()];
        if owned {
            values.push(owner.into());
        }
        exec(db, sql, values).await;
    }
}

/// Rows of `owner`'s networks: (network, key, member, ceremony, audit).
async fn networks(db: &DatabaseConnection, owner: &str) -> [i64; 5] {
    let mut rows = [0; 5];
    for (n, table) in [
        "encryption_network",
        "encryption_network_key",
        "encryption_network_member",
        "encryption_ceremony",
        "encryption_audit",
    ]
    .into_iter()
    .enumerate()
    {
        rows[n] = int(
            db,
            &format!("SELECT count(*) AS n FROM {table} WHERE network_id LIKE 'urn:tinycloud:encryption:'||$1||':%'"),
            vec![owner.into()],
        )
        .await;
    }
    rows
}

/// (legacy, reserved, credit) bytes of an owner's account, if it exists.
async fn account(db: &DatabaseConnection, owner: &str) -> Option<(i64, i64, i64)> {
    db.query_one(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT legacy_bytes,reserved_bytes,credit_bytes FROM artifact_account WHERE owner=$1",
        [owner.into()],
    ))
    .await
    .unwrap()
    .map(|row| {
        (
            row.try_get("", "legacy_bytes").unwrap(),
            row.try_get("", "reserved_bytes").unwrap(),
            row.try_get("", "credit_bytes").unwrap(),
        )
    })
}

/// The usage an owner's remaining rows account for, by the chunks.sql ledger.
async fn usage(db: &DatabaseConnection, owner: &str) -> (i64, i64, i64) {
    let row = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT (SELECT COALESCE(sum(size_bytes),0)::bigint FROM database_artifact
                WHERE checkpoint_part_id IS NULL AND artifact_owner(space)=$1) AS legacy,
             (SELECT COALESCE(sum(size_bytes),0)::bigint FROM artifact_part WHERE owner=$1) AS reserved,
             (SELECT COALESCE(sum(replacement_credit),0)::bigint FROM artifact_part WHERE owner=$1) AS credit",
            [owner.into()],
        ))
        .await
        .unwrap()
        .unwrap();
    (
        row.try_get("", "legacy").unwrap(),
        row.try_get("", "reserved").unwrap(),
        row.try_get("", "credit").unwrap(),
    )
}

/// Reserve a part in any pre-publication state and upload `chunks` payloads.
#[allow(clippy::too_many_arguments)]
async fn part(
    db: &DatabaseConnection,
    space: &str,
    name: &str,
    id: &str,
    size: i64,
    base: Option<(i64, String)>,
    chunks: &[usize],
    state: &str,
) {
    let (revision, hash) = base.unzip();
    let admitted = db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT artifact_reserve('sql',$1,$2,$3,artifact_owner($1),$4,$5,$6,$7) AS ok",
            [
                space.into(),
                name.into(),
                id.into(),
                size.into(),
                i32::try_from((size as u64).div_ceil(CHUNK_BYTES as u64))
                    .unwrap()
                    .into(),
                revision.into(),
                hash.into(),
            ],
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get::<bool>("", "ok")
        .unwrap();
    assert!(admitted);
    for (ordinal, len) in chunks.iter().enumerate() {
        exec(
            db,
            "INSERT INTO artifact_chunk(service,space,name,part_id,ordinal,payload) VALUES('sql',$1,$2,$3,$4,$5)",
            vec![
                space.into(),
                name.into(),
                id.into(),
                (ordinal as i32).into(),
                vec![9u8; *len].into(),
            ],
        )
        .await;
    }
    if state != "uploading" {
        exec(
            db,
            "UPDATE artifact_part SET state=$2,content_hash='synthetic' WHERE part_id=$1",
            vec![id.into(), state.into()],
        )
        .await;
    }
}

/// Accept owner retirement as `retire_owner` records it: the owner digest
/// under the job's key id.
async fn retire(db: &DatabaseConnection, keys: &LedgerKeys, owner: &str) {
    exec(
        db,
        "INSERT INTO space_retirement(owner_hmac,hmac_key_id,retirement_id,accepted_at)
         VALUES($1,'test',$2,now())",
        vec![
            keys.target_hmac("test", "owner", owner).unwrap().into(),
            uuid::Uuid::new_v4().to_string().into(),
        ],
    )
    .await;
}

/// Drive one space through database, access and objects to completion,
/// repeating each step to show it is idempotent. Returns the reap batches.
async fn purge(db: &DatabaseConnection, keys: &LedgerKeys, space: &str) -> usize {
    let purge_id = uuid::Uuid::new_v4().to_string();
    let digest = keys.target_hmac("test", "space", space).unwrap();
    // Space acceptance digests the space's DID under the job's key id.
    let (did, _) = space
        .strip_prefix("tinycloud:")
        .unwrap()
        .rsplit_once(':')
        .unwrap();
    let owner = keys
        .target_hmac("test", "owner", &format!("did:{did}"))
        .unwrap();
    exec(db,
        "INSERT INTO space_purge_job(purge_id,space,tombstone_hmac,hmac_key_id,owner_hmac,accepted_at,phase,fence_generation,updated_at,next_attempt_at,attempt_count)
         VALUES($1,$2,$3,'test',$4,now(),'database',1,now(),now(),0)",
        vec![purge_id.clone().into(), space.into(), digest.clone().into(), owner.into()]).await;
    let lease = || uuid::Uuid::new_v4().to_string();
    let job = claim_specific(db, &lease(), &purge_id)
        .await
        .unwrap()
        .unwrap();
    let tx = db.begin().await.unwrap();
    delete_sql_and_hook_rows(&tx, &job).await.unwrap();
    assert_eq!(delete_sql_and_hook_rows(&tx, &job).await.unwrap(), 0);
    assert!(advance(&tx, &job).await.unwrap());
    tx.commit().await.unwrap();
    let job = claim_specific(db, &lease(), &purge_id)
        .await
        .unwrap()
        .unwrap();
    assert!(advance(db, &job).await.unwrap());
    let job = claim_specific(db, &lease(), &purge_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(job.phase, "objects");
    let mut batches = 1;
    while !reap_artifact_parts(db, &job, 2).await.unwrap() {
        batches += 1;
        assert!(batches < 64, "reaping must make progress");
    }
    assert!(reap_artifact_parts(db, &job, 2).await.unwrap());
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
    assert!(complete(db, &job, keys, &record).await.unwrap());
    assert!(!complete(db, &job, keys, &record).await.unwrap());
    batches
}

#[tokio::test]
async fn postgres_purge_erases_chunked_artifacts_and_last_owner_rows() {
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!("purge_chunks_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )
    .unwrap();
    assert_eq!(
        int(
            &db,
            "SELECT count(*) AS n WHERE artifact_owner($1)=$2",
            vec![TARGET.into(), OWNER.into()]
        )
        .await,
        1
    );
    let legacy = SeaOrmDatabaseArtifactRepository::new(db.clone());
    let repo = legacy.clone().with_chunk_limits(Some(ChunkLimits {
        artifact_bytes: 4 * CHUNK_BYTES as u64,
        account_bytes: 64 * CHUNK_BYTES as u64,
    }));
    let checkpoint = vec![5u8; CHUNK_BYTES + 512];
    let mut published = BTreeMap::new();
    for space in [TARGET, KEPT, OTHER] {
        exec(&db, "INSERT INTO space(id) VALUES($1)", vec![space.into()]).await;
        legacy
            .save(
                "sql",
                space,
                "legacy",
                vec![1; 128],
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        let meta = repo
            .save_snapshot(
                "sql",
                space,
                "main",
                snapshot(&checkpoint),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        published.insert(space, (meta.revision, meta.checkpoint_content_hash));
    }
    // Target parts in every state, including an in-flight replacement chain
    // whose credit is charged against the published checkpoint.
    let replacement = CHUNK_BYTES as i64 + 100;
    part(
        &db,
        TARGET,
        "main",
        "replacement",
        replacement,
        published.get(TARGET).cloned(),
        &[CHUNK_BYTES],
        "uploading",
    )
    .await;
    part(
        &db,
        TARGET,
        "fresh",
        "uploading",
        600,
        None,
        &[300],
        "uploading",
    )
    .await;
    part(&db, TARGET, "sealed", "sealed", 400, None, &[400], "sealed").await;
    part(
        &db,
        TARGET,
        "stale",
        "deleting",
        200,
        None,
        &[200],
        "deleting",
    )
    .await;
    part(
        &db,
        KEPT,
        "fresh",
        "kept-uploading",
        300,
        None,
        &[300],
        "uploading",
    )
    .await;
    let states = int(
        &db,
        "SELECT count(DISTINCT state) AS n FROM artifact_part WHERE space=$1",
        vec![TARGET.into()],
    )
    .await;
    assert_eq!(states, 4, "uploading, sealed, published and deleting parts");
    let checkpoint_size = checkpoint.len() as i64;
    assert_eq!(
        account(&db, OWNER).await,
        Some((
            256,
            2 * checkpoint_size + replacement + 600 + 400 + 200 + 300,
            replacement
        ))
    );
    assert_eq!(account(&db, OWNER).await, Some(usage(&db, OWNER).await));
    assert_eq!(artifact_rows(&db, TARGET).await, (6, 5, 1));
    let kept = artifact_rows(&db, KEPT).await;
    let other = artifact_rows(&db, OTHER).await;
    let other_account = account(&db, OTHER_OWNER).await;
    assert_eq!(kept, (3, 2, 1));
    assert_eq!(other, (2, 1, 1));
    network(&db, OWNER).await;
    network(&db, OTHER_OWNER).await;
    assert_eq!(networks(&db, OWNER).await, [1; 5]);

    assert!(
        purge(&db, &keys, TARGET).await > 1,
        "reaping is bounded per batch"
    );
    assert_eq!(artifact_rows(&db, TARGET).await, (0, 0, 0));
    assert_eq!(
        int(
            &db,
            "SELECT count(*) AS n FROM database_artifact WHERE space=$1",
            vec![TARGET.into()]
        )
        .await,
        0
    );
    assert_eq!(artifact_rows(&db, KEPT).await, kept);
    assert_eq!(artifact_rows(&db, OTHER).await, other);
    assert_eq!(
        account(&db, OWNER).await,
        Some((128, checkpoint_size + 300, 0))
    );
    assert_eq!(account(&db, OWNER).await, Some(usage(&db, OWNER).await));
    assert_eq!(account(&db, OTHER_OWNER).await, other_account);
    assert_eq!(networks(&db, OWNER).await, [1; 5], "KEPT is still live");

    // Purging the owner's last space is not account erasure: without this
    // owner's retirement (another owner's does not count) the networks stay.
    // The artifact quota counters go; they are re-created on demand.
    retire(&db, &keys, OTHER_OWNER).await;
    purge(&db, &keys, KEPT).await;
    assert_eq!(artifact_rows(&db, KEPT).await, (0, 0, 0));
    assert_eq!(account(&db, OWNER).await, None);
    assert_eq!(networks(&db, OWNER).await, [1; 5], "owner is not retired");
    assert_eq!(artifact_rows(&db, OTHER).await, other);
    assert_eq!(account(&db, OTHER_OWNER).await, other_account);
    assert_eq!(
        account(&db, OTHER_OWNER).await,
        Some(usage(&db, OTHER_OWNER).await)
    );
    assert_eq!(networks(&db, OTHER_OWNER).await, [1; 5]);

    // A retired owner keeps the networks while a live space remains; the
    // last space takes the owner-keyed rows with it. The key-operation audit
    // trail stays (RETAINED).
    for space in [LATER, LAST] {
        exec(&db, "INSERT INTO space(id) VALUES($1)", vec![space.into()]).await;
    }
    retire(&db, &keys, OWNER).await;
    purge(&db, &keys, LATER).await;
    assert_eq!(networks(&db, OWNER).await, [1; 5], "LAST is still live");
    purge(&db, &keys, LAST).await;
    assert_eq!(networks(&db, OWNER).await, [0, 0, 0, 0, 1]);
    assert_eq!(networks(&db, OTHER_OWNER).await, [1; 5], "OTHER is live");
    let spaces = int(
        &db,
        "SELECT count(*) AS n FROM space WHERE id IN ($1,$2,$3,$4)",
        vec![TARGET.into(), KEPT.into(), LATER.into(), LAST.into()],
    )
    .await;
    assert_eq!(spaces, 0);
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

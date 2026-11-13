use std::{collections::BTreeMap, io};
use time::OffsetDateTime;
use tinycloud::storage::{
    file_system::FileSystemConfig, purge_completion::complete_purge, purge_ledger::PurgeLedgerStore,
};
use tinycloud_core::sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database, DbBackend,
    EntityTrait, Statement,
};
use tinycloud_core::{
    migrations::Migrator,
    models::{space_purge_job, space_purge_tombstone},
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::LedgerKeys,
    space_purge_worker::claim,
    storage::StorageConfig,
};

struct UnavailableLedger;
#[rocket::async_trait]
impl PurgeLedgerStore for UnavailableLedger {
    async fn append_purge_record(&self, _: &str, _: &[u8]) -> io::Result<()> {
        Err(io::Error::other("test publication failure"))
    }
    async fn read_purge_record(&self, _: &str) -> io::Result<Option<Vec<u8>>> {
        Err(io::Error::other("test read failure"))
    }
    async fn list_purge_records(&self) -> io::Result<Vec<String>> {
        Err(io::Error::other("test list failure"))
    }
}

#[tokio::test]
async fn postgres_completion_resumes_after_ledger_publication_and_clears_identity_atomically() {
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!("purge_complete_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let store = FileSystemConfig::new(root.path()).open().await.unwrap();
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )
    .unwrap();
    let space = "tinycloud:key:test:completion";
    let target = keys.target_hmac("test", "space", space).unwrap();
    let purge_id = uuid::Uuid::new_v4().to_string();
    let now = OffsetDateTime::now_utc();
    let accepted_at = OffsetDateTime::from_unix_timestamp(now.unix_timestamp() - 600).unwrap();
    let identity: tinycloud_auth::resource::SpaceId = space.parse().unwrap();
    let accepted = keys
        .with_prefixes(
            keys.sign(
                "test",
                "space",
                &target,
                &purge_id,
                "purging",
                accepted_at.unix_timestamp(),
            )
            .unwrap(),
            vec![keys
                .prefix_hmac(
                    "test",
                    "kv-filesystem",
                    &format!("{}/{}/", identity.suffix(), identity.name()),
                )
                .unwrap()],
        )
        .unwrap();
    let accepted_path = accepted.object_key().unwrap();
    let accepted_body = accepted.to_bytes().unwrap();
    store
        .append_purge_record(&accepted_path, &accepted_body)
        .await
        .unwrap();
    tinycloud_core::space_purge_ledger_copy::retain(
        &db,
        &keys,
        &accepted_path,
        &accepted_body,
        now,
    )
    .await
    .unwrap();

    space_purge_job::ActiveModel {
        purge_id: Set(purge_id.clone()),
        space: Set(Some(space.into())),
        tombstone_hmac: Set(target.clone()),
        hmac_key_id: Set("test".into()),
        owner_hmac: Set(vec![8; 32]),
        accepted_at: Set(accepted_at),
        phase: Set("objects".into()),
        fence_generation: Set(1),
        updated_at: Set(now),
        next_attempt_at: Set(now),
        attempt_count: Set(0),
        last_error_code: Set(None),
        lease_token: Set(None),
        lease_until: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();
    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO space(id) VALUES($1)",
        [space.into()],
    ))
    .await
    .unwrap();
    let job = claim(&db, &uuid::Uuid::new_v4().to_string())
        .await
        .unwrap()
        .unwrap();
    assert!(complete_purge(&db, &UnavailableLedger, &keys, &job)
        .await
        .is_err());
    assert_eq!(
        space_purge_job::Entity::find_by_id(&purge_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .phase,
        "objects"
    );
    assert!(space_purge_tombstone::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
    // Simulate a successful external write followed by process death before DB commit.
    let previous_timestamp = now.unix_timestamp() - 10;
    let record = keys
        .completion_from_acceptance(accepted, previous_timestamp)
        .unwrap();
    let path = record.object_key().unwrap();
    store
        .append_purge_record(&path, &record.to_bytes().unwrap())
        .await
        .unwrap();
    drop(store);
    let store = FileSystemConfig::new(root.path()).open().await.unwrap();
    let mut stale = job.clone();
    stale.lease_token = uuid::Uuid::new_v4().to_string();
    assert!(!complete_purge(&db, &store, &keys, &stale).await.unwrap());
    db.execute_unprepared("CREATE TABLE completion_blocker (space TEXT REFERENCES space(id))")
        .await
        .unwrap();
    db.execute(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "INSERT INTO completion_blocker(space) VALUES($1)",
        [space.into()],
    ))
    .await
    .unwrap();
    assert!(complete_purge(&db, &store, &keys, &job).await.is_err());
    assert!(space_purge_tombstone::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
    assert_eq!(
        space_purge_job::Entity::find_by_id(&purge_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .phase,
        "objects"
    );
    db.execute_unprepared("DELETE FROM completion_blocker")
        .await
        .unwrap();
    assert!(complete_purge(&db, &store, &keys, &job).await.unwrap());
    let done = space_purge_job::Entity::find_by_id(&purge_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(done.phase, "complete");
    assert!(done.space.is_none());
    assert!(done.lease_token.is_none());
    let tombstone = space_purge_tombstone::Entity::find()
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(tombstone.completed_at.unix_timestamp(), previous_timestamp);
    assert_eq!(tombstone.purge_id, purge_id);
    assert!(!complete_purge(&db, &store, &keys, &job).await.unwrap());
    assert!(db
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT id FROM space WHERE id=$1",
            [space.into()]
        ))
        .await
        .unwrap()
        .is_none());
    let body = store.read_purge_record(&path).await.unwrap().unwrap();
    assert_eq!(
        keys.verify(&path, &body).unwrap().timestamp,
        previous_timestamp
    );
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

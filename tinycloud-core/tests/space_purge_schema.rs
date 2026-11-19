use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
    DatabaseConnection, DbBackend, EntityTrait, Statement,
};
use time::OffsetDateTime;
use tinycloud_core::{
    migrations::Migrator, models::space_purge_job, sea_orm_migration::MigratorTrait,
};

fn job(id: &str) -> space_purge_job::ActiveModel {
    let now = OffsetDateTime::now_utc();
    space_purge_job::ActiveModel {
        purge_id: Set(id.into()),
        space: Set(Some(
            "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files"
                .parse::<tinycloud_auth::resource::SpaceId>()
                .unwrap()
                .to_string(),
        )),
        tombstone_hmac: Set(vec![1; 32]),
        hmac_key_id: Set("test".into()),
        owner_hmac: Set(vec![2; 32]),
        accepted_at: Set(now),
        phase: Set("drain".into()),
        fence_generation: Set(1),
        updated_at: Set(now),
        next_attempt_at: Set(now),
        attempt_count: Set(0),
        last_error_code: Set(None),
        lease_token: Set(None),
        lease_until: Set(None),
    }
}

async fn constraints(db: &DatabaseConnection) {
    Migrator::up(db, None).await.unwrap();
    Migrator::up(db, None).await.unwrap();
    job("first").insert(db).await.unwrap();
    assert!(job("duplicate").insert(db).await.is_err());
    let mut invalid = job("invalid");
    invalid.space = Set(None);
    assert!(invalid.insert(db).await.is_err());
    let mut complete = job("first");
    complete.phase = Set("complete".into());
    assert!(complete.clone().update(db).await.is_err());
    complete.space = Set(None);
    complete.update(db).await.unwrap();
    job("replacement").insert(db).await.unwrap();
    assert_eq!(
        space_purge_job::Entity::find().all(db).await.unwrap().len(),
        2
    );
}

#[tokio::test]
async fn sqlite_purge_schema_enforces_active_uniqueness_and_clears_terminal_identity() {
    constraints(&Database::connect("sqlite::memory:").await.unwrap()).await;
}

#[tokio::test]
async fn postgres_purge_schema_enforces_active_uniqueness_and_clears_terminal_identity() {
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").expect("isolated PostgreSQL test URL");
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "purge_schema_{}_{}",
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
    constraints(&db).await;
    db.close().await.unwrap();
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .unwrap();
}

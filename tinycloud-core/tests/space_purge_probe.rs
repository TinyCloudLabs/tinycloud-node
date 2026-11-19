use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
    DatabaseConnection, TransactionTrait,
};
use std::{collections::BTreeMap, sync::Arc};
use time::OffsetDateTime;
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    migrations::Migrator,
    models::space,
    sea_orm_migration::MigratorTrait,
    space_purge_fence::{FenceError, SpaceProbe, SpacePurgeFence},
    space_purge_ledger::LedgerKeys,
};
async fn probe_states(db: &DatabaseConnection) {
    Migrator::up(db, None).await.unwrap();
    let keys = Arc::new(
        LedgerKeys::new(
            "current".into(),
            BTreeMap::from([
                ("current".into(), vec![16; 32]),
                ("old".into(), vec![17; 32]),
            ]),
        )
        .unwrap(),
    );
    let fence = SpacePurgeFence::new(keys.clone());
    fence.set_serving_ready(true);
    let hosted: SpaceId =
        "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:hosted"
            .parse()
            .unwrap();
    let absent: SpaceId =
        "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:absent"
            .parse()
            .unwrap();
    let other: SpaceId = "tinycloud:pkh:eip155:1:0x2222222222222222222222222222222222222222:hosted"
        .parse()
        .unwrap();
    space::ActiveModel {
        id: Set(hosted.clone().into()),
    }
    .insert(db)
    .await
    .unwrap();
    assert_eq!(
        fence.probe(db, &hosted).await.unwrap(),
        SpaceProbe {
            exists: true,
            fenced: false
        }
    );
    assert_eq!(
        fence.probe(db, &absent).await.unwrap(),
        SpaceProbe {
            exists: false,
            fenced: false
        }
    );
    let tx = db.begin().await.unwrap();
    let digest = keys
        .target_hmac("old", "space", &hosted.to_string())
        .unwrap();
    fence
        .fence_hmac(&tx, "space", "old", &digest)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        fence.probe(db, &hosted).await.unwrap(),
        SpaceProbe {
            exists: true,
            fenced: true
        }
    );
    assert_eq!(
        fence.probe(db, &other).await.unwrap(),
        SpaceProbe {
            exists: false,
            fenced: false
        }
    );
    let tx = db.begin().await.unwrap();
    let digest = keys
        .target_hmac("old", "owner", absent.did().as_str())
        .unwrap();
    fence
        .fence_hmac(&tx, "owner", "old", &digest)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        fence.probe(db, &absent).await.unwrap(),
        SpaceProbe {
            exists: false,
            fenced: true
        }
    );
    fence.set_serving_ready(false);
    assert!(matches!(
        fence.probe(db, &hosted).await,
        Err(FenceError::Unavailable)
    ));
}
#[tokio::test]
async fn sqlite_absent_and_fenced_targets_share_the_same_probe() {
    probe_states(&Database::connect("sqlite::memory:").await.unwrap()).await;
}
#[tokio::test]
async fn postgres_probe_checks_old_key_space_and_owner_fences() {
    if std::env::var("TINYCLOUD_ALLOW_LOCAL_PG").as_deref() != Ok("1")
        && std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
    {
        return;
    }
    let url = std::env::var("TINYCLOUD_TEST_POSTGRES_URL").unwrap();
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "purge_probe_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    probe_states(&db).await;
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

use tinycloud_core::{
    hash::hash,
    migrations::Migrator,
    models::space_purge_shared_residue,
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, EntityTrait,
    },
    sea_orm_migration::MigratorTrait,
};

async fn constraints(db: &DatabaseConnection) {
    Migrator::up(db, None).await.unwrap();
    Migrator::up(db, None).await.unwrap();
    let row = space_purge_shared_residue::ActiveModel {
        purge_id: Set("opaque-a".into()),
        record_kind: Set("invocation".into()),
        record_id: Set(hash(b"shared-record")),
    };
    row.clone().insert(db).await.unwrap();
    assert!(row.clone().insert(db).await.is_err());
    let mut second = row.clone();
    second.purge_id = Set("opaque-b".into());
    second.insert(db).await.unwrap();
    let mut invalid = row;
    invalid.record_kind = Set("unknown".into());
    assert!(invalid.insert(db).await.is_err());
    let rows = space_purge_shared_residue::Entity::find()
        .all(db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows
        .iter()
        .all(|row| row.record_id == hash(b"shared-record")));
}

#[tokio::test]
async fn sqlite_shared_residue_has_opaque_identity_and_unique_links() {
    constraints(&Database::connect("sqlite::memory:").await.unwrap()).await;
}

#[tokio::test]
async fn postgres_shared_residue_has_opaque_identity_and_unique_links() {
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!(
        "purge_residue_{}",
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
    constraints(&db).await;
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

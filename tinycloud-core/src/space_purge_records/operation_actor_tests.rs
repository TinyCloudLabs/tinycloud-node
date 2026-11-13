use super::*;

#[tokio::test]
async fn postgres_materialized_actor_write_takes_lock_even_when_actor_already_exists() {
    use sea_orm::{ConnectOptions, Database};
    let Ok(url) = std::env::var("TINYCLOUD_TEST_POSTGRES_URL") else {
        return;
    };
    let admin = Database::connect(&url).await.unwrap();
    let schema = format!("purge_actor_lock_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = ConnectOptions::new(url);
    options.set_schema_search_path(schema.clone());
    let db = Database::connect(options).await.unwrap();
    db.execute_unprepared("CREATE TABLE actor(id TEXT PRIMARY KEY)")
        .await
        .unwrap();
    // An exclusive collector prevents the first actor INSERT, not merely the
    // later signed-row INSERT. It also prevents an ON CONFLICT no-op write.
    for _ in 0..2 {
        let gc = db.begin().await.unwrap();
        lock(&gc).await.unwrap();
        let writer_db = db.clone();
        let writer = tokio::spawn(async move {
            let tx = writer_db.begin().await.unwrap();
            operation_actors(&tx, &["did:key:actor"]).await.unwrap();
            tx.commit().await.unwrap();
        });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!writer.is_finished());
        gc.commit().await.unwrap();
        writer.await.unwrap();
    }
    let writer = db.begin().await.unwrap();
    operation_actors(&writer, &["did:key:actor"]).await.unwrap();
    let gc_db = db.clone();
    let gc = tokio::spawn(async move {
        let tx = gc_db.begin().await.unwrap();
        lock(&tx).await.unwrap();
        tx.commit().await.unwrap();
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(!gc.is_finished());
    writer.commit().await.unwrap();
    gc.await.unwrap();
    db.close().await.unwrap();
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

//! TC-4366: the stored-identity step (`delegation_cid_alias::recompute`) runs
//! inside node startup. The node is built only after it committed its marker,
//! and a node whose step did not commit is never built, so it never serves.
use anyhow::Result;
use rocket::figment::{providers::Serialized, Figment};
use serde_json::json;
use tinycloud_core::sea_orm::{ConnectionTrait, Database, DatabaseConnection};

fn figment(dir: &tempfile::TempDir, db_url: &str) -> Result<Figment> {
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some(db_url.to_owned());
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config([42; 32], base64::URL_SAFE_NO_PAD),
    }))?;
    Ok(Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config)))
}

async fn marker(db: &DatabaseConnection) -> Result<i64> {
    let row = db
        .query_one(tinycloud_core::sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT COUNT(*) AS n FROM delegation_cid_alias_rule".to_owned(),
        ))
        .await?
        .expect("one row");
    Ok(row.try_get("", "n")?)
}

#[tokio::test]
async fn the_node_is_built_only_after_the_identity_step_committed() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let db_url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("node.sqlite").display()
    );
    let figment = figment(&dir, &db_url)?;

    // First start: the returned (not yet launched) node already has the marker.
    let node = tinycloud::app(&figment).await?;
    let db = Database::connect(&db_url).await?;
    assert_eq!(
        marker(&db).await?,
        1,
        "the step committed before the node was built"
    );
    drop(node);

    // An upgrade from an image without the step: no marker. The marker write
    // fails, so the whole step rolls back and the node is not built.
    db.execute_unprepared("DELETE FROM delegation_cid_alias_rule")
        .await?;
    db.execute_unprepared(
        "CREATE TRIGGER refuse_identity_marker BEFORE INSERT ON delegation_cid_alias_rule \
         BEGIN SELECT RAISE(ABORT, 'identity marker refused'); END",
    )
    .await?;
    let Err(error) = tinycloud::app(&figment).await else {
        panic!("a node whose identity step did not commit must not be built");
    };
    assert!(
        format!("{error:#}").contains("identity marker refused"),
        "the start failed at the identity step: {error:#}"
    );
    assert_eq!(marker(&db).await?, 0, "nothing was recorded");

    // Once the step can commit, the next start records it before the node exists.
    db.execute_unprepared("DROP TRIGGER refuse_identity_marker")
        .await?;
    let node = tinycloud::app(&figment).await?;
    assert_eq!(
        marker(&db).await?,
        1,
        "the step committed before the node was built"
    );
    drop(node);
    Ok(())
}

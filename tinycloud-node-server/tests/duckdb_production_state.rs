//! TC-4193: with the `duckdb` feature on, the production Rocket
//! (`tinycloud::app`, the constructor `main.rs` uses) manages `DuckDbService`.
//! `routes::invoke` takes `&State<DuckDbService>`, so ignition would abort on
//! an unmanaged state; the lib test harnesses that build their own Rocket must
//! add that state because production already has it.
//!
//! Run with `cargo test -p tinycloud-node --features duckdb --test
//! duckdb_production_state`.
#![cfg(feature = "duckdb")]

use anyhow::Result;
use rocket::{
    figment::{providers::Serialized, Figment},
    http::Status,
    local::asynchronous::Client,
};
use serde_json::json;
use tinycloud_core::duckdb::DuckDbService;

#[tokio::test]
async fn production_rocket_manages_the_duckdb_service_and_serves() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config([57; 32], base64::URL_SAFE_NO_PAD),
    }))?;
    let figment = Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));

    // Ignition checks every mounted route's sentinels, `invoke` included.
    let client = Client::tracked(tinycloud::app(&figment).await?).await?;

    assert!(
        client.rocket().state::<DuckDbService>().is_some(),
        "the production rocket must manage DuckDbService with the duckdb feature on"
    );
    let response = client.get("/healthz").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    Ok(())
}

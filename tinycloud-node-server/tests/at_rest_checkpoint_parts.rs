//! TC-887: checkpoint parts (TC-2917) are stored in plaintext, so the node
//! refuses `encrypt` while `storage.sql.chunked_artifacts` is on, or while any
//! published part exists with it off. Through the real app on PostgreSQL.
//! One test in its own process, since it sets process environment.

mod common;

use std::path::Path;

use rocket::{
    figment::{providers::Serialized, Figment},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use tinycloud_core::sea_orm::{ConnectionTrait, Database};

const ROOT_KEY: &str = "TINYCLOUD_AT_REST_ROOT_KEY";

/// The test database URL with `schema` on the search path.
fn schema_url(url: &str, schema: &str) -> String {
    let mut url = reqwest::Url::parse(url).expect("TINYCLOUD_TEST_POSTGRES_URL is a URL");
    url.query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    url.to_string()
}

/// Boots the app with an env root (a throwaway key, never a real one; the
/// node refuses a key of one repeated byte). The node takes the key out of
/// the environment, so each boot sets it again.
async fn boot(dir: &Path, url: &str, mode: &str, chunked: bool) -> anyhow::Result<Client> {
    let key: [u8; 32] = std::array::from_fn(|i| i as u8);
    std::env::set_var(ROOT_KEY, base64::encode_config(key, base64::STANDARD));
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.into();
    config.storage.database = Some(url.into());
    config.storage.sql.chunked_artifacts = chunked;
    config.storage.sql.chunked_artifact_max_bytes = 1 << 20;
    config.storage.sql.chunked_account_max_bytes = 1 << 20;
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config([1u8; 32], base64::URL_SAFE_NO_PAD),
    }))?;
    config.at_rest = serde_json::from_value(json!({"root_source": "env", "mode": mode}))?;
    let figment = Figment::from(rocket::Config {
        address: "127.0.0.1".parse()?,
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    Ok(Client::untracked(tinycloud::app(&figment).await?).await?)
}

async fn refused(dir: &Path, url: &str, mode: &str, chunked: bool) -> String {
    match boot(dir, url, mode, chunked).await {
        Ok(_) => panic!("the node started, but mode {mode} must be refused here"),
        Err(e) => format!("{e:#}"),
    }
}

#[tokio::test]
async fn postgres_encrypt_is_refused_while_checkpoint_parts_are_enabled_or_published() {
    let test = "postgres_encrypt_is_refused_while_checkpoint_parts_are_enabled_or_published";
    let Some(base) = common::postgres_test_url(test) else {
        return;
    };
    let admin = Database::connect(base.as_str()).await.unwrap();
    let schema = format!(
        "tc887_parts_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos() % 1_000_000_000_000
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let url = schema_url(&base, &schema);
    let dir = tempfile::tempdir().unwrap();

    // Neither: no published part and the flag off, so encrypt boots.
    let client = boot(dir.path(), &url, "encrypt", false).await.unwrap();
    let res = client.get("/at-rest/status").dispatch().await;
    let status: Value = serde_json::from_str(&res.into_string().await.unwrap()).unwrap();
    assert_eq!(status["encrypting"], true, "{status}");
    drop(client);

    // The flag on: refused, in both modes that seal.
    for mode in ["encrypt", "strict"] {
        let err = refused(dir.path(), &url, mode, true).await;
        assert!(
            err.contains("storage.sql.chunked_artifacts"),
            "{mode}: {err}"
        );
    }

    // A published part with the flag off: still refused, since a database
    // stored in parts keeps writing them.
    admin
        .execute_unprepared(&format!(
            "INSERT INTO {schema}.artifact_account(owner) VALUES ('legacy:probe'); \
             INSERT INTO {schema}.artifact_part(service,space,name,part_id,owner,size_bytes,chunk_count,state,lease_until) \
             VALUES ('sql','probe','main','part-1','legacy:probe',0,0,'published','infinity')"
        ))
        .await
        .unwrap();
    for mode in ["encrypt", "strict"] {
        let err = refused(dir.path(), &url, mode, false).await;
        assert!(err.contains("checkpoint parts"), "{mode}: {err}");
    }
    // Mode off is unaffected.
    drop(boot(dir.path(), &url, "off", false).await.unwrap());

    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
}

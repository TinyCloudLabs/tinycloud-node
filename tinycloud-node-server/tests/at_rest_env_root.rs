//! TC-887: an at-rest root from the environment, through the real app.
//! Boots, refusals, and root changes with `TINYCLOUD_AT_REST_PREVIOUS_ROOT_KEY`.
//! One test in its own process, since it sets process environment.

use std::path::Path;

use rocket::{
    figment::{providers::Serialized, Figment},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use sha2::Digest as _;

const ROOT_KEY: &str = "TINYCLOUD_AT_REST_ROOT_KEY";
const PREVIOUS: &str = "TINYCLOUD_AT_REST_PREVIOUS_ROOT_KEY";

fn key(seed: u8) -> String {
    let bytes: Vec<u8> = (0..32u8)
        .map(|b| b.wrapping_mul(7).wrapping_add(seed))
        .collect();
    base64::encode_config(bytes, base64::STANDARD)
}

/// What an operator computes offline to match a key copy.
fn fingerprint(b64: &str) -> String {
    let mut h = sha2::Sha256::new();
    h.update(b"tinycloud/at-rest/root-fingerprint/v1");
    h.update(base64::decode_config(b64, base64::STANDARD).unwrap());
    hex::encode(h.finalize())[..16].to_string()
}

fn set_env(root: Option<&str>, previous: Option<&str>) {
    for (name, value) in [(ROOT_KEY, root), (PREVIOUS, previous)] {
        match value {
            Some(v) => std::env::set_var(name, v),
            None => std::env::remove_var(name),
        }
    }
}

async fn app(dir: &Path, at_rest: Value) -> anyhow::Result<Client> {
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.into();
    config.storage.database = Some(format!("sqlite:{}?mode=rwc", dir.join("caps.db").display()));
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config([1u8; 32], base64::URL_SAFE_NO_PAD),
    }))?;
    config.at_rest = serde_json::from_value(at_rest)?;
    let figment = Figment::from(rocket::Config {
        address: "127.0.0.1".parse()?,
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    let rocket = tinycloud::app(&figment).await?;
    Ok(Client::untracked(rocket).await?)
}

async fn refused(dir: &Path, at_rest: Value) -> String {
    match app(dir, at_rest).await {
        Ok(_) => panic!("the node started, but this configuration must be refused"),
        Err(e) => format!("{e:#}"),
    }
}

async fn status(client: &Client) -> Value {
    let res = client.get("/at-rest/status").dispatch().await;
    serde_json::from_str(&res.into_string().await.unwrap()).unwrap()
}

#[tokio::test]
async fn an_env_root_boots_refuses_and_changes_without_losing_keys() {
    let dir = tempfile::tempdir().unwrap();
    let env_root = json!({"root_source": "env"});
    let (a, b) = (key(1), key(2));

    // No key, or a malformed one: refused, and the value is never echoed.
    set_env(None, None);
    let err = refused(dir.path(), env_root.clone()).await;
    assert!(err.contains(ROOT_KEY), "{err}");
    let bad = format!("{}A", &a[..43]);
    set_env(Some(&bad), None);
    let err = refused(dir.path(), env_root.clone()).await;
    assert!(err.contains("is invalid") && !err.contains(&bad), "{err}");

    // Key A provisions the keys; the status names it by fingerprint only.
    set_env(Some(&a), None);
    let client = app(dir.path(), env_root.clone()).await.unwrap();
    let s = status(&client).await;
    assert_eq!(s["root_source"], "env");
    assert_eq!(s["state"], "unlocked");
    assert_eq!(s["encrypting"], false);
    assert_eq!(s["root_fingerprint"], fingerprint(&a));
    assert!(!s.to_string().contains(&a));
    drop(client);

    // Another key alone doesn't open them: refused, never booted locked.
    set_env(Some(&b), None);
    let err = refused(dir.path(), env_root.clone()).await;
    assert!(
        err.contains("does not open") && err.contains(&fingerprint(&b)),
        "{err}"
    );

    // B with A as the previous root re-seals; afterwards B alone opens them
    // and A no longer does.
    set_env(Some(&b), Some(&a));
    let client = app(dir.path(), env_root.clone()).await.unwrap();
    assert_eq!(status(&client).await["root_fingerprint"], fingerprint(&b));
    drop(client);
    set_env(Some(&b), None);
    let client = app(dir.path(), env_root.clone()).await.unwrap();
    assert_eq!(status(&client).await["state"], "unlocked");
    drop(client);
    set_env(Some(&a), None);
    refused(dir.path(), env_root.clone()).await;

    // Misplaced or combined settings.
    set_env(Some(&b), Some(&b));
    let err = refused(dir.path(), env_root.clone()).await;
    assert!(err.contains("is the current at-rest root"), "{err}");
    set_env(Some(&b), None);
    let err = refused(dir.path(), json!({"escrow_none": true})).await;
    assert!(err.contains("root_source is \"escrow\""), "{err}");
    let err = refused(
        dir.path(),
        json!({"root_source": "env", "escrow_none": true}),
    )
    .await;
    assert!(err.contains("has no escrow"), "{err}");

    // Moving to the node's own root: the env key becomes the previous root.
    set_env(None, Some(&b));
    let client = app(dir.path(), json!({"escrow_none": true})).await.unwrap();
    let s = status(&client).await;
    assert_eq!(
        (s["root_source"].as_str(), s["state"].as_str()),
        (Some("escrow"), Some("unlocked"))
    );
    assert!(s.get("root_fingerprint").is_none());
    drop(client);
    set_env(None, None);
    let client = app(dir.path(), json!({"escrow_none": true})).await.unwrap();
    assert_eq!(status(&client).await["state"], "unlocked");
    drop(client);
    set_env(Some(&b), None);
    refused(dir.path(), env_root).await;
    set_env(None, None);
}

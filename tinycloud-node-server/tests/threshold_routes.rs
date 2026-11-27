//! TC-2225: the real node serves the threshold routes only when
//! `encryption_network.threshold_v1` is on; off, both answer 404.

use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Status},
    local::asynchronous::Client,
};
use serde_json::json;

const NETWORK: &str =
    "urn:tinycloud:encryption:did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK:vault";

async fn app(threshold_v1: bool) -> (Client, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
    config.keys = serde_json::from_value(
        json!({"type":"static", "secret":base64::encode_config([42; 32], base64::URL_SAFE_NO_PAD)}),
    )
    .unwrap();
    config.encryption_network.threshold_v1 = threshold_v1;
    let figment = Figment::from(rocket::Config {
        address: "127.0.0.1".parse().unwrap(),
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    let rocket = tinycloud::app(&figment).await.unwrap();
    (Client::tracked(rocket).await.unwrap(), dir)
}

#[rocket::async_test]
async fn the_threshold_routes_answer_404_with_the_flag_off() {
    for on in [false, true] {
        let (client, _dir) = app(on).await;
        let chain = client
            .get(format!("/threshold/{NETWORK}/chain"))
            .remote("127.0.0.1:9000".parse().unwrap())
            .dispatch()
            .await
            .status();
        let push = client
            .post(format!("/threshold/{NETWORK}/objects"))
            .remote("127.0.0.1:9000".parse().unwrap())
            .header(ContentType::JSON)
            .body(json!({"kind": "cert", "object": "AA", "nonce": "n-1"}).to_string())
            .dispatch()
            .await
            .status();
        if on {
            assert_eq!((chain, push), (Status::Ok, Status::UnprocessableEntity));
        } else {
            assert_eq!((chain, push), (Status::NotFound, Status::NotFound));
        }
    }
}

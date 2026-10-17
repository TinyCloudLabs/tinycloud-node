//! TC-1080: real route refusal and public, count-only evidence.
#[path = "../../tinycloud-core/tests/support/did_resolution.rs"]
mod support;
use rocket::{
    figment::providers::Serialized,
    http::{Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use support::*;
use tinycloud_auth::ssi::jwk::{Algorithm, JWK};

async fn client() -> (Client, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
    // Generated fixture key, supplied in memory; no operator key/session files.
    config.keys = serde_json::from_value(
        json!({"type":"static", "secret":base64::encode_config([41; 32], base64::URL_SAFE_NO_PAD)}),
    )
    .unwrap();
    let figment = rocket::figment::Figment::from(rocket::Config {
        address: "127.0.0.1".parse().unwrap(),
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    let rocket = tinycloud::app_with_control(&figment, &config, None)
        .await
        .unwrap();
    (Client::tracked(rocket).await.unwrap(), dir)
}

async fn assert_route_refuses(path: &str, status: Status) {
    let (client, _dir) = client().await;
    let listener = bound_listener();
    let issuer = format!(
        "did:web:127.0.0.1%3A{}",
        listener.local_addr().unwrap().port()
    );
    let jwk = JWK::generate_ed25519().unwrap();
    let ucan = signed_ucan(&issuer, &jwk, Algorithm::EdDSA);
    let token = if path == "/revoke" {
        let mut payload = ucan.payload().clone();
        payload.attenuation.with_actions(
            format!("urn:cid:{}", payload.proof[0]).parse().unwrap(),
            [("tinycloud.delegation/revoke".parse().unwrap(), [])],
        );
        payload
            .sign(Algorithm::EdDSA, &jwk)
            .unwrap()
            .encode()
            .unwrap()
    } else {
        ucan.encode().unwrap()
    };
    let response = client
        .post(path)
        .header(Header::new("Authorization", token))
        .dispatch()
        .await;
    assert_eq!(response.status(), status);
    let body = response.into_string().await.unwrap();
    assert!(body.starts_with("did_method_disabled:"), "{body}");
    assert_no_connections(&[&listener]).await;
}

#[tokio::test]
async fn invoke_keeps_401_with_method_disabled_body() {
    assert_route_refuses("/invoke", Status::Unauthorized).await;
}
#[tokio::test]
async fn delegate_keeps_401_with_method_disabled_body() {
    assert_route_refuses("/delegate", Status::Unauthorized).await;
}
#[tokio::test]
async fn revoke_keeps_403_with_method_disabled_body() {
    assert_route_refuses("/revoke", Status::Forbidden).await;
}

#[tokio::test]
async fn actionless_revoke_is_forbidden_without_resolution() {
    let (client, _dir) = client().await;
    let listener = bound_listener();
    let issuer = format!(
        "did:web:127.0.0.1%3A{}",
        listener.local_addr().unwrap().port()
    );
    let token = signed_ucan(&issuer, &JWK::generate_ed25519().unwrap(), Algorithm::EdDSA)
        .encode()
        .unwrap();
    let response = client
        .post("/revoke")
        .header(Header::new("Authorization", token))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Forbidden);
    assert_no_connections(&[&listener]).await;
}

#[tokio::test]
async fn info_exposes_only_policy_boolean_and_lifetime_count_and_metric_counts_every_refusal() {
    let (client, _dir) = client().await;
    let before = client
        .get("/info")
        .dispatch()
        .await
        .into_json::<Value>()
        .await
        .unwrap();
    assert_eq!(before["did_resolution"]["network_methods"], false);
    let initial_count = before["did_resolution"]["refused_total"].as_u64().unwrap();
    let metric = tinycloud::prometheus::DID_RESOLUTION_REFUSED
        .with_label_values(&["unknown", "method_disabled"]);
    let metric_before = metric.get();
    let ucan = signed_ucan(
        "did:future:local",
        &JWK::generate_ed25519().unwrap(),
        Algorithm::EdDSA,
    );
    for _ in 0..100 {
        assert!(matches!(
            tinycloud_core::did_resolution::verify_ucan_signature(&ucan).await,
            Err(tinycloud_core::did_resolution::UcanVerifyError::MethodDisabled { .. })
        ));
    }
    assert_eq!(metric.get() - metric_before, 100);
    let response = client.get("/info").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let after = response.into_json::<Value>().await.unwrap();
    let evidence = after["did_resolution"].as_object().unwrap();
    assert_eq!(evidence.len(), 2);
    assert_eq!(evidence["network_methods"], false);
    assert!(evidence["refused_total"].as_u64().unwrap() >= initial_count + 100);
}

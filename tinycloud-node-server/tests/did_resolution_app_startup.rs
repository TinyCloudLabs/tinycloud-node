//! Real app startup applies the documented environment opt-in and restart policy.
//! One test in its own process isolates the process-global policy and env fixture.
#[path = "../../tinycloud-core/tests/support/did_resolution.rs"]
mod support;
use rocket::{
    figment::{
        providers::{Env, Serialized},
        Figment,
    },
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    time::Duration,
};
use support::*;
use tinycloud_auth::ssi::jwk::{Algorithm, JWK};
use tinycloud_core::did_resolution::{verify_ucan_signature, UcanVerifyError};

const NETWORK_METHODS_ENV: &str = "TINYCLOUD_DID_RESOLUTION__NETWORK_METHODS";

// Restore only this test's variable without reading credential/session files.
struct RestoreEnv(Option<std::ffi::OsString>);
impl Drop for RestoreEnv {
    fn drop(&mut self) {
        if let Some(value) = &self.0 {
            std::env::set_var(NETWORK_METHODS_ENV, value);
        } else {
            std::env::remove_var(NETWORK_METHODS_ENV);
        }
    }
}

async fn app() -> (Client, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
    config.keys = serde_json::from_value(
        json!({"type":"static", "secret":base64::encode_config([42; 32], base64::URL_SAFE_NO_PAD)}),
    )
    .unwrap();
    // The same canonical provider as runtime::with_serve_env, restricted to
    // this fixture's variable so unrelated operator env cannot affect it.
    let figment = Figment::from(rocket::Config {
        address: "127.0.0.1".parse().unwrap(),
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config))
    .merge(
        Env::prefixed("TINYCLOUD_")
            .only(&["did_resolution__network_methods"])
            .split("__")
            .global(),
    );
    let rocket = tinycloud::app(&figment).await.unwrap();
    (Client::tracked(rocket).await.unwrap(), dir)
}

async fn network_methods(client: &Client) -> bool {
    client
        .get("/info")
        .dispatch()
        .await
        .into_json::<Value>()
        .await
        .unwrap()["did_resolution"]["network_methods"]
        .as_bool()
        .unwrap()
}

async fn assert_web_refused() {
    let listener = bound_listener();
    let issuer = format!(
        "did:web:127.0.0.1%3A{}#key",
        listener.local_addr().unwrap().port()
    );
    let ucan = signed_ucan(&issuer, &JWK::generate_ed25519().unwrap(), Algorithm::EdDSA);
    let outcome = verify_ucan_signature(&ucan).await;
    assert_no_connections(&[&listener]).await;
    assert_eq!(
        outcome,
        Err(UcanVerifyError::MethodDisabled {
            method: "web".into()
        })
    );
}

async fn assert_web_verified_locally() {
    let listener = bound_listener();
    let did = format!(
        "did:web:127.0.0.1%3A{}",
        listener.local_addr().unwrap().port()
    );
    let issuer = format!("{did}#key");
    let key = JWK::generate_ed25519().unwrap();
    let ucan = signed_ucan(&issuer, &key, Algorithm::EdDSA);
    let body = json!({"@context":"https://www.w3.org/ns/did/v1", "id":did,
        "verificationMethod":[{"id":issuer,"type":"JsonWebKey2020","controller":did,"publicKeyJwk":key.to_public()}]}).to_string();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        loop {
            match listener.accept() {
                Ok((mut stream, peer)) => {
                    assert!(peer.ip().is_loopback());
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = [0; 4096];
                    let size = stream.read(&mut request).unwrap();
                    assert!(String::from_utf8_lossy(&request[..size])
                        .starts_with("GET /.well-known/did.json HTTP/1.1"));
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/did+ld+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                    return 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if std::time::Instant::now() >= deadline {
                        return 0;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                result => panic!("local listener failed: {result:?}"),
            }
        }
    });
    let outcome = tokio::time::timeout(Duration::from_secs(5), verify_ucan_signature(&ucan)).await;
    let accepted = server.join().unwrap();
    assert_eq!(outcome, Ok(Ok(())), "app must apply the environment opt-in");
    assert_eq!(accepted, 1);
}

#[tokio::test]
async fn app_startup_honors_default_env_opt_in_and_restart_to_default() {
    let _restore = RestoreEnv(std::env::var_os(NETWORK_METHODS_ENV));
    std::env::remove_var(NETWORK_METHODS_ENV);
    let (client, _dir) = app().await;
    assert!(!network_methods(&client).await);
    assert_web_refused().await;
    drop(client);

    std::env::set_var(NETWORK_METHODS_ENV, "true");
    let (client, _dir) = app().await;
    // Resolve before checking /info so the configure-removal mutant fails on
    // refused verification, rather than only on the reported policy boolean.
    assert_web_verified_locally().await;
    assert!(network_methods(&client).await);
    drop(client);

    std::env::remove_var(NETWORK_METHODS_ENV);
    let (client, _dir) = app().await;
    assert!(!network_methods(&client).await);
    assert_web_refused().await;
}

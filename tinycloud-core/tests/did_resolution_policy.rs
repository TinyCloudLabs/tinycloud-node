//! TC-1080 refusal regressions. Every socket target is a listener bound by this test.
#[path = "support/did_resolution.rs"]
mod support;
use futures::FutureExt;
use std::{
    io::{Read, Write},
    sync::OnceLock,
    time::Duration,
};
use support::*;
use tinycloud_auth::{
    resolver::DID_METHODS,
    ssi::{
        dids::{
            resolution::{DerefError, Error as ResolutionError, Options},
            DIDBuf, DIDResolver, DIDURLBuf,
        },
        jwk::{Algorithm, JWK},
        ucan::UcanRevocation,
    },
};
use tinycloud_core::did_resolution::*;

async fn policy_lock() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
        .lock()
        .await
}
struct ResetPolicy;
impl Drop for ResetPolicy {
    fn drop(&mut self) {
        configure(DidResolutionPolicy::default());
    }
}

#[tokio::test]
async fn default_refuses_web_variants_before_connecting() {
    let _lock = policy_lock().await;
    assert_eq!(policy(), DidResolutionPolicy::default());
    let first = bound_listener();
    let second = bound_listener(); // Would be a local redirect destination.
    let port = first.local_addr().unwrap().port();
    let key = JWK::generate_ed25519().unwrap();
    for issuer in [
        format!("did:web:127.0.0.1%3A{port}"),
        format!("did:web:localhost%3A{port}:internal:admin"),
        format!("did:web:127.0.0.1%3A{port}:redirect"),
        format!("did:web:127.0.0.1%3A{port}:silent"),
    ] {
        let ucan = signed_ucan(&issuer, &key, Algorithm::EdDSA);
        assert_eq!(
            verify_ucan_signature(&ucan).await,
            Err(UcanVerifyError::MethodDisabled {
                method: "web".into()
            })
        );
    }
    assert_no_connections(&[&first, &second]).await;
}

#[tokio::test]
async fn default_direct_representation_refuses_valid_web_before_connecting() {
    let _lock = policy_lock().await;
    assert_eq!(policy(), DidResolutionPolicy::default());
    let listener = bound_listener();
    let did: DIDBuf = format!(
        "did:web:127.0.0.1%3A{}",
        listener.local_addr().unwrap().port()
    )
    .parse()
    .unwrap();
    let resolver = NodeDidResolver::current();
    // Bound the test if the resolver's second guard regresses and SSI waits for HTTP.
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        resolver.resolve_representation(&did, Options::default()),
    )
    .await;
    assert_no_connections(&[&listener]).await;
    let expected = UcanVerifyError::MethodDisabled {
        method: "web".into(),
    }
    .to_string();
    assert!(matches!(result, Ok(Err(ResolutionError::Internal(message))) if message == expected));
}

#[tokio::test]
async fn default_direct_dereference_refuses_valid_web_before_connecting() {
    let _lock = policy_lock().await;
    assert_eq!(policy(), DidResolutionPolicy::default());
    let listener = bound_listener();
    let issuer: DIDURLBuf = format!(
        "did:web:127.0.0.1%3A{}#key",
        listener.local_addr().unwrap().port()
    )
    .parse()
    .unwrap();
    let resolver = NodeDidResolver::current();
    let result = tokio::time::timeout(Duration::from_secs(1), resolver.dereference(&issuer)).await;
    assert_no_connections(&[&listener]).await;
    let expected = UcanVerifyError::MethodDisabled {
        method: "web".into(),
    }
    .to_string();
    assert!(
        matches!(result, Ok(Err(DerefError::Resolution(ResolutionError::Internal(message)))) if message == expected)
    );
}

#[tokio::test]
async fn offline_refuses_tz_ethr_ion_and_unknown_methods() {
    let _lock = policy_lock().await;
    let listener = bound_listener();
    let key = JWK::generate_ed25519().unwrap();
    for method in ["tz", "ethr", "ion", "future"] {
        let issuer = format!("did:{method}:local");
        let ucan = signed_ucan(&issuer, &key, Algorithm::EdDSA);
        assert_eq!(
            verify_ucan_signature(&ucan).await,
            Err(UcanVerifyError::MethodDisabled {
                method: method.into()
            })
        );
        let did: DIDBuf = issuer.parse().unwrap();
        assert!(NodeDidResolver::current().resolve(&did).await.is_err());
    }
    assert_no_connections(&[&listener]).await;
}

#[tokio::test]
async fn issuer_queries_are_refused_without_panic_under_both_policies() {
    let _lock = policy_lock().await;
    let _reset = ResetPolicy;
    let listener = bound_listener();
    let port = listener.local_addr().unwrap().port();
    let key = JWK::generate_ed25519().unwrap();
    for enabled in [false, true] {
        configure(DidResolutionPolicy {
            network_methods: enabled,
        });
        for issuer in [
            format!("did:tz:mainnet:local?tzkt_url=http://127.0.0.1:{port}/"),
            format!("did:web:127.0.0.1%3A{port}?accept=foo"),
            "did:key:local?accept%5B0%5D=foo".into(),
            "did:key:local?".into(),
        ] {
            let ucan = signed_ucan(&issuer, &key, Algorithm::EdDSA);
            let outcome = std::panic::AssertUnwindSafe(verify_ucan_signature(&ucan))
                .catch_unwind()
                .await;
            assert_eq!(outcome.unwrap(), Err(UcanVerifyError::QueryRejected));
            let revocation = UcanRevocation::sign(
                issuer.parse().unwrap(),
                ucan.payload().proof[0],
                &key,
                Algorithm::EdDSA,
            )
            .unwrap();
            assert_eq!(
                verify_ucan_revocation_signature(&revocation, Algorithm::EdDSA, None).await,
                Err(UcanVerifyError::QueryRejected)
            );
        }
    }
    assert_no_connections(&[&listener]).await;
}

#[tokio::test]
async fn key_pkh_and_jwk_still_verify_offline() {
    let _lock = policy_lock().await;
    for method in ["key", "pkh:eip155:1", "jwk"] {
        let (key, algorithm) = if method.starts_with("pkh") {
            (JWK::generate_secp256k1(), Algorithm::ES256K)
        } else {
            (JWK::generate_ed25519().unwrap(), Algorithm::EdDSA)
        };
        let did = DID_METHODS.generate(&key, method).unwrap().to_string();
        let issuer = if method == "jwk" {
            format!("{did}#0")
        } else {
            did
        };
        let ucan = signed_ucan(&issuer, &key, algorithm);
        assert_eq!(verify_ucan_signature(&ucan).await, Ok(()), "{method}");
        let revocation = UcanRevocation::sign(
            issuer.parse().unwrap(),
            ucan.payload().proof[0],
            &key,
            algorithm,
        )
        .unwrap();
        assert_eq!(
            verify_ucan_revocation_signature(&revocation, algorithm, Some(&key.to_public())).await,
            Ok(()),
            "{method}"
        );
    }
}

#[tokio::test]
async fn explicit_opt_in_verifies_web_against_bound_listener() {
    let _lock = policy_lock().await;
    let _reset = ResetPolicy;
    configure(DidResolutionPolicy {
        network_methods: true,
    });
    let listener = bound_listener();
    let port = listener.local_addr().unwrap().port();
    let did = format!("did:web:127.0.0.1%3A{port}");
    let issuer = format!("{did}#key");
    let key = JWK::generate_ed25519().unwrap();
    let ucan = signed_ucan(&issuer, &key, Algorithm::EdDSA);
    let body = serde_json::json!({"@context":"https://www.w3.org/ns/did/v1", "id":did, "verificationMethod":[{"id":issuer,"type":"JsonWebKey2020","controller":did,"publicKeyJwk":key.to_public()}]}).to_string();
    let server = std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut request = [0; 4096];
                    let size = stream.read(&mut request).unwrap();
                    assert!(String::from_utf8_lossy(&request[..size])
                        .starts_with("GET /.well-known/did.json HTTP/1.1"));
                    write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/did+ld+json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                    return 1;
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(5))
                }
                result => panic!("local resolution failed: {result:?}"),
            }
        }
    });
    let outcome = verify_ucan_signature(&ucan).await;
    assert_eq!(server.join().unwrap(), 1);
    assert_eq!(outcome, Ok(()));
}

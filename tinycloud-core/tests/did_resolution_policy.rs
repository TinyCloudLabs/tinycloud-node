//! TC-1080 / TC-1500 issuer regressions. Every socket target is a listener bound by this test.
#[path = "support/did_resolution.rs"]
mod support;
use futures::FutureExt;
use std::time::Duration;
use support::*;
use tinycloud_auth::ipld_core::cid::multibase;
use tinycloud_auth::{
    resolver::DID_METHODS,
    ssi::{
        dids::{
            resolution::{DerefError, Error as ResolutionError, Options},
            DIDBuf, DIDResolver, DIDURLBuf,
        },
        jwk::{Algorithm, Params, JWK},
        ucan::UcanRevocation,
    },
};
use tinycloud_core::did_resolution::*;

#[tokio::test]
async fn refuses_web_variants_before_connecting() {
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
async fn direct_representation_refuses_valid_web_before_connecting() {
    let listener = bound_listener();
    let did: DIDBuf = format!(
        "did:web:127.0.0.1%3A{}",
        listener.local_addr().unwrap().port()
    )
    .parse()
    .unwrap();
    // Bound the test if the resolver's second guard regresses and SSI waits for HTTP.
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        NodeDidResolver.resolve_representation(&did, Options::default()),
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
async fn direct_dereference_refuses_valid_web_before_connecting() {
    let listener = bound_listener();
    let issuer: DIDURLBuf = format!(
        "did:web:127.0.0.1%3A{}#key",
        listener.local_addr().unwrap().port()
    )
    .parse()
    .unwrap();
    let result =
        tokio::time::timeout(Duration::from_secs(1), NodeDidResolver.dereference(&issuer)).await;
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
async fn refuses_tz_ethr_ion_and_unknown_methods() {
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
        assert!(NodeDidResolver.resolve(&did).await.is_err());
    }
    assert_no_connections(&[&listener]).await;
}

#[tokio::test]
async fn issuer_queries_are_refused_without_panic() {
    let listener = bound_listener();
    let port = listener.local_addr().unwrap().port();
    let key = JWK::generate_ed25519().unwrap();
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
    assert_no_connections(&[&listener]).await;
}

/// The issuer URL `signed_ucan` signs under for a generated DID: did:jwk's verification
/// method is `#0`; the others are the bare DID.
fn issuer_for(did: &str) -> String {
    if did.starts_with("did:jwk:") {
        format!("{did}#0")
    } else {
        did.to_owned()
    }
}

fn solana_did(key: &JWK) -> String {
    let legacy = DID_METHODS.generate(key, "pkh:sol").unwrap().to_string();
    let address = legacy.rsplit(':').next().unwrap();
    format!("did:pkh:solana:4sGjMW1sUnHzSxGspuhpqLDx6wiyjNtZ:{address}")
}

/// TC-1500: every key type the node verifies offline is accepted, and a UCAN re-signed by
/// another key of the same type is not.
#[tokio::test]
async fn every_offline_key_type_verifies_and_forgery_is_refused() {
    type Generate = fn() -> JWK;
    let ed: Generate = || JWK::generate_ed25519().unwrap();
    let k1: Generate = JWK::generate_secp256k1;
    let p256: Generate = JWK::generate_p256;
    let cases = [
        ("key", ed, Algorithm::EdDSA),
        ("key", k1, Algorithm::ES256K),
        ("key", p256, Algorithm::ES256),
        ("jwk", ed, Algorithm::EdDSA),
        ("jwk", k1, Algorithm::ES256K),
        ("jwk", p256, Algorithm::ES256),
        ("pkh:eip155:1", k1, Algorithm::ES256KR),
        ("solana", ed, Algorithm::EdDSA),
        (
            "pkh:bip122:000000000019d6689c085ae165831e93",
            k1,
            Algorithm::ES256KR,
        ),
    ];
    for (method, generate, algorithm) in cases {
        let key = generate();
        let did = if method == "solana" {
            solana_did(&key)
        } else {
            DID_METHODS.generate(&key, method).unwrap().to_string()
        };
        assert_eq!(
            check_verifiable(did.parse::<DIDBuf>().unwrap().as_did()),
            Ok(()),
            "{did}"
        );
        assert!(check_holder(&did), "{did}");
        let issuer = issuer_for(&did);
        let ucan = signed_ucan(&issuer, &key, algorithm);
        assert_eq!(
            verify_ucan_signature(&ucan).await,
            Ok(()),
            "{did} {algorithm:?}"
        );
        let forged = signed_ucan(&issuer, &generate(), algorithm);
        assert_eq!(
            verify_ucan_signature(&forged).await,
            Err(UcanVerifyError::Invalid),
            "forgery under {did}"
        );
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
            "{did}"
        );
    }
}

/// TC-1500: offline-method DIDs whose key type, namespace or encoding the node cannot verify
/// are refused before resolution, as issuers and as holders.
#[tokio::test]
async fn unverifiable_offline_identifiers_are_refused() {
    let ed = JWK::generate_ed25519().unwrap();
    let Params::OKP(okp) = &ed.params else {
        unreachable!()
    };
    // The production z2D… host keys: Ed25519 behind a one-byte 0xed prefix (TC-1500 census).
    let mut single_byte = vec![0xed];
    single_byte.extend_from_slice(&okp.public_key.0);
    let z2d = format!(
        "did:key:{}",
        multibase::encode(multibase::Base::Base58Btc, single_byte)
    );
    assert!(z2d.starts_with("did:key:z2D"), "{z2d}");
    let k1 = JWK::generate_secp256k1();
    // The node's ssi build cannot generate a Tezos account; the issuer is refused first.
    let tezos = "did:pkh:tezos:NetXdQprcVkpaWU:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x".to_owned();
    let legacy_eth = DID_METHODS.generate(&k1, "pkh:eth").unwrap().to_string();
    for (did, key, algorithm) in [
        (z2d, &ed, Algorithm::EdDSA),
        (tezos, &ed, Algorithm::EdDSA),
        (legacy_eth, &k1, Algorithm::ES256KR),
    ] {
        let ucan = signed_ucan(&issuer_for(&did), key, algorithm);
        assert_eq!(
            verify_ucan_signature(&ucan).await,
            Err(UcanVerifyError::Unverifiable {
                method: did.split(':').nth(1).unwrap().into()
            }),
            "{did}"
        );
        assert!(!check_holder(&did), "{did}");
    }
}

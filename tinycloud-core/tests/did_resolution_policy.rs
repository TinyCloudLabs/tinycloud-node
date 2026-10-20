//! DID method allow-list refusal tests. Every socket target is a listener bound by this test.
#[path = "support/did_resolution.rs"]
mod support;
use futures::FutureExt;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use support::*;
use tinycloud_auth::{
    resolver::DID_METHODS,
    ssi::{
        dids::{
            resolution::{DerefError, Error as ResolutionError, Options, Output},
            DIDBuf, DIDResolver, DIDURLBuf, DID,
        },
        jwk::{Algorithm, JWK},
        ucan::UcanRevocation,
    },
};
use tinycloud_core::did_resolution::*;

/// Counts lookups that reach the inner backend. Always fails, so a test cannot pass by success.
#[derive(Clone, Default)]
struct CountingResolver(Arc<AtomicUsize>);

impl CountingResolver {
    fn lookups(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

impl DIDResolver for CountingResolver {
    async fn resolve_representation<'a>(
        &'a self,
        _did: &'a DID,
        _options: Options,
    ) -> Result<Output<Vec<u8>>, ResolutionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(ResolutionError::internal("counting stub"))
    }
}

/// (issuer, method label expected in the refusal).
const REFUSED: &[(&str, &str)] = &[
    ("did:web:127.0.0.1%3A1", "web"),
    ("did:web:example.com", "web"),
    ("did:tz:mainnet:local", "tz"),
    (
        "did:ethr:0x0000000000000000000000000000000000000001",
        "ethr",
    ),
    ("did:ion:local", "ion"),
    ("did:future:local", "future"),
    ("did:pkh:solana:local:abc", "pkh"),
    ("did:pkh:bip122:local:abc", "pkh"),
    ("did:pkh:tezos:local:abc", "pkh"),
    ("did:pkh:aleo:local:abc", "pkh"),
    // secp256k1 did:key (multibase prefix zQ3s), not Ed25519 (z6Mk).
    (
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme",
        "key",
    ),
];

#[tokio::test]
async fn refused_dids_are_refused_with_zero_lookups_at_every_site() {
    let key = JWK::generate_ed25519().unwrap();
    for (issuer, method) in REFUSED {
        let refusal = || UcanVerifyError::MethodDisabled {
            method: (*method).into(),
        };
        let message = refusal().to_string();

        let counting = CountingResolver::default();
        let ucan = signed_ucan(issuer, &key, Algorithm::EdDSA);
        assert_eq!(
            verify_ucan_signature_with(&ucan, counting.clone()).await,
            Err(refusal()),
            "{issuer}: ucan signature"
        );
        assert_eq!(counting.lookups(), 0, "{issuer}: ucan signature lookups");

        let counting = CountingResolver::default();
        let revocation = UcanRevocation::sign(
            issuer.parse().unwrap(),
            ucan.payload().proof[0],
            &key,
            Algorithm::EdDSA,
        )
        .unwrap();
        assert_eq!(
            verify_ucan_revocation_signature_with(
                &revocation,
                Algorithm::EdDSA,
                None,
                counting.clone()
            )
            .await,
            Err(refusal()),
            "{issuer}: revocation"
        );
        assert_eq!(counting.lookups(), 0, "{issuer}: revocation lookups");

        let did: DIDBuf = issuer.parse().unwrap();
        let counting = CountingResolver::default();
        let result = NodeDidResolver::new(counting.clone())
            .resolve_representation(&did, Options::default())
            .await;
        assert!(
            matches!(&result, Err(ResolutionError::Internal(m)) if *m == message),
            "{issuer}: direct representation"
        );
        assert_eq!(
            counting.lookups(),
            0,
            "{issuer}: direct representation lookups"
        );

        let url: DIDURLBuf = format!("{issuer}#key").parse().unwrap();
        let counting = CountingResolver::default();
        let result = NodeDidResolver::new(counting.clone())
            .dereference(&url)
            .await;
        assert!(
            matches!(
                &result,
                Err(DerefError::Resolution(ResolutionError::Internal(m))) if *m == message
            ),
            "{issuer}: direct dereference"
        );
        assert_eq!(
            counting.lookups(),
            0,
            "{issuer}: direct dereference lookups"
        );
    }
}

#[tokio::test]
async fn allowed_dids_pass_the_gate_and_reach_lookup_once() {
    let ed = JWK::generate_ed25519().unwrap();
    let secp = JWK::generate_secp256k1();
    let cases = [
        (DID_METHODS.generate(&ed, "key").unwrap().to_string(), "key"),
        (
            DID_METHODS
                .generate(&secp, "pkh:eip155:1")
                .unwrap()
                .to_string(),
            "pkh:eip155:1",
        ),
        (DID_METHODS.generate(&ed, "jwk").unwrap().to_string(), "jwk"),
    ];
    for (did, label) in cases {
        let did: DIDBuf = did.parse().unwrap();
        let counting = CountingResolver::default();
        let result = NodeDidResolver::new(counting.clone())
            .resolve_representation(&did, Options::default())
            .await;
        assert_eq!(counting.lookups(), 1, "{label}: lookup must run once");
        assert!(
            matches!(&result, Err(ResolutionError::Internal(m)) if m == "counting stub"),
            "{label}: must reach the inner backend, not the refusal"
        );
    }
}

#[tokio::test]
async fn web_variants_are_refused_before_connecting() {
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
    let resolver = NodeDidResolver::current();
    // Bound the test if the refusal regresses and SSI waits for HTTP.
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
async fn direct_dereference_refuses_valid_web_before_connecting() {
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
async fn real_resolver_refuses_non_allowlisted_methods_offline() {
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

#[tokio::test]
async fn key_pkh_and_jwk_still_verify_offline() {
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

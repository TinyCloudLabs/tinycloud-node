use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions, TinyCloudInvocation},
    resolver::DID_METHODS,
    resource::iri_string::types::UriString,
    ssi::jwk::{Algorithm, JWK},
};

#[tokio::test]
async fn direct_owner_invocation_uses_recoverable_jws() {
    let mut key = JWK::generate_secp256k1();
    key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS.generate(&key, "pkh:eip155").unwrap();
    let method = format!("{owner}#blockchainAccountId");
    let invocation = make_invocation_from_uris(
        [(
            owner.as_str().parse::<UriString>().unwrap(),
            ["tinycloud.space/retire-owner".parse().unwrap()],
        )],
        &Cid::default(),
        &key,
        &method,
        4_102_444_800.0,
        InvocationOptions {
            not_before: Some(4_102_444_500.0),
            nonce: Some("synthetic-owner-nonce".into()),
            facts: Some(vec![
                serde_json::json!({"idempotency_key":"00000000-0000-4000-8000-000000000001"}),
            ]),
            proof: Some(vec![]),
        },
    )
    .unwrap();
    invocation.verify_signature(&*DID_METHODS).await.unwrap();
    let jwt = invocation.encode().unwrap();
    TinyCloudInvocation::decode(&jwt)
        .unwrap()
        .verify_signature(&*DID_METHODS)
        .await
        .unwrap();
    let segments: Vec<_> = jwt.split('.').collect();
    let header: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[0]).unwrap()).unwrap();
    assert_eq!(header["alg"], "ES256K-R");
    let payload: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segments[1]).unwrap()).unwrap();
    let signature = URL_SAFE_NO_PAD.decode(segments[2]).unwrap();
    assert_eq!(signature.len(), 65);
    assert!(signature[64] <= 1);
    assert_eq!(payload["prf"], serde_json::json!([]));
    assert!(invocation.payload().proof.is_empty());
    assert_eq!(invocation.payload().issuer.as_str(), method);
}

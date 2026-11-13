use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::space_purge_auth::{verify_owner, OwnerProofError};
const KEY: &str = "00000000-0000-4000-8000-000000000001";

#[tokio::test]
async fn only_direct_fresh_exact_owner_proof_passes() {
    let mut key = JWK::generate_secp256k1();
    key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS
        .generate(&key, "pkh:eip155")
        .unwrap()
        .to_string();
    let method = format!("{owner}#blockchainAccountId");
    let action = "tinycloud.space/retire-owner";
    let invocation = make_invocation_from_uris(
        [(owner.parse().unwrap(), [action.parse().unwrap()])],
        &Cid::default(),
        &key,
        &method,
        1300.0,
        InvocationOptions {
            not_before: Some(1000.0),
            nonce: Some("synthetic-nonce".into()),
            facts: Some(vec![serde_json::json!({"idempotency_key":KEY})]),
            proof: Some(vec![]),
        },
    )
    .unwrap();
    assert!(verify_owner(&invocation, action, &owner, &owner, KEY, 1000)
        .await
        .is_ok());
    assert!(verify_owner(&invocation, action, &owner, &owner, KEY, 1300)
        .await
        .is_err());
    assert!(verify_owner(
        &invocation,
        action,
        &owner,
        &owner,
        "00000000-0000-4000-8000-000000000002",
        1000
    )
    .await
    .is_err());
    let other = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
    assert!(matches!(
        verify_owner(&invocation, action, other, other, KEY, 1000).await,
        Err(OwnerProofError::NotOwner)
    ));
    let original = invocation.payload().clone();
    let mut mutations = Vec::new();
    let mut changed = original.clone();
    changed.proof = vec![Cid::default()];
    mutations.push(changed);
    let mut changed = original.clone();
    changed.nonce = Some(String::new());
    mutations.push(changed);
    let mut changed = original.clone();
    changed.nonce = None;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.expiration =
        tinycloud_auth::ssi::claims::jwt::NumericDate::try_from_seconds(1301.0).unwrap();
    mutations.push(changed);
    let mut changed = original.clone();
    changed.not_before = None;
    mutations.push(changed);
    let mut changed = original.clone();
    changed.facts = Some(vec![
        serde_json::json!({"idempotency_key":KEY}),
        serde_json::json!({"idempotency_key":KEY}),
    ]);
    mutations.push(changed);
    for payload in mutations {
        let signed = payload.sign(Algorithm::ES256KR, &key).unwrap();
        assert!(verify_owner(&signed, action, &owner, &owner, KEY, 1000)
            .await
            .is_err());
    }
    for target in [format!("tinycloud:{}", &owner[4..]), other.to_owned()] {
        let invalid = make_invocation_from_uris(
            [(target.parse().unwrap(), [action.parse().unwrap()])],
            &Cid::default(),
            &key,
            &method,
            1300.0,
            InvocationOptions {
                not_before: Some(1000.0),
                nonce: Some("another-synthetic-nonce".into()),
                facts: Some(vec![serde_json::json!({"idempotency_key":KEY})]),
                proof: Some(vec![]),
            },
        )
        .unwrap();
        assert!(verify_owner(&invalid, action, &owner, &owner, KEY, 1000)
            .await
            .is_err());
    }
    // A different key cannot claim this owner, even with an otherwise valid payload.
    let mut attacker = JWK::generate_secp256k1();
    attacker.algorithm = Some(Algorithm::ES256KR);
    let spoofed = original.sign(Algorithm::ES256KR, &attacker).unwrap();
    assert!(verify_owner(&spoofed, action, &owner, &owner, KEY, 1000)
        .await
        .is_err());
}

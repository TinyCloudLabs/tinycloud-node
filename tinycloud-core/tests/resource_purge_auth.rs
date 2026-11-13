use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::space_purge_auth::verify_owner;
#[tokio::test]
async fn direct_owner_resource_proofs_match_exact_networks_and_keys_without_prefix_authority() {
    let mut key = JWK::generate_secp256k1();
    key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS
        .generate(&key, "pkh:eip155")
        .unwrap()
        .to_string();
    let owner = tinycloud_auth::identity::canonicalize_did(&owner).unwrap();
    let network = format!("urn:tinycloud:encryption:{owner}:default");
    let exact_key = format!("{network}/apps/app/key");
    let now = OffsetDateTime::now_utc().unix_timestamp();
    for (resource, expected, valid) in [
        (network.as_str(), network.as_str(), true),
        (exact_key.as_str(), exact_key.as_str(), true),
        (network.as_str(), exact_key.as_str(), false),
        (exact_key.as_str(), network.as_str(), false),
        (
            format!("{network}/apps/app/").as_str(),
            exact_key.as_str(),
            false,
        ),
    ] {
        let id = uuid::Uuid::new_v4().to_string();
        let invocation = make_invocation_from_uris(
            [(
                resource.parse().unwrap(),
                ["tinycloud.resource/delete".parse().unwrap()],
            )],
            &Cid::default(),
            &key,
            &format!("{owner}#blockchainAccountId"),
            (now + 300) as f64,
            InvocationOptions {
                not_before: Some(now as f64),
                nonce: Some(uuid::Uuid::new_v4().to_string()),
                facts: Some(vec![serde_json::json!({"idempotency_key":id})]),
                proof: Some(vec![]),
            },
        )
        .unwrap();
        assert_eq!(
            verify_owner(
                &invocation,
                "tinycloud.resource/delete",
                expected,
                &owner,
                &id,
                now
            )
            .await
            .is_ok(),
            valid
        );
    }
}

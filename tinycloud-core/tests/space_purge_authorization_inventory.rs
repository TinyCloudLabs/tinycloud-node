use std::collections::BTreeMap;
use tinycloud_auth::{
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::space_purge_records::policy::{inventory_authorization_targets, PolicyTarget};

fn signed(resources: &[&str]) -> Vec<u8> {
    let signer = JWK::generate_ed25519().unwrap();
    let issuer = DID_METHODS.generate(&signer, "key").unwrap().to_string();
    let vm = format!("{issuer}#{}", issuer.trim_start_matches("did:key:"));
    let mut caps = Capabilities::new();
    for resource in resources {
        caps.with_action(
            resource.parse().unwrap(),
            "tinycloud.kv/get".parse().unwrap(),
            [BTreeMap::<String, serde_json::Value>::new()],
        );
    }
    Payload::<serde_json::Value, serde_json::Value> {
        issuer: vm.parse().unwrap(),
        audience: issuer.parse().unwrap(),
        not_before: None,
        expiration: NumericDate::try_from_seconds(2_000_000_000.0).unwrap(),
        nonce: None,
        facts: None,
        proof: vec![],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, &signer)
    .unwrap()
    .encode()
    .unwrap()
    .into_bytes()
}

#[test]
fn signed_copies_inventory_without_any_registration() {
    let space = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files";
    let network = "urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default";
    let bytes = signed(&[&format!("{space}/kv/key"), network]);
    let targets = inventory_authorization_targets(&bytes).unwrap();
    assert_eq!(targets.len(), 2);
    assert!(targets.contains(&PolicyTarget::Space(space.into())));
    assert!(targets.iter().any(|target| matches!(target, PolicyTarget::Resource(resource) if resource.to_string() == network)));
}

#[test]
fn malformed_authority_never_returns_an_empty_success() {
    for (index, bytes) in [
        vec![],
        b"not authorization".to_vec(),
        vec![255, 254],
        signed(&["tinycloud:invalid/kv/key"]),
        signed(&["urn:tinycloud:encryption:invalid"]),
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            inventory_authorization_targets(&bytes).is_err(),
            "case {index}"
        );
    }
}

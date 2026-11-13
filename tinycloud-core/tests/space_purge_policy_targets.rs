use serde_json::json;
use tinycloud_core::space_purge_records::policy::{
    capability_target, native_policy_targets, PolicyTarget,
};

const SPACE: &str = "tinycloud:pkh:eip155:1:0x1111111111111111111111111111111111111111:files";

#[test]
fn inventory_preserves_exact_policy_authority_target() {
    let native = json!({"capabilityCeiling":[
        {"kind":"kv","resource":format!("{SPACE}/kv/key"),"actions":["tinycloud.kv/get"]},
        {"kind":"encryption","resource":"urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default","actions":["tinycloud.encryption/decrypt"]}
    ]});
    let targets = native_policy_targets(&serde_json::to_vec(&native).unwrap()).unwrap();
    assert_eq!(targets[0], PolicyTarget::Space(SPACE.into()));
    assert!(
        matches!(&targets[1], PolicyTarget::Resource(resource) if resource.to_string().starts_with("urn:tinycloud:encryption:"))
    );
    let kernel = json!({"service":"tinycloud.kv", "space":SPACE,"path":"key","actions":["tinycloud.kv/get"]});
    assert_eq!(
        capability_target(&kernel).unwrap(),
        PolicyTarget::Space(SPACE.into())
    );
}

#[test]
fn uncertain_policy_inventory_is_an_error() {
    for value in [
        json!({}),
        json!({"resource":null}),
        json!({"resource":"not a URI"}),
        json!({"space":SPACE}),
    ] {
        assert!(capability_target(&value).is_err());
    }
    for bytes in [
        b"{}".as_slice(),
        b"not JSON".as_slice(),
        b"{\"capabilityCeiling\":{}}".as_slice(),
    ] {
        assert!(native_policy_targets(bytes).is_err());
    }
}

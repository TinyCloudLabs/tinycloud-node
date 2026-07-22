mod common;

use serde_json::Value;

use common::email_claim_fixture_root;
use tinycloud::share_email::{CapabilityDescriptor, NODE_CAPABILITY_ROUTES};

const FROZEN_MANIFEST_DIGEST: &str = "pl8-1Rpx_DYCBjOpK3hRrLfrSVDINNFssZDfFw6BMTs";

fn frozen_node_routes() -> Value {
    let root = email_claim_fixture_root();
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(root.join("manifest.json")).expect("frozen manifest must be present"),
    )
    .expect("frozen manifest must be JSON");
    assert_eq!(
        manifest["manifestDigest"], FROZEN_MANIFEST_DIGEST,
        "route parity must use the immutable Share contract"
    );
    serde_json::from_slice(
        &std::fs::read(
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("specs/email-claim-v1/domains.json"),
        )
        .expect("frozen domains must be present"),
    )
    .expect("frozen domains must be JSON")
}

#[test]
fn serialized_production_descriptor_matches_frozen_node_routes() {
    let domains: Value = frozen_node_routes();
    let expected = domains["capabilities"]["node"]["routes"]
        .as_array()
        .expect("frozen node routes");
    let actual: Vec<Value> = NODE_CAPABILITY_ROUTES
        .iter()
        .map(|route| Value::String((*route).to_owned()))
        .collect();
    assert_eq!(actual, *expected);

    let descriptor = CapabilityDescriptor {
        id: "tinycloud.node-policy-email-v1",
        version: 1,
        origin: "https://node.example".to_owned(),
        return_origin: "https://share.tinycloud.xyz".to_owned(),
        routes: NODE_CAPABILITY_ROUTES,
        content_kinds: ["kv", "sql"],
        mail_provider: "resend",
        status: "ready",
    };
    let serialized = serde_json::to_value(descriptor).expect("descriptor serializes");
    assert_eq!(serialized["routes"], Value::Array(expected.clone()));
    assert_eq!(serialized["routes"].as_array().unwrap().len(), 4);
}

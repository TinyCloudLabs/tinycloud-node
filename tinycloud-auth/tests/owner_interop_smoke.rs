use tinycloud_auth::{authorization::TinyCloudInvocation, resolver::DID_METHODS};
#[tokio::test]
async fn verifies_openkey_synthetic_owner_invocation() {
    let fixture: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/openkey-owner-retirement.json")).unwrap();
    assert_eq!(fixture["synthetic"], true);
    let invocation = TinyCloudInvocation::decode(fixture["invocation"].as_str().unwrap()).unwrap();
    invocation.verify_signature(&*DID_METHODS).await.unwrap();
    assert_eq!(
        invocation.payload().issuer.as_str(),
        format!("{}#blockchainAccountId", fixture["owner"].as_str().unwrap())
    );
    assert!(invocation.payload().proof.is_empty());
}

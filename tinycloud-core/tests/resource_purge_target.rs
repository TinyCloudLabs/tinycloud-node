use tinycloud_core::resource_purge_fence::ResourceTarget;
#[test]
fn resource_purge_targets_require_exact_canonical_uri_identities() {
    let network = "urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default";
    let target = ResourceTarget::parse(network).unwrap();
    assert_eq!(target.as_str(), network);
    let key = ResourceTarget::parse(&format!("{network}/apps/app/key")).unwrap();
    assert_eq!(key.network_id(), network);
    assert!(ResourceTarget::parse(&format!("{network}/apps/app/")).is_err());
    assert!(ResourceTarget::parse(&format!("{network}\n")).is_err());
    assert!(ResourceTarget::parse(&format!("{network}\u{0000}")).is_err());
}

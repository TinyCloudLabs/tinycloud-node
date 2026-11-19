use std::collections::BTreeMap;
use tinycloud_core::{
    resource_purge_dependencies::ResourceDependencySnapshot, resource_purge_fence::ResourceTarget,
    resource_retirement_snapshot::prepare, space_purge_ledger::LedgerKeys,
};

#[test]
fn prepared_manifest_binds_exact_target_parent_network_and_retirement() {
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )
    .unwrap();
    let network = "urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default";
    let target = ResourceTarget::parse(&format!("{network}/named")).unwrap();
    let body = serde_json::to_vec(&(target.as_str(), Vec::<(String, String)>::new())).unwrap();
    let snapshot = ResourceDependencySnapshot::from_db_bytes(&target, &body).unwrap();
    let first = prepare(
        &keys,
        "test",
        "00000000-0000-4000-8000-000000000001",
        &snapshot,
    )
    .unwrap();
    let second = prepare(
        &keys,
        "test",
        "00000000-0000-4000-8000-000000000002",
        &snapshot,
    )
    .unwrap();
    assert_eq!(
        first.commitment().target_hmac,
        hex::encode(
            keys.target_hmac("test", "resource", target.as_str())
                .unwrap()
        )
    );
    assert_eq!(
        first.commitment().network_hmac,
        hex::encode(keys.target_hmac("test", "resource", network).unwrap())
    );
    assert_ne!(
        first.commitment().snapshot_hmac,
        second.commitment().snapshot_hmac
    );
    assert!(prepare(
        &keys,
        "missing",
        "00000000-0000-4000-8000-000000000001",
        &snapshot
    )
    .is_err());
}

#[test]
fn primitive_admission_refuses_oversized_strings_counts_and_bodies() {
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )
    .unwrap();
    let raw = "urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default";
    let target = ResourceTarget::parse(raw).unwrap();
    let retirement = "00000000-0000-4000-8000-000000000001";
    let huge = serde_json::to_vec(&(raw, vec![("member", "x".repeat(2 * 1024 * 1024))])).unwrap();
    assert!(ResourceDependencySnapshot::from_db_bytes(&target, &huge).is_err());
    assert!(keys
        .retirement_snapshot_hmac("test", retirement, &huge)
        .is_err());
    let long = serde_json::to_vec(&(raw, vec![("member", "x".repeat(4097))])).unwrap();
    assert!(ResourceDependencySnapshot::from_db_bytes(&target, &long).is_err());
    assert!(keys
        .retirement_snapshot_hmac("test", retirement, &long)
        .is_err());
    let many = serde_json::to_vec(&(raw, vec![("member", "did:key:a"); 4097])).unwrap();
    assert!(ResourceDependencySnapshot::from_db_bytes(&target, &many).is_err());
    assert!(keys
        .retirement_snapshot_hmac("test", retirement, &many)
        .is_err());
    assert!(keys
        .verify("unused", &vec![b' '; 4 * 1024 * 1024 + 1])
        .is_err());
}

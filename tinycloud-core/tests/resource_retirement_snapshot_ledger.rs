use std::collections::BTreeMap;
use tinycloud_core::space_purge_ledger::{LedgerKeys, RetirementSnapshotCommitment};

#[test]
fn retirement_commitments_bind_target_operation_and_manifest_without_publishing_relationships() {
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )
    .unwrap();
    let retirement = "00000000-0000-4000-8000-000000000001";
    let other_retirement = "00000000-0000-4000-8000-000000000002";
    // The strict graph snapshot decoder is a separate admission prerequisite.
    let body = br#"["urn:tinycloud:encryption:pkh:eip155:1:0x1111111111111111111111111111111111111111:network",[["member","did:key:outside"]]]"#;
    let digest = keys
        .retirement_snapshot_hmac("test", retirement, body)
        .unwrap();
    assert_ne!(
        digest,
        keys.retirement_snapshot_hmac("test", other_retirement, body)
            .unwrap()
    );
    assert_ne!(
        digest,
        keys.target_hmac("test", "resource", std::str::from_utf8(body).unwrap())
            .unwrap()
    );
    let changed = std::str::from_utf8(body)
        .unwrap()
        .replace("outside", "different");
    assert_ne!(
        digest,
        keys.retirement_snapshot_hmac("test", retirement, changed.as_bytes())
            .unwrap()
    );
    let owner = keys
        .target_hmac(
            "test",
            "owner",
            "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
        )
        .unwrap();
    let old = keys
        .sign("test", "owner", &owner, retirement, "retired", 100)
        .unwrap();
    let historical_bytes = old.to_bytes().unwrap();
    assert_eq!(
        keys.verify(&old.object_key().unwrap(), &historical_bytes)
            .unwrap(),
        old
    );
    let manifest = vec![RetirementSnapshotCommitment {
        target_hmac: "a".repeat(64),
        network_hmac: "a".repeat(64),
        snapshot_hmac: hex::encode(digest),
    }];
    let record = keys
        .with_retirement_snapshots(old.clone(), manifest.clone())
        .unwrap();
    assert_eq!(record.version, 3);
    let bytes = record.to_bytes().unwrap();
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(!text.contains("did:"));
    assert!(!text.contains("network\""));
    assert_eq!(
        keys.verify(&record.object_key().unwrap(), &bytes).unwrap(),
        record
    );
    let mut changed = record.clone();
    changed.retirement_snapshots[0].snapshot_hmac = "b".repeat(64);
    assert!(keys
        .verify(&changed.object_key().unwrap(), &changed.to_bytes().unwrap())
        .is_err());
    let mut downgraded = record.clone();
    downgraded.version = 1;
    assert!(keys
        .verify(
            &record.object_key().unwrap(),
            &downgraded.to_bytes().unwrap()
        )
        .is_err());
    assert!(keys
        .with_retirement_snapshots(old.clone(), vec![manifest[0].clone(), manifest[0].clone()])
        .is_err());
    let empty = keys.with_retirement_snapshots(old, vec![]).unwrap();
    assert_eq!(empty.version, 3);
    assert!(empty.retirement_snapshots.is_empty());
    assert_eq!(
        keys.verify(&empty.object_key().unwrap(), &empty.to_bytes().unwrap())
            .unwrap(),
        empty
    );
    assert!(keys
        .retirement_snapshot_hmac("unknown", retirement, body)
        .is_err());
}

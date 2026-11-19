use std::collections::BTreeMap;
use tinycloud::storage::purge_reconcile::{PrefixStoreKind, VerifiedPurgePrefix};
use tinycloud_core::space_purge_ledger::LedgerKeys;

#[test]
fn authenticated_prefix_inventory_binds_backend_and_exact_candidate() {
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )
    .unwrap();
    let prefix = "sql/v1/~0123456789abcdef/";
    let base = keys
        .sign(
            "test",
            "space",
            &[3; 32],
            "00000000-0000-4000-8000-000000000001",
            "purging",
            1,
        )
        .unwrap();
    let record = keys
        .with_prefixes(
            base,
            vec![keys.prefix_hmac("test", "sql-filesystem", prefix).unwrap()],
        )
        .unwrap();
    let completion = keys.completion_from_acceptance(record.clone(), 2).unwrap();
    assert_eq!(completion.prefixes, record.prefixes);
    assert_eq!(completion.state, "complete");
    assert!(keys
        .verify(
            &completion.object_key().unwrap(),
            &completion.to_bytes().unwrap()
        )
        .is_ok());
    assert!(!String::from_utf8(record.to_bytes().unwrap())
        .unwrap()
        .contains(prefix));
    assert_ne!(
        keys.prefix_hmac("test", "sqlite-cache", "space/").unwrap(),
        keys.prefix_hmac("test", "duckdb-cache", "space/").unwrap()
    );
    let path = record.object_key().unwrap();
    let body = record.to_bytes().unwrap();
    let proof = VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &body,
        PrefixStoreKind::SqlFileSystem,
        prefix,
    )
    .unwrap();
    assert_eq!(proof.prefix(), prefix);
    assert_eq!(proof.store_kind(), PrefixStoreKind::SqlFileSystem);
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &body,
        PrefixStoreKind::SqlS3,
        prefix
    )
    .is_err());
    assert!(VerifiedPurgePrefix::verify_candidate(
        &keys,
        &path,
        &body,
        PrefixStoreKind::SqlFileSystem,
        "sql/v1/neighbour/"
    )
    .is_err());
    let mut altered = record.clone();
    altered.prefixes.clear();
    assert!(keys.verify(&path, &altered.to_bytes().unwrap()).is_err());
    assert!(keys
        .prefix_hmac("test", "sql-filesystem", "_purge-ledger/spaces/")
        .is_err());
    assert!(keys
        .prefix_hmac("test", "sql-filesystem", "/absolute/")
        .is_err());
}

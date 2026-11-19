use std::collections::BTreeMap;
use tinycloud_core::space_purge_ledger::{LedgerKeys, LedgerRecord};

fn keys() -> LedgerKeys {
    LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )
    .unwrap()
}
const OP: &str = "00000000-0000-4000-8000-000000000001";

#[test]
fn ledger_mac_binds_every_field_and_object_location() {
    let keys = keys();
    let target = keys
        .target_hmac("test", "space", "synthetic-target")
        .unwrap();
    let record = keys
        .sign("test", "space", &target, OP, "purging", 100)
        .unwrap();
    let path = record.object_key().unwrap();
    let body = record.to_bytes().unwrap();
    assert_eq!(keys.verify(&path, &body).unwrap(), record);
    assert!(keys.verify(&format!("{path}/other"), &body).is_err());
    for (field, value) in [
        ("version", serde_json::json!(2)),
        ("key_id", serde_json::json!("unknown")),
        ("kind", serde_json::json!("owner")),
        ("target_hmac", serde_json::json!("ff".repeat(32))),
        (
            "operation_id",
            serde_json::json!("00000000-0000-4000-8000-000000000002"),
        ),
        ("state", serde_json::json!("complete")),
        ("timestamp", serde_json::json!(101)),
        ("mac", serde_json::json!("00".repeat(32))),
        ("raw_space", serde_json::json!("forbidden")),
    ] {
        let mut changed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        changed[field] = value;
        assert!(
            keys.verify(&path, &serde_json::to_vec(&changed).unwrap())
                .is_err(),
            "{field}"
        );
        if let Ok(record) = serde_json::from_value::<LedgerRecord>(changed.clone()) {
            if let Ok(moved_path) = record.object_key() {
                assert!(
                    keys.verify(&moved_path, &serde_json::to_vec(&changed).unwrap())
                        .is_err(),
                    "moved {field}"
                );
            }
        }
    }
    assert!(!String::from_utf8(body)
        .unwrap()
        .contains("synthetic-target"));
}

#[test]
fn retirement_and_purge_states_are_domain_separated_and_append_only() {
    let keys = keys();
    let owner = keys.target_hmac("test", "owner", "same-target").unwrap();
    let space = keys.target_hmac("test", "space", "same-target").unwrap();
    assert_ne!(owner, space);
    let retirement = keys
        .sign("test", "owner", &owner, OP, "retired", 100)
        .unwrap();
    assert!(retirement
        .object_key()
        .unwrap()
        .starts_with("_purge-ledger/owners/test/"));
    assert!(keys
        .sign("test", "owner", &owner, OP, "complete", 100)
        .is_err());
    let acceptance = keys
        .sign("test", "space", &space, OP, "purging", 100)
        .unwrap();
    let completion = keys
        .sign("test", "space", &space, OP, "complete", 101)
        .unwrap();
    assert_ne!(
        acceptance.object_key().unwrap(),
        completion.object_key().unwrap()
    );
    assert!(keys
        .verify(
            &completion.object_key().unwrap(),
            &completion.to_bytes().unwrap()
        )
        .is_ok());
}

#[test]
fn rotation_retains_verification_of_old_records() {
    let old = keys();
    let digest = old.target_hmac("test", "space", "synthetic").unwrap();
    let record = old
        .sign("test", "space", &digest, OP, "purging", 100)
        .unwrap();
    let rotated = LedgerKeys::new(
        "next".into(),
        BTreeMap::from([("test".into(), vec![7; 32]), ("next".into(), vec![8; 32])]),
    )
    .unwrap();
    assert!(rotated
        .verify(&record.object_key().unwrap(), &record.to_bytes().unwrap())
        .is_ok());
    let missing = LedgerKeys::new(
        "next".into(),
        BTreeMap::from([("next".into(), vec![8; 32])]),
    )
    .unwrap();
    assert!(missing
        .verify(&record.object_key().unwrap(), &record.to_bytes().unwrap())
        .is_err());
    assert!(LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 31])])
    )
    .is_err());
}

#[test]
fn persistent_key_config_is_stable_and_retains_prior_key_versions() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let encoded = URL_SAFE_NO_PAD.encode([17_u8; 32]);
    let first = LedgerKeys::from_config(encoded.clone()).unwrap();
    let restarted = LedgerKeys::from_config(encoded.clone()).unwrap();
    assert_eq!(first.active_key_id(), restarted.active_key_id());
    let digest = first
        .target_hmac(first.active_key_id(), "space", "synthetic")
        .unwrap();
    let record = first
        .sign(first.active_key_id(), "space", &digest, OP, "purging", 100)
        .unwrap();
    assert!(restarted
        .verify(&record.object_key().unwrap(), &record.to_bytes().unwrap())
        .is_ok());
    let config = serde_json::json!({"active_key_id":"next","keys":{first.active_key_id():encoded,"next":URL_SAFE_NO_PAD.encode([18_u8;32])}});
    let rotated = LedgerKeys::from_config(config.to_string()).unwrap();
    assert_eq!(rotated.active_key_id(), "next");
    assert!(rotated
        .verify(&record.object_key().unwrap(), &record.to_bytes().unwrap())
        .is_ok());
    for invalid in [
        String::new(),
        "not a key".into(),
        URL_SAFE_NO_PAD.encode([0_u8; 31]),
        "{}".into(),
    ] {
        assert!(LedgerKeys::from_config(invalid).is_err());
    }
}

#[test]
fn resource_records_are_domain_and_path_separated_from_space_records() {
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![13; 32])]),
    )
    .unwrap();
    let target = "urn:tinycloud:encryption:did:pkh:eip155:1:0x1111111111111111111111111111111111111111:default";
    let digest = keys.target_hmac("test", "resource", target).unwrap();
    assert_ne!(digest, keys.target_hmac("test", "space", target).unwrap());
    let record = keys
        .sign(
            "test",
            "resource",
            &digest,
            &uuid::Uuid::new_v4().to_string(),
            "purging",
            1,
        )
        .unwrap();
    let path = record.object_key().unwrap();
    assert!(path.starts_with("_purge-ledger/resources/"));
    assert_eq!(
        keys.verify(&path, &record.to_bytes().unwrap()).unwrap(),
        record
    );
    assert!(keys
        .verify(
            &path.replace("/resources/", "/spaces/"),
            &record.to_bytes().unwrap()
        )
        .is_err());
}

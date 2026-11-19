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

const OWNER_DID: &str = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";

/// Pinned `("owner","erased")` vector (TC-2871 S5, option A): the v1 MAC,
/// domain and field order of a retirement, at its own sibling path.
#[test]
fn owner_erased_record_is_pinned_v1_at_its_own_path() {
    let keys = keys();
    let owner = keys.target_hmac("test", "owner", OWNER_DID).unwrap();
    let retired = keys
        .sign("test", "owner", &owner, OP, "retired", 100)
        .unwrap();
    // A timestamp before the retirement's is raised to it.
    assert_eq!(
        keys.erasure_from_retirement(&retired, 99)
            .unwrap()
            .timestamp,
        100
    );
    let erased = keys.erasure_from_retirement(&retired, 200).unwrap();
    assert_eq!(
        erased,
        keys.sign("test", "owner", &owner, OP, "erased", 200)
            .unwrap()
    );
    let digest = hex::encode(&owner);
    assert_eq!(
        erased.object_key().unwrap(),
        format!("_purge-ledger/owners-erased/test/{digest}")
    );
    assert_eq!(
        retired.object_key().unwrap(),
        format!("_purge-ledger/owners/test/{digest}")
    );
    assert_eq!(digest, PINNED_OWNER_HMAC);
    assert_eq!(erased.mac, PINNED_ERASED_MAC);
    assert_eq!(
        String::from_utf8(erased.to_bytes().unwrap()).unwrap(),
        format!(
            r#"{{"version":1,"key_id":"test","kind":"owner","target_hmac":"{PINNED_OWNER_HMAC}","operation_id":"{OP}","state":"erased","timestamp":200,"mac":"{PINNED_ERASED_MAC}"}}"#
        )
    );
    assert_eq!(
        keys.verify(&erased.object_key().unwrap(), &erased.to_bytes().unwrap())
            .unwrap(),
        erased
    );
}

// Computed outside this crate: HMAC-SHA256 under key [7; 32] over
// `tinycloud-owner-tombstone-v1\0` + OWNER_DID, and over
// `tinycloud-space-purge-ledger-v1\0` + the fixed-order v1 field JSON.
const PINNED_OWNER_HMAC: &str = "993172355863edf59ea783b177ad40f6f0b219559b65b4368e9eb146aa669361";
const PINNED_ERASED_MAC: &str = "716c439adc5f08d630ea0892e52c74f6ae6ab3aac7f0a55d79f99a93d17797e5";

#[test]
fn owner_erased_and_retired_records_do_not_verify_at_each_others_path() {
    let keys = keys();
    let owner = keys.target_hmac("test", "owner", OWNER_DID).unwrap();
    let retired = keys
        .sign("test", "owner", &owner, OP, "retired", 100)
        .unwrap();
    let erased = keys.erasure_from_retirement(&retired, 200).unwrap();
    let (retired_path, erased_path) = (retired.object_key().unwrap(), erased.object_key().unwrap());
    assert_ne!(retired_path, erased_path);
    assert!(keys
        .verify(&erased_path, &retired.to_bytes().unwrap())
        .is_err());
    assert!(keys
        .verify(&retired_path, &erased.to_bytes().unwrap())
        .is_err());
    // Relabelling the state keeps the MAC from verifying at either path.
    let mut relabelled: serde_json::Value =
        serde_json::from_slice(&retired.to_bytes().unwrap()).unwrap();
    relabelled["state"] = serde_json::json!("erased");
    let relabelled = serde_json::to_vec(&relabelled).unwrap();
    assert!(keys.verify(&erased_path, &relabelled).is_err());
    assert!(keys.verify(&retired_path, &relabelled).is_err());
}

#[test]
fn owner_erased_is_refused_for_any_other_kind_state_or_version() {
    let keys = keys();
    let owner = keys.target_hmac("test", "owner", OWNER_DID).unwrap();
    let space = keys.target_hmac("test", "space", "synthetic").unwrap();
    assert!(keys
        .sign("test", "owner", &owner, OP, "complete", 100)
        .is_err());
    assert!(keys
        .sign("test", "owner", &owner, OP, "purging", 100)
        .is_err());
    for kind in ["space", "resource"] {
        assert!(keys.sign("test", kind, &space, OP, "erased", 100).is_err());
    }
    // Only a retirement yields an erasure, and an erasure is never upgraded.
    let erased = keys
        .sign("test", "owner", &owner, OP, "erased", 100)
        .unwrap();
    assert!(keys.erasure_from_retirement(&erased, 200).is_err());
    let purging = keys
        .sign("test", "space", &space, OP, "purging", 100)
        .unwrap();
    assert!(keys.erasure_from_retirement(&purging, 200).is_err());
    assert!(keys
        .with_retirement_snapshots(erased.clone(), Vec::new())
        .is_err());
    assert!(keys.with_prefixes(erased.clone(), Vec::new()).is_err());
    for version in [2, 3] {
        let mut body: serde_json::Value =
            serde_json::from_slice(&erased.to_bytes().unwrap()).unwrap();
        body["version"] = serde_json::json!(version);
        assert!(serde_json::from_value::<LedgerRecord>(body)
            .unwrap()
            .object_key()
            .is_err());
    }
}

/// A reader that predates `("owner","erased")` accepts only the pairs it
/// knew, so it refuses this record and its reconcile stays fail-closed. This
/// is why a node that wrote one must not be rolled back below this release.
#[test]
fn older_reader_refuses_owner_erased_records() {
    fn older_reader_accepts(record: &LedgerRecord) -> bool {
        matches!(
            (record.kind.as_str(), record.state.as_str()),
            ("owner", "retired") | ("space" | "resource", "purging" | "complete")
        )
    }
    let keys = keys();
    let owner = keys.target_hmac("test", "owner", OWNER_DID).unwrap();
    let retired = keys
        .sign("test", "owner", &owner, OP, "retired", 100)
        .unwrap();
    let erased = keys.erasure_from_retirement(&retired, 200).unwrap();
    assert!(older_reader_accepts(&retired));
    assert!(!older_reader_accepts(&erased));
}

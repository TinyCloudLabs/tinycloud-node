use super::*;

#[tokio::test]
async fn minio_purge_restart_and_prefix_isolation() {
    let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
        return;
    };
    let bucket = std::env::var("TC735_TEST_MINIO_BUCKET").unwrap();
    let config = S3BlockConfig {
        bucket,
        endpoint: Some(endpoint.parse().unwrap()),
    };
    let store = config.open().await.unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let space: SpaceId = format!("tinycloud:key:test:purge-{nonce}").parse().unwrap();
    let neighbour = format!("{space}-neighbour/keep");
    let mut keys: Vec<_> = (0..300)
        .map(|index| format!("{space}/object-{index}"))
        .collect();
    keys.push(neighbour.clone());
    for key in keys {
        store
            .client
            .put_object()
            .bucket(&store.bucket)
            .key(key)
            .body(ByteStream::from_static(b"data"))
            .send()
            .await
            .unwrap();
    }
    assert!(!store.purge_space_batch(&space).await.unwrap());
    drop(store);
    let store = config.open().await.unwrap();
    assert!(!store.purge_space_batch(&space).await.unwrap());
    assert!(store.purge_space_batch(&space).await.unwrap());
    // A late object requires another deletion and final empty verification.
    store
        .client
        .put_object()
        .bucket(&store.bucket)
        .key(format!("{space}/late"))
        .body(ByteStream::from_static(b"late"))
        .send()
        .await
        .unwrap();
    assert!(!store.purge_space_batch(&space).await.unwrap());
    assert!(store.purge_space_batch(&space).await.unwrap());
    store
        .client
        .head_object()
        .bucket(&store.bucket)
        .key(&neighbour)
        .send()
        .await
        .unwrap();
    store
        .client
        .delete_object()
        .bucket(&store.bucket)
        .key(neighbour)
        .send()
        .await
        .unwrap();
}

// test-ruling: TC-2871 ledger out of the data bucket (Naomi 11-18): the ledger
// is `S3PurgeLedger` on its own bucket, created with Object Lock and a default
// COMPLIANCE retention, so this checks the write is accepted there (a lock
// bucket refuses a PUT without a checksum) and lands locked. Locked records
// cannot be cleaned up; use a throwaway bucket with a short retention.
#[tokio::test]
async fn minio_ledger_is_append_only_on_its_own_locked_bucket() {
    use crate::storage::purge_ledger::{PurgeLedgerStore, S3PurgeLedger, S3PurgeLedgerConfig};
    let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
        return;
    };
    let Ok(bucket) = std::env::var("TC735_TEST_MINIO_LEDGER_BUCKET") else {
        return;
    };
    let config = S3PurgeLedgerConfig {
        bucket,
        endpoint: Some(endpoint.parse().unwrap()),
        region: None,
        access_key_id: None,
        secret_access_key: None,
    };
    let store = S3PurgeLedger::new(&config).await;
    let key = format!("_purge-ledger/owners/test-{}/opaque", uuid::Uuid::new_v4());
    assert_eq!(store.read_purge_record(&key).await.unwrap(), None);
    store
        .append_purge_record(&key, b"authenticated-protocol-bytes")
        .await
        .unwrap();
    store
        .append_purge_record(&key, b"authenticated-protocol-bytes")
        .await
        .unwrap();
    assert_eq!(
        store
            .append_purge_record(&key, b"different")
            .await
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::AlreadyExists
    );
    assert!(store.list_purge_records().await.unwrap().contains(&key));
    let store = S3PurgeLedger::new(&config).await;
    assert_eq!(
        store.read_purge_record(&key).await.unwrap().unwrap(),
        b"authenticated-protocol-bytes"
    );
    let (client, bucket) = store.client();
    let head = client
        .head_object()
        .bucket(bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert_eq!(
        head.object_lock_mode(),
        Some(&aws_sdk_s3::types::ObjectLockMode::Compliance)
    );
    assert!(head.object_lock_retain_until_date().is_some());
}

// TC-2871 S5: the owner's `erased` record sits beside its `retired` record
// on the locked ledger bucket; both are stored, listed and read back. The
// key id is fresh per run because locked records cannot be cleaned up.
#[tokio::test]
async fn minio_owner_retired_and_erased_records_are_stored_side_by_side() {
    use crate::storage::purge_ledger::{PurgeLedgerStore, S3PurgeLedger, S3PurgeLedgerConfig};
    use tinycloud_core::space_purge_ledger::owner_object_key;
    let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
        return;
    };
    let Ok(bucket) = std::env::var("TC735_TEST_MINIO_LEDGER_BUCKET") else {
        return;
    };
    let config = S3PurgeLedgerConfig {
        bucket,
        endpoint: Some(endpoint.parse().unwrap()),
        region: None,
        access_key_id: None,
        secret_access_key: None,
    };
    let store = S3PurgeLedger::new(&config).await;
    let key_id = format!("test-{}", uuid::Uuid::new_v4().simple());
    let digest = "cd".repeat(32);
    let retired = owner_object_key(&key_id, &digest, "retired").unwrap();
    let erased = owner_object_key(&key_id, &digest, "erased").unwrap();
    store
        .append_purge_record(&retired, b"retired")
        .await
        .unwrap();
    store.append_purge_record(&erased, b"erased").await.unwrap();
    let store = S3PurgeLedger::new(&config).await;
    let listed = store.list_purge_records().await.unwrap();
    assert!(listed.contains(&retired) && listed.contains(&erased));
    assert_eq!(
        store.read_purge_record(&retired).await.unwrap().unwrap(),
        b"retired"
    );
    assert_eq!(
        store.read_purge_record(&erased).await.unwrap().unwrap(),
        b"erased"
    );
}

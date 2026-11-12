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

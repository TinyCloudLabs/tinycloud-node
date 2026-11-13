use super::*;

#[tokio::test]
async fn minio_empty_probe_preserves_objects_and_neighbour_prefix() {
    let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
        return;
    };
    let config = S3BlockConfig {
        bucket: std::env::var("TC735_TEST_MINIO_BUCKET").unwrap(),
        endpoint: Some(endpoint.parse().unwrap()),
    };
    let store = config.open().await.unwrap();
    let space: SpaceId = format!("tinycloud:key:test:probe-{}", uuid::Uuid::new_v4())
        .parse()
        .unwrap();
    let key = format!("{space}/keep");
    let neighbour = format!("{space}-other/keep");
    assert!(store.space_is_empty(&space).await.unwrap());
    for name in [&key, &neighbour] {
        store
            .client
            .put_object()
            .bucket(&store.bucket)
            .key(name)
            .body(ByteStream::from_static(b"kept"))
            .send()
            .await
            .unwrap();
    }
    assert!(!store.space_is_empty(&space).await.unwrap());
    store
        .client
        .head_object()
        .bucket(&store.bucket)
        .key(&key)
        .send()
        .await
        .unwrap();
    assert!(!store.purge_space_batch(&space).await.unwrap());
    assert!(store.space_is_empty(&space).await.unwrap());
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

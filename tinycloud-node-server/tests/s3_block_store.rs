//! TC-1354: the S3 block store against a real S3 API (the native MinIO of
//! `scripts/at-rest-harness`). Ignored by default; run with the harness
//! environment loaded:
//!
//! ```sh
//! (set -a; . "$RUN_DIR/harness.env"; set +a;
//!  cargo test -p tinycloud-node --test s3_block_store -- --ignored)
//! ```

use anyhow::{ensure, Context, Result};
use futures::io::AsyncWriteExt;
use tinycloud::storage::s3::{S3BlockConfig, S3BlockStore, S3StoreError};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    hash::Hash,
    storage::{
        memory::MemoryStaging, HashBuffer, ImmutableDeleteStore, ImmutableReadStore,
        ImmutableWriteStore, StorageConfig, StorageSetup, StoreSize,
    },
};

fn env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} (load the harness env)"))
}

async fn store() -> Result<(S3BlockStore, SpaceId)> {
    // The S3 client reads credentials from the AWS_* environment.
    std::env::set_var("AWS_ACCESS_KEY_ID", env("TC887_S3_ACCESS_KEY_ID")?);
    std::env::set_var("AWS_SECRET_ACCESS_KEY", env("TC887_S3_SECRET_ACCESS_KEY")?);
    std::env::set_var("AWS_REGION", env("TC887_S3_REGION")?);
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    let config: S3BlockConfig = serde_json::from_value(serde_json::json!({
        "bucket": env("TC887_S3_BUCKET")?,
        "endpoint": env("TC887_S3_ENDPOINT")?,
    }))?;
    let store = config.open().await?;
    let space: SpaceId = format!(
        "tinycloud:key:s3remove:{}",
        hex::encode(rand::random::<[u8; 6]>())
    )
    .parse()?;
    store.create(&space).await?;
    Ok((store, space))
}

fn value(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 13 % 251) as u8).collect()
}

async fn put(store: &S3BlockStore, space: &SpaceId, data: &[u8]) -> Result<Hash, S3StoreError> {
    let mut staged = HashBuffer::new(Vec::new());
    staged.write_all(data).await.unwrap();
    ImmutableWriteStore::<MemoryStaging>::persist(store, space, staged, 0).await
}

#[tokio::test]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn remove_deletes_the_block_and_releases_its_size() -> Result<()> {
    let (store, space) = store().await?;
    let removed = put(&store, &space, &value(5000)).await?;
    let kept = put(&store, &space, &value(17)).await?;
    ensure!(
        store.total_size(&space).await? == Some(5017),
        "size after puts"
    );

    ensure!(
        store.remove(&space, &removed, 0).await? == Some(()),
        "remove of a stored block"
    );
    ensure!(
        !store.contains(&space, &removed, 0).await?,
        "object still exists"
    );
    ensure!(store.contains(&space, &kept, 0).await?, "other block removed");
    ensure!(
        store.total_size(&space).await? == Some(17),
        "size drops by the removed block's length"
    );

    // Removing again, or removing a block never stored, is a no-op.
    ensure!(
        store.remove(&space, &removed, 0).await?.is_none(),
        "second remove"
    );
    let mut unstored = HashBuffer::new(Vec::new());
    unstored.write_all(b"never stored").await?;
    ensure!(
        store.remove(&space, &unstored.hash(), 0).await?.is_none(),
        "absent block"
    );
    ensure!(
        store.total_size(&space).await? == Some(17),
        "no-op removes leave the size"
    );
    Ok(())
}

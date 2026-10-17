//! TC-887 S3c: the S3 block store with encryption at rest, against a real
//! S3 API (the native MinIO of `scripts/at-rest-harness`). Ignored by
//! default; run with the harness environment loaded:
//!
//! ```sh
//! (set -a; . "$RUN_DIR/harness.env"; set +a;
//!  cargo test -p tinycloud-node --test at_rest_s3_store -- --ignored)
//! ```

use std::sync::Arc;

use anyhow::{ensure, Context, Result};
use futures::io::{AsyncReadExt, AsyncWriteExt};
use parking_lot::RwLock;
use tinycloud::{
    config::AtRestMode,
    storage::{
        s3::{S3BlockConfig, S3BlockStore, S3StoreError},
        sealed::{AtRestHandle, AtRestSource, AtRestStoreError, AtRestView},
    },
};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    at_rest::{ciphertext_len, DataKeyProvider, FixedKeyProvider, SEGMENT_LEN},
    hash::Hash,
    storage::{
        memory::MemoryStaging, ByteRangeSpec, HashBuffer, ImmutableDeleteStore, ImmutableReadStore,
        ImmutableWriteStore, RangeRead, StorageConfig, StorageSetup, StoreSize,
    },
};

const SEG: usize = SEGMENT_LEN;

struct Switch(RwLock<AtRestView>);

impl AtRestSource for Switch {
    fn view(&self) -> AtRestView {
        self.0.read().clone()
    }
}

fn view(mode: AtRestMode, encrypting: bool, keys: Option<FixedKeyProvider>) -> AtRestView {
    AtRestView {
        mode,
        encrypting,
        provider: keys.map(|k| Arc::new(k) as Arc<dyn DataKeyProvider>),
    }
}

fn keys() -> FixedKeyProvider {
    FixedKeyProvider::new([31; 32])
}

fn env(name: &str) -> Result<String> {
    std::env::var(name).with_context(|| format!("{name} (load the harness env)"))
}

async fn open_store(v: AtRestView) -> Result<(S3BlockStore, Arc<Switch>)> {
    // The S3 client reads credentials from the AWS_* environment.
    std::env::set_var("AWS_ACCESS_KEY_ID", env("TC887_S3_ACCESS_KEY_ID")?);
    std::env::set_var("AWS_SECRET_ACCESS_KEY", env("TC887_S3_SECRET_ACCESS_KEY")?);
    std::env::set_var("AWS_REGION", env("TC887_S3_REGION")?);
    std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
    let config: S3BlockConfig = serde_json::from_value(serde_json::json!({
        "bucket": env("TC887_S3_BUCKET")?,
        "endpoint": env("TC887_S3_ENDPOINT")?,
    }))?;
    let mut store = config.open().await?;
    let switch = Arc::new(Switch(RwLock::new(v)));
    store.attach_at_rest(AtRestHandle::new(switch.clone()));
    Ok((store, switch))
}

async fn store(v: AtRestView) -> Result<(S3BlockStore, Arc<Switch>, SpaceId)> {
    let (store, switch) = open_store(v).await?;
    let space: SpaceId = format!(
        "tinycloud:key:s3store:{}",
        hex::encode(rand::random::<[u8; 6]>())
    )
    .parse()?;
    store.create(&space).await?;
    Ok((store, switch, space))
}

fn value(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 13 % 251) as u8).collect()
}

async fn put(store: &S3BlockStore, space: &SpaceId, data: &[u8]) -> Result<Hash, S3StoreError> {
    ImmutableWriteStore::<MemoryStaging>::prepare_write(store, space).await?;
    let mut staged = HashBuffer::new(Vec::new());
    staged.write_all(data).await.unwrap();
    ImmutableWriteStore::<MemoryStaging>::persist(store, space, staged).await
}

async fn get(store: &S3BlockStore, space: &SpaceId, h: &Hash) -> Result<Vec<u8>> {
    let content = store.read(space, h).await?.context("block missing")?;
    let len = content.len();
    let mut out = Vec::new();
    Box::pin(content).read_to_end(&mut out).await?;
    ensure!(
        out.len() as u64 == len,
        "Content::len is not the plaintext length"
    );
    Ok(out)
}

async fn raw(store: &S3BlockStore, key: &str) -> Result<Vec<u8>> {
    Ok(store
        .client
        .get_object()
        .bucket(&store.bucket)
        .key(key)
        .send()
        .await?
        .body
        .collect()
        .await?
        .into_bytes()
        .to_vec())
}

#[tokio::test]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn sealed_blocks_round_trip_and_range_over_s3() -> Result<()> {
    let (store, _, space) = store(view(AtRestMode::Encrypt, true, Some(keys()))).await?;
    let nk = keys().object_name_key()?;
    let mut total = 0u64;
    for n in [0, 17, SEG, SEG + 1, 3 * SEG + 9] {
        let data = value(n);
        let h = put(&store, &space, &data).await?;
        total += n as u64;
        // Stored under the sealed name only, as TCE1.
        let sealed = tinycloud_core::at_rest::sealed_object_name(&nk, &space.to_string(), &h);
        let bytes = raw(&store, &sealed).await?;
        ensure!(
            bytes.len() as u64 == ciphertext_len(n as u64)?,
            "{n}: stored size"
        );
        ensure!(bytes.starts_with(b"TCE1"), "{n}: not TCE1");
        ensure!(get(&store, &space, &h).await? == data, "{n}: read back");
        if n > 0 {
            let edges = [0, 1, SEG.saturating_sub(1), SEG, SEG + 1, n - 1];
            for &a in edges.iter().filter(|&&a| a < n) {
                for &b in edges.iter().filter(|&&b| b >= a && b < n) {
                    let spec = ByteRangeSpec::Inclusive {
                        start: a as u64,
                        end: b as u64,
                    };
                    match store.read_range(&space, &h, spec).await?.context("range")? {
                        RangeRead::Content {
                            total_size,
                            range,
                            content,
                        } => {
                            ensure!(total_size == n as u64, "{n}: range total");
                            ensure!((range.start(), range.end()) == (a as u64, b as u64));
                            let mut out = Vec::new();
                            Box::pin(content).read_to_end(&mut out).await?;
                            ensure!(out == data[a..=b], "{n}: range {a}..={b}");
                        }
                        RangeRead::Unsatisfiable { .. } => anyhow::bail!("{n}: {a}..={b} 416"),
                    }
                }
            }
        }
        match store
            .read_range(&space, &h, ByteRangeSpec::From { start: n as u64 })
            .await?
            .context("range")?
        {
            RangeRead::Unsatisfiable { total_size } => {
                ensure!(
                    total_size == n as u64,
                    "{n}: 416 total is the plaintext length"
                )
            }
            RangeRead::Content { .. } => anyhow::bail!("{n}: range past the end was served"),
        }
    }
    ensure!(
        store.total_size(&space).await? == Some(total),
        "plaintext quota"
    );
    // A fresh store over the same bucket counts the sealed objects' plaintext
    // bytes at boot, by space tag, with no legacy objects for the space.
    let (reopened, _) = open_store(view(AtRestMode::Encrypt, true, Some(keys()))).await?;
    ensure!(
        reopened.total_size(&space).await? == Some(total),
        "boot-scan plaintext quota"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn legacy_locked_strict_and_tamper_over_s3() -> Result<()> {
    let (store, switch, space) = store(AtRestView::off()).await?;
    let legacy = value(5000);
    let hl = put(&store, &space, &legacy).await?;

    // encrypt: legacy still readable; a new block is sealed.
    *switch.0.write() = view(AtRestMode::Encrypt, true, Some(keys()));
    ensure!(
        get(&store, &space, &hl).await? == legacy,
        "legacy in encrypt"
    );
    let sealed = value(SEG + 7);
    let hs = put(&store, &space, &sealed).await?;

    // Locked: writes and sealed reads are 503; legacy is served.
    *switch.0.write() = view(AtRestMode::Encrypt, false, Some(keys().locked()));
    let unavailable = |e: &S3StoreError| matches!(e, S3StoreError::AtRest(e) if e.status() == rocket::http::Status::ServiceUnavailable);
    ensure!(
        put(&store, &space, &value(9))
            .await
            .as_ref()
            .is_err_and(unavailable),
        "locked write"
    );
    ensure!(
        store
            .read(&space, &hs)
            .await
            .as_ref()
            .is_err_and(unavailable),
        "locked sealed read"
    );
    ensure!(
        get(&store, &space, &hl).await? == legacy,
        "legacy while locked"
    );

    // strict: legacy refused, sealed served.
    *switch.0.write() = view(AtRestMode::Strict, true, Some(keys()));
    ensure!(
        matches!(
            store.read(&space, &hl).await,
            Err(S3StoreError::AtRest(AtRestStoreError::LegacyRefused))
        ),
        "strict refuses legacy"
    );
    ensure!(
        get(&store, &space, &hs).await? == sealed,
        "strict reads sealed"
    );

    // A tampered sealed object fails closed.
    let nk = keys().object_name_key()?;
    let key = tinycloud_core::at_rest::sealed_object_name(&nk, &space.to_string(), &hs);
    let mut bytes = raw(&store, &key).await?;
    bytes[64 + 3] ^= 1;
    store
        .client
        .put_object()
        .bucket(&store.bucket)
        .key(&key)
        .body(bytes.into())
        .send()
        .await?;
    let content = store.read(&space, &hs).await?.context("block")?;
    let mut out = Vec::new();
    let err = Box::pin(content).read_to_end(&mut out).await.unwrap_err();
    ensure!(
        err.kind() == std::io::ErrorKind::InvalidData && out.is_empty(),
        "tamper"
    );

    // Removing the sealed block drops it.
    ensure!(store.remove(&space, &hs).await? == Some(()), "remove");
    ensure!(store.read(&space, &hs).await?.is_none(), "removed");
    Ok(())
}

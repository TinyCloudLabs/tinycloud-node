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
        file_system::TempFileSystemStage,
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
        ImmutableStaging, ImmutableWriteStore, RangeRead, StorageConfig, StorageSetup, StoreSize,
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

async fn put_file(store: &S3BlockStore, space: &SpaceId, data: &[u8]) -> Result<Hash> {
    ImmutableWriteStore::<TempFileSystemStage>::prepare_write(store, space).await?;
    let mut staged = TempFileSystemStage.stage(space).await?;
    staged.write_all(data).await?;
    staged.flush().await?;
    Ok(ImmutableWriteStore::<TempFileSystemStage>::persist(store, space, staged).await?)
}

async fn range(
    store: &S3BlockStore,
    space: &SpaceId,
    h: &Hash,
    spec: ByteRangeSpec,
) -> Result<(u64, Vec<u8>)> {
    match store.read_range(space, h, spec).await?.context("range")? {
        RangeRead::Content {
            total_size,
            content,
            ..
        } => {
            let mut out = Vec::new();
            Box::pin(content).read_to_end(&mut out).await?;
            Ok((total_size, out))
        }
        RangeRead::Unsatisfiable { .. } => anyhow::bail!("{spec:?} unsatisfiable"),
    }
}

fn status(e: &S3StoreError) -> Option<rocket::http::Status> {
    match e {
        S3StoreError::AtRest(e) => Some(e.status()),
        _ => None,
    }
}

/// Temp-file staging seals on S3 too; ranges across the tail and From /
/// Suffix ranges at segment edges match the plaintext.
#[tokio::test]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn temp_file_staging_seals_and_ranges_over_s3() -> Result<()> {
    let (store, _, space) = store(view(AtRestMode::Encrypt, true, Some(keys()))).await?;
    for n in [3 * SEG, 2 * SEG + 1, 2 * SEG - 1] {
        let data = value(n);
        let h = put_file(&store, &space, &data).await?;
        let nk = keys().object_name_key()?;
        let sealed = tinycloud_core::at_rest::sealed_object_name(&nk, &space.to_string(), &h);
        ensure!(
            raw(&store, &sealed).await?.starts_with(b"TCE1"),
            "{n}: not sealed"
        );
        ensure!(get(&store, &space, &h).await? == data, "{n}: read back");
        for at in [0, 1, SEG - 1, SEG, SEG + 1, 2 * SEG - 1, 2 * SEG, n - 1] {
            if at >= n {
                continue;
            }
            for spec in [
                ByteRangeSpec::From { start: at as u64 },
                ByteRangeSpec::Suffix {
                    length: (n - at) as u64,
                },
            ] {
                let (total, out) = range(&store, &space, &h, spec).await?;
                ensure!(total == n as u64 && out == data[at..], "{n}: {spec:?}");
            }
        }
    }
    Ok(())
}

/// Back to `off` with keys: sealed blocks still read; `off` with locked keys
/// answers 503 for a sealed-only block. `strict` with locked keys answers 503
/// for legacy and sealed blocks alike.
#[tokio::test]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn off_after_encrypt_and_strict_while_locked_over_s3() -> Result<()> {
    let (store, switch, space) = store(AtRestView::off()).await?;
    let hl = put(&store, &space, &value(70)).await?;
    *switch.0.write() = view(AtRestMode::Encrypt, true, Some(keys()));
    let sealed = value(SEG + 2);
    let hs = put(&store, &space, &sealed).await?;

    *switch.0.write() = view(AtRestMode::Off, false, Some(keys()));
    ensure!(
        get(&store, &space, &hs).await? == sealed,
        "off reads sealed"
    );
    *switch.0.write() = view(AtRestMode::Off, false, Some(keys().locked()));
    let e = store.read(&space, &hs).await.map(|_| ()).unwrap_err();
    ensure!(
        status(&e) == Some(rocket::http::Status::ServiceUnavailable),
        "off + locked: {e}"
    );

    *switch.0.write() = view(AtRestMode::Strict, false, Some(keys().locked()));
    for h in [hl, hs] {
        let e = store.read(&space, &h).await.map(|_| ()).unwrap_err();
        ensure!(
            status(&e) == Some(rocket::http::Status::ServiceUnavailable),
            "strict + locked: {e}"
        );
    }
    Ok(())
}

/// `contains` checks the name a write would use (INTERFACES §7).
#[tokio::test]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn contains_checks_the_name_a_write_would_use_over_s3() -> Result<()> {
    let (store, switch, space) = store(AtRestView::off()).await?;
    let data = value(90);
    let h = put(&store, &space, &data).await?;
    ensure!(store.contains(&space, &h).await?, "legacy in off");
    *switch.0.write() = view(AtRestMode::Encrypt, true, Some(keys()));
    ensure!(!store.contains(&space, &h).await?, "legacy only in encrypt");
    put(&store, &space, &data).await?;
    ensure!(store.contains(&space, &h).await?, "sealed in encrypt");
    Ok(())
}

/// A sealed object replaced (same block, another salt) between a range
/// read's header GET and its segment GET: the segment GET is pinned to the
/// header's ETag, so the read starts over or answers 503, and never returns
/// wrong bytes or a false integrity 500.
#[tokio::test]
#[ignore = "needs the at-rest harness MinIO (TC887_S3_* env)"]
async fn a_replaced_object_never_yields_a_false_integrity_error() -> Result<()> {
    let (store, _, space) = store(view(AtRestMode::Encrypt, true, Some(keys()))).await?;
    let data = value(3 * SEG + 5);
    let h = put(&store, &space, &data).await?;
    let nk = keys().object_name_key()?;
    let key = tinycloud_core::at_rest::sealed_object_name(&nk, &space.to_string(), &h);
    let space_str = space.to_string();
    let identity = tinycloud_core::at_rest::BlobIdentity::KvBlock {
        space: &space_str,
        content_hash: &h,
    };
    let dek = keys().current_key(&space_str).await?;
    let versions = [
        raw(&store, &key).await?,
        tinycloud_core::at_rest::seal(&dek, &identity, data.clone())?,
    ];
    ensure!(versions[0] != versions[1], "two encryptions differ by salt");

    let writer = {
        let (client, bucket, key) = (store.client.clone(), store.bucket.clone(), key.clone());
        let versions = versions.clone();
        tokio::spawn(async move {
            for i in 0..200usize {
                client
                    .put_object()
                    .bucket(&bucket)
                    .key(&key)
                    .body(versions[i % 2].clone().into())
                    .send()
                    .await
                    .expect("put");
            }
        })
    };
    let (mut served, mut retried_out) = (0, 0);
    while !writer.is_finished() {
        let spec = ByteRangeSpec::Inclusive {
            start: (SEG - 3) as u64,
            end: (2 * SEG + 3) as u64,
        };
        match store.read_range(&space, &h, spec).await {
            Ok(Some(RangeRead::Content { content, .. })) => {
                let mut out = Vec::new();
                // A body may still abort if the object changes mid-stream
                // after the pinned GET started; it never yields wrong bytes.
                if Box::pin(content).read_to_end(&mut out).await.is_ok() {
                    ensure!(out == data[SEG - 3..=2 * SEG + 3], "wrong bytes served");
                    served += 1;
                }
            }
            Ok(other) => anyhow::bail!("unexpected {:?}", other.is_some()),
            Err(e) => {
                ensure!(
                    status(&e) == Some(rocket::http::Status::ServiceUnavailable),
                    "a replaced object must not be an integrity error: {e}"
                );
                retried_out += 1;
            }
        }
    }
    writer.await?;
    println!("served {served}, gave up after a retry {retried_out}");
    ensure!(served > 0, "no range read completed");
    Ok(())
}

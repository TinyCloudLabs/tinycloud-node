use aws_config::{BehaviorVersion, SdkConfig};
use aws_sdk_s3::config::{
    RequestChecksumCalculation, ResponseChecksumValidation, SharedHttpClient,
};
use aws_sdk_s3::{
    error::{ProvideErrorMetadata, SdkError},
    operation::{get_object::GetObjectError, head_object::HeadObjectError},
    primitives::{ByteStream, ByteStreamError},
    Client, Error as S3Error,
};
use aws_smithy_http_client::tls;
use futures::{
    future::Either as AsyncEither,
    stream::{IntoAsyncRead, Stream, TryStreamExt},
};
use rocket::{async_trait, http::hyper::Uri};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Write as _,
    future::Future,
    io::Error as IoError,
    ops::AddAssign,
    pin::Pin,
    sync::Arc,
    time::Instant,
};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{hash::Hash, storage::*};
use tokio_util::bytes::Bytes;

#[cfg(test)]
use super::TestPause;
use super::{file_system, size::SpaceSizes, BlobGenerationKey, BlobOperationLocks};
use tokio::sync::Mutex;
#[cfg(test)]
use tokio::sync::Notify;

/// Pinned so an SDK bump cannot change client defaults unnoticed.
pub fn behavior_version() -> BehaviorVersion {
    BehaviorVersion::v2026_01_12()
}

/// HTTPS client for the SDK, with rustls on the `ring` provider.
pub fn http_client() -> SharedHttpClient {
    aws_smithy_http_client::Builder::new()
        .tls_provider(tls::Provider::Rustls(
            tls::rustls_provider::CryptoMode::Ring,
        ))
        .build_https()
}

async fn aws_config() -> SdkConfig {
    aws_config::defaults(behavior_version())
        .http_client(http_client())
        .load()
        .await
}

#[derive(Debug, Clone)]
pub struct S3BlockStore {
    pub client: Client,
    pub bucket: String,
    sizes: SpaceSizes,
    // A PUT can succeed on S3 even if its response fails. Reserve its size
    // before sending; this shared map refunds a missing object on known
    // failure without subtracting another writer's committed bytes.
    pending: Arc<Mutex<HashMap<BlobGenerationKey, u64>>>,
    // A DELETE can land on S3 while its response is lost. Keep the pre-DELETE
    // size until absence is confirmed, so retry refunds exactly once. On
    // restart, the initial bucket listing reconstructs only physical bytes.
    deleting: Arc<Mutex<HashMap<BlobGenerationKey, u64>>>,
    operations: BlobOperationLocks,
    #[cfg(test)]
    after_delete_head: TestPause,
    #[cfg(test)]
    after_put_head: TestPause,
}

#[serde_as]
#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct S3BlockConfig {
    pub bucket: String,
    #[serde_as(as = "Option<DisplayFromStr>")]
    #[serde(default)]
    pub endpoint: Option<Uri>,
}

#[async_trait]
impl StorageConfig<S3BlockStore> for S3BlockConfig {
    type Error = S3Error;
    async fn open(&self) -> Result<S3BlockStore, Self::Error> {
        S3BlockStore::new_(self, &[]).await
    }
}

impl S3BlockConfig {
    /// Reconstruct quota and the charge for in-progress DELETEs from one
    /// bucket listing, before the node starts its orphan collector.
    pub async fn open_with_deleting(
        &self,
        deleting: &[(SpaceId, Hash, i64)],
    ) -> Result<S3BlockStore, S3Error> {
        S3BlockStore::new_(self, deleting).await
    }
}

#[async_trait]
impl StorageSetup for S3BlockStore {
    type Error = std::convert::Infallible;
    async fn create(&self, space: &SpaceId) -> Result<(), Self::Error> {
        self.sizes.init_size(space.clone()).await;
        Ok(())
    }
}

async fn new_client(config: &S3BlockConfig) -> Client {
    let general_config = aws_config().await;
    // Checksums only when an operation requires them: the SDK 1.x defaults
    // (CRC32 trailers, aws-chunked uploads, checksum-mode GETs) are rejected
    // by some S3-compatible providers and older MinIO, and the pre-1.0 SDK
    // sent none.
    let sdk_config = aws_sdk_s3::config::Builder::from(&general_config)
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .response_checksum_validation(ResponseChecksumValidation::WhenRequired);
    let sdk_config = match &config.endpoint {
        // A custom endpoint (MinIO etc.) addresses buckets by path, as the
        // pre-1.0 SDK's immutable endpoint did.
        Some(e) => sdk_config
            .endpoint_url(e.to_string())
            .force_path_style(true),
        None => sdk_config,
    };
    let sdk_config = sdk_config.build();
    Client::from_conf(sdk_config)
}

async fn file_body(
    file: file_system::TempFileStage,
) -> Result<(u64, ByteStream, tempfile::TempPath), S3StoreError> {
    let size = file.size().await?;
    let (_file, path) = file.into_inner();
    let body = ByteStream::from_path(&path).await?;
    Ok((size, body, path))
}

impl S3BlockStore {
    async fn new_(
        config: &S3BlockConfig,
        deleting: &[(SpaceId, Hash, i64)],
    ) -> Result<Self, S3Error> {
        let client = new_client(config).await;
        let deleting_keys: HashMap<_, _> = deleting
            .iter()
            .map(|(space, hash, generation)| {
                (
                    Self::key_for(space, hash, *generation),
                    (space.clone(), *hash, *generation),
                )
            })
            .collect();
        let mut pages = client
            .list_objects_v2()
            .bucket(&config.bucket)
            .into_paginator()
            .send();
        // get the sum of all objects per space across all pages, and the
        // physical size of every object a pending DELETE still names
        let mut acc: HashMap<SpaceId, u64> = HashMap::new();
        let mut counted_deletes = HashMap::new();
        while let Some(page) = pages.try_next().await.map_err(S3Error::from)? {
            for content in page.contents() {
                let Some(key) = content.key() else { continue };
                let Some((prefix, _)) = key.rsplit_once('/') else {
                    continue;
                };
                let Ok(space) = prefix.parse::<SpaceId>() else {
                    continue;
                };
                let size = content.size().unwrap_or_default();
                if size > 0 {
                    acc.entry(space).or_insert(0).add_assign(size as u64);
                }
                if let Some((space, hash, generation)) = deleting_keys.get(key) {
                    counted_deletes.insert((space.clone(), *hash, *generation), size.max(0) as u64);
                }
            }
        }
        let sizes = acc.into();
        Ok(S3BlockStore {
            client,
            bucket: config.bucket.clone(),
            sizes,
            pending: Arc::new(Mutex::new(HashMap::new())),
            deleting: Arc::new(Mutex::new(counted_deletes)),
            operations: BlobOperationLocks::default(),
            #[cfg(test)]
            after_delete_head: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_put_head: Arc::new(Mutex::new(None)),
        })
    }

    fn key_for(space: &SpaceId, id: &Hash, generation: i64) -> String {
        let mut key = format!("{space}/");
        // Hash digests fit in 64 bytes; encode on the stack so generated
        // reads allocate only their storage-key String.
        let mut encoded = [0u8; 88];
        let len = base64::encode_config_slice(id.as_ref(), base64::URL_SAFE, &mut encoded);
        key.push_str(std::str::from_utf8(&encoded[..len]).expect("base64 is ASCII"));
        if generation != 0 {
            write!(&mut key, "@{generation}").expect("writing to String cannot fail");
        }
        key
    }

    fn key(&self, space: &SpaceId, id: &Hash, generation: i64) -> String {
        Self::key_for(space, id, generation)
    }

    async fn increment_size(&self, space: &SpaceId, size: u64) {
        self.sizes.increment_size(space, size).await;
    }
    async fn decrement_size(&self, space: &SpaceId, size: u64) {
        self.sizes.decrement_size(space, size).await;
    }

    async fn put_if_absent<F, Fut, G>(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        body: F,
    ) -> Result<(), S3StoreError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(u64, ByteStream, G), S3StoreError>>,
    {
        let key = (space.clone(), hash, generation);
        // Dedup, reservation, PUT and settlement are one physical generation
        // operation. A second KV path cannot charge the same bytes again.
        let _operation = self.operations.lock(key.clone()).await;
        if self.contains(space, &hash, generation).await? {
            // A retry of an ambiguous PUT can find its original object.
            self.pending.lock().await.remove(&key);
            return Ok(());
        }
        #[cfg(test)]
        let pause = self.after_put_head.lock().await.take();
        #[cfg(test)]
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
        let (size, body, guard) = body().await?;
        let mut pending = self.pending.lock().await;
        if let Entry::Vacant(slot) = pending.entry(key.clone()) {
            slot.insert(size);
            self.increment_size(space, size).await;
        }
        drop(pending);
        let upload = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(self.key(space, &hash, generation))
            .body(body)
            .send()
            .await;
        drop(guard);
        upload.map_err(S3Error::from)?;
        self.pending.lock().await.remove(&key);
        Ok(())
    }

    async fn refund_missing_pending(&self, space: &SpaceId, id: &Hash, generation: i64) {
        let key = (space.clone(), *id, generation);
        let mut pending = self.pending.lock().await;
        if let Some(size) = pending.get(&key).copied() {
            self.decrement_size(space, size).await;
            pending.remove(&key);
        }
    }

    async fn refund_confirmed_absence(&self, space: &SpaceId, id: &Hash, generation: i64) {
        let key = (space.clone(), *id, generation);
        let mut deleting = self.deleting.lock().await;
        if let Some(size) = deleting.get(&key).copied() {
            let mut pending = self.pending.lock().await;
            // Hold both reservations until the quota update finishes. Once
            // it runs, both removals are synchronous and cancellation cannot
            // cause a second refund on the next HEAD 404.
            self.decrement_size(space, size).await;
            deleting.remove(&key);
            pending.remove(&key);
        } else {
            drop(deleting);
            self.refund_missing_pending(space, id, generation).await;
        }
    }
}

/// An object body as a `futures` byte stream (`ByteStream` itself only
/// offers `try_next`).
pub type BodyStream = Pin<Box<dyn Stream<Item = Result<Bytes, IoError>> + Send + Sync>>;

pub fn body_stream(body: ByteStream) -> BodyStream {
    Box::pin(futures::stream::try_unfold(body, |mut body| async move {
        match body.try_next().await {
            Ok(Some(chunk)) => Ok(Some((chunk, body))),
            Ok(None) => Ok(None),
            Err(e) => Err(IoError::from(e)),
        }
    }))
}

#[derive(thiserror::Error, Debug)]
pub enum S3StoreError {
    #[error(transparent)]
    S3(Box<S3Error>),
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Bytestream(#[from] ByteStreamError),
    #[error(transparent)]
    Length(#[from] std::num::TryFromIntError),
    #[error("invalid S3 Content-Range response: {0}")]
    InvalidContentRange(String),
}

impl From<S3Error> for S3StoreError {
    fn from(e: S3Error) -> Self {
        Self::S3(Box::new(e))
    }
}

#[async_trait]
impl ImmutableReadStore for S3BlockStore {
    type Error = S3StoreError;
    type Readable = IntoAsyncRead<BodyStream>;
    async fn contains(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<bool, Self::Error> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.key(space, id, generation))
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(SdkError::ServiceError(e)) if matches!(e.err(), HeadObjectError::NotFound(_)) => {
                Ok(false)
            }
            Err(e) => Err(S3Error::from(e).into()),
        }
    }

    async fn read(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        let start = Instant::now();
        let res = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(space, id, generation))
            .send()
            .await;
        let result = match res {
            Ok(o) => Ok(Some(Content::new(
                o.content_length().unwrap_or_default().try_into()?,
                body_stream(o.body).into_async_read(),
            ))),
            Err(SdkError::ServiceError(e)) if matches!(e.err(), GetObjectError::NoSuchKey(_)) => {
                Ok(None)
            }
            Err(e) => Err(S3Error::from(e).into()),
        };
        crate::prometheus::observe_stage(
            crate::prometheus::InvocationStage::BlockRead,
            crate::prometheus::StageOutcome::from(result.is_ok()),
            start.elapsed(),
        );
        result
    }

    async fn read_range(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
        range: ByteRangeSpec,
    ) -> Result<Option<RangeRead<Self::Readable>>, Self::Error> {
        let key = self.key(space, id, generation);
        let output = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(range.to_http_value())
            .send()
            .await;
        match output {
            Ok(output) => {
                let content_range = output.content_range().ok_or_else(|| {
                    S3StoreError::InvalidContentRange("missing header".to_string())
                })?;
                let (range, total_size) = parse_content_range(content_range)?;
                let content = Content::new(range.len(), body_stream(output.body).into_async_read());
                Ok(Some(RangeRead::Content {
                    total_size,
                    range,
                    content,
                }))
            }
            Err(SdkError::ServiceError(e)) if matches!(e.err(), GetObjectError::NoSuchKey(_)) => {
                return Ok(None)
            }
            Err(SdkError::ServiceError(e)) if e.err().code() == Some("InvalidRange") => {
                let head = self
                    .client
                    .head_object()
                    .bucket(&self.bucket)
                    .key(self.key(space, id, generation))
                    .send()
                    .await;
                match head {
                    Ok(output) => Ok(Some(RangeRead::Unsatisfiable {
                        total_size: output.content_length().unwrap_or_default().try_into()?,
                    })),
                    Err(SdkError::ServiceError(e))
                        if matches!(e.err(), HeadObjectError::NotFound(_)) =>
                    {
                        Ok(None)
                    }
                    Err(error) => Err(S3Error::from(error).into()),
                }
            }
            Err(error) => Err(S3Error::from(error).into()),
        }
    }
}

fn parse_content_range(value: &str) -> Result<(ResolvedByteRange, u64), S3StoreError> {
    let value = value
        .strip_prefix("bytes ")
        .ok_or_else(|| S3StoreError::InvalidContentRange(format!("unsupported value {value:?}")))?;
    let (bounds, total_size) = value
        .split_once('/')
        .ok_or_else(|| S3StoreError::InvalidContentRange(format!("missing total in {value:?}")))?;
    let (start, end) = bounds
        .split_once('-')
        .ok_or_else(|| S3StoreError::InvalidContentRange(format!("missing bounds in {value:?}")))?;
    let start = start
        .parse::<u64>()
        .map_err(|_| S3StoreError::InvalidContentRange(format!("invalid start in {value:?}")))?;
    let end = end
        .parse::<u64>()
        .map_err(|_| S3StoreError::InvalidContentRange(format!("invalid end in {value:?}")))?;
    let total_size = total_size
        .parse::<u64>()
        .map_err(|_| S3StoreError::InvalidContentRange(format!("invalid total in {value:?}")))?;
    let range = ByteRangeSpec::Inclusive { start, end }
        .resolve(total_size)
        .filter(|range| range.start() == start && range.end() == end)
        .ok_or_else(|| S3StoreError::InvalidContentRange(format!("invalid range in {value:?}")))?;
    Ok((range, total_size))
}

#[async_trait]
impl ImmutableWriteStore<memory::MemoryStaging> for S3BlockStore {
    type Error = S3StoreError;
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<memory::MemoryStaging as ImmutableStaging>::Writable>,
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let result = async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();

            self.put_if_absent(space, hash, generation, || async move {
                Ok((f.len() as u64, ByteStream::from(f), ()))
            })
            .await?;
            Ok(hash)
        }
        .await;
        crate::prometheus::observe_stage(
            crate::prometheus::InvocationStage::BlockWrite,
            crate::prometheus::StageOutcome::from(result.is_ok()),
            start.elapsed(),
        );
        result
    }
}

#[async_trait]
impl ImmutableWriteStore<file_system::TempFileSystemStage> for S3BlockStore {
    type Error = S3StoreError;
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<file_system::TempFileSystemStage as ImmutableStaging>::Writable>,
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let result = async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();

            self.put_if_absent(space, hash, generation, || file_body(f))
                .await?;
            Ok(hash)
        }
        .await;
        crate::prometheus::observe_stage(
            crate::prometheus::InvocationStage::BlockWrite,
            crate::prometheus::StageOutcome::from(result.is_ok()),
            start.elapsed(),
        );
        result
    }
}

#[async_trait]
impl ImmutableWriteStore<either::Either<file_system::TempFileSystemStage, memory::MemoryStaging>>
    for S3BlockStore
{
    type Error = S3StoreError;
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<either::Either<file_system::TempFileSystemStage, memory::MemoryStaging> as ImmutableStaging>::Writable>,
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let result = async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();

            match f {
                AsyncEither::Left(t_file) => {
                    self.put_if_absent(space, hash, generation, || file_body(t_file))
                        .await?;
                }
                AsyncEither::Right(b) => {
                    self.put_if_absent(space, hash, generation, || async move {
                        Ok((b.len() as u64, ByteStream::from(b), ()))
                    })
                    .await?;
                }
            }
            Ok(hash)
        }
        .await;
        crate::prometheus::observe_stage(
            crate::prometheus::InvocationStage::BlockWrite,
            crate::prometheus::StageOutcome::from(result.is_ok()),
            start.elapsed(),
        );
        result
    }
}

#[async_trait]
impl ImmutableDeleteStore for S3BlockStore {
    type Error = S3StoreError;
    async fn remove(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<()>, Self::Error> {
        // A stale positive HEAD must not recreate a charge after another
        // deleter has already confirmed absence and refunded it.
        let _operation = self.operations.lock((space.clone(), *id, generation)).await;
        let size: u64 = match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.key(space, id, generation))
            .send()
            .await
        {
            Ok(object) => object.content_length().unwrap_or_default().try_into()?,
            Err(SdkError::ServiceError(e)) if matches!(e.err(), HeadObjectError::NotFound(_)) => {
                self.refund_confirmed_absence(space, id, generation).await;
                return Ok(None);
            }
            Err(error) => return Err(S3Error::from(error).into()),
        };
        #[cfg(test)]
        let pause = self.after_delete_head.lock().await.take();
        #[cfg(test)]
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
        self.deleting
            .lock()
            .await
            .entry((space.clone(), *id, generation))
            .or_insert(size);
        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.key(space, id, generation))
            .send()
            .await
        {
            Ok(_) => {
                self.refund_confirmed_absence(space, id, generation).await;
                Ok(Some(()))
            }
            Err(e) => Err(S3Error::from(e).into()),
        }
    }
    async fn cleanup_stages(
        &self,
        _space: &SpaceId,
        _id: &Hash,
        _generation: i64,
    ) -> Result<(), Self::Error> {
        // Staging is not in the bucket; an incomplete S3 PUT has no visible key.
        Ok(())
    }
}

#[async_trait]
impl StoreSize for S3BlockStore {
    type Error = S3StoreError;
    async fn total_size(&self, space: &SpaceId) -> Result<Option<u64>, Self::Error> {
        Ok(self.sizes.get_size(space).await)
    }
    async fn init_size(&self, space: &SpaceId) -> Result<u64, Self::Error> {
        Ok(self.sizes.init_size(space.clone()).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn filesystem_body_keeps_staged_file_until_deferred_read() {
        use futures::io::AsyncWriteExt;

        let data = b"nonempty deferred S3 upload";
        let mut file = file_system::TempFileStage::new(tempfile::NamedTempFile::new().unwrap());
        file.write_all(data).await.unwrap();
        file.flush().await.unwrap();

        let (size, body, guard) = file_body(file).await.unwrap();
        assert_eq!(size, data.len() as u64);
        assert_eq!(body.collect().await.unwrap().into_bytes().as_ref(), data);
        drop(guard);
    }

    #[tokio::test]
    async fn minio_persists_each_staging_arm_and_accepts_restage_retry() {
        use futures::io::AsyncWriteExt;

        let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
            return;
        };
        let bucket = std::env::var("TC735_TEST_MINIO_BUCKET")
            .expect("TC735_TEST_MINIO_BUCKET is required with TC735_TEST_MINIO_ENDPOINT");
        let store = S3BlockConfig {
            bucket: bucket.clone(),
            endpoint: Some(endpoint.parse().unwrap()),
        }
        .open()
        .await
        .unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let space: SpaceId = format!("tinycloud:key:test:tc735-stage-{nonce}")
            .parse()
            .unwrap();
        store.create(&space).await.unwrap();
        let mut hashes = Vec::new();

        for mode in 0..3 {
            let data = format!(
                "TC-735 S3 staged upload {nonce} {} {mode}",
                std::process::id()
            )
            .into_bytes();
            let mut initial_hash = None;
            for _ in 0..2 {
                // A retry re-stages the same bytes; it never rewinds an SDK body.
                let hash = if mode == 0 {
                    let mut stage = file_system::TempFileSystemStage
                        .stage(&space)
                        .await
                        .unwrap();
                    stage.write_all(&data).await.unwrap();
                    ImmutableWriteStore::<file_system::TempFileSystemStage>::persist(
                        &store, &space, stage, 0,
                    )
                    .await
                    .unwrap()
                } else {
                    let staging = if mode == 1 {
                        either::Either::A(file_system::TempFileSystemStage)
                    } else {
                        either::Either::B(memory::MemoryStaging)
                    };
                    let mut stage = staging.stage(&space).await.unwrap();
                    stage.write_all(&data).await.unwrap();
                    ImmutableWriteStore::<
                        either::Either<file_system::TempFileSystemStage, memory::MemoryStaging>,
                    >::persist(&store, &space, stage, 0)
                    .await
                    .unwrap()
                };
                assert_eq!(*initial_hash.get_or_insert(hash), hash);
                if !hashes.contains(&hash) {
                    hashes.push(hash);
                }
                let object = store
                    .client
                    .get_object()
                    .bucket(&bucket)
                    .key(store.key(&space, &hash, 0))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    object.body.collect().await.unwrap().into_bytes().as_ref(),
                    data.as_slice()
                );
            }
        }
        for hash in hashes {
            store.remove(&space, &hash, 0).await.unwrap();
        }
    }

    #[tokio::test]
    async fn minio_same_generation_concurrent_put_charges_once() {
        use futures::io::AsyncWriteExt;
        let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
            return;
        };
        let bucket = std::env::var("TC735_TEST_MINIO_BUCKET")
            .expect("TC735_TEST_MINIO_BUCKET is required with TC735_TEST_MINIO_ENDPOINT");
        let store = S3BlockConfig {
            bucket,
            endpoint: Some(endpoint.parse().unwrap()),
        }
        .open()
        .await
        .unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let space: SpaceId = format!("tinycloud:key:test:tc735-same-charge-{nonce}")
            .parse()
            .unwrap();
        store.create(&space).await.unwrap();
        let data = b"same bytes under two KV paths";
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *store.after_put_head.lock().await = Some((entered.clone(), release.clone()));
        let mut first_stage = memory::MemoryStaging.stage(&space).await.unwrap();
        first_stage.write_all(data).await.unwrap();
        let hash = first_stage.hash();
        let first_store = store.clone();
        let first_space = space.clone();
        let first = tokio::spawn(async move {
            ImmutableWriteStore::<memory::MemoryStaging>::persist(
                &first_store,
                &first_space,
                first_stage,
                0,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), entered.notified())
            .await
            .unwrap();
        let mut second_stage = memory::MemoryStaging.stage(&space).await.unwrap();
        second_stage.write_all(data).await.unwrap();
        let second_store = store.clone();
        let second_space = space.clone();
        let mut second = tokio::spawn(async move {
            ImmutableWriteStore::<memory::MemoryStaging>::persist(
                &second_store,
                &second_space,
                second_stage,
                0,
            )
            .await
        });
        let early_second =
            tokio::time::timeout(std::time::Duration::from_secs(2), &mut second).await;
        release.notify_one();
        assert_eq!(first.await.unwrap().unwrap(), hash);
        let second_hash = match early_second {
            Ok(result) => result.unwrap().unwrap(),
            Err(_) => second.await.unwrap().unwrap(),
        };
        assert_eq!(second_hash, hash);
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(data.len() as u64)
        );
        assert_eq!(
            store.read_to_vec(&space, &hash, 0).await.unwrap(),
            Some(data.to_vec())
        );
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), Some(()));
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
    }

    #[tokio::test]
    async fn minio_stale_head_cannot_recreate_refunded_deletion_charge() {
        use futures::io::AsyncWriteExt;
        let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
            return;
        };
        let bucket = std::env::var("TC735_TEST_MINIO_BUCKET")
            .expect("TC735_TEST_MINIO_BUCKET is required with TC735_TEST_MINIO_ENDPOINT");
        let store = S3BlockConfig {
            bucket,
            endpoint: Some(endpoint.parse().unwrap()),
        }
        .open()
        .await
        .unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let space: SpaceId = format!("tinycloud:key:test:tc735-stale-head-{nonce}")
            .parse()
            .unwrap();
        store.create(&space).await.unwrap();
        let data = b"same generation charge";
        let mut stage = memory::MemoryStaging.stage(&space).await.unwrap();
        stage.write_all(data).await.unwrap();
        let hash = ImmutableWriteStore::<memory::MemoryStaging>::persist(&store, &space, stage, 0)
            .await
            .unwrap();
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(data.len() as u64)
        );

        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *store.after_delete_head.lock().await = Some((entered.clone(), release.clone()));
        let first_store = store.clone();
        let first_space = space.clone();
        let first = tokio::spawn(async move { first_store.remove(&first_space, &hash, 0).await });
        tokio::time::timeout(std::time::Duration::from_secs(3), entered.notified())
            .await
            .unwrap();
        let second_store = store.clone();
        let second_space = space.clone();
        let mut second =
            tokio::spawn(async move { second_store.remove(&second_space, &hash, 0).await });
        // Without per-generation serialization, second DELETE completes
        // while the first retains a stale positive HEAD. With the fix, it
        // waits and then observes the confirmed absence.
        let early_second =
            tokio::time::timeout(std::time::Duration::from_secs(2), &mut second).await;
        release.notify_one();
        let first_result = first.await.unwrap().unwrap();
        let second_result = match early_second {
            Ok(result) => result.unwrap().unwrap(),
            Err(_) => second.await.unwrap().unwrap(),
        };
        assert!(first_result.is_some() || second_result.is_some());
        assert!(!store.contains(&space, &hash, 0).await.unwrap());
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(0),
            "the same generation can refund physical bytes only once"
        );
    }

    #[tokio::test]
    async fn minio_lost_delete_response_refunds_once_and_restart_reconstructs() {
        use futures::io::AsyncWriteExt;

        let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
            return;
        };
        let bucket = std::env::var("TC735_TEST_MINIO_BUCKET")
            .expect("TC735_TEST_MINIO_BUCKET is required with TC735_TEST_MINIO_ENDPOINT");
        let config = S3BlockConfig {
            bucket: bucket.clone(),
            endpoint: Some(endpoint.parse().unwrap()),
        };
        let store = config.open().await.unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let space: SpaceId = format!("tinycloud:key:test:tc735-delete-{nonce}")
            .parse()
            .unwrap();
        store.create(&space).await.unwrap();
        let data = format!("TC-735 ambiguous DELETE {} {nonce}", std::process::id()).into_bytes();
        let mut stage = memory::MemoryStaging.stage(&space).await.unwrap();
        stage.write_all(&data).await.unwrap();
        let hash = ImmutableWriteStore::<memory::MemoryStaging>::persist(&store, &space, stage, 0)
            .await
            .unwrap();
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(data.len() as u64)
        );

        // A replacement process lists the object *before* the old DELETE
        // lands. Its deletion reservation must come from that same listing.
        let counted_boot = config
            .open_with_deleting(&[(space.clone(), hash, 0)])
            .await
            .unwrap();
        let counted_before = counted_boot.total_size(&space).await.unwrap().unwrap();
        assert_eq!(
            counted_boot
                .deleting
                .lock()
                .await
                .get(&(space.clone(), hash, 0)),
            Some(&(data.len() as u64))
        );
        // DELETE lands on S3, but its response is lost. The original process
        // and the boot-counted process each reconcile their own physical count.
        store
            .deleting
            .lock()
            .await
            .insert((space.clone(), hash, 0), data.len() as u64);
        store
            .client
            .delete_object()
            .bucket(&bucket)
            .key(store.key(&space, &hash, 0))
            .send()
            .await
            .unwrap();
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), None);
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), None);
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
        assert_eq!(counted_boot.remove(&space, &hash, 0).await.unwrap(), None);
        assert_eq!(
            counted_boot.total_size(&space).await.unwrap(),
            Some(counted_before - data.len() as u64)
        );
        assert_eq!(counted_boot.remove(&space, &hash, 0).await.unwrap(), None);
        assert_eq!(
            counted_boot.total_size(&space).await.unwrap(),
            Some(counted_before - data.len() as u64)
        );

        // DELETE before startup, or a crash after the first refund but before
        // the DB fence was removed: neither boot listing counted this object.
        let after_boot = config
            .open_with_deleting(&[(space.clone(), hash, 0)])
            .await
            .unwrap();
        let rebuilt = after_boot.total_size(&space).await.unwrap();
        assert!(!after_boot
            .deleting
            .lock()
            .await
            .contains_key(&(space.clone(), hash, 0)));
        assert_eq!(after_boot.remove(&space, &hash, 0).await.unwrap(), None);
        assert_eq!(after_boot.total_size(&space).await.unwrap(), rebuilt);
    }

    #[tokio::test]
    async fn minio_postgres_boot_reconciles_deleting_fence_from_same_listing() {
        use futures::io::AsyncWriteExt;
        use tinycloud_core::{
            db::migrate,
            db_pool::RecoveringConnection,
            kv_orphans::{collect_candidates, deleting_fences, register_candidates},
            sea_orm::{
                ConnectOptions, ConnectionTrait, Database, DbBackend, Statement, TransactionTrait,
            },
        };

        let (Ok(endpoint), Ok(pg_url)) = (
            std::env::var("TC735_TEST_MINIO_ENDPOINT"),
            std::env::var("TINYCLOUD_TEST_POSTGRES_URL"),
        ) else {
            return;
        };
        let bucket = std::env::var("TC735_TEST_MINIO_BUCKET")
            .expect("TC735_TEST_MINIO_BUCKET is required with TC735_TEST_MINIO_ENDPOINT");
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let schema = format!("tc735_s3_boot_{}_{}", std::process::id(), nonce);
        let admin = Database::connect(pg_url.as_str()).await.unwrap();
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("CREATE SCHEMA {schema}"),
            ))
            .await
            .unwrap();
        let mut options = ConnectOptions::new(pg_url);
        options.set_schema_search_path(schema.clone());
        let conn = Database::connect(options).await.unwrap();
        migrate(&RecoveringConnection::new(conn.clone()))
            .await
            .unwrap();

        let config = S3BlockConfig {
            bucket: bucket.clone(),
            endpoint: Some(endpoint.parse().unwrap()),
        };
        let uploader = config.open().await.unwrap();
        let space: SpaceId = format!("tinycloud:key:test:tc735-boot-{nonce}")
            .parse()
            .unwrap();
        uploader.create(&space).await.unwrap();
        for delete_before_boot in [true, false] {
            let data = format!("TC-735 PG boot {nonce} {delete_before_boot}").into_bytes();
            let mut stage = memory::MemoryStaging.stage(&space).await.unwrap();
            stage.write_all(&data).await.unwrap();
            let hash =
                ImmutableWriteStore::<memory::MemoryStaging>::persist(&uploader, &space, stage, 0)
                    .await
                    .unwrap();
            let tx = conn.begin().await.unwrap();
            let registered = register_candidates(&tx, &[(space.clone(), hash)], "aborted")
                .await
                .unwrap();
            assert_eq!(registered, vec![(space.clone(), hash, 0)]);
            tx.execute(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "DELETE FROM kv_orphan_attempt WHERE space = $1 AND value = $2",
                [space.to_string().into(), hash.into()],
            ))
            .await
            .unwrap();
            tx.execute(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "UPDATE kv_orphan_candidate SET deleting_at = CURRENT_TIMESTAMP - INTERVAL '1 second',
                    deletion_bytes = $3 WHERE space = $1 AND value = $2",
                [
                    space.to_string().into(),
                    hash.into(),
                    (data.len() as i64).into(),
                ],
            ))
            .await
            .unwrap();
            tx.commit().await.unwrap();
            let deleting = deleting_fences(&conn).await.unwrap();
            assert_eq!(deleting, vec![(space.clone(), hash, 0)]);
            if delete_before_boot {
                uploader
                    .client
                    .delete_object()
                    .bucket(&bucket)
                    .key(uploader.key(&space, &hash, 0))
                    .send()
                    .await
                    .unwrap();
            }
            let boot = config.open_with_deleting(&deleting).await.unwrap();
            let counted = boot.total_size(&space).await.unwrap().unwrap_or(0);
            assert_eq!(
                boot.deleting
                    .lock()
                    .await
                    .contains_key(&(space.clone(), hash, 0)),
                !delete_before_boot,
            );
            if !delete_before_boot {
                assert_eq!(counted, data.len() as u64);
                uploader
                    .client
                    .delete_object()
                    .bucket(&bucket)
                    .key(uploader.key(&space, &hash, 0))
                    .send()
                    .await
                    .unwrap();
            }
            assert_eq!(
                collect_candidates(&conn, &boot, 10, time::Duration::ZERO)
                    .await
                    .unwrap(),
                0
            );
            assert!(deleting_fences(&conn).await.unwrap().is_empty());
            assert_eq!(
                boot.total_size(&space).await.unwrap().unwrap_or(0),
                if delete_before_boot {
                    counted
                } else {
                    counted - data.len() as u64
                },
            );
        }
        conn.close().await.unwrap();
        admin
            .execute(Statement::from_string(
                DbBackend::Postgres,
                format!("DROP SCHEMA {schema} CASCADE"),
            ))
            .await
            .unwrap();
        admin.close().await.unwrap();
    }

    #[tokio::test]
    async fn minio_generations_survive_old_delete_and_rebuild_quota_together() {
        use futures::io::{AsyncReadExt, AsyncWriteExt};
        let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
            return;
        };
        let bucket = std::env::var("TC735_TEST_MINIO_BUCKET")
            .expect("TC735_TEST_MINIO_BUCKET is required with TC735_TEST_MINIO_ENDPOINT");
        let config = S3BlockConfig {
            bucket,
            endpoint: Some(endpoint.parse().unwrap()),
        };
        let store = config.open().await.unwrap();
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let space: SpaceId = format!("tinycloud:key:test:tc735-generation-{nonce}")
            .parse()
            .unwrap();
        store.create(&space).await.unwrap();
        let mut old = memory::MemoryStaging.stage(&space).await.unwrap();
        old.write_all(b"same bytes").await.unwrap();
        let hash = old.hash();
        let legacy_key = format!(
            "{}/{}",
            space,
            base64::encode_config(hash.as_ref(), base64::URL_SAFE)
        );
        assert_eq!(store.key(&space, &hash, 0), legacy_key);
        ImmutableWriteStore::<memory::MemoryStaging>::persist(&store, &space, old, 0)
            .await
            .unwrap();
        let mut next = memory::MemoryStaging.stage(&space).await.unwrap();
        next.write_all(b"same bytes").await.unwrap();
        ImmutableWriteStore::<memory::MemoryStaging>::persist(&store, &space, next, 1)
            .await
            .unwrap();
        assert_eq!(store.key(&space, &hash, 1), format!("{legacy_key}@1"));
        let boot = config
            .open_with_deleting(&[(space.clone(), hash, 0)])
            .await
            .unwrap();
        assert_eq!(boot.total_size(&space).await.unwrap(), Some(20));
        assert_eq!(
            boot.deleting.lock().await.get(&(space.clone(), hash, 0)),
            Some(&10)
        );
        assert_eq!(
            boot.read_to_vec(&space, &hash, 0).await.unwrap(),
            Some(b"same bytes".to_vec())
        );
        let RangeRead::Content { mut content, .. } = boot
            .read_range(
                &space,
                &hash,
                1,
                ByteRangeSpec::Inclusive { start: 5, end: 9 },
            )
            .await
            .unwrap()
            .unwrap()
        else {
            panic!("expected generation-one range");
        };
        let mut range_bytes = Vec::new();
        content.read_to_end(&mut range_bytes).await.unwrap();
        assert_eq!(range_bytes, b"bytes");
        assert_eq!(boot.remove(&space, &hash, 0).await.unwrap(), Some(()));
        assert_eq!(boot.remove(&space, &hash, 0).await.unwrap(), None);
        assert!(boot.contains(&space, &hash, 1).await.unwrap());
        assert_eq!(
            boot.read_to_vec(&space, &hash, 1).await.unwrap(),
            Some(b"same bytes".to_vec())
        );
        assert_eq!(boot.total_size(&space).await.unwrap(), Some(10));
        boot.remove(&space, &hash, 1).await.unwrap();
        assert_eq!(boot.total_size(&space).await.unwrap(), Some(0));
    }

    #[test]
    fn parses_s3_content_range() {
        let (range, total_size) = parse_content_range("bytes 1048576-2097151/67108864").unwrap();
        assert_eq!(range.start(), 1_048_576);
        assert_eq!(range.end(), 2_097_151);
        assert_eq!(range.len(), 1_048_576);
        assert_eq!(total_size, 67_108_864);
        assert!(parse_content_range("bytes */67108864").is_err());
    }
}

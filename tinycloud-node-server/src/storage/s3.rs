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
use std::{collections::HashMap, io::Error as IoError, ops::AddAssign, pin::Pin, time::Instant};
use tinycloud_auth::resource::{SpaceId, SPACE_ID_PREFIX};
use tinycloud_core::{hash::Hash, storage::*};
use tokio_util::bytes::Bytes;

use super::{file_system, size::SpaceSizes};

/// Prefix of the boot scan's listing: every KV object key starts with it.
pub(crate) const KV_SCAN_PREFIX: &str = SPACE_ID_PREFIX;

/// The key of a KV block: `{space}/{base64url(hash)}`.
pub(crate) fn kv_object_key(space: &SpaceId, id: &Hash) -> String {
    format!(
        "{}/{}",
        space,
        base64::encode_config(id.as_ref(), base64::URL_SAFE)
    )
}

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
        S3BlockStore::new_(self).await
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

pub(crate) async fn new_client(config: &S3BlockConfig) -> Client {
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

impl S3BlockStore {
    async fn new_(config: &S3BlockConfig) -> Result<Self, S3Error> {
        let client = new_client(config).await;
        let mut pages = client
            .list_objects_v2()
            .bucket(&config.bucket)
            // Every KV object key is `{space}/{hash}` and a space id string
            // starts with `SPACE_ID_PREFIX`; only such keys count towards a space.
            .prefix(KV_SCAN_PREFIX)
            .into_paginator()
            .send();
        // get the sum of all objects per space across all pages
        let mut acc: HashMap<SpaceId, u64> = HashMap::new();
        while let Some(page) = pages.try_next().await.map_err(S3Error::from)? {
            for content in page.contents() {
                let Some((space, size)) = content.key().and_then(|key| {
                    let (o, _) = key.rsplit_once('/')?;
                    let space: SpaceId = o.parse().ok()?;
                    match content.size() {
                        Some(size) if size > 0 => Some((space, size as u64)),
                        _ => None,
                    }
                }) else {
                    continue;
                };
                acc.entry(space).or_insert(0).add_assign(size);
            }
        }
        let sizes = acc.into();
        Ok(S3BlockStore {
            client,
            bucket: config.bucket.clone(),
            sizes,
        })
    }

    fn key(&self, space: &SpaceId, id: &Hash) -> String {
        kv_object_key(space, id)
    }

    async fn increment_size(&self, space: &SpaceId, size: u64) {
        self.sizes.increment_size(space, size).await;
    }
    async fn decrement_size(&self, space: &SpaceId, size: u64) {
        self.sizes.decrement_size(space, size).await;
    }

    /// The stored size of an object, or `None` if absent. HeadObject, not
    /// GetObjectAttributes: that call needs an explicit attribute list, and
    /// S3 (and MinIO) reject it without one.
    async fn object_size(&self, key: &str) -> Result<Option<u64>, S3StoreError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(o) => Ok(Some(o.content_length().unwrap_or_default().try_into()?)),
            Err(SdkError::ServiceError(e)) if matches!(e.err(), HeadObjectError::NotFound(_)) => {
                Ok(None)
            }
            Err(e) => Err(S3Error::from(e).into()),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), S3StoreError> {
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
            .map_err(S3Error::from)?;
        Ok(())
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
    async fn contains(&self, space: &SpaceId, id: &Hash) -> Result<bool, Self::Error> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(self.key(space, id))
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
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        let start = Instant::now();
        let res = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(space, id))
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
        range: ByteRangeSpec,
    ) -> Result<Option<RangeRead<Self::Readable>>, Self::Error> {
        let key = self.key(space, id);
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
                    .key(self.key(space, id))
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
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let result = async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();

            if !self.contains(space, &hash).await? {
                let size = f.len() as u64;
                self.client
                    .put_object()
                    .bucket(&self.bucket)
                    .key(self.key(space, &hash))
                    .body(ByteStream::from(f))
                    .send()
                    .await
                    .map_err(S3Error::from)?;
                self.increment_size(space, size).await;
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
impl ImmutableWriteStore<file_system::TempFileSystemStage> for S3BlockStore {
    type Error = S3StoreError;
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<file_system::TempFileSystemStage as ImmutableStaging>::Writable>,
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let result = async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();

            if !self.contains(space, &hash).await? {
                let size = f.size().await?;
                let (_file, path) = f.into_inner();

                self.client
                    .put_object()
                    .bucket(&self.bucket)
                    .key(self.key(space, &hash))
                    .body(ByteStream::from_path(&path).await?)
                    .send()
                    .await
                    .map_err(S3Error::from)?;
                self.increment_size(space, size).await;
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
impl ImmutableWriteStore<either::Either<file_system::TempFileSystemStage, memory::MemoryStaging>>
    for S3BlockStore
{
    type Error = S3StoreError;
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<either::Either<file_system::TempFileSystemStage, memory::MemoryStaging> as ImmutableStaging>::Writable>,
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let result = async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();

            if !self.contains(space, &hash).await? {
                match f {
                    AsyncEither::Left(t_file) => {
                        let size = t_file.size().await?;
                        let (_file, path) = t_file.into_inner();
                        self.client
                            .put_object()
                            .bucket(&self.bucket)
                            .key(self.key(space, &hash))
                            .body(ByteStream::from_path(&path).await?)
                            .send()
                            .await
                            .map_err(S3Error::from)?;
                        self.increment_size(space, size).await;
                    }
                    AsyncEither::Right(b) => {
                        let size = b.len() as u64;
                        self.client
                            .put_object()
                            .bucket(&self.bucket)
                            .key(self.key(space, &hash))
                            .body(ByteStream::from(b))
                            .send()
                            .await
                            .map_err(S3Error::from)?;
                        self.increment_size(space, size).await;
                    }
                }
            };
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
    async fn remove(&self, space: &SpaceId, id: &Hash) -> Result<Option<()>, Self::Error> {
        let key = self.key(space, id);
        let Some(size) = self.object_size(&key).await? else {
            return Ok(None);
        };
        self.delete(&key).await?;
        self.decrement_size(space, size).await;
        Ok(Some(()))
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

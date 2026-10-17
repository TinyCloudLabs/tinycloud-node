use aws_sdk_s3::{
    error::{GetObjectError, GetObjectErrorKind, HeadObjectError, HeadObjectErrorKind},
    types::{ByteStream, SdkError},
    Client, // Config,
    Error as S3Error,
};
use aws_smithy_http::{byte_stream::Error as ByteStreamError, endpoint::Endpoint};
use aws_types::sdk_config::SdkConfig;
use futures::{
    future::Either as AsyncEither,
    io::AsyncReadExt,
    stream::{IntoAsyncRead, MapErr, TryStreamExt},
};
use rocket::{async_trait, http::hyper::Uri};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{
    collections::HashMap, future::Future, io::Error as IoError, ops::AddAssign, time::Instant,
};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    at_rest::{plaintext_len, DataKeyProvider, HEADER_LEN},
    hash::Hash,
    storage::*,
};

use super::{
    file_system,
    sealed::{
        self, contains_name, open_sealed, plan_range, read_plan, scanned_object, seal_file,
        seal_vec, space_tag_of, write_target, AtRestHandle, AtRestStoreError, AtRestView,
        ContainsName, LoggedDecrypt, ReadPlan, ScannedObject, SealFileError, SealedName,
        WriteTarget,
    },
    size::SpaceSizes,
};

async fn aws_config() -> SdkConfig {
    aws_config::from_env().load().await
}

#[derive(Debug, Clone)]
pub struct S3BlockStore {
    pub client: Client,
    pub bucket: String,
    sizes: SpaceSizes,
    at_rest: Option<AtRestHandle>,
}

/// An S3 object body as an `AsyncRead`.
type Body = IntoAsyncRead<MapErr<ByteStream, fn(ByteStreamError) -> IoError>>;

/// Plaintext from a legacy object, or authenticated plaintext from a sealed one.
/// The decrypting side is boxed: it carries the AES key schedule and segment
/// buffers, and `Content` values move by value through deep request paths.
pub type S3Readable = AsyncEither<Body, Box<LoggedDecrypt<Body>>>;

fn body(stream: ByteStream) -> Body {
    stream
        .map_err(convert as fn(ByteStreamError) -> IoError)
        .into_async_read()
}

/// A staged block on its way into the store.
enum Staged {
    File(file_system::TempFileStage),
    Bytes(Vec<u8>),
}

/// The outcome of a ranged GET.
enum RangeGet {
    Missing,
    InvalidRange,
    /// `If-Match` failed: the object was replaced since the ETag was read.
    Changed,
    Got {
        range: ResolvedByteRange,
        total: u64,
        etag: Option<String>,
        body: Body,
    },
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
    let sdk_config = aws_sdk_s3::config::Builder::from(&general_config);
    let sdk_config = match &config.endpoint {
        Some(e) => sdk_config.endpoint_resolver(Endpoint::immutable(e.clone())),
        None => sdk_config,
    };
    let sdk_config = sdk_config.build();
    Client::from_conf(sdk_config)
}

impl S3BlockStore {
    async fn new_(config: &S3BlockConfig) -> Result<Self, S3Error> {
        let client = new_client(config).await;
        let (spaces, sealed, invalid) = client
            .list_objects_v2()
            .bucket(&config.bucket)
            .into_paginator()
            .send()
            // sum stored plaintext bytes per space (legacy names) and per
            // space tag (sealed names) in each page
            .try_fold(
                (
                    HashMap::new(),
                    HashMap::new(),
                    sealed::InvalidLengthLog::default(),
                ),
                |(mut spaces, mut sealed, mut invalid), page| async move {
                    for content in page.contents.into_iter().flatten() {
                        let (Some(key), size) = (content.key(), content.size().max(0) as u64)
                        else {
                            continue;
                        };
                        match scanned_object(key) {
                            ScannedObject::Legacy(space) if size > 0 => {
                                spaces.entry(space).or_insert(0).add_assign(size);
                            }
                            ScannedObject::Sealed(tag) => {
                                let plaintext = plaintext_len(size).unwrap_or_else(|| {
                                    invalid.record(size);
                                    0
                                });
                                sealed
                                    .entry(tag.to_owned())
                                    .or_insert(0)
                                    .add_assign(plaintext);
                            }
                            _ => {}
                        }
                    }
                    Ok((spaces, sealed, invalid))
                },
            )
            .await?;
        invalid.finish();
        let sizes = SpaceSizes::from_scan(spaces, sealed);
        Ok(S3BlockStore {
            client,
            bucket: config.bucket.clone(),
            sizes,
            at_rest: None,
        })
    }

    fn key(&self, space: &SpaceId, id: &Hash) -> String {
        format!(
            "{}/{}",
            space,
            base64::encode_config(id.as_ref(), base64::URL_SAFE)
        )
    }

    /// Links the store to the node's at-rest state (TC-887). Without it the
    /// store behaves as at-rest mode `off`.
    pub fn attach_at_rest(&mut self, handle: AtRestHandle) {
        self.at_rest = Some(handle);
    }

    fn view(&self) -> AtRestView {
        AtRestView::of(self.at_rest.as_ref())
    }

    async fn head_exists(&self, key: &str) -> Result<bool, S3StoreError> {
        Ok(self.object_size(key).await?.is_some())
    }

    /// The whole object: (stored length, body), or `None` if absent.
    async fn get_full(&self, key: &str) -> Result<Option<(u64, Body)>, S3StoreError> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(o) => Ok(Some((o.content_length().try_into()?, body(o.body)))),
            Err(SdkError::ServiceError {
                err:
                    GetObjectError {
                        kind: GetObjectErrorKind::NoSuchKey(_),
                        ..
                    },
                ..
            }) => Ok(None),
            Err(e) => Err(S3Error::from(e).into()),
        }
    }

    async fn get_range(
        &self,
        key: &str,
        range: ByteRangeSpec,
        if_match: Option<&str>,
    ) -> Result<RangeGet, S3StoreError> {
        match self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(key)
            .range(range.to_http_value())
            .set_if_match(if_match.map(str::to_owned))
            .send()
            .await
        {
            Ok(output) => {
                let content_range = output.content_range().ok_or_else(|| {
                    S3StoreError::InvalidContentRange("missing header".to_string())
                })?;
                let (range, total) = parse_content_range(content_range)?;
                Ok(RangeGet::Got {
                    range,
                    total,
                    etag: output.e_tag().map(str::to_owned),
                    body: body(output.body),
                })
            }
            Err(SdkError::ServiceError {
                err:
                    GetObjectError {
                        kind: GetObjectErrorKind::NoSuchKey(_),
                        ..
                    },
                ..
            }) => Ok(RangeGet::Missing),
            Err(SdkError::ServiceError { err, .. }) if err.code() == Some("InvalidRange") => {
                Ok(RangeGet::InvalidRange)
            }
            Err(SdkError::ServiceError { err, .. }) if err.code() == Some("PreconditionFailed") => {
                Ok(RangeGet::Changed)
            }
            Err(error) => Err(S3Error::from(error).into()),
        }
    }

    async fn put(&self, key: &str, body: ByteStream) -> Result<(), S3StoreError> {
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(key)
            .body(body)
            .send()
            .await
            .map_err(S3Error::from)?;
        Ok(())
    }

    async fn persist_staged(
        &self,
        space: &SpaceId,
        hash: &Hash,
        staged: Staged,
    ) -> Result<(), S3StoreError> {
        match write_target(&self.view(), space, hash).await? {
            WriteTarget::Legacy => {
                let key = self.key(space, hash);
                if self.head_exists(&key).await? {
                    return Ok(());
                }
                let size = match staged {
                    Staged::File(t_file) => {
                        let size = t_file.size().await?;
                        let (_file, path) = t_file.into_inner();
                        self.put(&key, ByteStream::from_path(&path).await?).await?;
                        size
                    }
                    Staged::Bytes(b) => {
                        let size = b.len() as u64;
                        self.put(&key, ByteStream::from(b)).await?;
                        size
                    }
                };
                self.sizes.increment_size(space, None, size).await;
            }
            WriteTarget::Sealed { name, key } => {
                // Only the sealed name dedups: a legacy copy never suppresses
                // the sealed write.
                let object = name.key();
                if self.head_exists(&object).await? {
                    return Ok(());
                }
                let size = match staged {
                    Staged::File(t_file) => {
                        let size = t_file.size().await?;
                        let (_file, path) = t_file.into_inner();
                        let sealed = seal_file(&key, space, hash, &path, size).await?;
                        self.put(&object, ByteStream::from_path(sealed.path()).await?)
                            .await?;
                        size
                    }
                    Staged::Bytes(b) => {
                        let size = b.len() as u64;
                        let ct = seal_vec(key, space, hash, b).await?;
                        self.put(&object, ByteStream::from(ct)).await?;
                        size
                    }
                };
                self.sizes
                    .increment_size(space, Some(&name.space_tag), size)
                    .await;
            }
        }
        Ok(())
    }

    async fn read_legacy(
        &self,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Content<S3Readable>>, S3StoreError> {
        Ok(self
            .get_full(&self.key(space, id))
            .await?
            .map(|(len, b)| Content::new(len, AsyncEither::Left(b))))
    }

    async fn read_sealed(
        &self,
        name: &SealedName,
        provider: &dyn DataKeyProvider,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Content<S3Readable>>, S3StoreError> {
        let Some((len, b)) = self.get_full(&name.key()).await? else {
            return Ok(None);
        };
        let (size, reader) = open_sealed(provider, space, id, b, len).await?.into_inner();
        Ok(Some(Content::new(
            size,
            AsyncEither::Right(Box::new(LoggedDecrypt::new(reader))),
        )))
    }

    async fn read_block(
        &self,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Content<S3Readable>>, S3StoreError> {
        match read_plan(&self.view(), space, id)? {
            ReadPlan::Legacy => self.read_legacy(space, id).await,
            ReadPlan::LegacyWhileLocked => match self.read_legacy(space, id).await? {
                Some(c) => Ok(Some(c)),
                None => Err(AtRestStoreError::Unavailable("at-rest keys are locked").into()),
            },
            ReadPlan::SealedThenLegacy { name, provider } => {
                match self.read_sealed(&name, &*provider, space, id).await? {
                    Some(c) => Ok(Some(c)),
                    None => self.read_legacy(space, id).await,
                }
            }
            ReadPlan::Sealed { name, provider } => {
                match self.read_sealed(&name, &*provider, space, id).await? {
                    Some(c) => Ok(Some(c)),
                    None if self.head_exists(&self.key(space, id)).await? => {
                        Err(AtRestStoreError::LegacyRefused.into())
                    }
                    None => Ok(None),
                }
            }
        }
    }

    async fn range_legacy(
        &self,
        space: &SpaceId,
        id: &Hash,
        spec: ByteRangeSpec,
    ) -> Result<Option<RangeRead<S3Readable>>, S3StoreError> {
        let key = self.key(space, id);
        match self.get_range(&key, spec, None).await? {
            RangeGet::Got {
                range, total, body, ..
            } => Ok(Some(RangeRead::Content {
                total_size: total,
                range,
                content: Content::new(range.len(), AsyncEither::Left(body)),
            })),
            RangeGet::Missing | RangeGet::Changed => Ok(None),
            RangeGet::InvalidRange => {
                let head = self
                    .client
                    .head_object()
                    .bucket(&self.bucket)
                    .key(&key)
                    .send()
                    .await;
                match head {
                    Ok(output) => Ok(Some(RangeRead::Unsatisfiable {
                        total_size: output.content_length().try_into()?,
                    })),
                    Err(SdkError::ServiceError {
                        err:
                            HeadObjectError {
                                kind: HeadObjectErrorKind::NotFound(_),
                                ..
                            },
                        ..
                    }) => Ok(None),
                    Err(error) => Err(S3Error::from(error).into()),
                }
            }
        }
    }

    /// A range of the block's sealed object, or `None` if it is absent: one
    /// GET for the header, one (pinned to the first one's ETag) for the
    /// segments. Totals and the 416 decision use the plaintext length. If the
    /// object is replaced or removed between the two, the read starts over
    /// once, then fails (503); once a header was read it never falls back to
    /// the legacy name.
    async fn range_sealed(
        &self,
        name: &SealedName,
        provider: &dyn DataKeyProvider,
        space: &SpaceId,
        id: &Hash,
        spec: ByteRangeSpec,
    ) -> Result<Option<RangeRead<S3Readable>>, S3StoreError> {
        let object = name.key();
        let header_span = ByteRangeSpec::Inclusive {
            start: 0,
            end: HEADER_LEN as u64 - 1,
        };
        let mut seen_header = false;
        for _ in 0..2 {
            let (total, etag, mut head_body) =
                match self.get_range(&object, header_span, None).await? {
                    RangeGet::Missing | RangeGet::Changed if seen_header => break,
                    RangeGet::Missing | RangeGet::Changed => return Ok(None),
                    RangeGet::InvalidRange => {
                        return Err(
                            AtRestStoreError::Integrity("object shorter than its header").into(),
                        )
                    }
                    RangeGet::Got {
                        total, etag, body, ..
                    } => (total, etag, body),
                };
            seen_header = true;
            let mut header = [0u8; HEADER_LEN];
            head_body
                .read_exact(&mut header)
                .await
                .map_err(|_| AtRestStoreError::Integrity("object shorter than its header"))?;
            let plan = plan_range(provider, space, &header, total, spec).await?;
            let Some(r) = plan.range else {
                return Ok(Some(RangeRead::Unsatisfiable {
                    total_size: plan.plaintext_len(),
                }));
            };
            let span = ByteRangeSpec::Inclusive {
                start: r.ciphertext_start(),
                end: r.ciphertext_end(),
            };
            let body = match self.get_range(&object, span, etag.as_deref()).await? {
                RangeGet::Got { range, body, .. }
                    if range.start() == r.ciphertext_start()
                        && range.end() == r.ciphertext_end() =>
                {
                    body
                }
                RangeGet::Got { .. } => {
                    return Err(
                        AtRestStoreError::Integrity("ranged GET returned another span").into(),
                    )
                }
                // Replaced, removed or shrunk since the header was read.
                RangeGet::Changed | RangeGet::Missing | RangeGet::InvalidRange => continue,
            };
            let reader = plan.reader(space, id, r, body)?;
            let range = r.plaintext_range();
            return Ok(Some(RangeRead::Content {
                total_size: plan.plaintext_len(),
                range,
                content: Content::new(
                    range.len(),
                    AsyncEither::Right(Box::new(LoggedDecrypt::new(reader))),
                ),
            }));
        }
        Err(AtRestStoreError::Unavailable("the object changed during the read").into())
    }

    async fn range_block(
        &self,
        space: &SpaceId,
        id: &Hash,
        spec: ByteRangeSpec,
    ) -> Result<Option<RangeRead<S3Readable>>, S3StoreError> {
        match read_plan(&self.view(), space, id)? {
            ReadPlan::Legacy => self.range_legacy(space, id, spec).await,
            ReadPlan::LegacyWhileLocked => match self.range_legacy(space, id, spec).await? {
                Some(r) => Ok(Some(r)),
                None => Err(AtRestStoreError::Unavailable("at-rest keys are locked").into()),
            },
            ReadPlan::SealedThenLegacy { name, provider } => {
                match self
                    .range_sealed(&name, &*provider, space, id, spec)
                    .await?
                {
                    Some(r) => Ok(Some(r)),
                    None => self.range_legacy(space, id, spec).await,
                }
            }
            ReadPlan::Sealed { name, provider } => {
                match self
                    .range_sealed(&name, &*provider, space, id, spec)
                    .await?
                {
                    Some(r) => Ok(Some(r)),
                    None if self.head_exists(&self.key(space, id)).await? => {
                        Err(AtRestStoreError::LegacyRefused.into())
                    }
                    None => Ok(None),
                }
            }
        }
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
            Ok(o) => Ok(Some(o.content_length().try_into()?)),
            Err(SdkError::ServiceError {
                err:
                    HeadObjectError {
                        kind: HeadObjectErrorKind::NotFound(_),
                        ..
                    },
                ..
            }) => Ok(None),
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

pub fn convert(e: ByteStreamError) -> IoError {
    e.into()
}

#[derive(thiserror::Error, Debug)]
pub enum S3StoreError {
    #[error(transparent)]
    S3(#[from] S3Error),
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Bytestream(#[from] ByteStreamError),
    #[error(transparent)]
    Length(#[from] std::num::TryFromIntError),
    #[error("invalid S3 Content-Range response: {0}")]
    InvalidContentRange(String),
    #[error(transparent)]
    AtRest(#[from] sealed::AtRestStoreError),
}

impl From<SealFileError> for S3StoreError {
    fn from(e: SealFileError) -> Self {
        match e {
            SealFileError::AtRest(e) => Self::AtRest(e),
            SealFileError::Io(e) => Self::Io(e),
        }
    }
}

#[async_trait]
impl ImmutableReadStore for S3BlockStore {
    type Error = S3StoreError;
    type Readable = S3Readable;
    async fn contains(&self, space: &SpaceId, id: &Hash) -> Result<bool, Self::Error> {
        // The name a write would use (INTERFACES §7).
        match contains_name(&self.view(), space, id)? {
            ContainsName::Legacy => self.head_exists(&self.key(space, id)).await,
            ContainsName::Sealed(name) => self.head_exists(&name.key()).await,
        }
    }
    fn prepares(&self) -> bool {
        super::sealed::prepares(&self.view())
    }
    async fn prepare_read(&self, space: &SpaceId) -> Result<(), Self::Error> {
        Ok(super::sealed::prepare_read(&self.view(), space).await?)
    }

    async fn read(
        &self,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        let start = Instant::now();
        // Boxed: the sealed read path's future is large, and the trait method
        // future is built on the caller's stack before async_trait boxes it.
        let result = Box::pin(self.read_block(space, id)).await;
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
        Box::pin(self.range_block(space, id, range)).await
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

/// Times a block write, as before.
async fn observed_write<F>(write: F) -> Result<Hash, S3StoreError>
where
    F: Future<Output = Result<Hash, S3StoreError>>,
{
    let start = Instant::now();
    let result = write.await;
    crate::prometheus::observe_stage(
        crate::prometheus::InvocationStage::BlockWrite,
        crate::prometheus::StageOutcome::from(result.is_ok()),
        start.elapsed(),
    );
    result
}

#[async_trait]
impl ImmutableWriteStore<memory::MemoryStaging> for S3BlockStore {
    type Error = S3StoreError;
    async fn prepare_write(&self, space: &SpaceId) -> Result<(), Self::Error> {
        Ok(sealed::prepare_write(&self.view(), space).await?)
    }
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<memory::MemoryStaging as ImmutableStaging>::Writable>,
    ) -> Result<Hash, Self::Error> {
        observed_write(async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();
            Box::pin(self.persist_staged(space, &hash, Staged::Bytes(f))).await?;
            Ok(hash)
        })
        .await
    }
}

#[async_trait]
impl ImmutableWriteStore<file_system::TempFileSystemStage> for S3BlockStore {
    type Error = S3StoreError;
    async fn prepare_write(&self, space: &SpaceId) -> Result<(), Self::Error> {
        Ok(sealed::prepare_write(&self.view(), space).await?)
    }
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<file_system::TempFileSystemStage as ImmutableStaging>::Writable>,
    ) -> Result<Hash, Self::Error> {
        observed_write(async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();
            Box::pin(self.persist_staged(space, &hash, Staged::File(f))).await?;
            Ok(hash)
        })
        .await
    }
}

#[async_trait]
impl ImmutableWriteStore<either::Either<file_system::TempFileSystemStage, memory::MemoryStaging>>
    for S3BlockStore
{
    type Error = S3StoreError;
    async fn prepare_write(&self, space: &SpaceId) -> Result<(), Self::Error> {
        Ok(sealed::prepare_write(&self.view(), space).await?)
    }
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<either::Either<file_system::TempFileSystemStage, memory::MemoryStaging> as ImmutableStaging>::Writable>,
    ) -> Result<Hash, Self::Error> {
        observed_write(async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();
            let staged = match f {
                AsyncEither::Left(t_file) => Staged::File(t_file),
                AsyncEither::Right(b) => Staged::Bytes(b),
            };
            Box::pin(self.persist_staged(space, &hash, staged)).await?;
            Ok(hash)
        })
        .await
    }
}

#[async_trait]
impl ImmutableDeleteStore for S3BlockStore {
    type Error = S3StoreError;
    async fn remove(&self, space: &SpaceId, id: &Hash) -> Result<Option<()>, Self::Error> {
        // A sealed copy first (if keys can name it), then the legacy object.
        if let Some(nk) = self.view().object_name_key() {
            let name = SealedName::new(&nk, space, id);
            if let Some(size) = self.object_size(&name.key()).await? {
                self.delete(&name.key()).await?;
                self.sizes
                    .decrement_size(
                        space,
                        Some(&name.space_tag),
                        plaintext_len(size).unwrap_or(0),
                    )
                    .await;
                return Ok(Some(()));
            }
        }
        let key = self.key(space, id);
        let Some(size) = self.object_size(&key).await? else {
            return Ok(None);
        };
        self.delete(&key).await?;
        self.sizes.decrement_size(space, None, size).await;
        Ok(Some(()))
    }
}

#[async_trait]
impl StoreSize for S3BlockStore {
    type Error = S3StoreError;
    async fn total_size(&self, space: &SpaceId) -> Result<Option<u64>, Self::Error> {
        let view = self.view();
        Ok(self
            .sizes
            .get_size(space, space_tag_of(&view, space).as_deref())
            .await)
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

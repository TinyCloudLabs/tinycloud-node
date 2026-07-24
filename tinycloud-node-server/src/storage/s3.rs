use aws_sdk_s3::{
    error::{
        GetObjectAttributesError, GetObjectAttributesErrorKind, GetObjectError, GetObjectErrorKind,
        HeadObjectError, HeadObjectErrorKind,
    },
    types::{ByteStream, SdkError},
    Client, // Config,
    Error as S3Error,
};
use aws_smithy_http::{byte_stream::Error as ByteStreamError, endpoint::Endpoint};
use aws_types::sdk_config::SdkConfig;
use futures::{
    future::Either as AsyncEither,
    stream::{IntoAsyncRead, MapErr, TryStreamExt},
};
use rocket::{async_trait, http::hyper::Uri};
use serde::{Deserialize, Serialize};
use serde_with::{serde_as, DisplayFromStr};
use std::{collections::HashMap, io::Error as IoError, ops::AddAssign};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{hash::Hash, storage::*};

use super::{file_system, size::SpaceSizes};

async fn aws_config() -> SdkConfig {
    aws_config::from_env().load().await
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

async fn new_client(config: &S3BlockConfig) -> Client {
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
        let sizes = client
            .list_objects_v2()
            .bucket(&config.bucket)
            .into_paginator()
            .send()
            // get the sum of all objects in each page
            .try_fold(HashMap::new(), |mut acc, page| async move {
                // get the sum of all objects per space in this particular page
                for (space, obj_size) in page.contents.into_iter().flatten().filter_map(|content| {
                    content.key().and_then(|key| {
                        let (o, _) = key.rsplit_once('/')?;
                        let space: SpaceId = o.parse().ok()?;
                        if content.size() > 0 {
                            Some((space, content.size() as u64))
                        } else {
                            None
                        }
                    })
                }) {
                    acc.entry(space).or_insert(0).add_assign(obj_size);
                }
                Ok(acc)
            })
            .await?
            .into();
        Ok(S3BlockStore {
            client,
            bucket: config.bucket.clone(),
            sizes,
        })
    }

    fn key(&self, space: &SpaceId, id: &Hash) -> String {
        format!(
            "{}/{}",
            space,
            base64::encode_config(id.as_ref(), base64::URL_SAFE)
        )
    }

    async fn increment_size(&self, space: &SpaceId, size: u64) {
        self.sizes.increment_size(space, size).await;
    }
    async fn decrement_size(&self, space: &SpaceId, size: u64) {
        self.sizes.decrement_size(space, size).await;
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
}

#[async_trait]
impl ImmutableReadStore for S3BlockStore {
    type Error = S3StoreError;
    type Readable = IntoAsyncRead<MapErr<ByteStream, fn(ByteStreamError) -> IoError>>;
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
            Err(SdkError::ServiceError {
                err:
                    HeadObjectError {
                        kind: HeadObjectErrorKind::NotFound(_),
                        ..
                    },
                ..
            }) => Ok(false),
            Err(e) => Err(S3Error::from(e).into()),
        }
    }

    async fn read(
        &self,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        let res = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(self.key(space, id))
            .send()
            .await;
        match res {
            Ok(o) => Ok(Some(Content::new(
                o.content_length().try_into()?,
                o.body
                    .map_err(convert as fn(ByteStreamError) -> IoError)
                    .into_async_read(),
            ))),
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
                let content = Content::new(
                    range.len(),
                    output
                        .body
                        .map_err(convert as fn(ByteStreamError) -> IoError)
                        .into_async_read(),
                );
                Ok(Some(RangeRead::Content {
                    total_size,
                    range,
                    content,
                }))
            }
            Err(SdkError::ServiceError {
                err:
                    GetObjectError {
                        kind: GetObjectErrorKind::NoSuchKey(_),
                        ..
                    },
                ..
            }) => return Ok(None),
            Err(SdkError::ServiceError { err, .. }) if err.code() == Some("InvalidRange") => {
                let head = self
                    .client
                    .head_object()
                    .bucket(&self.bucket)
                    .key(self.key(space, id))
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
}

#[async_trait]
impl ImmutableWriteStore<file_system::TempFileSystemStage> for S3BlockStore {
    type Error = S3StoreError;
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<file_system::TempFileSystemStage as ImmutableStaging>::Writable>,
    ) -> Result<Hash, Self::Error> {
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
}

#[async_trait]
impl ImmutableDeleteStore for S3BlockStore {
    type Error = S3StoreError;
    async fn remove(&self, space: &SpaceId, id: &Hash) -> Result<Option<()>, Self::Error> {
        let size: u64 = match self
            .client
            .get_object_attributes()
            .bucket(&self.bucket)
            .key(self.key(space, id))
            .send()
            .await
        {
            Ok(o) if !o.delete_marker() => o.object_size().try_into()?,
            Ok(_) => return Ok(None),
            Err(SdkError::ServiceError {
                err:
                    GetObjectAttributesError {
                        kind: GetObjectAttributesErrorKind::NoSuchKey(_),
                        ..
                    },
                ..
            }) => return Ok(None),
            Err(e) => return Err(S3Error::from(e).into()),
        };
        match self
            .client
            .delete_object()
            .bucket(&self.bucket)
            .key(self.key(space, id))
            .send()
            .await
        {
            Ok(_) => {
                self.decrement_size(space, size).await;
                Ok(Some(()))
            }
            // TODO does this distinguish between object missing and object present?
            Err(e) => Err(S3Error::from(e).into()),
        }
    }
}

#[async_trait]
impl StoreSize for S3BlockStore {
    type Error = S3StoreError;
    async fn total_size(&self, space: &SpaceId) -> Result<Option<u64>, Self::Error> {
        Ok(self.sizes.get_size(space).await)
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

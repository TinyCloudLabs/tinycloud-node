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
    io::AsyncReadExt,
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
use tinycloud_auth::resource::{SpaceId, SPACE_ID_PREFIX};
use tinycloud_core::{
    at_rest::{
        plaintext_len, AtRestView, DataKey, DataKeyProvider, HEADER_LEN, SEALED_NAME_PREFIX,
    },
    hash::Hash,
    storage::*,
};
use tokio_util::bytes::Bytes;

#[cfg(test)]
use super::TestPause;
use super::{
    file_system,
    sealed::{
        self, contains_name, open_sealed, plan_range, read_plan, removal_name, seal_file, seal_vec,
        space_tag_of, write_target, AtRestHandle, AtRestStoreError, ContainsName, LoggedDecrypt,
        ReadPlan, SealFileError, SealedName, WriteTarget,
    },
    size::SpaceSizes,
    BlobGenerationKey, BlobOperationLocks,
};
use tokio::sync::Mutex;
#[cfg(test)]
use tokio::sync::Notify;

/// Prefix of the boot scan's listing: every KV object key starts with it.
pub(crate) const KV_SCAN_PREFIX: &str = SPACE_ID_PREFIX;

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
    // The same for sealed copies (TC-887). Kept apart: a boot listing can't
    // name sealed objects (keys arrive after storage opens), so `deleting`
    // holds only legacy charges, and a block may have both copies.
    deleting_sealed: Arc<Mutex<HashMap<BlobGenerationKey, u64>>>,
    operations: BlobOperationLocks,
    // The node's at-rest state (TC-887); without it the store is mode `off`.
    at_rest: Option<AtRestHandle>,
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
        let tag = space_tag_of(&self.view(), space);
        self.sizes.init_size(space.clone(), tag.as_deref()).await;
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
            // Every KV object key is `{space}/{hash}` and a space id string
            // starts with `SPACE_ID_PREFIX`; only such keys count towards a space.
            .prefix(KV_SCAN_PREFIX)
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
        let sealed = sealed_sizes(&client, &config.bucket).await?;
        let sizes = SpaceSizes::from_scan(acc, sealed);
        Ok(S3BlockStore {
            client,
            bucket: config.bucket.clone(),
            sizes,
            pending: Arc::new(Mutex::new(HashMap::new())),
            deleting: Arc::new(Mutex::new(counted_deletes)),
            deleting_sealed: Arc::new(Mutex::new(HashMap::new())),
            operations: BlobOperationLocks::default(),
            at_rest: None,
            #[cfg(test)]
            after_delete_head: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_put_head: Arc::new(Mutex::new(None)),
        })
    }

    pub(crate) fn key_for(space: &SpaceId, id: &Hash, generation: i64) -> String {
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

    /// Links the store to the node's at-rest state (TC-887). Without it the
    /// store behaves as at-rest mode `off`.
    pub fn attach_at_rest(&mut self, handle: AtRestHandle) {
        self.at_rest = Some(handle);
    }

    fn view(&self) -> AtRestView {
        AtRestHandle::view_of(self.at_rest.as_ref())
    }

    /// `tag`: the space tag of sealed bytes (TC-887), `None` for legacy ones.
    async fn increment_size(&self, space: &SpaceId, tag: Option<&str>, size: u64) {
        self.sizes.increment_size(space, tag, size).await;
    }
    async fn decrement_size(&self, space: &SpaceId, tag: Option<&str>, size: u64) {
        self.sizes.decrement_size(space, tag, size).await;
    }

    /// The stored size of an object, or `None` if absent (HeadObject).
    async fn head_size(&self, key: &str) -> Result<Option<u64>, S3StoreError> {
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(key)
            .send()
            .await
        {
            Ok(object) => Ok(Some(
                object.content_length().unwrap_or_default().try_into()?,
            )),
            Err(SdkError::ServiceError(e)) if matches!(e.err(), HeadObjectError::NotFound(_)) => {
                Ok(None)
            }
            Err(e) => Err(S3Error::from(e).into()),
        }
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
            Ok(o) => Ok(Some((
                o.content_length().unwrap_or_default().try_into()?,
                body_stream(o.body).into_async_read(),
            ))),
            Err(SdkError::ServiceError(e)) if matches!(e.err(), GetObjectError::NoSuchKey(_)) => {
                Ok(None)
            }
            Err(e) => Err(S3Error::from(e).into()),
        }
    }

    /// A ranged GET, optionally pinned to an ETag (`If-Match`).
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
                    body: body_stream(output.body).into_async_read(),
                })
            }
            Err(SdkError::ServiceError(e)) if matches!(e.err(), GetObjectError::NoSuchKey(_)) => {
                Ok(RangeGet::Missing)
            }
            Err(SdkError::ServiceError(e)) if e.err().code() == Some("InvalidRange") => {
                Ok(RangeGet::InvalidRange)
            }
            Err(SdkError::ServiceError(e))
                if e.err().code() == Some("PreconditionFailed")
                    || e.raw().status().as_u16() == 412 =>
            {
                Ok(RangeGet::Changed)
            }
            Err(error) => Err(S3Error::from(error).into()),
        }
    }

    /// Uploads a staged block under the name the at-rest state picks: the
    /// legacy name in mode `off`, else the sealed name (TC-887). Only that
    /// name dedups: a legacy copy never suppresses a sealed write. The quota
    /// charge is the plaintext size either way.
    async fn persist_staged(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        staged: Staged,
    ) -> Result<(), S3StoreError> {
        match write_target(&self.view(), space, &hash, generation).await? {
            WriteTarget::Legacy => {
                let object = self.key(space, &hash, generation);
                match staged {
                    Staged::File(file) => {
                        self.put_if_absent(space, hash, generation, &object, None, || {
                            file_body(file)
                        })
                        .await
                    }
                    Staged::Bytes(bytes) => {
                        self.put_if_absent(space, hash, generation, &object, None, || async move {
                            Ok((bytes.len() as u64, ByteStream::from(bytes), ()))
                        })
                        .await
                    }
                }
            }
            WriteTarget::Sealed { name, key } => {
                let (object, tag) = (name.key(), Some(name.space_tag.as_str()));
                match staged {
                    Staged::File(file) => {
                        self.put_if_absent(space, hash, generation, &object, tag, || {
                            sealed_file_body(key, space, hash, file)
                        })
                        .await
                    }
                    Staged::Bytes(bytes) => {
                        self.put_if_absent(space, hash, generation, &object, tag, || async move {
                            let size = bytes.len() as u64;
                            let sealed = seal_vec(key, space, &hash, bytes).await?;
                            Ok((size, ByteStream::from(sealed), ()))
                        })
                        .await
                    }
                }
            }
        }
    }

    async fn put_if_absent<F, Fut, G>(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        object: &str,
        tag: Option<&str>,
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
        if self.head_size(object).await?.is_some() {
            // A retry of an ambiguous PUT can find the object it uploaded.
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
            self.increment_size(space, tag, size).await;
        }
        drop(pending);
        let upload = self
            .client
            .put_object()
            .bucket(&self.bucket)
            .key(object)
            .body(body)
            .send()
            .await;
        drop(guard);
        upload.map_err(S3Error::from)?;
        self.pending.lock().await.remove(&key);
        Ok(())
    }

    async fn refund_missing_pending(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
        tag: Option<&str>,
    ) {
        let key = (space.clone(), *id, generation);
        let mut pending = self.pending.lock().await;
        if let Some(size) = pending.get(&key).copied() {
            self.decrement_size(space, tag, size).await;
            pending.remove(&key);
        }
    }

    /// Settles the deletion charge `deleting` holds for this generation, if
    /// any, together with its upload reservation. Returns whether there was
    /// one.
    async fn refund_confirmed_absence(
        &self,
        deleting: &Mutex<HashMap<BlobGenerationKey, u64>>,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
        tag: Option<&str>,
    ) -> bool {
        let key = (space.clone(), *id, generation);
        let mut deleting = deleting.lock().await;
        let Some(size) = deleting.get(&key).copied() else {
            return false;
        };
        let mut pending = self.pending.lock().await;
        // Hold both reservations until the quota update finishes. Once it
        // runs, both removals are synchronous and cancellation cannot cause a
        // second refund on the next HEAD 404.
        self.decrement_size(space, tag, size).await;
        deleting.remove(&key);
        pending.remove(&key);
        true
    }

    /// Deletes one stored copy of a generation (`object`), charged `tag`'s
    /// bytes. Returns (deleted now, its charge was settled). Callers hold
    /// the generation's operation lock.
    #[allow(clippy::too_many_arguments)]
    async fn remove_object(
        &self,
        deleting: &Mutex<HashMap<BlobGenerationKey, u64>>,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
        object: &str,
        tag: Option<&str>,
        sealed: bool,
    ) -> Result<(bool, bool), S3StoreError> {
        let size = match self.head_size(object).await? {
            // A sealed object is charged its plaintext bytes, as counted.
            Some(stored) if sealed => plaintext_len(stored).unwrap_or(0),
            Some(stored) => stored,
            None => {
                let settled = self
                    .refund_confirmed_absence(deleting, space, id, generation, tag)
                    .await;
                return Ok((false, settled));
            }
        };
        #[cfg(test)]
        let pause = self.after_delete_head.lock().await.take();
        #[cfg(test)]
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
        deleting
            .lock()
            .await
            .entry((space.clone(), *id, generation))
            .or_insert(size);
        self.client
            .delete_object()
            .bucket(&self.bucket)
            .key(object)
            .send()
            .await
            .map_err(S3Error::from)?;
        self.refund_confirmed_absence(deleting, space, id, generation, tag)
            .await;
        Ok((true, true))
    }

    async fn read_legacy(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<Content<S3Readable>>, S3StoreError> {
        Ok(self
            .get_full(&self.key(space, id, generation))
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
        let (size, reader) = open_sealed(provider, space, id, b, len)
            .await
            .inspect_err(|e| e.log_at(name))?
            .into_inner();
        Ok(Some(Content::new(
            size,
            AsyncEither::Right(Box::new(LoggedDecrypt::new(reader, name))),
        )))
    }

    async fn read_block(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<Content<S3Readable>>, S3StoreError> {
        match read_plan(&self.view(), space, id, generation)? {
            ReadPlan::Legacy => self.read_legacy(space, id, generation).await,
            ReadPlan::LegacyWhileLocked => match self.read_legacy(space, id, generation).await? {
                Some(c) => Ok(Some(c)),
                None => Err(AtRestStoreError::Unavailable("at-rest keys are locked").into()),
            },
            ReadPlan::SealedThenLegacy { name, provider } => {
                match self.read_sealed(&name, &*provider, space, id).await? {
                    Some(c) => Ok(Some(c)),
                    None => self.read_legacy(space, id, generation).await,
                }
            }
            ReadPlan::Sealed { name, provider } => {
                match self.read_sealed(&name, &*provider, space, id).await? {
                    Some(c) => Ok(Some(c)),
                    None if self
                        .head_size(&self.key(space, id, generation))
                        .await?
                        .is_some() =>
                    {
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
        generation: i64,
        spec: ByteRangeSpec,
    ) -> Result<Option<RangeRead<S3Readable>>, S3StoreError> {
        let key = self.key(space, id, generation);
        match self.get_range(&key, spec, None).await? {
            RangeGet::Got {
                range, total, body, ..
            } => Ok(Some(RangeRead::Content {
                total_size: total,
                range,
                content: Content::new(range.len(), AsyncEither::Left(body)),
            })),
            RangeGet::Missing | RangeGet::Changed => Ok(None),
            RangeGet::InvalidRange => Ok(self
                .head_size(&key)
                .await?
                .map(|total_size| RangeRead::Unsatisfiable { total_size })),
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
        let logged = |e: AtRestStoreError| {
            e.log_at(name);
            e
        };
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
                        return Err(logged(AtRestStoreError::Integrity(
                            "object shorter than its header",
                        ))
                        .into())
                    }
                    RangeGet::Got {
                        total, etag, body, ..
                    } => (total, etag, body),
                };
            seen_header = true;
            let mut header = [0u8; HEADER_LEN];
            head_body.read_exact(&mut header).await.map_err(|_| {
                logged(AtRestStoreError::Integrity(
                    "object shorter than its header",
                ))
            })?;
            let plan = plan_range(provider, space, &header, total, spec)
                .await
                .map_err(logged)?;
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
                    return Err(logged(AtRestStoreError::Integrity(
                        "ranged GET returned another span",
                    ))
                    .into())
                }
                // Replaced, removed or shrunk since the header was read.
                RangeGet::Changed | RangeGet::Missing | RangeGet::InvalidRange => continue,
            };
            let reader = plan.reader(space, id, r, body).map_err(logged)?;
            let range = r.plaintext_range();
            return Ok(Some(RangeRead::Content {
                total_size: plan.plaintext_len(),
                range,
                content: Content::new(
                    range.len(),
                    AsyncEither::Right(Box::new(LoggedDecrypt::new(reader, name))),
                ),
            }));
        }
        Err(AtRestStoreError::Unavailable("the object changed during the read").into())
    }

    async fn range_block(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
        spec: ByteRangeSpec,
    ) -> Result<Option<RangeRead<S3Readable>>, S3StoreError> {
        match read_plan(&self.view(), space, id, generation)? {
            ReadPlan::Legacy => self.range_legacy(space, id, generation, spec).await,
            ReadPlan::LegacyWhileLocked => {
                match self.range_legacy(space, id, generation, spec).await? {
                    Some(r) => Ok(Some(r)),
                    None => Err(AtRestStoreError::Unavailable("at-rest keys are locked").into()),
                }
            }
            ReadPlan::SealedThenLegacy { name, provider } => {
                match self
                    .range_sealed(&name, &*provider, space, id, spec)
                    .await?
                {
                    Some(r) => Ok(Some(r)),
                    None => self.range_legacy(space, id, generation, spec).await,
                }
            }
            ReadPlan::Sealed { name, provider } => {
                match self
                    .range_sealed(&name, &*provider, space, id, spec)
                    .await?
                {
                    Some(r) => Ok(Some(r)),
                    None if self
                        .head_size(&self.key(space, id, generation))
                        .await?
                        .is_some() =>
                    {
                        Err(AtRestStoreError::LegacyRefused.into())
                    }
                    None => Ok(None),
                }
            }
        }
    }
}

/// An S3 object body as an `AsyncRead`.
type Body = IntoAsyncRead<BodyStream>;

/// Plaintext from a legacy object, or authenticated plaintext from a sealed one.
/// The decrypting side is boxed: it carries the AES key schedule and segment
/// buffers, and `Content` values move by value through deep request paths.
pub type S3Readable = AsyncEither<Body, Box<LoggedDecrypt<Body>>>;

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

/// Seals a staged plaintext file into a temporary file and returns its
/// plaintext size and upload body. The plaintext stage is removed once
/// sealed; the sealed file lives until the returned guard drops.
async fn sealed_file_body(
    key: DataKey,
    space: &SpaceId,
    hash: Hash,
    file: file_system::TempFileStage,
) -> Result<(u64, ByteStream, tempfile::TempPath), S3StoreError> {
    let size = file.size().await?;
    let (_file, src) = file.into_inner();
    let out = tempfile::NamedTempFile::new()?;
    seal_file(&key, space, &hash, &src, size, out.reopen()?).await?;
    drop(src);
    let path = out.into_temp_path();
    let body = ByteStream::from_path(&path).await?;
    Ok((size, body, path))
}

/// Plaintext bytes per space tag of the sealed objects (`v1/{space_tag}/…`,
/// TC-887), from a second listing restricted to that prefix: the KV listing
/// above only sees legacy names.
async fn sealed_sizes(client: &Client, bucket: &str) -> Result<HashMap<String, u64>, S3Error> {
    let mut pages = client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(SEALED_NAME_PREFIX)
        .into_paginator()
        .send();
    let mut sealed: HashMap<String, u64> = HashMap::new();
    let mut invalid = sealed::InvalidLengthLog::default();
    while let Some(page) = pages.try_next().await.map_err(S3Error::from)? {
        for content in page.contents() {
            let Some(tag) = content.key().and_then(sealed::sealed_tag) else {
                continue;
            };
            let size = content.size().unwrap_or_default().max(0) as u64;
            let plaintext = plaintext_len(size).unwrap_or_else(|| {
                invalid.record(size);
                0
            });
            let total = sealed.entry(tag.to_owned()).or_insert(0);
            *total = total.saturating_add(plaintext);
        }
    }
    invalid.finish();
    Ok(sealed)
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
    #[error(transparent)]
    AtRest(#[from] sealed::AtRestStoreError),
}

impl From<S3Error> for S3StoreError {
    fn from(e: S3Error) -> Self {
        Self::S3(Box::new(e))
    }
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
    /// Whether the block exists under the name a write would use (INTERFACES
    /// §7): in `encrypt`/`strict` only the sealed name counts.
    async fn contains(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<bool, Self::Error> {
        let object = match contains_name(&self.view(), space, id, generation)? {
            ContainsName::Legacy => self.key(space, id, generation),
            ContainsName::Sealed(name) => name.key(),
        };
        Ok(self.head_size(&object).await?.is_some())
    }
    fn prepares(&self) -> bool {
        sealed::prepares(&self.view())
    }
    async fn prepare_read(&self, space: &SpaceId) -> Result<(), Self::Error> {
        Ok(sealed::prepare_read(&self.view(), space).await?)
    }

    async fn read(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        let start = Instant::now();
        // Boxed: the sealed read path's future is large, and the trait method
        // future is built on the caller's stack before async_trait boxes it.
        let result = Box::pin(self.read_block(space, id, generation)).await;
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
        Box::pin(self.range_block(space, id, generation, range)).await
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
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        observed_write(async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();
            Box::pin(self.persist_staged(space, hash, generation, Staged::Bytes(f))).await?;
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
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        observed_write(async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();
            Box::pin(self.persist_staged(space, hash, generation, Staged::File(f))).await?;
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
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        observed_write(async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();
            let staged = match f {
                AsyncEither::Left(file) => Staged::File(file),
                AsyncEither::Right(bytes) => Staged::Bytes(bytes),
            };
            Box::pin(self.persist_staged(space, hash, generation, staged)).await?;
            Ok(hash)
        })
        .await
    }
}

#[async_trait]
impl ImmutableDeleteStore for S3BlockStore {
    type Error = S3StoreError;
    /// Deletes both copies of the generation: the sealed name whenever keys
    /// are set up, then the legacy name. With keys set up but locked nothing
    /// is deleted (503) and the collector retries later.
    async fn remove(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<()>, Self::Error> {
        let sealed = removal_name(&self.view(), space, id, generation)?;
        let tag = sealed.as_ref().map(|name| name.space_tag.as_str());
        // A stale positive HEAD must not recreate a charge after another
        // deleter has already confirmed absence and refunded it.
        let _operation = self.operations.lock((space.clone(), *id, generation)).await;
        let (mut removed, mut settled) = (false, false);
        if let Some(name) = &sealed {
            let (r, s) = self
                .remove_object(
                    &self.deleting_sealed,
                    space,
                    id,
                    generation,
                    &name.key(),
                    tag,
                    true,
                )
                .await?;
            (removed, settled) = (r, s);
        }
        let legacy = self.key(space, id, generation);
        let (r, s) = self
            .remove_object(&self.deleting, space, id, generation, &legacy, None, false)
            .await?;
        (removed, settled) = (removed || r, settled || s);
        if !settled {
            // Neither copy exists, nor did a deletion charge: an upload whose
            // PUT never landed still holds its reservation.
            self.refund_missing_pending(space, id, generation, tag)
                .await;
        }
        Ok(removed.then_some(()))
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
        let tag = space_tag_of(&self.view(), space);
        Ok(self.sizes.get_size(space, tag.as_deref()).await)
    }
    async fn init_size(&self, space: &SpaceId) -> Result<u64, Self::Error> {
        let tag = space_tag_of(&self.view(), space);
        Ok(self.sizes.init_size(space.clone(), tag.as_deref()).await)
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
        // Without per-generation serialization, the second DELETE completes
        // while the first retains a stale positive HEAD. With it, the second
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

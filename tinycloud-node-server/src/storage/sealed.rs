//! Encryption at rest for KV blocks (TC-887 S3): the decisions and the
//! envelope plumbing shared by the S3 and FileSystem block stores.
//!
//! Rules (agreed with the key-continuity work; `docs/at-rest/INTERFACES.md`):
//! - mode `off` writes plaintext under the legacy name, exactly as before;
//!   any other mode seals iff [`AtRestView::encrypting`], else 503, never a
//!   plaintext fallback;
//! - reads try the sealed name whenever keys exist, then the legacy name,
//!   unless `strict` (legacy refused); a sealed read under locked keys is a
//!   503; integrity and unsupported-format failures are hard errors, never
//!   treated as legacy.
//!
//! Legacy vs sealed is decided by name (`{space}/…` vs `v1/{space_tag}/…`),
//! never by the stored bytes.

use crate::at_rest::AtRestRuntime;
use crate::config::AtRestMode;
use futures::io::{AsyncRead, AsyncReadExt};
use std::{path::Path, sync::Arc};
use tinycloud_auth::resource::SpaceId;
use tinycloud_core::{
    at_rest::{
        space_tag, BlobIdentity, DataKey, DataKeyError, DataKeyProvider, DecryptReader,
        EncryptReader, EnvelopeError, Header, ObjectNameKey, SegmentRange, HEADER_LEN,
    },
    hash::Hash,
    storage::{ByteRangeSpec, Content},
};
use tokio_util::compat::{TokioAsyncReadCompatExt, TokioAsyncWriteCompatExt};

/// Why a KV block operation failed for at-rest reasons.
#[derive(Debug, thiserror::Error)]
pub enum AtRestStoreError {
    /// Keys are locked, not set up, or the encrypt gate is closed. Retryable
    /// once an operator acts: answer 503.
    #[error("encrypted storage is unavailable: {0}")]
    Unavailable(&'static str),
    /// The key store could not be read (database or mirror). Answer 503.
    #[error("at-rest key store failed: {0}")]
    KeyStore(String),
    /// The sealed object failed authentication or does not match its header.
    #[error("stored object failed integrity checks: {0}")]
    Integrity(&'static str),
    /// A well-formed header of a later format generation. Unauthenticated, so
    /// it is a hard error like an integrity failure.
    #[error("unsupported at-rest format version {0}")]
    Unsupported(u8),
    /// `strict` mode refuses legacy plaintext objects.
    #[error("legacy plaintext object refused in strict mode")]
    LegacyRefused,
}

impl AtRestStoreError {
    /// The HTTP status a request failing with this error should get.
    pub fn status(&self) -> rocket::http::Status {
        use rocket::http::Status;
        match self {
            Self::Unavailable(_) | Self::KeyStore(_) => Status::ServiceUnavailable,
            Self::Integrity(_) | Self::Unsupported(_) | Self::LegacyRefused => {
                Status::InternalServerError
            }
        }
    }
}

/// The at-rest cause of a node block-store error, if it has one.
pub fn block_store_at_rest_error(
    e: &tinycloud_core::storage::either::EitherError<
        super::s3::S3StoreError,
        super::file_system::FileSystemStoreError,
    >,
) -> Option<&AtRestStoreError> {
    use tinycloud_core::storage::either::EitherError;
    match e {
        EitherError::A(super::s3::S3StoreError::AtRest(e))
        | EitherError::B(super::file_system::FileSystemStoreError::AtRest(e)) => Some(e),
        _ => None,
    }
}

impl From<DataKeyError> for AtRestStoreError {
    fn from(e: DataKeyError) -> Self {
        match e {
            DataKeyError::Locked => Self::Unavailable("at-rest keys are locked"),
            DataKeyError::UnknownKey { .. } => Self::Integrity("header names an unknown data key"),
            other => Self::KeyStore(other.to_string()),
        }
    }
}

impl From<EnvelopeError> for AtRestStoreError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::Unsupported { version } => Self::Unsupported(version),
            EnvelopeError::Header(_) => Self::Integrity("invalid header"),
            EnvelopeError::KeyMismatch => Self::Integrity("header names another data key"),
            EnvelopeError::TooLarge => Self::Integrity("object too large"),
            EnvelopeError::LengthMismatch => Self::Integrity("length mismatch"),
            _ => Self::Integrity("authentication failed"),
        }
    }
}

/// A snapshot of the node's at-rest state for one storage operation.
#[derive(Clone)]
pub struct AtRestView {
    pub mode: AtRestMode,
    pub encrypting: bool,
    pub provider: Option<Arc<dyn DataKeyProvider>>,
}

impl AtRestView {
    /// The state a store without at-rest wiring behaves as: `off`, no keys.
    pub fn off() -> Self {
        Self {
            mode: AtRestMode::Off,
            encrypting: false,
            provider: None,
        }
    }

    pub fn of(runtime: Option<&AtRestRuntime>) -> Self {
        match runtime {
            None => Self::off(),
            Some(rt) => Self {
                mode: rt.mode(),
                encrypting: rt.encrypting(),
                provider: rt.provider(),
            },
        }
    }

    /// The object-name key, if keys are set up and unlocked.
    pub fn object_name_key(&self) -> Option<ObjectNameKey> {
        self.provider.as_ref()?.object_name_key().ok()
    }
}

/// The sealed name of a block: backends lay it out as `v1/{space_tag}/{object_tag}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedName {
    pub space_tag: String,
    pub object_tag: String,
}

impl SealedName {
    pub fn new(nk: &ObjectNameKey, space: &SpaceId, hash: &Hash) -> Self {
        let full = tinycloud_core::at_rest::sealed_object_name(nk, &space.to_string(), hash);
        let mut parts = full.splitn(3, '/').skip(1);
        let (space_tag, object_tag) = (parts.next(), parts.next());
        Self {
            space_tag: space_tag.expect("v1/{tag}/{obj}").to_owned(),
            object_tag: object_tag.expect("v1/{tag}/{obj}").to_owned(),
        }
    }

    /// The S3 object key / FS relative path.
    pub fn key(&self) -> String {
        format!(
            "{}{}/{}",
            tinycloud_core::at_rest::SEALED_NAME_PREFIX,
            self.space_tag,
            self.object_tag
        )
    }
}

/// The pseudonymous size-accounting tag of a space, if keys are unlocked.
pub fn space_tag_of(view: &AtRestView, space: &SpaceId) -> Option<String> {
    view.object_name_key()
        .map(|nk| space_tag(&nk, &space.to_string()))
}

/// Where a new block is written.
pub enum WriteTarget {
    Legacy,
    Sealed { name: SealedName, key: DataKey },
}

/// What a stored S3 object name is, for the boot size scan.
#[derive(Debug, PartialEq, Eq)]
pub enum ScannedObject<'a> {
    /// `{space}/{b64url digest}`.
    Legacy(SpaceId),
    /// `v1/{space_tag}/{object_tag}`: counted under its tag.
    Sealed(&'a str),
    /// Anything else, including the key mirror under `_tc/`.
    Other,
}

/// The key mirror's prefix in the block bucket (`_tc/at-rest/...`).
pub const RESERVED_PREFIX: &str = "_tc/";

pub fn scanned_object(key: &str) -> ScannedObject<'_> {
    if key.starts_with(RESERVED_PREFIX) {
        return ScannedObject::Other;
    }
    if let Some(rest) = key.strip_prefix(tinycloud_core::at_rest::SEALED_NAME_PREFIX) {
        return match rest.split_once('/') {
            Some((tag, obj)) if !tag.is_empty() && !obj.is_empty() && !obj.contains('/') => {
                ScannedObject::Sealed(tag)
            }
            _ => ScannedObject::Other,
        };
    }
    match key.rsplit_once('/').and_then(|(o, _)| o.parse().ok()) {
        Some(space) => ScannedObject::Legacy(space),
        None => ScannedObject::Other,
    }
}

pub async fn write_target(
    view: &AtRestView,
    space: &SpaceId,
    hash: &Hash,
) -> Result<WriteTarget, AtRestStoreError> {
    if view.mode == AtRestMode::Off {
        return Ok(WriteTarget::Legacy);
    }
    if !view.encrypting {
        return Err(AtRestStoreError::Unavailable("encryption is not enabled"));
    }
    let provider = view
        .provider
        .as_ref()
        .ok_or(AtRestStoreError::Unavailable("at-rest keys are not set up"))?;
    let nk = provider.object_name_key()?;
    let key = provider.current_key(&space.to_string()).await?;
    Ok(WriteTarget::Sealed {
        name: SealedName::new(&nk, space, hash),
        key,
    })
}

/// Which names a read tries, in order.
pub enum ReadPlan {
    /// No keys: the legacy name only.
    Legacy,
    /// Keys locked: the legacy name only, and a miss there is a 503 (a sealed
    /// copy may exist but cannot be named or opened).
    LegacyWhileLocked,
    /// The sealed name, then the legacy name.
    SealedThenLegacy {
        name: SealedName,
        provider: Arc<dyn DataKeyProvider>,
    },
    /// `strict`: the sealed name only.
    Sealed {
        name: SealedName,
        provider: Arc<dyn DataKeyProvider>,
    },
}

pub fn read_plan(
    view: &AtRestView,
    space: &SpaceId,
    hash: &Hash,
) -> Result<ReadPlan, AtRestStoreError> {
    let strict = view.mode == AtRestMode::Strict;
    let Some(provider) = view.provider.clone() else {
        return if strict {
            Err(AtRestStoreError::Unavailable("at-rest keys are not set up"))
        } else {
            Ok(ReadPlan::Legacy)
        };
    };
    match provider.object_name_key() {
        Ok(nk) => {
            let name = SealedName::new(&nk, space, hash);
            Ok(if strict {
                ReadPlan::Sealed { name, provider }
            } else {
                ReadPlan::SealedThenLegacy { name, provider }
            })
        }
        Err(DataKeyError::Locked) if !strict => Ok(ReadPlan::LegacyWhileLocked),
        Err(e) => Err(e.into()),
    }
}

fn identity<'a>(space: &'a str, hash: &'a Hash) -> BlobIdentity<'a> {
    BlobIdentity::KvBlock {
        space,
        content_hash: hash,
    }
}

/// Reads and parses the header at the start of a sealed object.
pub async fn read_header<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Header, AtRestStoreError> {
    let mut b = [0u8; HEADER_LEN];
    reader
        .read_exact(&mut b)
        .await
        .map_err(|_| AtRestStoreError::Integrity("object shorter than its header"))?;
    Ok(Header::parse(&b)?)
}

/// The header's declared size must match the stored object's size. Still a
/// hint (the header is authenticated only when a segment decrypts), but it
/// rejects truncated or padded objects before any byte is served.
fn check_object_len(header: &Header, object_len: u64) -> Result<(), AtRestStoreError> {
    if header.ciphertext_len() == object_len {
        Ok(())
    } else {
        Err(AtRestStoreError::Integrity(
            "object size does not match its header",
        ))
    }
}

/// Opens a whole sealed object. `reader` yields the object from byte 0 and
/// `object_len` is the stored size. The returned content reports the
/// plaintext length and yields only authenticated bytes; a corrupt object
/// fails part way with an `InvalidData` I/O error, which the HTTP layer turns
/// into an aborted body.
pub async fn open_sealed<R: AsyncRead + Unpin>(
    provider: &dyn DataKeyProvider,
    space: &SpaceId,
    hash: &Hash,
    mut reader: R,
    object_len: u64,
) -> Result<Content<DecryptReader<R>>, AtRestStoreError> {
    let header = read_header(&mut reader).await?;
    check_object_len(&header, object_len)?;
    let space = space.to_string();
    let key = provider.key(&space, header.dek_id()).await?;
    let plaintext_len = header.plaintext_len();
    let decrypt = DecryptReader::new(&key, &identity(&space, hash), &header, reader)?;
    Ok(Content::new(plaintext_len, decrypt))
}

/// A sealed range read, planned from the object's header.
pub struct SealedRange {
    header: Header,
    key: DataKey,
    /// `None`: unsatisfiable against the plaintext length.
    pub range: Option<SegmentRange>,
}

impl SealedRange {
    pub fn plaintext_len(&self) -> u64 {
        self.header.plaintext_len()
    }

    /// Wraps the fetched ciphertext span (`range.ciphertext_start()..=end`).
    pub fn reader<R: AsyncRead + Unpin>(
        &self,
        space: &SpaceId,
        hash: &Hash,
        range: SegmentRange,
        inner: R,
    ) -> Result<DecryptReader<R>, AtRestStoreError> {
        let space = space.to_string();
        Ok(DecryptReader::range(
            &self.key,
            &identity(&space, hash),
            &self.header,
            range,
            inner,
        )?)
    }
}

/// Plans a range read from the object's first [`HEADER_LEN`] bytes.
pub async fn plan_range(
    provider: &dyn DataKeyProvider,
    space: &SpaceId,
    header_bytes: &[u8],
    object_len: u64,
    spec: ByteRangeSpec,
) -> Result<SealedRange, AtRestStoreError> {
    let header = Header::parse(header_bytes)?;
    check_object_len(&header, object_len)?;
    let key = provider.key(&space.to_string(), header.dek_id()).await?;
    let range = header.map_range(spec);
    Ok(SealedRange { header, key, range })
}

/// Seals an in-memory block, off the async executor.
pub async fn seal_vec(
    key: DataKey,
    space: &SpaceId,
    hash: &Hash,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, AtRestStoreError> {
    let space = space.to_string();
    let hash = *hash;
    tokio::task::spawn_blocking(move || {
        tinycloud_core::at_rest::seal(&key, &identity(&space, &hash), plaintext)
    })
    .await
    .map_err(|_| AtRestStoreError::Integrity("sealing task failed"))?
    .map_err(Into::into)
}

/// Seals the staged plaintext file `src` (`plaintext_len` bytes) into a new
/// temporary file in the same directory, streaming one segment at a time.
pub async fn seal_file(
    key: &DataKey,
    space: &SpaceId,
    hash: &Hash,
    src: &Path,
    plaintext_len: u64,
) -> Result<tempfile::NamedTempFile, SealFileError> {
    let dir = src.parent().unwrap_or_else(|| Path::new("."));
    let out = tempfile::NamedTempFile::new_in(dir)?;
    let space = space.to_string();
    let input = tokio::fs::File::open(src).await?.compat();
    let mut reader = EncryptReader::new(key, &identity(&space, hash), plaintext_len, input)
        .map_err(AtRestStoreError::from)?;
    let mut writer = tokio::fs::File::from_std(out.reopen()?).compat_write();
    futures::io::copy(&mut reader, &mut writer).await?;
    futures::io::AsyncWriteExt::close(&mut writer).await?;
    Ok(out)
}

#[derive(Debug, thiserror::Error)]
pub enum SealFileError {
    #[error(transparent)]
    AtRest(#[from] AtRestStoreError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Rate-limits the boot-scan warning for sealed objects whose size is not a
/// valid TCE1 length: the first few are logged, the rest only counted.
#[derive(Default)]
pub struct InvalidLengthLog {
    seen: u64,
}

impl InvalidLengthLog {
    const LOGGED: u64 = 5;

    pub fn record(&mut self, object_len: u64) {
        self.seen += 1;
        if self.seen <= Self::LOGGED {
            tracing::warn!(
                object_len,
                "sealed object size is not a valid TCE1 length; counted as 0 bytes"
            );
        }
    }

    pub fn finish(self) {
        if self.seen > Self::LOGGED {
            tracing::warn!(
                total = self.seen,
                "sealed objects with invalid TCE1 lengths (only the first were logged)"
            );
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
use super::TestPause;
use super::{
    sealed::{
        contains_name, open_sealed, plan_range, read_plan, removal_name, seal_file, seal_vec,
        space_tag_of, write_target, AtRestHandle, AtRestStoreError, ContainsName, LoggedDecrypt,
        ReadPlan, SealFileError, SealedName, WriteTarget,
    },
    size::SpaceSizes,
    BlobGenerationKey, BlobOperationLocks,
};
use core::pin::Pin;
use futures::{
    future::Either as AsyncEither,
    io::{AsyncWrite, AsyncWriteExt},
    stream::TryStreamExt,
    task::{Context, Poll},
};
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::{
    collections::{hash_map::Entry, HashMap},
    fmt::Write as _,
    io::{Error as IoError, ErrorKind, SeekFrom},
    path::{Path, PathBuf},
    sync::Arc,
    time::Instant,
};
use tempfile::{NamedTempFile, PathPersistError};
use tinycloud_auth::{resource::SpaceId, ssi::dids::DIDBuf};
use tinycloud_core::{
    at_rest::{plaintext_len, AtRestView, DataKey, DataKeyProvider, HEADER_LEN},
    hash::Hash,
    storage::*,
};
#[cfg(test)]
use tokio::sync::Notify;
use tokio::{
    fs::{create_dir_all, metadata, remove_file, File},
    io::{AsyncReadExt, AsyncSeekExt},
    sync::Mutex,
};
use tokio_stream::wrappers::ReadDirStream;

use tokio_util::compat::{Compat, TokioAsyncReadCompatExt};

#[derive(Debug, Clone)]
pub struct FileSystemStore {
    path: PathBuf,
    sizes: SpaceSizes,
    // Reserve the full size before writing a temporary file. A cancellation
    // or failed publish leaves a conservative charge until cleanup confirms
    // that neither the stage nor the final object remains.
    pending: Arc<Mutex<HashMap<BlobGenerationKey, u64>>>,
    // Paths and charges from the same boot listing as `sizes`. A later upload
    // reservation for the same hash is a separate charge, not a replacement.
    boot_stages: Arc<Mutex<HashMap<PathBuf, u64>>>,
    operations: BlobOperationLocks,
    // The node's at-rest state (TC-887); without it the store is mode `off`.
    at_rest: Option<AtRestHandle>,
    #[cfg(test)]
    before_memory_write: TestPause,
    #[cfg(test)]
    before_pending_refund: TestPause,
    #[cfg(test)]
    before_reserve_charge: TestPause,
    #[cfg(test)]
    after_memory_contains: TestPause,
    #[cfg(test)]
    fail_stage_cleanup: Arc<AtomicBool>,
    #[cfg(test)]
    after_stage_unlink: TestPause,
}

impl FileSystemStore {
    async fn new(path: PathBuf) -> Result<Self, IoError> {
        // Count each stage and its enclosing space from one listing snapshot.
        let (spaces, mut boot_stages) = store_sizes(&path).await?;
        let (sealed, sealed_stages) = sealed_sizes(&path.join(SEALED_DIR)).await?;
        boot_stages.extend(sealed_stages);
        Ok(Self {
            path,
            sizes: SpaceSizes::from_scan(spaces, sealed),
            pending: Arc::new(Mutex::new(HashMap::new())),
            boot_stages: Arc::new(Mutex::new(boot_stages)),
            operations: BlobOperationLocks::default(),
            at_rest: None,
            #[cfg(test)]
            before_memory_write: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            before_pending_refund: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_memory_contains: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            before_reserve_charge: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            fail_stage_cleanup: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            after_stage_unlink: Arc::new(Mutex::new(None)),
        })
    }

    fn get_path(&self, space: &SpaceId, mh: &Hash, generation: i64) -> PathBuf {
        let mut name = base64::encode_config(mh.as_ref(), base64::URL_SAFE);
        if generation != 0 {
            write!(&mut name, "@{generation}").expect("writing to String cannot fail");
        }
        self.path
            .join(space.suffix())
            .join(space.name().as_str())
            .join(name)
    }

    /// Links the store to the node's at-rest state (TC-887). Without it the
    /// store behaves as at-rest mode `off`.
    pub fn attach_at_rest(&mut self, handle: AtRestHandle) {
        self.at_rest = Some(handle);
    }

    fn view(&self) -> AtRestView {
        AtRestHandle::view_of(self.at_rest.as_ref())
    }

    fn sealed_path(&self, name: &SealedName) -> PathBuf {
        self.path
            .join(SEALED_DIR)
            .join(&name.space_tag)
            .join(&name.object)
    }

    /// `tag`: the space tag of sealed bytes (TC-887), `None` for legacy ones.
    async fn increment_size(&self, space: &SpaceId, tag: Option<&str>, size: u64) {
        self.sizes.increment_size(space, tag, size).await;
    }
    async fn decrement_size(&self, space: &SpaceId, tag: Option<&str>, size: u64) {
        self.sizes.decrement_size(space, tag, size).await;
    }

    async fn reserve(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        tag: Option<&str>,
        size: u64,
    ) {
        let key = (space.clone(), hash, generation);
        let mut pending = self.pending.lock().await;
        if let Entry::Vacant(slot) = pending.entry(key) {
            #[cfg(test)]
            if let Some((entered, release)) = self.before_reserve_charge.lock().await.take() {
                entered.notify_one();
                release.notified().await;
            }
            // Charge before publishing the reservation. Cancellation while
            // waiting on SpaceSizes leaves neither a charge nor a claim.
            self.increment_size(space, tag, size).await;
            slot.insert(size);
        }
    }

    async fn settle(&self, space: &SpaceId, hash: Hash, generation: i64) {
        self.pending
            .lock()
            .await
            .remove(&(space.clone(), hash, generation));
    }

    async fn refund_pending(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        tag: Option<&str>,
    ) {
        let key = (space.clone(), hash, generation);
        let mut pending = self.pending.lock().await;
        if let Some(&reserved) = pending.get(&key) {
            #[cfg(test)]
            if let Some((entered, release)) = self.before_pending_refund.lock().await.take() {
                entered.notify_one();
                release.notified().await;
            }
            // Retain the refund obligation until the size change completes.
            // No await may separate decrement from clearing this claim.
            if reserved != 0 {
                self.decrement_size(space, tag, reserved).await;
            }
            pending.remove(&key);
        }
    }

    async fn discard_failed_stage(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        tag: Option<&str>,
        path: tempfile::TempPath,
    ) -> Result<(), IoError> {
        // Do not refund a reservation until its unpublished bytes are gone.
        path.close()?;
        self.refund_pending(space, hash, generation, tag).await;
        Ok(())
    }

    fn stage_prefix(path: &Path) -> String {
        format!(
            ".tc-stage-{}-",
            path.file_name()
                .expect("blob path has a name")
                .to_string_lossy()
        )
    }

    /// A process crash can leave a named temporary file in a space directory.
    /// Boot quota reconstruction counts its actual bytes; candidate GC removes
    /// files for that hash and refunds them along with any published object.
    async fn remove_stages(
        &self,
        space: &SpaceId,
        path: &Path,
        tag: Option<&str>,
        refund_each: bool,
    ) -> Result<(u64, u64), IoError> {
        let Some(parent) = path.parent() else {
            return Ok((0, 0));
        };
        let mut entries = match tokio::fs::read_dir(parent).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok((0, 0)),
            Err(error) => return Err(error),
        };
        let prefix = Self::stage_prefix(path);
        let mut removed = 0u64;
        let mut boot_refunded = 0u64;
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_name().to_string_lossy().starts_with(&prefix)
                || !entry.file_type().await?.is_file()
            {
                continue;
            }
            let size = entry.metadata().await?.len();
            let stage_path = entry.path();
            match remove_file(&stage_path).await {
                Ok(()) => {
                    removed = removed
                        .checked_add(size)
                        .ok_or_else(|| IoError::other("staged blob byte count overflow"))?;
                    #[cfg(test)]
                    if let Some((entered, release)) = self.after_stage_unlink.lock().await.take() {
                        entered.notify_one();
                        release.notified().await;
                    }
                    let counted_at_boot = self
                        .boot_stages
                        .lock()
                        .await
                        .remove(&stage_path)
                        .unwrap_or(0);
                    boot_refunded = boot_refunded
                        .checked_add(counted_at_boot)
                        .ok_or_else(|| IoError::other("boot stage byte count overflow"))?;
                    if counted_at_boot != 0 || refund_each {
                        self.decrement_size(
                            space,
                            tag,
                            if counted_at_boot != 0 {
                                counted_at_boot
                            } else {
                                size
                            },
                        )
                        .await;
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok((removed, boot_refunded))
    }

    /// Persists a staged block under the name the at-rest state picks: the
    /// legacy name in mode `off`, else the sealed name (TC-887).
    async fn persist_staged(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        staged: Staged,
    ) -> Result<(), FileSystemStoreError> {
        match write_target(&self.view(), space, &hash, generation).await? {
            WriteTarget::Legacy => match staged {
                Staged::File(file) => self.persist_temp(space, hash, generation, file).await,
                Staged::Bytes(bytes) => self.persist_memory(space, hash, generation, bytes).await,
            },
            WriteTarget::Sealed { name, key } => {
                self.persist_sealed(space, hash, generation, &name, key, staged)
                    .await
            }
        }
    }

    /// Seals a staged block into a `.tc-stage-` file beside its sealed name,
    /// then renames it into place. Only the sealed name dedups: a legacy copy
    /// never suppresses the sealed write. The quota charge is the plaintext
    /// size, reserved and settled like a legacy write.
    async fn persist_sealed(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        name: &SealedName,
        key: DataKey,
        staged: Staged,
    ) -> Result<(), FileSystemStoreError> {
        let tag = Some(name.space_tag.as_str());
        let _operation = self
            .operations
            .lock((space.clone(), hash, generation))
            .await;
        let target = self.sealed_path(name);
        if target.exists() {
            self.settle(space, hash, generation).await;
            return Ok(());
        }
        let size = match &staged {
            Staged::File(file) => file.size().await?,
            Staged::Bytes(bytes) => bytes.len() as u64,
        };
        self.reserve(space, hash, generation, tag, size).await;
        let dir = target.parent().expect("sealed path has a parent");
        let stage = match create_dir_all(dir).await.and_then(|()| {
            tempfile::Builder::new()
                .prefix(&Self::stage_prefix(&target))
                .tempfile_in(dir)
        }) {
            Ok(stage) => stage,
            Err(error) => {
                self.refund_pending(space, hash, generation, tag).await;
                return Err(error.into());
            }
        };
        let (file, path) = stage.into_parts();
        let sealed = match staged {
            // The plaintext stage is removed when `src` drops, sealed or not.
            Staged::File(plain) => {
                let (_, src) = plain.into_inner();
                seal_file(&key, space, &hash, &src, size, file)
                    .await
                    .map_err(FileSystemStoreError::from)
            }
            Staged::Bytes(bytes) => match seal_vec(key, space, &hash, bytes).await {
                Ok(ciphertext) => {
                    let mut writer = File::from_std(file).compat();
                    async {
                        writer.write_all(&ciphertext).await?;
                        writer.flush().await
                    }
                    .await
                    .map_err(FileSystemStoreError::from)
                }
                Err(error) => Err(error.into()),
            },
        };
        if let Err(error) = sealed {
            self.discard_failed_stage(space, hash, generation, tag, path)
                .await?;
            return Err(error);
        }
        match path.persist(&target) {
            Ok(()) => {
                self.settle(space, hash, generation).await;
                Ok(())
            }
            Err(PathPersistError { error, path }) => {
                self.discard_failed_stage(space, hash, generation, tag, path)
                    .await?;
                Err(error.into())
            }
        }
    }

    async fn persist_temp(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        file: TempFileStage,
    ) -> Result<(), FileSystemStoreError> {
        let _operation = self
            .operations
            .lock((space.clone(), hash, generation))
            .await;
        if self.get_path(space, &hash, generation).exists() {
            self.settle(space, hash, generation).await;
            return Ok(());
        }
        let size = file.size().await?;
        self.reserve(space, hash, generation, None, size).await;
        let (_, path) = file.into_inner();
        match path.persist(self.get_path(space, &hash, generation)) {
            Ok(()) => {
                self.settle(space, hash, generation).await;
                Ok(())
            }
            Err(PathPersistError { error, path }) => {
                self.discard_failed_stage(space, hash, generation, None, path)
                    .await?;
                Err(error.into())
            }
        }
    }

    async fn persist_memory(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        bytes: Vec<u8>,
    ) -> Result<(), FileSystemStoreError> {
        let _operation = self
            .operations
            .lock((space.clone(), hash, generation))
            .await;
        if self.get_path(space, &hash, generation).exists() {
            self.settle(space, hash, generation).await;
            return Ok(());
        }
        #[cfg(test)]
        let pause = self.after_memory_contains.lock().await.take();
        #[cfg(test)]
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
        self.reserve(space, hash, generation, None, bytes.len() as u64)
            .await;
        let target = self.get_path(space, &hash, generation);
        // Stage on the target filesystem so the final rename is atomic and
        // never depends on a cross-device copy.
        let staged = match tempfile::Builder::new()
            .prefix(&Self::stage_prefix(&target))
            .tempfile_in(target.parent().expect("blob path has a parent"))
        {
            Ok(staged) => staged,
            Err(error) => {
                self.refund_pending(space, hash, generation, None).await;
                return Err(error.into());
            }
        };
        let (file, path) = staged.into_parts();
        #[cfg(test)]
        let pause = self.before_memory_write.lock().await.take();
        #[cfg(test)]
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
        let mut writer = File::from_std(file).compat();
        let written = async {
            writer.write_all(&bytes).await?;
            writer.flush().await
        }
        .await;
        drop(writer);
        if let Err(error) = written {
            self.discard_failed_stage(space, hash, generation, None, path)
                .await?;
            return Err(error.into());
        }
        match path.persist(target) {
            Ok(()) => {
                self.settle(space, hash, generation).await;
                Ok(())
            }
            Err(PathPersistError { error, path }) => {
                self.discard_failed_stage(space, hash, generation, None, path)
                    .await?;
                Err(error.into())
            }
        }
    }

    async fn open_legacy(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<Content<PlainReader>>, FileSystemStoreError> {
        match File::open(self.get_path(space, id, generation)).await {
            Ok(file) => {
                let size = file.metadata().await?.len();
                Ok(Some(Content::new(size, file.take(size).compat())))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Opens the block's sealed file, or `None` if it is absent.
    async fn open_sealed_file(
        &self,
        name: &SealedName,
        provider: &dyn DataKeyProvider,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Content<FsReadable>>, FileSystemStoreError> {
        let file = match File::open(self.sealed_path(name)).await {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let len = file.metadata().await?.len();
        let (size, reader) = open_sealed(provider, space, id, file.take(len).compat(), len)
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
    ) -> Result<Option<Content<FsReadable>>, FileSystemStoreError> {
        let legacy = |c: Option<Content<PlainReader>>| {
            c.map(|c| {
                let (size, r) = c.into_inner();
                Content::new(size, AsyncEither::Left(r))
            })
        };
        match read_plan(&self.view(), space, id, generation)? {
            ReadPlan::Legacy => Ok(legacy(self.open_legacy(space, id, generation).await?)),
            ReadPlan::LegacyWhileLocked => {
                match legacy(self.open_legacy(space, id, generation).await?) {
                    Some(c) => Ok(Some(c)),
                    None => Err(AtRestStoreError::Unavailable("at-rest keys are locked").into()),
                }
            }
            ReadPlan::SealedThenLegacy { name, provider } => {
                match self.open_sealed_file(&name, &*provider, space, id).await? {
                    Some(c) => Ok(Some(c)),
                    None => Ok(legacy(self.open_legacy(space, id, generation).await?)),
                }
            }
            ReadPlan::Sealed { name, provider } => {
                match self.open_sealed_file(&name, &*provider, space, id).await? {
                    Some(c) => Ok(Some(c)),
                    None if self.get_path(space, id, generation).exists() => {
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
        range: ByteRangeSpec,
    ) -> Result<Option<RangeRead<FsReadable>>, FileSystemStoreError> {
        match File::open(self.get_path(space, id, generation)).await {
            Ok(mut file) => {
                let total_size = file.metadata().await?.len();
                let Some(range) = range.resolve(total_size) else {
                    return Ok(Some(RangeRead::Unsatisfiable { total_size }));
                };
                file.seek(SeekFrom::Start(range.start())).await?;
                let content = Content::new(
                    range.len(),
                    AsyncEither::Left(file.take(range.len()).compat()),
                );
                Ok(Some(RangeRead::Content {
                    total_size,
                    range,
                    content,
                }))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// A range of the block's sealed file, or `None` if it is absent. Totals
    /// and the 416 decision use the plaintext length.
    async fn range_sealed(
        &self,
        name: &SealedName,
        provider: &dyn DataKeyProvider,
        space: &SpaceId,
        id: &Hash,
        spec: ByteRangeSpec,
    ) -> Result<Option<RangeRead<FsReadable>>, FileSystemStoreError> {
        let mut file = match File::open(self.sealed_path(name)).await {
            Ok(file) => file,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let len = file.metadata().await?.len();
        let logged = |e: AtRestStoreError| {
            e.log_at(name);
            e
        };
        let mut header = [0u8; HEADER_LEN];
        file.read_exact(&mut header).await.map_err(|_| {
            logged(AtRestStoreError::Integrity(
                "object shorter than its header",
            ))
        })?;
        let plan = plan_range(provider, space, &header, len, spec)
            .await
            .map_err(logged)?;
        let Some(r) = plan.range else {
            return Ok(Some(RangeRead::Unsatisfiable {
                total_size: plan.plaintext_len(),
            }));
        };
        file.seek(SeekFrom::Start(r.ciphertext_start())).await?;
        let span = r.ciphertext_end() - r.ciphertext_start() + 1;
        let reader = plan
            .reader(space, id, r, file.take(span).compat())
            .map_err(logged)?;
        let range = r.plaintext_range();
        Ok(Some(RangeRead::Content {
            total_size: plan.plaintext_len(),
            range,
            content: Content::new(
                range.len(),
                AsyncEither::Right(Box::new(LoggedDecrypt::new(reader, name))),
            ),
        }))
    }

    async fn range_block(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
        spec: ByteRangeSpec,
    ) -> Result<Option<RangeRead<FsReadable>>, FileSystemStoreError> {
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
                    None if self.get_path(space, id, generation).exists() => {
                        Err(AtRestStoreError::LegacyRefused.into())
                    }
                    None => Ok(None),
                }
            }
        }
    }

    /// The block's files a removal touches: the sealed name whenever keys
    /// are set up (with its space tag), then the legacy name. Refused (503)
    /// while keys are locked, so a sealed copy is never left unnamed.
    fn removal_paths(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Vec<(PathBuf, Option<String>)>, FileSystemStoreError> {
        let mut paths = Vec::with_capacity(2);
        if let Some(name) = removal_name(&self.view(), space, id, generation)? {
            paths.push((self.sealed_path(&name), Some(name.space_tag)));
        }
        paths.push((self.get_path(space, id, generation), None));
        Ok(paths)
    }
}

/// A staged block on its way into the store.
enum Staged {
    File(TempFileStage),
    Bytes(Vec<u8>),
}

type PlainReader = Compat<tokio::io::Take<File>>;

/// Plaintext from a legacy file, or authenticated plaintext from a sealed one.
/// The decrypting side is boxed: it carries the AES key schedule and segment
/// buffers, and `Content` values move by value through deep request paths.
pub type FsReadable = AsyncEither<PlainReader, Box<LoggedDecrypt<PlainReader>>>;

#[derive(Serialize, Deserialize, Debug, Clone, Hash, PartialEq, Eq)]
pub struct FileSystemConfig {
    path: PathBuf,
}

impl FileSystemConfig {
    pub fn new<P: AsRef<Path>>(p: P) -> Self {
        Self {
            path: p.as_ref().into(),
        }
    }
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[async_trait]
impl StorageConfig<FileSystemStore> for FileSystemConfig {
    type Error = IoError;
    async fn open(&self) -> Result<FileSystemStore, Self::Error> {
        if !self.path.is_dir() {
            create_dir_all(&self.path).await?;
        }
        Ok(FileSystemStore::new(self.path.clone()).await?)
    }
}

#[async_trait]
impl StorageSetup for FileSystemStore {
    type Error = IoError;
    async fn create(&self, space: &SpaceId) -> Result<(), Self::Error> {
        let path = self.path.join(space.suffix()).join(space.name().as_str());
        if !path.is_dir() {
            create_dir_all(&path).await?;
        }
        let tag = space_tag_of(&self.view(), space);
        self.sizes.init_size(space.clone(), tag.as_deref()).await;
        Ok(())
    }
}

impl Default for FileSystemConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::new(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum FileSystemStoreError {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Persist(#[from] PathPersistError),
    #[error(transparent)]
    AtRest(#[from] super::sealed::AtRestStoreError),
}

impl From<SealFileError> for FileSystemStoreError {
    fn from(e: SealFileError) -> Self {
        match e {
            SealFileError::AtRest(e) => Self::AtRest(e),
            SealFileError::Io(e) => Self::Io(e),
        }
    }
}

#[async_trait]
impl ImmutableReadStore for FileSystemStore {
    type Error = FileSystemStoreError;
    type Readable = FsReadable;
    /// Whether the block exists under the name a write would use (INTERFACES
    /// §7): in `encrypt`/`strict` only the sealed name counts.
    async fn contains(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<bool, Self::Error> {
        Ok(match contains_name(&self.view(), space, id, generation)? {
            ContainsName::Legacy => self.get_path(space, id, generation).exists(),
            ContainsName::Sealed(name) => self.sealed_path(&name).exists(),
        })
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

#[async_trait]
impl StoreSize for FileSystemStore {
    type Error = FileSystemStoreError;
    async fn total_size(&self, space: &SpaceId) -> Result<Option<u64>, Self::Error> {
        let tag = space_tag_of(&self.view(), space);
        Ok(self.sizes.get_size(space, tag.as_deref()).await)
    }
    async fn init_size(&self, space: &SpaceId) -> Result<u64, Self::Error> {
        let tag = space_tag_of(&self.view(), space);
        Ok(self.sizes.init_size(space.clone(), tag.as_deref()).await)
    }
}

// get the sum size of all files in this directory (recurse into subdirectories with space ID names)
async fn store_sizes<P: AsRef<Path>>(
    path: &P,
) -> Result<(HashMap<SpaceId, u64>, HashMap<PathBuf, u64>), IoError> {
    ReadDirStream::new(tokio::fs::read_dir(path).await?)
        // for every entry in the store dir
        .try_fold(
            (HashMap::new(), HashMap::new()),
            |(mut acc, mut stages), entry| async move {
                // if its a directory and the suffix is a valid string (the
                // sealed `v1` directory is scanned by `sealed_sizes`)
                if let (true, Ok(ref suffix)) = (
                    entry.metadata().await?.is_dir(),
                    entry.file_name().into_string(),
                ) {
                    if suffix == SEALED_DIR {
                        return Ok((acc, stages));
                    }
                    let mut ds = ReadDirStream::new(tokio::fs::read_dir(entry.path()).await?);
                    let did: DIDBuf = ["did:", suffix.as_str()].concat().parse().map_err(|_| {
                        IoError::new(ErrorKind::InvalidData, format!("Invalid DID: {suffix}"))
                    })?;
                    // go through each suffix directory
                    while let Some(entry) = ds.try_next().await? {
                        // for each entry in the suffix directory
                        // if its a directory and the name is a valid string
                        if let (true, Ok(name)) = (
                            entry.metadata().await?.is_dir(),
                            entry.file_name().into_string(),
                        ) {
                            // get the space ID from suffix and name
                            let space =
                                SpaceId::new(did.clone(), name.try_into().map_err(IoError::other)?);
                            let (size, space_stages) = space_size(&entry.path()).await?;
                            acc.insert(space, size);
                            stages.extend(space_stages);
                        }
                    }
                };
                Ok((acc, stages))
            },
        )
        .await
}

/// The sealed-object directory under the store root: `v1/{space_tag}/{object}`.
const SEALED_DIR: &str = "v1";

/// Plaintext bytes per space tag under `v1/` (TC-887), and the incomplete
/// stages found there with their stored bytes (a stage is charged its raw
/// size, as in a space directory). A missing directory holds nothing.
async fn sealed_sizes(
    path: &Path,
) -> Result<(HashMap<String, u64>, HashMap<PathBuf, u64>), IoError> {
    let mut sizes = HashMap::new();
    let mut stages = HashMap::new();
    let mut invalid = super::sealed::InvalidLengthLog::default();
    let mut tags = match tokio::fs::read_dir(path).await {
        Ok(dir) => ReadDirStream::new(dir),
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok((sizes, stages)),
        Err(e) => return Err(e),
    };
    while let Some(tag) = tags.try_next().await? {
        let (true, Ok(name)) = (
            tag.metadata().await?.is_dir(),
            tag.file_name().into_string(),
        ) else {
            continue;
        };
        let mut total = 0u64;
        let mut objects = ReadDirStream::new(tokio::fs::read_dir(tag.path()).await?);
        while let Some(object) = objects.try_next().await? {
            let meta = object.metadata().await?;
            if !meta.is_file() {
                continue;
            }
            let len = meta.len();
            let charged = if object
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(".tc-stage-"))
            {
                stages.insert(object.path(), len);
                len
            } else {
                plaintext_len(len).unwrap_or_else(|| {
                    invalid.record(len);
                    0
                })
            };
            total = total
                .checked_add(charged)
                .ok_or_else(|| IoError::other("sealed byte count overflow"))?;
        }
        sizes.insert(name, total);
    }
    invalid.finish();
    Ok((sizes, stages))
}

async fn space_size<P: AsRef<Path>>(path: &P) -> Result<(u64, HashMap<PathBuf, u64>), IoError> {
    // This one directory listing establishes both the charged total and the
    // exact incomplete stages which contributed to that total at boot.
    ReadDirStream::new(tokio::fs::read_dir(path).await?)
        .try_fold(
            (0u64, HashMap::new()),
            |(acc, mut stages), entry| async move {
                let metadata = entry.metadata().await?;
                if metadata.is_dir() {
                    return Ok((acc, stages));
                }
                let size = metadata.len();
                if metadata.is_file()
                    && entry
                        .file_name()
                        .to_str()
                        .is_some_and(|name| name.starts_with(".tc-stage-"))
                {
                    stages.insert(entry.path(), size);
                }
                let total = acc
                    .checked_add(size)
                    .ok_or_else(|| IoError::other("space byte count overflow"))?;
                Ok((total, stages))
            },
        )
        .await
}

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct TempFileSystemStage;

#[pin_project]
#[derive(Debug)]
pub struct TempFileStage(#[pin] Compat<File>, tempfile::TempPath);

impl TempFileStage {
    pub fn new(file: NamedTempFile) -> Self {
        let (f, p) = file.into_parts();
        Self(File::from_std(f).compat(), p)
    }
    pub fn into_inner(self) -> (Compat<File>, tempfile::TempPath) {
        (self.0, self.1)
    }

    pub async fn size(&self) -> Result<u64, IoError> {
        Ok(self.0.get_ref().metadata().await?.len())
    }
}

impl AsyncWrite for TempFileStage {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, IoError>> {
        self.project().0.poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.project().0.poll_flush(cx)
    }
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        self.project().0.poll_close(cx)
    }
}

#[async_trait]
impl ImmutableStaging for TempFileSystemStage {
    type Error = FileSystemStoreError;
    type Writable = TempFileStage;
    async fn get_staging_buffer(&self, _: &SpaceId) -> Result<Self::Writable, Self::Error> {
        Ok(TempFileStage::new(NamedTempFile::new()?))
    }
}

#[async_trait]
impl ImmutableWriteStore<TempFileSystemStage> for FileSystemStore {
    type Error = FileSystemStoreError;
    async fn prepare_write(&self, space: &SpaceId) -> Result<(), Self::Error> {
        Ok(super::sealed::prepare_write(&self.view(), space).await?)
    }
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<TempFileSystemStage as ImmutableStaging>::Writable>,
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let result = async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();
            Box::pin(self.persist_staged(space, hash, generation, Staged::File(f))).await?;
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
impl ImmutableWriteStore<memory::MemoryStaging> for FileSystemStore {
    type Error = FileSystemStoreError;
    async fn prepare_write(&self, space: &SpaceId) -> Result<(), Self::Error> {
        Ok(super::sealed::prepare_write(&self.view(), space).await?)
    }
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<memory::MemoryStaging as ImmutableStaging>::Writable>,
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let result = async move {
            let (mut h, v) = staged.into_inner();
            let hash = h.finalize();
            Box::pin(self.persist_staged(space, hash, generation, Staged::Bytes(v))).await?;
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
impl ImmutableWriteStore<either::Either<TempFileSystemStage, memory::MemoryStaging>>
    for FileSystemStore
{
    type Error = FileSystemStoreError;
    async fn prepare_write(&self, space: &SpaceId) -> Result<(), Self::Error> {
        Ok(super::sealed::prepare_write(&self.view(), space).await?)
    }
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<<either::Either<TempFileSystemStage, memory::MemoryStaging> as ImmutableStaging>::Writable>,
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let result = async move {
            let (mut h, f) = staged.into_inner();
            let hash = h.finalize();

            let staged = match f {
                AsyncEither::Left(file) => Staged::File(file),
                AsyncEither::Right(bytes) => Staged::Bytes(bytes),
            };
            Box::pin(self.persist_staged(space, hash, generation, staged)).await?;
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
impl ImmutableDeleteStore for FileSystemStore {
    type Error = FileSystemStoreError;
    async fn remove(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<()>, Self::Error> {
        // The sealed copy (whenever keys are set up) and the legacy one; with
        // keys locked nothing is removed and the collector retries later.
        let paths = self.removal_paths(space, id, generation)?;
        let store = self.clone();
        let space = space.clone();
        let id = *id;
        // Finish unlink and quota settlement under the same physical lock
        // even if the request or collector is cancelled after unlink.
        tokio::spawn(async move {
            let key = (space.clone(), id, generation);
            let _operation = store.operations.lock(key.clone()).await;
            let pending = store.pending.lock().await.contains_key(&key);
            let (mut staged, mut boot_refunded, mut removed_bytes) = (0u64, 0u64, 0u64);
            let mut removed_any = false;
            for (path, tag) in &paths {
                let tag = tag.as_deref();
                // Boot stages and a new reservation are independently charged.
                let (s, b) = store.remove_stages(&space, path, tag, !pending).await?;
                staged = staged.saturating_add(s);
                boot_refunded = boot_refunded.saturating_add(b);
                let final_size = match metadata(path).await {
                    Ok(meta) => Some(meta.len()),
                    Err(error) if error.kind() == ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                };
                let Some(size) = final_size else { continue };
                match remove_file(path).await {
                    Ok(()) => {}
                    Err(error) if error.kind() == ErrorKind::NotFound => continue,
                    Err(error) => return Err(error.into()),
                }
                removed_any = true;
                // A sealed file is charged its plaintext bytes, as counted.
                let charged = match tag {
                    Some(_) => plaintext_len(size).unwrap_or(0),
                    None => size,
                };
                if pending {
                    removed_bytes = removed_bytes.saturating_add(charged);
                } else {
                    store.decrement_size(&space, tag, charged).await;
                }
            }
            if pending {
                let reserved = store.pending.lock().await.remove(&key).unwrap_or(0);
                store
                    .decrement_size(
                        &space,
                        paths[0].1.as_deref(),
                        reserved.max(
                            staged
                                .saturating_sub(boot_refunded)
                                .saturating_add(removed_bytes),
                        ),
                    )
                    .await;
            }
            Ok::<_, FileSystemStoreError>((removed_any || staged != 0).then_some(()))
        })
        .await
        .map_err(IoError::other)?
    }
    async fn cleanup_stages(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<(), Self::Error> {
        let paths = self.removal_paths(space, id, generation)?;
        let store = self.clone();
        let space = space.clone();
        let id = *id;
        // The DB fence may time out or its caller may be cancelled. Finish
        // each unlink and its quota refund together before releasing the
        // physical lock; the retained DB attempt makes a retry idempotent.
        tokio::spawn(async move {
            let key = (space.clone(), id, generation);
            let _operation = store.operations.lock(key.clone()).await;
            #[cfg(test)]
            if store.fail_stage_cleanup.load(Ordering::SeqCst) {
                return Err(IoError::other("injected stage cleanup failure").into());
            }
            let pending = store.pending.lock().await.contains_key(&key);
            // This path is for a referenced final blob. Only incomplete
            // stages are removed; never unlink a committed row's object.
            for (path, tag) in &paths {
                store
                    .remove_stages(&space, path, tag.as_deref(), !pending)
                    .await?;
            }
            if pending {
                store
                    .refund_pending(&space, id, generation, paths[0].1.as_deref())
                    .await;
            }
            Ok::<(), FileSystemStoreError>(())
        })
        .await
        .map_err(IoError::other)?
    }
}

#[async_trait]
impl StorageConfig<TempFileSystemStage> for TempFileSystemStage {
    type Error = std::convert::Infallible;
    async fn open(&self) -> Result<TempFileSystemStage, Self::Error> {
        Ok(Self)
    }
}

#[cfg(test)]
mod sealed_tests;

#[cfg(test)]
mod test {
    use super::*;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn memory_publish_is_atomic_for_concurrent_same_hash_paths() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        let space: SpaceId = "tinycloud:key:test:atomic".parse().unwrap();
        store.create(&space).await.unwrap();
        let data = b"same-content two distinct KV paths".to_vec();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *store.before_memory_write.lock().await = Some((entered.clone(), release));
        let mut first_stage = HashBuffer::new(Vec::new());
        first_stage.write_all(&data).await.unwrap();
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
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        let prematurely_visible = store.contains(&space, &hash, 0).await.unwrap();
        let mut second_stage = HashBuffer::new(Vec::new());
        second_stage.write_all(&data).await.unwrap();
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
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut second).await;
        first.abort();
        assert!(first.await.unwrap_err().is_cancelled());
        let second_hash = match early_second {
            Ok(result) => result.unwrap().unwrap(),
            Err(_) => tokio::time::timeout(std::time::Duration::from_secs(2), second)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
        };
        assert_eq!(second_hash, hash);
        let stored = store.read_to_vec(&space, &hash, 0).await.unwrap().unwrap();
        assert!(
            !prematurely_visible,
            "a complete candidate must be published before same-hash dedup"
        );
        assert_eq!(stored, data, "a committed alias must read all staged bytes");
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(data.len() as u64)
        );
    }

    #[tokio::test]
    async fn same_generation_concurrent_memory_put_charges_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        let space: SpaceId = "tinycloud:key:test:one-charge".parse().unwrap();
        store.create(&space).await.unwrap();
        let data = b"same content for two KV records".to_vec();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *store.after_memory_contains.lock().await = Some((entered.clone(), release.clone()));
        let mut first_stage = HashBuffer::new(Vec::new());
        first_stage.write_all(&data).await.unwrap();
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
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        let mut second_stage = HashBuffer::new(Vec::new());
        second_stage.write_all(&data).await.unwrap();
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
            tokio::time::timeout(std::time::Duration::from_millis(100), &mut second).await;
        release.notify_one();
        assert_eq!(first.await.unwrap().unwrap(), hash);
        let second_hash = match early_second {
            Ok(result) => result.unwrap().unwrap(),
            Err(_) => tokio::time::timeout(std::time::Duration::from_secs(2), second)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
        };
        assert_eq!(second_hash, hash);
        assert_eq!(
            store.read_to_vec(&space, &hash, 0).await.unwrap(),
            Some(data.clone())
        );
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(data.len() as u64)
        );
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), Some(()));
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
    }

    #[tokio::test]
    async fn restart_counts_then_collects_crash_leftover_memory_stage() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        let space: SpaceId = "tinycloud:key:test:stage-restart".parse().unwrap();
        store.create(&space).await.unwrap();
        let hash = tinycloud_core::hash::hash(b"unfinished memory stage");
        let path = store.get_path(&space, &hash, 0);
        let prefix = format!(".tc-stage-{}-", path.file_name().unwrap().to_str().unwrap());
        let mut stage = tempfile::Builder::new()
            .prefix(&prefix)
            .tempfile_in(path.parent().unwrap())
            .unwrap();
        std::io::Write::write_all(&mut stage, b"partial").unwrap();
        let stage_path = stage.path().to_path_buf();
        stage.into_temp_path().keep().unwrap();
        drop(store);

        let reopened = FileSystemConfig::new(dir.path()).open().await.unwrap();
        assert_eq!(reopened.total_size(&space).await.unwrap(), Some(7));
        reopened.remove(&space, &hash, 0).await.unwrap();
        assert_eq!(reopened.total_size(&space).await.unwrap(), Some(0));
        assert!(!stage_path.exists());
    }

    #[tokio::test]
    async fn cancelled_delete_finishes_boot_stage_refund_before_retry() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        let space: SpaceId = "tinycloud:key:test:cancel-stage".parse().unwrap();
        store.create(&space).await.unwrap();
        let value = tinycloud_core::hash::hash(b"cancelled stage delete");
        let target = store.get_path(&space, &value, 0);
        let mut stage = tempfile::Builder::new()
            .prefix(&FileSystemStore::stage_prefix(&target))
            .tempfile_in(target.parent().unwrap())
            .unwrap();
        std::io::Write::write_all(&mut stage, b"partial").unwrap();
        let stage_path = stage.path().to_path_buf();
        stage.into_temp_path().keep().unwrap();
        drop(store);
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        assert_eq!(store.total_size(&space).await.unwrap(), Some(7));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *store.after_stage_unlink.lock().await = Some((entered.clone(), release.clone()));
        let deleting_store = store.clone();
        let deleting_space = space.clone();
        let deletion =
            tokio::spawn(async move { deleting_store.remove(&deleting_space, &value, 0).await });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        assert!(!stage_path.exists());
        deletion.abort();
        assert!(deletion.await.unwrap_err().is_cancelled());
        release.notify_one();
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                store.remove(&space, &value, 0)
            )
            .await
            .unwrap()
            .unwrap(),
            None
        );
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
    }

    #[tokio::test]
    async fn boot_counted_stage_and_failed_retry_refund_both_charges_once() {
        use tinycloud_core::sea_orm::{
            ConnectionTrait, Database, DbBackend, Statement, TransactionTrait,
        };
        use tinycloud_core::sea_orm_migration::MigratorTrait;
        use tinycloud_core::{hash::hash, kv_orphans, migrations::Migrator};

        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.execute_unprepared("PRAGMA foreign_keys = OFF")
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        let space: SpaceId = "tinycloud:key:test:stage-and-reservation".parse().unwrap();
        store.create(&space).await.unwrap();
        let bytes = b"retrying the same hash after a crash";
        let value = hash(bytes);
        let blob = [(space.clone(), value)];
        let tx = db.begin().await.unwrap();
        kv_orphans::register_candidates(&tx, &blob, "crashed-a")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let target = store.get_path(&space, &value, 0);
        let mut stage = tempfile::Builder::new()
            .prefix(&FileSystemStore::stage_prefix(&target))
            .tempfile_in(target.parent().unwrap())
            .unwrap();
        std::io::Write::write_all(&mut stage, b"partial").unwrap();
        let boot_stage = stage.path().to_path_buf();
        stage.into_temp_path().keep().unwrap();
        drop(store);
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        assert_eq!(store.total_size(&space).await.unwrap(), Some(7));

        let tx = db.begin().await.unwrap();
        let failed = kv_orphans::register_candidates(&tx, &blob, "failed-b")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *store.before_memory_write.lock().await = Some((entered.clone(), release));
        let mut retry = HashBuffer::new(Vec::new());
        retry.write_all(bytes).await.unwrap();
        let uploading_store = store.clone();
        let uploading_space = space.clone();
        let uploading = tokio::spawn(async move {
            ImmutableWriteStore::<memory::MemoryStaging>::persist(
                &uploading_store,
                &uploading_space,
                retry,
                0,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
            .await
            .unwrap();
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(7 + bytes.len() as u64)
        );
        uploading.abort();
        assert!(uploading.await.unwrap_err().is_cancelled());
        kv_orphans::refund_failed(&db, &store, &failed, "failed-b")
            .await
            .unwrap();

        let unrelated = b"other";
        let mut other_stage = HashBuffer::new(Vec::new());
        other_stage.write_all(unrelated).await.unwrap();
        let other =
            ImmutableWriteStore::<memory::MemoryStaging>::persist(&store, &space, other_stage, 0)
                .await
                .unwrap();
        db.execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "UPDATE kv_orphan_attempt SET created_at = ? WHERE attempt_id = ?",
            [
                (time::OffsetDateTime::now_utc() - time::Duration::minutes(6)).into(),
                "crashed-a".into(),
            ],
        ))
        .await
        .unwrap();
        assert_eq!(
            kv_orphans::collect_candidates(&db, &store, 256, kv_orphans::ORPHAN_GRACE)
                .await
                .unwrap(),
            1
        );
        assert!(!boot_stage.exists());
        assert!(!store.contains(&space, &value, 0).await.unwrap());
        assert_eq!(
            store.read_to_vec(&space, &other, 0).await.unwrap(),
            Some(unrelated.to_vec())
        );
        assert_eq!(store.total_size(&space).await.unwrap(), Some(5));
        assert_eq!(
            kv_orphans::collect_candidates(&db, &store, 256, kv_orphans::ORPHAN_GRACE)
                .await
                .unwrap(),
            0
        );
        assert_eq!(store.total_size(&space).await.unwrap(), Some(5));
    }

    #[tokio::test]
    async fn referenced_retry_collects_crashed_stage_without_deleting_committed_blob() {
        referenced_retry_with_crashed_stage(false, false, false).await;
    }

    #[tokio::test]
    async fn referenced_retry_retains_stage_recovery_if_crash_attempt_expires_first() {
        referenced_retry_with_crashed_stage(true, false, false).await;
    }

    #[tokio::test]
    async fn referenced_retry_retains_candidate_when_stage_cleanup_fails() {
        referenced_retry_with_crashed_stage(false, true, false).await;
    }

    #[tokio::test]
    async fn referenced_retry_cancelled_cleanup_completes_stage_refund() {
        referenced_retry_with_crashed_stage(false, false, true).await;
    }

    async fn referenced_retry_with_crashed_stage(
        collect_before_commit: bool,
        fail_cleanup: bool,
        cancel_cleanup: bool,
    ) {
        use tinycloud_core::sea_orm::{
            ConnectionTrait, Database, DbBackend, EntityTrait, PaginatorTrait, Statement,
            TransactionTrait,
        };
        use tinycloud_core::sea_orm_migration::MigratorTrait;
        use tinycloud_core::{
            hash::hash,
            kv_orphans,
            migrations::Migrator,
            models::{kv_orphan_attempt, kv_orphan_candidate},
        };

        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.execute_unprepared("PRAGMA foreign_keys = OFF")
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cfg = FileSystemConfig::new(dir.path());
        let store = cfg.open().await.unwrap();
        let space: SpaceId = "tinycloud:key:test:referenced-stage".parse().unwrap();
        store.create(&space).await.unwrap();
        let data = b"complete same-hash retry after crash";
        let value = hash(data);
        let blobs = [(space.clone(), value)];
        let tx = db.begin().await.unwrap();
        kv_orphans::register_candidates(&tx, &blobs, "crashed-A")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        let path = store.get_path(&space, &value, 0);
        let staged = tempfile::Builder::new()
            .prefix(&FileSystemStore::stage_prefix(&path))
            .tempfile_in(path.parent().unwrap())
            .unwrap();
        let stage_path = staged.path().to_path_buf();
        std::fs::write(&stage_path, b"partial").unwrap();
        staged.into_temp_path().keep().unwrap();
        drop(store);
        let store = cfg.open().await.unwrap();
        assert_eq!(store.total_size(&space).await.unwrap(), Some(7));

        let tx = db.begin().await.unwrap();
        let registered = kv_orphans::register_candidates(&tx, &blobs, "retry-B")
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let mut stage = HashBuffer::new(Vec::new());
        stage.write_all(data).await.unwrap();
        ImmutableWriteStore::<memory::MemoryStaging>::persist(
            &store,
            &space,
            stage,
            registered[0].2,
        )
        .await
        .unwrap();
        if collect_before_commit {
            // A's DB-time claim is older than the five-minute grace; B's
            // fresh claim still protects its in-flight upload.
            db.execute(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE kv_orphan_attempt SET created_at = ? WHERE attempt_id = ?",
                [
                    (time::OffsetDateTime::now_utc() - time::Duration::minutes(6)).into(),
                    "crashed-A".into(),
                ],
            ))
            .await
            .unwrap();
            kv_orphans::collect_candidates(&db, &store, 256, kv_orphans::ORPHAN_GRACE)
                .await
                .unwrap();
            assert!(stage_path.exists());
        }
        let tx = db.begin().await.unwrap();
        kv_orphans::lock_candidates(&tx, &registered, "retry-B")
            .await
            .unwrap();
        tx.execute(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO kv_write (space,key,invocation,seq,epoch,epoch_seq,value,metadata,generation)
             VALUES (?,'retry',?,1,?,1,?,'{}',?)",
            [
                space.to_string().into(),
                Vec::<u8>::from(hash(b"invocation")).into(),
                Vec::<u8>::from(hash(b"epoch")).into(),
                Vec::<u8>::from(value).into(),
                registered[0].2.into(),
            ],
        ))
        .await
        .unwrap();
        kv_orphans::finish_candidates(&tx, &registered, "retry-B")
            .await
            .unwrap();
        tx.commit().await.unwrap();

        if fail_cleanup {
            store.fail_stage_cleanup.store(true, Ordering::SeqCst);
            assert!(
                kv_orphans::collect_candidates(&db, &store, 256, time::Duration::ZERO)
                    .await
                    .is_err()
            );
            assert!(stage_path.exists());
            assert_eq!(
                kv_orphan_candidate::Entity::find()
                    .count(&db)
                    .await
                    .unwrap(),
                1
            );
            assert_eq!(
                kv_orphan_attempt::Entity::find().count(&db).await.unwrap(),
                1
            );
            assert_eq!(
                store.total_size(&space).await.unwrap(),
                Some(7 + data.len() as u64)
            );
            store.fail_stage_cleanup.store(false, Ordering::SeqCst);
            kv_orphans::refund_failed(&db, &store, &registered, "crashed-A")
                .await
                .unwrap();
        } else if cancel_cleanup {
            let entered = Arc::new(Notify::new());
            let release = Arc::new(Notify::new());
            *store.after_stage_unlink.lock().await = Some((entered.clone(), release.clone()));
            let collecting_db = db.clone();
            let collecting_store = store.clone();
            let collector = tokio::spawn(async move {
                kv_orphans::collect_candidates(
                    &collecting_db,
                    &collecting_store,
                    256,
                    time::Duration::ZERO,
                )
                .await
            });
            tokio::time::timeout(std::time::Duration::from_secs(2), entered.notified())
                .await
                .unwrap();
            assert!(!stage_path.exists());
            assert_eq!(
                store.total_size(&space).await.unwrap(),
                Some(7 + data.len() as u64)
            );
            collector.abort();
            assert!(collector.await.unwrap_err().is_cancelled());
            release.notify_one();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                kv_orphans::refund_failed(&db, &store, &registered, "crashed-A"),
            )
            .await
            .unwrap()
            .unwrap();
        } else {
            kv_orphans::collect_candidates(&db, &store, 256, time::Duration::ZERO)
                .await
                .unwrap();
        }
        assert_eq!(
            store.read_to_vec(&space, &value, 0).await.unwrap(),
            Some(data.to_vec()),
            "GC must preserve the committed retry"
        );
        assert!(!stage_path.exists(), "the crashed stage is unreferenced");
        assert_eq!(
            store.total_size(&space).await.unwrap(),
            Some(data.len() as u64)
        );
        assert_eq!(
            kv_orphan_candidate::Entity::find()
                .count(&db)
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            kv_orphan_attempt::Entity::find().count(&db).await.unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn expired_crash_stage_is_refunded_after_overlapping_retry_commits_or_aborts() {
        use tinycloud_core::sea_orm::{
            ConnectionTrait, Database, DbBackend, EntityTrait, PaginatorTrait, Statement,
            TransactionTrait,
        };
        use tinycloud_core::sea_orm_migration::MigratorTrait;
        use tinycloud_core::{
            hash::hash,
            kv_orphans,
            migrations::Migrator,
            models::{kv_orphan_attempt, kv_orphan_candidate, kv_write},
        };

        for commits in [true, false] {
            let db = Database::connect("sqlite::memory:").await.unwrap();
            Migrator::up(&db, None).await.unwrap();
            db.execute_unprepared("PRAGMA foreign_keys = OFF")
                .await
                .unwrap();
            let dir = tempfile::tempdir().unwrap();
            let cfg = FileSystemConfig::new(dir.path());
            let store = cfg.open().await.unwrap();
            let space: SpaceId = "tinycloud:key:test:overlap-bound".parse().unwrap();
            store.create(&space).await.unwrap();
            let data = b"complete retry after crashed stage";
            let value = hash(data);
            let blobs = [(space.clone(), value)];
            let tx = db.begin().await.unwrap();
            kv_orphans::register_candidates(&tx, &blobs, "crashed-A")
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let target = store.get_path(&space, &value, 0);
            let mut stage = tempfile::Builder::new()
                .prefix(&FileSystemStore::stage_prefix(&target))
                .tempfile_in(target.parent().unwrap())
                .unwrap();
            std::io::Write::write_all(&mut stage, b"partial").unwrap();
            let stage_path = stage.path().to_path_buf();
            stage.into_temp_path().keep().unwrap();
            drop(store);
            let store = cfg.open().await.unwrap();
            assert_eq!(store.total_size(&space).await.unwrap(), Some(7));
            db.execute(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE kv_orphan_attempt SET created_at = ? WHERE attempt_id = ?",
                [
                    (time::OffsetDateTime::now_utc() - time::Duration::minutes(6)).into(),
                    "crashed-A".into(),
                ],
            ))
            .await
            .unwrap();

            let tx = db.begin().await.unwrap();
            let retry = kv_orphans::register_candidates(&tx, &blobs, "live-B")
                .await
                .unwrap();
            tx.commit().await.unwrap();
            let mut upload = HashBuffer::new(Vec::new());
            upload.write_all(data).await.unwrap();
            assert_eq!(
                ImmutableWriteStore::<memory::MemoryStaging>::persist(
                    &store, &space, upload, retry[0].2
                )
                .await
                .unwrap(),
                value
            );
            assert_eq!(
                store.total_size(&space).await.unwrap(),
                Some(7 + data.len() as u64)
            );
            assert_eq!(
                kv_orphans::collect_candidates(&db, &store, 256, kv_orphans::ORPHAN_GRACE)
                    .await
                    .unwrap(),
                0,
                "A's expired stage must remain charged while B is live"
            );
            assert!(stage_path.exists());

            if commits {
                let tx = db.begin().await.unwrap();
                kv_orphans::lock_candidates(&tx, &retry, "live-B")
                    .await
                    .unwrap();
                tx.execute(Statement::from_sql_and_values(
                    DbBackend::Sqlite,
                    "INSERT INTO kv_write (space,key,invocation,seq,epoch,epoch_seq,value,metadata,generation)
                     VALUES (?,'retry',?,1,?,1,?,'{}',?)",
                    [
                        space.to_string().into(),
                        Vec::<u8>::from(hash(b"invocation")).into(),
                        Vec::<u8>::from(hash(b"epoch")).into(),
                        Vec::<u8>::from(value).into(),
                        retry[0].2.into(),
                    ],
                ))
                .await
                .unwrap();
                kv_orphans::finish_candidates(&tx, &retry, "live-B")
                    .await
                    .unwrap();
                tx.commit().await.unwrap();
            } else {
                kv_orphans::refund_failed(&db, &store, &retry, "live-B")
                    .await
                    .unwrap();
            }

            assert_eq!(
                kv_orphans::collect_candidates(&db, &store, 256, kv_orphans::ORPHAN_GRACE)
                    .await
                    .unwrap(),
                usize::from(!commits),
                "A's crash charge must settle on the next pass after B leaves"
            );
            assert!(!stage_path.exists());
            assert_eq!(
                store.read_to_vec(&space, &value, 0).await.unwrap(),
                commits.then(|| data.to_vec()),
                "a committed retry must remain readable; an aborted one must be absent"
            );
            assert_eq!(
                kv_write::Entity::find().count(&db).await.unwrap(),
                u64::from(commits)
            );
            assert_eq!(
                store.total_size(&space).await.unwrap(),
                Some(if commits { data.len() as u64 } else { 0 })
            );
            assert_eq!(
                kv_orphans::collect_candidates(&db, &store, 256, kv_orphans::ORPHAN_GRACE)
                    .await
                    .unwrap(),
                0,
                "settled crash attempts cannot refund twice"
            );
            assert_eq!(
                kv_orphan_candidate::Entity::find()
                    .count(&db)
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(
                kv_orphan_attempt::Entity::find().count(&db).await.unwrap(),
                0
            );
        }
    }

    #[tokio::test]
    async fn failed_file_creation_refunds_reserved_quota() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        let space: SpaceId = "tinycloud:key:test:failed".parse().unwrap();
        store.create(&space).await.unwrap();
        tokio::fs::remove_dir(store.path.join(space.suffix()).join(space.name().as_str()))
            .await
            .unwrap();
        let mut stage = HashBuffer::new(Vec::new());
        stage.write_all(b"failed-write").await.unwrap();
        let hash = stage.hash();
        assert!(
            ImmutableWriteStore::<memory::MemoryStaging>::persist(&store, &space, stage, 0)
                .await
                .is_err()
        );
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), None);
        assert!(!store.contains(&space, &hash, 0).await.unwrap());
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));

        let mut staged = HashBuffer::new(
            TempFileSystemStage
                .get_staging_buffer(&space)
                .await
                .unwrap(),
        );
        staged.write_all(b"failed-stage").await.unwrap();
        let staged_hash = staged.hash();
        assert!(
            ImmutableWriteStore::<TempFileSystemStage>::persist(&store, &space, staged, 0)
                .await
                .is_err()
        );
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
        assert_eq!(store.remove(&space, &staged_hash, 0).await.unwrap(), None);
    }

    #[tokio::test]
    async fn cancelled_failed_upload_retains_refund_until_quota_lock_is_available() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        let space: SpaceId = "tinycloud:key:test:cancel-refund".parse().unwrap();
        store.create(&space).await.unwrap();
        let bytes = b"failed upload quota";
        let hash = tinycloud_core::hash::hash(bytes);
        let target = store.get_path(&space, &hash, 0);

        let writing = Arc::new(Notify::new());
        let resume_write = Arc::new(Notify::new());
        *store.before_memory_write.lock().await = Some((writing.clone(), resume_write.clone()));
        let refunding = Arc::new(Notify::new());
        let resume_refund = Arc::new(Notify::new());
        *store.before_pending_refund.lock().await =
            Some((refunding.clone(), resume_refund.clone()));
        let mut stage = HashBuffer::new(Vec::new());
        stage.write_all(bytes).await.unwrap();
        let uploading_store = store.clone();
        let uploading_space = space.clone();
        let upload = tokio::spawn(async move {
            ImmutableWriteStore::<memory::MemoryStaging>::persist(
                &uploading_store,
                &uploading_space,
                stage,
                0,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), writing.notified())
            .await
            .unwrap();
        tokio::fs::create_dir(&target).await.unwrap();
        let quota_lock = store.sizes.lock_updates_for_test().await;
        resume_write.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(2), refunding.notified())
            .await
            .unwrap();
        resume_refund.notify_one();
        tokio::task::yield_now().await;
        upload.abort();
        assert!(upload.await.unwrap_err().is_cancelled());
        drop(quota_lock);
        tokio::fs::remove_dir(&target).await.unwrap();
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), None);
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
    }

    #[tokio::test]
    async fn cancelled_reservation_cannot_refund_bytes_never_charged() {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        let space: SpaceId = "tinycloud:key:test:cancel-reserve".parse().unwrap();
        store.create(&space).await.unwrap();
        let bytes = b"unacquired charge";
        let hash = tinycloud_core::hash::hash(bytes);
        let checked = Arc::new(Notify::new());
        let resume_check = Arc::new(Notify::new());
        *store.after_memory_contains.lock().await = Some((checked.clone(), resume_check.clone()));
        let charging = Arc::new(Notify::new());
        let resume_charge = Arc::new(Notify::new());
        *store.before_reserve_charge.lock().await = Some((charging.clone(), resume_charge.clone()));
        let mut stage = HashBuffer::new(Vec::new());
        stage.write_all(bytes).await.unwrap();
        let uploading_store = store.clone();
        let uploading_space = space.clone();
        let upload = tokio::spawn(async move {
            ImmutableWriteStore::<memory::MemoryStaging>::persist(
                &uploading_store,
                &uploading_space,
                stage,
                0,
            )
            .await
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), checked.notified())
            .await
            .unwrap();
        let quota_lock = store.sizes.lock_updates_for_test().await;
        resume_check.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(2), charging.notified())
            .await
            .unwrap();
        resume_charge.notify_one();
        tokio::task::yield_now().await;
        upload.abort();
        assert!(upload.await.unwrap_err().is_cancelled());
        drop(quota_lock);
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), None);
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
    }

    #[tokio::test]
    async fn test_file_system_store() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = FileSystemConfig::new(dir.path());
        let store = cfg.open().await.unwrap();
        let data = b"hello world";
        let space_id: SpaceId = "tinycloud:key:test:default".parse().unwrap();
        assert_eq!(store.total_size(&space_id).await.unwrap(), None);
        store.create(&space_id).await.unwrap();
        assert_eq!(store.total_size(&space_id).await.unwrap(), Some(0));
        let tfs = TempFileSystemStage;
        let mut stage = tfs.stage(&space_id).await.unwrap();
        futures::io::copy(&mut &data[..], &mut stage).await.unwrap();

        let hash = ImmutableWriteStore::<TempFileSystemStage>::persist(&store, &space_id, stage, 0)
            .await
            .unwrap();

        assert!(store.contains(&space_id, &hash, 0).await.unwrap());
        assert_eq!(
            store.total_size(&space_id).await.unwrap(),
            Some(data.len() as u64)
        );

        let mut buf = Vec::new();
        store
            .read(&space_id, &hash, 0)
            .await
            .unwrap()
            .unwrap()
            .read_to_end(&mut buf)
            .await
            .unwrap();

        assert_eq!(buf, data);
        assert_eq!(
            store
                .read_to_vec(&space_id, &hash, 0)
                .await
                .unwrap()
                .unwrap(),
            data
        );

        let range_read = store
            .read_range(
                &space_id,
                &hash,
                0,
                ByteRangeSpec::Inclusive { start: 6, end: 10 },
            )
            .await
            .unwrap()
            .unwrap();
        let RangeRead::Content {
            total_size,
            range,
            mut content,
        } = range_read
        else {
            panic!("expected satisfiable range");
        };
        let mut range_buf = Vec::new();
        content.read_to_end(&mut range_buf).await.unwrap();
        assert_eq!(total_size, data.len() as u64);
        assert_eq!(
            range,
            ByteRangeSpec::Inclusive { start: 6, end: 10 }
                .resolve(data.len() as u64)
                .unwrap()
        );
        assert_eq!(range_buf, b"world");

        assert!(matches!(
            store
                .read_range(&space_id, &hash, 0, ByteRangeSpec::From { start: 99 })
                .await
                .unwrap()
                .unwrap(),
            RangeRead::Unsatisfiable { total_size: 11 }
        ));

        assert_eq!(store.remove(&space_id, &hash, 0).await.unwrap(), Some(()));
        assert_eq!(store.remove(&space_id, &hash, 0).await.unwrap(), None);
        assert!(!store.contains(&space_id, &hash, 0).await.unwrap());
        assert_eq!(store.total_size(&space_id).await.unwrap(), Some(0));
        assert_eq!(
            store.read(&space_id, &hash, 0).await.unwrap().map(|_| ()),
            None
        );
    }
    #[tokio::test]
    async fn reads_preexisting_bare_hash_file_as_generation_zero() {
        let dir = tempfile::tempdir().unwrap();
        let space: SpaceId = "tinycloud:key:test:old-file".parse().unwrap();
        let initial = FileSystemConfig::new(dir.path()).open().await.unwrap();
        initial.create(&space).await.unwrap();
        let mut data = HashBuffer::new(Vec::new());
        data.write_all(b"legacy").await.unwrap();
        let hash = data.hash();
        let bare = initial.get_path(&space, &hash, 0);
        tokio::fs::write(&bare, b"legacy").await.unwrap();
        let loaded = FileSystemConfig::new(dir.path()).open().await.unwrap();
        assert_eq!(
            loaded.read_to_vec(&space, &hash, 0).await.unwrap(),
            Some(b"legacy".to_vec())
        );
        assert_eq!(loaded.read_to_vec(&space, &hash, 1).await.unwrap(), None);
        assert_eq!(loaded.total_size(&space).await.unwrap(), Some(6));
    }

    #[tokio::test]
    async fn generations_keep_legacy_key_and_account_for_both_files_on_restart() {
        let dir = tempfile::tempdir().unwrap();
        let space: SpaceId = "tinycloud:key:test:generations".parse().unwrap();
        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        store.create(&space).await.unwrap();
        let mut old = HashBuffer::new(Vec::new());
        old.write_all(b"same bytes").await.unwrap();
        let hash = old.hash();
        let legacy_path = store.get_path(&space, &hash, 0);
        assert_eq!(
            legacy_path.file_name().unwrap(),
            base64::encode_config(hash.as_ref(), base64::URL_SAFE).as_str()
        );
        ImmutableWriteStore::<memory::MemoryStaging>::persist(&store, &space, old, 0)
            .await
            .unwrap();
        assert_eq!(
            store.read_to_vec(&space, &hash, 0).await.unwrap().unwrap(),
            b"same bytes"
        );
        let mut next = HashBuffer::new(Vec::new());
        next.write_all(b"same bytes").await.unwrap();
        ImmutableWriteStore::<memory::MemoryStaging>::persist(&store, &space, next, 1)
            .await
            .unwrap();
        assert_ne!(legacy_path, store.get_path(&space, &hash, 1));
        assert_eq!(store.total_size(&space).await.unwrap(), Some(20));
        let restarted = FileSystemConfig::new(dir.path()).open().await.unwrap();
        assert_eq!(restarted.total_size(&space).await.unwrap(), Some(20));
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), Some(()));
        assert!(store.contains(&space, &hash, 1).await.unwrap());
        assert_eq!(
            store.read_to_vec(&space, &hash, 1).await.unwrap().unwrap(),
            b"same bytes"
        );
        let RangeRead::Content { mut content, .. } = store
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
        assert_eq!(store.total_size(&space).await.unwrap(), Some(10));
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), None);
        assert_eq!(store.total_size(&space).await.unwrap(), Some(10));
        assert_eq!(store.remove(&space, &hash, 1).await.unwrap(), Some(()));
        assert_eq!(store.total_size(&space).await.unwrap(), Some(0));
    }

    /// TC-887: a store holding sealed objects under `v1/` still opens (the
    /// directory is not a DID), and counts their plaintext bytes per space
    /// tag, never under a space. A stage there is charged its stored bytes.
    #[tokio::test]
    async fn boot_scan_counts_sealed_objects_by_tag() {
        use tinycloud_core::at_rest::ciphertext_len;
        let dir = tempfile::tempdir().unwrap();
        let space_id: SpaceId = "tinycloud:key:test:default".parse().unwrap();
        let legacy = dir
            .path()
            .join(space_id.suffix())
            .join(space_id.name().as_str());
        std::fs::create_dir_all(&legacy).unwrap();
        std::fs::write(legacy.join("obj"), [1u8; 11]).unwrap();
        let tag = dir.path().join(SEALED_DIR).join("tagA");
        std::fs::create_dir_all(&tag).unwrap();
        for (name, plain) in [("o1", 100u64), ("o2@1", 70_000)] {
            let len = ciphertext_len(plain).unwrap() as usize;
            std::fs::write(tag.join(name), vec![0u8; len]).unwrap();
        }
        // Not a valid TCE1 length: counted as 0.
        std::fs::write(tag.join("bad"), [0u8; 70]).unwrap();
        let stage = tag.join(".tc-stage-o3-x");
        std::fs::write(&stage, [0u8; 30]).unwrap();

        let store = FileSystemConfig::new(dir.path()).open().await.unwrap();
        assert_eq!(store.total_size(&space_id).await.unwrap(), Some(11));
        assert_eq!(
            store.sizes.get_size(&space_id, Some("tagA")).await,
            Some(11 + 100 + 70_000 + 30)
        );
        assert_eq!(store.boot_stages.lock().await.get(&stage), Some(&30));
    }
}

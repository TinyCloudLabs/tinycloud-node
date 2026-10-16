#[cfg(test)]
use super::TestPause;
use super::{size::SpaceSizes, BlobGenerationKey, BlobOperationLocks};
use core::pin::Pin;
use futures::{
    future::{Either as AsyncEither, TryFutureExt},
    io::{AsyncWrite, AsyncWriteExt},
    stream::TryStreamExt,
    task::{Context, Poll},
};
use pin_project::pin_project;
use serde::{Deserialize, Serialize};
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
use tinycloud_core::{hash::Hash, storage::*};
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
    operations: BlobOperationLocks,
    #[cfg(test)]
    before_memory_write: TestPause,
    #[cfg(test)]
    after_memory_contains: TestPause,
}

impl FileSystemStore {
    async fn new(path: PathBuf) -> Result<Self, IoError> {
        // get the size of the directory
        let sizes = store_sizes(&path).await?.into();
        Ok(Self {
            path,
            sizes,
            pending: Arc::new(Mutex::new(HashMap::new())),
            operations: BlobOperationLocks::default(),
            #[cfg(test)]
            before_memory_write: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            after_memory_contains: Arc::new(Mutex::new(None)),
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

    async fn increment_size(&self, space: &SpaceId, size: u64) {
        self.sizes.increment_size(space, size).await;
    }
    async fn decrement_size(&self, space: &SpaceId, size: u64) {
        self.sizes.decrement_size(space, size).await;
    }

    async fn reserve(&self, space: &SpaceId, hash: Hash, generation: i64, size: u64) {
        let mut pending = self.pending.lock().await;
        if let Entry::Vacant(slot) = pending.entry((space.clone(), hash, generation)) {
            slot.insert(size);
            self.increment_size(space, size).await;
        }
    }

    async fn settle(&self, space: &SpaceId, hash: Hash, generation: i64) {
        self.pending
            .lock()
            .await
            .remove(&(space.clone(), hash, generation));
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
        refund_each: bool,
    ) -> Result<u64, IoError> {
        let Some(parent) = path.parent() else {
            return Ok(0);
        };
        let mut entries = match tokio::fs::read_dir(parent).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error),
        };
        let prefix = Self::stage_prefix(path);
        let mut removed = 0u64;
        while let Some(entry) = entries.next_entry().await? {
            if !entry.file_name().to_string_lossy().starts_with(&prefix)
                || !entry.file_type().await?.is_file()
            {
                continue;
            }
            let size = entry.metadata().await?.len();
            match remove_file(entry.path()).await {
                Ok(()) => {
                    removed = removed
                        .checked_add(size)
                        .ok_or_else(|| IoError::other("staged blob byte count overflow"))?;
                    if refund_each {
                        self.decrement_size(space, size).await;
                    }
                }
                Err(error) if error.kind() == ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(removed)
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
        if self.contains(space, &hash, generation).await? {
            self.settle(space, hash, generation).await;
            return Ok(());
        }
        let size = file.size().await?;
        self.reserve(space, hash, generation, size).await;
        let (_, path) = file.into_inner();
        path.persist(self.get_path(space, &hash, generation))?;
        self.settle(space, hash, generation).await;
        Ok(())
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
        if self.contains(space, &hash, generation).await? {
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
        self.reserve(space, hash, generation, bytes.len() as u64)
            .await;
        let target = self.get_path(space, &hash, generation);
        // Stage on the target filesystem so the final rename is atomic and
        // never depends on a cross-device copy.
        let staged = tempfile::Builder::new()
            .prefix(&Self::stage_prefix(&target))
            .tempfile_in(target.parent().expect("blob path has a parent"))?;
        let (file, path) = staged.into_parts();
        #[cfg(test)]
        let pause = self.before_memory_write.lock().await.take();
        #[cfg(test)]
        if let Some((entered, release)) = pause {
            entered.notify_one();
            release.notified().await;
        }
        let mut writer = File::from_std(file).compat();
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        drop(writer);
        path.persist(target)?;
        self.settle(space, hash, generation).await;
        Ok(())
    }
}

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
        self.sizes.init_size(space.clone()).await;
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
}

#[async_trait]
impl ImmutableReadStore for FileSystemStore {
    type Error = FileSystemStoreError;
    type Readable = Compat<tokio::io::Take<File>>;
    async fn contains(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<bool, Self::Error> {
        Ok(self.get_path(space, id, generation).exists())
    }
    async fn read(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        let start = Instant::now();
        let result = match File::open(self.get_path(space, id, generation)).await {
            Ok(file) => {
                let size = file.metadata().await?.len();
                Ok(Some(Content::new(size, file.take(size).compat())))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
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
        match File::open(self.get_path(space, id, generation)).await {
            Ok(mut file) => {
                let total_size = file.metadata().await?.len();
                let Some(range) = range.resolve(total_size) else {
                    return Ok(Some(RangeRead::Unsatisfiable { total_size }));
                };
                file.seek(SeekFrom::Start(range.start())).await?;
                let content = Content::new(range.len(), file.take(range.len()).compat());
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
}

#[async_trait]
impl StoreSize for FileSystemStore {
    type Error = FileSystemStoreError;
    async fn total_size(&self, space: &SpaceId) -> Result<Option<u64>, Self::Error> {
        Ok(self.sizes.get_size(space).await)
    }
}

// get the sum size of all files in this directory (recurse into subdirectories with space ID names)
async fn store_sizes<P: AsRef<Path>>(path: &P) -> Result<HashMap<SpaceId, u64>, IoError> {
    ReadDirStream::new(tokio::fs::read_dir(path).await?)
        // for every entry in the store dir
        .try_fold(HashMap::new(), |mut acc, entry| async move {
            // if its a directory and the suffix is a valid string
            if let (true, Ok(ref suffix)) = (
                entry.metadata().await?.is_dir(),
                entry.file_name().into_string(),
            ) {
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
                        let size = space_size(&entry.path()).await?;
                        acc.insert(space, size);
                    }
                }
            };
            Ok(acc)
        })
        .await
}

async fn space_size<P: AsRef<Path>>(path: &P) -> Result<u64, IoError> {
    // get the sum size of all files in this directory (do not recurse into subdirectories)
    ReadDirStream::new(tokio::fs::read_dir(path).await?)
        .try_fold(0, |acc, entry| async move {
            entry
                .metadata()
                .map_ok(|m| if m.is_dir() { acc } else { acc + m.len() })
                .await
        })
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
            self.persist_temp(space, hash, generation, f).await?;
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
            self.persist_memory(space, hash, generation, v).await?;
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

            match f {
                AsyncEither::Left(file) => self.persist_temp(space, hash, generation, file).await?,
                AsyncEither::Right(bytes) => {
                    self.persist_memory(space, hash, generation, bytes).await?
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
impl ImmutableDeleteStore for FileSystemStore {
    type Error = FileSystemStoreError;
    async fn remove(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<()>, Self::Error> {
        let key = (space.clone(), *id, generation);
        let _operation = self.operations.lock(key.clone()).await;
        let path = self.get_path(space, id, generation);
        let pending = self.pending.lock().await.contains_key(&key);
        // A crash can leave a named, incomplete memory stage. Boot counted
        // its actual bytes; a live reservation instead counted its full size.
        let staged = self.remove_stages(space, &path, !pending).await?;
        let final_size = match metadata(&path).await {
            Ok(meta) => Some(meta.len()),
            Err(error) if error.kind() == ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        let removed_final = if let Some(size) = final_size {
            match remove_file(&path).await {
                Ok(()) => Some(size),
                Err(error) if error.kind() == ErrorKind::NotFound => None,
                Err(error) => return Err(error.into()),
            }
        } else {
            None
        };
        if pending {
            let reserved = self.pending.lock().await.remove(&key).unwrap_or(0);
            self.decrement_size(
                space,
                reserved.max(staged.saturating_add(removed_final.unwrap_or(0))),
            )
            .await;
        } else if let Some(size) = removed_final {
            self.decrement_size(space, size).await;
        }
        Ok((removed_final.is_some() || staged != 0).then_some(()))
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
        assert_eq!(store.total_size(&space).await.unwrap(), Some(12));
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), None);
        assert!(!store.contains(&space, &hash, 0).await.unwrap());
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
}

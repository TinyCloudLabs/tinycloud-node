use super::{size::SpaceSizes, BlobGenerationKey};
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
    // A partial filesystem write can fail after creating a file. Reserve
    // before writing and refund the full reservation when deleting it.
    pending: Arc<Mutex<HashMap<BlobGenerationKey, u64>>>,
}

impl FileSystemStore {
    async fn new(path: PathBuf) -> Result<Self, IoError> {
        // get the size of the directory
        let sizes = store_sizes(&path).await?.into();
        Ok(Self {
            path,
            sizes,
            pending: Arc::new(Mutex::new(HashMap::new())),
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

    async fn refund_missing_pending(&self, space: &SpaceId, hash: Hash, generation: i64) {
        if let Some(size) = self
            .pending
            .lock()
            .await
            .remove(&(space.clone(), hash, generation))
        {
            self.decrement_size(space, size).await;
        }
    }

    async fn persist_temp(
        &self,
        space: &SpaceId,
        hash: Hash,
        generation: i64,
        file: TempFileStage,
    ) -> Result<(), FileSystemStoreError> {
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
        if self.contains(space, &hash, generation).await? {
            self.settle(space, hash, generation).await;
            return Ok(());
        }
        self.reserve(space, hash, generation, bytes.len() as u64)
            .await;
        let file = File::create(self.get_path(space, &hash, generation)).await?;
        let mut writer = futures::io::BufWriter::new(file.compat());
        writer.write_all(&bytes).await?;
        writer.flush().await?;
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
        let path = self.get_path(space, id, generation);
        let size = match metadata(&path).await {
            Ok(m) => m.len(),
            Err(e) if e.kind() == ErrorKind::NotFound => {
                self.refund_missing_pending(space, *id, generation).await;
                return Ok(None);
            }
            Err(e) => return Err(e.into()),
        };
        match remove_file(path).await {
            Ok(()) => {
                let charged = self
                    .pending
                    .lock()
                    .await
                    .remove(&(space.clone(), *id, generation))
                    .unwrap_or(size);
                self.decrement_size(space, charged).await;
                Ok(Some(()))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                self.refund_missing_pending(space, *id, generation).await;
                Ok(None)
            }
            Err(e) => Err(e.into()),
        }
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

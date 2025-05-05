use crate::hash::Hash;
use crate::storage::{
    Content, HashBuffer, ImmutableDeleteStore, ImmutableReadStore, ImmutableStaging,
    ImmutableWriteStore, KeyedWriteError, StorageConfig, StorageSetup, StoreSize, VecReadError,
};
use dashmap::DashMap;
use futures::io::{AsyncRead, AsyncWrite, Cursor};
use sea_orm_migration::async_trait::async_trait;
use std::{io, pin::Pin, sync::Arc};
use tinycloud_lib::resource::OrbitId;

#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    orbits: Arc<DashMap<OrbitId, Arc<DashMap<Hash, Vec<u8>>>>>,
}

#[derive(Debug, Clone, Default)]
pub struct MemoryStoreConfig;

#[async_trait]
impl StorageConfig<MemoryStore> for MemoryStoreConfig {
    type Error = io::Error;
    async fn open(&self) -> Result<MemoryStore, Self::Error> {
        Ok(MemoryStore::default())
    }
}

#[async_trait]
impl StorageSetup for MemoryStore {
    type Error = io::Error;
    async fn create(&self, orbit: &OrbitId) -> Result<(), Self::Error> {
        self.orbits
            .entry(orbit.clone())
            .or_insert_with(|| Arc::new(DashMap::new()));
        Ok(())
    }
}

#[async_trait]
impl ImmutableReadStore for MemoryStore {
    type Error = io::Error;
    type Readable = Cursor<Vec<u8>>;

    async fn contains(&self, orbit: &OrbitId, id: &Hash) -> Result<bool, Self::Error> {
        Ok(self
            .orbits
            .get(orbit)
            .map(|o| o.contains_key(id))
            .unwrap_or(false))
    }

    async fn read(
        &self,
        orbit: &OrbitId,
        id: &Hash,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        match self.orbits.get(orbit) {
            Some(o) => match o.get(id) {
                Some(data) => {
                    let len = data.len() as u64;
                    let reader = Cursor::new(data.clone());
                    Ok(Some(Content::new(len, reader)))
                }
                None => Ok(None),
            },
            None => Ok(None),
        }
    }

    async fn read_to_vec(
        &self,
        orbit: &OrbitId,
        id: &Hash,
    ) -> Result<Option<Vec<u8>>, VecReadError<Self::Error>> {
        match self.orbits.get(orbit) {
            Some(o) => Ok(o.get(id).map(|data| data.clone())),
            None => Ok(None),
        }
    }
}

// Use Vec<u8> as the staging buffer directly
pub struct MemoryStagingBuffer(Cursor<Vec<u8>>);

impl MemoryStagingBuffer {
    fn new() -> Self {
        Self(Cursor::new(Vec::new()))
    }

    fn into_inner(self) -> Vec<u8> {
        self.0.into_inner()
    }
}

impl AsyncWrite for MemoryStagingBuffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

#[async_trait]
impl ImmutableStaging for MemoryStore {
    type Error = io::Error;
    type Writable = MemoryStagingBuffer;

    async fn get_staging_buffer(&self, _orbit: &OrbitId) -> Result<Self::Writable, Self::Error> {
        // Ensure the orbit exists, though staging doesn't strictly need it yet
        // self.create(orbit).await?; // Not strictly necessary here
        Ok(MemoryStagingBuffer::new())
    }
}

#[async_trait]
impl ImmutableWriteStore<MemoryStore> for MemoryStore {
    type Error = io::Error;

    async fn persist(
        &self,
        orbit: &OrbitId,
        mut staged: HashBuffer<MemoryStagingBuffer>,
    ) -> Result<Hash, Self::Error> {
        let hash = staged.hash();
        let (_hasher, staging_buffer) = staged.into_inner();
        let data = staging_buffer.into_inner(); // MemoryStagingBuffer -> Vec<u8>

        let orbit_storage = self
            .orbits
            .entry(orbit.clone())
            .or_insert_with(|| Arc::new(DashMap::new()))
            .clone(); // Clone the Arc<DashMap>

        orbit_storage.insert(hash, data);
        Ok(hash)
    }

    async fn persist_keyed(
        &self,
        orbit: &OrbitId,
        mut staged: HashBuffer<MemoryStagingBuffer>,
        hash: &Hash,
    ) -> Result<(), KeyedWriteError<Self::Error>> {
        if hash != &staged.hash() {
            return Err(KeyedWriteError::IncorrectHash);
        };
        let (_hasher, staging_buffer) = staged.into_inner();
        let data = staging_buffer.into_inner();

        let orbit_storage = self
            .orbits
            .entry(orbit.clone())
            .or_insert_with(|| Arc::new(DashMap::new()))
            .clone();

        orbit_storage.insert(*hash, data);
        Ok(())
    }
}

#[async_trait]
impl ImmutableDeleteStore for MemoryStore {
    type Error = io::Error;

    async fn remove(&self, orbit: &OrbitId, id: &Hash) -> Result<Option<()>, Self::Error> {
        Ok(self.orbits.get(orbit).and_then(|o| o.remove(id)).map(|_| ()))
    }
}

#[async_trait]
impl StoreSize for MemoryStore {
    type Error = io::Error;

    async fn total_size(&self, orbit: &OrbitId) -> Result<Option<u64>, Self::Error> {
        Ok(self.orbits.get(orbit).map(|o| {
            o.iter()
                .map(|entry| entry.value().len() as u64)
                .sum::<u64>()
        }))
    }
}

use crate::hash::Hash;
use crate::storage::{
    Content, HashBuffer, ImmutableDeleteStore, ImmutableReadStore, ImmutableStaging,
    ImmutableWriteStore, KeyedWriteError, StorageConfig, StorageSetup, StoreSize, VecReadError,
};
use dashmap::DashMap;
use futures::io::Cursor;
use sea_orm_migration::async_trait::async_trait;
use std::{io, sync::Arc};
use tinycloud_lib::resource::OrbitId;

#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    orbits: Arc<DashMap<OrbitId, Arc<Blocks>>>,
}

type Blocks = DashMap<Hash, Vec<u8>>;

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct MemoryStaging;

#[async_trait]
impl ImmutableStaging for MemoryStaging {
    type Writable = Vec<u8>;
    type Error = std::io::Error;
    async fn get_staging_buffer(&self, _: &OrbitId) -> Result<Self::Writable, Self::Error> {
        Ok(Vec::new())
    }
}

#[async_trait]
impl StorageConfig<MemoryStaging> for MemoryStaging {
    type Error = std::convert::Infallible;
    async fn open(&self) -> Result<MemoryStaging, Self::Error> {
        Ok(Self)
    }
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

#[async_trait]
impl ImmutableWriteStore<MemoryStaging> for MemoryStore {
    type Error = io::Error;

    async fn persist(
        &self,
        orbit: &OrbitId,
        mut staged: HashBuffer<Vec<u8>>,
    ) -> Result<Hash, Self::Error> {
        let hash = staged.hash();
        let (_hasher, staging_buffer) = staged.into_inner();
        let data = staging_buffer;

        let orbit_storage = self
            .orbits
            .entry(orbit.clone())
            .or_insert_with(|| Arc::new(DashMap::new()))
            .clone();

        orbit_storage.insert(hash, data);
        Ok(hash)
    }

    async fn persist_keyed(
        &self,
        orbit: &OrbitId,
        mut staged: HashBuffer<Vec<u8>>,
        hash: &Hash,
    ) -> Result<(), KeyedWriteError<Self::Error>> {
        if hash != &staged.hash() {
            return Err(KeyedWriteError::IncorrectHash);
        };
        let (_hasher, staging_buffer) = staged.into_inner();
        let data = staging_buffer;

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
        Ok(self
            .orbits
            .get(orbit)
            .and_then(|o| o.remove(id))
            .map(|_| ()))
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

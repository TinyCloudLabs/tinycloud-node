use crate::hash::Hash;
use crate::storage::{
    ByteRangeSpec, Content, HashBuffer, ImmutableDeleteStore, ImmutableReadStore, ImmutableStaging,
    ImmutableWriteStore, KeyedWriteError, RangeRead, StorageConfig, StorageSetup, StoreSize,
    VecReadError,
};
use dashmap::DashMap;
use futures::io::Cursor;
use sea_orm_migration::async_trait::async_trait;
use std::time::Instant;
use std::{io, sync::Arc};
use tinycloud_auth::resource::SpaceId;

#[derive(Debug, Default, Clone)]
pub struct MemoryStore {
    spaces: Arc<DashMap<SpaceId, Arc<Blocks>>>,
}

type Blocks = DashMap<(Hash, i64), Vec<u8>>;

#[derive(Default, Debug, Clone, Hash, PartialEq, Eq)]
pub struct MemoryStaging;

#[async_trait]
impl ImmutableStaging for MemoryStaging {
    type Writable = Vec<u8>;
    type Error = std::io::Error;
    async fn get_staging_buffer(&self, _: &SpaceId) -> Result<Self::Writable, Self::Error> {
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
    async fn create(&self, space: &SpaceId) -> Result<(), Self::Error> {
        self.spaces
            .entry(space.clone())
            .or_insert_with(|| Arc::new(DashMap::new()));
        Ok(())
    }
}

#[async_trait]
impl ImmutableReadStore for MemoryStore {
    type Error = io::Error;
    type Readable = Cursor<Vec<u8>>;

    async fn contains(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<bool, Self::Error> {
        Ok(self
            .spaces
            .get(space)
            .map(|o| o.contains_key(&(*id, generation)))
            .unwrap_or(false))
    }

    async fn read(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        let start = Instant::now();
        let result = match self.spaces.get(space) {
            Some(o) => match o.get(&(*id, generation)) {
                Some(data) => {
                    let len = data.len() as u64;
                    let reader = Cursor::new(data.clone());
                    Ok(Some(Content::new(len, reader)))
                }
                None => Ok(None),
            },
            None => Ok(None),
        };
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::BlockRead,
            crate::telemetry::StageOutcome::from(result.is_ok()),
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
        let Some(space) = self.spaces.get(space) else {
            return Ok(None);
        };
        let Some(data) = space.get(&(*id, generation)) else {
            return Ok(None);
        };
        let total_size = data.len() as u64;
        let Some(range) = range.resolve(total_size) else {
            return Ok(Some(RangeRead::Unsatisfiable { total_size }));
        };
        let bytes = data[range.start() as usize..=range.end() as usize].to_vec();
        Ok(Some(RangeRead::Content {
            total_size,
            range,
            content: Content::new(bytes.len() as u64, Cursor::new(bytes)),
        }))
    }

    async fn read_to_vec(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<Vec<u8>>, VecReadError<Self::Error>> {
        match self.spaces.get(space) {
            Some(o) => Ok(o.get(&(*id, generation)).map(|data| data.clone())),
            None => Ok(None),
        }
    }
}

#[async_trait]
impl ImmutableWriteStore<MemoryStaging> for MemoryStore {
    type Error = io::Error;

    async fn persist(
        &self,
        space: &SpaceId,
        mut staged: HashBuffer<Vec<u8>>,
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        let start = Instant::now();
        let hash = staged.hash();
        let (_hasher, staging_buffer) = staged.into_inner();
        let data = staging_buffer;

        let space_storage = self
            .spaces
            .entry(space.clone())
            .or_insert_with(|| Arc::new(DashMap::new()))
            .clone();

        space_storage.insert((hash, generation), data);
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::BlockWrite,
            crate::telemetry::StageOutcome::Ok,
            start.elapsed(),
        );
        Ok(hash)
    }

    async fn persist_keyed(
        &self,
        space: &SpaceId,
        mut staged: HashBuffer<Vec<u8>>,
        hash: &Hash,
        generation: i64,
    ) -> Result<(), KeyedWriteError<Self::Error>> {
        let start = Instant::now();
        if hash != &staged.hash() {
            crate::telemetry::observe_stage(
                crate::telemetry::InvocationStage::BlockWrite,
                crate::telemetry::StageOutcome::Error,
                start.elapsed(),
            );
            return Err(KeyedWriteError::IncorrectHash);
        };
        let (_hasher, staging_buffer) = staged.into_inner();
        let data = staging_buffer;

        let space_storage = self
            .spaces
            .entry(space.clone())
            .or_insert_with(|| Arc::new(DashMap::new()))
            .clone();

        space_storage.insert((*hash, generation), data);
        crate::telemetry::observe_stage(
            crate::telemetry::InvocationStage::BlockWrite,
            crate::telemetry::StageOutcome::Ok,
            start.elapsed(),
        );
        Ok(())
    }
}

#[async_trait]
impl ImmutableDeleteStore for MemoryStore {
    type Error = io::Error;

    async fn remove(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<()>, Self::Error> {
        Ok(self
            .spaces
            .get(space)
            .and_then(|o| o.remove(&(*id, generation)))
            .map(|_| ()))
    }
    async fn cleanup_stages(
        &self,
        _space: &SpaceId,
        _id: &Hash,
        _generation: i64,
    ) -> Result<(), Self::Error> {
        // Memory staging has no filesystem artifact after the writer exits.
        Ok(())
    }
}

#[async_trait]
impl StoreSize for MemoryStore {
    type Error = io::Error;

    async fn total_size(&self, space: &SpaceId) -> Result<Option<u64>, Self::Error> {
        Ok(self.spaces.get(space).map(|o| {
            o.iter()
                .map(|entry| entry.value().len() as u64)
                .sum::<u64>()
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn same_hash_generations_are_independent() {
        let store = MemoryStore::default();
        let space: SpaceId = "tinycloud:key:test:memory-generations".parse().unwrap();
        let mut old = HashBuffer::new(Vec::new());
        old.write_all(b"same bytes").await.unwrap();
        let hash = old.hash();
        store.persist(&space, old, 0).await.unwrap();
        let mut next = HashBuffer::new(Vec::new());
        next.write_all(b"same bytes").await.unwrap();
        store.persist(&space, next, 1).await.unwrap();
        assert_eq!(store.total_size(&space).await.unwrap(), Some(20));
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), Some(()));
        assert!(!store.contains(&space, &hash, 0).await.unwrap());
        assert!(store.contains(&space, &hash, 1).await.unwrap());
        assert_eq!(
            store.read_to_vec(&space, &hash, 1).await.unwrap(),
            Some(b"same bytes".to_vec())
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
            panic!("expected range");
        };
        let mut bytes = Vec::new();
        content.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"bytes");
        assert_eq!(store.remove(&space, &hash, 0).await.unwrap(), None);
        assert_eq!(store.total_size(&space).await.unwrap(), Some(10));
    }
}

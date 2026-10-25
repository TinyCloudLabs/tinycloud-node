use crate::{hash::Hash, storage::*};
use futures::future::Either as AsyncEither;
use sea_orm_migration::async_trait::async_trait;
use tinycloud_auth::resource::SpaceId;

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum Either<A, B> {
    A(A),
    B(B),
}

#[derive(thiserror::Error, Debug)]
pub enum EitherError<A, B> {
    #[error(transparent)]
    A(A),
    #[error(transparent)]
    B(B),
}

#[async_trait]
impl<A, B> ImmutableReadStore for Either<A, B>
where
    A: ImmutableReadStore,
    B: ImmutableReadStore,
{
    type Readable = AsyncEither<A::Readable, B::Readable>;
    type Error = EitherError<A::Error, B::Error>;
    async fn contains(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<bool, Self::Error> {
        match self {
            Self::A(l) => l
                .contains(space, id, generation)
                .await
                .map_err(Self::Error::A),
            Self::B(r) => r
                .contains(space, id, generation)
                .await
                .map_err(Self::Error::B),
        }
    }
    async fn read(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        match self {
            Self::A(l) => l
                .read(space, id, generation)
                .await
                .map(|o| {
                    o.map(|c| {
                        let (l, r) = c.into_inner();
                        Content::new(l, Self::Readable::Left(r))
                    })
                })
                .map_err(Self::Error::A),
            Self::B(r) => r
                .read(space, id, generation)
                .await
                .map(|o| {
                    o.map(|c| {
                        let (l, r) = c.into_inner();
                        Content::new(l, Self::Readable::Right(r))
                    })
                })
                .map_err(Self::Error::B),
        }
    }

    async fn read_range(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
        range: ByteRangeSpec,
    ) -> Result<Option<RangeRead<Self::Readable>>, Self::Error> {
        match self {
            Self::A(store) => store
                .read_range(space, id, generation, range)
                .await
                .map(|read| {
                    read.map(|read| match read {
                        RangeRead::Content {
                            total_size,
                            range,
                            content,
                        } => {
                            let (size, reader) = content.into_inner();
                            RangeRead::Content {
                                total_size,
                                range,
                                content: Content::new(size, AsyncEither::Left(reader)),
                            }
                        }
                        RangeRead::Unsatisfiable { total_size } => {
                            RangeRead::Unsatisfiable { total_size }
                        }
                    })
                })
                .map_err(Self::Error::A),
            Self::B(store) => store
                .read_range(space, id, generation, range)
                .await
                .map(|read| {
                    read.map(|read| match read {
                        RangeRead::Content {
                            total_size,
                            range,
                            content,
                        } => {
                            let (size, reader) = content.into_inner();
                            RangeRead::Content {
                                total_size,
                                range,
                                content: Content::new(size, AsyncEither::Right(reader)),
                            }
                        }
                        RangeRead::Unsatisfiable { total_size } => {
                            RangeRead::Unsatisfiable { total_size }
                        }
                    })
                })
                .map_err(Self::Error::B),
        }
    }
}

#[async_trait]
impl<A, B> ImmutableStaging for Either<A, B>
where
    A: ImmutableStaging,
    B: ImmutableStaging,
{
    type Writable = AsyncEither<A::Writable, B::Writable>;
    type Error = EitherError<A::Error, B::Error>;
    async fn get_staging_buffer(&self, space: &SpaceId) -> Result<Self::Writable, Self::Error> {
        match self {
            Self::A(l) => l
                .get_staging_buffer(space)
                .await
                .map(AsyncEither::Left)
                .map_err(Self::Error::A),
            Self::B(r) => r
                .get_staging_buffer(space)
                .await
                .map(AsyncEither::Right)
                .map_err(Self::Error::B),
        }
    }
}

#[async_trait]
impl<A, B, S> ImmutableWriteStore<S> for Either<A, B>
where
    A: ImmutableWriteStore<S>,
    B: ImmutableWriteStore<S>,
    S: ImmutableStaging,
    S::Writable: 'static,
{
    type Error = EitherError<A::Error, B::Error>;
    async fn persist(
        &self,
        space: &SpaceId,
        staged: HashBuffer<S::Writable>,
        generation: i64,
    ) -> Result<Hash, Self::Error> {
        match self {
            Self::A(a) => a
                .persist(space, staged, generation)
                .await
                .map_err(Self::Error::A),
            Self::B(b) => b
                .persist(space, staged, generation)
                .await
                .map_err(Self::Error::B),
        }
    }
}

#[async_trait]
impl<A, B, SA, SB> StorageConfig<Either<SA, SB>> for Either<A, B>
where
    A: StorageConfig<SA> + Sync,
    B: StorageConfig<SB> + Sync,
{
    type Error = EitherError<A::Error, B::Error>;
    async fn open(&self) -> Result<Either<SA, SB>, Self::Error> {
        match self {
            Self::A(a) => a.open().await.map(Either::A).map_err(Self::Error::A),
            Self::B(b) => b.open().await.map(Either::B).map_err(Self::Error::B),
        }
    }
}

#[async_trait]
impl<A, B> StorageSetup for Either<A, B>
where
    A: StorageSetup + Sync,
    B: StorageSetup + Sync,
{
    type Error = EitherError<A::Error, B::Error>;
    async fn create(&self, space: &SpaceId) -> Result<(), Self::Error> {
        match self {
            Self::A(a) => a.create(space).await.map_err(Self::Error::A),
            Self::B(b) => b.create(space).await.map_err(Self::Error::B),
        }
    }
}

#[async_trait]
impl<A, B> ImmutableDeleteStore for Either<A, B>
where
    A: ImmutableDeleteStore,
    B: ImmutableDeleteStore,
{
    type Error = EitherError<A::Error, B::Error>;
    async fn remove(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<Option<()>, Self::Error> {
        match self {
            Self::A(l) => l
                .remove(space, id, generation)
                .await
                .map_err(Self::Error::A),
            Self::B(r) => r
                .remove(space, id, generation)
                .await
                .map_err(Self::Error::B),
        }
    }
    async fn cleanup_stages(
        &self,
        space: &SpaceId,
        id: &Hash,
        generation: i64,
    ) -> Result<(), Self::Error> {
        match self {
            Self::A(store) => store
                .cleanup_stages(space, id, generation)
                .await
                .map_err(Self::Error::A),
            Self::B(store) => store
                .cleanup_stages(space, id, generation)
                .await
                .map_err(Self::Error::B),
        }
    }
}

#[async_trait]
impl<A, B> StoreSize for Either<A, B>
where
    A: StoreSize,
    B: StoreSize,
{
    type Error = EitherError<A::Error, B::Error>;
    async fn total_size(&self, space: &SpaceId) -> Result<Option<u64>, Self::Error> {
        match self {
            Either::A(a) => a.total_size(space).await.map_err(EitherError::A),
            Either::B(b) => b.total_size(space).await.map_err(EitherError::B),
        }
    }
    async fn init_size(&self, space: &SpaceId) -> Result<u64, Self::Error> {
        match self {
            Either::A(a) => a.init_size(space).await.map_err(EitherError::A),
            Either::B(b) => b.init_size(space).await.map_err(EitherError::B),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn either_dispatches_each_generation() {
        let space: SpaceId = "tinycloud:key:test:either-generations".parse().unwrap();
        for store in [
            Either::A(MemoryStore::default()),
            Either::B(MemoryStore::default()),
        ] {
            let mut old = HashBuffer::new(Vec::new());
            old.write_all(b"same bytes").await.unwrap();
            let hash = old.hash();
            store.persist(&space, old, 0).await.unwrap();
            let mut next = HashBuffer::new(Vec::new());
            next.write_all(b"same bytes").await.unwrap();
            store.persist(&space, next, 1).await.unwrap();
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
        }
    }
}

use crate::{hash::Hash, storage::*};
use futures::future::Either as AsyncEither;
use sea_orm_migration::async_trait::async_trait;
use tinycloud_lib::resource::NamespaceId;

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
    async fn contains(&self, namespace: &NamespaceId, id: &Hash) -> Result<bool, Self::Error> {
        match self {
            Self::A(l) => l.contains(namespace, id).await.map_err(Self::Error::A),
            Self::B(r) => r.contains(namespace, id).await.map_err(Self::Error::B),
        }
    }
    async fn read(
        &self,
        namespace: &NamespaceId,
        id: &Hash,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        match self {
            Self::A(l) => l
                .read(namespace, id)
                .await
                .map(|o| {
                    o.map(|c| {
                        let (l, r) = c.into_inner();
                        Content::new(l, Self::Readable::Left(r))
                    })
                })
                .map_err(Self::Error::A),
            Self::B(r) => r
                .read(namespace, id)
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
}

#[async_trait]
impl<A, B> ImmutableStaging for Either<A, B>
where
    A: ImmutableStaging,
    B: ImmutableStaging,
{
    type Writable = AsyncEither<A::Writable, B::Writable>;
    type Error = EitherError<A::Error, B::Error>;
    async fn get_staging_buffer(&self, namespace: &NamespaceId) -> Result<Self::Writable, Self::Error> {
        match self {
            Self::A(l) => l
                .get_staging_buffer(namespace)
                .await
                .map(AsyncEither::Left)
                .map_err(Self::Error::A),
            Self::B(r) => r
                .get_staging_buffer(namespace)
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
        namespace: &NamespaceId,
        staged: HashBuffer<S::Writable>,
    ) -> Result<Hash, Self::Error> {
        match self {
            Self::A(a) => a.persist(namespace, staged).await.map_err(Self::Error::A),
            Self::B(b) => b.persist(namespace, staged).await.map_err(Self::Error::B),
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
    async fn create(&self, namespace: &NamespaceId) -> Result<(), Self::Error> {
        match self {
            Self::A(a) => a.create(namespace).await.map_err(Self::Error::A),
            Self::B(b) => b.create(namespace).await.map_err(Self::Error::B),
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
    async fn remove(&self, namespace: &NamespaceId, id: &Hash) -> Result<Option<()>, Self::Error> {
        match self {
            Self::A(l) => l.remove(namespace, id).await.map_err(Self::Error::A),
            Self::B(r) => r.remove(namespace, id).await.map_err(Self::Error::B),
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
    async fn total_size(&self, namespace: &NamespaceId) -> Result<Option<u64>, Self::Error> {
        match self {
            Either::A(a) => a.total_size(namespace).await.map_err(EitherError::A),
            Either::B(b) => b.total_size(namespace).await.map_err(EitherError::B),
        }
    }
}

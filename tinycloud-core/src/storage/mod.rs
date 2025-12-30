use crate::hash::Hash;
use sea_orm_migration::async_trait::async_trait;
use std::error::Error as StdError;
use tinycloud_lib::resource::NamespaceId;

pub mod either;
pub mod memory;
mod util;
pub use memory::{MemoryStore, MemoryStoreConfig};
pub use util::{Content, HashBuffer};

#[async_trait]
pub trait StorageConfig<S> {
    type Error: StdError;
    async fn open(&self) -> Result<S, Self::Error>;
}

#[async_trait]
pub trait StorageSetup {
    type Error: StdError;
    async fn create(&self, namespace: &NamespaceId) -> Result<(), Self::Error>;
}

#[derive(thiserror::Error, Debug)]
pub enum VecReadError<E> {
    #[error(transparent)]
    Store(#[from] E),
    #[error(transparent)]
    Read(futures::io::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum KeyedWriteError<E> {
    #[error("Hash Mismatch")]
    IncorrectHash,
    #[error(transparent)]
    Store(#[from] E),
}

/// A Store implementing content-addressed storage
/// Content is addressed by [Multihash][libipld::cid::multihash::Multihash] and represented as an
/// [AsyncRead][futures::io::AsyncRead]-implementing type.
#[async_trait]
pub trait ImmutableReadStore: Send + Sync {
    type Error: StdError + Send + Sync;
    type Readable: futures::io::AsyncRead + Send + Sync;
    async fn contains(&self, namespace: &NamespaceId, id: &Hash) -> Result<bool, Self::Error>;
    async fn read(
        &self,
        namespace: &NamespaceId,
        id: &Hash,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error>;
    async fn read_to_vec(
        &self,
        namespace: &NamespaceId,
        id: &Hash,
    ) -> Result<Option<Vec<u8>>, VecReadError<Self::Error>>
    where
        Self::Readable: Send,
    {
        use futures::io::AsyncReadExt;
        let (l, r) = match self.read(namespace, id).await? {
            None => return Ok(None),
            Some(r) => r.into_inner(),
        };
        let mut v = Vec::with_capacity(l as usize);
        Box::pin(r)
            .read_to_end(&mut v)
            .await
            .map_err(VecReadError::Read)?;
        Ok(Some(v))
    }
}

#[async_trait]
pub trait ImmutableStaging: Send + Sync {
    type Error: StdError + Send + Sync;
    type Writable: futures::io::AsyncWrite + Send + Sync;
    async fn stage(
        &self,
        namespace: &NamespaceId,
    ) -> Result<HashBuffer<Self::Writable>, Self::Error> {
        self.get_staging_buffer(namespace)
            .await
            .map(HashBuffer::new)
    }
    async fn get_staging_buffer(
        &self,
        namespace: &NamespaceId,
    ) -> Result<Self::Writable, Self::Error>;
}

#[async_trait]
pub trait ImmutableWriteStore<S>: Send + Sync
where
    S: ImmutableStaging,
    S::Writable: 'static,
{
    type Error: StdError + Send + Sync;
    async fn persist(
        &self,
        namespace: &NamespaceId,
        staged: HashBuffer<S::Writable>,
    ) -> Result<Hash, Self::Error>;
    async fn persist_keyed(
        &self,
        namespace: &NamespaceId,
        mut staged: HashBuffer<S::Writable>,
        hash: &Hash,
    ) -> Result<(), KeyedWriteError<Self::Error>> {
        if hash != &staged.hash() {
            return Err(KeyedWriteError::IncorrectHash);
        };
        self.persist(namespace, staged).await?;
        Ok(())
    }
}

#[async_trait]
pub trait ImmutableDeleteStore: Send + Sync {
    type Error: StdError + Send + Sync;
    async fn remove(&self, namespace: &NamespaceId, id: &Hash) -> Result<Option<()>, Self::Error>;
}

#[async_trait]
pub trait StoreSize: Send + Sync {
    type Error: StdError;
    async fn total_size(&self, namespace: &NamespaceId) -> Result<Option<u64>, Self::Error>;
}

#[async_trait]
impl<S> ImmutableReadStore for Box<S>
where
    S: ImmutableReadStore,
{
    type Error = S::Error;
    type Readable = S::Readable;
    async fn contains(&self, namespace: &NamespaceId, id: &Hash) -> Result<bool, Self::Error> {
        self.contains(namespace, id).await
    }
    async fn read(
        &self,
        namespace: &NamespaceId,
        id: &Hash,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        self.read(namespace, id).await
    }
    async fn read_to_vec(
        &self,
        namespace: &NamespaceId,
        id: &Hash,
    ) -> Result<Option<Vec<u8>>, VecReadError<Self::Error>>
    where
        Self::Readable: Send,
    {
        self.read_to_vec(namespace, id).await
    }
}

#[async_trait]
impl<S> ImmutableStaging for Box<S>
where
    S: ImmutableStaging,
{
    type Error = S::Error;
    type Writable = S::Writable;
    async fn get_staging_buffer(
        &self,
        namespace: &NamespaceId,
    ) -> Result<Self::Writable, Self::Error> {
        self.get_staging_buffer(namespace).await
    }
}

#[async_trait]
impl<S, W> ImmutableWriteStore<W> for Box<S>
where
    S: ImmutableWriteStore<W>,
    W: ImmutableStaging,
    W::Writable: 'static,
{
    type Error = S::Error;
    async fn persist(
        &self,
        namespace: &NamespaceId,
        staged: HashBuffer<W::Writable>,
    ) -> Result<Hash, Self::Error> {
        self.persist(namespace, staged).await
    }
    async fn persist_keyed(
        &self,
        namespace: &NamespaceId,
        staged: HashBuffer<W::Writable>,
        hash: &Hash,
    ) -> Result<(), KeyedWriteError<Self::Error>> {
        self.persist_keyed(namespace, staged, hash).await
    }
}

#[async_trait]
impl<S> ImmutableDeleteStore for Box<S>
where
    S: ImmutableDeleteStore,
{
    type Error = S::Error;
    async fn remove(&self, namespace: &NamespaceId, id: &Hash) -> Result<Option<()>, Self::Error> {
        self.remove(namespace, id).await
    }
}

#[async_trait]
impl<S> StoreSize for Box<S>
where
    S: StoreSize,
{
    type Error = S::Error;
    async fn total_size(&self, namespace: &NamespaceId) -> Result<Option<u64>, Self::Error> {
        (**self).total_size(namespace).await
    }
}

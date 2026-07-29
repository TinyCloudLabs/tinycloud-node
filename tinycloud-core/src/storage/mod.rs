use crate::hash::Hash;
use sea_orm_migration::async_trait::async_trait;
use std::error::Error as StdError;
use tinycloud_auth::resource::SpaceId;

pub mod either;
pub mod memory;
mod util;
pub use memory::{MemoryStore, MemoryStoreConfig};
pub use util::{Content, HashBuffer};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ByteRangeSpec {
    Inclusive { start: u64, end: u64 },
    From { start: u64 },
    Suffix { length: u64 },
}

impl ByteRangeSpec {
    pub fn to_http_value(self) -> String {
        match self {
            Self::Inclusive { start, end } => format!("bytes={start}-{end}"),
            Self::From { start } => format!("bytes={start}-"),
            Self::Suffix { length } => format!("bytes=-{length}"),
        }
    }

    pub fn resolve(self, total_size: u64) -> Option<ResolvedByteRange> {
        if total_size == 0 {
            return None;
        }

        let last = total_size - 1;
        match self {
            Self::Inclusive { start, end } if start <= end && start < total_size => {
                Some(ResolvedByteRange {
                    start,
                    end: end.min(last),
                })
            }
            Self::From { start } if start < total_size => {
                Some(ResolvedByteRange { start, end: last })
            }
            Self::Suffix { length } if length > 0 => {
                let length = length.min(total_size);
                Some(ResolvedByteRange {
                    start: total_size - length,
                    end: last,
                })
            }
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResolvedByteRange {
    start: u64,
    end: u64,
}

impl ResolvedByteRange {
    pub fn start(self) -> u64 {
        self.start
    }

    pub fn end(self) -> u64 {
        self.end
    }

    pub fn len(self) -> u64 {
        self.end - self.start + 1
    }

    pub fn is_empty(self) -> bool {
        false
    }
}

#[derive(Debug)]
pub enum RangeRead<R> {
    Content {
        total_size: u64,
        range: ResolvedByteRange,
        content: Content<R>,
    },
    Unsatisfiable {
        total_size: u64,
    },
}

#[async_trait]
pub trait StorageConfig<S> {
    type Error: StdError;
    async fn open(&self) -> Result<S, Self::Error>;
}

#[async_trait]
pub trait StorageSetup {
    type Error: StdError;
    async fn create(&self, space: &SpaceId) -> Result<(), Self::Error>;
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
    async fn contains(&self, space: &SpaceId, id: &Hash) -> Result<bool, Self::Error>;
    async fn read(
        &self,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error>;
    async fn read_range(
        &self,
        space: &SpaceId,
        id: &Hash,
        range: ByteRangeSpec,
    ) -> Result<Option<RangeRead<Self::Readable>>, Self::Error>;
    async fn read_to_vec(
        &self,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Vec<u8>>, VecReadError<Self::Error>>
    where
        Self::Readable: Send,
    {
        use futures::io::AsyncReadExt;
        let (l, r) = match self.read(space, id).await? {
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
    async fn stage(&self, space: &SpaceId) -> Result<HashBuffer<Self::Writable>, Self::Error> {
        self.get_staging_buffer(space).await.map(HashBuffer::new)
    }
    async fn get_staging_buffer(&self, space: &SpaceId) -> Result<Self::Writable, Self::Error>;
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
        space: &SpaceId,
        staged: HashBuffer<S::Writable>,
    ) -> Result<Hash, Self::Error>;
    async fn persist_keyed(
        &self,
        space: &SpaceId,
        mut staged: HashBuffer<S::Writable>,
        hash: &Hash,
    ) -> Result<(), KeyedWriteError<Self::Error>> {
        if hash != &staged.hash() {
            return Err(KeyedWriteError::IncorrectHash);
        };
        self.persist(space, staged).await?;
        Ok(())
    }
}

#[async_trait]
pub trait ImmutableDeleteStore: Send + Sync {
    type Error: StdError + Send + Sync;
    async fn remove(&self, space: &SpaceId, id: &Hash) -> Result<Option<()>, Self::Error>;
}

#[async_trait]
pub trait StoreSize: Send + Sync {
    type Error: StdError;
    async fn total_size(&self, space: &SpaceId) -> Result<Option<u64>, Self::Error>;
}

#[async_trait]
impl<S> ImmutableReadStore for Box<S>
where
    S: ImmutableReadStore,
{
    type Error = S::Error;
    type Readable = S::Readable;
    async fn contains(&self, space: &SpaceId, id: &Hash) -> Result<bool, Self::Error> {
        self.contains(space, id).await
    }
    async fn read(
        &self,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Content<Self::Readable>>, Self::Error> {
        self.read(space, id).await
    }
    async fn read_range(
        &self,
        space: &SpaceId,
        id: &Hash,
        range: ByteRangeSpec,
    ) -> Result<Option<RangeRead<Self::Readable>>, Self::Error> {
        self.read_range(space, id, range).await
    }
    async fn read_to_vec(
        &self,
        space: &SpaceId,
        id: &Hash,
    ) -> Result<Option<Vec<u8>>, VecReadError<Self::Error>>
    where
        Self::Readable: Send,
    {
        self.read_to_vec(space, id).await
    }
}

#[async_trait]
impl<S> ImmutableStaging for Box<S>
where
    S: ImmutableStaging,
{
    type Error = S::Error;
    type Writable = S::Writable;
    async fn get_staging_buffer(&self, space: &SpaceId) -> Result<Self::Writable, Self::Error> {
        self.get_staging_buffer(space).await
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
        space: &SpaceId,
        staged: HashBuffer<W::Writable>,
    ) -> Result<Hash, Self::Error> {
        self.persist(space, staged).await
    }
    async fn persist_keyed(
        &self,
        space: &SpaceId,
        staged: HashBuffer<W::Writable>,
        hash: &Hash,
    ) -> Result<(), KeyedWriteError<Self::Error>> {
        self.persist_keyed(space, staged, hash).await
    }
}

#[async_trait]
impl<S> ImmutableDeleteStore for Box<S>
where
    S: ImmutableDeleteStore,
{
    type Error = S::Error;
    async fn remove(&self, space: &SpaceId, id: &Hash) -> Result<Option<()>, Self::Error> {
        self.remove(space, id).await
    }
}

#[async_trait]
impl<S> StoreSize for Box<S>
where
    S: StoreSize,
{
    type Error = S::Error;
    async fn total_size(&self, space: &SpaceId) -> Result<Option<u64>, Self::Error> {
        (**self).total_size(space).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_http_byte_range_shapes() {
        assert_eq!(
            ByteRangeSpec::Inclusive { start: 2, end: 5 }.resolve(10),
            Some(ResolvedByteRange { start: 2, end: 5 })
        );
        assert_eq!(
            ByteRangeSpec::Inclusive { start: 8, end: 50 }.resolve(10),
            Some(ResolvedByteRange { start: 8, end: 9 })
        );
        assert_eq!(
            ByteRangeSpec::From { start: 7 }.resolve(10),
            Some(ResolvedByteRange { start: 7, end: 9 })
        );
        assert_eq!(
            ByteRangeSpec::Suffix { length: 3 }.resolve(10),
            Some(ResolvedByteRange { start: 7, end: 9 })
        );
        assert_eq!(
            ByteRangeSpec::Suffix { length: 50 }.resolve(10),
            Some(ResolvedByteRange { start: 0, end: 9 })
        );
        assert_eq!(ByteRangeSpec::From { start: 10 }.resolve(10), None);
        assert_eq!(ByteRangeSpec::Suffix { length: 0 }.resolve(10), None);
        assert_eq!(ByteRangeSpec::From { start: 0 }.resolve(0), None);
    }
}

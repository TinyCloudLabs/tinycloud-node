//! In-memory [`SqlObjectStore`] for tests.

use std::{collections::HashMap, sync::Mutex};

use async_trait::async_trait;

use super::key::ObjectKey;
use super::object::{sha256, ObjectMeta, ObjectRange, PutOutcome, SqlObjectStore, SqlStoreError};
use crate::storage::ByteRangeSpec;

#[derive(Default)]
pub struct MemorySqlObjectStore {
    objects: Mutex<HashMap<String, Vec<u8>>>,
}

impl MemorySqlObjectStore {
    pub fn len(&self) -> usize {
        self.objects.lock().unwrap().len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl SqlObjectStore for MemorySqlObjectStore {
    async fn put_if_absent(
        &self,
        key: &ObjectKey,
        body: Vec<u8>,
    ) -> Result<PutOutcome, SqlStoreError> {
        if &sha256(&body) != key.sha256() {
            return Err(SqlStoreError::BodyMismatch);
        }
        let mut objects = self.objects.lock().unwrap();
        match objects.get(key.as_str()) {
            Some(existing) if existing == &body => Ok(PutOutcome::AlreadyPresent),
            Some(_) => Err(SqlStoreError::Conflict),
            None => {
                objects.insert(key.as_str().to_owned(), body);
                Ok(PutOutcome::Created)
            }
        }
    }

    async fn get_range(
        &self,
        key: &ObjectKey,
        range: ByteRangeSpec,
    ) -> Result<Option<ObjectRange>, SqlStoreError> {
        let objects = self.objects.lock().unwrap();
        let Some(body) = objects.get(key.as_str()) else {
            return Ok(None);
        };
        let total = body.len() as u64;
        Ok(range.resolve(total).map(|r| ObjectRange {
            total_size: total,
            start: r.start(),
            data: body[r.start() as usize..=r.end() as usize].to_vec(),
        }))
    }

    async fn head(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>, SqlStoreError> {
        Ok(self
            .objects
            .lock()
            .unwrap()
            .get(key.as_str())
            .map(|body| ObjectMeta {
                bytes: body.len() as u64,
                sha256: sha256(body),
            }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::store::key::{DbRef, Lineage};

    fn key_for(body: &[u8], at: u64) -> ObjectKey {
        ObjectKey::snapshot(
            &DbRef {
                space: "tinycloud:s",
                db_id: "v2n",
            },
            &Lineage::parse(&"11".repeat(16)).unwrap(),
            at,
            &sha256(body),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn put_if_absent_never_overwrites() {
        let store = MemorySqlObjectStore::default();
        let key = key_for(b"abc", 1);
        assert_eq!(
            store.put_if_absent(&key, b"abc".to_vec()).await.unwrap(),
            PutOutcome::Created
        );
        assert_eq!(
            store.put_if_absent(&key, b"abc".to_vec()).await.unwrap(),
            PutOutcome::AlreadyPresent
        );
        // Different bytes under a key that names other bytes are refused.
        assert!(matches!(
            store.put_if_absent(&key, b"abd".to_vec()).await,
            Err(SqlStoreError::BodyMismatch)
        ));
        assert_eq!(store.len(), 1);
        assert_eq!(store.head(&key).await.unwrap().unwrap().bytes, 3);
        let part = store
            .get_range(&key, ByteRangeSpec::Inclusive { start: 1, end: 5 })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            (part.start, part.total_size, part.data),
            (1, 3, b"bc".to_vec())
        );
        assert!(store.head(&key_for(b"zz", 2)).await.unwrap().is_none());
    }
}

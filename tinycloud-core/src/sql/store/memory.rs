//! In-memory [`SqlObjectStore`] for tests.

use std::{collections::HashMap, path::Path, sync::Mutex};

use async_trait::async_trait;

use super::key::ObjectKey;
use super::object::{
    discard_download, sha256, ObjectMeta, ObjectRange, PutOutcome, SqlObjectStore, SqlStoreError,
};
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
    /// The stored bytes of `key`, for test assertions.
    pub fn bytes(&self, key: &str) -> Option<Vec<u8>> {
        self.objects.lock().unwrap().get(key).cloned()
    }
    /// Store `body` under `key` with no check at all, as a corrupt disk or a
    /// foreign writer would; for tests of what reads do with bad bytes.
    pub fn plant(&self, key: &str, body: Vec<u8>) {
        self.objects.lock().unwrap().insert(key.to_owned(), body);
    }
}

#[async_trait]
impl SqlObjectStore for MemorySqlObjectStore {
    async fn put_file(
        &self,
        key: &ObjectKey,
        path: &Path,
        size: u64,
    ) -> Result<PutOutcome, SqlStoreError> {
        let body = tokio::fs::read(path)
            .await
            .map_err(|e| SqlStoreError::file("read", &e))?;
        if body.len() as u64 != size {
            return Err(SqlStoreError::Invalid("body file size does not match"));
        }
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

    async fn get_to_file(
        &self,
        key: &ObjectKey,
        path: &Path,
        max_bytes: u64,
    ) -> Result<Option<ObjectMeta>, SqlStoreError> {
        let Some(body) = self.bytes(key.as_str()) else {
            return Ok(None);
        };
        // Written first and checked after, like a streaming backend, so a
        // refusal must leave the target empty.
        let result = async {
            let delivered = &body[..body.len().min(max_bytes.saturating_add(1) as usize)];
            tokio::fs::write(path, delivered)
                .await
                .map_err(|e| SqlStoreError::file("write", &e))?;
            if body.len() as u64 > max_bytes {
                return Err(SqlStoreError::Oversize);
            }
            let meta = ObjectMeta {
                bytes: body.len() as u64,
                sha256: sha256(&body),
            };
            if &meta.sha256 != key.sha256() {
                return Err(SqlStoreError::BodyMismatch);
            }
            Ok(Some(meta))
        }
        .await;
        if result.is_err() {
            discard_download(path);
        }
        result
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

    fn file_with(dir: &tempfile::TempDir, name: &str, body: &[u8]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, body).unwrap();
        path
    }

    #[tokio::test]
    async fn put_file_never_overwrites_and_get_to_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemorySqlObjectStore::default();
        let key = key_for(b"abc", 1);
        let abc = file_with(&dir, "abc", b"abc");
        assert_eq!(
            store.put_file(&key, &abc, 3).await.unwrap(),
            PutOutcome::Created
        );
        assert_eq!(
            store.put_file(&key, &abc, 3).await.unwrap(),
            PutOutcome::AlreadyPresent
        );
        // Different bytes under a key that names other bytes are refused.
        let abd = file_with(&dir, "abd", b"abd");
        assert!(matches!(
            store.put_file(&key, &abd, 3).await,
            Err(SqlStoreError::BodyMismatch)
        ));
        // A declared size the file does not have is refused.
        assert!(matches!(
            store.put_file(&key, &abc, 4).await,
            Err(SqlStoreError::Invalid(_))
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
        let out = dir.path().join("out");
        let meta = store.get_to_file(&key, &out, 3).await.unwrap().unwrap();
        assert_eq!(meta.bytes, 3);
        assert_eq!(std::fs::read(&out).unwrap(), b"abc");
        assert!(store.head(&key_for(b"zz", 2)).await.unwrap().is_none());
        assert!(store
            .get_to_file(&key_for(b"zz", 2), &out, 3)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn a_refused_download_leaves_no_bytes_in_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let store = MemorySqlObjectStore::default();
        let key = key_for(b"abc", 1);
        let out = dir.path().join("out");
        // More bytes than the recorded size: aborted, the target emptied.
        store.plant(key.as_str(), b"abc".to_vec());
        std::fs::write(&out, b"stale").unwrap();
        assert!(matches!(
            store.get_to_file(&key, &out, 2).await,
            Err(SqlStoreError::Oversize)
        ));
        assert_eq!(std::fs::read(&out).unwrap(), b"");
        // Bytes that do not hash to the key: refused, the target emptied.
        store.plant(key.as_str(), b"abd".to_vec());
        assert!(matches!(
            store.get_to_file(&key, &out, 3).await,
            Err(SqlStoreError::BodyMismatch)
        ));
        assert_eq!(std::fs::read(&out).unwrap(), b"");
    }
}

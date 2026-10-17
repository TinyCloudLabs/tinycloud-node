//! Test-only key provider. Compiled only for this crate's tests or with the
//! `test-util` feature, which downstream crates enable on their
//! `tinycloud-core` dev-dependency only.

use super::key::{DataKey, DekId, ObjectNameKey};
use super::provider::{DataKeyError, DataKeyProvider};
use async_trait::async_trait;
use sha2::{Digest, Sha256};

/// Deterministic in-memory provider for tests. Not for production: every key
/// is derived from a public seed.
///
/// Each space has keys `1..=current`; `current_key` returns `current`.
#[derive(Clone)]
pub struct FixedKeyProvider {
    seed: [u8; 32],
    current: DekId,
    locked: bool,
}

impl std::fmt::Debug for FixedKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FixedKeyProvider")
            .field("current", &self.current)
            .field("locked", &self.locked)
            .finish_non_exhaustive()
    }
}

impl FixedKeyProvider {
    pub fn new(seed: [u8; 32]) -> Self {
        Self {
            seed,
            current: DekId::new(1),
            locked: false,
        }
    }

    /// Every space has keys `1..=current`. Panics on 0.
    pub fn with_current(mut self, current: DekId) -> Self {
        assert!(current.get() > 0, "dek ids start at 1");
        self.current = current;
        self
    }

    /// A provider that behaves like a node booted locked.
    pub fn locked(mut self) -> Self {
        self.locked = true;
        self
    }

    fn derive(&self, label: &[u8], space: &str, dek_id: u32) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(label);
        h.update(self.seed);
        h.update((space.len() as u32).to_be_bytes());
        h.update(space.as_bytes());
        h.update(dek_id.to_be_bytes());
        h.finalize().into()
    }
}

#[async_trait]
impl DataKeyProvider for FixedKeyProvider {
    async fn current_key(&self, space: &str) -> Result<DataKey, DataKeyError> {
        self.key(space, self.current).await
    }

    async fn key(&self, space: &str, dek_id: DekId) -> Result<DataKey, DataKeyError> {
        if self.locked {
            return Err(DataKeyError::Locked);
        }
        if dek_id.get() == 0 || dek_id > self.current {
            return Err(DataKeyError::UnknownKey { dek_id });
        }
        Ok(DataKey::new(
            dek_id,
            self.derive(b"tinycloud/at-rest/test-fixed/dek", space, dek_id.get()),
        ))
    }

    async fn prepare_read(&self, _space: &str) -> Result<(), DataKeyError> {
        Ok(())
    }

    fn object_name_key(&self) -> Result<ObjectNameKey, DataKeyError> {
        if self.locked {
            return Err(DataKeyError::Locked);
        }
        Ok(ObjectNameKey::new(self.derive(
            b"tinycloud/at-rest/test-fixed/nk",
            "",
            0,
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_prints_key_bytes() {
        let bytes = [0xA5u8; 32];
        let dek = format!("{:?}", DataKey::new(DekId::new(7), bytes));
        let nk = format!("{:?}", ObjectNameKey::new(bytes));
        let provider = format!("{:?}", FixedKeyProvider::new(bytes));
        for out in [&dek, &nk, &provider] {
            assert!(!out.contains("165"), "{out}");
            assert!(!out.to_lowercase().contains("a5"), "{out}");
        }
        assert!(dek.contains("7"), "{dek}");
    }

    #[tokio::test]
    async fn fixed_provider_serves_issued_keys_only() {
        let p = FixedKeyProvider::new([1; 32]).with_current(DekId::new(2));
        let cur = p.current_key("space-a").await.unwrap();
        assert_eq!(cur.id(), DekId::new(2));
        let old = p.key("space-a", DekId::new(1)).await.unwrap();
        assert_ne!(old.bytes(), cur.bytes());
        assert_eq!(
            p.key("space-a", DekId::new(2)).await.unwrap().bytes(),
            cur.bytes()
        );
        assert_ne!(
            p.key("space-b", DekId::new(2)).await.unwrap().bytes(),
            cur.bytes()
        );
        for id in [0, 3] {
            assert!(matches!(
                p.key("space-a", DekId::new(id)).await,
                Err(DataKeyError::UnknownKey { dek_id }) if dek_id == DekId::new(id)
            ));
        }
    }

    #[tokio::test]
    async fn locked_provider_refuses_everything() {
        let p = FixedKeyProvider::new([1; 32]).locked();
        assert!(matches!(
            p.current_key("s").await,
            Err(DataKeyError::Locked)
        ));
        assert!(matches!(
            p.key("s", DekId::new(1)).await,
            Err(DataKeyError::Locked)
        ));
        assert!(matches!(p.object_name_key(), Err(DataKeyError::Locked)));
    }
}

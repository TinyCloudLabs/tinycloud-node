use std::{collections::HashMap, sync::Arc};
use tinycloud_auth::resource::SpaceId;
use tokio::sync::RwLock;

/// Per-space stored plaintext bytes, for quota and usage.
///
/// Legacy objects are named by space, so a boot scan attributes them to a
/// [`SpaceId`]. Sealed objects (TC-887) are named by a pseudonymous
/// `space_tag` that only the unlocked object-name key can compute, so the
/// scan files them by tag and a lookup joins the two once the caller can
/// name the tag. While keys are locked a space reports its legacy bytes only.
#[derive(Debug, Clone, Default)]
pub struct SpaceSizes(Arc<RwLock<Sizes>>);

#[derive(Debug, Default)]
struct Sizes {
    spaces: HashMap<SpaceId, u64>,
    sealed: HashMap<String, u64>,
}

impl SpaceSizes {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_scan(spaces: HashMap<SpaceId, u64>, sealed: HashMap<String, u64>) -> Self {
        Self(Arc::new(RwLock::new(Sizes { spaces, sealed })))
    }

    pub async fn init_size(&self, space: SpaceId) {
        self.0.write().await.spaces.insert(space, 0);
    }

    /// Adds `size` bytes to the space's entry, or to its sealed-tag entry if
    /// only that is known (a space whose objects are all sealed after a
    /// restart). A space known under neither is left untouched, as before.
    pub async fn increment_size(&self, space: &SpaceId, tag: Option<&str>, size: u64) {
        let mut s = self.0.write().await;
        if let Some(n) = s.spaces.get_mut(space) {
            *n = n.saturating_add(size);
        } else if let Some(n) = tag.and_then(|t| s.sealed.get_mut(t)) {
            *n = n.saturating_add(size);
        }
    }

    /// Subtracts `size` bytes, from the sealed-tag entry first when the
    /// removed object was sealed (that is where a boot scan counted it).
    pub async fn decrement_size(&self, space: &SpaceId, tag: Option<&str>, size: u64) {
        let mut s = self.0.write().await;
        let mut left = size;
        if let Some(n) = tag.and_then(|t| s.sealed.get_mut(t)) {
            let take = left.min(*n);
            *n -= take;
            left -= take;
        }
        if let Some(n) = s.spaces.get_mut(space) {
            *n = n.saturating_sub(left);
        }
    }

    /// The space's bytes, joining its sealed-tag entry when `tag` is given.
    /// `None` when the space is known under neither.
    pub async fn get_size(&self, space: &SpaceId, tag: Option<&str>) -> Option<u64> {
        let s = self.0.read().await;
        let legacy = s.spaces.get(space).copied();
        let sealed = tag.and_then(|t| s.sealed.get(t)).copied();
        match (legacy, sealed) {
            (None, None) => None,
            (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
        }
    }
}

impl From<HashMap<SpaceId, u64>> for SpaceSizes {
    fn from(map: HashMap<SpaceId, u64>) -> Self {
        Self::from_scan(map, HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn space(n: &str) -> SpaceId {
        format!("tinycloud:pkh:eip155:1:0x0000000000000000000000000000000000000001:{n}")
            .parse()
            .unwrap()
    }

    #[tokio::test]
    async fn sealed_bytes_join_only_when_the_tag_is_known() {
        let a = space("a");
        let sizes = SpaceSizes::from_scan(
            HashMap::from([(a.clone(), 100)]),
            HashMap::from([("tagA".to_string(), 40)]),
        );
        // Locked: no tag, legacy only.
        assert_eq!(sizes.get_size(&a, None).await, Some(100));
        // Unlocked: legacy + sealed, without any rescan.
        assert_eq!(sizes.get_size(&a, Some("tagA")).await, Some(140));
        assert_eq!(sizes.get_size(&a, Some("other")).await, Some(100));
    }

    #[tokio::test]
    async fn a_sealed_only_space_is_known_and_grows_under_its_tag() {
        let b = space("b");
        let sizes = SpaceSizes::from_scan(HashMap::new(), HashMap::from([("tagB".into(), 10)]));
        assert_eq!(sizes.get_size(&b, None).await, None);
        assert_eq!(sizes.get_size(&b, Some("tagB")).await, Some(10));
        sizes.increment_size(&b, Some("tagB"), 5).await;
        assert_eq!(sizes.get_size(&b, Some("tagB")).await, Some(15));
        sizes.decrement_size(&b, Some("tagB"), 20).await;
        assert_eq!(sizes.get_size(&b, Some("tagB")).await, Some(0));
    }

    #[tokio::test]
    async fn sealed_removal_drains_the_tag_entry_first() {
        let c = space("c");
        let sizes = SpaceSizes::from_scan(
            HashMap::from([(c.clone(), 50)]),
            HashMap::from([("tagC".into(), 30)]),
        );
        sizes.decrement_size(&c, Some("tagC"), 40).await;
        assert_eq!(sizes.get_size(&c, Some("tagC")).await, Some(40));
        assert_eq!(sizes.get_size(&c, None).await, Some(40));
        // A second removal of the same bytes (double remove) floors at zero
        // under both entries; it never wraps.
        sizes.decrement_size(&c, Some("tagC"), 40).await;
        sizes.decrement_size(&c, None, 40).await;
        assert_eq!(sizes.get_size(&c, Some("tagC")).await, Some(0));
    }
}

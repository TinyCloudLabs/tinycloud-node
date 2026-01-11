use std::{
    collections::HashMap,
    ops::{AddAssign, SubAssign},
    sync::Arc,
};
use tinycloud_lib::resource::SpaceId;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Default)]
pub struct SpaceSizes(Arc<RwLock<HashMap<SpaceId, u64>>>);

impl SpaceSizes {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }
    pub async fn init_size(&self, space: SpaceId) {
        self.0.write().await.insert(space, 0);
    }
    pub async fn increment_size(&self, space: &SpaceId, size: u64) {
        if let Some(s) = self.0.write().await.get_mut(space) {
            s.add_assign(size)
        }
    }
    pub async fn decrement_size(&self, space: &SpaceId, size: u64) {
        if let Some(s) = self.0.write().await.get_mut(space) {
            s.sub_assign(size)
        }
    }
    pub async fn get_size(&self, space: &SpaceId) -> Option<u64> {
        self.0.read().await.get(space).copied()
    }
}

impl From<HashMap<SpaceId, u64>> for SpaceSizes {
    fn from(map: HashMap<SpaceId, u64>) -> Self {
        Self(Arc::new(RwLock::new(map)))
    }
}

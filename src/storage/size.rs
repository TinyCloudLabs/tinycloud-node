use std::{
    collections::HashMap,
    ops::{AddAssign, SubAssign},
    sync::Arc,
};
use tinycloud_lib::resource::NamespaceId;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Default)]
pub struct NamespaceSizes(Arc<RwLock<HashMap<NamespaceId, u64>>>);

impl NamespaceSizes {
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }
    pub async fn init_size(&self, namespace: NamespaceId) {
        self.0.write().await.insert(namespace, 0);
    }
    pub async fn increment_size(&self, namespace: &NamespaceId, size: u64) {
        if let Some(s) = self.0.write().await.get_mut(namespace) {
            s.add_assign(size)
        }
    }
    pub async fn decrement_size(&self, namespace: &NamespaceId, size: u64) {
        if let Some(s) = self.0.write().await.get_mut(namespace) {
            s.sub_assign(size)
        }
    }
    pub async fn get_size(&self, namespace: &NamespaceId) -> Option<u64> {
        self.0.read().await.get(namespace).copied()
    }
}

impl From<HashMap<NamespaceId, u64>> for NamespaceSizes {
    fn from(map: HashMap<NamespaceId, u64>) -> Self {
        Self(Arc::new(RwLock::new(map)))
    }
}

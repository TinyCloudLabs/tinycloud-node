use super::*;

impl DuckDbService {
    /// Close all space actors before unlinking their cache and crash remnants.
    /// Caller must hold the exclusive space lifetime guard after its durable fence.
    /// This does not delete the durable artifact repository.
    pub async fn drain_and_evict_space(&self, space: &SpaceId) -> Result<(), DuckDbError> {
        let target = space.to_string();
        // DuckDB hydrations run within request/operation lifetimes, so the
        // exclusive caller guard has already waited for their completion.
        let actors: Vec<_> = self
            .databases
            .iter()
            .filter(|entry| entry.key().0 == target)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        for (key, handle) in actors {
            let lock = Self::database_lock(&self.operation_locks, &key).await;
            let _operation = lock.lock().await;
            handle.shutdown().await?;
        }
        self.lineage.retain(|key, _| key.0 != target);
        crate::space_purge_cache::remove_directory(&self.base_path, &target)
            .await
            .map_err(|_| DuckDbError::Internal("space cache removal failed".into()))
    }
}

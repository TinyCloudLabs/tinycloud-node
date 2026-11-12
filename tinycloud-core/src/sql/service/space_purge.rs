use super::*;

impl SqlService {
    /// Join detached hydration, close actors, then unlink every cache artifact.
    /// Caller must hold the exclusive space lifetime guard after its durable fence.
    /// This does not delete the durable artifact repository.
    pub async fn drain_and_evict_space(&self, space: &SpaceId) -> Result<(), SqlError> {
        let target = space.to_string();
        let flights: Vec<_> = {
            let registry = self
                .hydrations
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            registry
                .iter()
                .filter(|(key, _)| key.0 == target)
                .map(|(_, flight)| flight.outcome.clone())
                .collect()
        };
        for mut outcome in flights {
            outcome
                .wait_for(Option::is_some)
                .await
                .map_err(|_| SqlError::Internal("purge hydration did not finish".into()))?;
        }
        // Never hold a DashMap reference while waiting on an actor: it deregisters
        // itself after connection close and before its shutdown acknowledgement.
        let actors: Vec<_> = self
            .databases
            .iter()
            .filter(|entry| entry.key().0 == target)
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect();
        for (key, handle) in actors {
            let lock = self.operation_lock(space, &key.1).await;
            let _operation = lock.lock().await;
            handle.shutdown().await?;
        }
        self.lineage.retain(|key, _| key.0 != target);
        crate::space_purge_cache::remove_directory(&self.base_path, &target)
            .await
            .map_err(|_| SqlError::Internal("space cache removal failed".into()))
    }
}

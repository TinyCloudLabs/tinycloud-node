//! Shared operation lifetimes and transaction-level permanent space fences.
use crate::{models::space_purge_fence as state, space_purge_ledger::LedgerKeys};
use sea_orm::{
    sea_query::OnConflict, ActiveModelTrait, ActiveValue::Set, ConnectionTrait,
    DatabaseTransaction, DbErr, EntityTrait, QuerySelect,
};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex, Weak,
    },
};
use tinycloud_auth::resource::SpaceId;
use tokio::sync::{OwnedRwLockReadGuard, OwnedRwLockWriteGuard, RwLock};

#[derive(Debug, thiserror::Error)]
pub enum FenceError {
    #[error("space deleted")]
    Deleted,
    #[error("space purge fence unavailable")]
    Unavailable,
    #[error(transparent)]
    Database(#[from] DbErr),
}

pub struct SpaceOperation {
    _guard: OwnedRwLockReadGuard<()>,
    _owner: OwnedRwLockReadGuard<()>,
    space: SpaceId,
    generation: i64,
}

/// Holding this value drains admitted operations and the orphan collector.
/// The executor must additionally close SQL actors and streaming response leases.
pub struct PurgeDrain {
    _space: OwnedRwLockWriteGuard<()>,
    _collector: OwnedRwLockWriteGuard<()>,
    _owner_shared: Option<OwnedRwLockReadGuard<()>>,
    _owner_exclusive: Option<OwnedRwLockWriteGuard<()>>,
    space: SpaceId,
}
impl PurgeDrain {
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
}

pub struct SpacePurgeFence {
    keys: Arc<LedgerKeys>,
    serving_ready: AtomicBool,
    locks: Mutex<BTreeMap<String, Weak<RwLock<()>>>>,
    collector: Arc<RwLock<()>>,
}
impl fmt::Debug for SpacePurgeFence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SpacePurgeFence")
    }
}
impl SpacePurgeFence {
    pub fn new(keys: Arc<LedgerKeys>) -> Self {
        Self {
            keys,
            serving_ready: AtomicBool::new(false),
            locks: Mutex::new(BTreeMap::new()),
            collector: Arc::new(RwLock::new(())),
        }
    }
    fn lock(&self, key: String) -> Arc<RwLock<()>> {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(RwLock::new(()));
        locks.insert(key, Arc::downgrade(&lock));
        lock
    }
    /// Called only after the request's signature and authority have verified.
    pub async fn admit<C: ConnectionTrait>(
        &self,
        conn: &C,
        space: &SpaceId,
    ) -> Result<SpaceOperation, FenceError> {
        self.check(conn, space).await?;
        let owner = self
            .lock(format!("owner:{}", space.did()))
            .read_owned()
            .await;
        let guard = self.lock(format!("space:{space}")).read_owned().await;
        self.check(conn, space).await?;
        Ok(SpaceOperation {
            _guard: guard,
            _owner: owner,
            space: space.clone(),
            generation: 0,
        })
    }
    /// Called by bootstrap/reconciliation after the independent ledger has verified.
    pub fn set_serving_ready(&self, ready: bool) {
        self.serving_ready.store(ready, Ordering::Release);
    }
    pub async fn check<C: ConnectionTrait>(
        &self,
        conn: &C,
        space: &SpaceId,
    ) -> Result<(), FenceError> {
        if !self.serving_ready.load(Ordering::Acquire) {
            return Err(FenceError::Unavailable);
        }
        self.check_state(conn, space).await
    }
    async fn check_state<C: ConnectionTrait>(
        &self,
        conn: &C,
        space: &SpaceId,
    ) -> Result<(), FenceError> {
        for (kind, target) in [
            ("owner", space.did().as_str().to_owned()),
            ("space", space.to_string()),
        ] {
            for key_id in self.keys.key_ids() {
                let digest = self
                    .keys
                    .target_hmac(key_id, kind, &target)
                    .map_err(|_| FenceError::Unavailable)?;
                if state::Entity::find_by_id((kind.to_owned(), digest, key_id.to_owned()))
                    .one(conn)
                    .await?
                    .is_some_and(|row| row.fenced || row.generation != 0)
                {
                    return Err(FenceError::Deleted);
                }
            }
        }
        Ok(())
    }
    async fn ensure<C: ConnectionTrait>(
        &self,
        conn: &C,
        kind: &str,
        target: &str,
    ) -> Result<(String, Vec<u8>, String), FenceError> {
        let key_id = self.keys.active_key_id().to_owned();
        let digest = self
            .keys
            .target_hmac(&key_id, kind, target)
            .map_err(|_| FenceError::Unavailable)?;
        let id = (kind.to_owned(), digest.clone(), key_id.clone());
        state::Entity::insert(state::ActiveModel {
            kind: Set(kind.into()),
            target_hmac: Set(digest),
            hmac_key_id: Set(key_id),
            generation: Set(0),
            fenced: Set(false),
        })
        .on_conflict(
            OnConflict::columns([
                state::Column::Kind,
                state::Column::TargetHmac,
                state::Column::HmacKeyId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(conn)
        .await?;
        Ok(id)
    }
    /// The lock is held by the caller's metadata transaction until commit.
    /// Permanent fences have generation >= 1; admitted live operations use 0.
    pub async fn recheck(
        &self,
        tx: &DatabaseTransaction,
        operation: &SpaceOperation,
    ) -> Result<(), FenceError> {
        if operation.generation != 0 {
            return Err(FenceError::Deleted);
        }
        self.lock_live(tx, &operation.space).await
    }
    pub async fn lock_live(
        &self,
        tx: &DatabaseTransaction,
        space: &SpaceId,
    ) -> Result<(), FenceError> {
        if !self.serving_ready.load(Ordering::Acquire) {
            return Err(FenceError::Unavailable);
        }
        for (kind, target) in [
            ("owner", space.did().as_str().to_owned()),
            ("space", space.to_string()),
        ] {
            self.ensure(tx, kind, &target).await?;
            for key_id in self.keys.key_ids() {
                let digest = self
                    .keys
                    .target_hmac(key_id, kind, &target)
                    .map_err(|_| FenceError::Unavailable)?;
                if state::Entity::find_by_id((kind.to_owned(), digest, key_id.to_owned()))
                    .lock_shared()
                    .one(tx)
                    .await?
                    .is_some_and(|row| row.fenced || row.generation != 0)
                {
                    return Err(FenceError::Deleted);
                }
            }
        }
        Ok(())
    }
    pub async fn retirement_drain(&self, owner: &str) -> OwnedRwLockWriteGuard<()> {
        self.lock(format!("owner:{owner}")).write_owned().await
    }
    async fn owner_retired<C: ConnectionTrait>(
        &self,
        conn: &C,
        owner: &str,
    ) -> Result<bool, FenceError> {
        for key_id in self.keys.key_ids() {
            let digest = self
                .keys
                .target_hmac(key_id, "owner", owner)
                .map_err(|_| FenceError::Unavailable)?;
            if state::Entity::find_by_id(("owner".to_owned(), digest, key_id.to_owned()))
                .one(conn)
                .await?
                .is_some_and(|row| row.fenced || row.generation != 0)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }
    /// Serializes owner lifecycle requests, quota accounting and retirement.
    pub async fn lock_owner(
        &self,
        tx: &DatabaseTransaction,
        owner: &str,
    ) -> Result<(), FenceError> {
        let id = self.ensure(tx, "owner", owner).await?;
        state::Entity::find_by_id(id)
            .lock_exclusive()
            .one(tx)
            .await?
            .ok_or(FenceError::Unavailable)?;
        Ok(())
    }
    /// Import or create a permanent authenticated fence. Never clears a fence.
    pub async fn fence_hmac(
        &self,
        tx: &DatabaseTransaction,
        kind: &str,
        key_id: &str,
        digest: &[u8],
    ) -> Result<i64, FenceError> {
        if !matches!(kind, "owner" | "space" | "resource")
            || digest.len() != 32
            || !self.keys.key_ids().any(|id| id == key_id)
        {
            return Err(FenceError::Unavailable);
        }
        let id = (kind.to_owned(), digest.to_vec(), key_id.to_owned());
        state::Entity::insert(state::ActiveModel {
            kind: Set(kind.into()),
            target_hmac: Set(digest.to_vec()),
            hmac_key_id: Set(key_id.into()),
            generation: Set(0),
            fenced: Set(false),
        })
        .on_conflict(
            OnConflict::columns([
                state::Column::Kind,
                state::Column::TargetHmac,
                state::Column::HmacKeyId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(tx)
        .await?;
        let row = state::Entity::find_by_id(id)
            .lock_exclusive()
            .one(tx)
            .await?
            .ok_or(FenceError::Unavailable)?;
        let generation = row.generation.max(1);
        let mut update: state::ActiveModel = row.into();
        update.generation = Set(generation);
        update.fenced = Set(true);
        update.update(tx).await?;
        Ok(generation)
    }
    /// The background collector holds this for a bounded collection pass.
    pub async fn collector_operation(&self) -> OwnedRwLockReadGuard<()> {
        self.collector.clone().read_owned().await
    }
    pub async fn drain<C: ConnectionTrait>(
        &self,
        conn: &C,
        space: &SpaceId,
    ) -> Result<PurgeDrain, FenceError> {
        if !matches!(
            self.check_state(conn, space).await,
            Err(FenceError::Deleted)
        ) {
            return Err(FenceError::Unavailable);
        }
        let collector = self.collector.clone().write_owned().await;
        let owner_lock = self.lock(format!("owner:{}", space.did()));
        let owner_shared = owner_lock.clone().read_owned().await;
        let (owner_shared, owner_exclusive) =
            if self.owner_retired(conn, space.did().as_str()).await? {
                drop(owner_shared);
                (None, Some(owner_lock.write_owned().await))
            } else {
                (Some(owner_shared), None)
            };
        let guard = self.lock(format!("space:{space}")).write_owned().await;
        Ok(PurgeDrain {
            _space: guard,
            _collector: collector,
            _owner_shared: owner_shared,
            _owner_exclusive: owner_exclusive,
            space: space.clone(),
        })
    }
}

impl SpacePurgeFence {
    async fn check_resource_state<C: ConnectionTrait>(
        &self,
        conn: &C,
        resource: &crate::resource_purge_fence::ResourceTarget,
    ) -> Result<(), FenceError> {
        for (kind, target) in resource.targets() {
            for key_id in self.keys.key_ids() {
                let digest = self
                    .keys
                    .target_hmac(key_id, kind, target)
                    .map_err(|_| FenceError::Unavailable)?;
                if state::Entity::find_by_id((kind.to_owned(), digest, key_id.to_owned()))
                    .one(conn)
                    .await?
                    .is_some_and(|row| row.fenced || row.generation != 0)
                {
                    return Err(FenceError::Deleted);
                }
            }
        }
        Ok(())
    }
    pub async fn check_resource<C: ConnectionTrait>(
        &self,
        conn: &C,
        resource: &crate::resource_purge_fence::ResourceTarget,
    ) -> Result<(), FenceError> {
        if !self.serving_ready.load(Ordering::Acquire) {
            return Err(FenceError::Unavailable);
        }
        self.check_resource_state(conn, resource).await
    }
    pub async fn admit_resource<C: ConnectionTrait>(
        &self,
        conn: &C,
        resource: &crate::resource_purge_fence::ResourceTarget,
    ) -> Result<crate::resource_purge_fence::ResourceOperation, FenceError> {
        self.check_resource(conn, resource).await?;
        let owner = self
            .lock(format!("owner:{}", resource.owner_did()))
            .read_owned()
            .await;
        let guard = self
            .lock(format!("resource:{}", resource.as_str()))
            .read_owned()
            .await;
        self.check_resource(conn, resource).await?;
        Ok(crate::resource_purge_fence::ResourceOperation {
            _owner: owner,
            _resource: guard,
            target: resource.clone(),
        })
    }
    pub async fn recheck_resource(
        &self,
        tx: &DatabaseTransaction,
        operation: &crate::resource_purge_fence::ResourceOperation,
    ) -> Result<(), FenceError> {
        if !self.serving_ready.load(Ordering::Acquire) {
            return Err(FenceError::Unavailable);
        }
        for (kind, target) in operation.target.targets() {
            self.ensure(tx, kind, target).await?;
            for key_id in self.keys.key_ids() {
                let digest = self
                    .keys
                    .target_hmac(key_id, kind, target)
                    .map_err(|_| FenceError::Unavailable)?;
                if state::Entity::find_by_id((kind.to_owned(), digest, key_id.to_owned()))
                    .lock_shared()
                    .one(tx)
                    .await?
                    .is_some_and(|row| row.fenced || row.generation != 0)
                {
                    return Err(FenceError::Deleted);
                }
            }
        }
        Ok(())
    }
    pub async fn drain_resource<C: ConnectionTrait>(
        &self,
        conn: &C,
        resource: &crate::resource_purge_fence::ResourceTarget,
    ) -> Result<crate::resource_purge_fence::ResourcePurgeDrain, FenceError> {
        if !matches!(
            self.check_resource_state(conn, resource).await,
            Err(FenceError::Deleted)
        ) {
            return Err(FenceError::Unavailable);
        }
        let owner = self
            .lock(format!("owner:{}", resource.owner_did()))
            .write_owned()
            .await;
        let guard = self
            .lock(format!("resource:{}", resource.as_str()))
            .write_owned()
            .await;
        Ok(crate::resource_purge_fence::ResourcePurgeDrain {
            _owner: owner,
            _resource: guard,
            target: resource.clone(),
        })
    }
}

use std::{
    collections::HashMap,
    future::Future,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Weak,
    },
    time::Duration,
};

use dashmap::DashMap;
use tinycloud_auth::resource::SpaceId;
use tokio::{sync::OwnedMutexGuard, time::Instant};
use tracing::Instrument;

use crate::database_artifacts::{
    read_artifact, sweep_stale_staging, ArtifactExpectation, ArtifactMeta, CacheFileSink,
    DatabaseArtifactError, DatabaseArtifactRepository,
};
use crate::db_pool::{is_transient_error, track_writes, transient_error_class};
use crate::{request_cancel, request_telemetry};

use super::{
    authority::{DdlPolicy, SqlAuthority},
    caveats::SqlCaveats,
    database::{spawn_actor_with_policy, DatabaseHandle, GrowthPolicy},
    durability::{DurabilityPolicy, ReservationGuard},
    types::*,
};

const MAX_WAL_DELTA_BYTES: usize = 8 * 1024 * 1024;

/// The first 16 bytes of every SQLite main database file.
const SQLITE_MAGIC: &[u8] = b"SQLite format 3\0";
/// The first 4 bytes of a SQLite WAL header. The low bit of the last byte
/// selects the checksum endianness; both values are valid.
const SQLITE_WAL_MAGIC: [&[u8]; 2] = [&[0x37, 0x7f, 0x06, 0x82], &[0x37, 0x7f, 0x06, 0x83]];

/// Per-(space, db) operation lock; see [`SqlService::operation_locks`].
type OperationLock = tokio::sync::Mutex<()>;
type OperationLockRegistry =
    Arc<tokio::sync::Mutex<HashMap<(String, String), Weak<OperationLock>>>>;

/// How a hydration ended, as every caller that joined it sees it.
#[derive(Clone, Debug)]
enum HydrationOutcome {
    Ready,
    Unavailable,
    Failed(String),
    TimedOut,
}

const PHASE_LOADING: u8 = 0;
const PHASE_WRITING: u8 = 1;

/// A hydration in progress: what it is doing, and how it ended once it has.
#[derive(Clone)]
struct HydrationFlight {
    phase: Arc<AtomicU8>,
    outcome: tokio::sync::watch::Receiver<Option<HydrationOutcome>>,
}

type HydrationRegistry = Arc<std::sync::Mutex<HashMap<(String, String), HydrationFlight>>>;

/// Hydrations one [`SqlService::handle`] call may run before it gives up.
const MAX_HYDRATIONS: usize = 2;

/// Retires a hydration's registry entry and publishes how it ended (TC-1274).
///
/// Dropped without [`Self::finish`] (the hydration task panicked or its
/// runtime shut down), it still retires the entry and reports a failure, so
/// joiners get an error and the next request starts a fresh hydration instead
/// of joining a dead one.
struct RetireFlight {
    service: SqlService,
    key: (String, String),
    phase: Arc<AtomicU8>,
    sender: Option<tokio::sync::watch::Sender<Option<HydrationOutcome>>>,
}

impl RetireFlight {
    fn finish(mut self, outcome: HydrationOutcome) {
        self.retire(outcome);
    }

    fn retire(&mut self, outcome: HydrationOutcome) {
        let Some(sender) = self.sender.take() else {
            return;
        };
        let mut flights = self
            .service
            .hydrations
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Only this flight's entry: the key is never re-registered while it
        // is present, but compare anyway rather than assume.
        if flights
            .get(&self.key)
            .is_some_and(|flight| Arc::ptr_eq(&flight.phase, &self.phase))
        {
            flights.remove(&self.key);
        }
        drop(flights);
        sender.send_replace(Some(outcome));
    }
}

impl Drop for RetireFlight {
    fn drop(&mut self) {
        self.retire(HydrationOutcome::Failed(
            "database hydration ended abnormally".into(),
        ));
    }
}

/// How long a SQL request waits at each stage before it answers
/// [`SqlError::Busy`] (TC-1274). Every wait is also cut short by the request
/// deadline while the request has not started writing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlWaitBounds {
    /// The per-(space, db) operation lock.
    pub lock_wait: Duration,
    /// A caller's wait for the database's local cache to be hydrated.
    pub hydration_wait: Duration,
    /// A durable artifact load or save that the caller awaits directly.
    pub artifact_transfer: Duration,
    /// A hydration's own artifact load. It keeps going after its callers
    /// give up, so the next request finds the database warm.
    pub hydration_max: Duration,
}

impl Default for SqlWaitBounds {
    fn default() -> Self {
        Self {
            lock_wait: Duration::from_secs(30),
            hydration_wait: Duration::from_secs(30),
            artifact_transfer: Duration::from_secs(45),
            hydration_max: Duration::from_secs(600),
        }
    }
}

#[derive(Clone)]
pub struct SqlService {
    databases: Arc<DashMap<(String, String), DatabaseHandle>>,
    /// The hydration in progress for each (space, db) with no live actor; see
    /// [`SqlService::handle`].
    hydrations: HydrationRegistry,
    /// Serialize execution through durable persistence, including checkpoint
    /// replacement, so another request cannot change the snapshot being saved.
    operation_locks: OperationLockRegistry,
    /// What each live actor's local database derives from, carried into every
    /// durable save so a stale actor is rejected instead of clobbering. Written
    /// on hydration (the only path that creates an actor) and after each
    /// successful save, cleared alongside the actor by `discard_local_state`.
    lineage: Arc<DashMap<(String, String), ArtifactExpectation>>,
    base_path: String,
    memory_threshold: u64,
    artifact_repository: Arc<dyn DatabaseArtifactRepository>,
    bounds: SqlWaitBounds,
    durability: DurabilityPolicy,
    ddl_policy: DdlPolicy,
}

impl SqlService {
    pub fn new(
        base_path: String,
        memory_threshold: u64,
        artifact_repository: Arc<dyn DatabaseArtifactRepository>,
    ) -> Self {
        Self {
            databases: Arc::new(DashMap::new()),
            hydrations: Arc::new(std::sync::Mutex::new(HashMap::new())),
            operation_locks: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            lineage: Arc::new(DashMap::new()),
            base_path,
            memory_threshold,
            artifact_repository,
            bounds: SqlWaitBounds::default(),
            durability: DurabilityPolicy::default(),
            ddl_policy: DdlPolicy::default(),
        }
    }

    /// The node's local durability policy (TC-1491): `synchronous`, the
    /// per-database size cap and the disk headroom.
    pub fn with_durability(mut self, durability: DurabilityPolicy) -> Self {
        self.durability = durability;
        self
    }

    /// Whether a schema-changing statement needs `tinycloud.sql/schema`
    /// (TC-1581). Defaults to [`DdlPolicy::Enforce`].
    pub fn with_ddl_policy(mut self, policy: DdlPolicy) -> Self {
        self.ddl_policy = policy;
        self
    }

    pub fn with_wait_bounds(mut self, bounds: SqlWaitBounds) -> Self {
        self.bounds = bounds;
        self
    }

    pub async fn execute(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
    ) -> Result<SqlExecutionResult, SqlError> {
        self.execute_with_growth(
            space,
            db_name,
            request,
            caveats,
            SqlAuthority::from(ability).with_ddl_policy(self.ddl_policy),
            GrowthPolicy::Allow,
        )
        .await
    }

    /// As [`Self::execute`], judging each statement against every SQL ability
    /// the invocation holds (TC-1581).
    pub async fn execute_authorized(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
    ) -> Result<SqlExecutionResult, SqlError> {
        self.execute_with_growth(
            space,
            db_name,
            request,
            caveats,
            authority.with_ddl_policy(self.ddl_policy),
            GrowthPolicy::Allow,
        )
        .await
    }

    /// Execute on a full space: refuse growth of either the live database or
    /// its durable representation. Successful writes replace checkpoint + WAL
    /// without increasing charged bytes; no-ops on absent databases do not
    /// materialize a checkpoint.
    pub async fn execute_without_growth(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
    ) -> Result<SqlExecutionResult, SqlError> {
        self.execute_with_growth(
            space,
            db_name,
            request,
            caveats,
            SqlAuthority::from(ability).with_ddl_policy(self.ddl_policy),
            GrowthPolicy::Forbid,
        )
        .await
    }

    /// As [`Self::execute_without_growth`], judging each statement against
    /// every SQL ability the invocation holds (TC-1581).
    pub async fn execute_without_growth_authorized(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
    ) -> Result<SqlExecutionResult, SqlError> {
        self.execute_with_growth(
            space,
            db_name,
            request,
            caveats,
            authority.with_ddl_policy(self.ddl_policy),
            GrowthPolicy::Forbid,
        )
        .await
    }

    /// Execute with the owner's remaining storage budget: a write that would
    /// grow the database by more than `remaining_bytes` is rolled back before
    /// COMMIT with [`SqlError::StorageWouldGrow`].
    pub async fn execute_with_budget(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        ability: String,
        remaining_bytes: u64,
    ) -> Result<SqlExecutionResult, SqlError> {
        self.execute_with_budget_authorized(
            space,
            db_name,
            request,
            caveats,
            SqlAuthority::from(ability),
            remaining_bytes,
        )
        .await
    }

    /// As [`Self::execute_with_budget`], judging each statement against every
    /// SQL ability the invocation holds (TC-1581). This is the entry point
    /// `/invoke` uses for a write inside the owner's remaining budget.
    pub async fn execute_with_budget_authorized(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
        remaining_bytes: u64,
    ) -> Result<SqlExecutionResult, SqlError> {
        self.execute_with_growth(
            space,
            db_name,
            request,
            caveats,
            authority.with_ddl_policy(self.ddl_policy),
            GrowthPolicy::Budget(remaining_bytes),
        )
        .await
    }

    async fn execute_with_growth(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
        growth: GrowthPolicy,
    ) -> Result<SqlExecutionResult, SqlError> {
        crate::request_telemetry::observe_space(space);
        let guard = self.acquire_operation(space, db_name).await?;
        let (space, db_name) = (space.clone(), db_name.to_string());
        self.run_locked(guard, move |service| async move {
            service
                .execute_locked(&space, &db_name, request, caveats, authority, growth)
                .await
        })
        .await
    }

    /// The body of an execute, run on the operation task under the lock.
    async fn execute_locked(
        &self,
        space: &SpaceId,
        db_name: &str,
        request: SqlRequest,
        caveats: Option<SqlCaveats>,
        authority: SqlAuthority,
        growth: GrowthPolicy,
    ) -> Result<SqlExecutionResult, SqlError> {
        let key = (space.to_string(), db_name.to_string());
        // Whatever the request still holds of the disk budget is released once
        // its outcome is known: after the durable save, or its failure.
        let _reservation = ReservationGuard::new(
            self.durability.budget.clone(),
            format!("{}/{}", key.0, key.1),
        );
        let mut handle = self.handle(space, db_name).await?;
        begin_write()?;

        let result = match handle
            .execute_authorized(request.clone(), caveats.clone(), authority.clone(), growth)
            .await
        {
            Err(SqlError::Internal(ref msg)) if msg.contains("Database actor not available") => {
                // Actor is dead — remove stale entry and respawn
                tracing::warn!("Dead SQL actor detected, respawning");
                self.databases.remove(&key);
                handle = self.handle(space, db_name).await?;
                handle
                    .execute_authorized(request, caveats, authority, growth)
                    .await
            }
            other => other,
        };
        let result = match result {
            Ok(result) => result,
            Err(error) => {
                if (growth == GrowthPolicy::Forbid
                    && self.expectation(&key) == ArtifactExpectation::Absent)
                    // The disk failed the commit: its WAL is not to be trusted
                    // (Postgres never saw the write), so start over from it.
                    || matches!(error, SqlError::CommitFailed)
                {
                    self.discard_local_state(&key).await?;
                }
                return Err(error);
            }
        };

        if !result.write_targets.is_empty() {
            if growth == GrowthPolicy::Forbid
                && self.expectation(&key) == ArtifactExpectation::Absent
            {
                // The actor's guard admitted no new pages. Serializing this
                // empty database would nevertheless create a charged header.
                // Discard the transient actor and its local cache without charging it.
                self.discard_local_state(&key).await?;
                return Ok(result);
            }
            let (persisted, write_may_have_applied) =
                track_writes(self.persist_write(space, db_name, &handle, growth)).await;
            if let Err(e) = persisted {
                self.discard_local_state(&key).await?;
                // A lost connection or an expired transfer after the artifact
                // write was sent: the write may be durable, so a blind retry
                // could apply it twice (TC-1054, TC-1274).
                return Err(match e {
                    SqlError::Unavailable | SqlError::Busy(_) if write_may_have_applied => {
                        SqlError::OutcomeUnknown
                    }
                    e => e,
                });
            }
        }

        Ok(result)
    }

    async fn operation_lock(&self, space: &SpaceId, db_name: &str) -> Arc<OperationLock> {
        let key = (space.to_string(), db_name.to_string());
        let mut registry = self.operation_locks.lock().await;
        registry.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = registry.get(&key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(OperationLock::new(()));
        registry.insert(key, Arc::downgrade(&lock));
        lock
    }

    /// Take the operation lock for (space, db), waiting at most the lock
    /// bound (or the request deadline).
    async fn acquire_operation(
        &self,
        space: &SpaceId,
        db_name: &str,
    ) -> Result<OwnedMutexGuard<()>, SqlError> {
        let lock = self.operation_lock(space, db_name).await;
        self.bounded(
            || SqlBusyStage::LockWait,
            self.bounds.lock_wait,
            lock.lock_owned(),
        )
        .await
    }

    /// Run `operation` under the operation lock on its own task (TC-1274).
    ///
    /// The task owns the guard, so a caller that goes away (its future
    /// dropped by a deadline, an aborted handler) can never stop the work
    /// midway: hydration writes, the actor's statement and the durable save
    /// that must follow it all complete, and the lock is released when they
    /// have. Before its write starts, the task stops at the request's
    /// deadline by itself (see [`begin_write`]).
    async fn run_locked<T, F, Fut>(
        &self,
        guard: OwnedMutexGuard<()>,
        operation: F,
    ) -> Result<T, SqlError>
    where
        T: Send + 'static,
        F: FnOnce(SqlService) -> Fut + Send + 'static,
        Fut: Future<Output = Result<T, SqlError>> + Send + 'static,
    {
        let service = self.clone();
        let task = request_cancel::within(request_cancel::current(), async move {
            let _guard = guard;
            operation(service).await
        })
        .instrument(tracing::Span::current());
        let joined = match request_telemetry::current() {
            Some(context) => tokio::spawn(request_telemetry::scope(context, task)).await,
            None => tokio::spawn(task).await,
        };
        match joined {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => Err(SqlError::Internal(format!(
                "SQL operation task ended early: {error}"
            ))),
        }
    }

    /// Wait for `future` at most `bound`, or until the request deadline while
    /// the request has not started writing (TC-1274). `stage` names what
    /// was being waited on when the bound expired.
    async fn bounded<T>(
        &self,
        stage: impl Fn() -> SqlBusyStage,
        bound: Duration,
        future: impl Future<Output = T>,
    ) -> Result<T, SqlError> {
        let started = Instant::now();
        let context = request_cancel::current().filter(|context| context.is_open());
        if let Some(context) = &context {
            context.set_stage(stage().into());
        }
        let bound_end = started + bound;
        let deadline = context
            .as_ref()
            .map(|context| context.deadline())
            .filter(|deadline| *deadline < bound_end);
        let waited = tokio::time::timeout_at(deadline.unwrap_or(bound_end), future).await;
        if let Some(context) = &context {
            context.set_stage(request_cancel::Stage::Other);
        }
        match (waited, context) {
            (Ok(output), _) => Ok(output),
            (Err(_), Some(context)) if deadline.is_some() => {
                context.set_stage(stage().into());
                // Logged once, by whichever of this wait and the route's
                // deadline claims the cut first.
                context.cut();
                Err(SqlError::RequestTimeout)
            }
            (Err(_), _) => {
                let stage = stage();
                log_busy(stage, bound, started.elapsed());
                Err(SqlError::Busy(stage))
            }
        }
    }

    /// Read-only compatibility command; the core actor rejects withdrawn mutations.
    pub async fn meeting_publication(
        &self,
        space: &SpaceId,
        command: serde_json::Value,
    ) -> Result<SqlExecutionResult, SqlError> {
        crate::request_telemetry::observe_space(space);
        let guard = self
            .acquire_operation(space, super::publication::DATABASE)
            .await?;
        let space = space.clone();
        self.run_locked(guard, move |service| async move {
            service.meeting_publication_locked(&space, command).await
        })
        .await
    }

    async fn meeting_publication_locked(
        &self,
        space: &SpaceId,
        command: serde_json::Value,
    ) -> Result<SqlExecutionResult, SqlError> {
        let db_name = super::publication::DATABASE;
        let key = (space.to_string(), db_name.to_string());
        let handle = self.handle(space, db_name).await?;
        begin_write()?;
        let result = handle.publication(command).await?;
        if !result.write_targets.is_empty() {
            if let Err(error) = self
                .persist_write(space, db_name, &handle, GrowthPolicy::Allow)
                .await
            {
                self.discard_local_state(&key).await?;
                return Err(error);
            }
        }
        Ok(result)
    }

    /// Export a durable database without persisting changes. A cached actor
    /// created by a query or rejected write does not establish its existence.
    pub async fn export(&self, space: &SpaceId, db_name: &str) -> Result<Vec<u8>, SqlError> {
        crate::request_telemetry::observe_space(space);
        let _operation_guard = self.acquire_operation(space, db_name).await?;
        let key = (space.to_string(), db_name.to_string());

        if self
            .bounded(
                || SqlBusyStage::ArtifactTransfer,
                self.bounds.artifact_transfer,
                self.artifact_repository
                    .load_meta("sql", &space.to_string(), db_name),
            )
            .await?
            .map_err(artifact_error_to_sql)?
            .is_none()
        {
            return Err(SqlError::DatabaseNotFound);
        }

        // If there's a live actor, route through it (handles both in-memory and file-backed)
        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            match handle.export().await {
                Err(SqlError::Internal(ref msg))
                    if msg.contains("Database actor not available") =>
                {
                    // Actor is dead — remove stale entry and fall through to cold read
                    tracing::warn!("Dead SQL actor detected during export, removing");
                    self.databases.remove(&key);
                }
                other => return other,
            }
        }
        self.handle(space, db_name).await?.export().await
    }

    pub fn db_name_from_path(path: Option<&str>) -> String {
        crate::database_identity::logical_name(path)
    }

    /// The pre-N2 selector, for N3's explicit legacy-artifact inventory only.
    pub fn legacy_db_name_from_path(path: Option<&str>) -> String {
        crate::database_identity::legacy_sql_name(path)
    }

    /// Resolve the live actor for `key`, hydrating the on-disk cache first if
    /// there is none.
    ///
    /// Hydration deletes and rewrites the very files a running actor reads BY
    /// PATH, and two hydrations of one database interleave their writes, so at
    /// most one hydration per (space, db) is in flight, it runs only while there
    /// is no actor, and it publishes its actor before it retires. Both
    /// properties are load-bearing: hydrating concurrently with another
    /// hydration, or under a live actor, is how a database silently reverts to
    /// an older checkpoint.
    ///
    /// The hydration runs on its own task, which no caller can cancel (its
    /// cache writes must not be orphaned, TC-1274). Callers join it: each waits
    /// at most its hydration bound and then answers busy, while the hydration
    /// keeps going under `hydration_max`, so the next request finds the
    /// database warm.
    async fn handle(&self, space: &SpaceId, db_name: &str) -> Result<DatabaseHandle, SqlError> {
        let key = (space.to_string(), db_name.to_string());
        let started = Instant::now();
        // A hydration that ends `Ready` has published its actor, but an actor
        // that cannot open its files deregisters itself at once. Hydrate at
        // most twice, as before TC-1274, rather than reload the artifact in a
        // loop while holding the operation lock.
        for _ in 0..MAX_HYDRATIONS {
            if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
                return Ok(handle);
            }
            let (flight, start) = {
                let mut flights = self
                    .hydrations
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                // Checked again under the registry: a hydration publishes its
                // actor before it leaves the registry.
                if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
                    return Ok(handle);
                }
                match flights.get(&key) {
                    Some(flight) => (flight.clone(), None),
                    None => {
                        let (flight, start) = self.prepare_hydration(space, db_name);
                        flights.insert(key.clone(), flight.clone());
                        (flight, Some(start))
                    }
                }
            };
            // Spawned only after the registry lock is released: if the
            // runtime is shutting down, the task is dropped at once and its
            // guard takes that lock to retire the entry.
            if let Some(start) = start {
                start();
            }
            match self.join_hydration(flight).await? {
                HydrationOutcome::Ready => continue,
                HydrationOutcome::Unavailable => return Err(SqlError::Unavailable),
                HydrationOutcome::Failed(message) => return Err(SqlError::Internal(message)),
                HydrationOutcome::TimedOut => {
                    log_busy(
                        SqlBusyStage::ArtifactTransfer,
                        self.bounds.hydration_max,
                        started.elapsed(),
                    );
                    return Err(SqlError::Busy(SqlBusyStage::ArtifactTransfer));
                }
            }
        }
        if let Some(handle) = self.databases.get(&key).map(|h| h.clone()) {
            return Ok(handle);
        }
        Err(SqlError::Internal(
            "database actor did not start after hydration".into(),
        ))
    }

    /// Wait for a hydration to end, at most the hydration bound.
    async fn join_hydration(&self, flight: HydrationFlight) -> Result<HydrationOutcome, SqlError> {
        let HydrationFlight { phase, mut outcome } = flight;
        let stage = || match phase.load(Ordering::Acquire) {
            PHASE_LOADING => SqlBusyStage::ArtifactTransfer,
            _ => SqlBusyStage::Hydration,
        };
        let ended = self
            .bounded(stage, self.bounds.hydration_wait, async {
                outcome
                    .wait_for(Option::is_some)
                    .await
                    .map(|ended| ended.clone())
            })
            .await?;
        Ok(match ended {
            Ok(Some(outcome)) => outcome,
            _ => HydrationOutcome::Failed("database hydration ended without an outcome".into()),
        })
    }

    /// Prepare the hydration of (space, db) and the call that spawns it.
    /// Prepared under the registry lock; spawn it after releasing the lock.
    fn prepare_hydration(
        &self,
        space: &SpaceId,
        db_name: &str,
    ) -> (HydrationFlight, impl FnOnce()) {
        let (sender, outcome) = tokio::sync::watch::channel(None);
        let phase = Arc::new(AtomicU8::new(PHASE_LOADING));
        let retire = RetireFlight {
            service: self.clone(),
            key: (space.to_string(), db_name.to_string()),
            phase: Arc::clone(&phase),
            sender: Some(sender),
        };
        let service = self.clone();
        let (space, db_name) = (space.clone(), db_name.to_string());
        let task = async move {
            let ended = service.hydrate(&space, &db_name, &retire.phase).await;
            retire.finish(ended);
        }
        .instrument(tracing::Span::current());
        let telemetry = request_telemetry::current();
        let start = move || match telemetry {
            Some(context) => drop(tokio::spawn(request_telemetry::scope(context, task))),
            None => drop(tokio::spawn(task)),
        };
        (HydrationFlight { phase, outcome }, start)
    }

    /// Stream the durable artifact into the cache, seed it and spawn the actor.
    /// Only the streaming read is bounded (`hydration_max`): it stages temp
    /// files that a timeout simply drops, while the commit after it is local
    /// and must finish once begun.
    async fn hydrate(&self, space: &SpaceId, db_name: &str, phase: &AtomicU8) -> HydrationOutcome {
        let cache_path = self.cache_path(space, db_name);
        sweep_stale_staging(&[&cache_path, &sql_wal_path(&cache_path)]).await;
        let mut sink = CacheFileSink::new(
            "sql",
            format!("{space}/{db_name}"),
            cache_path.clone(),
            sql_wal_path(&cache_path),
            is_sqlite_database,
            is_sqlite_wal,
        );
        let loaded = tokio::time::timeout(
            self.bounds.hydration_max,
            read_artifact(
                self.artifact_repository.as_ref(),
                "sql",
                &space.to_string(),
                db_name,
                &mut sink,
            ),
        )
        .await;
        let meta = match loaded {
            Ok(Ok(meta)) => meta,
            Ok(Err(error)) => return hydration_failure(artifact_error_to_sql(error)),
            Err(_) => {
                tracing::warn!(
                    service = "sql",
                    error_class = "hydration_timeout",
                    bound_ms = self.bounds.hydration_max.as_millis() as u64,
                    "Database hydration gave up loading its artifact"
                );
                return HydrationOutcome::TimedOut;
            }
        };
        phase.store(PHASE_WRITING, Ordering::Release);
        if let Err(error) = self.seed_cache(space, db_name, meta, sink).await {
            return hydration_failure(error);
        }
        self.databases
            .entry((space.to_string(), db_name.to_string()))
            .or_insert_with(|| {
                spawn_actor_with_policy(
                    space.to_string(),
                    db_name.to_string(),
                    self.base_path.clone(),
                    self.memory_threshold,
                    self.databases.clone(),
                    self.durability.clone(),
                )
            });
        HydrationOutcome::Ready
    }

    /// Replace the cache files with the verified artifact staged in `sink`
    /// (or with nothing, when there is no artifact).
    async fn seed_cache(
        &self,
        space: &SpaceId,
        db_name: &str,
        meta: Option<ArtifactMeta>,
        mut sink: CacheFileSink,
    ) -> Result<(), SqlError> {
        let cache_path = self.cache_path(space, db_name);
        let key = (space.to_string(), db_name.to_string());
        match meta {
            Some(meta) => {
                tracing::info!(
                    service = "sql",
                    revision = meta.revision,
                    storage_mode = %meta.storage_mode,
                    bytes = meta.checkpoint_size_bytes,
                    delta_bytes = meta.delta_size_bytes,
                    logical_bytes = meta.size_bytes,
                    content_hash = %meta.content_hash,
                    checkpoint_content_hash = %meta.checkpoint_content_hash,
                    "Loaded database artifact"
                );
                remove_sql_cache_files(&cache_path).await?;
                sink.commit()
                    .await
                    .map_err(|e| SqlError::Internal(e.to_string()))?;
                self.lineage.insert(
                    key,
                    ArtifactExpectation::Derived {
                        revision: meta.revision,
                        checkpoint_content_hash: meta.checkpoint_content_hash,
                    },
                );
                Ok(())
            }
            None => {
                tracing::info!(
                    service = "sql",
                    "No durable database artifact; starting from an empty database"
                );
                remove_sql_cache_files(&cache_path).await?;
                self.lineage.insert(key, ArtifactExpectation::Absent);
                Ok(())
            }
        }
    }

    fn cache_path(&self, space: &SpaceId, db_name: &str) -> PathBuf {
        PathBuf::from(&self.base_path)
            .join(space.to_string())
            .join(format!("{}.db", db_name))
    }

    async fn discard_local_state(&self, key: &(String, String)) -> Result<(), SqlError> {
        if let Some((_, handle)) = self.databases.remove(key) {
            // Wait for the connection to close before unlinking its cache:
            // an exit-time flush must not race the next durable hydration.
            handle.shutdown().await?;
        }
        self.lineage.remove(key);
        let cache_path = PathBuf::from(&self.base_path)
            .join(&key.0)
            .join(format!("{}.db", key.1));
        remove_sql_cache_files(&cache_path).await
    }

    /// What the actor for `key` derives from.
    ///
    /// Every actor is created by `handle`, which records this during hydration,
    /// so a live actor always has an entry. A missing one means the actor
    /// outlived its record and there is nothing to assert against.
    fn expectation(&self, key: &(String, String)) -> ArtifactExpectation {
        match self.lineage.get(key).map(|entry| entry.clone()) {
            Some(expectation) => expectation,
            None => {
                tracing::warn!(
                    service = "sql",
                    "No recorded artifact lineage for a live database; saving without a lineage assertion"
                );
                ArtifactExpectation::Any
            }
        }
    }

    async fn persist_write(
        &self,
        space: &SpaceId,
        db_name: &str,
        handle: &DatabaseHandle,
        growth: GrowthPolicy,
    ) -> Result<(), SqlError> {
        let key = (space.to_string(), db_name.to_string());
        let expected = self.expectation(&key);

        // Repeated DELETE/UPDATE/DROP operations can append WAL frames without
        // adding a database page. Full spaces replace checkpoint + WAL, but
        // must also bound the resulting image against the durable charge:
        // live state can include partial writes from an earlier failed request.
        let wal = if growth != GrowthPolicy::Forbid {
            handle.wal().await?
        } else {
            None
        };
        if let Some(wal) = wal.filter(|wal| wal.len() < MAX_WAL_DELTA_BYTES) {
            match self
                .bounded(
                    || SqlBusyStage::ArtifactTransfer,
                    self.bounds.artifact_transfer,
                    self.artifact_repository.save_delta(
                        "sql",
                        &space.to_string(),
                        db_name,
                        wal,
                        expected.clone(),
                    ),
                )
                .await?
            {
                Ok(saved) => {
                    // The delta rides on the same checkpoint, so only the
                    // revision this actor is caught up to moves.
                    self.lineage
                        .insert(key, expected.advanced_to(saved.revision));
                    tracing::info!(
                        service = "sql",
                        mode = "wal",
                        bytes = saved.delta_size_bytes,
                        logical_bytes = saved.size_bytes,
                        revision = saved.revision,
                        "Persisted incremental database artifact"
                    );
                    return Ok(());
                }
                Err(
                    DatabaseArtifactError::MissingCheckpoint
                    | DatabaseArtifactError::IncrementalPersistenceUnsupported,
                ) => {}
                Err(error) => return Err(artifact_error_to_sql(error)),
            }
        }

        let payload = handle.checkpoint().await?;
        let bytes = payload.len();
        if growth == GrowthPolicy::Forbid {
            let durable_bytes = self
                .bounded(
                    || SqlBusyStage::ArtifactTransfer,
                    self.bounds.artifact_transfer,
                    self.artifact_repository.load_meta("sql", &key.0, db_name),
                )
                .await?
                .map_err(artifact_error_to_sql)?
                .map_or(0, |artifact| artifact.size_bytes.max(0) as u64);
            if bytes as u64 > durable_bytes {
                return Err(SqlError::StorageWouldGrow);
            }
        }
        let saved = self
            .bounded(
                || SqlBusyStage::ArtifactTransfer,
                self.bounds.artifact_transfer,
                self.artifact_repository.save(
                    "sql",
                    &space.to_string(),
                    db_name,
                    payload,
                    expected,
                ),
            )
            .await?
            .map_err(artifact_error_to_sql)?;
        self.lineage.insert(
            key,
            ArtifactExpectation::Derived {
                revision: saved.revision,
                checkpoint_content_hash: saved.checkpoint_content_hash.clone(),
            },
        );
        tracing::info!(
            service = "sql",
            mode = "checkpoint",
            bytes,
            logical_bytes = saved.size_bytes,
            revision = saved.revision,
            "Persisted database checkpoint"
        );
        Ok(())
    }
}

/// Whether `payload` carries SQLite's main-database header.
fn is_sqlite_database(payload: &[u8]) -> bool {
    payload.starts_with(SQLITE_MAGIC)
}

/// Whether `payload` carries a SQLite WAL header.
fn is_sqlite_wal(payload: &[u8]) -> bool {
    SQLITE_WAL_MAGIC
        .iter()
        .any(|magic| payload.starts_with(magic))
}

async fn remove_sql_cache_files(path: &Path) -> Result<(), SqlError> {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        match tokio::fs::remove_file(&candidate).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(SqlError::Internal(e.to_string())),
        }
    }
    Ok(())
}

fn sql_wal_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}-wal", path.display()))
}

fn artifact_error_to_sql(err: DatabaseArtifactError) -> SqlError {
    match err {
        DatabaseArtifactError::Db(ref error) if is_transient_error(error) => {
            tracing::warn!(
                service = "sql",
                error_class = transient_error_class(error).unwrap_or("other"),
                "Database artifact storage unavailable"
            );
            SqlError::Unavailable
        }
        // The row kept changing across every restart. Nothing was written, so
        // a fresh request is safe: the same answer as any contended store.
        DatabaseArtifactError::ArtifactChanged => {
            tracing::warn!(
                service = "sql",
                error_class = "artifact_changed",
                "Database artifact kept changing while it was read"
            );
            SqlError::Unavailable
        }
        err => SqlError::Internal(err.to_string()),
    }
}

/// The request's point of no return (TC-1274): the next step hands the
/// statement to the actor, which applies it whether or not anyone is still
/// waiting. Latch the request so its deadline can no longer answer
/// `request_timeout`, unless the deadline has already passed or cut it.
fn begin_write() -> Result<(), SqlError> {
    let Some(context) = request_cancel::current() else {
        return Ok(());
    };
    if context.is_open() && Instant::now() >= context.deadline() && context.cut() {
        return Err(SqlError::RequestTimeout);
    }
    if context.latch() {
        Ok(())
    } else {
        Err(SqlError::RequestTimeout)
    }
}

fn hydration_failure(error: SqlError) -> HydrationOutcome {
    match error {
        SqlError::Unavailable => HydrationOutcome::Unavailable,
        SqlError::Internal(message) => HydrationOutcome::Failed(message),
        error => HydrationOutcome::Failed(error.to_string()),
    }
}

impl From<SqlBusyStage> for request_cancel::Stage {
    fn from(stage: SqlBusyStage) -> Self {
        match stage {
            SqlBusyStage::LockWait => request_cancel::Stage::LockWait,
            SqlBusyStage::Hydration => request_cancel::Stage::Hydration,
            SqlBusyStage::ArtifactTransfer => request_cancel::Stage::ArtifactTransfer,
        }
    }
}

/// The typed busy event; each stage has its own fixed message so the log
/// shipper can map it to a code (`log-shipper/diagnostics.json`).
fn log_busy(stage: SqlBusyStage, bound: Duration, waited: Duration) {
    let bound_ms = bound.as_millis() as u64;
    let waited_ms = waited.as_millis() as u64;
    let stage_name = stage.as_str();
    match stage {
        SqlBusyStage::LockWait => tracing::warn!(
            service = "sql",
            error_class = "sql_busy",
            stage = stage_name,
            bound_ms,
            waited_ms,
            "SQL busy: lock wait"
        ),
        SqlBusyStage::Hydration => tracing::warn!(
            service = "sql",
            error_class = "sql_busy",
            stage = stage_name,
            bound_ms,
            waited_ms,
            "SQL busy: hydration"
        ),
        SqlBusyStage::ArtifactTransfer => tracing::warn!(
            service = "sql",
            error_class = "sql_busy",
            stage = stage_name,
            bound_ms,
            waited_ms,
            "SQL busy: artifact transfer"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_artifacts::staging_path as temp_write_path;
    use crate::{
        database_artifacts::{
            test_support::ReadAll, ArtifactMeta, ArtifactSink, DatabaseArtifact, DeltaSave,
            SeaOrmDatabaseArtifactRepository,
        },
        migrations::Migrator,
        sea_orm::{ConnectOptions, Database, DbErr},
        sea_orm_migration::MigratorTrait,
        sql_sizes::{SizeTrackingArtifactRepository, SqlSizes},
    };
    use async_trait::async_trait;
    use std::sync::atomic::AtomicU64;
    use tempfile::TempDir;
    use tinycloud_auth::{
        resolver::DID_METHODS,
        ssi::{dids::DIDBuf, jwk::JWK},
    };

    fn test_space_id(name: &str) -> SpaceId {
        let jwk = JWK::generate_ed25519().unwrap();
        let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
        SpaceId::new(did, name.parse().unwrap())
    }

    async fn artifact_repository() -> Arc<SeaOrmDatabaseArtifactRepository> {
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        Arc::new(SeaOrmDatabaseArtifactRepository::new(db))
    }

    #[tokio::test]
    async fn tc626_export_guarded_errors_discard_absent_actors() {
        for memory_threshold in [u64::MAX, 0] {
            let sizes = SqlSizes::new();
            let repo = Arc::new(SizeTrackingArtifactRepository::new(
                artifact_repository().await,
                sizes.clone(),
            ));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("sql-rejected-export");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo.clone(),
            );
            for (name, sql) in [
                ("quota", "CREATE TABLE refused (id INTEGER)"),
                ("sql-error", "INSERT INTO missing_table VALUES (1)"),
            ] {
                let original = service.handle(&space, name).await.unwrap();
                let rejected = service
                    .execute_without_growth(
                        &space,
                        name,
                        SqlRequest::Execute {
                            schema: None,
                            sql: sql.into(),
                            params: vec![],
                        },
                        None,
                        "tinycloud.sql/admin".into(),
                    )
                    .await;
                match name {
                    "quota" => assert!(
                        matches!(rejected, Err(SqlError::StorageWouldGrow)),
                        "{rejected:?}"
                    ),
                    _ => assert!(matches!(rejected, Err(SqlError::Sqlite(_))), "{rejected:?}"),
                }
                // Rejection must close the actor, not merely remove its cache entry.
                let old_actor = original
                    .execute(
                        SqlRequest::Query {
                            sql: "SELECT 1".into(),
                            params: vec![],
                            max_rows: None,
                            max_bytes: None,
                        },
                        None,
                        "tinycloud.sql/read".into(),
                        GrowthPolicy::Allow,
                    )
                    .await;
                assert!(
                    matches!(old_actor, Err(SqlError::Internal(_))),
                    "{old_actor:?}"
                );
                assert!(matches!(
                    service.export(&space, name).await,
                    Err(SqlError::DatabaseNotFound)
                ));
                assert_eq!(sizes.space_total(&space).await, 0);
                assert!(repo
                    .read_all("sql", &space.to_string(), name)
                    .await
                    .unwrap()
                    .is_none());
            }
        }
    }

    #[tokio::test]
    async fn tc626_export_query_only_database_is_not_found() {
        for memory_threshold in [u64::MAX, 0] {
            let sizes = SqlSizes::new();
            let repo = Arc::new(SizeTrackingArtifactRepository::new(
                artifact_repository().await,
                sizes.clone(),
            ));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("sql-query-export");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo.clone(),
            );
            let result = service
                .execute(
                    &space,
                    "main",
                    SqlRequest::Query {
                        sql: "SELECT 1".into(),
                        params: vec![],
                        max_rows: None,
                        max_bytes: None,
                    },
                    None,
                    "tinycloud.sql/read".into(),
                )
                .await
                .unwrap();
            let SqlResponse::Query(query) = result.response else {
                panic!("query response required")
            };
            assert_eq!(query.rows, vec![vec![SqlValue::Integer(1)]]);
            assert!(matches!(
                service.export(&space, "main").await,
                Err(SqlError::DatabaseNotFound)
            ));
            assert_eq!(sizes.space_total(&space).await, 0);
            assert!(repo
                .read_all("sql", &space.to_string(), "main")
                .await
                .unwrap()
                .is_none());
        }
    }

    #[tokio::test]
    async fn tc626_review_absent_noops_do_not_create_charged_artifacts() {
        for memory_threshold in [u64::MAX, 0] {
            let sizes = SqlSizes::new();
            let repo = Arc::new(SizeTrackingArtifactRepository::new(
                artifact_repository().await,
                sizes.clone(),
            ));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("sql-absent-noops");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo.clone(),
            );
            for name in ["unused-one", "unused-two", "unused-three"] {
                service
                    .execute_without_growth(
                        &space,
                        name,
                        SqlRequest::Execute {
                            schema: None,
                            sql: "DROP TABLE IF EXISTS absent".into(),
                            params: vec![],
                        },
                        None,
                        "tinycloud.sql/admin".into(),
                    )
                    .await
                    .expect("dropping an absent table is a successful no-op");
                assert_eq!(sizes.space_total(&space).await, 0);
                assert!(repo
                    .read_all("sql", &space.to_string(), name)
                    .await
                    .unwrap()
                    .is_none());
                assert!(matches!(
                    service.export(&space, name).await,
                    Err(SqlError::DatabaseNotFound)
                ));
            }
        }
    }

    #[tokio::test]
    async fn tc626_review_serialized_growth_is_rejected_and_discarded() {
        for memory_threshold in [u64::MAX, 0] {
            let sizes = SqlSizes::new();
            let repo = Arc::new(SizeTrackingArtifactRepository::new(
                artifact_repository().await,
                sizes.clone(),
            ));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("sql-durable-budget");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo.clone(),
            );
            service
                .execute(
                    &space,
                    "main",
                    SqlRequest::Execute {
                        schema: Some(vec!["CREATE TABLE data (id INTEGER, body TEXT)".into()]),
                        sql: "INSERT INTO data VALUES (1, 'durable')".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                )
                .await
                .unwrap();
            let before = repo
                .read_all("sql", &space.to_string(), "main")
                .await
                .unwrap()
                .unwrap();

            // A failing request no longer leaves a committed prefix (TC-1491),
            // so put the actor ahead of its last durable checkpoint directly:
            // the durable-size comparison must still hold against live state
            // that was never persisted.
            let actor = service.handle(&space, "main").await.unwrap();
            actor
                .execute(
                    SqlRequest::Execute {
                        schema: None,
                        sql: "INSERT INTO data VALUES (2, hex(zeroblob(65536)))".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                    GrowthPolicy::Allow,
                )
                .await
                .unwrap();
            let rejected = service
                .execute_without_growth(
                    &space,
                    "main",
                    SqlRequest::Execute {
                        schema: None,
                        sql: "DELETE FROM data WHERE id = 1".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                )
                .await;
            assert!(
                matches!(rejected, Err(SqlError::StorageWouldGrow)),
                "{rejected:?}"
            );
            let after = repo
                .read_all("sql", &space.to_string(), "main")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(after.revision, before.revision);
            assert_eq!(after.payload, before.payload);
            assert_eq!(after.delta_payload, before.delta_payload);
            assert_eq!(sizes.space_total(&space).await, before.size_bytes as u64);

            let query = || SqlRequest::Query {
                sql: "SELECT id, body FROM data ORDER BY id".into(),
                params: vec![],
                max_rows: None,
                max_bytes: None,
            };
            let live = service
                .execute(&space, "main", query(), None, "tinycloud.sql/read".into())
                .await
                .unwrap();
            let SqlResponse::Query(live) = live.response else {
                panic!("query response required")
            };
            assert_eq!(
                live.rows,
                vec![vec![SqlValue::Integer(1), SqlValue::Text("durable".into())]]
            );
            service
                .execute(
                    &space,
                    "main",
                    SqlRequest::Execute {
                        schema: None,
                        sql: "UPDATE data SET body = 'later' WHERE id = 1".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                )
                .await
                .unwrap();
            let cold_cache = TempDir::new().unwrap();
            let recovered = SqlService::new(
                cold_cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo,
            );
            let cold = recovered
                .execute(&space, "main", query(), None, "tinycloud.sql/read".into())
                .await
                .unwrap();
            let SqlResponse::Query(cold) = cold.response else {
                panic!("query response required")
            };
            assert_eq!(
                cold.rows,
                vec![vec![SqlValue::Integer(1), SqlValue::Text("later".into())]]
            );
        }
    }

    #[tokio::test]
    async fn sql_schema_ability_can_create_schema() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let space = test_space_id("sql-schema");
        let service = SqlService::new(cache.path().to_string_lossy().to_string(), u64::MAX, repo);

        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
                        .to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/schema".to_string(),
            )
            .await
            .expect("schema ability should create tables");
    }

    fn ddl(sql: &str) -> SqlRequest {
        SqlRequest::Execute {
            schema: None,
            sql: sql.to_string(),
            params: Vec::new(),
        }
    }

    async fn table_count(service: &SqlService, space: &SpaceId) -> i64 {
        let result = service
            .execute(
                space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT count(*) FROM items".to_string(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".to_string(),
            )
            .await
            .expect("count rows");
        let SqlResponse::Query(rows) = result.response else {
            panic!("expected rows");
        };
        let SqlValue::Integer(count) = rows.rows[0][0] else {
            panic!("expected an integer");
        };
        count
    }

    /// TC-1581 through the service: `write` alone runs data statements and
    /// is refused schema-changing ones; the data it wrote is durable.
    #[tokio::test]
    async fn sql_write_alone_cannot_change_the_schema_but_writes_data() {
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(cache.path().to_string_lossy().to_string(), u64::MAX, repo);
        let space = test_space_id("sql-ddl-needs-schema");

        let refused = service
            .execute(
                &space,
                "main",
                ddl("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)"),
                None,
                "tinycloud.sql/write".to_string(),
            )
            .await;
        assert!(
            matches!(refused, Err(SqlError::PermissionDenied(_))),
            "{refused:?}"
        );

        service
            .execute(
                &space,
                "main",
                ddl("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)"),
                None,
                "tinycloud.sql/schema".to_string(),
            )
            .await
            .expect("schema creates the table");
        for sql in [
            "INSERT INTO items (name) VALUES ('a')",
            "UPDATE items SET name = 'b'",
            "WITH c AS (SELECT 'c' AS name) INSERT INTO items (name) SELECT name FROM c",
        ] {
            service
                .execute(
                    &space,
                    "main",
                    ddl(sql),
                    None,
                    "tinycloud.sql/write".to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("write runs {sql}: {e:?}"));
        }
        for sql in [
            "DROP TABLE items",
            "ALTER TABLE items ADD COLUMN extra TEXT",
            "CREATE INDEX items_name ON items (name)",
        ] {
            let refused = service
                .execute(
                    &space,
                    "main",
                    ddl(sql),
                    None,
                    "tinycloud.sql/write".to_string(),
                )
                .await;
            assert!(
                matches!(refused, Err(SqlError::PermissionDenied(_))),
                "{sql}: {refused:?}"
            );
            // A full space answers the same, not a storage error.
            let refused = service
                .execute_without_growth(
                    &space,
                    "main",
                    ddl(sql),
                    None,
                    "tinycloud.sql/write".to_string(),
                )
                .await;
            assert!(
                matches!(refused, Err(SqlError::PermissionDenied(_))),
                "{sql}: {refused:?}"
            );
        }
        assert_eq!(table_count(&service, &space).await, 2);

        // Mixed `[write, schema]` request, the SDK's migration shape.
        service
            .execute_authorized(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: Some(vec!["ALTER TABLE items ADD COLUMN extra TEXT".to_string()]),
                    sql: "INSERT INTO items (name, extra) VALUES ('d', 'x')".to_string(),
                    params: Vec::new(),
                },
                None,
                SqlAuthority::new(["tinycloud.sql/write", "tinycloud.sql/schema"]),
            )
            .await
            .expect("write and schema together run both statement kinds");
        assert_eq!(table_count(&service, &space).await, 3);
    }

    /// TC-1581 `ddl_requires_schema`: `off` and `log` keep the earlier rule
    /// for `write`; the default is `enforce`.
    #[tokio::test]
    async fn ddl_policy_reaches_the_actor_through_the_service() {
        let _serial = crate::sql::authority::LOG_COUNTER_LOCK.lock().await;
        use crate::sql::authority::DdlPolicy;
        for (policy, write_may_change_schema) in [
            (None, false),
            (Some(DdlPolicy::Enforce), false),
            (Some(DdlPolicy::Log), true),
            (Some(DdlPolicy::Off), true),
        ] {
            let repo = artifact_repository().await;
            let cache = TempDir::new().unwrap();
            let mut service =
                SqlService::new(cache.path().to_string_lossy().to_string(), u64::MAX, repo);
            if let Some(policy) = policy {
                service = service.with_ddl_policy(policy);
            }
            let space = test_space_id("sql-ddl-policy");
            let result = service
                .execute(
                    &space,
                    "main",
                    ddl("CREATE TABLE items (id INTEGER)"),
                    None,
                    "tinycloud.sql/write".to_string(),
                )
                .await;
            assert_eq!(
                result.is_ok(),
                write_may_change_schema,
                "{policy:?}: {result:?}"
            );
        }
    }

    /// TC-1585: a `WITH … INSERT/UPDATE` is a write. It is made durable like
    /// any other write (a fresh node hydrating the artifact sees it) and
    /// reports its target tables for write hooks.
    #[tokio::test]
    async fn cte_wrapped_writes_are_durable_and_reported_as_writes() {
        let repo = artifact_repository().await;
        let cache_one = TempDir::new().unwrap();
        let cache_two = TempDir::new().unwrap();
        let space = test_space_id("sql-cte-write");
        let service = SqlService::new(
            cache_one.path().to_string_lossy().to_string(),
            u64::MAX,
            repo.clone(),
        );
        service
            .execute(
                &space,
                "main",
                ddl("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"),
                None,
                "tinycloud.sql/schema".to_string(),
            )
            .await
            .unwrap();

        for (sql, kind) in [
            (
                "WITH c AS (SELECT 'inserted' AS name) INSERT INTO items (name) SELECT name FROM c",
                "insert",
            ),
            (
                "WITH c AS (SELECT 'updated' AS name) UPDATE items SET name = (SELECT name FROM c)",
                "update",
            ),
        ] {
            let result = service
                .execute(
                    &space,
                    "main",
                    ddl(sql),
                    None,
                    "tinycloud.sql/write".to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("{kind}: {e:?}"));
            assert_eq!(
                result.write_targets,
                vec![crate::write_hooks::TouchedTables::supported(vec![
                    "items".to_string()
                ])],
                "{kind} must report its target table for write hooks"
            );
            let SqlResponse::Execute(response) = result.response else {
                panic!("{kind}: expected an execute response");
            };
            assert_eq!(response.changes, 1, "{kind}");
        }
        drop(service);

        let recreated = SqlService::new(
            cache_two.path().to_string_lossy().to_string(),
            u64::MAX,
            repo,
        );
        let result = recreated
            .execute(
                &space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT name FROM items".to_string(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".to_string(),
            )
            .await
            .unwrap();
        let SqlResponse::Query(rows) = result.response else {
            panic!("expected rows");
        };
        assert_eq!(rows.rows, vec![vec![SqlValue::Text("updated".to_string())]]);
    }

    async fn pragma_value(service: &SqlService, space: &SpaceId, pragma: &str) -> SqlValue {
        let result = service
            .execute(
                space,
                "main",
                SqlRequest::Query {
                    sql: format!("PRAGMA {pragma}"),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/admin".to_string(),
            )
            .await
            .expect("admin reads a pragma");
        let SqlResponse::Query(rows) = result.response else {
            panic!("expected rows");
        };
        rows.rows[0][0].clone()
    }

    /// The connection-level PRAGMAs that request SQL must not be able to change.
    const STATE_PRAGMAS: [&str; 9] = [
        "PRAGMA writable_schema = ON",
        "PRAGMA query_only = ON",
        "PRAGMA foreign_keys = OFF",
        "PRAGMA ignore_check_constraints = ON",
        "PRAGMA recursive_triggers = ON",
        "PRAGMA max_page_count = 1",
        "PRAGMA cache_spill = 0",
        "PRAGMA soft_heap_limit = 1",
        "PRAGMA temp_store_directory = ''",
    ];

    async fn seeded_items(service: &SqlService, space: &SpaceId) {
        service
            .execute(
                space,
                "main",
                ddl("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)"),
                None,
                "tinycloud.sql/schema".to_string(),
            )
            .await
            .unwrap();
        service
            .execute(
                space,
                "main",
                ddl("INSERT INTO items (name) VALUES ('kept')"),
                None,
                "tinycloud.sql/write".to_string(),
            )
            .await
            .unwrap();
    }

    /// TC-1586: connection state is shared by every request on a database, so
    /// no request may change it. An admin may run only a short list of
    /// PRAGMAs (none of which change connection state); the rest are refused
    /// on every request path, and a later `write` request sees the opening
    /// state and cannot edit `sqlite_master`. Covers an in-memory database and
    /// one promoted to a WAL-backed file.
    #[tokio::test]
    async fn an_admin_request_cannot_change_connection_state() {
        for (name, memory_threshold) in [("sql-pragma-mem", u64::MAX), ("sql-pragma-file", 0)] {
            let repo = artifact_repository().await;
            let cache = TempDir::new().unwrap();
            let service = SqlService::new(
                cache.path().to_string_lossy().to_string(),
                memory_threshold,
                repo,
            );
            let space = test_space_id(name);
            seeded_items(&service, &space).await;
            let journal_mode = pragma_value(&service, &space, "journal_mode").await;
            let admin = || "tinycloud.sql/admin".to_string();

            for pragma in STATE_PRAGMAS {
                let query = SqlRequest::Query {
                    sql: pragma.to_string(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                };
                let batch = SqlRequest::Batch {
                    statements: vec![SqlStatement {
                        sql: pragma.to_string(),
                        params: Vec::new(),
                    }],
                };
                let in_schema_list = SqlRequest::Execute {
                    schema: Some(vec![pragma.to_string()]),
                    sql: "SELECT 1".to_string(),
                    params: Vec::new(),
                };
                for request in [ddl(pragma), query, batch, in_schema_list] {
                    let refused = service
                        .execute(&space, "main", request, None, admin())
                        .await;
                    assert!(refused.is_err(), "{name}: {pragma}: {refused:?}");
                }
            }
            for pragma in [
                "journal_mode = DELETE",
                "journal_mode = OFF",
                "locking_mode = EXCLUSIVE",
            ] {
                let refused = service
                    .execute(
                        &space,
                        "main",
                        SqlRequest::Query {
                            sql: format!("PRAGMA {pragma}"),
                            params: Vec::new(),
                            max_rows: None,
                            max_bytes: None,
                        },
                        None,
                        admin(),
                    )
                    .await;
                assert!(refused.is_err(), "{name}: {pragma}: {refused:?}");
            }

            // A named statement is judged the same way.
            let named = Some(SqlCaveats {
                statements: Some(vec![crate::sql::caveats::PreparedStatement {
                    name: "state".into(),
                    sql: "PRAGMA writable_schema = ON".into(),
                }]),
                ..SqlCaveats::default()
            });
            let refused = service
                .execute(
                    &space,
                    "main",
                    SqlRequest::ExecuteStatement {
                        name: "state".into(),
                        params: Vec::new(),
                    },
                    named,
                    admin(),
                )
                .await;
            assert!(refused.is_err(), "{name}: named statement: {refused:?}");

            // The next request starts from the opening state.
            assert_eq!(
                pragma_value(&service, &space, "writable_schema").await,
                SqlValue::Integer(0),
                "{name}"
            );
            assert_eq!(
                pragma_value(&service, &space, "query_only").await,
                SqlValue::Integer(0),
                "{name}"
            );
            assert_eq!(
                pragma_value(&service, &space, "foreign_keys").await,
                SqlValue::Integer(1),
                "{name}"
            );
            assert_eq!(
                pragma_value(&service, &space, "journal_mode").await,
                journal_mode,
                "{name}"
            );

            // A holder of write only can write data, not the schema table.
            service
                .execute(
                    &space,
                    "main",
                    ddl("INSERT INTO items (name) VALUES ('more')"),
                    None,
                    "tinycloud.sql/write".to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: write must still write data: {e:?}"));
            for sql in [
                "UPDATE sqlite_master SET name = 'renamed' WHERE name = 'items'",
                "DELETE FROM sqlite_master WHERE name = 'items'",
            ] {
                let refused = service
                    .execute(
                        &space,
                        "main",
                        ddl(sql),
                        None,
                        "tinycloud.sql/write".to_string(),
                    )
                    .await;
                assert!(
                    refused.is_err(),
                    "{name}: write must not run {sql}: {refused:?}"
                );
            }
            assert_eq!(table_count(&service, &space).await, 2, "{name}");
        }
    }

    /// TC-1586: an admin request that is allowed a PRAGMA (the database header
    /// values) leaves the connection as it found it, and the growth guard
    /// still works on the next request.
    #[tokio::test]
    async fn an_allowed_admin_pragma_leaves_the_growth_guard_working() {
        for (name, memory_threshold) in [
            ("sql-pragma-guard-mem", u64::MAX),
            ("sql-pragma-guard-file", 0),
        ] {
            let repo = artifact_repository().await;
            let cache = TempDir::new().unwrap();
            let service = SqlService::new(
                cache.path().to_string_lossy().to_string(),
                memory_threshold,
                repo,
            );
            let space = test_space_id(name);
            seeded_items(&service, &space).await;

            service
                .execute(
                    &space,
                    "main",
                    ddl("PRAGMA user_version = 7"),
                    None,
                    "tinycloud.sql/admin".to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: user_version is allowed: {e:?}"));
            assert_eq!(
                pragma_value(&service, &space, "user_version").await,
                SqlValue::Integer(7),
                "{name}"
            );
            assert_eq!(
                pragma_value(&service, &space, "foreign_keys").await,
                SqlValue::Integer(1),
                "{name}"
            );

            let grown = service
                .execute_without_growth(
                    &space,
                    "main",
                    SqlRequest::Execute {
                        schema: None,
                        sql: "INSERT INTO items (name) VALUES (?)".to_string(),
                        params: vec![SqlValue::Text("y".repeat(256 * 1024))],
                    },
                    None,
                    "tinycloud.sql/write".to_string(),
                )
                .await;
            assert!(
                matches!(grown, Err(SqlError::StorageWouldGrow)),
                "{name}: the growth guard must still refuse growth: {grown:?}"
            );
            assert_eq!(
                table_count(&service, &space).await,
                1,
                "{name}: refused write undone"
            );
            service
                .execute_without_growth(
                    &space,
                    "main",
                    ddl("DELETE FROM items"),
                    None,
                    "tinycloud.sql/write".to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: a shrinking write passes: {e:?}"));
        }
    }

    /// TC-1586: when the reset after a PRAGMA fails, the actor is retired
    /// rather than serving another request on a connection in unknown state.
    /// The next request rebuilds it from the durable copy, and nothing
    /// persisted before is lost.
    #[tokio::test]
    async fn a_failed_reset_retires_the_actor() {
        for (name, memory_threshold) in [
            ("sql-reset-fails-mem", u64::MAX),
            ("sql-reset-fails-file", 0),
        ] {
            let repo = artifact_repository().await;
            let cache = TempDir::new().unwrap();
            let service = SqlService::new(
                cache.path().to_string_lossy().to_string(),
                memory_threshold,
                repo,
            );
            let space = test_space_id(name);
            seeded_items(&service, &space).await;

            let key = (space.to_string(), "main".to_string());
            crate::sql::database::RESET_FAILURES
                .lock()
                .unwrap()
                .push(key.clone());
            let result = service
                .execute(
                    &space,
                    "main",
                    ddl("PRAGMA user_version = 5"),
                    None,
                    "tinycloud.sql/admin".to_string(),
                )
                .await;
            crate::sql::database::RESET_FAILURES
                .lock()
                .unwrap()
                .retain(|failing| *failing != key);
            assert!(
                matches!(result, Err(SqlError::Internal(_))),
                "{name}: the request must fail closed: {result:?}"
            );

            service
                .execute(
                    &space,
                    "main",
                    ddl("INSERT INTO items (name) VALUES ('after')"),
                    None,
                    "tinycloud.sql/write".to_string(),
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: the next request rebuilds the actor: {e:?}"));
            assert_eq!(table_count(&service, &space).await, 2, "{name}");
        }
    }

    /// TC-626: on a full space, writes that cannot grow the database run and
    /// a growing write is undone. Covers both an in-memory database and one
    /// promoted to a WAL-backed file (threshold 0), which is what large
    /// production databases use.
    #[tokio::test]
    async fn execute_without_growth_keeps_non_growing_writes_and_undoes_growth() {
        for (name, memory_threshold) in [("sql-growth-mem", u64::MAX), ("sql-growth-file", 0)] {
            let repo = artifact_repository().await;
            let cache = TempDir::new().unwrap();
            let space = test_space_id(name);
            let service = SqlService::new(
                cache.path().to_string_lossy().to_string(),
                memory_threshold,
                repo.clone(),
            );
            let write = |sql: &str, params: Vec<SqlValue>| SqlRequest::Execute {
                schema: None,
                sql: sql.to_string(),
                params,
            };
            let ability = || "tinycloud.sql/admin".to_string();
            for row in ["a", "b", "c"] {
                service
                    .execute(
                        &space,
                        "main",
                        SqlRequest::Execute {
                            schema: Some(vec![
                                "CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, body TEXT)"
                                    .to_string(),
                            ]),
                            sql: "INSERT INTO notes (id, body) VALUES (?, ?)".to_string(),
                            params: vec![
                                SqlValue::Text(row.into()),
                                SqlValue::Text("x".repeat(64)),
                            ],
                        },
                        None,
                        ability(),
                    )
                    .await
                    .unwrap();
            }
            let mut charged_bytes = repo
                .read_all("sql", &space.to_string(), "main")
                .await
                .unwrap()
                .unwrap()
                .size_bytes;

            for sql in [
                "CREATE TABLE IF NOT EXISTS notes (id TEXT PRIMARY KEY, body TEXT)",
                "DELETE FROM notes WHERE id = 'a'",
                "UPDATE notes SET body = 'shorter' WHERE id = 'b'",
            ] {
                service
                    .execute_without_growth(&space, "main", write(sql, vec![]), None, ability())
                    .await
                    .unwrap_or_else(|e| panic!("{name}: non-growing write must pass: {e}"));
                let artifact = repo
                    .read_all("sql", &space.to_string(), "main")
                    .await
                    .unwrap()
                    .unwrap();
                assert!(
                    artifact.size_bytes <= charged_bytes,
                    "{name}: {sql} increased charged checkpoint + WAL bytes"
                );
                charged_bytes = artifact.size_bytes;
            }

            let grown = service
                .execute_without_growth(
                    &space,
                    "main",
                    write(
                        "INSERT INTO notes (id, body) VALUES ('big', ?)",
                        vec![SqlValue::Text("y".repeat(256 * 1024))],
                    ),
                    None,
                    ability(),
                )
                .await;
            assert!(
                matches!(grown, Err(SqlError::StorageWouldGrow)),
                "{name}: a growing write must be refused, got {grown:?}"
            );

            // A later successful persistence must not pick up the refused write.
            service
                .execute_without_growth(
                    &space,
                    "main",
                    write("UPDATE notes SET body = body", vec![]),
                    None,
                    ability(),
                )
                .await
                .unwrap();
            let cold_cache = TempDir::new().unwrap();
            let recreated = SqlService::new(
                cold_cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo.clone(),
            );
            for reader in [&service, &recreated] {
                let rows = reader
                    .execute(
                        &space,
                        "main",
                        SqlRequest::Query {
                            sql: "SELECT id, body FROM notes ORDER BY id".to_string(),
                            params: vec![],
                            max_rows: None,
                            max_bytes: None,
                        },
                        None,
                        "tinycloud.sql/read".to_string(),
                    )
                    .await
                    .unwrap();
                match rows.response {
                    SqlResponse::Query(query) => assert_eq!(
                        query.rows,
                        vec![
                            vec![SqlValue::Text("b".into()), SqlValue::Text("shorter".into())],
                            vec![SqlValue::Text("c".into()), SqlValue::Text("x".repeat(64))]
                        ],
                        "{name}: live and rehydrated state must retain the delete, not the refused insert"
                    ),
                    other => panic!("{name}: expected query rows, got {other:?}"),
                }
            }

            service
                .execute_without_growth(
                    &space,
                    "main",
                    write("DROP TABLE notes", vec![]),
                    None,
                    ability(),
                )
                .await
                .unwrap_or_else(|e| panic!("{name}: DROP must pass: {e}"));
            let artifact = repo
                .read_all("sql", &space.to_string(), "main")
                .await
                .unwrap()
                .unwrap();
            assert!(
                artifact.size_bytes <= charged_bytes,
                "{name}: DROP increased charged checkpoint + WAL bytes"
            );
            let dropped_cache = TempDir::new().unwrap();
            let recreated = SqlService::new(
                dropped_cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo,
            );
            let dropped = recreated
                .execute(
                    &space,
                    "main",
                    SqlRequest::Query {
                        sql: "SELECT id FROM notes".into(),
                        params: vec![],
                        max_rows: None,
                        max_bytes: None,
                    },
                    None,
                    "tinycloud.sql/read".into(),
                )
                .await;
            assert!(
                matches!(dropped, Err(SqlError::Sqlite(_))),
                "{name}: the dropped table must remain absent after rehydration"
            );
        }
    }

    #[tokio::test]
    async fn execute_without_growth_rolls_back_growing_batch_before_rehydration() {
        for memory_threshold in [u64::MAX, 0] {
            let repo = artifact_repository().await;
            let cache = TempDir::new().unwrap();
            let cold_cache = TempDir::new().unwrap();
            let space = test_space_id("sql-growth-batch");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo.clone(),
            );
            service
                .execute(
                    &space,
                    "main",
                    SqlRequest::Execute {
                        schema: Some(vec![
                            "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)".into(),
                        ]),
                        sql: "INSERT INTO notes VALUES (1, 'kept')".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                )
                .await
                .unwrap();
            let charged_bytes = repo
                .read_all("sql", &space.to_string(), "main")
                .await
                .unwrap()
                .unwrap()
                .size_bytes;
            for fail_after_growth in [false, true] {
                let mut statements = vec![
                    SqlStatement {
                        sql: "DELETE FROM notes".into(),
                        params: vec![],
                    },
                    SqlStatement {
                        sql: "INSERT INTO notes VALUES (2, ?)".into(),
                        params: vec![SqlValue::Text("x".repeat(256 * 1024))],
                    },
                ];
                if fail_after_growth {
                    statements.push(SqlStatement {
                        sql: "INSERT INTO notes VALUES (2, 'duplicate')".into(),
                        params: vec![],
                    });
                }
                let rejected = service
                    .execute_without_growth(
                        &space,
                        "main",
                        SqlRequest::Batch { statements },
                        None,
                        "tinycloud.sql/admin".into(),
                    )
                    .await;
                assert!(matches!(rejected, Err(SqlError::StorageWouldGrow)));
            }

            // Persist again so an escaped prefix or insertion cannot hide only
            // in the old actor's cache and disappear on cold hydration.
            service
                .execute_without_growth(
                    &space,
                    "main",
                    SqlRequest::Execute {
                        schema: None,
                        sql: "UPDATE notes SET body = body".into(),
                        params: vec![],
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                )
                .await
                .unwrap();
            let artifact = repo
                .read_all("sql", &space.to_string(), "main")
                .await
                .unwrap()
                .unwrap();
            assert!(artifact.size_bytes <= charged_bytes);
            let recreated = SqlService::new(
                cold_cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo,
            );
            let result = recreated
                .execute(
                    &space,
                    "main",
                    SqlRequest::Query {
                        sql: "SELECT id, body FROM notes".into(),
                        params: vec![],
                        max_rows: None,
                        max_bytes: None,
                    },
                    None,
                    "tinycloud.sql/read".into(),
                )
                .await
                .unwrap();
            let SqlResponse::Query(query) = result.response else {
                panic!("expected query response");
            };
            assert_eq!(
                query.rows,
                vec![vec![SqlValue::Integer(1), SqlValue::Text("kept".into())]]
            );
        }
    }

    #[tokio::test]
    async fn sql_write_export_is_not_throttled_by_backup_pacing() {
        // Regression for tinycloud-node#112: handle_export paced the SQLite
        // backup at 5 pages / 250ms, capping export at ~80KB/s of database
        // size. Every write exports the full database, so a write on a ~2MB
        // database took ~25s and a production-sized (45MB) one ~9 minutes.
        let repo = artifact_repository().await;
        let cache = TempDir::new().unwrap();
        let space = test_space_id("sql-export-speed");
        let service = SqlService::new(cache.path().to_string_lossy().to_string(), u64::MAX, repo);

        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "CREATE TABLE blobs (id INTEGER PRIMARY KEY, body TEXT NOT NULL)"
                        .to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/schema".to_string(),
            )
            .await
            .expect("create table");

        // Grow the database to ~2MB (1MB of random bytes hex-encoded).
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO blobs (body) VALUES (hex(randomblob(1000000)))".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/admin".to_string(),
            )
            .await
            .expect("grow database");

        let start = std::time::Instant::now();
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO blobs (body) VALUES ('tiny')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/admin".to_string(),
            )
            .await
            .expect("small write");
        let elapsed = start.elapsed();
        assert!(
            elapsed < std::time::Duration::from_secs(10),
            "small write on a ~2MB database took {elapsed:?}; the export backup must not be paced"
        );
    }

    #[tokio::test]
    async fn sql_write_survives_service_recreation_with_empty_cache() {
        let repo = artifact_repository().await;
        let cache_one = TempDir::new().unwrap();
        let cache_two = TempDir::new().unwrap();
        let space = test_space_id("sql-hydrate");

        let service = SqlService::new(
            cache_one.path().to_string_lossy().to_string(),
            u64::MAX,
            repo.clone(),
        );
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: Some(vec![
                        "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
                            .to_string(),
                    ]),
                    sql: "INSERT INTO items (name) VALUES (?)".to_string(),
                    params: vec![SqlValue::Text("durable".to_string())],
                },
                None,
                "tinycloud.sql/admin".to_string(),
            )
            .await
            .unwrap();
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO items (name) VALUES (?)".to_string(),
                    params: vec![SqlValue::Text("updated".to_string())],
                },
                None,
                "tinycloud.sql/admin".to_string(),
            )
            .await
            .unwrap();
        drop(service);

        let recreated = SqlService::new(
            cache_two.path().to_string_lossy().to_string(),
            u64::MAX,
            repo,
        );
        let result = recreated
            .execute(
                &space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT name FROM items ORDER BY id".to_string(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".to_string(),
            )
            .await
            .unwrap();

        match result.response {
            SqlResponse::Query(query) => {
                assert_eq!(query.row_count, 2);
                assert_eq!(query.rows[0][0], SqlValue::Text("durable".to_string()));
                assert_eq!(query.rows[1][0], SqlValue::Text("updated".to_string()));
            }
            other => panic!("expected query response, got {:?}", other),
        }

        let hydrated_path = cache_two.path().join(space.to_string()).join("main.db");
        assert!(
            hydrated_path.exists(),
            "durable artifact should hydrate cache"
        );
    }

    #[tokio::test]
    async fn file_backed_small_writes_persist_wal_not_full_database() {
        let repo = artifact_repository().await;
        let cache_one = TempDir::new().unwrap();
        let cache_two = TempDir::new().unwrap();
        let space = test_space_id("sql-wal-delta");
        let service = SqlService::new(
            cache_one.path().to_string_lossy().to_string(),
            0,
            repo.clone(),
        );

        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)"
                        .to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/schema".to_string(),
            )
            .await
            .unwrap();
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO items (name) VALUES ('one')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/admin".to_string(),
            )
            .await
            .unwrap();

        let artifact = repo
            .read_all("sql", &space.to_string(), "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(artifact.storage_mode, "checkpoint+wal");
        assert!(artifact.delta_size_bytes > 0);
        println!(
            "sql artifact persistence: checkpoint={} delta={}",
            artifact.payload.len(),
            artifact.delta_size_bytes
        );
        assert!(
            artifact.delta_size_bytes < artifact.payload.len() as i64,
            "a small write should transfer fewer bytes than the checkpoint"
        );

        // User-facing export must not reset the WAL baseline. A later delta
        // still has to contain both acknowledged writes.
        service.export(&space, "main").await.unwrap();
        let after_export = repo
            .read_all("sql", &space.to_string(), "main")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(after_export.revision, artifact.revision);
        assert_eq!(after_export.payload, artifact.payload);
        assert_eq!(after_export.delta_payload, artifact.delta_payload);
        assert_eq!(after_export.size_bytes, artifact.size_bytes);
        service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO items (name) VALUES ('two')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/admin".to_string(),
            )
            .await
            .unwrap();

        let recreated = SqlService::new(cache_two.path().to_string_lossy().to_string(), 0, repo);
        let result = recreated
            .execute(
                &space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT name FROM items ORDER BY id".to_string(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".to_string(),
            )
            .await
            .unwrap();
        match result.response {
            SqlResponse::Query(query) => {
                assert_eq!(query.row_count, 2);
                assert_eq!(query.rows[0][0], SqlValue::Text("one".to_string()));
                assert_eq!(query.rows[1][0], SqlValue::Text("two".to_string()));
            }
            other => panic!("expected query response, got {other:?}"),
        }
    }

    #[test]
    fn hydration_temp_paths_never_collide_between_checkpoint_and_wal() {
        let database = PathBuf::from("/cache/space/main.db");
        let wal = sql_wal_path(&database);

        // The defect: `with_extension` REPLACES the last extension, so the two
        // distinct targets of one hydration mapped onto a single temp file and
        // cross-consumed each other's bytes.
        assert_eq!(
            database.with_extension("db.tmp"),
            wal.with_extension("db.tmp"),
            "this equality is the bug being fixed; if it ever stops holding the \
             regression below no longer proves anything"
        );

        let database_temp = temp_write_path(&database);
        let wal_temp = temp_write_path(&wal);
        assert_ne!(database_temp, wal_temp);
        assert_ne!(
            temp_write_path(&database),
            temp_write_path(&database),
            "two writes of one target must not share a temp path either"
        );

        // Same directory, so the rename that publishes the file stays atomic.
        assert_eq!(database_temp.parent(), database.parent());
        assert_eq!(wal_temp.parent(), wal.parent());
        // And a temp path must never be mistaken for the file it stages.
        assert_ne!(database_temp, database);
        assert_ne!(wal_temp, wal);
    }

    #[test]
    fn hydration_payload_headers_are_checked_against_their_role() {
        let database = [SQLITE_MAGIC, &[0u8; 84][..]].concat();
        let wal = [&[0x37, 0x7f, 0x06, 0x82][..], &[0u8; 28][..]].concat();
        let wal_big_endian_checksums = [&[0x37, 0x7f, 0x06, 0x83][..], &[0u8; 28][..]].concat();

        assert!(is_sqlite_database(&database));
        assert!(is_sqlite_wal(&wal));
        assert!(is_sqlite_wal(&wal_big_endian_checksums));

        // The two cross-consumption outcomes the temp-path collision produced.
        assert!(
            !is_sqlite_database(&wal),
            "WAL bytes on the database path open as a fresh empty database"
        );
        assert!(
            !is_sqlite_wal(&database),
            "checkpoint bytes on the WAL path make SQLite ignore the WAL"
        );

        assert!(!is_sqlite_database(&[]));
        assert!(!is_sqlite_wal(&[]));
        assert!(!is_sqlite_database(&SQLITE_MAGIC[..8]));
    }

    #[tokio::test]
    async fn hydration_rejects_a_checkpoint_that_is_not_a_database() {
        let repo = artifact_repository().await;
        let space = test_space_id("sql-bad-header");
        // A durable row whose payload is not a database: hydrating it would
        // hand SQLite bytes it opens as an empty database, and the next write
        // would make that emptiness durable.
        repo.save(
            "sql",
            &space.to_string(),
            "main",
            vec![0x37, 0x7f, 0x06, 0x82, 0, 0, 0, 0],
            ArtifactExpectation::Any,
        )
        .await
        .unwrap();

        let cache = TempDir::new().unwrap();
        let service = SqlService::new(cache.path().to_string_lossy().to_string(), u64::MAX, repo);
        let err = service
            .execute(
                &space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT 1".to_string(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".to_string(),
            )
            .await
            .expect_err("hydration must refuse a checkpoint with no SQLite header");
        assert!(
            matches!(&err, SqlError::Internal(message) if message.contains("file header")),
            "expected a loud header failure, got {err:?}"
        );
        assert!(
            !cache
                .path()
                .join(space.to_string())
                .join("main.db")
                .exists(),
            "a rejected payload must never reach the cache"
        );
    }

    /// Counts `load` calls so a test can assert how many hydrations ran.
    struct CountingArtifactRepository {
        inner: Arc<SeaOrmDatabaseArtifactRepository>,
        loads: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[async_trait]
    impl DatabaseArtifactRepository for CountingArtifactRepository {
        async fn load_meta(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
            self.loads.fetch_add(1, Ordering::Relaxed);
            self.inner.load_meta(service, space, name).await
        }

        async fn read_chunks(
            &self,
            service: &str,
            space: &str,
            name: &str,
            meta: &ArtifactMeta,
            sink: &mut dyn ArtifactSink,
        ) -> Result<(), DatabaseArtifactError> {
            self.inner
                .read_chunks(service, space, name, meta, sink)
                .await
        }

        async fn save(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            self.inner
                .save(service, space, name, payload, expected)
                .await
        }

        async fn save_delta(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DeltaSave, DatabaseArtifactError> {
            self.inner
                .save_delta(service, space, name, payload, expected)
                .await
        }
    }

    #[tokio::test]
    async fn concurrent_cold_reads_hydrate_the_cache_exactly_once() {
        let repo = artifact_repository().await;
        let space = test_space_id("sql-cold-stampede");
        let seed_cache = TempDir::new().unwrap();
        let seed = SqlService::new(
            seed_cache.path().to_string_lossy().to_string(),
            u64::MAX,
            repo.clone(),
        );
        seed.execute(
            &space,
            "main",
            SqlRequest::Execute {
                schema: Some(vec![
                    "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT NOT NULL)".to_string(),
                ]),
                sql: "INSERT INTO items (name) VALUES ('durable')".to_string(),
                params: Vec::new(),
            },
            None,
            "tinycloud.sql/admin".to_string(),
        )
        .await
        .unwrap();
        drop(seed);

        // A cold service, then a stampede of readers for one database. Each
        // hydration deletes and rewrites the files the others are writing (and
        // that the actor will open), so exactly one may run.
        let loads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().to_string(),
            u64::MAX,
            Arc::new(CountingArtifactRepository {
                inner: repo,
                loads: loads.clone(),
            }),
        );

        let readers = (0..8)
            .map(|_| {
                let service = service.clone();
                let space = space.clone();
                tokio::spawn(async move {
                    service
                        .execute(
                            &space,
                            "main",
                            SqlRequest::Query {
                                sql: "SELECT name FROM items".to_string(),
                                params: Vec::new(),
                                max_rows: None,
                                max_bytes: None,
                            },
                            None,
                            "tinycloud.sql/read".to_string(),
                        )
                        .await
                })
            })
            .collect::<Vec<_>>();

        for reader in readers {
            let result = reader.await.unwrap().expect("every cold reader must serve");
            match result.response {
                SqlResponse::Query(query) => assert_eq!(query.row_count, 1),
                other => panic!("expected query response, got {other:?}"),
            }
        }
        assert_eq!(
            loads.load(Ordering::Relaxed),
            1,
            "the miss -> hydrate -> spawn window must be serialized per database"
        );
    }

    /// Fails the next `failures` repository calls with `error`, then
    /// delegates.
    struct FlakyArtifactRepository {
        inner: Arc<SeaOrmDatabaseArtifactRepository>,
        failures: AtomicU64,
        error: fn() -> DbErr,
    }

    /// Performs every save, then reports the first `lost_replies` of them
    /// as lost connections: the write committed, its reply never arrived.
    struct LostReplyArtifactRepository {
        inner: Arc<SeaOrmDatabaseArtifactRepository>,
        lost_replies: AtomicU64,
    }

    impl LostReplyArtifactRepository {
        fn lose_reply(&self) -> Result<(), DatabaseArtifactError> {
            let losing = self
                .lost_replies
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if losing {
                Err(DatabaseArtifactError::Db(DbErr::Exec(
                    sea_orm::RuntimeErr::SqlxError(sea_orm::error::SqlxError::Io(
                        std::io::Error::from(std::io::ErrorKind::TimedOut),
                    )),
                )))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl DatabaseArtifactRepository for LostReplyArtifactRepository {
        async fn load_meta(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
            self.inner.load_meta(service, space, name).await
        }

        async fn read_chunks(
            &self,
            service: &str,
            space: &str,
            name: &str,
            meta: &ArtifactMeta,
            sink: &mut dyn ArtifactSink,
        ) -> Result<(), DatabaseArtifactError> {
            self.inner
                .read_chunks(service, space, name, meta, sink)
                .await
        }

        async fn save(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            let saved = self
                .inner
                .save(service, space, name, payload, expected)
                .await?;
            self.lose_reply()?;
            Ok(saved)
        }

        async fn save_delta(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DeltaSave, DatabaseArtifactError> {
            let saved = self
                .inner
                .save_delta(service, space, name, payload, expected)
                .await?;
            self.lose_reply()?;
            Ok(saved)
        }
    }

    /// TC-1054 (Astra's P2): a persist whose write committed but whose reply
    /// was lost is `OutcomeUnknown`, not a retryable `Unavailable`: the write
    /// is durable, and a blind fresh retry would apply it twice.
    #[tokio::test]
    async fn a_lost_commit_reply_is_an_unknown_outcome() {
        let repo = Arc::new(LostReplyArtifactRepository {
            inner: artifact_repository().await,
            lost_replies: AtomicU64::new(0),
        });
        let cache = TempDir::new().unwrap();
        let space = test_space_id("sql-lost-reply");
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        );
        let write = |value: &'static str| {
            service.execute(
                &space,
                "a",
                insert(value),
                None,
                "tinycloud.sql/admin".into(),
            )
        };
        write("first").await.unwrap();

        repo.lost_replies.store(1, Ordering::SeqCst);
        let err = write("second").await.expect_err("the reply was lost");
        assert!(matches!(err, SqlError::OutcomeUnknown), "{err:?}");
        // The write is durable: reading back (after re-hydration) shows it,
        // which is what the client must do before deciding to retry.
        let read = service
            .execute(&space, "a", count(), None, "tinycloud.sql/read".into())
            .await
            .unwrap();
        match read.response {
            SqlResponse::Query(query) => {
                assert_eq!(query.rows, vec![vec![SqlValue::Integer(2)]])
            }
            other => panic!("expected a query response, got {other:?}"),
        }
    }

    impl FlakyArtifactRepository {
        fn fail(&self) -> Result<(), DatabaseArtifactError> {
            let failing = self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
            if failing {
                Err(DatabaseArtifactError::Db((self.error)()))
            } else {
                Ok(())
            }
        }
    }

    #[async_trait]
    impl DatabaseArtifactRepository for FlakyArtifactRepository {
        async fn load_meta(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
            self.fail()?;
            self.inner.load_meta(service, space, name).await
        }

        async fn read_chunks(
            &self,
            service: &str,
            space: &str,
            name: &str,
            meta: &ArtifactMeta,
            sink: &mut dyn ArtifactSink,
        ) -> Result<(), DatabaseArtifactError> {
            self.inner
                .read_chunks(service, space, name, meta, sink)
                .await
        }

        async fn save(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            self.fail()?;
            self.inner
                .save(service, space, name, payload, expected)
                .await
        }

        async fn save_delta(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DeltaSave, DatabaseArtifactError> {
            self.fail()?;
            self.inner
                .save_delta(service, space, name, payload, expected)
                .await
        }
    }

    fn insert(value: &str) -> SqlRequest {
        SqlRequest::Execute {
            schema: Some(vec![
                "CREATE TABLE IF NOT EXISTS items (name TEXT)".to_string()
            ]),
            sql: format!("INSERT INTO items (name) VALUES ('{value}')"),
            params: Vec::new(),
        }
    }

    fn count() -> SqlRequest {
        SqlRequest::Query {
            sql: "SELECT COUNT(*) FROM items".to_string(),
            params: Vec::new(),
            max_rows: None,
            max_bytes: None,
        }
    }

    /// TC-1054: a lost connection, an exhausted pool or a statement timeout
    /// on the durable store, during hydration or persistence, is a
    /// retryable `Unavailable` (503), not an internal error; the database's
    /// operation lock is released on that path, so the next request on the
    /// same database runs instead of queueing behind it.
    #[tokio::test]
    async fn transient_storage_errors_are_unavailable_and_release_the_lock() {
        let lost: fn() -> DbErr = || {
            DbErr::Exec(sea_orm::RuntimeErr::SqlxError(
                sea_orm::error::SqlxError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut)),
            ))
        };
        let exhausted: fn() -> DbErr =
            || DbErr::ConnectionAcquire(sea_orm::error::ConnAcquireErr::Timeout);
        for error in [lost, exhausted] {
            let inner = artifact_repository().await;
            let repo = Arc::new(FlakyArtifactRepository {
                inner: inner.clone(),
                failures: AtomicU64::new(0),
                error,
            });
            let cache = TempDir::new().unwrap();
            let space = test_space_id("sql-transient");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                u64::MAX,
                repo.clone(),
            );
            // The bound is above every bounded wait on this path (lock 30 s,
            // hydration 30 s, transfer 45 s), so a slow-but-bounded stall
            // surfaces as a typed `Busy(stage)` naming the stage; only an
            // unbounded wait trips this timeout (TC-1317 review).
            let run = |db: &'static str, request: SqlRequest, ability: &'static str| {
                let service = &service;
                let space = &space;
                async move {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(60),
                        service.execute(space, db, request, None, ability.to_string()),
                    )
                    .await
                    .expect("a request on a database whose last request failed must not wait")
                }
            };
            for db in ["a", "b"] {
                run(db, insert("seed"), "tinycloud.sql/admin")
                    .await
                    .unwrap();
            }

            // Persistence fails: the write is refused as retryable.
            repo.failures.store(1, Ordering::SeqCst);
            let err = run("a", insert("lost"), "tinycloud.sql/admin")
                .await
                .expect_err("a write whose persist failed must fail");
            assert!(matches!(err, SqlError::Unavailable), "{err:?}");
            // The lock was released and the failed write's local state
            // discarded: the next write on `a` re-hydrates and succeeds,
            // and `b` was never affected.
            run("a", insert("retried"), "tinycloud.sql/admin")
                .await
                .unwrap();
            run("b", count(), "tinycloud.sql/read").await.unwrap();

            // Hydration fails on a cold node: retryable, then served.
            let cold_cache = TempDir::new().unwrap();
            let cold = SqlService::new(
                cold_cache.path().to_string_lossy().into_owned(),
                u64::MAX,
                repo.clone(),
            );
            repo.failures.store(1, Ordering::SeqCst);
            let err = cold
                .execute(&space, "a", count(), None, "tinycloud.sql/read".into())
                .await
                .expect_err("a read whose hydration failed must fail");
            assert!(matches!(err, SqlError::Unavailable), "{err:?}");
            let served = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                cold.execute(&space, "a", count(), None, "tinycloud.sql/read".into()),
            )
            .await
            .expect("the hydration failure released the lock")
            .unwrap();
            match served.response {
                SqlResponse::Query(query) => {
                    assert_eq!(query.rows, vec![vec![SqlValue::Integer(2)]])
                }
                other => panic!("expected a query response, got {other:?}"),
            }
        }
    }

    struct FailingArtifactRepository;

    #[async_trait]
    impl DatabaseArtifactRepository for FailingArtifactRepository {
        async fn load_meta(
            &self,
            _service: &str,
            _space: &str,
            _name: &str,
        ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
            Ok(None)
        }

        async fn read_chunks(
            &self,
            _service: &str,
            _space: &str,
            _name: &str,
            _meta: &ArtifactMeta,
            _sink: &mut dyn ArtifactSink,
        ) -> Result<(), DatabaseArtifactError> {
            Ok(())
        }

        async fn save(
            &self,
            _service: &str,
            _space: &str,
            _name: &str,
            _payload: Vec<u8>,
            _expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            Err(DatabaseArtifactError::Backend("forced failure".to_string()))
        }
    }

    #[tokio::test]
    async fn sql_write_fails_when_durable_persistence_fails() {
        let cache = TempDir::new().unwrap();
        let space = test_space_id("sql-failure");
        let service = SqlService::new(
            cache.path().to_string_lossy().to_string(),
            u64::MAX,
            Arc::new(FailingArtifactRepository),
        );

        let err = service
            .execute(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: Some(vec!["CREATE TABLE items (name TEXT NOT NULL)".to_string()]),
                    sql: "INSERT INTO items (name) VALUES ('lost')".to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/admin".to_string(),
            )
            .await
            .expect_err("write must fail when durable save fails");

        assert!(matches!(err, SqlError::Internal(_)));
        assert!(matches!(
            service.export(&space, "main").await,
            Err(SqlError::DatabaseNotFound)
        ));
    }
    #[tokio::test]
    async fn connector_sql_durable_cas_fences_another_node_and_recovers() {
        let repo = artifact_repository().await;
        let space = test_space_id("connector-cas");
        let one = TempDir::new().unwrap();
        let two = TempDir::new().unwrap();
        let first = SqlService::new(one.path().to_string_lossy().into(), u64::MAX, repo.clone());
        let second = SqlService::new(two.path().to_string_lossy().into(), u64::MAX, repo);
        first
            .execute(
                &space,
                "connectors",
                SqlRequest::Execute {
                    sql: "INSERT INTO connector_meeting(id,title) VALUES('old','Original')".into(),
                    params: vec![],
                    schema: Some(vec![
                        "CREATE TABLE connector_meeting(id TEXT PRIMARY KEY,title TEXT)".into(),
                    ]),
                },
                None,
                "tinycloud.sql/admin".into(),
            )
            .await
            .unwrap();
        let query = || SqlRequest::Query {
            sql: "SELECT title FROM connector_meeting WHERE id='old'".into(),
            params: vec![],
            max_rows: None,
            max_bytes: None,
        };
        second
            .execute(
                &space,
                "connectors",
                query(),
                None,
                "tinycloud.sql/read".into(),
            )
            .await
            .unwrap();
        let update = |title: &str| SqlRequest::Execute {
            sql: "UPDATE connector_meeting SET title=? WHERE id='old'".into(),
            params: vec![SqlValue::Text(title.into())],
            schema: None,
        };
        first
            .execute(
                &space,
                "connectors",
                update("First"),
                None,
                "tinycloud.sql/admin".into(),
            )
            .await
            .unwrap();
        assert!(second
            .execute(
                &space,
                "connectors",
                update("Stale"),
                None,
                "tinycloud.sql/admin".into()
            )
            .await
            .is_err());
        second
            .execute(
                &space,
                "connectors",
                update("Recovered"),
                None,
                "tinycloud.sql/admin".into(),
            )
            .await
            .unwrap();
        let result = second
            .execute(
                &space,
                "connectors",
                query(),
                None,
                "tinycloud.sql/read".into(),
            )
            .await
            .unwrap();
        let SqlResponse::Query(query) = result.response else {
            panic!("query result required")
        };
        assert_eq!(query.rows, vec![vec![SqlValue::Text("Recovered".into())]]);
    }

    // TC-1274: bounded waits, deadline cuts, and cancel safety.

    /// Holds `load` and the saves until their gate opens; counts loads and
    /// saves that have reached the gate.
    struct GatedArtifactRepository {
        inner: Arc<SeaOrmDatabaseArtifactRepository>,
        loads: std::sync::atomic::AtomicUsize,
        saves_waiting: std::sync::atomic::AtomicUsize,
        /// Once through the gate, `load` fails as storage being unavailable.
        fail_loads: std::sync::atomic::AtomicBool,
        load_open: tokio::sync::watch::Sender<bool>,
        save_open: tokio::sync::watch::Sender<bool>,
    }

    impl GatedArtifactRepository {
        fn new(inner: Arc<SeaOrmDatabaseArtifactRepository>) -> Arc<Self> {
            Arc::new(Self {
                inner,
                loads: Default::default(),
                saves_waiting: Default::default(),
                fail_loads: Default::default(),
                load_open: tokio::sync::watch::channel(true).0,
                save_open: tokio::sync::watch::channel(true).0,
            })
        }

        fn loads(&self) -> usize {
            self.loads.load(Ordering::SeqCst)
        }

        async fn pass(gate: &tokio::sync::watch::Sender<bool>) {
            let mut open = gate.subscribe();
            let _ = open.wait_for(|open| *open).await;
        }
    }

    #[async_trait]
    impl DatabaseArtifactRepository for GatedArtifactRepository {
        async fn load_meta(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
            self.loads.fetch_add(1, Ordering::SeqCst);
            Self::pass(&self.load_open).await;
            if self.fail_loads.load(Ordering::SeqCst) {
                return Err(DatabaseArtifactError::Db(DbErr::ConnectionAcquire(
                    sea_orm::error::ConnAcquireErr::Timeout,
                )));
            }
            self.inner.load_meta(service, space, name).await
        }

        async fn read_chunks(
            &self,
            service: &str,
            space: &str,
            name: &str,
            meta: &ArtifactMeta,
            sink: &mut dyn ArtifactSink,
        ) -> Result<(), DatabaseArtifactError> {
            self.inner
                .read_chunks(service, space, name, meta, sink)
                .await
        }

        async fn save(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            self.saves_waiting.fetch_add(1, Ordering::SeqCst);
            Self::pass(&self.save_open).await;
            self.inner
                .save(service, space, name, payload, expected)
                .await
        }

        async fn save_delta(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DeltaSave, DatabaseArtifactError> {
            self.saves_waiting.fetch_add(1, Ordering::SeqCst);
            Self::pass(&self.save_open).await;
            self.inner
                .save_delta(service, space, name, payload, expected)
                .await
        }
    }

    fn wait_bounds(millis: u64) -> SqlWaitBounds {
        let bound = Duration::from_millis(millis);
        SqlWaitBounds {
            lock_wait: bound,
            hydration_wait: bound,
            artifact_transfer: bound,
            hydration_max: Duration::from_secs(600),
        }
    }

    /// A durable database `a` in a fresh space, holding one row.
    async fn seeded(name: &str) -> (Arc<SeaOrmDatabaseArtifactRepository>, SpaceId) {
        let repo = artifact_repository().await;
        let space = test_space_id(name);
        let cache = TempDir::new().unwrap();
        SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        )
        .execute(
            &space,
            "a",
            insert("seed"),
            None,
            "tinycloud.sql/admin".into(),
        )
        .await
        .unwrap();
        (repo, space)
    }

    fn rows(result: SqlExecutionResult) -> i64 {
        let SqlResponse::Query(query) = result.response else {
            panic!("query result required")
        };
        match query.rows[..] {
            [ref row] => match row[..] {
                [SqlValue::Integer(count)] => count,
                _ => panic!("one integer column required"),
            },
            _ => panic!("one row required"),
        }
    }

    async fn read(service: &SqlService, space: &SpaceId) -> Result<SqlExecutionResult, SqlError> {
        service
            .execute(space, "a", count(), None, "tinycloud.sql/read".into())
            .await
    }

    const PATIENCE: Duration = Duration::from_secs(10);

    #[tokio::test]
    async fn tc1274_a_held_operation_lock_answers_sql_busy_lock_wait() {
        let (repo, space) = seeded("sql-busy-lock").await;
        let cache = TempDir::new().unwrap();
        // Warm both databases under the default bounds first: the hydration
        // (disk, fsync) is not what this test asserts, only the lock wait,
        // which must not depend on how fast the disk is.
        let service = SqlService::new(cache.path().to_string_lossy().into_owned(), u64::MAX, repo);
        read(&service, &space).await.unwrap();
        service
            .execute(&space, "b", insert("w"), None, "tinycloud.sql/admin".into())
            .await
            .unwrap();
        let service = service.with_wait_bounds(wait_bounds(200));
        let held = service.operation_lock(&space, "a").await.lock_owned().await;

        let err = tokio::time::timeout(PATIENCE, read(&service, &space))
            .await
            .expect("the waiter must give up at its bound")
            .expect_err("a held lock must answer busy");
        assert!(
            matches!(err, SqlError::Busy(SqlBusyStage::LockWait)),
            "{err:?}"
        );
        assert!(err.to_string().starts_with("sql_busy: lock_wait:"), "{err}");

        // Another database in the same space is unaffected.
        service
            .execute(&space, "b", insert("x"), None, "tinycloud.sql/admin".into())
            .await
            .unwrap();
        drop(held);
        assert_eq!(rows(read(&service, &space).await.unwrap()), 1);
    }

    #[tokio::test]
    async fn a_hydration_sweeps_temp_files_a_crashed_one_left_behind() {
        let (repo, space) = seeded("sql-sweep-orphans").await;
        let cache = TempDir::new().unwrap();
        let dir = cache.path().join(space.to_string());
        std::fs::create_dir_all(&dir).unwrap();
        // pid 1 never matches this process's live files: a crashed hydration's.
        let orphan = dir.join("a.db.tmp.1.0");
        let orphan_wal = dir.join("a.db-wal.tmp.1.1");
        let unrelated = dir.join("b.db.tmp.1.0");
        for file in [&orphan, &orphan_wal, &unrelated] {
            std::fs::write(file, b"x").unwrap();
        }
        let service = SqlService::new(cache.path().to_string_lossy().into_owned(), u64::MAX, repo);
        assert_eq!(rows(read(&service, &space).await.unwrap()), 1);
        assert!(!orphan.exists() && !orphan_wal.exists());
        assert!(unrelated.exists(), "another database's file is not ours");
    }

    #[tokio::test]
    async fn tc1274_a_stalled_hydration_answers_busy_and_still_warms_once() {
        let (inner, space) = seeded("sql-busy-hydration").await;
        let repo = GatedArtifactRepository::new(inner);
        repo.load_open.send_replace(false);
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        )
        .with_wait_bounds(wait_bounds(200));

        for caller in ["first", "second"] {
            let err = tokio::time::timeout(PATIENCE, read(&service, &space))
                .await
                .unwrap_or_else(|_| panic!("the {caller} caller must give up at its bound"))
                .expect_err("a stalled artifact load must answer busy");
            assert!(
                matches!(err, SqlError::Busy(SqlBusyStage::ArtifactTransfer)),
                "{caller}: {err:?}"
            );
        }
        assert_eq!(repo.loads(), 1, "the second caller joined the hydration");

        // The hydration was never abandoned: once its load completes, the
        // database is warm and the next request needs no load of its own.
        repo.load_open.send_replace(true);
        let served = tokio::time::timeout(PATIENCE, async {
            loop {
                match read(&service, &space).await {
                    Ok(result) => break result,
                    Err(SqlError::Busy(_)) => tokio::time::sleep(Duration::from_millis(20)).await,
                    Err(error) => panic!("{error:?}"),
                }
            }
        })
        .await
        .expect("the hydration must complete");
        assert_eq!(rows(served), 1);
        assert_eq!(repo.loads(), 1, "exactly one hydration ran");
    }

    #[tokio::test]
    async fn tc1274_a_request_cut_by_its_deadline_releases_the_lock() {
        let (inner, space) = seeded("sql-deadline-cut").await;
        let repo = GatedArtifactRepository::new(inner);
        repo.load_open.send_replace(false);
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        )
        .with_wait_bounds(wait_bounds(30_000));

        let cut = tokio::time::timeout(
            PATIENCE,
            crate::request_cancel::run_with_deadline(
                Some(Duration::from_millis(300)),
                read(&service, &space),
            ),
        )
        .await
        .expect("the deadline must cut the request");
        assert!(
            matches!(cut, Err(crate::request_cancel::DeadlineExceeded)),
            "{cut:?}"
        );
        let lock = service.operation_lock(&space, "a").await;
        tokio::time::timeout(Duration::from_secs(2), lock.lock_owned())
            .await
            .expect("a cut request must release the operation lock");

        repo.load_open.send_replace(true);
        assert_eq!(rows(read(&service, &space).await.unwrap()), 1);
        assert_no_temp_files(cache.path());
    }

    #[tokio::test]
    async fn tc1274_a_latched_write_reports_its_true_outcome_past_the_deadline() {
        let (inner, space) = seeded("sql-deadline-latched").await;
        let repo = GatedArtifactRepository::new(inner);
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        );
        read(&service, &space).await.unwrap();

        repo.save_open.send_replace(false);
        let writer = service.clone();
        let write_space = space.clone();
        let request = tokio::spawn(crate::request_cancel::run_with_deadline(
            Some(Duration::from_millis(200)),
            async move {
                writer
                    .execute(
                        &write_space,
                        "a",
                        insert("late"),
                        None,
                        "tinycloud.sql/admin".into(),
                    )
                    .await
            },
        ));
        // The write is latched before it reaches its save; once it waits
        // there, run past the deadline before letting it finish.
        tokio::time::timeout(PATIENCE, async {
            while repo.saves_waiting.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the write must reach its save");
        tokio::time::sleep(Duration::from_millis(300)).await;
        repo.save_open.send_replace(true);
        let outcome = tokio::time::timeout(PATIENCE, request)
            .await
            .expect("the write must finish")
            .unwrap();
        assert!(matches!(outcome, Ok(Ok(_))), "{outcome:?}");
        assert_eq!(rows(read(&service, &space).await.unwrap()), 2);
    }

    #[tokio::test]
    async fn tc1274_a_dropped_caller_never_leaves_a_half_applied_write() {
        let (inner, space) = seeded("sql-dropped-writer").await;
        let repo = GatedArtifactRepository::new(inner.clone());
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        );
        read(&service, &space).await.unwrap();

        repo.save_open.send_replace(false);
        let writer = service.clone();
        let write_space = space.clone();
        let caller = tokio::spawn(async move {
            writer
                .execute(
                    &write_space,
                    "a",
                    insert("second"),
                    None,
                    "tinycloud.sql/admin".into(),
                )
                .await
        });
        tokio::time::timeout(PATIENCE, async {
            while repo.saves_waiting.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the write must reach its save");
        caller.abort();
        let _ = caller.await;
        repo.save_open.send_replace(true);

        // The write the actor applied is made durable, not left live-only: a
        // cold service over the same store sees it once the save lands.
        let cold_cache = TempDir::new().unwrap();
        let cold = SqlService::new(
            cold_cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            inner,
        );
        tokio::time::timeout(PATIENCE, async {
            loop {
                let durable = rows(read(&cold, &space).await.unwrap());
                if durable == 2 {
                    break;
                }
                assert_eq!(durable, 1, "only the seed row or both rows");
                cold.discard_local_state(&(space.to_string(), "a".to_string()))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the dropped caller's write must still be persisted");
        assert_eq!(rows(read(&service, &space).await.unwrap()), 2);
    }

    /// TC-1274 B1: a save whose write statement is already on the wire when
    /// its bound expires can still commit (PostgreSQL does not cancel it), so
    /// the request must answer `outcome_unknown`, never a `sql_busy` that
    /// invites a retry applying the write twice.
    #[tokio::test]
    async fn postgres_a_save_expiring_after_its_write_was_sent_is_an_unknown_outcome() {
        use crate::sea_orm::{ConnectionTrait, TransactionTrait};
        const TEST: &str =
            "postgres_a_save_expiring_after_its_write_was_sent_is_an_unknown_outcome";
        let Some(schema) = crate::test_support::PostgresTestSchema::new(TEST).await else {
            return;
        };
        // One connection, so the delta UPDATE below is already prepared on it
        // and the timed-out save's statement is executing, not still parsing.
        let repo = Arc::new(SeaOrmDatabaseArtifactRepository::new(
            schema.connect(1).await,
        ));
        let space = test_space_id("sql-save-in-flight");
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        )
        .with_wait_bounds(SqlWaitBounds {
            artifact_transfer: Duration::from_millis(500),
            ..SqlWaitBounds::default()
        });
        for value in ["seed", "warm"] {
            service
                .execute(
                    &space,
                    "a",
                    insert(value),
                    None,
                    "tinycloud.sql/admin".into(),
                )
                .await
                .unwrap();
        }

        // Readers pass; the save's UPDATE waits on the lock, already sent.
        let locker = schema.connect(1).await;
        let lock = locker.begin().await.unwrap();
        lock.execute_unprepared("LOCK TABLE database_artifact IN EXCLUSIVE MODE")
            .await
            .unwrap();
        let outcome = tokio::time::timeout(
            PATIENCE,
            service.execute(
                &space,
                "a",
                insert("once"),
                None,
                "tinycloud.sql/admin".into(),
            ),
        )
        .await;
        // Release before asserting: a failed assertion must not leave the
        // lock held while the schema is dropped.
        lock.commit().await.unwrap();
        let err = outcome
            .expect("the save's bound must expire")
            .expect_err("a save that expired must fail");
        assert!(matches!(err, SqlError::OutcomeUnknown), "{err:?}");

        // Released, the write that was in flight commits on its own.
        let cold_cache = TempDir::new().unwrap();
        let cold = SqlService::new(
            cold_cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo,
        );
        tokio::time::timeout(PATIENCE, async {
            loop {
                let durable = rows(read(&cold, &space).await.unwrap());
                if durable == 3 {
                    break;
                }
                assert_eq!(durable, 2, "the write commits once or not yet");
                cold.discard_local_state(&(space.to_string(), "a".to_string()))
                    .await
                    .unwrap();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("the in-flight write committed, which is why it is not retryable");
    }

    /// Hydration temp files (`<file>.tmp.<pid>.<n>`) left anywhere under
    /// `dir` would mean a cache write was abandoned midway.
    fn assert_no_temp_files(dir: &Path) {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                assert_no_temp_files(&path);
            } else {
                let name = path.file_name().unwrap().to_string_lossy();
                assert!(!name.contains(".tmp."), "leftover temp file {path:?}");
            }
        }
    }

    /// A hydration whose own load outlives `hydration_max` ends `TimedOut`:
    /// its callers answer busy, its registry entry is retired, and the next
    /// request starts a fresh hydration.
    #[tokio::test]
    async fn tc1274_a_hydration_past_its_own_bound_is_retired() {
        let (inner, space) = seeded("sql-hydration-max").await;
        let repo = GatedArtifactRepository::new(inner);
        repo.load_open.send_replace(false);
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        )
        .with_wait_bounds(SqlWaitBounds {
            hydration_max: Duration::from_millis(200),
            ..SqlWaitBounds::default()
        });

        let err = tokio::time::timeout(PATIENCE, read(&service, &space))
            .await
            .expect("the hydration's own bound must end the wait")
            .expect_err("a hydration that timed out must fail");
        assert!(
            matches!(err, SqlError::Busy(SqlBusyStage::ArtifactTransfer)),
            "{err:?}"
        );
        assert!(service.hydrations.lock().unwrap().is_empty());

        // The fresh hydration does real disk work (fsync); give it the
        // default bound so only the gated first attempt is bound-limited.
        let service = service.with_wait_bounds(SqlWaitBounds::default());
        repo.load_open.send_replace(true);
        assert_eq!(rows(read(&service, &space).await.unwrap()), 1);
        assert_eq!(repo.loads(), 2, "the next request hydrated afresh");
        assert_no_temp_files(cache.path());
    }

    /// Every caller that joined a hydration sees how it failed.
    #[tokio::test]
    async fn tc1274_every_joiner_sees_a_failed_hydration() {
        let (inner, space) = seeded("sql-joiners-fail").await;
        let repo = GatedArtifactRepository::new(inner);
        repo.load_open.send_replace(false);
        repo.fail_loads.store(true, Ordering::SeqCst);
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        );

        let first = tokio::spawn({
            let (service, space) = (service.clone(), space.clone());
            async move { read(&service, &space).await }
        });
        // The second caller queues behind the first on the operation lock
        // and then joins the same failed hydration, or finds it retired and
        // starts its own; either way it must fail like the first.
        tokio::time::timeout(PATIENCE, async {
            while repo.loads() == 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the hydration must start");
        let joiner = tokio::spawn({
            let (service, space) = (service.clone(), space.clone());
            async move {
                let flight = service
                    .hydrations
                    .lock()
                    .unwrap()
                    .get(&(space.to_string(), "a".to_string()))
                    .cloned()
                    .expect("the hydration is in flight");
                service.join_hydration(flight).await
            }
        });
        repo.load_open.send_replace(true);
        let first = tokio::time::timeout(PATIENCE, first)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(first, Err(SqlError::Unavailable)), "{first:?}");
        let joined = tokio::time::timeout(PATIENCE, joiner)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(joined, Ok(HydrationOutcome::Unavailable)),
            "{joined:?}"
        );
        assert_eq!(repo.loads(), 1, "one hydration served both");
    }

    /// Loads its artifact by panicking once, then normally.
    struct PanickingArtifactRepository {
        inner: Arc<SeaOrmDatabaseArtifactRepository>,
        panicked: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl DatabaseArtifactRepository for PanickingArtifactRepository {
        async fn load_meta(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
            if !self.panicked.swap(true, Ordering::SeqCst) {
                panic!("injected hydration panic");
            }
            self.inner.load_meta(service, space, name).await
        }

        async fn read_chunks(
            &self,
            service: &str,
            space: &str,
            name: &str,
            meta: &ArtifactMeta,
            sink: &mut dyn ArtifactSink,
        ) -> Result<(), DatabaseArtifactError> {
            self.inner
                .read_chunks(service, space, name, meta, sink)
                .await
        }

        async fn save(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            self.inner
                .save(service, space, name, payload, expected)
                .await
        }

        async fn save_delta(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DeltaSave, DatabaseArtifactError> {
            self.inner
                .save_delta(service, space, name, payload, expected)
                .await
        }
    }

    /// TC-1274 M3: a hydration task that panics retires its registry entry,
    /// so the database is not wedged until the node restarts.
    #[tokio::test]
    async fn tc1274_a_panicking_hydration_does_not_wedge_the_database() {
        let (inner, space) = seeded("sql-hydration-panic").await;
        let repo = Arc::new(PanickingArtifactRepository {
            inner,
            panicked: Default::default(),
        });
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(cache.path().to_string_lossy().into_owned(), u64::MAX, repo);

        let err = tokio::time::timeout(PATIENCE, read(&service, &space))
            .await
            .expect("a panicked hydration must not hang its caller")
            .expect_err("a panicked hydration must fail");
        assert!(matches!(err, SqlError::Internal(_)), "{err:?}");
        assert!(service.hydrations.lock().unwrap().is_empty());
        let served = tokio::time::timeout(PATIENCE, read(&service, &space))
            .await
            .expect("the next request must not join the dead hydration")
            .unwrap();
        assert_eq!(rows(served), 1);
    }

    /// A write whose deadline passed while it waited is refused at its point
    /// of no return, and nothing is applied.
    #[tokio::test]
    async fn tc1274_a_write_past_its_deadline_is_refused_before_it_starts() {
        let (repo, space) = seeded("sql-begin-write-cut").await;
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(cache.path().to_string_lossy().into_owned(), u64::MAX, repo);
        read(&service, &space).await.unwrap();

        let context = crate::request_cancel::RequestCancel::new(Duration::ZERO);
        let err = crate::request_cancel::within(
            Some(Arc::clone(&context)),
            service.execute(
                &space,
                "a",
                insert("late"),
                None,
                "tinycloud.sql/admin".into(),
            ),
        )
        .await
        .expect_err("a write past its deadline must not start");
        assert!(matches!(err, SqlError::RequestTimeout), "{err:?}");
        assert!(!context.latch(), "the request was cut, not latched");
        assert_eq!(rows(read(&service, &space).await.unwrap()), 1);
    }

    /// Counts metadata reads and the payload bytes delivered to sinks.
    struct ByteSpyRepository {
        inner: Arc<SeaOrmDatabaseArtifactRepository>,
        metas: AtomicU64,
        chunk_reads: AtomicU64,
        payload_bytes: Arc<AtomicU64>,
    }

    struct CountingSink<'a>(&'a mut dyn ArtifactSink, Arc<AtomicU64>);

    #[async_trait]
    impl ArtifactSink for CountingSink<'_> {
        async fn reset(&mut self) -> Result<(), DatabaseArtifactError> {
            self.0.reset().await
        }
        async fn begin_part(
            &mut self,
            part: crate::database_artifacts::ArtifactPart,
        ) -> Result<(), DatabaseArtifactError> {
            self.0.begin_part(part).await
        }
        async fn write(&mut self, bytes: &[u8]) -> Result<(), DatabaseArtifactError> {
            self.1.fetch_add(bytes.len() as u64, Ordering::SeqCst);
            self.0.write(bytes).await
        }
        async fn finish_part(&mut self) -> Result<(), DatabaseArtifactError> {
            self.0.finish_part().await
        }
    }

    #[async_trait]
    impl DatabaseArtifactRepository for ByteSpyRepository {
        async fn load_meta(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
            self.metas.fetch_add(1, Ordering::SeqCst);
            self.inner.load_meta(service, space, name).await
        }

        async fn read_chunks(
            &self,
            service: &str,
            space: &str,
            name: &str,
            meta: &ArtifactMeta,
            sink: &mut dyn ArtifactSink,
        ) -> Result<(), DatabaseArtifactError> {
            self.chunk_reads.fetch_add(1, Ordering::SeqCst);
            let mut counting = CountingSink(sink, Arc::clone(&self.payload_bytes));
            self.inner
                .read_chunks(service, space, name, meta, &mut counting)
                .await
        }

        async fn save(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            self.inner
                .save(service, space, name, payload, expected)
                .await
        }

        async fn save_delta(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DeltaSave, DatabaseArtifactError> {
            self.inner
                .save_delta(service, space, name, payload, expected)
                .await
        }
    }

    #[tokio::test]
    async fn forbid_growth_checks_and_export_existence_read_no_payload_bytes() {
        let spy = Arc::new(ByteSpyRepository {
            inner: artifact_repository().await,
            metas: AtomicU64::new(0),
            chunk_reads: AtomicU64::new(0),
            payload_bytes: Arc::new(AtomicU64::new(0)),
        });
        let cache = TempDir::new().unwrap();
        let space = test_space_id("sql-zero-payload");
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            spy.clone(),
        );
        let write = |sql: &str| SqlRequest::Execute {
            schema: Some(vec![
                "CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, body TEXT)".into(),
            ]),
            sql: sql.into(),
            params: vec![],
        };
        service
            .execute(
                &space,
                "main",
                write("INSERT INTO notes VALUES (1, 'kept')"),
                None,
                "tinycloud.sql/admin".into(),
            )
            .await
            .unwrap();
        let reset = || {
            spy.metas.store(0, Ordering::SeqCst);
            spy.chunk_reads.store(0, Ordering::SeqCst);
            spy.payload_bytes.store(0, Ordering::SeqCst);
        };

        // Export of a live, present database: existence from metadata alone.
        reset();
        assert!(!service.export(&space, "main").await.unwrap().is_empty());
        assert_eq!(spy.metas.load(Ordering::SeqCst), 1);
        assert_eq!(spy.chunk_reads.load(Ordering::SeqCst), 0);
        assert_eq!(spy.payload_bytes.load(Ordering::SeqCst), 0);

        // Export of a missing database.
        reset();
        assert!(matches!(
            service.export(&space, "absent").await,
            Err(SqlError::DatabaseNotFound)
        ));
        assert_eq!(spy.payload_bytes.load(Ordering::SeqCst), 0);
        assert_eq!(spy.chunk_reads.load(Ordering::SeqCst), 0);

        // A write that would grow a full space: the durable size comes from
        // metadata, not from reading the checkpoint back.
        reset();
        let rejected = service
            .execute_without_growth(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "INSERT INTO notes VALUES (2, ?)".into(),
                    params: vec![SqlValue::Text("x".repeat(256 * 1024))],
                },
                None,
                "tinycloud.sql/admin".into(),
            )
            .await;
        assert!(matches!(rejected, Err(SqlError::StorageWouldGrow)));
        assert_eq!(spy.chunk_reads.load(Ordering::SeqCst), 0);
        assert_eq!(spy.payload_bytes.load(Ordering::SeqCst), 0);

        // A write that fits: it reaches the Forbid size comparison, which is
        // answered from metadata. (Warm the actor first; hydration does read.)
        service
            .execute(
                &space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT COUNT(*) FROM notes".into(),
                    params: vec![],
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".into(),
            )
            .await
            .unwrap();
        reset();
        service
            .execute_without_growth(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: "UPDATE notes SET body = 'kept'".into(),
                    params: vec![],
                },
                None,
                "tinycloud.sql/admin".into(),
            )
            .await
            .unwrap();
        assert!(
            spy.metas.load(Ordering::SeqCst) >= 1,
            "the Forbid path consulted the durable size"
        );
        assert_eq!(spy.chunk_reads.load(Ordering::SeqCst), 0);
        assert_eq!(spy.payload_bytes.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn hydration_rejects_a_corrupt_artifact_and_seeds_nothing() {
        use sea_orm::ConnectionTrait;
        let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
            .await
            .unwrap();
        Migrator::up(&db, None).await.unwrap();
        let repo = Arc::new(SeaOrmDatabaseArtifactRepository::new(db.clone()));
        let space = test_space_id("sql-corrupt-hydration");
        let seed_cache = TempDir::new().unwrap();
        let seed = SqlService::new(
            seed_cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo.clone(),
        );
        seed.execute(
            &space,
            "main",
            SqlRequest::Execute {
                schema: Some(vec!["CREATE TABLE t (id INTEGER)".into()]),
                sql: "INSERT INTO t VALUES (1)".into(),
                params: vec![],
            },
            None,
            "tinycloud.sql/admin".into(),
        )
        .await
        .unwrap();
        // Keep the SQLite header so only the content hash can catch it.
        let stored = repo
            .read_all("sql", &space.to_string(), "main")
            .await
            .unwrap()
            .unwrap();
        let mut flipped = stored.payload.clone();
        *flipped.last_mut().unwrap() ^= 0xff;
        db.execute(sea_orm::Statement::from_sql_and_values(
            sea_orm::DbBackend::Sqlite,
            "UPDATE database_artifact SET payload = ?",
            [flipped.into()],
        ))
        .await
        .unwrap();

        let cold_cache = TempDir::new().unwrap();
        let cold = SqlService::new(
            cold_cache.path().to_string_lossy().into_owned(),
            u64::MAX,
            repo,
        );
        let result = cold
            .execute(
                &space,
                "main",
                SqlRequest::Query {
                    sql: "SELECT COUNT(*) FROM t".into(),
                    params: vec![],
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".into(),
            )
            .await;
        assert!(result.is_err(), "a corrupt artifact must not hydrate");
        let leftovers: Vec<_> = walkdir_files(cold_cache.path());
        assert!(leftovers.is_empty(), "nothing seeded: {leftovers:?}");
    }

    fn walkdir_files(dir: &Path) -> Vec<PathBuf> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(walkdir_files(&path));
            } else {
                found.push(path);
            }
        }
        found
    }

    /// Counts every repository call, by kind.
    struct CallCountingRepository {
        inner: Arc<SeaOrmDatabaseArtifactRepository>,
        calls: Arc<std::sync::Mutex<Vec<&'static str>>>,
    }

    impl CallCountingRepository {
        fn note(&self, call: &'static str) {
            self.calls.lock().unwrap().push(call);
        }
    }

    #[async_trait]
    impl DatabaseArtifactRepository for CallCountingRepository {
        async fn load_meta(
            &self,
            service: &str,
            space: &str,
            name: &str,
        ) -> Result<Option<ArtifactMeta>, DatabaseArtifactError> {
            self.note("load_meta");
            self.inner.load_meta(service, space, name).await
        }

        async fn read_chunks(
            &self,
            service: &str,
            space: &str,
            name: &str,
            meta: &ArtifactMeta,
            sink: &mut dyn ArtifactSink,
        ) -> Result<(), DatabaseArtifactError> {
            self.note("read_chunks");
            self.inner
                .read_chunks(service, space, name, meta, sink)
                .await
        }

        async fn save(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DatabaseArtifact, DatabaseArtifactError> {
            self.note("save");
            self.inner
                .save(service, space, name, payload, expected)
                .await
        }

        async fn save_delta(
            &self,
            service: &str,
            space: &str,
            name: &str,
            payload: Vec<u8>,
            expected: ArtifactExpectation,
        ) -> Result<DeltaSave, DatabaseArtifactError> {
            self.note("save_delta");
            self.inner
                .save_delta(service, space, name, payload, expected)
                .await
        }
    }

    fn atomic_batch(statements: &[&str]) -> SqlRequest {
        SqlRequest::Batch {
            statements: statements
                .iter()
                .map(|sql| SqlStatement {
                    sql: (*sql).into(),
                    params: Vec::new(),
                })
                .collect(),
        }
    }

    async fn rows_of(service: &SqlService, space: &SpaceId, sql: &str) -> Vec<Vec<SqlValue>> {
        let result = service
            .execute(
                space,
                "main",
                SqlRequest::Query {
                    sql: sql.into(),
                    params: Vec::new(),
                    max_rows: None,
                    max_bytes: None,
                },
                None,
                "tinycloud.sql/read".into(),
            )
            .await
            .unwrap();
        match result.response {
            SqlResponse::Query(query) => query.rows,
            other => panic!("expected a query response, got {other:?}"),
        }
    }

    /// TC-1491: a failing batch leaves the local file unchanged, writes
    /// nothing to Postgres, and the local file still equals the durable
    /// artifact after the next successful write.
    #[tokio::test]
    async fn tc1491_failed_batch_matches_what_the_durable_artifact_holds() {
        for memory_threshold in [u64::MAX, 0] {
            let repo = artifact_repository().await;
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("sql-atomic-batch");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                Arc::new(CallCountingRepository {
                    inner: repo.clone(),
                    calls: calls.clone(),
                }),
            );
            let write = |sql: &'static str| {
                service.execute(
                    &space,
                    "main",
                    SqlRequest::Execute {
                        schema: None,
                        sql: sql.into(),
                        params: Vec::new(),
                    },
                    None,
                    "tinycloud.sql/admin".into(),
                )
            };
            write("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)")
                .await
                .unwrap();
            write("INSERT INTO t (v) VALUES ('durable')").await.unwrap();
            let handle = service.handle(&space, "main").await.unwrap();
            let before = handle.checkpoint().await.unwrap();

            // The failing request: no repository call at all, no local change.
            calls.lock().unwrap().clear();
            let failed = service
                .execute(
                    &space,
                    "main",
                    atomic_batch(&[
                        "INSERT INTO t (v) VALUES ('prefix-1')",
                        "UPDATE t SET v = 'prefix-2'",
                        "INSERT INTO t (v) VALUES (NULL)",
                    ]),
                    None,
                    "tinycloud.sql/write".into(),
                )
                .await;
            assert!(matches!(failed, Err(SqlError::Sqlite(_))), "{failed:?}");
            assert!(
                calls.lock().unwrap().is_empty(),
                "a rejected batch costs no repository (Postgres) round trip: {:?}",
                calls.lock().unwrap()
            );
            assert_eq!(handle.checkpoint().await.unwrap(), before);

            // A successful 3-statement batch costs exactly the one persist
            // call a single statement costs.
            calls.lock().unwrap().clear();
            service
                .execute(
                    &space,
                    "main",
                    atomic_batch(&[
                        "INSERT INTO t (v) VALUES ('next-1')",
                        "INSERT INTO t (v) VALUES ('next-2')",
                        "INSERT INTO t (v) VALUES ('next-3')",
                    ]),
                    None,
                    "tinycloud.sql/write".into(),
                )
                .await
                .unwrap();
            let persisted = calls.lock().unwrap().clone();
            assert_eq!(persisted.len(), 1, "{persisted:?}");
            assert!(
                matches!(persisted[0], "save" | "save_delta"),
                "{persisted:?}"
            );

            // What a cold node rebuilds from the repository is the local state.
            let local = rows_of(&service, &space, "SELECT id, v FROM t ORDER BY id").await;
            assert_eq!(local.len(), 4);
            assert!(!format!("{local:?}").contains("prefix"));
            let cold_cache = TempDir::new().unwrap();
            let cold = SqlService::new(
                cold_cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo,
            );
            assert_eq!(
                rows_of(&cold, &space, "SELECT id, v FROM t ORDER BY id").await,
                local
            );
        }
    }

    /// TC-1491: the budget and the disk reservation cost no Postgres round
    /// trip, and a refused write costs none at all.
    #[tokio::test]
    async fn tc1491_reservation_adds_no_repository_round_trips() {
        for memory_threshold in [u64::MAX, 0] {
            let mut sequences = Vec::new();
            for budget in [None, Some(1 << 30)] {
                let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
                let cache = TempDir::new().unwrap();
                let service = SqlService::new(
                    cache.path().to_string_lossy().into_owned(),
                    memory_threshold,
                    Arc::new(CallCountingRepository {
                        inner: artifact_repository().await,
                        calls: calls.clone(),
                    }),
                );
                let space = test_space_id("sql-reservation-trips");
                let write = |sql: &str| {
                    let request = SqlRequest::Execute {
                        schema: None,
                        sql: sql.to_string(),
                        params: Vec::new(),
                    };
                    let ability = "tinycloud.sql/admin".to_string();
                    let space = space.clone();
                    let service = service.clone();
                    async move {
                        match budget {
                            None => {
                                service
                                    .execute(&space, "main", request, None, ability)
                                    .await
                            }
                            Some(left) => {
                                service
                                    .execute_with_budget(
                                        &space, "main", request, None, ability, left,
                                    )
                                    .await
                            }
                        }
                    }
                };
                write("CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)")
                    .await
                    .unwrap();
                write("INSERT INTO t (v) VALUES (zeroblob(1000))")
                    .await
                    .unwrap();
                sequences.push(calls.lock().unwrap().clone());
            }
            assert_eq!(
                sequences[0], sequences[1],
                "a budget changes which repository calls a write makes"
            );
            // One persist per write, after the initial hydration lookup.
            let persists = sequences[0]
                .iter()
                .filter(|call| matches!(**call, "save" | "save_delta"))
                .count();
            assert_eq!(persists, 2, "{:?}", sequences[0]);
        }

        // A write the budget refuses reaches Postgres not at all, and leaves the
        // local database as it was.
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let cache = TempDir::new().unwrap();
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            0,
            Arc::new(CallCountingRepository {
                inner: artifact_repository().await,
                calls: calls.clone(),
            }),
        );
        let space = test_space_id("sql-reservation-refused");
        let request = |sql: &str| SqlRequest::Execute {
            schema: None,
            sql: sql.to_string(),
            params: Vec::new(),
        };
        service
            .execute(
                &space,
                "main",
                request("CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)"),
                None,
                "tinycloud.sql/admin".into(),
            )
            .await
            .unwrap();
        calls.lock().unwrap().clear();
        let refused = service
            .execute_with_budget(
                &space,
                "main",
                request("INSERT INTO t (v) VALUES (zeroblob(500000))"),
                None,
                "tinycloud.sql/write".into(),
                4096,
            )
            .await;
        assert!(
            matches!(refused, Err(SqlError::StorageWouldGrow)),
            "{refused:?}"
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "{:?}",
            calls.lock().unwrap()
        );
        assert!(rows_of(&service, &space, "SELECT id FROM t")
            .await
            .is_empty());
        assert_eq!(service.durability.budget.reserved(), 0);
    }

    /// TC-1491: with the disk headroom check on, a successful write holds
    /// nothing once its save is done, except the growth the next checkpoint
    /// will cause. A save of a small WAL ships the WAL and does not
    /// checkpoint, so that growth stays held until a checkpoint runs.
    #[tokio::test]
    async fn tc1491_a_saved_write_holds_only_its_pending_checkpoint_growth() {
        let cache = TempDir::new().unwrap();
        let durability = crate::sql::durability::DurabilityPolicy {
            min_free_bytes: 1,
            ..Default::default()
        };
        let service = SqlService::new(
            cache.path().to_string_lossy().into_owned(),
            0,
            artifact_repository().await,
        )
        .with_durability(durability);
        let space = test_space_id("sql-reservation-pending");
        let write = |sql: &str| {
            service.execute_with_budget(
                &space,
                "main",
                SqlRequest::Execute {
                    schema: None,
                    sql: sql.to_string(),
                    params: Vec::new(),
                },
                None,
                "tinycloud.sql/admin".into(),
                1 << 30,
            )
        };
        let budget = &service.durability.budget;

        write("CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)")
            .await
            .unwrap();
        assert_eq!(budget.reserved(), 0);

        // Saved as a WAL delta: no checkpoint, so the growth is still held.
        write("INSERT INTO t (v) VALUES (zeroblob(400000))")
            .await
            .unwrap();
        let held = budget.reserved();
        assert!(held >= 390_000, "held {held}");
        write("INSERT INTO t (v) VALUES (zeroblob(10))")
            .await
            .unwrap();
        assert!(budget.reserved() >= 390_000);

        // A checkpoint puts it on the disk; a write that adds no page then
        // leaves nothing held after its save.
        let handle = service.handle(&space, "main").await.unwrap();
        handle.checkpoint().await.unwrap();
        assert_eq!(budget.reserved(), 0);
        write("INSERT INTO t (v) VALUES (zeroblob(10))")
            .await
            .unwrap();
        assert_eq!(budget.reserved(), 0);
    }

    /// TC-1491 + TC-1585: a `WITH … INSERT` is a write, so in a batch it is
    /// one of the statements that must be kept or undone with the rest. A
    /// later failure leaves nothing of it locally, writes nothing to Postgres,
    /// and a cold node rebuilt from the durable artifact agrees.
    #[tokio::test]
    async fn tc1491_nested_write_cte_in_a_failed_batch_leaves_nothing() {
        for memory_threshold in [u64::MAX, 0] {
            let repo = artifact_repository().await;
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("sql-atomic-cte");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                Arc::new(CallCountingRepository {
                    inner: repo.clone(),
                    calls: calls.clone(),
                }),
            );
            let run = |request: SqlRequest| {
                service.execute(&space, "main", request, None, "tinycloud.sql/admin".into())
            };
            let batch = |statements: &[&str]| SqlRequest::Batch {
                statements: statements
                    .iter()
                    .map(|sql| SqlStatement {
                        sql: (*sql).into(),
                        params: Vec::new(),
                    })
                    .collect(),
            };
            run(SqlRequest::Execute {
                schema: None,
                sql: "CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT NOT NULL)".into(),
                params: Vec::new(),
            })
            .await
            .unwrap();
            let handle = service.handle(&space, "main").await.unwrap();
            let before = handle.checkpoint().await.unwrap();

            calls.lock().unwrap().clear();
            let failed = run(batch(&[
                "WITH c AS (SELECT 'cte-insert' AS v) INSERT INTO t (v) SELECT v FROM c",
                "INSERT INTO t (v) VALUES (NULL)",
            ]))
            .await;
            assert!(matches!(failed, Err(SqlError::Sqlite(_))), "{failed:?}");
            assert!(
                calls.lock().unwrap().is_empty(),
                "a rejected batch costs no repository (Postgres) round trip: {:?}",
                calls.lock().unwrap()
            );
            assert_eq!(handle.checkpoint().await.unwrap(), before);
            assert!(rows_of(&service, &space, "SELECT v FROM t")
                .await
                .is_empty());

            // The same CTE write kept when the batch succeeds, and durable.
            run(batch(&[
                "WITH c AS (SELECT 'cte-insert' AS v) INSERT INTO t (v) SELECT v FROM c",
                "INSERT INTO t (v) VALUES ('plain')",
            ]))
            .await
            .unwrap();
            let local = rows_of(&service, &space, "SELECT id, v FROM t ORDER BY id").await;
            assert_eq!(local.len(), 2);
            let cold_cache = TempDir::new().unwrap();
            let cold = SqlService::new(
                cold_cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                repo,
            );
            assert_eq!(
                rows_of(&cold, &space, "SELECT id, v FROM t ORDER BY id").await,
                local
            );
        }
    }

    /// TC-1491: a single write is all-or-nothing whatever its conflict clause
    /// says. A statement that stops with `OR FAIL` or `ON CONFLICT FAIL`
    /// leaves the rows it changed first when it runs on its own; the request
    /// is one transaction, so it leaves none of them: the local file is
    /// unchanged and no repository (Postgres) call is made.
    #[tokio::test]
    async fn tc1491_a_single_write_with_fail_conflict_resolution_leaves_nothing() {
        for memory_threshold in [u64::MAX, 0] {
            let repo = artifact_repository().await;
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("sql-atomic-or-fail");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                Arc::new(CallCountingRepository {
                    inner: repo,
                    calls: calls.clone(),
                }),
            );
            let run = |sql: &str, ability: &str| {
                service.execute(
                    &space,
                    "main",
                    SqlRequest::Execute {
                        schema: None,
                        sql: sql.into(),
                        params: Vec::new(),
                    },
                    None,
                    ability.into(),
                )
            };
            run(
                "CREATE TABLE u (id INTEGER PRIMARY KEY, v TEXT UNIQUE)",
                "tinycloud.sql/admin",
            )
            .await
            .unwrap();
            run(
                "INSERT INTO u VALUES (10,'x'),(11,'y'),(12,'z')",
                "tinycloud.sql/write",
            )
            .await
            .unwrap();
            let handle = service.handle(&space, "main").await.unwrap();
            let before = handle.checkpoint().await.unwrap();

            for sql in ["INSERT OR FAIL INTO u VALUES (1,'a'),(2,'b'),(1,'dup')"] {
                calls.lock().unwrap().clear();
                let failed = run(sql, "tinycloud.sql/write").await;
                assert!(
                    matches!(failed, Err(SqlError::Sqlite(_))),
                    "{sql}: {failed:?}"
                );
                assert!(
                    calls.lock().unwrap().is_empty(),
                    "{sql}: a rejected write costs no repository call"
                );
                assert_eq!(
                    rows_of(&service, &space, "SELECT count(*) FROM u").await,
                    vec![vec![SqlValue::Integer(3)]],
                    "{sql}"
                );
                assert_eq!(
                    rows_of(&service, &space, "SELECT group_concat(v) FROM u").await,
                    vec![vec![SqlValue::Text("x,y,z".into())]],
                    "{sql}"
                );
                assert!(
                    handle.checkpoint().await.unwrap() == before,
                    "{sql}: the checkpoint must not change"
                );
            }

            // The same write as a `query` request, which the classifier
            // treats as a write too.
            let failed = service
                .execute(
                    &space,
                    "main",
                    SqlRequest::Query {
                        sql: "INSERT OR FAIL INTO u VALUES (1,'a'),(2,'b'),(1,'dup')".into(),
                        params: Vec::new(),
                        max_rows: None,
                        max_bytes: None,
                    },
                    None,
                    "tinycloud.sql/write".into(),
                )
                .await;
            assert!(failed.is_err(), "{failed:?}");
            assert!(handle.checkpoint().await.unwrap() == before);
        }
    }

    /// TC-1491: a deferred foreign key is checked when the request's
    /// transaction commits. A violation there rolls the request back: nothing
    /// is kept, the error is reported, and no repository call is made.
    #[tokio::test]
    async fn tc1491_a_deferred_constraint_failing_at_commit_leaves_nothing() {
        for memory_threshold in [u64::MAX, 0] {
            let repo = artifact_repository().await;
            let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
            let cache = TempDir::new().unwrap();
            let space = test_space_id("sql-atomic-deferred-fk");
            let service = SqlService::new(
                cache.path().to_string_lossy().into_owned(),
                memory_threshold,
                Arc::new(CallCountingRepository {
                    inner: repo,
                    calls: calls.clone(),
                }),
            );
            let run = |request: SqlRequest| {
                service.execute(&space, "main", request, None, "tinycloud.sql/admin".into())
            };
            let execute = |sql: &str| SqlRequest::Execute {
                schema: None,
                sql: sql.into(),
                params: Vec::new(),
            };
            for ddl in [
                "CREATE TABLE parents (id INTEGER PRIMARY KEY)",
                "CREATE TABLE children (parent_id INTEGER REFERENCES parents(id) DEFERRABLE INITIALLY DEFERRED)",
                "INSERT INTO parents VALUES (1)",
                "INSERT INTO children VALUES (1)",
            ] {
                run(execute(ddl)).await.unwrap();
            }
            let handle = service.handle(&space, "main").await.unwrap();
            let before = handle.checkpoint().await.unwrap();

            for failing in [
                execute("DELETE FROM parents"),
                atomic_batch(&[
                    "INSERT INTO parents VALUES (2)",
                    "DELETE FROM parents WHERE id = 1",
                ]),
            ] {
                calls.lock().unwrap().clear();
                let failed = run(failing).await;
                assert!(matches!(failed, Err(SqlError::Sqlite(_))), "{failed:?}");
                assert!(
                    calls.lock().unwrap().is_empty(),
                    "a request rejected at commit costs no repository call: {:?}",
                    calls.lock().unwrap()
                );
                assert_eq!(
                    rows_of(&service, &space, "SELECT id FROM parents ORDER BY id").await,
                    vec![vec![SqlValue::Integer(1)]]
                );
                assert!(handle.checkpoint().await.unwrap() == before);
            }

            // The connection is not left inside a transaction: the next
            // request commits and is persisted.
            calls.lock().unwrap().clear();
            run(execute("DELETE FROM children")).await.unwrap();
            assert_eq!(calls.lock().unwrap().len(), 1);
            assert!(rows_of(&service, &space, "SELECT * FROM children")
                .await
                .is_empty());
        }
    }
}

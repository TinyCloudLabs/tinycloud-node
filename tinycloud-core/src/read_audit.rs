//! Durable audit journal for successful authenticated reads.
//!
//! Read requests must not enter the mutation transaction merely to record that
//! they happened. They authorize and read on ordinary database connections,
//! then wait for this pipeline to commit their immutable invocation record
//! before the response is acknowledged. Concurrent records are drained into
//! one transaction. Mutations and audit batches share the same writer lock.

use crate::{
    db_pool::{is_transient_error, transient_error_class, RecoveringConnection},
    encryption::{maybe_encrypt, ColumnEncryption},
    events::Invocation,
    hash::Hash,
    models::{actor, invocation},
    relationships::{invoked_abilities, parent_delegations},
    request_telemetry::{self, Metrics, RequestContext, Snapshot},
    types::{Ability, Resource},
};
use sea_orm::{
    sea_query::{Alias, CommonTableExpression, OnConflict, WithClause},
    ActiveValue::Set,
    ConnectionTrait, DbBackend, DbErr, EntityTrait, Insert, QueryTrait, Statement,
    TransactionTrait,
};
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use time::OffsetDateTime;
use tokio::sync::{mpsc, oneshot, Mutex};

const CHANNEL_CAPACITY: usize = 1024;
const MAX_BATCH_SIZE: usize = 64;

#[derive(Debug)]
struct ReadAuditRecord {
    id: Hash,
    invoker: String,
    issued_at: OffsetDateTime,
    serialization: Vec<u8>,
    abilities: Vec<(Resource, Ability)>,
    parents: Vec<Hash>,
}

impl ReadAuditRecord {
    fn from_invocation(invocation: &Invocation, encryption: Option<&ColumnEncryption>) -> Self {
        Self {
            id: invocation.content_hash(),
            invoker: invocation.0.invoker.clone(),
            issued_at: OffsetDateTime::now_utc(),
            serialization: maybe_encrypt(encryption, invocation.serialized_bytes()),
            abilities: invocation
                .0
                .capabilities
                .iter()
                .map(|capability| (capability.resource.clone(), capability.ability.clone()))
                .collect(),
            parents: invocation
                .0
                .parents
                .iter()
                .copied()
                .map(Hash::from)
                .collect(),
        }
    }
}

/// Why a read's audit record was not confirmed (TC-1317). The read's data is
/// never returned without a confirmed record.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReadAuditError {
    /// The record was not confirmed within the read-audit wait bound.
    #[error("read_audit_busy: the read audit is backlogged; retry the request")]
    Busy,
    /// The record's batch failed with a transient database error; nothing
    /// of the read was returned, so a fresh request is safe.
    #[error(
        "unavailable_retryable: read audit storage temporarily unavailable; retry the request"
    )]
    Unavailable,
    /// The record's batch failed otherwise.
    #[error("read audit failed: {0}")]
    Failed(String),
    /// The pipeline is gone.
    #[error("read audit pipeline stopped")]
    Stopped,
}

struct Command {
    record: ReadAuditRecord,
    committed: oneshot::Sender<Result<(), ReadAuditError>>,
    context: Option<Arc<RequestContext>>,
    enqueued: Instant,
}

#[derive(Debug)]
struct PipelineStats {
    records: AtomicU64,
    batches: AtomicU64,
    failed_batches: AtomicU64,
    abandoned: AtomicU64,
    busy: AtomicU64,
    /// Batches in flight longer than [`SLOW_BATCH`], and the longest. On
    /// SQLite this includes the wait for the writer lock, not only the commit.
    slow_batches: AtomicU64,
    max_commit_ms: AtomicU64,
    /// When the batch now being committed started, in ms since `epoch` plus
    /// one; 0 when none is in flight.
    in_flight_since: AtomicU64,
    /// The longest queue wait of the last formed batch's records.
    last_queue_wait_ms: AtomicU64,
    /// The class of the latest failed batch (a fixed string).
    last_failure_class: std::sync::Mutex<&'static str>,
    /// Reads whose pipeline was gone when they queued or waited.
    stopped: AtomicU64,
    epoch: Instant,
    /// Test-only fault: this pipeline's next batch commit panics.
    #[cfg(test)]
    panic_next_batch: std::sync::atomic::AtomicBool,
}

impl Default for PipelineStats {
    fn default() -> Self {
        Self {
            records: AtomicU64::new(0),
            batches: AtomicU64::new(0),
            failed_batches: AtomicU64::new(0),
            abandoned: AtomicU64::new(0),
            busy: AtomicU64::new(0),
            slow_batches: AtomicU64::new(0),
            max_commit_ms: AtomicU64::new(0),
            in_flight_since: AtomicU64::new(0),
            last_queue_wait_ms: AtomicU64::new(0),
            last_failure_class: std::sync::Mutex::new("other"),
            stopped: AtomicU64::new(0),
            epoch: Instant::now(),
            #[cfg(test)]
            panic_next_batch: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl PipelineStats {
    fn in_flight_age(&self) -> Duration {
        match self.in_flight_since.load(Ordering::Acquire) {
            0 => Duration::ZERO,
            since => self
                .epoch
                .elapsed()
                .saturating_sub(Duration::from_millis(since - 1)),
        }
    }

    fn failure_class(&self) -> &'static str {
        *self
            .last_failure_class
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// A point-in-time view of the pipeline: counts and durations only.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadAuditHealth {
    /// Records committed.
    pub records: u64,
    /// Batches committed.
    pub batches: u64,
    /// Batches that failed.
    pub failed_batches: u64,
    /// Records skipped because their waiter was gone when the batch formed.
    pub abandoned: u64,
    /// Waits that gave up at the bound.
    pub busy: u64,
    /// Records waiting in the queue.
    pub queue_depth: u64,
    /// How long the batch being committed has been in flight (0 if none).
    pub in_flight_batch_age_ms: u64,
    /// The longest queue wait among the records of the last formed batch.
    pub last_queue_wait_ms: u64,
    /// Reads answered `Stopped` because the pipeline was gone.
    pub stopped: u64,
    /// The drain is gone: nothing will ever commit a record again.
    pub drain_stopped: bool,
}

/// A batch in flight longer than this (the commit, plus the SQLite writer-lock
/// wait) is reported (TC-1317).
const SLOW_BATCH: Duration = Duration::from_secs(5);
/// A batch in flight longer than this, or a queue that waited longer than
/// [`STALLED_QUEUE_WAIT`] with no batch completing, is a stalled drain.
const STALLED_BATCH: Duration = Duration::from_secs(30);
const STALLED_QUEUE_WAIT: Duration = Duration::from_secs(10);
/// How often the watchdog looks, and how often each warning may repeat.
const WATCHDOG_TICK: Duration = Duration::from_secs(10);
const WARNING_INTERVAL: Duration = Duration::from_secs(60);

/// Default bound on a read's wait for its audit record (TC-1317).
pub const DEFAULT_READ_AUDIT_WAIT: Duration = Duration::from_secs(20);

#[derive(Clone, Debug)]
pub(crate) struct ReadAuditPipeline {
    sender: mpsc::Sender<Command>,
    stats: Arc<PipelineStats>,
    wait_ms: Arc<AtomicU64>,
    #[cfg(test)]
    gate: Arc<Mutex<()>>,
}

impl ReadAuditPipeline {
    pub(crate) fn start(
        conn: impl Into<RecoveringConnection>,
        writer_lock: Option<Arc<Mutex<()>>>,
    ) -> Self {
        let conn = conn.into();
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        let stats = Arc::new(PipelineStats::default());
        #[cfg(test)]
        let gate = Arc::new(Mutex::new(()));
        tokio::spawn(run_pipeline(
            conn,
            writer_lock,
            receiver,
            stats.clone(),
            #[cfg(test)]
            gate.clone(),
        ));
        tokio::spawn(run_watchdog(sender.downgrade(), stats.clone()));
        Self {
            sender,
            stats,
            wait_ms: Arc::new(AtomicU64::new(DEFAULT_READ_AUDIT_WAIT.as_millis() as u64)),
            #[cfg(test)]
            gate,
        }
    }

    /// Bound a read's wait for its audit record.
    pub(crate) fn set_wait(&self, wait: Duration) {
        self.wait_ms
            .store(wait.as_millis() as u64, Ordering::Relaxed);
    }

    /// Hold every batch before it is committed until the guard drops.
    #[cfg(test)]
    pub(crate) async fn hold_drain(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.gate.clone().lock_owned().await
    }

    pub(crate) async fn record(
        &self,
        invocation: &Invocation,
        encryption: Option<&ColumnEncryption>,
    ) -> Result<(), ReadAuditError> {
        self.enqueue(ReadAuditRecord::from_invocation(invocation, encryption))
            .await
    }

    /// Queue `record` and wait for its commit, at most the wait bound.
    ///
    /// Giving up drops the receipt. The drain then skips the record if its
    /// batch has not formed yet, and commits it otherwise; either way nothing
    /// is confirmed to a caller whose record is not committed.
    async fn enqueue(&self, record: ReadAuditRecord) -> Result<(), ReadAuditError> {
        let bound = Duration::from_millis(self.wait_ms.load(Ordering::Relaxed));
        crate::request_cancel::set_stage(crate::request_cancel::Stage::ReadAudit);
        let waited = tokio::time::timeout(bound, async {
            let (committed, receipt) = oneshot::channel();
            self.sender
                .send(Command {
                    record,
                    committed,
                    context: request_telemetry::current(),
                    enqueued: Instant::now(),
                })
                .await
                .map_err(|_| ReadAuditError::Stopped)?;
            receipt.await.map_err(|_| ReadAuditError::Stopped)?
        })
        .await;
        crate::request_cancel::set_stage(crate::request_cancel::Stage::Other);
        match waited {
            Ok(Err(ReadAuditError::Stopped)) => {
                self.stats.stopped.fetch_add(1, Ordering::Relaxed);
                Err(ReadAuditError::Stopped)
            }
            Ok(outcome) => outcome,
            Err(_) => {
                self.stats.busy.fetch_add(1, Ordering::Relaxed);
                Err(ReadAuditError::Busy)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn stats(&self) -> (u64, u64) {
        (
            self.stats.records.load(Ordering::Relaxed),
            self.stats.batches.load(Ordering::Relaxed),
        )
    }

    pub(crate) fn health(&self) -> ReadAuditHealth {
        health(&self.stats, &self.sender)
    }
}

fn health(stats: &PipelineStats, sender: &mpsc::Sender<Command>) -> ReadAuditHealth {
    ReadAuditHealth {
        records: stats.records.load(Ordering::Relaxed),
        batches: stats.batches.load(Ordering::Relaxed),
        failed_batches: stats.failed_batches.load(Ordering::Relaxed),
        abandoned: stats.abandoned.load(Ordering::Relaxed),
        busy: stats.busy.load(Ordering::Relaxed),
        queue_depth: (sender.max_capacity() - sender.capacity()) as u64,
        in_flight_batch_age_ms: stats.in_flight_age().as_millis() as u64,
        last_queue_wait_ms: stats.last_queue_wait_ms.load(Ordering::Relaxed),
        stopped: stats.stopped.load(Ordering::Relaxed),
        drain_stopped: sender.is_closed(),
    }
}

/// What the waiters of a failed batch are told: a transient database error
/// is retryable (nothing of the read was returned), anything else is not.
fn batch_error(error: DbErr) -> ReadAuditError {
    if is_transient_error(&error) {
        ReadAuditError::Unavailable
    } else {
        ReadAuditError::Failed(error.to_string())
    }
}

/// The warnings the watchdog has emitted, and what it last reported.
#[derive(Default)]
struct WatchdogState {
    reported: ReadAuditHealth,
    reported_slow: u64,
    last: [Option<Instant>; 4],
    /// Batches committed, failed or skipped at the last look that moved.
    progress: u64,
    progress_at: Option<Instant>,
}

/// A drain that is stuck cannot report itself, so a separate task watches
/// it (TC-1317). Every warning carries counts and durations only, and each
/// repeats at most once per [`WARNING_INTERVAL`].
async fn run_watchdog(sender: mpsc::WeakSender<Command>, stats: Arc<PipelineStats>) {
    let mut state = WatchdogState::default();
    let mut tick = tokio::time::interval(WATCHDOG_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        // The pipeline is gone once every sender has been dropped.
        let Some(sender) = sender.upgrade() else {
            return;
        };
        let now = health(&stats, &sender);
        drop(sender);
        watch(&stats, &mut state, now, Instant::now());
    }
}

fn watch(stats: &PipelineStats, state: &mut WatchdogState, now: ReadAuditHealth, at: Instant) {
    let mut due = |kind: usize| {
        let due = state.last[kind].is_none_or(|last| at.duration_since(last) >= WARNING_INTERVAL);
        if due {
            state.last[kind] = Some(at);
        }
        due
    };
    let busy = now.busy - state.reported.busy;
    if busy > 0 && due(0) {
        tracing::warn!(
            error_class = "read_audit_busy",
            count = busy,
            queue_depth = now.queue_depth,
            last_queue_wait_ms = now.last_queue_wait_ms,
            "Read audit wait expired"
        );
        state.reported.busy = now.busy;
    }
    let slow = stats.slow_batches.load(Ordering::Relaxed);
    if slow > state.reported_slow && due(1) {
        tracing::warn!(
            error_class = "read_audit_batch_slow",
            count = slow - state.reported_slow,
            max_commit_ms = stats.max_commit_ms.swap(0, Ordering::Relaxed),
            "Read audit batch slow"
        );
        state.reported_slow = slow;
    }
    let failed = now.failed_batches - state.reported.failed_batches;
    if failed > 0 && due(2) {
        tracing::warn!(
            error_class = stats.failure_class(),
            count = failed,
            "Read audit batch failed"
        );
        state.reported.failed_batches = now.failed_batches;
    }
    // A queue that has not moved since the last look: nothing committed,
    // failed or skipped while records waited.
    let progress = now.batches + now.failed_batches + now.abandoned;
    if progress != state.progress || now.queue_depth == 0 || state.progress_at.is_none() {
        state.progress = progress;
        state.progress_at = Some(at);
    }
    let idle_for = state
        .progress_at
        .map_or(Duration::ZERO, |since| at.duration_since(since));
    let stuck_batch = Duration::from_millis(now.in_flight_batch_age_ms) >= STALLED_BATCH;
    let stuck_queue = now.queue_depth > 0 && idle_for >= STALLED_QUEUE_WAIT;
    // A dead drain: reads fail as `Stopped` and nothing will ever commit.
    let dead = now.drain_stopped || now.stopped > state.reported.stopped;
    if (stuck_batch || stuck_queue || dead) && due(3) {
        tracing::warn!(
            error_class = "read_audit_drain_stalled",
            in_flight_batch_age_ms = now.in_flight_batch_age_ms,
            queue_depth = now.queue_depth,
            queue_idle_ms = idle_for.as_millis() as u64,
            abandoned = now.abandoned,
            drain_stopped = now.drain_stopped,
            stopped = now.stopped,
            "Read audit drain stalled"
        );
        state.reported.stopped = now.stopped;
    }
}

async fn run_pipeline(
    conn: RecoveringConnection,
    writer_lock: Option<Arc<Mutex<()>>>,
    mut receiver: mpsc::Receiver<Command>,
    stats: Arc<PipelineStats>,
    #[cfg(test)] gate: Arc<Mutex<()>>,
) {
    while let Some(first) = receiver.recv().await {
        let mut batch = vec![first];
        tokio::task::yield_now().await;
        while batch.len() < MAX_BATCH_SIZE {
            match receiver.try_recv() {
                Ok(command) => batch.push(command),
                Err(_) => break,
            }
        }
        let formed = Instant::now();
        let queue_wait = batch
            .iter()
            .map(|command| formed.duration_since(command.enqueued))
            .max()
            .unwrap_or_default();
        stats
            .last_queue_wait_ms
            .store(queue_wait.as_millis() as u64, Ordering::Relaxed);
        // A waiter that is already gone gave up or was cut: its read was not
        // and can never be confirmed, since its receipt is closed for good.
        // Committing its record would only spend drain time on a read nobody
        // received. A waiter that leaves after this point is still committed.
        let before = batch.len();
        batch.retain(|command| !command.committed.is_closed());
        stats
            .abandoned
            .fetch_add((before - batch.len()) as u64, Ordering::Relaxed);
        if batch.is_empty() {
            continue;
        }

        // In flight from here, including the SQLite writer-lock wait, so a
        // batch stuck on that lock shows as a stalled drain.
        let started = stats.epoch.elapsed();
        stats
            .in_flight_since
            .store(started.as_millis() as u64 + 1, Ordering::Release);
        #[cfg(test)]
        drop(gate.lock().await);
        let _writer = match &writer_lock {
            Some(lock) => Some(lock.lock().await),
            None => None,
        };
        commit_batch(&conn, batch, &stats).await;
        stats.in_flight_since.store(0, Ordering::Release);
        let took = stats.epoch.elapsed().saturating_sub(started);
        if took >= SLOW_BATCH {
            stats.slow_batches.fetch_add(1, Ordering::Relaxed);
            stats
                .max_commit_ms
                .fetch_max(took.as_millis() as u64, Ordering::Relaxed);
        }
    }
}

/// Charge each waiting request the full physical batch, not a share of a
/// process-wide delta. These totals are non-additive across requests.
/// Queue/writer-lock waits and detached driver rollback cleanup are excluded.
async fn commit_batch(
    conn: &RecoveringConnection,
    batch: Vec<Command>,
    stats: &PipelineStats,
) -> Snapshot {
    let metrics = Arc::new(Metrics::default());
    let persisted = std::panic::AssertUnwindSafe(sqlx_core::request_telemetry::scope(
        metrics.clone(),
        async {
            #[cfg(test)]
            if stats.panic_next_batch.swap(false, Ordering::SeqCst) {
                panic!("injected read-audit batch panic");
            }
            persist_batch(conn, &batch).await
        },
    ));
    // A panic fails this batch's waiters; the drain goes on (TC-1317).
    let result = match futures::FutureExt::catch_unwind(persisted).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            let class = transient_error_class(&error).unwrap_or("other");
            *stats
                .last_failure_class
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = class;
            Err(batch_error(error))
        }
        Err(_) => {
            *stats
                .last_failure_class
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = "panic";
            Err(ReadAuditError::Failed("read audit batch panicked".into()))
        }
    };
    let snapshot = metrics.snapshot();
    // At most 64 commands: scanning prior entries avoids a recipient allocation
    // and deduplicates by context identity, never by account or request UUID.
    for (index, command) in batch.iter().enumerate() {
        if let Some(context) = &command.context {
            if !batch[..index].iter().any(|previous| {
                previous
                    .context
                    .as_ref()
                    .is_some_and(|previous| Arc::ptr_eq(previous, context))
            }) {
                context.metrics().accumulate(snapshot);
            }
        }
    }
    if result.is_ok() {
        stats
            .records
            .fetch_add(batch.len() as u64, Ordering::Relaxed);
        stats.batches.fetch_add(1, Ordering::Relaxed);
    } else {
        stats.failed_batches.fetch_add(1, Ordering::Relaxed);
    }
    for command in batch {
        let _ = command.committed.send(result.clone());
    }
    snapshot
}

async fn persist_batch(conn: &RecoveringConnection, batch: &[Command]) -> Result<(), DbErr> {
    let inserts = audit_inserts(batch);
    if conn.get_database_backend() == DbBackend::Postgres {
        if let Some(statement) = inserts.as_ref().and_then(postgres_single_statement) {
            // Every INSERT in the statement is `ON CONFLICT DO NOTHING` on
            // keys fixed by the batch, and the readers wait only for "the
            // rows exist", so running it again after a lost connection is a
            // no-op if the first run committed (TC-951).
            return conn.execute_idempotent(statement).await.map(|_| ());
        }
    }
    let tx = conn.begin().await?;
    if let Some(inserts) = inserts {
        persist_inserts(&tx, inserts).await?;
    }
    tx.commit().await
}

/// PostgreSQL commits the batch's INSERTs as one statement instead of
/// `BEGIN`, one statement per table and `COMMIT` (6 sequential round-trips
/// for a typical read). The INSERTs are exactly those `persist_inserts` runs,
/// with the same rows and `ON CONFLICT DO NOTHING` targets, as data-modifying
/// CTEs of the invocation INSERT. One statement is atomic on its own, and
/// PostgreSQL checks the foreign keys between these tables (invocation to
/// actor, invoked ability to invocation, parent edge to delegation) at the end
/// of the statement, so rows inserted by a sibling CTE satisfy them.
/// PostgreSQL does not define the order in which the CTEs run, so their rows
/// may be locked in a different order than the old transaction's; only two
/// writers of the same invocation id could notice, and the invocation replay
/// guard admits an invocation once.
///
/// `None` when the combined statement would bind more than the 65,535
/// parameters PostgreSQL's protocol allows (each per-table statement had that
/// limit on its own); `persist_batch` then takes the transactional path.
fn postgres_single_statement(inserts: &AuditInserts) -> Option<Statement> {
    let mut ctes = WithClause::new();
    let mut any_cte = false;
    for (name, insert) in [
        (
            "read_audit_actor",
            inserts.actors.as_ref().map(|i| i.as_query().clone()),
        ),
        (
            "read_audit_invoked_abilities",
            inserts.abilities.as_ref().map(|i| i.as_query().clone()),
        ),
        (
            "read_audit_parent_delegation",
            inserts.parents.as_ref().map(|i| i.as_query().clone()),
        ),
    ] {
        if let Some(insert) = insert {
            ctes.cte(
                CommonTableExpression::new()
                    .table_name(Alias::new(name))
                    .query(insert)
                    .to_owned(),
            );
            any_cte = true;
        }
    }
    let mut statement = inserts.invocations.as_query().clone();
    if any_cte {
        statement.with_cte(ctes);
    }
    let statement = DbBackend::Postgres.build(&statement);
    let parameters = statement.values.as_ref().map_or(0, |values| values.0.len());
    (parameters <= usize::from(u16::MAX)).then_some(statement)
}

/// The INSERTs that persist one drained batch: at most one `insert_many` per
/// table, instead of the previous ~4 statements per record.
///
/// Every VALUES list is deduplicated by its `ON CONFLICT` target before it is
/// sent. This is mandatory once rows are batched: some backends (notably
/// Postgres) reject a single `INSERT ... ON CONFLICT` whose VALUES contain the
/// same conflict key twice, and a saturated batch can legitimately carry a
/// repeated invoker (many reads by one principal) or even a repeated
/// invocation (identical concurrent reads share a content hash). The old
/// per-record path never hit this because each row was its own statement.
///
/// Everything that the per-record path guaranteed is preserved: the same
/// `ON CONFLICT DO NOTHING` targets, the already-encrypted `serialization`
/// bytes carried verbatim from each record, and — because inserts stay
/// conflict-idempotent — identical final table contents and no-op re-persists.
struct AuditInserts {
    actors: Option<Insert<actor::ActiveModel>>,
    invocations: Insert<invocation::ActiveModel>,
    abilities: Option<Insert<invoked_abilities::ActiveModel>>,
    parents: Option<Insert<parent_delegations::ActiveModel>>,
}

/// `None` for a batch with no records.
fn audit_inserts(batch: &[Command]) -> Option<AuditInserts> {
    // Collapse repeated invocations (identical concurrent reads hash to the
    // same id) to their first occurrence so every downstream VALUES list is
    // duplicate-free at the invocation level.
    let mut seen_invocations = HashSet::new();
    let records: Vec<&ReadAuditRecord> = batch
        .iter()
        .map(|command| &command.record)
        .filter(|record| seen_invocations.insert(record.id))
        .collect();

    if records.is_empty() {
        return None;
    }

    // 1. Actors — one row per distinct invoker.
    let mut seen_actors = HashSet::new();
    let actors: Vec<actor::ActiveModel> = records
        .iter()
        .filter(|record| seen_actors.insert(record.invoker.as_str()))
        .map(|record| actor::ActiveModel {
            id: Set(record.invoker.clone()),
        })
        .collect();
    let actors = (!actors.is_empty()).then(|| {
        actor::Entity::insert_many(actors).on_conflict(
            OnConflict::column(actor::Column::Id)
                .do_nothing()
                .to_owned(),
        )
    });

    // 2. Invocations — one row per distinct invocation (records already deduped).
    let invocations: Vec<invocation::ActiveModel> = records
        .iter()
        .map(|record| invocation::ActiveModel {
            id: Set(record.id),
            invoker: Set(record.invoker.clone()),
            issued_at: Set(record.issued_at),
            facts: Set(None),
            serialization: Set(record.serialization.clone()),
        })
        .collect();
    let invocations = invocation::Entity::insert_many(invocations).on_conflict(
        OnConflict::column(invocation::Column::Id)
            .do_nothing()
            .to_owned(),
    );

    // 3. Invoked abilities — every (invocation, resource, ability) across the
    //    batch, deduplicated by the full primary key.
    let mut seen_abilities = HashSet::new();
    let abilities: Vec<invoked_abilities::ActiveModel> = records
        .iter()
        .flat_map(|record| {
            let invocation = record.id;
            record
                .abilities
                .iter()
                .map(move |(resource, ability)| (invocation, resource.clone(), ability.clone()))
        })
        .filter(|(invocation, resource, ability)| {
            seen_abilities.insert((*invocation, resource.clone(), ability.clone()))
        })
        .map(
            |(invocation, resource, ability)| invoked_abilities::ActiveModel {
                invocation: Set(invocation),
                resource: Set(resource),
                ability: Set(ability),
            },
        )
        .collect();
    let abilities = (!abilities.is_empty()).then(|| {
        invoked_abilities::Entity::insert_many(abilities).on_conflict(
            OnConflict::columns([
                invoked_abilities::Column::Invocation,
                invoked_abilities::Column::Resource,
                invoked_abilities::Column::Ability,
            ])
            .do_nothing()
            .to_owned(),
        )
    });

    // 4. Parent delegations — every (parent, child) across the batch,
    //    deduplicated by the full primary key.
    let mut seen_parents = HashSet::new();
    let parents: Vec<parent_delegations::ActiveModel> = records
        .iter()
        .flat_map(|record| {
            let child = record.id;
            record.parents.iter().map(move |parent| (*parent, child))
        })
        .filter(|(parent, child)| seen_parents.insert((*parent, *child)))
        .map(|(parent, child)| parent_delegations::ActiveModel {
            parent: Set(parent),
            child: Set(child),
        })
        .collect();
    let parents = (!parents.is_empty()).then(|| {
        parent_delegations::Entity::insert_many(parents).on_conflict(
            OnConflict::columns([
                parent_delegations::Column::Parent,
                parent_delegations::Column::Child,
            ])
            .do_nothing()
            .to_owned(),
        )
    });

    Some(AuditInserts {
        actors,
        invocations,
        abilities,
        parents,
    })
}

/// Persist a drained batch inside the caller's transaction with one statement
/// per table (SQLite, MySQL, and PostgreSQL past the parameter limit).
async fn persist_inserts<C: ConnectionTrait>(db: &C, inserts: AuditInserts) -> Result<(), DbErr> {
    let AuditInserts {
        actors,
        invocations,
        abilities,
        parents,
    } = inserts;
    if let Some(actors) = actors {
        ignore_record_not_inserted(actors.exec(db).await)?;
    }
    ignore_record_not_inserted(invocations.exec(db).await)?;
    if let Some(abilities) = abilities {
        ignore_record_not_inserted(abilities.exec(db).await)?;
    }
    if let Some(parents) = parents {
        ignore_record_not_inserted(parents.exec(db).await)?;
    }
    Ok(())
}

fn ignore_record_not_inserted<T>(result: Result<T, DbErr>) -> Result<(), DbErr> {
    match result {
        Ok(_) | Err(DbErr::RecordNotInserted) => Ok(()),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migrations::Migrator;
    use sea_orm::{ConnectOptions, Database, DatabaseConnection, PaginatorTrait};
    use sea_orm_migration::MigratorTrait;

    fn record(index: usize) -> ReadAuditRecord {
        ReadAuditRecord {
            id: crate::hash::hash(format!("read-audit-{index}").as_bytes()),
            invoker: "did:key:read-audit-test".to_string(),
            issued_at: OffsetDateTime::now_utc(),
            serialization: format!("serialized-{index}").into_bytes(),
            abilities: Vec::new(),
            parents: Vec::new(),
        }
    }

    async fn database(url: String, max_connections: u32) -> DatabaseConnection {
        let mut options = ConnectOptions::new(url);
        options.max_connections(max_connections);
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        conn
    }

    fn telemetry_context() -> Arc<crate::request_telemetry::RequestContext> {
        crate::request_telemetry::RequestContext::new(
            "12345678-1234-4234-8234-123456789abc".parse().unwrap(),
            Arc::new(crate::telemetry::Pseudonymizer::new(
                &crate::keys::StaticSecret::new(vec![17; 32]).unwrap(),
            )),
        )
    }

    async fn assert_batch_telemetry(fail: bool) {
        let conn = database("sqlite::memory:".to_string(), 1).await;
        if fail {
            conn.execute(Statement::from_string(
                DbBackend::Sqlite,
                "DROP TABLE invocation".to_string(),
            ))
            .await
            .unwrap();
        }
        let first = telemetry_context();
        let second = telemetry_context();
        let unrelated = telemetry_context();
        let mut batch = Vec::new();
        let mut receipts = Vec::new();
        for (index, context) in [first.clone(), second.clone(), first.clone()]
            .into_iter()
            .enumerate()
        {
            let (committed, receipt) = oneshot::channel();
            batch.push(Command {
                record: record(index),
                committed,
                context: Some(context),
                enqueued: Instant::now(),
            });
            receipts.push(receipt);
        }
        let stats = PipelineStats::default();
        // An unrelated ambient request must neither receive SQL nor become a
        // recipient of this explicitly captured batch.
        let physical = crate::request_telemetry::scope(
            unrelated.clone(),
            commit_batch(&RecoveringConnection::new(conn), batch, &stats),
        )
        .await;
        // BEGIN, actor INSERT, invocation INSERT, then COMMIT on success.
        // Failure's detached rollback is deliberately not a request query.
        assert_eq!(physical.query_count, if fail { 3 } else { 4 });
        assert!(physical.query_time_ns > 0);
        assert_eq!(first.snapshot(), physical);
        assert_eq!(second.snapshot(), physical);
        assert_eq!(unrelated.snapshot(), Default::default());
        for mut receipt in receipts {
            // Publication is complete before even a ready receipt is consumed.
            assert_eq!(receipt.try_recv().unwrap().is_err(), fail);
            assert_eq!(first.snapshot(), physical);
            assert_eq!(second.snapshot(), physical);
        }
        assert_eq!(
            stats.records.load(Ordering::Relaxed),
            if fail { 0 } else { 3 }
        );
    }

    #[tokio::test]
    async fn shared_batch_charges_physical_work_once_per_request() {
        assert_batch_telemetry(false).await;
    }

    #[tokio::test]
    async fn failed_batch_charges_physical_work_before_failure_receipt() {
        assert_batch_telemetry(true).await;
    }

    #[tokio::test]
    async fn concurrent_records_group_commit_and_are_durable() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite:{}?mode=rwc",
            directory.path().join("audit.db").display()
        );
        let conn = database(url.clone(), 8).await;
        let pipeline = ReadAuditPipeline::start(conn.clone(), Some(Arc::new(Mutex::new(()))));
        pipeline.set_wait(COMMIT_TEST_WAIT);

        let requests = (0..32)
            .map(|index| {
                let pipeline = pipeline.clone();
                tokio::spawn(async move { pipeline.enqueue(record(index)).await })
            })
            .collect::<Vec<_>>();
        for request in requests {
            request.await.unwrap().unwrap();
        }

        let (records, batches) = pipeline.stats();
        println!("durable read audit: {records} records in {batches} commits");
        assert_eq!(records, 32);
        assert!(
            batches < records,
            "saturated reads should use fewer commits than records"
        );
        assert_eq!(invocation::Entity::find().count(&conn).await.unwrap(), 32);

        drop(pipeline);
        drop(conn);
        let reopened = database(url, 1).await;
        assert_eq!(
            invocation::Entity::find().count(&reopened).await.unwrap(),
            32
        );
    }

    #[tokio::test]
    async fn wal_reader_progresses_while_audit_waits_for_writer() {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite:{}?mode=rwc",
            directory.path().join("concurrent.db").display()
        );
        let mut options = ConnectOptions::new(url);
        options.max_connections(4).map_sqlx_sqlite_opts(|options| {
            options
                .create_if_missing(true)
                .pragma("journal_mode", "WAL")
        });
        let conn = Database::connect(options).await.unwrap();
        Migrator::up(&conn, None).await.unwrap();
        let writer_lock = Arc::new(Mutex::new(()));
        let pipeline = ReadAuditPipeline::start(conn.clone(), Some(writer_lock.clone()));
        pipeline.set_wait(COMMIT_TEST_WAIT);
        let writer = writer_lock.lock().await;

        let audit = tokio::spawn(async move { pipeline.enqueue(record(0)).await });
        tokio::task::yield_now().await;
        assert!(!audit.is_finished());

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            invocation::Entity::find().count(&conn),
        )
        .await
        .expect("WAL read should not wait for the writer lock")
        .unwrap();

        drop(writer);
        audit.await.unwrap().unwrap();
    }

    fn resource(uri: &str) -> Resource {
        uri.parse().expect("valid resource uri")
    }

    fn ability(uri: &str) -> Ability {
        uri.to_string().try_into().expect("valid ability")
    }

    fn rich_record(
        seed: &str,
        invoker: &str,
        abilities: Vec<(Resource, Ability)>,
        parents: Vec<Hash>,
    ) -> ReadAuditRecord {
        ReadAuditRecord {
            id: crate::hash::hash(seed.as_bytes()),
            invoker: invoker.to_string(),
            issued_at: OffsetDateTime::now_utc(),
            serialization: format!("serialized-{seed}").into_bytes(),
            abilities,
            parents,
        }
    }

    fn command(record: ReadAuditRecord) -> Command {
        let (committed, _receipt) = oneshot::channel();
        Command {
            record,
            committed,
            context: None,
            enqueued: Instant::now(),
        }
    }

    /// A `parent_delegation.parent` value must reference a real `delegation`
    /// row (enforced FK), so seed one before persisting audit records that cite
    /// it as a parent. Mirrors the delegation module's own test helper.
    async fn insert_parent_delegation(conn: &DatabaseConnection, id: Hash) {
        use crate::models::delegation;
        ignore_record_not_inserted(
            actor::Entity::insert(actor::ActiveModel {
                id: Set("did:key:parent-authority".to_string()),
            })
            .on_conflict(
                OnConflict::column(actor::Column::Id)
                    .do_nothing()
                    .to_owned(),
            )
            .exec(conn)
            .await,
        )
        .unwrap();
        delegation::Entity::insert(delegation::ActiveModel {
            id: Set(id),
            delegator: Set("did:key:parent-authority".to_string()),
            delegatee: Set("did:key:parent-authority".to_string()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(id.as_ref().to_vec()),
        })
        .exec(conn)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn batched_persist_matches_per_record_contents_and_is_idempotent() {
        let conn = database("sqlite::memory:".to_string(), 1).await;
        assert_batched_persist_contents(&conn, persist_batch_boxed).await;
    }

    /// How a test persists a batch: `persist_batch` (one statement on
    /// PostgreSQL), or the transaction of per-table INSERTs it replaces there.
    type Persist = for<'a> fn(
        &'a DatabaseConnection,
        &'a [Command],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), DbErr>> + Send + 'a>,
    >;

    fn persist_batch_boxed<'a>(
        conn: &'a DatabaseConnection,
        batch: &'a [Command],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DbErr>> + Send + 'a>> {
        Box::pin(
            async move { persist_batch(&RecoveringConnection::new(conn.clone()), batch).await },
        )
    }

    fn persist_in_transaction<'a>(
        conn: &'a DatabaseConnection,
        batch: &'a [Command],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), DbErr>> + Send + 'a>> {
        Box::pin(async move {
            let tx = conn.begin().await?;
            if let Some(inserts) = audit_inserts(batch) {
                persist_inserts(&tx, inserts).await?;
            }
            tx.commit().await
        })
    }

    async fn assert_batched_persist_contents(conn: &DatabaseConnection, persist: Persist) {
        let conn = conn.clone();

        let parent_one = crate::hash::hash(b"parent-one");
        let parent_two = crate::hash::hash(b"parent-two");
        insert_parent_delegation(&conn, parent_one).await;
        insert_parent_delegation(&conn, parent_two).await;

        let res_a = resource("tinycloud:did:key:ne-delegator:files/kv/a");
        let res_b = resource("tinycloud:did:key:ne-delegator:files/kv/b");
        let get = ability("tinycloud.kv/get");
        let put = ability("tinycloud.kv/put");
        let read = ability("tinycloud.capabilities/read");

        // alice1: multiple abilities on one resource, two parents.
        let alice1 = rich_record(
            "alice-1",
            "did:key:alice",
            vec![(res_a.clone(), get.clone()), (res_a.clone(), put.clone())],
            vec![parent_one, parent_two],
        );
        // alice2: DUPLICATE actor (did:key:alice), one ability, shares parent_one.
        let alice2 = rich_record(
            "alice-2",
            "did:key:alice",
            vec![(res_b.clone(), read.clone())],
            vec![parent_one],
        );
        // bob: distinct actor, no abilities, no parents.
        let bob = rich_record("bob-1", "did:key:bob", vec![], vec![]);

        let alice1_id = alice1.id;
        let alice2_id = alice2.id;
        let bob_id = bob.id;

        let batch = vec![command(alice1), command(alice2), command(bob)];
        persist(&conn, &batch).await.unwrap();

        // Actors: the duplicate invoker collapses to one row.
        let actors: HashSet<String> = actor::Entity::find()
            .all(&conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .collect();
        assert!(actors.contains("did:key:alice"));
        assert!(actors.contains("did:key:bob"));

        // Invocations: three rows; invoker + (already-encrypted) serialization
        // are carried verbatim.
        let invocations = invocation::Entity::find().all(&conn).await.unwrap();
        assert_eq!(invocations.len(), 3);
        let by_id: std::collections::HashMap<Hash, invocation::Model> =
            invocations.into_iter().map(|row| (row.id, row)).collect();
        assert_eq!(by_id[&alice1_id].invoker, "did:key:alice");
        assert_eq!(
            by_id[&alice1_id].serialization,
            b"serialized-alice-1".to_vec()
        );
        assert_eq!(by_id[&alice2_id].invoker, "did:key:alice");
        assert_eq!(by_id[&bob_id].invoker, "did:key:bob");

        // Invoked abilities: exact (invocation, resource, ability) set.
        let ability_rows: HashSet<(Hash, String, String)> = invoked_abilities::Entity::find()
            .all(&conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| {
                (
                    row.invocation,
                    row.resource.to_string(),
                    row.ability.to_string(),
                )
            })
            .collect();
        let expected_abilities: HashSet<(Hash, String, String)> = [
            (alice1_id, res_a.to_string(), get.to_string()),
            (alice1_id, res_a.to_string(), put.to_string()),
            (alice2_id, res_b.to_string(), read.to_string()),
        ]
        .into_iter()
        .collect();
        assert_eq!(ability_rows, expected_abilities);

        // Parent delegations: exact (parent, child) set.
        let parent_rows: HashSet<(Hash, Hash)> = parent_delegations::Entity::find()
            .all(&conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.parent, row.child))
            .collect();
        let expected_parents: HashSet<(Hash, Hash)> = [
            (parent_one, alice1_id),
            (parent_two, alice1_id),
            (parent_one, alice2_id),
        ]
        .into_iter()
        .collect();
        assert_eq!(parent_rows, expected_parents);

        // Re-persisting the identical batch is a no-op (ON CONFLICT DO NOTHING).
        persist(&conn, &batch).await.unwrap();
        assert_eq!(invocation::Entity::find().count(&conn).await.unwrap(), 3);
        assert_eq!(
            invoked_abilities::Entity::find()
                .count(&conn)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            parent_delegations::Entity::find()
                .count(&conn)
                .await
                .unwrap(),
            3
        );
    }

    async fn audit_rows(
        conn: &DatabaseConnection,
    ) -> (
        Vec<String>,
        Vec<(Hash, String, Vec<u8>)>,
        Vec<(Hash, String, String)>,
        Vec<(Hash, Hash)>,
    ) {
        let mut actors: Vec<String> = actor::Entity::find()
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id)
            .filter(|id| id != "did:key:parent-authority")
            .collect();
        let mut invocations: Vec<(Hash, String, Vec<u8>)> = invocation::Entity::find()
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.id, row.invoker, row.serialization))
            .collect();
        let mut abilities: Vec<(Hash, String, String)> = invoked_abilities::Entity::find()
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| {
                (
                    row.invocation,
                    row.resource.to_string(),
                    row.ability.to_string(),
                )
            })
            .collect();
        let mut parents: Vec<(Hash, Hash)> = parent_delegations::Entity::find()
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| (row.parent, row.child))
            .collect();
        actors.sort();
        invocations.sort_by(|left, right| left.0.as_ref().cmp(right.0.as_ref()));
        abilities.sort_by(|left, right| {
            (left.0.as_ref(), &left.1, &left.2).cmp(&(right.0.as_ref(), &right.1, &right.2))
        });
        parents.sort_by(|left, right| {
            (left.0.as_ref(), left.1.as_ref()).cmp(&(right.0.as_ref(), right.1.as_ref()))
        });
        (actors, invocations, abilities, parents)
    }

    /// PostgreSQL persists a batch as one statement. The same batch persisted
    /// by the transaction of per-table INSERTs it replaced (in a second,
    /// isolated schema) leaves exactly the same rows, a failing batch leaves
    /// none of its rows on either path, and concurrent reads still group
    /// commit and are durable.
    #[tokio::test]
    async fn postgres_read_audit_batch_is_one_atomic_statement_with_unchanged_rows() {
        use crate::test_support::PostgresTestSchema;
        use std::sync::atomic::AtomicUsize;

        const TEST: &str = "postgres_read_audit_batch_is_one_atomic_statement_with_unchanged_rows";
        let Some(transactional) = PostgresTestSchema::new(TEST).await else {
            return;
        };
        let Some(single) = PostgresTestSchema::new(TEST).await else {
            return;
        };
        // The new actors in this batch exercise invocation -> actor, and its
        // parents invoked_abilities -> invocation and parent -> delegation,
        // all within one statement.
        assert_batched_persist_contents(&transactional.conn, persist_in_transaction).await;
        assert_batched_persist_contents(&single.conn, persist_batch_boxed).await;
        assert_eq!(
            audit_rows(&single.conn).await,
            audit_rows(&transactional.conn).await
        );

        // One statement per batch on PostgreSQL; the transactional path ran
        // one per table (plus BEGIN and COMMIT on the wire).
        let parent = crate::hash::hash(b"parent-one");
        let batch = || {
            vec![
                command(rich_record(
                    "count-1",
                    "did:key:count",
                    vec![(
                        resource("tinycloud:did:key:ne-delegator:files/kv/count"),
                        ability("tinycloud.kv/get"),
                    )],
                    vec![parent],
                )),
                command(rich_record("count-2", "did:key:count", vec![], vec![])),
            ]
        };
        for (conn, persist, expected) in [
            (&single.conn, persist_batch_boxed as Persist, 1),
            (&transactional.conn, persist_in_transaction as Persist, 4),
        ] {
            let statements = Arc::new(AtomicUsize::new(0));
            let counter = statements.clone();
            let mut counted = conn.clone();
            counted.set_metric_callback(move |_| {
                counter.fetch_add(1, Ordering::SeqCst);
            });
            persist(&counted, &batch()).await.unwrap();
            assert_eq!(statements.load(Ordering::SeqCst), expected);
        }
        assert_eq!(
            audit_rows(&single.conn).await,
            audit_rows(&transactional.conn).await
        );

        // A record citing a delegation that does not exist violates the parent
        // edge's foreign key: the whole batch fails, including its new actor
        // and the other record's rows.
        let doomed = vec![
            command(rich_record("doomed-ok", "did:key:doomed", vec![], vec![])),
            command(rich_record(
                "doomed-bad",
                "did:key:doomed",
                vec![],
                vec![crate::hash::hash(b"no-such-delegation")],
            )),
        ];
        for (conn, persist) in [
            (&single.conn, persist_batch_boxed as Persist),
            (&transactional.conn, persist_in_transaction as Persist),
        ] {
            let before = audit_rows(conn).await;
            assert!(persist(conn, &doomed).await.is_err());
            assert_eq!(audit_rows(conn).await, before);
        }

        // The pipeline itself, without a writer lock as on PostgreSQL in
        // production: concurrent reads group commit and are durable.
        let pipeline = ReadAuditPipeline::start(single.conn.clone(), None);
        pipeline.set_wait(COMMIT_TEST_WAIT);
        let before = invocation::Entity::find()
            .count(&single.conn)
            .await
            .unwrap();
        let requests = (0..32)
            .map(|index| {
                let pipeline = pipeline.clone();
                tokio::spawn(async move { pipeline.enqueue(record(index)).await })
            })
            .collect::<Vec<_>>();
        for request in requests {
            request.await.unwrap().unwrap();
        }
        let (records, batches) = pipeline.stats();
        assert_eq!(records, 32);
        assert!(batches < records, "saturated reads share commits");
        assert_eq!(
            invocation::Entity::find()
                .count(&single.conn)
                .await
                .unwrap(),
            before + 32
        );
    }

    #[test]
    fn single_statement_audit_covers_every_table_and_falls_back_past_the_parameter_limit() {
        assert!(audit_inserts(&[]).is_none());
        let single_statement = |batch: &[Command]| {
            postgres_single_statement(&audit_inserts(batch).expect("a non-empty batch"))
        };

        let get = ability("tinycloud.kv/get");
        let batch = vec![command(rich_record(
            "shape",
            "did:key:shape",
            vec![(
                resource("tinycloud:did:key:ne-delegator:files/kv/a"),
                get.clone(),
            )],
            vec![crate::hash::hash(b"parent")],
        ))];
        let sql = single_statement(&batch)
            .expect("an ordinary batch is one statement")
            .sql;
        assert!(sql.starts_with("WITH "), "{sql}");
        for table in [
            r#"INSERT INTO "actor""#,
            r#"INSERT INTO "invoked_abilities""#,
            r#"INSERT INTO "parent_delegation""#,
            r#"INSERT INTO "invocation""#,
        ] {
            assert_eq!(sql.matches(table).count(), 1, "{table}: {sql}");
        }
        assert_eq!(sql.matches("ON CONFLICT").count(), 4, "{sql}");
        assert!(!sql.contains("RETURNING"), "{sql}");

        // 6 parameters for the actor and invocation, 3 per invoked ability:
        // past 65,535 the batch takes the transactional path instead.
        let fits = (65_535 - 6) / 3;
        let abilities = |count: usize| {
            (0..count)
                .map(|index| {
                    (
                        resource(&format!("tinycloud:did:key:ne-delegator:files/kv/{index}")),
                        get.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        let at_limit = vec![command(rich_record(
            "at-limit",
            "did:key:limit",
            abilities(fits),
            vec![],
        ))];
        assert!(single_statement(&at_limit).is_some());
        let past_limit = vec![command(rich_record(
            "past-limit",
            "did:key:limit",
            abilities(fits + 1),
            vec![],
        ))];
        assert!(single_statement(&past_limit).is_none());
    }

    // PostgreSQL regressions for the read-audit pipeline as a whole (TC-951):
    // completeness under saturated, overlapping reads, and atomicity when a
    // batch fails part-way through, on the single statement and the
    // transactional path alike.

    type RowSets = (
        HashSet<String>,
        HashSet<(Hash, String, Vec<u8>)>,
        HashSet<(Hash, String, String)>,
        HashSet<(Hash, Hash)>,
    );

    async fn audit_row_sets(conn: &DatabaseConnection) -> RowSets {
        let (actors, invocations, abilities, parents) = audit_rows(conn).await;
        (
            actors.into_iter().collect(),
            invocations.into_iter().collect(),
            abilities.into_iter().collect(),
            parents.into_iter().collect(),
        )
    }

    /// The rows `reads` must leave, derived from the records alone: every
    /// invoker, one invocation per id, and every capability and parent edge
    /// of every read.
    fn expected_rows(reads: &[ReadAuditRecord]) -> RowSets {
        let mut rows = RowSets::default();
        for read in reads {
            rows.0.insert(read.invoker.clone());
            rows.1
                .insert((read.id, read.invoker.clone(), read.serialization.clone()));
            for (resource, ability) in &read.abilities {
                rows.2
                    .insert((read.id, resource.to_string(), ability.to_string()));
            }
            for parent in &read.parents {
                rows.3.insert((*parent, read.id));
            }
        }
        rows
    }

    fn union(mut left: RowSets, right: RowSets) -> RowSets {
        left.0.extend(right.0);
        left.1.extend(right.1);
        left.2.extend(right.2);
        left.3.extend(right.3);
        left
    }

    fn commands(reads: Vec<ReadAuditRecord>) -> Vec<Command> {
        reads.into_iter().map(command).collect()
    }

    async fn query_i32(conn: &impl ConnectionTrait, sql: &str, values: Vec<sea_orm::Value>) -> i32 {
        conn.query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            sql,
            values,
        ))
        .await
        .unwrap()
        .expect("one row")
        .try_get_by_index(0)
        .unwrap()
    }

    /// Another pool on `fixture`'s schema. It skips the ping before acquire
    /// like the node's PostgreSQL pool, so a connection the server killed is
    /// only noticed when it is returned.
    async fn schema_pool(
        test: &str,
        fixture: &DatabaseConnection,
        max_connections: u32,
    ) -> DatabaseConnection {
        let url = crate::test_support::postgres_test_url(test).expect("the fixture exists");
        let schema: String = fixture
            .query_one(Statement::from_string(
                DbBackend::Postgres,
                "SELECT current_schema()",
            ))
            .await
            .unwrap()
            .expect("one row")
            .try_get_by_index(0)
            .unwrap();
        let mut options = ConnectOptions::new(url);
        options
            .max_connections(max_connections)
            .test_before_acquire(false)
            .sqlx_logging(false)
            .set_schema_search_path(schema);
        Database::connect(options).await.unwrap()
    }

    /// An open transaction on its own connection holding an uncommitted
    /// `actor` row and optionally an uncommitted `invocation`, so an audit
    /// INSERT of the same key waits inside PostgreSQL until it ends.
    struct RowLock {
        tx: sea_orm::DatabaseTransaction,
        pid: i32,
    }

    async fn row_lock(conn: &DatabaseConnection, actor: &str, invocation: Option<Hash>) -> RowLock {
        let tx = conn.begin().await.unwrap();
        let pid = query_i32(&tx, "SELECT pg_backend_pid()", Vec::new()).await;
        actor::Entity::insert(actor::ActiveModel {
            id: Set(actor.to_string()),
        })
        .exec(&tx)
        .await
        .unwrap();
        if let Some(id) = invocation {
            invocation::Entity::insert(invocation::ActiveModel {
                id: Set(id),
                invoker: Set(actor.to_string()),
                issued_at: Set(OffsetDateTime::now_utc()),
                facts: Set(None),
                serialization: Set(b"held by another transaction".to_vec()),
            })
            .exec(&tx)
            .await
            .unwrap();
        }
        RowLock { tx, pid }
    }

    /// The backend that waits on a lock held by `blocker`. Polls until one
    /// does; the deadline only turns a hang into a failure.
    async fn backend_blocked_by(observer: &DatabaseConnection, blocker: i32) -> i32 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if let Some(row) = observer
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT pid FROM pg_stat_activity WHERE $1 = ANY(pg_blocking_pids(pid))",
                    [blocker.into()],
                ))
                .await
                .unwrap()
            {
                return row.try_get_by_index(0).unwrap();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "no backend waits on {blocker}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    /// The single statement is idempotent, so `persist_batch` retries it
    /// once after its backend is terminated (TC-951); the retry waits on the
    /// same row lock from a new backend. Terminate that one too, so the
    /// batch fails after its one retry.
    async fn terminate_retry(observer: &DatabaseConnection, blocker: i32, first: i32) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let retry: i32 = loop {
            if let Some(row) = observer
                .query_one(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT pid FROM pg_stat_activity \
                     WHERE $1 = ANY(pg_blocking_pids(pid)) AND pid <> $2",
                    [blocker.into(), first.into()],
                ))
                .await
                .unwrap()
            {
                break row.try_get_by_index(0).unwrap();
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the audit statement was not retried"
            );
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        };
        terminate_backend(observer, retry).await;
    }

    async fn terminate_backend(observer: &DatabaseConnection, pid: i32) {
        let terminated: bool = observer
            .query_one(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT pg_terminate_backend($1)",
                [pid.into()],
            ))
            .await
            .unwrap()
            .expect("one row")
            .try_get_by_index(0)
            .unwrap();
        assert!(terminated, "backend {pid} was not terminated");
    }

    /// A pipeline whose next batch, the gate read alone, waits inside
    /// PostgreSQL on another transaction's uncommitted actor row. Reads
    /// enqueued meanwhile stay in the channel, so once the gate commits the
    /// following batches are exactly consecutive runs of `MAX_BATCH_SIZE`.
    struct Stall {
        lock: RowLock,
        gate: tokio::task::JoinHandle<Result<(), ReadAuditError>>,
    }

    fn gate_read(name: &str) -> ReadAuditRecord {
        rich_record(name, &format!("did:key:{name}"), vec![], vec![])
    }

    async fn stall(
        pipeline: &ReadAuditPipeline,
        locks: &DatabaseConnection,
        observer: &DatabaseConnection,
        gate: &str,
    ) -> Stall {
        let lock = row_lock(locks, &format!("did:key:{gate}"), None).await;
        let pipeline = pipeline.clone();
        let read = gate_read(gate);
        let gate = tokio::spawn(async move { pipeline.enqueue(read).await });
        backend_blocked_by(observer, lock.pid).await;
        Stall { lock, gate }
    }

    impl Stall {
        /// Rolls the lock back, so the gate read commits.
        async fn release(self) {
            self.lock.tx.rollback().await.unwrap();
            self.gate.await.unwrap().unwrap();
        }
    }

    /// Enqueues `reads` on a stalled pipeline in this order, one task per
    /// read, all waiting at once. Returns each read's receipt.
    async fn enqueue_in_order(
        pipeline: &ReadAuditPipeline,
        reads: Vec<ReadAuditRecord>,
    ) -> Vec<tokio::task::JoinHandle<Result<(), ReadAuditError>>> {
        let queued = || CHANNEL_CAPACITY - pipeline.sender.capacity();
        let already = queued();
        let mut receipts = Vec::new();
        for read in reads {
            let sender = pipeline.clone();
            receipts.push(tokio::spawn(async move { sender.enqueue(read).await }));
            while queued() < already + receipts.len() {
                tokio::task::yield_now().await;
            }
        }
        receipts
    }

    /// One read of the overlap workload: 7 invokers, 4 parent delegations,
    /// 3 resources shared by every read, a capability listed twice, a parent
    /// cited twice, and reads with no capability or parent.
    fn overlapping_read(key: usize, parents: &[Hash]) -> ReadAuditRecord {
        let resources = ["a", "b", "c"]
            .map(|name| resource(&format!("tinycloud:did:key:ne-delegator:files/kv/{name}")));
        let get = ability("tinycloud.kv/get");
        let put = ability("tinycloud.kv/put");
        let mut abilities = Vec::new();
        let mut cited = Vec::new();
        if !key.is_multiple_of(13) {
            abilities.push((resources[key % 3].clone(), get.clone()));
            cited.push(parents[key % 4]);
        }
        if key.is_multiple_of(2) {
            abilities.push((resources[(key + 1) % 3].clone(), put));
        }
        if key.is_multiple_of(4) {
            abilities.push((resources[key % 3].clone(), get));
        }
        if key.is_multiple_of(3) {
            cited.push(parents[(key + 1) % 4]);
        }
        if key.is_multiple_of(11) {
            cited.push(parents[key % 4]);
        }
        rich_record(
            &format!("overlap-{key}"),
            &format!("did:key:reader-{}", key % 7),
            abilities,
            cited,
        )
    }

    /// The read the `index`th request makes. Identical reads hash to one
    /// invocation id: every tenth request repeats the one before it (same
    /// batch), and from the second batch on another tenth repeats the read
    /// made one batch earlier (already committed).
    fn overlap_key(index: usize) -> usize {
        match index % 10 {
            9 => index - 1,
            5 if index >= MAX_BATCH_SIZE => index - MAX_BATCH_SIZE,
            _ => index,
        }
    }

    /// Every read through the real pipeline on PostgreSQL commits exactly the
    /// rows the transactional path commits for the same batches (run in a
    /// second, isolated schema), and every waiting read gets Ok. 200 reads
    /// queue behind a stalled batch, so they commit as exactly 64 + 64 + 64 +
    /// 8 with repeated invokers, parents and invocations inside each batch and
    /// across batches; then 100 more run free, half of them repeating
    /// committed reads.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn postgres_read_audit_pipeline_commits_every_overlapping_read_like_the_transaction() {
        use crate::test_support::PostgresTestSchema;

        const TEST: &str =
            "postgres_read_audit_pipeline_commits_every_overlapping_read_like_the_transaction";
        const SATURATED: usize = 200;
        let Some(pipelined) = PostgresTestSchema::new(TEST).await else {
            return;
        };
        let Some(transactional) = PostgresTestSchema::new(TEST).await else {
            return;
        };
        let parents: Vec<Hash> = (0..4)
            .map(|index| crate::hash::hash(format!("overlap-parent-{index}").as_bytes()))
            .collect();
        for conn in [&pipelined.conn, &transactional.conn] {
            for parent in &parents {
                insert_parent_delegation(conn, *parent).await;
            }
        }
        let reads = |indexes: std::ops::Range<usize>| {
            indexes
                .map(|index| overlapping_read(overlap_key(index), &parents))
                .collect::<Vec<_>>()
        };

        let pipeline = ReadAuditPipeline::start(schema_pool(TEST, &pipelined.conn, 4).await, None);
        pipeline.set_wait(COMMIT_TEST_WAIT);
        let locks = schema_pool(TEST, &pipelined.conn, 1).await;
        let stalled = stall(&pipeline, &locks, &pipelined.conn, "overlap-gate").await;
        let receipts = enqueue_in_order(&pipeline, reads(0..SATURATED)).await;
        stalled.release().await;
        for receipt in receipts {
            receipt.await.unwrap().unwrap();
        }
        assert_eq!(
            pipeline.stats(),
            (
                1 + SATURATED as u64,
                1 + SATURATED.div_ceil(MAX_BATCH_SIZE) as u64
            )
        );

        let receipts = reads(150..250)
            .into_iter()
            .map(|read| {
                let pipeline = pipeline.clone();
                tokio::spawn(async move { pipeline.enqueue(read).await })
            })
            .collect::<Vec<_>>();
        for receipt in receipts {
            receipt.await.unwrap().unwrap();
        }
        assert_eq!(pipeline.stats().0, 1 + SATURATED as u64 + 100);

        // The transactional path, batch for batch.
        persist_in_transaction(&transactional.conn, &[command(gate_read("overlap-gate"))])
            .await
            .unwrap();
        for start in (0..SATURATED).step_by(MAX_BATCH_SIZE) {
            let batch = commands(reads(start..SATURATED.min(start + MAX_BATCH_SIZE)));
            persist_in_transaction(&transactional.conn, &batch)
                .await
                .unwrap();
        }
        for read in reads(150..250) {
            persist_in_transaction(&transactional.conn, &[command(read)])
                .await
                .unwrap();
        }

        let rows = audit_rows(&pipelined.conn).await;
        assert_eq!(rows, audit_rows(&transactional.conn).await);

        let mut all = vec![gate_read("overlap-gate")];
        all.extend(reads(0..SATURATED));
        all.extend(reads(150..250));
        let expected = expected_rows(&all);
        assert!(
            expected.1.len() < all.len(),
            "the workload repeats invocations"
        );
        assert_eq!(audit_row_sets(&pipelined.conn).await, expected);
    }

    #[derive(Clone, Copy, Debug)]
    enum Failure {
        /// A read cites a delegation that does not exist: the parent edge's
        /// foreign key fails once the batch's INSERTs have run.
        MissingParent,
        /// The writer's backend is terminated while its INSERT of the
        /// batch's last invocation waits on another transaction's
        /// uncommitted row, after the earlier invocations went in.
        Terminated,
    }

    impl Failure {
        fn name(self) -> &'static str {
            match self {
                Failure::MissingParent => "missing-parent",
                Failure::Terminated => "terminated",
            }
        }

        /// Text of the error every waiter must receive.
        fn error(self) -> &'static str {
            match self {
                Failure::MissingParent => "foreign key constraint",
                Failure::Terminated => "terminating connection",
            }
        }

        /// What a waiter of the failed batch is told (TC-1317): a terminated
        /// connection is a retryable failure, a constraint is not.
        fn waiter_error(self) -> &'static str {
            match self {
                Failure::MissingParent => "foreign key constraint",
                Failure::Terminated => "unavailable_retryable",
            }
        }

        fn held_invocation(self) -> Hash {
            crate::hash::hash(format!("{}-held", self.name()).as_bytes())
        }
    }

    const COMMITTED_READ: &str = "already-committed";

    fn committed_read(parent: Hash) -> ReadAuditRecord {
        rich_record(
            COMMITTED_READ,
            "did:key:already-committed",
            vec![(
                resource("tinycloud:did:key:ne-delegator:files/kv/doomed"),
                ability("tinycloud.kv/get"),
            )],
            vec![parent],
        )
    }

    /// Reads that commit on their own: new invokers, capabilities and parent
    /// edges, a read repeated within the batch, and a repeat of
    /// `committed_read`.
    fn valid_reads(failure: Failure, parent: Hash) -> Vec<ReadAuditRecord> {
        let name = failure.name();
        let read = |seed: &str, invoker: &str, parents: Vec<Hash>| {
            rich_record(
                &format!("{name}-{seed}"),
                &format!("did:key:{name}-{invoker}"),
                vec![(
                    resource("tinycloud:did:key:ne-delegator:files/kv/doomed"),
                    ability("tinycloud.kv/get"),
                )],
                parents,
            )
        };
        vec![
            read("a", "first", vec![parent]),
            committed_read(parent),
            read("b", "second", vec![]),
            read("a", "first", vec![parent]),
        ]
    }

    /// `valid_reads` plus the read that makes the batch fail as `failure`
    /// says: in the middle for `MissingParent`, last for `Terminated` (it is
    /// `held_invocation`, whose row the test holds). With `oversized`, one
    /// more read before the last has so many capabilities that the batch
    /// exceeds the single statement's parameter limit (while each per-table
    /// INSERT stays within it), so it takes the transactional path.
    fn doomed_reads(failure: Failure, parent: Hash, oversized: bool) -> Vec<ReadAuditRecord> {
        let name = failure.name();
        let mut reads = valid_reads(failure, parent);
        match failure {
            Failure::MissingParent => reads.insert(
                2,
                rich_record(
                    &format!("{name}-orphan"),
                    &format!("did:key:{name}-orphan"),
                    vec![],
                    vec![crate::hash::hash(b"no-such-delegation")],
                ),
            ),
            Failure::Terminated => reads.push(ReadAuditRecord {
                id: failure.held_invocation(),
                ..rich_record(
                    "held",
                    &format!("did:key:{name}-second"),
                    vec![(
                        resource("tinycloud:did:key:ne-delegator:files/kv/held"),
                        ability("tinycloud.kv/get"),
                    )],
                    vec![parent],
                )
            }),
        }
        if oversized {
            let ability_rows = expected_rows(&reads).2.len();
            let capabilities = (ability_rows..21_840)
                .map(|index| {
                    (
                        resource(&format!(
                            "tinycloud:did:key:ne-delegator:files/kv/oversized/{index}"
                        )),
                        ability("tinycloud.kv/get"),
                    )
                })
                .collect();
            let last = reads.len() - 1;
            reads.insert(
                last,
                rich_record(
                    &format!("{name}-oversized"),
                    &format!("did:key:{name}-oversized"),
                    capabilities,
                    vec![],
                ),
            );
        }
        let batch = commands(reads);
        assert_eq!(
            postgres_single_statement(&audit_inserts(&batch).unwrap()).is_some(),
            !oversized,
            "the batch takes the intended path"
        );
        batch.into_iter().map(|command| command.record).collect()
    }

    /// A batch that fails part-way commits none of its rows on PostgreSQL,
    /// and every read waiting on it gets the error, on the single statement
    /// and on the transactional path (a batch past the parameter limit). The
    /// batch carries new invokers, capabilities and parent edges, a read
    /// repeated within it and one already committed. It fails either by a
    /// foreign key or by the writer's backend being terminated while it
    /// waits on a row lock after inserting earlier invocations. The next
    /// batch commits, on a fresh connection after the termination. Both
    /// paths end with identical rows. The single statement is retried once
    /// after a termination (TC-951), so it fails only when the retry's
    /// backend is terminated too.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn postgres_read_audit_failed_batch_commits_nothing_and_fails_every_waiter() {
        use crate::test_support::PostgresTestSchema;

        const TEST: &str =
            "postgres_read_audit_failed_batch_commits_nothing_and_fails_every_waiter";
        let mut final_rows = Vec::new();
        for oversized in [false, true] {
            let Some(fixture) = PostgresTestSchema::new(TEST).await else {
                return;
            };
            let conn = &fixture.conn;
            let parent = crate::hash::hash(b"doomed-parent");
            insert_parent_delegation(conn, parent).await;
            persist_in_transaction(conn, &[command(committed_read(parent))])
                .await
                .unwrap();
            let pipeline = ReadAuditPipeline::start(schema_pool(TEST, conn, 4).await, None);
            pipeline.set_wait(COMMIT_TEST_WAIT);
            let locks = schema_pool(TEST, conn, 2).await;

            for failure in [Failure::Terminated, Failure::MissingParent] {
                let gate = format!("gate-{}", failure.name());
                let before = union(
                    audit_row_sets(conn).await,
                    expected_rows(&[gate_read(&gate)]),
                );
                let stats = pipeline.stats();

                let stalled = stall(&pipeline, &locks, conn, &gate).await;
                let held = match failure {
                    Failure::Terminated => Some(
                        row_lock(
                            &locks,
                            "did:key:lock-holder",
                            Some(failure.held_invocation()),
                        )
                        .await,
                    ),
                    Failure::MissingParent => None,
                };
                let reads = doomed_reads(failure, parent, oversized);
                let waiters = reads.len();
                let receipts = enqueue_in_order(&pipeline, reads).await;
                stalled.release().await;
                if let Some(held) = &held {
                    let writer = backend_blocked_by(conn, held.pid).await;
                    terminate_backend(conn, writer).await;
                    if !oversized {
                        terminate_retry(conn, held.pid, writer).await;
                    }
                }
                let mut failed = 0;
                for receipt in receipts {
                    let error = receipt
                        .await
                        .unwrap()
                        .expect_err("a read of a failed batch is not acknowledged");
                    assert!(
                        error.to_string().contains(failure.waiter_error()),
                        "{failure:?}: {error}"
                    );
                    failed += 1;
                }
                assert_eq!(failed, waiters);
                if let Some(held) = held {
                    held.tx.rollback().await.unwrap();
                }
                assert_eq!(audit_row_sets(conn).await, before, "{failure:?}");
                assert_eq!(pipeline.stats(), (stats.0 + 1, stats.1 + 1));

                // The next batch commits: the same reads without the one
                // that failed them.
                let receipts = valid_reads(failure, parent)
                    .into_iter()
                    .map(|read| {
                        let pipeline = pipeline.clone();
                        tokio::spawn(async move { pipeline.enqueue(read).await })
                    })
                    .collect::<Vec<_>>();
                for receipt in receipts {
                    receipt.await.unwrap().unwrap();
                }
                assert_eq!(
                    audit_row_sets(conn).await,
                    union(before, expected_rows(&valid_reads(failure, parent))),
                    "{failure:?}"
                );
            }
            final_rows.push(audit_rows(conn).await);
        }
        assert_eq!(final_rows[0], final_rows[1]);
    }

    /// The same failing batch through `persist_batch` (one statement) and
    /// through the transaction it replaced, each in its own schema: both
    /// return the same error and leave the same rows as before, whether a
    /// foreign key fails or the backend is terminated mid-write.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn postgres_read_audit_failed_batch_fails_alike_on_both_paths() {
        use crate::test_support::PostgresTestSchema;

        const TEST: &str = "postgres_read_audit_failed_batch_fails_alike_on_both_paths";
        let mut outcomes = Vec::new();
        for (persist, retried) in [
            (persist_batch_boxed as Persist, true),
            (persist_in_transaction as Persist, false),
        ] {
            let Some(fixture) = PostgresTestSchema::new(TEST).await else {
                return;
            };
            let conn = &fixture.conn;
            let parent = crate::hash::hash(b"doomed-parent");
            insert_parent_delegation(conn, parent).await;
            persist_in_transaction(conn, &[command(committed_read(parent))])
                .await
                .unwrap();
            let writer = schema_pool(TEST, conn, 1).await;
            let locks = schema_pool(TEST, conn, 1).await;

            let mut outcome = Vec::new();
            for failure in [Failure::MissingParent, Failure::Terminated] {
                let before = audit_rows(conn).await;
                let held = match failure {
                    Failure::Terminated => Some(
                        row_lock(
                            &locks,
                            "did:key:lock-holder",
                            Some(failure.held_invocation()),
                        )
                        .await,
                    ),
                    Failure::MissingParent => None,
                };
                let batch = commands(doomed_reads(failure, parent, false));
                let writer = writer.clone();
                let persisted = tokio::spawn(async move {
                    persist(&writer, &batch).await.map_err(|e| e.to_string())
                });
                if let Some(held) = &held {
                    let backend = backend_blocked_by(conn, held.pid).await;
                    terminate_backend(conn, backend).await;
                    if retried {
                        terminate_retry(conn, held.pid, backend).await;
                    }
                }
                let error = persisted.await.unwrap().expect_err("the batch fails");
                assert!(error.contains(failure.error()), "{failure:?}: {error}");
                if let Some(held) = held {
                    held.tx.rollback().await.unwrap();
                }
                let after = audit_rows(conn).await;
                assert_eq!(after, before, "{failure:?}");
                outcome.push((failure.name(), error, after));
            }
            outcomes.push(outcome);
        }
        assert_eq!(outcomes[0], outcomes[1]);
    }

    // TC-1317: a bounded wait, abandoned records skipped, and the invariant
    // that no read is confirmed without its committed record.

    const PATIENCE: Duration = Duration::from_secs(10);
    /// Tests of commit semantics, not of the bound: a loaded host must not
    /// turn their waits into `Busy` (TC-1317 review).
    const COMMIT_TEST_WAIT: Duration = Duration::from_secs(600);

    async fn file_pipeline() -> (tempfile::TempDir, DatabaseConnection, ReadAuditPipeline) {
        let directory = tempfile::tempdir().unwrap();
        let url = format!(
            "sqlite:{}?mode=rwc",
            directory.path().join("bounded.db").display()
        );
        let conn = database(url, 4).await;
        let pipeline = ReadAuditPipeline::start(conn.clone(), Some(Arc::new(Mutex::new(()))));
        (directory, conn, pipeline)
    }

    async fn committed(conn: &DatabaseConnection, index: usize) -> bool {
        invocation::Entity::find_by_id(record(index).id)
            .one(conn)
            .await
            .unwrap()
            .is_some()
    }

    async fn until(mut done: impl FnMut() -> bool) {
        tokio::time::timeout(PATIENCE, async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("condition must hold in time");
    }

    /// `enqueue`, failing the test rather than hanging if it never returns.
    async fn bounded(pipeline: &ReadAuditPipeline, index: usize) -> Result<(), ReadAuditError> {
        tokio::time::timeout(PATIENCE, pipeline.enqueue(record(index)))
            .await
            .expect("enqueue must return within its bound")
    }

    /// The watchdog reports a drain that stopped moving, once per interval,
    /// and stays quiet while it progresses.
    #[test]
    fn tc1317_the_watchdog_reports_a_stalled_drain_once_per_interval() {
        let stats = PipelineStats::default();
        let mut state = WatchdogState::default();
        let start = Instant::now();
        let waiting = ReadAuditHealth {
            queue_depth: 3,
            ..Default::default()
        };
        let stalled = |state: &WatchdogState| state.last[3];

        watch(&stats, &mut state, waiting, start);
        assert_eq!(stalled(&state), None, "just started waiting");
        watch(&stats, &mut state, waiting, start + STALLED_QUEUE_WAIT);
        assert_eq!(stalled(&state), Some(start + STALLED_QUEUE_WAIT));
        watch(&stats, &mut state, waiting, start + STALLED_QUEUE_WAIT * 2);
        assert_eq!(
            stalled(&state),
            Some(start + STALLED_QUEUE_WAIT),
            "rate-limited"
        );

        // A batch completes: no longer stalled, even with records queued.
        let moved = ReadAuditHealth {
            batches: 1,
            ..waiting
        };
        let later = start + STALLED_QUEUE_WAIT + WARNING_INTERVAL;
        watch(&stats, &mut state, moved, later);
        assert_eq!(stalled(&state), Some(start + STALLED_QUEUE_WAIT));

        // A batch in flight too long is stalled whatever the queue does.
        let hung = ReadAuditHealth {
            batches: 1,
            in_flight_batch_age_ms: STALLED_BATCH.as_millis() as u64,
            ..Default::default()
        };
        watch(&stats, &mut state, hung, later + Duration::from_secs(1));
        assert_eq!(stalled(&state), Some(later + Duration::from_secs(1)));
    }

    /// A drain that is gone answers every read `Stopped`, counts it, and is
    /// reported as a stalled drain until it comes back, which it never does.
    #[tokio::test]
    async fn tc1317_a_dead_drain_is_counted_and_reported() {
        let (sender, receiver) = mpsc::channel(CHANNEL_CAPACITY);
        drop(receiver);
        let pipeline = ReadAuditPipeline {
            sender,
            stats: Arc::default(),
            wait_ms: Arc::new(AtomicU64::new(PATIENCE.as_millis() as u64)),
            gate: Arc::default(),
        };
        let stalled = |state: &WatchdogState| state.last[3];
        let mut state = WatchdogState::default();
        let start = Instant::now();

        // Dead before any read: reported on the first look.
        let idle = pipeline.health();
        assert!(idle.drain_stopped);
        assert_eq!(idle.stopped, 0);
        watch(&pipeline.stats, &mut state, idle, start);
        assert_eq!(stalled(&state), Some(start));

        for index in 0..2 {
            assert_eq!(
                bounded(&pipeline, index).await,
                Err(ReadAuditError::Stopped)
            );
        }
        let failing = pipeline.health();
        assert_eq!((failing.stopped, failing.busy), (2, 0));
        watch(&pipeline.stats, &mut state, failing, start + WATCHDOG_TICK);
        assert_eq!(stalled(&state), Some(start), "rate-limited");
        let later = start + WARNING_INTERVAL;
        watch(&pipeline.stats, &mut state, failing, later);
        assert_eq!(stalled(&state), Some(later), "still dead, reported again");
        assert_eq!(state.reported.stopped, 2);
    }

    /// A request's deadline context says the time is going to the read
    /// audit while a read waits for its record, and stops saying so once the
    /// wait ends: a deadline that cuts the wait logs `stage = read_audit`.
    #[tokio::test]
    async fn tc1317_a_read_waiting_on_its_audit_is_in_the_read_audit_stage() {
        use crate::request_cancel::{within, RequestCancel, Stage};

        let (_directory, _conn, pipeline) = file_pipeline().await;
        pipeline.set_wait(COMMIT_TEST_WAIT);
        let context = RequestCancel::new(COMMIT_TEST_WAIT);
        let held = pipeline.hold_drain().await;
        let read = tokio::spawn({
            let (pipeline, context) = (pipeline.clone(), context.clone());
            async move { within(Some(context), pipeline.enqueue(record(0))).await }
        });
        tokio::time::timeout(PATIENCE, async {
            while context.stage() != Stage::ReadAudit {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the waiting read must be in the read-audit stage");
        assert!(!read.is_finished(), "still waiting on the held drain");

        drop(held);
        let outcome = tokio::time::timeout(PATIENCE, read)
            .await
            .expect("released drain commits")
            .unwrap();
        assert_eq!(outcome, Ok(()));
        assert_eq!(context.stage(), Stage::Other);
    }

    #[tokio::test]
    async fn tc1317_a_held_drain_answers_busy_within_the_bound() {
        let (_directory, _conn, pipeline) = file_pipeline().await;
        pipeline.set_wait(Duration::from_millis(200));
        let held = pipeline.hold_drain().await;
        let started = std::time::Instant::now();
        let outcome = tokio::time::timeout(PATIENCE, pipeline.enqueue(record(0)))
            .await
            .expect("the wait must end at its bound");
        assert_eq!(outcome, Err(ReadAuditError::Busy));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(pipeline.health().busy, 1);
        drop(held);
    }

    /// Records whose waiters were gone when their batch formed are skipped
    /// and counted; a waiter still waiting is always committed.
    #[tokio::test]
    async fn tc1317_abandoned_records_are_skipped_and_the_drain_recovers() {
        let (_directory, conn, pipeline) = file_pipeline().await;
        pipeline.set_wait(Duration::from_millis(100));
        let held = pipeline.hold_drain().await;

        // Record 0 is taken into a batch, which then waits at the gate.
        assert_eq!(bounded(&pipeline, 0).await, Err(ReadAuditError::Busy));
        until(|| pipeline.health().queue_depth == 0).await;
        // Records 1-5 queue behind it, and their waiters give up.
        for index in 1..=5 {
            assert_eq!(bounded(&pipeline, index).await, Err(ReadAuditError::Busy));
        }
        assert_eq!(pipeline.health().queue_depth, 5);

        drop(held);
        until(|| pipeline.health().abandoned == 5).await;
        // The batch formed before its waiter left is committed (harmless:
        // nothing was returned); the abandoned ones never reach the DB.
        until(|| pipeline.health().records == 1).await;
        assert!(committed(&conn, 0).await);
        for index in 1..=5 {
            assert!(!committed(&conn, index).await, "record {index}");
        }

        pipeline.set_wait(DEFAULT_READ_AUDIT_WAIT);
        tokio::time::timeout(PATIENCE, pipeline.enqueue(record(6)))
            .await
            .expect("a recovered drain answers at once")
            .unwrap();
        assert!(committed(&conn, 6).await);
    }

    /// The invariant: whenever `enqueue` confirms, the record is committed,
    /// including when waiters around it are cut at random points.
    #[tokio::test]
    async fn tc1317_no_read_is_confirmed_without_its_committed_record() {
        let (_directory, conn, pipeline) = file_pipeline().await;
        let held = pipeline.hold_drain().await;
        let waiters = (0..48)
            .map(|index| {
                let pipeline = pipeline.clone();
                tokio::spawn(async move {
                    // Every third waiter is cut while it waits.
                    let cut = Duration::from_millis(if index % 3 == 0 { 20 } else { 5_000 });
                    (
                        index,
                        tokio::time::timeout(cut, pipeline.enqueue(record(index))).await,
                    )
                })
            })
            .collect::<Vec<_>>();
        // Every cut waiter has gone before the drain is released.
        let (cut, staying): (Vec<_>, Vec<_>) = waiters
            .into_iter()
            .enumerate()
            .partition(|(index, _)| index % 3 == 0);
        for (_, waiter) in cut {
            let (_, outcome) = waiter.await.unwrap();
            assert!(outcome.is_err(), "a cut waiter is never confirmed");
        }
        drop(held);
        let mut confirmed = 0;
        for (_, waiter) in staying {
            let (index, outcome) = waiter.await.unwrap();
            if matches!(outcome, Ok(Ok(()))) {
                confirmed += 1;
                assert!(
                    committed(&conn, index).await,
                    "confirmed {index} uncommitted"
                );
            }
        }
        assert_eq!(confirmed, 32, "every waiter that stayed was confirmed");
        let health = pipeline.health();
        assert_eq!(
            health.records + health.abandoned,
            48,
            "each record is either committed or counted as abandoned"
        );
    }

    #[tokio::test]
    async fn tc1317_a_transient_batch_failure_is_retryable() {
        assert_eq!(
            batch_error(DbErr::ConnectionAcquire(
                sea_orm::error::ConnAcquireErr::Timeout
            )),
            ReadAuditError::Unavailable
        );
        assert!(matches!(
            batch_error(DbErr::Custom("constraint".into())),
            ReadAuditError::Failed(_)
        ));
    }

    /// A panic while committing one batch fails only that batch's waiters;
    /// the drain keeps serving.
    #[tokio::test]
    async fn tc1317_a_panicking_batch_does_not_stop_the_drain() {
        let (_directory, conn, pipeline) = file_pipeline().await;
        pipeline
            .stats
            .panic_next_batch
            .store(true, Ordering::SeqCst);
        let outcome = tokio::time::timeout(PATIENCE, pipeline.enqueue(record(0)))
            .await
            .expect("the panicking batch's waiter must be answered");
        assert!(
            matches!(outcome, Err(ReadAuditError::Failed(_))),
            "{outcome:?}"
        );
        assert_eq!(pipeline.health().failed_batches, 1);
        tokio::time::timeout(PATIENCE, pipeline.enqueue(record(1)))
            .await
            .expect("the drain survives")
            .unwrap();
        assert!(committed(&conn, 1).await);
    }
}

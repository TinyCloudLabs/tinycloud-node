//! The shadow uploader's IO shell (TC-1491 P1): one task that steps the
//! per-database machines and runs their uploads.
//!
//! - Inputs: hook notices (drained from the [`NoticeBoard`] on its wake-up),
//!   the lag scan (once at startup, which is how bootstrap begins, then every
//!   `scan_every`), a periodic tick, and upload completions.
//! - Uploads run as jobs on a `JoinSet`. A job reads the artifact head,
//!   plans with [`plan_publish`], reserves scratch disk and upload bytes,
//!   streams the checkpoint and/or WAL into scratch files, puts them, and
//!   publishes the chain in one control-database transaction. Its result
//!   comes back to the machine as `Published`, `Lost` or `Failed`.
//! - Limits: one byte semaphore (charged with the job's size before it
//!   streams), one PG-concurrency semaphore (held only around PG calls), a
//!   per-database daily byte budget, and one breaker for infrastructure
//!   failures that withholds the tick permit while open.
//! - Drain: stop scheduling, wait for in-flight jobs up to a deadline, and
//!   report each database's `last_seq` against its target revision.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sea_orm::DatabaseConnection;
use tokio::sync::{oneshot, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

use super::budget::{DiskBudget, Reservation};
use super::machine::{
    plan_publish, step, ArtifactHead, BlockReason, Command, DbMachine, Event, Failure, Head,
    LineagePick, Phase, Policy, PolicyReason, PublishPlan, Work,
};
use super::metrics::{PublishResult, ShadowMetrics, UploadResult};
use super::scan::scan_space;
use super::source::{ShadowSource, SourceError};
use super::{DbKey, NoticeBoard};
use crate::sql::store::key::{DbRef, Lineage, ObjectKey, PublishId};
use crate::sql::store::manifest::{
    now_timestamp, Frontier, ObjectRecord, PublishChain, PublishOutcome, SqlManifest,
};
use crate::sql::store::object::{SqlObjectStore, SqlStoreError};

/// Everything the scheduler and its jobs talk to.
pub struct ShadowDeps {
    /// The control database the lag scan reads.
    pub control: DatabaseConnection,
    pub manifest: Arc<dyn SqlManifest>,
    pub store: Arc<dyn SqlObjectStore>,
    pub source: Arc<dyn ShadowSource>,
    pub disk: Arc<DiskBudget>,
    pub board: Arc<NoticeBoard>,
    pub metrics: Arc<dyn ShadowMetrics>,
}

#[derive(Debug, Clone)]
pub struct SchedulerConfig {
    pub policy: Policy,
    /// How often every machine is ticked.
    pub tick: Duration,
    /// How often the lag scan runs after the startup scan.
    pub scan_every: Duration,
    /// Rows per lag-scan statement.
    pub scan_page: u64,
    /// Upload jobs running at once.
    pub max_jobs: usize,
    /// Bytes the running jobs may stream at once.
    pub upload_bytes: u64,
    /// PG calls (artifact reads, manifest publishes, scans) at once.
    pub pg_concurrency: usize,
    /// Bytes one database may publish per UTC day; 0 is unlimited.
    pub daily_upload_byte_budget: u64,
    /// Consecutive infrastructure failures that open the breaker.
    pub breaker_failures: u32,
    pub breaker_cooldown: Duration,
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            policy: Policy::default(),
            tick: Duration::from_secs(1),
            scan_every: Duration::from_secs(300),
            scan_page: 500,
            max_jobs: 4,
            upload_bytes: 64 * 1024 * 1024,
            pg_concurrency: 2,
            daily_upload_byte_budget: 0,
            breaker_failures: 5,
            breaker_cooldown: Duration::from_secs(60),
        }
    }
}

/// One database at drain time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbDrain {
    pub space: String,
    pub db_id: String,
    pub last_seq: Option<u64>,
    pub target_revision: Option<i64>,
    pub phase: &'static str,
}

impl DbDrain {
    /// The frontier covers the newest revision the uploader learned of.
    pub fn caught_up(&self) -> bool {
        match (self.last_seq, self.target_revision) {
            (_, None) => true,
            (Some(seq), Some(rev)) => i64::try_from(seq).is_ok_and(|seq| seq >= rev),
            (None, Some(_)) => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DrainReport {
    /// Sorted by `(space, db_id)`.
    pub databases: Vec<DbDrain>,
    /// Jobs still running at the deadline; they were aborted.
    pub abandoned_jobs: usize,
}

/// The running scheduler. Dropping it without [`Self::drain`] aborts it.
pub struct SchedulerHandle {
    stop: Option<oneshot::Sender<Duration>>,
    task: JoinHandle<DrainReport>,
}

impl SchedulerHandle {
    /// Stop scheduling, give in-flight jobs up to `deadline`, and report.
    pub async fn drain(mut self, deadline: Duration) -> DrainReport {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(deadline);
        }
        (&mut self.task).await.unwrap_or_default()
    }
}

impl Drop for SchedulerHandle {
    fn drop(&mut self) {
        if self.stop.is_some() {
            self.task.abort();
        }
    }
}

/// Start the scheduler on the current runtime.
pub fn spawn(deps: ShadowDeps, config: SchedulerConfig) -> SchedulerHandle {
    let (stop, stopped) = oneshot::channel();
    let scheduler = Scheduler::new(deps, config);
    SchedulerHandle {
        stop: Some(stop),
        task: tokio::spawn(scheduler.run(stopped)),
    }
}

/// What a job needs, shared by every job.
struct JobDeps {
    manifest: Arc<dyn SqlManifest>,
    store: Arc<dyn SqlObjectStore>,
    source: Arc<dyn ShadowSource>,
    disk: Arc<DiskBudget>,
    metrics: Arc<dyn ShadowMetrics>,
    pg: Semaphore,
    bytes: Semaphore,
    /// `bytes`' capacity in KiB permits.
    bytes_kib: u32,
}

impl JobDeps {
    /// KiB permits for `bytes`, capped at the whole semaphore so one large
    /// upload waits for every other one instead of never starting.
    fn charge(&self, bytes: u64) -> u32 {
        u32::try_from(bytes.div_ceil(1024))
            .unwrap_or(u32::MAX)
            .clamp(1, self.bytes_kib)
    }
}

#[derive(Debug)]
struct Uploaded {
    outcome: PublishOutcome,
    bytes: u64,
    observed: Head,
}

#[derive(Debug)]
enum JobError {
    Policy(PolicyReason),
    /// Retried with backoff; `infra` failures feed the breaker. `observed`
    /// is a newer head the job saw (the source moved on).
    Transient {
        infra: bool,
        observed: Option<Head>,
    },
    /// The artifact is below the frontier (a PG restore).
    Regressed(Head),
}

struct JobDone {
    key: DbKey,
    work: Work,
    have: Option<Frontier>,
    result: Result<Uploaded, JobError>,
}

/// Consecutive infrastructure failures, and how long the breaker stays open.
#[derive(Debug, Default)]
struct Breaker {
    failures: u32,
    open_until: Option<Instant>,
}

impl Breaker {
    fn is_open(&mut self, now: Instant) -> bool {
        match self.open_until {
            Some(until) if now < until => true,
            Some(_) => {
                self.open_until = None;
                false
            }
            None => false,
        }
    }
}

/// Bytes published per database in the current UTC day.
#[derive(Debug)]
struct Spend {
    day: time::Date,
    bytes: HashMap<DbKey, u64>,
}

struct Scheduler {
    deps: Arc<JobDeps>,
    control: DatabaseConnection,
    board: Arc<NoticeBoard>,
    config: SchedulerConfig,
    machines: HashMap<DbKey, DbMachine>,
    jobs: JoinSet<JobDone>,
    running: HashMap<tokio::task::Id, (DbKey, Work, Option<Frontier>)>,
    breaker: Breaker,
    spend: Spend,
    last_scan: Option<Instant>,
}

impl Scheduler {
    fn new(deps: ShadowDeps, config: SchedulerConfig) -> Self {
        let bytes_kib = u32::try_from(config.upload_bytes.div_ceil(1024))
            .unwrap_or(u32::MAX)
            .clamp(1, Semaphore::MAX_PERMITS as u32);
        Self {
            deps: Arc::new(JobDeps {
                manifest: deps.manifest,
                store: deps.store,
                source: deps.source,
                disk: deps.disk,
                metrics: deps.metrics,
                pg: Semaphore::new(config.pg_concurrency.max(1)),
                bytes: Semaphore::new(bytes_kib as usize),
                bytes_kib,
            }),
            control: deps.control,
            board: deps.board,
            machines: HashMap::new(),
            jobs: JoinSet::new(),
            running: HashMap::new(),
            breaker: Breaker::default(),
            spend: Spend {
                day: time::OffsetDateTime::now_utc().date(),
                bytes: HashMap::new(),
            },
            last_scan: None,
            config,
        }
    }

    async fn run(mut self, mut stop: oneshot::Receiver<Duration>) -> DrainReport {
        let mut tick = tokio::time::interval(self.config.tick.max(Duration::from_millis(1)));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let deadline = loop {
            tokio::select! {
                deadline = &mut stop => break deadline.unwrap_or_default(),
                () = self.board.notified() => self.absorb_notices().await,
                Some(done) = self.jobs.join_next_with_id(), if !self.jobs.is_empty() => {
                    self.finish(done);
                }
                _ = tick.tick() => {
                    let now = Instant::now();
                    if self
                        .last_scan
                        .is_none_or(|at| now.duration_since(at) >= self.config.scan_every)
                    {
                        self.scan().await;
                        self.last_scan = Some(Instant::now());
                    }
                    self.absorb_notices().await;
                    self.tick(Instant::now());
                }
            }
        };
        self.drain(deadline).await
    }

    /// Feed one event to a machine and act on its commands.
    fn feed(&mut self, key: &DbKey, event: Event, now: Instant) {
        let Some(machine) = self.machines.get_mut(key) else {
            return;
        };
        let commands = step(machine, event, now, &self.config.policy);
        self.act(key, commands);
    }

    fn act(&mut self, key: &DbKey, commands: Vec<Command>) {
        for command in commands {
            match command {
                Command::Blocked(reason) => {
                    self.deps.metrics.blocked(reason.label());
                    if reason == BlockReason::Regressed {
                        self.deps.metrics.regressed();
                    }
                    tracing::warn!(
                        reason = reason.label(),
                        "sql_store shadow upload blocked for a database"
                    );
                }
                Command::Upload { work, have, .. } => self.start(key.clone(), work, have),
            }
        }
    }

    fn start(&mut self, key: DbKey, work: Work, have: Option<Frontier>) {
        let budget_left = match self.config.daily_upload_byte_budget {
            0 => None,
            budget => Some(budget.saturating_sub(self.spend.bytes.get(&key).copied().unwrap_or(0))),
        };
        let deps = self.deps.clone();
        let job_key = key.clone();
        let job_have = have.clone();
        let handle = self.jobs.spawn(async move {
            let started = Instant::now();
            let result = upload(&deps, &job_key, job_have.as_ref(), budget_left).await;
            deps.metrics
                .record_cycle_seconds("upload", started.elapsed().as_secs_f64());
            JobDone {
                key: job_key,
                work,
                have: job_have,
                result,
            }
        });
        self.running.insert(handle.id(), (key, work, have));
    }

    fn finish(&mut self, done: Result<(tokio::task::Id, JobDone), tokio::task::JoinError>) {
        let now = Instant::now();
        let done = match done {
            Ok((id, done)) => {
                self.running.remove(&id);
                done
            }
            Err(error) => {
                // A panicked or aborted job: retry it like a transient failure.
                let Some((key, work, have)) = self.running.remove(&error.id()) else {
                    return;
                };
                JobDone {
                    key,
                    work,
                    have,
                    result: Err(JobError::Transient {
                        infra: false,
                        observed: None,
                    }),
                }
            }
        };
        let kind = done.work.label();
        let key = done.key;
        match done.result {
            Ok(uploaded) => {
                self.breaker.failures = 0;
                self.feed(&key, Event::Scanned(uploaded.observed), now);
                match uploaded.outcome {
                    PublishOutcome::Published(frontier) => {
                        *self.spend.bytes.entry(key.clone()).or_default() += uploaded.bytes;
                        self.deps
                            .metrics
                            .upload(kind, UploadResult::Ok, uploaded.bytes);
                        self.deps.metrics.publish(PublishResult::Published);
                        self.feed(&key, Event::Published(frontier), now);
                    }
                    PublishOutcome::Lost(current) => {
                        if uploaded.bytes > 0 {
                            self.deps
                                .metrics
                                .upload(kind, UploadResult::CasLost, uploaded.bytes);
                            self.deps.metrics.publish(PublishResult::Lost);
                        }
                        self.feed(&key, Event::Lost(current), now);
                    }
                }
            }
            Err(JobError::Policy(reason)) => {
                self.deps.metrics.upload(kind, UploadResult::Blocked, 0);
                self.feed(&key, Event::Failed(Failure::Policy(reason)), now);
            }
            Err(JobError::Regressed(head)) => {
                self.deps.metrics.upload(kind, UploadResult::Blocked, 0);
                self.feed(&key, Event::Regressed(head), now);
                // The completion that applies the deferred block.
                self.feed(&key, Event::Lost(done.have), now);
            }
            Err(JobError::Transient { infra, observed }) => {
                let result = if infra {
                    UploadResult::StoreError
                } else {
                    UploadResult::SourceError
                };
                self.deps.metrics.upload(kind, result, 0);
                if infra {
                    self.breaker.failures = self.breaker.failures.saturating_add(1);
                    if self.breaker.failures >= self.config.breaker_failures.max(1) {
                        self.breaker.open_until = Some(now + self.config.breaker_cooldown);
                        self.breaker.failures = 0;
                    }
                }
                if let Some(head) = observed {
                    self.feed(&key, Event::Scanned(head), now);
                }
                self.feed(&key, Event::Failed(Failure::Transient), now);
            }
        }
    }

    /// A machine for `key`, created on its manifest row when new. `None`
    /// when the row cannot be read now (the lag scan retries later).
    async fn ensure(&mut self, key: &DbKey) -> bool {
        if self.machines.contains_key(key) {
            return true;
        }
        let current = {
            let _pg = self.deps.pg.acquire().await;
            self.deps
                .manifest
                .current(&DbRef {
                    space: &key.0,
                    db_id: &key.1,
                })
                .await
        };
        match current {
            Ok(have) => {
                self.machines.insert(key.clone(), DbMachine::new(have));
                true
            }
            Err(error) => {
                tracing::warn!(%error, "sql_store shadow could not read a manifest row");
                false
            }
        }
    }

    async fn absorb_notices(&mut self) {
        for (key, head) in self.board.take() {
            if self.ensure(&key).await {
                self.feed(&key, Event::Notified(head), Instant::now());
            }
        }
    }

    /// The lag scan over every allowlisted space.
    async fn scan(&mut self) {
        let started = Instant::now();
        let spaces: Vec<String> = self
            .board
            .allowlist()
            .spaces()
            .map(str::to_owned)
            .collect();
        for space in spaces {
            let drift = {
                let _pg = self.deps.pg.acquire().await;
                scan_space(&self.control, &space, self.config.scan_page).await
            };
            let drift = match drift {
                Ok(drift) => drift,
                Err(error) => {
                    tracing::warn!(%error, "sql_store shadow lag scan failed");
                    continue;
                }
            };
            for row in drift {
                let key = (space.clone(), row.db_id.clone());
                let regressed = row.regressed();
                self.machines
                    .entry(key.clone())
                    .or_insert_with(|| DbMachine::new(row.have.clone()));
                let event = if regressed {
                    Event::Regressed(row.head)
                } else {
                    Event::Scanned(row.head)
                };
                self.feed(&key, event, Instant::now());
            }
        }
        self.deps
            .metrics
            .record_cycle_seconds("scan", started.elapsed().as_secs_f64());
    }

    fn tick(&mut self, now: Instant) {
        self.roll_day(now);
        let open = self.breaker.is_open(now);
        self.deps.metrics.breaker_open(open);
        let keys: Vec<DbKey> = self.machines.keys().cloned().collect();
        for key in keys {
            let permit = !open && self.jobs.len() < self.config.max_jobs.max(1);
            self.feed(&key, Event::Tick { permit }, now);
        }
        let dirty = self
            .machines
            .values()
            .filter_map(|m| match m.phase {
                Phase::Dirty { since, .. } => Some(since),
                _ => None,
            })
            .collect::<Vec<_>>();
        self.deps.metrics.dirty_databases(dirty.len() as u64);
        self.deps.metrics.oldest_dirty_age_seconds(
            dirty
                .iter()
                .map(|since| now.saturating_duration_since(*since).as_secs_f64())
                .fold(0.0, f64::max),
        );
        let held = self.deps.bytes_kib as usize - self.deps.bytes.available_permits();
        self.deps.metrics.inflight_bytes(held as u64 * 1024);
    }

    /// A new UTC day resets the spend and releases budget blocks.
    fn roll_day(&mut self, now: Instant) {
        let today = time::OffsetDateTime::now_utc().date();
        if today == self.spend.day {
            return;
        }
        self.spend = Spend {
            day: today,
            bytes: HashMap::new(),
        };
        let blocked: Vec<DbKey> = self
            .machines
            .iter()
            .filter(|(_, m)| {
                m.phase
                    == Phase::Blocked {
                        reason: BlockReason::Policy(PolicyReason::DailyBudget),
                    }
            })
            .map(|(k, _)| k.clone())
            .collect();
        for key in blocked {
            self.feed(&key, Event::Released, now);
        }
    }

    async fn drain(mut self, deadline: Duration) -> DrainReport {
        let finished = tokio::time::timeout(deadline, async {
            while let Some(done) = self.jobs.join_next_with_id().await {
                self.finish(done);
            }
        })
        .await;
        let abandoned_jobs = if finished.is_err() { self.jobs.len() } else { 0 };
        self.jobs.abort_all();
        let mut databases: Vec<DbDrain> = self
            .machines
            .iter()
            .map(|((space, db_id), m)| DbDrain {
                space: space.clone(),
                db_id: db_id.clone(),
                last_seq: m.last_seq(),
                target_revision: m.target.as_ref().map(|t| t.revision),
                phase: m.phase.label(),
            })
            .collect();
        databases.sort_by(|a, b| (&a.space, &a.db_id).cmp(&(&b.space, &b.db_id)));
        for db in databases.iter().filter(|db| !db.caught_up()) {
            tracing::warn!(
                last_seq = db.last_seq,
                target_revision = db.target_revision,
                phase = db.phase,
                "sql_store shadow drained behind PG"
            );
        }
        DrainReport {
            databases,
            abandoned_jobs,
        }
    }
}

/// How many times a WAL read restarts on a row that only gained revisions.
const WAL_READ_RETRIES: usize = 3;

fn source_failure(error: SourceError) -> JobError {
    match error {
        SourceError::Gone => JobError::Policy(PolicyReason::SourceGone),
        SourceError::TooLarge => JobError::Policy(PolicyReason::TooLarge),
        SourceError::Unreadable(_) => JobError::Policy(PolicyReason::Refused),
        SourceError::MovedOn => JobError::Transient {
            infra: false,
            observed: None,
        },
        SourceError::Transient(_) => JobError::Transient {
            infra: true,
            observed: None,
        },
    }
}

fn store_failure(error: SqlStoreError) -> JobError {
    match error {
        SqlStoreError::Key(_)
        | SqlStoreError::Conflict
        | SqlStoreError::BodyMismatch
        | SqlStoreError::Invalid(_) => JobError::Policy(PolicyReason::Refused),
        SqlStoreError::ObjectNotUploaded => JobError::Transient {
            infra: false,
            observed: None,
        },
        SqlStoreError::Backend(_) | SqlStoreError::File(_) | SqlStoreError::Manifest(_) => {
            JobError::Transient {
                infra: true,
                observed: None,
            }
        }
    }
}

fn scratch_failure(_: std::io::Error) -> JobError {
    JobError::Transient {
        infra: true,
        observed: None,
    }
}

/// A scratch file and the async handle the source writes through.
async fn scratch(reservation: &Reservation) -> Result<(tempfile::TempPath, tokio::fs::File), JobError> {
    let named = reservation.scratch().map_err(scratch_failure)?;
    let file = named.as_file().try_clone().map_err(scratch_failure)?;
    Ok((named.into_temp_path(), tokio::fs::File::from_std(file)))
}

/// Bytes a plan streams for `head`.
fn plan_bytes(plan: &PublishPlan, head: &ArtifactHead) -> u64 {
    match plan {
        PublishPlan::Chain {
            segment_to: Some(_),
            ..
        } => head.total_bytes(),
        PublishPlan::Chain { .. } => head.checkpoint_bytes,
        PublishPlan::Segment { .. } => head.delta_bytes,
    }
}

/// Is `head` below the frontier (contract 11.7)?
fn below(have: Option<&Frontier>, head: &ArtifactHead) -> bool {
    have.is_some_and(|f| {
        let last = i64::try_from(f.last_seq).unwrap_or(i64::MAX);
        head.revision < last || (head.revision == last && head.cid != f.base_checkpoint_cid)
    })
}

/// One upload job.
async fn upload(
    deps: &JobDeps,
    key: &DbKey,
    have: Option<&Frontier>,
    budget_left: Option<u64>,
) -> Result<Uploaded, JobError> {
    let db = DbRef {
        space: &key.0,
        db_id: &key.1,
    };
    let mut head = {
        let _pg = deps.pg.acquire().await;
        deps.source.head(&db).await
    }
    .map_err(source_failure)?
    .ok_or(JobError::Policy(PolicyReason::SourceGone))?;
    if below(have, &head) {
        return Err(JobError::Regressed(head.head()));
    }
    let Some(plan) = plan_publish(have, &head) else {
        // The frontier already covers PG: reload it.
        return Ok(Uploaded {
            outcome: PublishOutcome::Lost(have.cloned()),
            bytes: 0,
            observed: head.head(),
        });
    };
    let bytes = plan_bytes(&plan, &head);
    if budget_left.is_some_and(|left| bytes > left) {
        return Err(JobError::Policy(PolicyReason::DailyBudget));
    }
    if bytes > deps.disk.capacity() {
        return Err(JobError::Policy(PolicyReason::TooLarge));
    }
    let reservation = deps
        .disk
        .try_reserve(bytes)
        .ok_or(JobError::Transient {
            infra: false,
            observed: None,
        })?;
    let _streaming = deps
        .bytes
        .acquire_many(deps.charge(bytes))
        .await
        .expect("the upload byte semaphore is never closed");

    // (record, scratch path) per object, in publish order.
    let mut objects: Vec<(ObjectRecord, tempfile::TempPath)> = Vec::new();
    let (lineage, base_seq, segment) = match plan {
        PublishPlan::Chain {
            lineage,
            snapshot_at,
            segment_to,
        } => {
            let lineage = match (lineage, have) {
                (LineagePick::Same, Some(f)) => f.lineage.clone(),
                _ => Lineage::random(),
            };
            let (path, mut file) = scratch(&reservation).await?;
            let copied = {
                let _pg = deps.pg.acquire().await;
                deps.source.checkpoint_to(&db, &head.cid, &mut file).await
            }
            .map_err(source_failure)?;
            let key = ObjectKey::snapshot(&db, &lineage, snapshot_at, &copied.sha256)
                .map_err(|e| store_failure(e.into()))?;
            objects.push((
                ObjectRecord {
                    key,
                    format: "sqlite-v1".into(),
                    bytes: copied.bytes,
                    created_at: now_timestamp(),
                },
                path,
            ));
            (lineage, snapshot_at, segment_to.is_some())
        }
        PublishPlan::Segment { base_seq, .. } => {
            let Some(f) = have else {
                return Err(JobError::Policy(PolicyReason::Refused));
            };
            (f.lineage.clone(), base_seq, true)
        }
    };
    if segment {
        let mut retries = 0;
        let (path, copied) = loop {
            let (path, mut file) = scratch(&reservation).await?;
            let read = {
                let _pg = deps.pg.acquire().await;
                deps.source.wal_to(&db, &head.head(), &mut file).await
            };
            match read {
                Ok(copied) => break (path, copied),
                Err(SourceError::MovedOn) if retries < WAL_READ_RETRIES => {
                    retries += 1;
                    // Only a WAL that grew on the same checkpoint is retried
                    // here; anything else goes back to the machine.
                    let now = {
                        let _pg = deps.pg.acquire().await;
                        deps.source.head(&db).await
                    }
                    .map_err(source_failure)?
                    .ok_or(JobError::Policy(PolicyReason::SourceGone))?;
                    let fits = objects
                        .first()
                        .map_or(0, |(record, _)| record.bytes)
                        .saturating_add(now.delta_bytes)
                        <= reservation.bytes();
                    if now.cid != head.cid || !now.has_delta || !fits {
                        return Err(JobError::Transient {
                            infra: false,
                            observed: Some(now.head()),
                        });
                    }
                    head = now;
                }
                Err(error) => return Err(source_failure(error)),
            }
        };
        let to_seq = u64::try_from(head.revision).map_err(|_| JobError::Policy(PolicyReason::Refused))?;
        let key = ObjectKey::segment(&db, &lineage, base_seq, base_seq + 1, to_seq, &copied.sha256)
            .map_err(|e| store_failure(e.into()))?;
        objects.push((
            ObjectRecord {
                key,
                format: "wal-cum-v1".into(),
                bytes: copied.bytes,
                created_at: now_timestamp(),
            },
            path,
        ));
    }

    let mut streamed = 0u64;
    for (record, path) in &objects {
        deps.store
            .put_file(&record.key, path, record.bytes)
            .await
            .map_err(store_failure)?;
        streamed += record.bytes;
    }
    let outcome = {
        let _pg = deps.pg.acquire().await;
        deps.manifest
            .publish_chain(
                &db,
                have,
                PublishChain {
                    objects: objects.into_iter().map(|(record, _)| record).collect(),
                    base_checkpoint_cid: head.cid.clone(),
                    publish_id: PublishId::random(),
                    now: now_timestamp(),
                },
            )
            .await
    }
    .map_err(store_failure)?;
    Ok(Uploaded {
        outcome,
        bytes: streamed,
        observed: head.head(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::database_artifacts::{
        ArtifactExpectation, DatabaseArtifactRepository, SeaOrmDatabaseArtifactRepository,
    };
    use crate::sql::store::manifest::DbSqlManifest;
    use crate::sql::store::memory::MemorySqlObjectStore;
    use crate::sql::store::object::sha256;
    use crate::sql::store::policy::SpaceAllowlist;
    use crate::sql::store::shadow::metrics::NoopMetrics;
    use crate::sql::store::shadow::source::tests::{repository, saved, SPACE};
    use crate::sql::store::shadow::source::{Copied, PgArtifactSource};
    use crate::sql::store::shadow::{Notice, ShadowSink};
    use crate::sql::store::ObjectKind;

    struct Rig {
        repo: Arc<SeaOrmDatabaseArtifactRepository>,
        manifest: Arc<DbSqlManifest>,
        store: Arc<MemorySqlObjectStore>,
        board: Arc<NoticeBoard>,
        _scratch: tempfile::TempDir,
    }

    fn fast() -> SchedulerConfig {
        SchedulerConfig {
            policy: Policy {
                interval: Duration::ZERO,
                backoff_base: Duration::from_millis(10),
                backoff_max: Duration::from_millis(50),
            },
            tick: Duration::from_millis(5),
            scan_every: Duration::from_secs(3600),
            scan_page: 2,
            ..SchedulerConfig::default()
        }
    }

    async fn rig(source: Option<Arc<dyn ShadowSource>>) -> (Rig, SchedulerHandle) {
        let (conn, repo) = repository().await;
        let manifest = Arc::new(DbSqlManifest::new(conn.clone()));
        let store = Arc::new(MemorySqlObjectStore::default());
        let board = Arc::new(NoticeBoard::new(
            SpaceAllowlist::new([SPACE.to_string()]),
            Arc::new(NoopMetrics),
        ));
        let scratch = tempfile::tempdir().unwrap();
        // Artifacts saved before the scheduler starts are found by the
        // startup scan, so callers save first and start second.
        let rig = Rig {
            repo: repo.clone(),
            manifest: manifest.clone(),
            store: store.clone(),
            board: board.clone(),
            _scratch: scratch,
        };
        let handle = spawn(
            ShadowDeps {
                control: conn,
                manifest,
                store,
                source: source.unwrap_or_else(|| Arc::new(PgArtifactSource::new(repo))),
                disk: DiskBudget::new(rig._scratch.path(), 1 << 20),
                board,
                metrics: Arc::new(NoopMetrics),
            },
            fast(),
        );
        (rig, handle)
    }

    const MAIN: DbRef<'static> = DbRef {
        space: SPACE,
        db_id: "main",
    };

    async fn wait_for_seq(manifest: &DbSqlManifest, seq: u64) -> Frontier {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(f) = manifest.current(&MAIN).await.unwrap() {
                    if f.last_seq >= seq {
                        return f;
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the frontier reaches the revision")
    }

    fn segment_of(rig: &Rig, f: &Frontier, records: &[ObjectRecord]) -> Vec<u8> {
        let segment = records
            .iter()
            .find(|r| r.key.kind() == ObjectKind::Segment && r.key.to_seq() == f.last_seq)
            .expect("the frontier's segment is recorded");
        assert_eq!(segment.key.base_seq(), f.base_seq);
        assert_eq!(segment.key.from_seq(), f.base_seq + 1);
        rig.store.bytes(segment.key.as_str()).unwrap()
    }

    async fn save_delta(rig: &Rig, wal: &'static [u8], revision: i64, cid: &str) -> i64 {
        rig.repo
            .save_delta(
                "sql",
                SPACE,
                "main",
                bytes::Bytes::from_static(wal),
                ArtifactExpectation::Derived {
                    revision,
                    checkpoint_content_hash: cid.into(),
                },
            )
            .await
            .unwrap()
            .revision
    }

    fn notify(rig: &Rig, revision: i64, cid: &str) {
        rig.board.notify(Notice {
            space: SPACE.into(),
            db_id: "main".into(),
            revision,
            cid: cid.into(),
        });
    }

    #[tokio::test]
    async fn bootstrap_then_segments_then_a_new_checkpoint_converge_to_the_pg_head() {
        let (conn, repo) = repository().await;
        let meta = saved(&repo, "main", b"checkpoint-1", &[b"wal-a", b"wal-ab"]).await;
        assert_eq!(meta.revision, 3);
        // Re-rig on the same database: the startup scan bootstraps it.
        let manifest = Arc::new(DbSqlManifest::new(conn.clone()));
        let store = Arc::new(MemorySqlObjectStore::default());
        let board = Arc::new(NoticeBoard::new(
            SpaceAllowlist::new([SPACE.to_string()]),
            Arc::new(NoopMetrics),
        ));
        let scratch = tempfile::tempdir().unwrap();
        let handle = spawn(
            ShadowDeps {
                control: conn,
                manifest: manifest.clone(),
                store: store.clone(),
                source: Arc::new(PgArtifactSource::new(repo.clone())),
                disk: DiskBudget::new(scratch.path(), 1 << 20),
                board: board.clone(),
                metrics: Arc::new(NoopMetrics),
            },
            fast(),
        );
        let rig = Rig {
            repo,
            manifest,
            store,
            board,
            _scratch: scratch,
        };

        // Bootstrap with a delta: exact checkpoint bytes at at_seq 0, then
        // the cumulative WAL as the segment 1..=3.
        let f = wait_for_seq(&rig.manifest, 3).await;
        assert_eq!((f.base_seq, f.last_seq), (0, 3));
        assert_eq!(f.base_checkpoint_cid, meta.checkpoint_content_hash);
        assert_eq!(
            rig.store.bytes(&f.base_snapshot_key).unwrap(),
            b"checkpoint-1"
        );
        let records = rig.manifest.list_objects(&MAIN, None).await.unwrap();
        assert_eq!(segment_of(&rig, &f, &records), b"wal-ab");

        // A WAL save on the same checkpoint: a segment on the same base.
        let cid = meta.checkpoint_content_hash.clone();
        let revision = save_delta(&rig, b"wal-abc", 3, &cid).await;
        notify(&rig, revision, &cid);
        let f2 = wait_for_seq(&rig.manifest, 4).await;
        assert_eq!((f2.lineage.clone(), f2.base_seq), (f.lineage.clone(), 0));
        let records = rig.manifest.list_objects(&MAIN, None).await.unwrap();
        assert_eq!(segment_of(&rig, &f2, &records), b"wal-abc");

        // A new checkpoint without a WAL: a snapshot at its revision.
        let saved = rig
            .repo
            .save(
                "sql",
                SPACE,
                "main",
                bytes::Bytes::from_static(b"checkpoint-2"),
                ArtifactExpectation::Derived {
                    revision: 4,
                    checkpoint_content_hash: cid,
                },
            )
            .await
            .unwrap();
        notify(&rig, saved.revision, &saved.checkpoint_content_hash);
        let f3 = wait_for_seq(&rig.manifest, 5).await;
        assert_eq!((f3.base_seq, f3.last_seq), (5, 5));
        assert_eq!(f3.lineage, f.lineage, "same lineage");
        assert_eq!(
            rig.store.bytes(&f3.base_snapshot_key).unwrap(),
            b"checkpoint-2"
        );

        let report = handle.drain(Duration::from_secs(5)).await;
        assert_eq!(report.abandoned_jobs, 0);
        assert_eq!(
            report.databases,
            vec![DbDrain {
                space: SPACE.into(),
                db_id: "main".into(),
                last_seq: Some(5),
                target_revision: Some(5),
                phase: "clean",
            }]
        );
        assert!(report.databases[0].caught_up());
    }

    #[tokio::test]
    async fn a_checkpoint_without_a_delta_bootstraps_at_its_revision() {
        let (rig, handle) = rig(None).await;
        // Saved after the startup scan: only the notice brings it in.
        let saved = rig
            .repo
            .save(
                "sql",
                SPACE,
                "main",
                bytes::Bytes::from_static(b"only"),
                ArtifactExpectation::Absent,
            )
            .await
            .unwrap();
        notify(&rig, saved.revision, &saved.checkpoint_content_hash);
        let f = wait_for_seq(&rig.manifest, 1).await;
        assert_eq!((f.base_seq, f.last_seq), (1, 1));
        assert_eq!(rig.store.bytes(&f.base_snapshot_key).unwrap(), b"only");
        assert_eq!(
            f.base_snapshot_key,
            ObjectKey::snapshot(&MAIN, &f.lineage, 1, &sha256(b"only"))
                .unwrap()
                .as_str()
        );
        let report = handle.drain(Duration::from_secs(5)).await;
        assert!(report.databases.iter().all(DbDrain::caught_up));
    }

    /// A source whose checkpoint reads never finish.
    struct Stalled(PgArtifactSource);

    #[async_trait::async_trait]
    impl ShadowSource for Stalled {
        async fn head(&self, db: &DbRef<'_>) -> Result<Option<ArtifactHead>, SourceError> {
            self.0.head(db).await
        }
        async fn checkpoint_to(
            &self,
            _: &DbRef<'_>,
            _: &str,
            _: &mut tokio::fs::File,
        ) -> Result<Copied, SourceError> {
            std::future::pending().await
        }
        async fn wal_to(
            &self,
            db: &DbRef<'_>,
            head: &Head,
            file: &mut tokio::fs::File,
        ) -> Result<Copied, SourceError> {
            self.0.wal_to(db, head, file).await
        }
    }

    #[tokio::test]
    async fn drain_stops_at_its_deadline_and_reports_who_is_behind() {
        let (conn, repo) = repository().await;
        let meta = saved(&repo, "main", b"ck", &[]).await;
        let handle = spawn(
            ShadowDeps {
                control: conn.clone(),
                manifest: Arc::new(DbSqlManifest::new(conn)),
                store: Arc::new(MemorySqlObjectStore::default()),
                source: Arc::new(Stalled(PgArtifactSource::new(repo))),
                disk: DiskBudget::new(std::env::temp_dir(), 1 << 20),
                board: Arc::new(NoticeBoard::new(
                    SpaceAllowlist::new([SPACE.to_string()]),
                    Arc::new(NoopMetrics),
                )),
                metrics: Arc::new(NoopMetrics),
            },
            fast(),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        let report = handle.drain(Duration::from_millis(50)).await;
        assert_eq!(report.abandoned_jobs, 1);
        assert_eq!(
            report.databases,
            vec![DbDrain {
                space: SPACE.into(),
                db_id: "main".into(),
                last_seq: None,
                target_revision: Some(meta.revision),
                phase: "in_flight",
            }]
        );
        assert!(!report.databases[0].caught_up());
    }
}

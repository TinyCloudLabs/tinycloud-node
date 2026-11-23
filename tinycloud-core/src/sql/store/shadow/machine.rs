//! The per-database shadow uploader state machine (TC-1491 P1).
//!
//! One [`DbMachine`] per database, advanced by [`step`]: a pure function of
//! the machine, one [`Event`], the caller's `now` and the [`Policy`]. It
//! performs no I/O and reads no clock. The IO shell (`scheduler.rs`) feeds it
//! hook notices, lag-scan results, ticks and upload completions, and turns
//! the [`Command`]s it returns into upload jobs.
//!
//! Transition table (every cell has a test below, named `cell_<phase>_<event>`):
//!
//! | Phase \ Event | Notified / Scanned(h) | Tick | Published(f) | Lost(c) | Failed(Transient) | Failed(Policy r) | Released | Regressed(h) |
//! |---|---|---|---|---|---|---|---|---|
//! | Clean | merge; classify != None → Dirty{now} | stay | ignore | have=c; recheck | ignore | ignore | stay | Blocked{Regressed} |
//! | Dirty{s} | merge | due(s) && permit: InFlight + Upload | ignore | have=c | ignore | ignore | stay | Blocked{Regressed} |
//! | InFlight{a} | merge (kept for after) | stay | have=f; None ? Clean : Dirty{now} | have=c; Dirty{now} | Backoff{now+exp(a), a} | Blocked{r} | stay | merge; resolved at completion |
//! | Backoff{u,a} | merge | now>=u: Dirty{now}, a carried | ignore | have=c | ignore | ignore | Dirty{now} | Blocked{Regressed} |
//! | Blocked{r} | merge | stay | ignore | have=c | ignore | ignore | None ? Clean : Dirty{now} | stay |
//!
//! `merge` keeps the head with the higher revision. A head with the same
//! revision as the target but another cid is a [`BlockReason::CidConflict`]:
//! the newer-arrived head becomes the target and the database blocks (while
//! in flight, the block is deferred to the completion, like a regression).
//! A `Dirty` tick whose work turned out to be `None` (a `Lost` reload caught
//! the frontier up) goes `Clean` without uploading.
//!
//! [`plan_publish`] is the upload job's pure half: what to publish for a
//! given frontier and artifact head. [`plan_delta`] decides whether a
//! segment can carry only the WAL bytes since the frontier (`wal-delta-v1`)
//! rather than the cumulative WAL (`wal-cum-v1`).

use std::time::{Duration, Instant};

use super::super::manifest::Frontier;
use crate::database_artifacts::WalMark;

/// PG's artifact head as last learned (hook notice or lag scan).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Head {
    pub revision: i64,
    /// `checkpoint_content_hash` of the artifact at `revision`.
    pub cid: String,
}

/// What the frontier is missing relative to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    None,
    /// No frontier: publish the checkpoint and the cumulative WAL.
    Bootstrap,
    /// Same checkpoint, target ahead: a cumulative-WAL segment.
    Segment,
    /// The checkpoint changed: a new snapshot (P3 turns this into a page delta).
    Snapshot,
}

impl Work {
    /// Metric label.
    pub fn label(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Bootstrap => "bootstrap",
            Self::Segment => "segment",
            Self::Snapshot => "snapshot",
        }
    }
}

/// `last_seq` as a revision; a frontier past `i64::MAX` cannot exist (keys
/// refuse it), so saturating is only defensive.
fn seq_as_revision(seq: u64) -> i64 {
    i64::try_from(seq).unwrap_or(i64::MAX)
}

pub fn classify(have: Option<&Frontier>, target: Option<&Head>) -> Work {
    let Some(target) = target else {
        return Work::None;
    };
    match have {
        None => Work::Bootstrap,
        Some(f) if target.revision <= seq_as_revision(f.last_seq) => Work::None,
        Some(f) if f.base_checkpoint_cid == target.cid => Work::Segment,
        Some(_) => Work::Snapshot,
    }
}

/// Why a database stopped uploading until [`Event::Released`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockReason {
    /// Two heads with one revision and different checkpoints.
    CidConflict,
    /// PG's revision went below the published frontier (a PG restore).
    Regressed,
    Policy(PolicyReason),
}

impl BlockReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::CidConflict => "cid_conflict",
            Self::Regressed => "regressed",
            Self::Policy(reason) => reason.label(),
        }
    }
}

/// A refusal that retrying cannot fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyReason {
    /// The object is larger than the scratch-disk budget.
    TooLarge,
    /// The database spent its daily upload budget; released at the UTC day change.
    DailyBudget,
    /// The space or artifact is gone (deleted, purged).
    SourceGone,
    /// The store or manifest refused the request itself (conflicting bytes
    /// under a key, an invalid publish).
    Refused,
}

impl PolicyReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::DailyBudget => "daily_budget",
            Self::SourceGone => "source_gone",
            Self::Refused => "refused",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    Transient,
    Policy(PolicyReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    Clean,
    /// `attempts` carries a backoff's count back into the next upload.
    Dirty {
        since: Instant,
        attempts: u32,
    },
    InFlight {
        attempt: u32,
    },
    Backoff {
        until: Instant,
        attempts: u32,
    },
    Blocked {
        reason: BlockReason,
    },
}

impl Phase {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::Dirty { .. } => "dirty",
            Self::InFlight { .. } => "in_flight",
            Self::Backoff { .. } => "backoff",
            Self::Blocked { .. } => "blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The save hook: metadata only.
    Notified(Head),
    /// The durable lag scan (also fed with the head an upload job observed).
    Scanned(Head),
    /// `permit` is the shell's capacity: breaker closed and upload slots free.
    Tick {
        permit: bool,
    },
    Published(Frontier),
    /// The CAS lost; carries the manifest row as reloaded.
    Lost(Option<Frontier>),
    Failed(Failure),
    /// Operator unblock or daily budget reset.
    Released,
    /// The scan saw PG below the published frontier.
    Regressed(Head),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Start one upload job. Only a `Dirty -> InFlight` tick emits this.
    Upload {
        work: Work,
        target: Head,
        have: Option<Frontier>,
        attempt: u32,
    },
    /// The machine just entered `Blocked`; for logs and metrics.
    Blocked(BlockReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// How long a database stays dirty before its upload is due.
    pub interval: Duration,
    pub backoff_base: Duration,
    pub backoff_max: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            backoff_base: Duration::from_secs(5),
            backoff_max: Duration::from_secs(15 * 60),
        }
    }
}

impl Policy {
    /// `backoff_base * 2^(attempt-1)`, capped at `backoff_max`.
    pub fn backoff(&self, attempt: u32) -> Duration {
        let factor = 1_u32
            .checked_shl(attempt.saturating_sub(1))
            .unwrap_or(u32::MAX);
        self.backoff_base
            .saturating_mul(factor)
            .min(self.backoff_max)
    }

    fn due(&self, since: Instant, now: Instant) -> bool {
        now.saturating_duration_since(since) >= self.interval
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbMachine {
    pub have: Option<Frontier>,
    pub target: Option<Head>,
    pub phase: Phase,
    /// A conflict or regression seen while in flight, applied at completion.
    deferred: Option<BlockReason>,
}

impl DbMachine {
    pub fn new(have: Option<Frontier>) -> Self {
        Self {
            have,
            target: None,
            phase: Phase::Clean,
            deferred: None,
        }
    }

    pub fn work(&self) -> Work {
        classify(self.have.as_ref(), self.target.as_ref())
    }

    pub fn in_flight(&self) -> bool {
        matches!(self.phase, Phase::InFlight { .. })
    }

    pub fn last_seq(&self) -> Option<u64> {
        self.have.as_ref().map(|f| f.last_seq)
    }

    /// Max-merge `head` into the target; true on a same-revision cid conflict,
    /// in which case the newer-arrived head becomes the target.
    fn merge(&mut self, head: Head) -> bool {
        match &self.target {
            Some(t) if head.revision < t.revision => false,
            Some(t) if head.revision == t.revision && head.cid == t.cid => false,
            Some(t) if head.revision == t.revision => {
                self.target = Some(head);
                true
            }
            _ => {
                self.target = Some(head);
                false
            }
        }
    }

    fn block(&mut self, reason: BlockReason, out: &mut Vec<Command>) {
        self.phase = Phase::Blocked { reason };
        self.deferred = None;
        out.push(Command::Blocked(reason));
    }

    /// Clean or Dirty, by what is left to do.
    fn settle(&mut self, now: Instant) {
        self.phase = match self.work() {
            Work::None => Phase::Clean,
            _ => Phase::Dirty {
                since: now,
                attempts: 0,
            },
        };
    }

    /// The end of an in-flight upload: a deferred block wins.
    fn complete(&mut self, next: Phase, out: &mut Vec<Command>) {
        match self.deferred.take() {
            Some(reason) => self.block(reason, out),
            None => self.phase = next,
        }
    }
}

/// Advance `m` by one event. Pure: no I/O, no clock read beyond `now`.
pub fn step(m: &mut DbMachine, event: Event, now: Instant, policy: &Policy) -> Vec<Command> {
    let mut out = Vec::new();
    match (m.phase.clone(), event) {
        // Notified / Scanned: merge everywhere.
        (phase, Event::Notified(head) | Event::Scanned(head)) => {
            let conflict = m.merge(head);
            match phase {
                Phase::Blocked { .. } => {}
                Phase::InFlight { .. } => {
                    if conflict {
                        m.deferred = Some(BlockReason::CidConflict);
                    }
                }
                _ if conflict => m.block(BlockReason::CidConflict, &mut out),
                Phase::Clean => {
                    if m.work() != Work::None {
                        m.phase = Phase::Dirty {
                            since: now,
                            attempts: 0,
                        };
                    }
                }
                Phase::Dirty { .. } | Phase::Backoff { .. } => {}
            }
        }

        // Tick.
        (Phase::Dirty { since, attempts }, Event::Tick { permit }) => {
            if policy.due(since, now) && permit {
                let work = m.work();
                match (work, m.target.clone()) {
                    (Work::None, _) | (_, None) => m.phase = Phase::Clean,
                    (work, Some(target)) => {
                        let attempt = attempts.saturating_add(1);
                        m.phase = Phase::InFlight { attempt };
                        out.push(Command::Upload {
                            work,
                            target,
                            have: m.have.clone(),
                            attempt,
                        });
                    }
                }
            }
        }
        (Phase::Backoff { until, attempts }, Event::Tick { .. }) => {
            if now >= until {
                m.phase = Phase::Dirty {
                    since: now,
                    attempts,
                };
            }
        }
        (Phase::Clean | Phase::InFlight { .. } | Phase::Blocked { .. }, Event::Tick { .. }) => {}

        // Published: only an in-flight upload's completion counts.
        (Phase::InFlight { .. }, Event::Published(frontier)) => {
            m.have = Some(frontier);
            let next = match m.work() {
                Work::None => Phase::Clean,
                _ => Phase::Dirty {
                    since: now,
                    attempts: 0,
                },
            };
            m.complete(next, &mut out);
        }
        (_, Event::Published(_)) => {}

        // Lost: always reload.
        (Phase::Clean, Event::Lost(current)) => {
            m.have = current;
            m.settle(now);
        }
        (Phase::InFlight { .. }, Event::Lost(current)) => {
            m.have = current;
            m.complete(
                Phase::Dirty {
                    since: now,
                    attempts: 0,
                },
                &mut out,
            );
        }
        (_, Event::Lost(current)) => m.have = current,

        // Failed: only an in-flight upload's completion counts.
        (Phase::InFlight { attempt }, Event::Failed(Failure::Transient)) => {
            m.complete(
                Phase::Backoff {
                    until: now + policy.backoff(attempt),
                    attempts: attempt,
                },
                &mut out,
            );
        }
        (Phase::InFlight { .. }, Event::Failed(Failure::Policy(reason))) => {
            m.block(BlockReason::Policy(reason), &mut out);
        }
        (_, Event::Failed(_)) => {}

        // Released.
        (Phase::Backoff { .. }, Event::Released) => {
            m.phase = Phase::Dirty {
                since: now,
                attempts: 0,
            };
        }
        (Phase::Blocked { .. }, Event::Released) => m.settle(now),
        (Phase::Clean | Phase::Dirty { .. } | Phase::InFlight { .. }, Event::Released) => {}

        // Regressed.
        (Phase::InFlight { .. }, Event::Regressed(head)) => {
            m.merge(head);
            m.deferred = Some(BlockReason::Regressed);
        }
        (Phase::Blocked { .. }, Event::Regressed(_)) => {}
        (Phase::Clean | Phase::Dirty { .. } | Phase::Backoff { .. }, Event::Regressed(_)) => {
            m.block(BlockReason::Regressed, &mut out);
        }
    }
    out
}

/// What an artifact looks like to the upload job (from `ShadowSource::head`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactHead {
    pub revision: i64,
    pub cid: String,
    /// The row carries a cumulative WAL next to its checkpoint.
    pub has_delta: bool,
    pub checkpoint_bytes: u64,
    pub delta_bytes: u64,
}

impl ArtifactHead {
    pub fn head(&self) -> Head {
        Head {
            revision: self.revision,
            cid: self.cid.clone(),
        }
    }

    /// Bytes an upload of this head may stream.
    pub fn total_bytes(&self) -> u64 {
        self.checkpoint_bytes.saturating_add(self.delta_bytes)
    }
}

/// Which lineage a chain's snapshot goes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineagePick {
    /// No frontier yet: first publish in a fresh lineage.
    First,
    /// A new chain in the frontier's lineage.
    Same,
    /// A new lineage on top of the frontier's.
    Switch,
}

/// What one upload publishes, atomically (one control-DB transaction).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishPlan {
    /// The artifact's exact checkpoint bytes as a snapshot labelled
    /// `snapshot_at`, then, when the row carries a WAL, the cumulative WAL as
    /// the segment `snapshot_at + 1 ..= to_seq`.
    ///
    /// PG does not record the revision a checkpoint was saved at. Without a
    /// WAL it is the artifact's revision; with one it is unknown, so the
    /// snapshot starts a lineage labelled `at_seq = 0` and the segment covers
    /// `1 ..= revision`. A restore is only defined at the published frontier.
    Chain {
        lineage: LineagePick,
        snapshot_at: u64,
        segment_to: Option<u64>,
    },
    /// Append the cumulative WAL to the frontier's chain.
    Segment { base_seq: u64, to_seq: u64 },
}

/// The upload job's decision for `head` on top of `have`; `None` when the
/// frontier already covers it (or the head is not a valid revision).
pub fn plan_publish(have: Option<&Frontier>, head: &ArtifactHead) -> Option<PublishPlan> {
    let revision = u64::try_from(head.revision).ok().filter(|r| *r >= 1)?;
    let chain = |lineage: LineagePick| {
        if head.has_delta {
            PublishPlan::Chain {
                lineage: if lineage == LineagePick::Same {
                    LineagePick::Switch
                } else {
                    lineage
                },
                snapshot_at: 0,
                segment_to: Some(revision),
            }
        } else {
            PublishPlan::Chain {
                lineage,
                snapshot_at: revision,
                segment_to: None,
            }
        }
    };
    match have {
        None => Some(chain(LineagePick::First)),
        Some(f) if revision <= f.last_seq => None,
        Some(f) if f.base_checkpoint_cid == head.cid && head.has_delta => {
            Some(PublishPlan::Segment {
                base_seq: f.base_seq,
                to_seq: revision,
            })
        }
        // A new checkpoint, or the same checkpoint bytes saved again without
        // a WAL: either way the checkpoint alone is the state at `revision`.
        Some(_) => Some(chain(LineagePick::Same)),
    }
}

/// A cumulative WAL smaller than this is uploaded whole: one object restores
/// faster than a chain of small ones and costs no more requests. Deltas pay
/// once the WAL they avoid re-uploading is larger than this.
pub const DELTA_MIN_WAL_BYTES: u64 = 64 * 1024;

/// A restore reads at most this many segments: every `MAX_DELTA_CHAIN`-th
/// publish (counted by the manifest's publication counter) is a cumulative
/// segment, which supersedes the deltas before it.
pub const MAX_DELTA_CHAIN: i64 = 64;

/// A delta: the stored WAL between two marks of the frontier's checkpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaPlan {
    /// The revisions the object covers: `from_seq = last_seq + 1`.
    pub from_seq: u64,
    pub to_seq: u64,
    /// The mark of the frontier's revision: the delta starts at its
    /// `wal_end_bytes`.
    pub start: WalMark,
    /// The mark of the head: the delta ends at its `wal_end_bytes`.
    pub end: WalMark,
}

/// Whether the `Segment` that [`plan_publish`] chose can be a delta, given
/// the artifact's `marks` (any order, any extras; the uploader loads the
/// frontier's and the head's). `None` means a cumulative segment: always a
/// correct publish, and the one that heals a gap.
///
/// A delta needs both marks on the frontier's checkpoint, the WAL growing
/// from one to the other and ending where the head's WAL ends. A frontier
/// still at its snapshot (`last_seq = base_seq`) has no segment yet and the
/// cumulative WAL is the delta from byte 0, so it is a cumulative segment. A
/// missing, regressed or other-checkpoint mark, a WAL that did not grow, a
/// cumulative WAL under `min_wal_bytes` and a chain at its [`MAX_DELTA_CHAIN`]
/// bound all give `None` too.
pub fn plan_delta(
    have: &Frontier,
    head: &ArtifactHead,
    marks: &[WalMark],
    min_wal_bytes: u64,
) -> Option<DeltaPlan> {
    let to_seq = u64::try_from(head.revision).ok()?;
    if !head.has_delta
        || head.cid != have.base_checkpoint_cid
        || to_seq <= have.last_seq
        || have.last_seq <= have.base_seq
        || (have.revision + 1) % MAX_DELTA_CHAIN == 0
    {
        return None;
    }
    let mark = |seq: u64| {
        marks
            .iter()
            .find(|m| u64::try_from(m.revision) == Ok(seq) && m.checkpoint_content_hash == head.cid)
    };
    let (start, end) = (mark(have.last_seq)?, mark(to_seq)?);
    if start.wal_end_bytes >= end.wal_end_bytes
        || end.wal_end_bytes != head.delta_bytes
        || end.wal_end_bytes < min_wal_bytes
    {
        return None;
    }
    Some(DeltaPlan {
        from_seq: have.last_seq + 1,
        to_seq,
        start: start.clone(),
        end: end.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::store::key::Lineage;

    const S: Duration = Duration::from_secs(1);

    fn policy() -> Policy {
        Policy {
            interval: 10 * S,
            backoff_base: 2 * S,
            backoff_max: 60 * S,
        }
    }

    fn head(revision: i64, cid: &str) -> Head {
        Head {
            revision,
            cid: cid.into(),
        }
    }

    fn frontier(last_seq: u64, cid: &str) -> Frontier {
        Frontier {
            lineage: Lineage::parse(&"ab".repeat(16)).unwrap(),
            epoch: 0,
            revision: last_seq as i64,
            base_snapshot_key: "sql/v1/s/d/l/snap/0".into(),
            base_seq: 0,
            base_checkpoint_cid: cid.into(),
            last_seq,
            publish_id: "00".repeat(16),
            published_at: "2026-11-22T00:00:00.000000Z".into(),
            frontier_bytes: 1,
        }
    }

    struct Case {
        m: DbMachine,
        t0: Instant,
    }

    impl Case {
        /// A machine with frontier `(5, a)` in `phase`, target `(7, a)`.
        fn new(phase: Phase) -> Self {
            let mut m = DbMachine::new(Some(frontier(5, "a")));
            m.target = Some(head(7, "a"));
            m.phase = phase;
            Self {
                m,
                t0: Instant::now(),
            }
        }
        fn clean_idle() -> Self {
            let mut c = Self::new(Phase::Clean);
            c.m.target = Some(head(5, "a"));
            c
        }
        fn at(&self, secs: u64) -> Instant {
            self.t0 + S * secs as u32
        }
        fn step(&mut self, event: Event, secs: u64) -> Vec<Command> {
            let now = self.at(secs);
            step(&mut self.m, event, now, &policy())
        }
    }

    fn dirty(c: &Case) -> Phase {
        Phase::Dirty {
            since: c.t0,
            attempts: 0,
        }
    }

    fn blocked(reason: BlockReason) -> Phase {
        Phase::Blocked { reason }
    }

    // ---- classify / merge / policy --------------------------------------

    #[test]
    fn classify_covers_every_work_kind() {
        assert_eq!(classify(None, None), Work::None);
        assert_eq!(classify(Some(&frontier(5, "a")), None), Work::None);
        assert_eq!(classify(None, Some(&head(3, "a"))), Work::Bootstrap);
        assert_eq!(
            classify(Some(&frontier(5, "a")), Some(&head(5, "a"))),
            Work::None
        );
        assert_eq!(
            classify(Some(&frontier(5, "a")), Some(&head(4, "b"))),
            Work::None
        );
        assert_eq!(
            classify(Some(&frontier(5, "a")), Some(&head(6, "a"))),
            Work::Segment
        );
        assert_eq!(
            classify(Some(&frontier(5, "a")), Some(&head(6, "b"))),
            Work::Snapshot
        );
    }

    #[test]
    fn merge_keeps_the_higher_revision_and_flags_cid_conflicts() {
        let mut m = DbMachine::new(None);
        assert!(!m.merge(head(3, "a")));
        assert!(!m.merge(head(2, "z")));
        assert_eq!(m.target, Some(head(3, "a")));
        assert!(!m.merge(head(3, "a")));
        assert!(!m.merge(head(4, "b")));
        assert_eq!(m.target, Some(head(4, "b")));
        assert!(m.merge(head(4, "c")));
        assert_eq!(m.target, Some(head(4, "c")));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let p = policy();
        assert_eq!(p.backoff(1), 2 * S);
        assert_eq!(p.backoff(2), 4 * S);
        assert_eq!(p.backoff(5), 32 * S);
        assert_eq!(p.backoff(6), 60 * S);
        assert_eq!(p.backoff(400), 60 * S);
        assert_eq!(p.backoff(0), 2 * S);
    }

    // ---- Clean -----------------------------------------------------------

    #[test]
    fn cell_clean_notified_scanned() {
        // Nothing new: stays clean.
        let mut c = Case::clean_idle();
        assert!(c.step(Event::Notified(head(5, "a")), 0).is_empty());
        assert_eq!(c.m.phase, Phase::Clean);
        assert!(c.step(Event::Scanned(head(4, "a")), 0).is_empty());
        assert_eq!(c.m.phase, Phase::Clean);
        // Ahead: dirty since now, by either source.
        assert!(c.step(Event::Notified(head(6, "a")), 3).is_empty());
        assert_eq!(
            c.m.phase,
            Phase::Dirty {
                since: c.at(3),
                attempts: 0
            }
        );
        let mut c = Case::clean_idle();
        c.step(Event::Scanned(head(9, "b")), 4);
        assert_eq!(
            c.m.phase,
            Phase::Dirty {
                since: c.at(4),
                attempts: 0
            }
        );
        assert_eq!(c.m.target, Some(head(9, "b")));
        // A same-revision cid conflict blocks.
        let mut c = Case::clean_idle();
        let out = c.step(Event::Notified(head(5, "x")), 0);
        assert_eq!(out, vec![Command::Blocked(BlockReason::CidConflict)]);
        assert_eq!(c.m.phase, blocked(BlockReason::CidConflict));
    }

    #[test]
    fn cell_clean_tick() {
        let mut c = Case::clean_idle();
        assert!(c.step(Event::Tick { permit: true }, 100).is_empty());
        assert_eq!(c.m.phase, Phase::Clean);
    }

    #[test]
    fn cell_clean_published() {
        let mut c = Case::clean_idle();
        assert!(c.step(Event::Published(frontier(9, "a")), 0).is_empty());
        assert_eq!(c.m.have, Some(frontier(5, "a")), "a stale completion");
        assert_eq!(c.m.phase, Phase::Clean);
    }

    #[test]
    fn cell_clean_lost() {
        // The reload shows the frontier behind the target: recheck -> dirty.
        let mut c = Case::clean_idle();
        c.step(Event::Lost(Some(frontier(3, "a"))), 2);
        assert_eq!(c.m.have, Some(frontier(3, "a")));
        assert_eq!(
            c.m.phase,
            Phase::Dirty {
                since: c.at(2),
                attempts: 0
            }
        );
        // The reload covers the target: stays clean.
        let mut c = Case::clean_idle();
        c.step(Event::Lost(Some(frontier(8, "a"))), 2);
        assert_eq!(c.m.phase, Phase::Clean);
    }

    #[test]
    fn cell_clean_failed_transient() {
        let mut c = Case::clean_idle();
        assert!(c.step(Event::Failed(Failure::Transient), 0).is_empty());
        assert_eq!(c.m.phase, Phase::Clean);
    }

    #[test]
    fn cell_clean_failed_policy() {
        let mut c = Case::clean_idle();
        let out = c.step(Event::Failed(Failure::Policy(PolicyReason::TooLarge)), 0);
        assert!(out.is_empty());
        assert_eq!(c.m.phase, Phase::Clean);
    }

    #[test]
    fn cell_clean_released() {
        let mut c = Case::clean_idle();
        assert!(c.step(Event::Released, 0).is_empty());
        assert_eq!(c.m.phase, Phase::Clean);
    }

    #[test]
    fn cell_clean_regressed() {
        let mut c = Case::clean_idle();
        let out = c.step(Event::Regressed(head(2, "a")), 0);
        assert_eq!(out, vec![Command::Blocked(BlockReason::Regressed)]);
        assert_eq!(c.m.phase, blocked(BlockReason::Regressed));
    }

    // ---- Dirty -----------------------------------------------------------

    #[test]
    fn cell_dirty_notified_scanned() {
        let mut c = Case::new(Phase::Clean);
        c.m.phase = dirty(&c);
        c.step(Event::Notified(head(8, "a")), 5);
        c.step(Event::Scanned(head(6, "a")), 6);
        assert_eq!(c.m.target, Some(head(8, "a")));
        assert_eq!(c.m.phase, dirty(&c), "since is the first dirty time");
        let out = c.step(Event::Scanned(head(8, "q")), 6);
        assert_eq!(out, vec![Command::Blocked(BlockReason::CidConflict)]);
    }

    #[test]
    fn cell_dirty_tick() {
        let mut c = Case::new(Phase::Clean);
        c.m.phase = dirty(&c);
        // Not due yet.
        assert!(c.step(Event::Tick { permit: true }, 9).is_empty());
        assert_eq!(c.m.phase, dirty(&c));
        // Due, but no permit.
        assert!(c.step(Event::Tick { permit: false }, 10).is_empty());
        assert_eq!(c.m.phase, dirty(&c));
        // Due and permitted: one upload.
        let out = c.step(Event::Tick { permit: true }, 10);
        assert_eq!(
            out,
            vec![Command::Upload {
                work: Work::Segment,
                target: head(7, "a"),
                have: Some(frontier(5, "a")),
                attempt: 1,
            }]
        );
        assert_eq!(c.m.phase, Phase::InFlight { attempt: 1 });
        // Attempts carried from a backoff continue the count.
        let mut c = Case::new(Phase::Clean);
        c.m.phase = Phase::Dirty {
            since: c.t0,
            attempts: 3,
        };
        let out = c.step(Event::Tick { permit: true }, 10);
        assert!(matches!(out[..], [Command::Upload { attempt: 4, .. }]));
        // Nothing left to do (a reload caught up): clean, no upload.
        let mut c = Case::new(Phase::Clean);
        c.m.phase = dirty(&c);
        c.m.have = Some(frontier(7, "a"));
        assert!(c.step(Event::Tick { permit: true }, 10).is_empty());
        assert_eq!(c.m.phase, Phase::Clean);
    }

    #[test]
    fn cell_dirty_published() {
        let mut c = Case::new(Phase::Clean);
        c.m.phase = dirty(&c);
        c.step(Event::Published(frontier(7, "a")), 1);
        assert_eq!(c.m.have, Some(frontier(5, "a")));
        assert_eq!(c.m.phase, dirty(&c));
    }

    #[test]
    fn cell_dirty_lost() {
        let mut c = Case::new(Phase::Clean);
        c.m.phase = dirty(&c);
        c.step(Event::Lost(Some(frontier(6, "a"))), 1);
        assert_eq!(c.m.have, Some(frontier(6, "a")));
        assert_eq!(c.m.phase, dirty(&c));
    }

    #[test]
    fn cell_dirty_failed_transient() {
        let mut c = Case::new(Phase::Clean);
        c.m.phase = dirty(&c);
        assert!(c.step(Event::Failed(Failure::Transient), 1).is_empty());
        assert_eq!(c.m.phase, dirty(&c));
    }

    #[test]
    fn cell_dirty_failed_policy() {
        let mut c = Case::new(Phase::Clean);
        c.m.phase = dirty(&c);
        c.step(Event::Failed(Failure::Policy(PolicyReason::Refused)), 1);
        assert_eq!(c.m.phase, dirty(&c));
    }

    #[test]
    fn cell_dirty_released() {
        let mut c = Case::new(Phase::Clean);
        c.m.phase = dirty(&c);
        c.step(Event::Released, 1);
        assert_eq!(c.m.phase, dirty(&c));
    }

    #[test]
    fn cell_dirty_regressed() {
        let mut c = Case::new(Phase::Clean);
        c.m.phase = dirty(&c);
        let out = c.step(Event::Regressed(head(1, "a")), 1);
        assert_eq!(out, vec![Command::Blocked(BlockReason::Regressed)]);
        assert_eq!(c.m.phase, blocked(BlockReason::Regressed));
    }

    // ---- InFlight --------------------------------------------------------

    fn in_flight(attempt: u32) -> Case {
        Case::new(Phase::InFlight { attempt })
    }

    #[test]
    fn cell_inflight_notified_scanned() {
        let mut c = in_flight(1);
        assert!(c.step(Event::Notified(head(9, "a")), 1).is_empty());
        assert!(c.step(Event::Scanned(head(8, "a")), 1).is_empty());
        assert_eq!(c.m.target, Some(head(9, "a")), "kept for after");
        assert_eq!(c.m.phase, Phase::InFlight { attempt: 1 });
        // A conflict waits for the completion.
        assert!(c.step(Event::Notified(head(9, "z")), 1).is_empty());
        assert_eq!(c.m.phase, Phase::InFlight { attempt: 1 });
        let out = c.step(Event::Published(frontier(7, "a")), 2);
        assert_eq!(out, vec![Command::Blocked(BlockReason::CidConflict)]);
        assert_eq!(c.m.have, Some(frontier(7, "a")));
        assert_eq!(c.m.phase, blocked(BlockReason::CidConflict));
    }

    #[test]
    fn cell_inflight_tick() {
        let mut c = in_flight(2);
        assert!(c.step(Event::Tick { permit: true }, 1000).is_empty());
        assert_eq!(c.m.phase, Phase::InFlight { attempt: 2 });
    }

    #[test]
    fn cell_inflight_published() {
        // Caught up: clean.
        let mut c = in_flight(1);
        c.step(Event::Published(frontier(7, "a")), 4);
        assert_eq!(c.m.have, Some(frontier(7, "a")));
        assert_eq!(c.m.phase, Phase::Clean);
        // The target moved on meanwhile: dirty since now.
        let mut c = in_flight(1);
        c.step(Event::Notified(head(9, "a")), 1);
        c.step(Event::Published(frontier(7, "a")), 4);
        assert_eq!(
            c.m.phase,
            Phase::Dirty {
                since: c.at(4),
                attempts: 0
            }
        );
    }

    #[test]
    fn cell_inflight_lost() {
        let mut c = in_flight(3);
        c.step(Event::Lost(Some(frontier(6, "a"))), 4);
        assert_eq!(c.m.have, Some(frontier(6, "a")));
        assert_eq!(
            c.m.phase,
            Phase::Dirty {
                since: c.at(4),
                attempts: 0
            },
            "no backoff"
        );
    }

    #[test]
    fn cell_inflight_failed_transient() {
        let mut c = in_flight(3);
        c.step(Event::Failed(Failure::Transient), 4);
        assert_eq!(
            c.m.phase,
            Phase::Backoff {
                until: c.at(4) + policy().backoff(3),
                attempts: 3
            }
        );
    }

    #[test]
    fn cell_inflight_failed_policy() {
        let mut c = in_flight(1);
        let out = c.step(Event::Failed(Failure::Policy(PolicyReason::DailyBudget)), 4);
        let reason = BlockReason::Policy(PolicyReason::DailyBudget);
        assert_eq!(out, vec![Command::Blocked(reason)]);
        assert_eq!(c.m.phase, blocked(reason));
    }

    #[test]
    fn cell_inflight_released() {
        let mut c = in_flight(1);
        c.step(Event::Released, 4);
        assert_eq!(c.m.phase, Phase::InFlight { attempt: 1 });
    }

    #[test]
    fn cell_inflight_regressed() {
        let mut c = in_flight(1);
        assert!(c.step(Event::Regressed(head(2, "a")), 4).is_empty());
        assert_eq!(c.m.phase, Phase::InFlight { attempt: 1 });
        assert_eq!(c.m.target, Some(head(7, "a")), "merge keeps the max");
        // Resolved at the completion, whichever it is.
        let out = c.step(Event::Failed(Failure::Transient), 5);
        assert_eq!(out, vec![Command::Blocked(BlockReason::Regressed)]);
        assert_eq!(c.m.phase, blocked(BlockReason::Regressed));
        let mut c = in_flight(1);
        c.step(Event::Regressed(head(2, "a")), 4);
        c.step(Event::Lost(Some(frontier(6, "a"))), 5);
        assert_eq!(c.m.phase, blocked(BlockReason::Regressed));
    }

    // ---- Backoff ---------------------------------------------------------

    fn backoff() -> Case {
        let mut c = Case::new(Phase::Clean);
        c.m.phase = Phase::Backoff {
            until: c.at(8),
            attempts: 2,
        };
        c
    }

    #[test]
    fn cell_backoff_notified_scanned() {
        let mut c = backoff();
        let before = c.m.phase.clone();
        c.step(Event::Notified(head(9, "a")), 1);
        c.step(Event::Scanned(head(10, "b")), 1);
        assert_eq!(c.m.target, Some(head(10, "b")));
        assert_eq!(c.m.phase, before);
        let out = c.step(Event::Scanned(head(10, "c")), 1);
        assert_eq!(out, vec![Command::Blocked(BlockReason::CidConflict)]);
    }

    #[test]
    fn cell_backoff_tick() {
        let mut c = backoff();
        let before = c.m.phase.clone();
        c.step(Event::Tick { permit: true }, 7);
        assert_eq!(c.m.phase, before);
        assert!(c.step(Event::Tick { permit: false }, 8).is_empty());
        assert_eq!(
            c.m.phase,
            Phase::Dirty {
                since: c.at(8),
                attempts: 2
            },
            "attempts carried"
        );
    }

    #[test]
    fn cell_backoff_published() {
        let mut c = backoff();
        let before = c.m.clone();
        c.step(Event::Published(frontier(7, "a")), 1);
        assert_eq!(c.m, before);
    }

    #[test]
    fn cell_backoff_lost() {
        let mut c = backoff();
        let before = c.m.phase.clone();
        c.step(Event::Lost(Some(frontier(6, "a"))), 1);
        assert_eq!(c.m.have, Some(frontier(6, "a")));
        assert_eq!(c.m.phase, before);
    }

    #[test]
    fn cell_backoff_failed_transient() {
        let mut c = backoff();
        let before = c.m.clone();
        c.step(Event::Failed(Failure::Transient), 1);
        assert_eq!(c.m, before);
    }

    #[test]
    fn cell_backoff_failed_policy() {
        let mut c = backoff();
        let before = c.m.clone();
        c.step(Event::Failed(Failure::Policy(PolicyReason::TooLarge)), 1);
        assert_eq!(c.m, before);
    }

    #[test]
    fn cell_backoff_released() {
        let mut c = backoff();
        c.step(Event::Released, 1);
        assert_eq!(
            c.m.phase,
            Phase::Dirty {
                since: c.at(1),
                attempts: 0
            }
        );
    }

    #[test]
    fn cell_backoff_regressed() {
        let mut c = backoff();
        let out = c.step(Event::Regressed(head(1, "a")), 1);
        assert_eq!(out, vec![Command::Blocked(BlockReason::Regressed)]);
        assert_eq!(c.m.phase, blocked(BlockReason::Regressed));
    }

    // ---- Blocked ---------------------------------------------------------

    fn blocked_case() -> Case {
        Case::new(blocked(BlockReason::Regressed))
    }

    #[test]
    fn cell_blocked_notified_scanned() {
        let mut c = blocked_case();
        assert!(c.step(Event::Notified(head(9, "a")), 1).is_empty());
        assert!(c.step(Event::Scanned(head(9, "z")), 1).is_empty());
        assert_eq!(c.m.target, Some(head(9, "z")));
        assert_eq!(c.m.phase, blocked(BlockReason::Regressed));
    }

    #[test]
    fn cell_blocked_tick() {
        let mut c = blocked_case();
        assert!(c.step(Event::Tick { permit: true }, 1000).is_empty());
        assert_eq!(c.m.phase, blocked(BlockReason::Regressed));
    }

    #[test]
    fn cell_blocked_published() {
        let mut c = blocked_case();
        let before = c.m.clone();
        c.step(Event::Published(frontier(7, "a")), 1);
        assert_eq!(c.m, before);
    }

    #[test]
    fn cell_blocked_lost() {
        let mut c = blocked_case();
        c.step(Event::Lost(Some(frontier(6, "a"))), 1);
        assert_eq!(c.m.have, Some(frontier(6, "a")));
        assert_eq!(c.m.phase, blocked(BlockReason::Regressed));
    }

    #[test]
    fn cell_blocked_failed_transient() {
        let mut c = blocked_case();
        let before = c.m.clone();
        c.step(Event::Failed(Failure::Transient), 1);
        assert_eq!(c.m, before);
    }

    #[test]
    fn cell_blocked_failed_policy() {
        let mut c = blocked_case();
        let before = c.m.clone();
        c.step(Event::Failed(Failure::Policy(PolicyReason::SourceGone)), 1);
        assert_eq!(c.m, before);
    }

    #[test]
    fn cell_blocked_released() {
        // Work left: dirty since now.
        let mut c = blocked_case();
        c.step(Event::Released, 3);
        assert_eq!(
            c.m.phase,
            Phase::Dirty {
                since: c.at(3),
                attempts: 0
            }
        );
        // Nothing left: clean.
        let mut c = blocked_case();
        c.m.target = Some(head(5, "a"));
        c.step(Event::Released, 3);
        assert_eq!(c.m.phase, Phase::Clean);
    }

    #[test]
    fn cell_blocked_regressed() {
        let mut c = blocked_case();
        c.m.phase = blocked(BlockReason::CidConflict);
        assert!(c.step(Event::Regressed(head(1, "a")), 1).is_empty());
        assert_eq!(c.m.phase, blocked(BlockReason::CidConflict));
    }

    // ---- plan_publish ----------------------------------------------------

    fn artifact(revision: i64, cid: &str, has_delta: bool) -> ArtifactHead {
        ArtifactHead {
            revision,
            cid: cid.into(),
            has_delta,
            checkpoint_bytes: 10,
            delta_bytes: if has_delta { 3 } else { 0 },
        }
    }

    #[test]
    fn bootstrap_without_a_wal_labels_the_snapshot_at_the_revision() {
        assert_eq!(
            plan_publish(None, &artifact(4, "a", false)),
            Some(PublishPlan::Chain {
                lineage: LineagePick::First,
                snapshot_at: 4,
                segment_to: None
            })
        );
    }

    #[test]
    fn bootstrap_with_a_wal_labels_the_snapshot_zero_and_covers_one_to_revision() {
        assert_eq!(
            plan_publish(None, &artifact(9, "a", true)),
            Some(PublishPlan::Chain {
                lineage: LineagePick::First,
                snapshot_at: 0,
                segment_to: Some(9)
            })
        );
    }

    #[test]
    fn same_checkpoint_with_a_wal_appends_a_cumulative_segment() {
        let mut f = frontier(5, "a");
        f.base_seq = 2;
        assert_eq!(
            plan_publish(Some(&f), &artifact(8, "a", true)),
            Some(PublishPlan::Segment {
                base_seq: 2,
                to_seq: 8
            })
        );
    }

    #[test]
    fn new_checkpoint_without_a_wal_is_a_snapshot_at_the_revision_in_the_lineage() {
        let f = frontier(5, "a");
        let expected = Some(PublishPlan::Chain {
            lineage: LineagePick::Same,
            snapshot_at: 8,
            segment_to: None,
        });
        assert_eq!(plan_publish(Some(&f), &artifact(8, "b", false)), expected);
        // The same checkpoint bytes saved again without a WAL, too.
        assert_eq!(plan_publish(Some(&f), &artifact(8, "a", false)), expected);
    }

    #[test]
    fn new_checkpoint_with_a_wal_switches_lineage_at_zero() {
        assert_eq!(
            plan_publish(Some(&frontier(5, "a")), &artifact(8, "b", true)),
            Some(PublishPlan::Chain {
                lineage: LineagePick::Switch,
                snapshot_at: 0,
                segment_to: Some(8)
            })
        );
    }

    #[test]
    fn covered_or_invalid_heads_plan_nothing() {
        let f = frontier(5, "a");
        assert_eq!(plan_publish(Some(&f), &artifact(5, "a", true)), None);
        assert_eq!(plan_publish(Some(&f), &artifact(3, "b", false)), None);
        assert_eq!(plan_publish(None, &artifact(0, "a", false)), None);
        assert_eq!(plan_publish(None, &artifact(-1, "a", false)), None);
    }

    // ---- convergence -----------------------------------------------------

    mod convergence {
        use super::*;
        use proptest::prelude::*;
        use std::collections::VecDeque;

        /// One PG save: its head and whether the row then carries a WAL.
        #[derive(Debug, Clone)]
        struct Save {
            artifact: ArtifactHead,
        }

        /// Monotonic revisions; the cid changes on `checkpoint == true`.
        fn saves(checkpoints: &[bool]) -> Vec<Save> {
            let mut out = Vec::new();
            let mut cid = 0u32;
            for (i, checkpoint) in checkpoints.iter().enumerate() {
                if *checkpoint || i == 0 {
                    cid += 1;
                }
                out.push(Save {
                    artifact: ArtifactHead {
                        revision: i as i64 + 1,
                        cid: format!("cid-{cid}"),
                        has_delta: !(*checkpoint || i == 0),
                        checkpoint_bytes: 10,
                        delta_bytes: 1,
                    },
                });
            }
            out
        }

        /// The model manifest: a CAS on `revision`, applying `plan_publish`.
        #[derive(Debug, Default)]
        struct Manifest {
            row: Option<Frontier>,
        }

        impl Manifest {
            fn apply(&mut self, plan: PublishPlan, artifact: &ArtifactHead) -> Frontier {
                let prev = self.row.clone();
                let revision = prev.as_ref().map_or(0, |f| f.revision + 1);
                let mut next = match (plan, prev) {
                    (
                        PublishPlan::Chain {
                            lineage,
                            snapshot_at,
                            segment_to,
                        },
                        prev,
                    ) => {
                        let lineage_id = match (lineage, prev) {
                            (LineagePick::Same, Some(p)) => p.lineage,
                            _ => Lineage::random(),
                        };
                        Frontier {
                            lineage: lineage_id,
                            epoch: 0,
                            revision,
                            base_snapshot_key: format!("snap-{snapshot_at}-{}", artifact.cid),
                            base_seq: snapshot_at,
                            base_checkpoint_cid: artifact.cid.clone(),
                            last_seq: segment_to.unwrap_or(snapshot_at),
                            publish_id: "00".repeat(16),
                            published_at: String::new(),
                            frontier_bytes: 0,
                        }
                    }
                    (PublishPlan::Segment { base_seq, to_seq }, Some(p)) => {
                        assert_eq!(p.base_seq, base_seq);
                        assert_eq!(p.base_checkpoint_cid, artifact.cid);
                        Frontier {
                            revision,
                            last_seq: to_seq,
                            ..p
                        }
                    }
                    (PublishPlan::Segment { .. }, None) => panic!("segment without a base"),
                };
                next.revision = revision;
                if let Some(p) = &self.row {
                    assert!(next.last_seq > p.last_seq, "a publish must advance");
                }
                self.row = Some(next.clone());
                next
            }
        }

        #[derive(Debug, Clone, Copy)]
        enum Delivery {
            Drop,
            Once,
            Twice,
        }

        /// One in-flight upload of the model shell.
        struct Job {
            have: Option<Frontier>,
            completes_at: u64,
        }

        #[derive(Debug, Clone)]
        struct Script {
            checkpoints: Vec<bool>,
            deliveries: Vec<(Delivery, u8)>,
            /// Per tick of the active phase: (new save?, transient failure?, CAS loss kind).
            noise: Vec<(bool, bool, u8, u8)>,
            scan_every: u64,
        }

        fn script() -> impl Strategy<Value = Script> {
            (1usize..24)
                .prop_flat_map(|n| {
                    (
                        proptest::collection::vec(proptest::bool::weighted(0.25), n),
                        proptest::collection::vec(
                            (
                                prop_oneof![
                                    Just(Delivery::Drop),
                                    Just(Delivery::Once),
                                    Just(Delivery::Twice)
                                ],
                                0u8..6,
                            ),
                            n,
                        ),
                        proptest::collection::vec(
                            (
                                proptest::bool::weighted(0.4),
                                proptest::bool::weighted(0.15),
                                0u8..10,
                                0u8..4,
                            ),
                            1..80,
                        ),
                        1u64..12,
                    )
                })
                .prop_map(|(checkpoints, deliveries, noise, scan_every)| Script {
                    checkpoints,
                    deliveries,
                    noise,
                    scan_every,
                })
        }

        fn run(script: Script) -> Result<(), TestCaseError> {
            let policy = Policy {
                interval: 3 * S,
                backoff_base: S,
                backoff_max: 8 * S,
            };
            let all = saves(&script.checkpoints);
            let t0 = Instant::now();
            let mut m = DbMachine::new(None);
            let mut manifest = Manifest::default();
            let mut pg: Option<ArtifactHead> = None;
            let mut next_save = 0usize;
            // (deliver_at_tick, head)
            let mut mailbox: VecDeque<(u64, Head)> = VecDeque::new();
            let mut job: Option<Job> = None;
            let mut last_seq_seen = 0u64;
            let active = script.noise.len() as u64;
            let mut scanned_after_quiet = false;

            let check =
                |m: &DbMachine, job: &Option<Job>, last: &mut u64| -> Result<(), TestCaseError> {
                    prop_assert_eq!(m.in_flight(), job.is_some(), "one upload per InFlight");
                    if let Some(seq) = m.last_seq() {
                        prop_assert!(seq >= *last, "last_seq regressed");
                        *last = seq;
                    }
                    Ok(())
                };

            for tick in 0..(active + 400) {
                let now = t0 + S * tick as u32;
                let noisy = script.noise.get(tick as usize).copied();
                let quiet = noisy.is_none();
                let (save, fail, lose, delay) = noisy.unwrap_or((false, false, 0, 0));
                // A PG save and its notifications.
                if (save || (quiet && next_save < all.len()) || next_save == 0)
                    && next_save < all.len()
                {
                    let s = &all[next_save];
                    pg = Some(s.artifact.clone());
                    let (delivery, lag) = script.deliveries[next_save];
                    let copies = match delivery {
                        Delivery::Drop => 0,
                        Delivery::Once => 1,
                        Delivery::Twice => 2,
                    };
                    for i in 0..copies {
                        mailbox.push_back((tick + lag as u64 + i, s.artifact.head()));
                    }
                    next_save += 1;
                }
                let pg_done = next_save == all.len();
                // Deliver due notifications, out of order.
                let mut due: Vec<Head> = Vec::new();
                mailbox.retain(|(at, h)| {
                    if *at <= tick {
                        due.push(h.clone());
                        false
                    } else {
                        true
                    }
                });
                due.reverse();
                for h in due {
                    let out = step(&mut m, Event::Notified(h), now, &policy);
                    let uploads = out
                        .iter()
                        .filter(|c| matches!(c, Command::Upload { .. }))
                        .count();
                    prop_assert_eq!(uploads, 0, "an upload only starts from a tick");
                    check(&m, &job, &mut last_seq_seen)?;
                }
                // Scans every k ticks.
                if tick % script.scan_every == 0 {
                    if let Some(head) = &pg {
                        step(&mut m, Event::Scanned(head.head()), now, &policy);
                        check(&m, &job, &mut last_seq_seen)?;
                        if quiet && pg_done {
                            scanned_after_quiet = true;
                        }
                    }
                }
                // A job completes.
                if job.as_ref().is_some_and(|j| j.completes_at <= tick) {
                    let j = job.take().unwrap();
                    let head = pg.clone().expect("a job implies a head");
                    // The shell feeds the head the job observed.
                    step(&mut m, Event::Scanned(head.head()), now, &policy);
                    let event = if fail && !quiet {
                        Event::Failed(Failure::Transient)
                    } else if j.have.as_ref().map(|f| f.revision)
                        != manifest.row.as_ref().map(|f| f.revision)
                    {
                        Event::Lost(manifest.row.clone())
                    } else {
                        match plan_publish(j.have.as_ref(), &head) {
                            None => Event::Lost(manifest.row.clone()),
                            Some(plan) => {
                                let f = manifest.apply(plan, &head);
                                // A lost response: published, reported lost.
                                if lose == 0 && !quiet {
                                    Event::Lost(manifest.row.clone())
                                } else {
                                    Event::Published(f)
                                }
                            }
                        }
                    };
                    let out = step(&mut m, event, now, &policy);
                    let uploads = out
                        .iter()
                        .filter(|c| matches!(c, Command::Upload { .. }))
                        .count();
                    prop_assert_eq!(uploads, 0, "an upload only starts from a tick");
                    check(&m, &job, &mut last_seq_seen)?;
                }
                // Tick.
                let out = step(&mut m, Event::Tick { permit: true }, now, &policy);
                for command in out {
                    match command {
                        Command::Upload { have, .. } => {
                            prop_assert!(job.is_none(), "two uploads in flight");
                            job = Some(Job {
                                have,
                                completes_at: tick + delay as u64,
                            });
                        }
                        Command::Blocked(reason) => {
                            return Err(TestCaseError::fail(format!("blocked: {reason:?}")))
                        }
                    }
                }
                check(&m, &job, &mut last_seq_seen)?;
            }

            let head = pg.expect("at least one save");
            prop_assert!(scanned_after_quiet, "a scan ran after quiescence");
            prop_assert_eq!(&m.phase, &Phase::Clean);
            let have = m.have.clone().expect("published");
            prop_assert_eq!(have.last_seq, head.revision as u64);
            prop_assert_eq!(&have.base_checkpoint_cid, &head.cid);
            prop_assert_eq!(Some(have), manifest.row);
            Ok(())
        }

        proptest! {
            #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]
            #[test]
            fn lost_reordered_duplicated_notices_converge_to_the_pg_head(s in script()) {
                run(s)?;
            }
        }

        /// The byte-level model (TC-1491 P3). The same machine and
        /// `plan_publish` drive it, but the manifest keeps every published
        /// segment with its bytes, PG keeps its WAL at every revision, and the
        /// shell plans deltas from marks, some of them missing. At every
        /// publish, restoring the frontier (the highest cumulative segment and
        /// the deltas after it, end to end) must give PG's artifact at the
        /// frontier's revision byte for byte.
        mod delta {
            use super::*;
            use crate::sql::store::object::sha256;
            use std::collections::HashMap;

            /// PG's artifact at one revision.
            #[derive(Debug, Clone, PartialEq, Eq)]
            struct State {
                cid: String,
                wal: Vec<u8>,
            }

            /// PG's history by revision, and the marks of the current
            /// checkpoint's saves that wrote one.
            #[derive(Default)]
            struct Pg {
                history: Vec<State>,
                marks: HashMap<i64, WalMark>,
            }

            impl Pg {
                /// One save: a new checkpoint, or `len` more WAL bytes.
                fn save(&mut self, checkpoint: bool, len: u8, mark_missing: bool) -> ArtifactHead {
                    let revision = self.history.len() as i64 + 1;
                    let state = match self.history.last() {
                        Some(prev) if !checkpoint => {
                            let mut wal = prev.wal.clone();
                            wal.extend(
                                (0..len).map(|i| (revision as u8).wrapping_mul(31).wrapping_add(i)),
                            );
                            State {
                                cid: prev.cid.clone(),
                                wal,
                            }
                        }
                        _ => {
                            // `save` drops the marks of the checkpoint it replaces.
                            self.marks.clear();
                            State {
                                cid: format!("cid-{revision}"),
                                wal: Vec::new(),
                            }
                        }
                    };
                    if !state.wal.is_empty() && !mark_missing {
                        self.marks.insert(
                            revision,
                            WalMark {
                                revision,
                                checkpoint_content_hash: state.cid.clone(),
                                wal_end_bytes: state.wal.len() as u64,
                                wal_prefix_sha256: sha256(&state.wal),
                            },
                        );
                    }
                    self.history.push(state);
                    self.head()
                }

                fn head(&self) -> ArtifactHead {
                    let state = self.history.last().expect("a save");
                    ArtifactHead {
                        revision: self.history.len() as i64,
                        cid: state.cid.clone(),
                        has_delta: !state.wal.is_empty(),
                        checkpoint_bytes: 10,
                        delta_bytes: state.wal.len() as u64,
                    }
                }

                fn marks_at(&self, revisions: [i64; 2]) -> Vec<WalMark> {
                    revisions
                        .iter()
                        .filter_map(|r| self.marks.get(r).cloned())
                        .collect()
                }
            }

            /// What the source streams for a delta: the WAL between the two
            /// marks, provided its prefixes hash to them.
            fn carve(wal: &[u8], delta: &DeltaPlan) -> Option<Vec<u8>> {
                let start = delta.start.wal_end_bytes as usize;
                let end = delta.end.wal_end_bytes as usize;
                (end == wal.len()
                    && sha256(&wal[..start]) == delta.start.wal_prefix_sha256
                    && sha256(&wal[..end]) == delta.end.wal_prefix_sha256)
                    .then(|| wal[start..end].to_vec())
            }

            /// A published segment and its bytes.
            struct Seg {
                lineage: Lineage,
                base: u64,
                from: u64,
                to: u64,
                bytes: Vec<u8>,
            }

            #[derive(Default)]
            struct Model {
                row: Option<Frontier>,
                segments: Vec<Seg>,
                cums: usize,
                deltas: usize,
            }

            impl Model {
                /// The shell's publish, with the manifest's CAS rules: a
                /// cumulative segment needs `last_seq < to`, a delta needs
                /// `last_seq = from - 1`.
                fn publish(
                    &mut self,
                    plan: PublishPlan,
                    pg: &Pg,
                    have: Option<&Frontier>,
                    min_wal: u64,
                ) -> Frontier {
                    let head = pg.head();
                    let wal = &pg.history.last().expect("a save").wal;
                    let prev = self.row.clone();
                    let revision = prev.as_ref().map_or(0, |f| f.revision + 1);
                    let next = match (plan, prev) {
                        (
                            PublishPlan::Chain {
                                lineage,
                                snapshot_at,
                                segment_to,
                            },
                            prev,
                        ) => {
                            let lineage = match (lineage, prev) {
                                (LineagePick::Same, Some(p)) => p.lineage,
                                _ => Lineage::random(),
                            };
                            if let Some(to) = segment_to {
                                self.segments.push(Seg {
                                    lineage: lineage.clone(),
                                    base: snapshot_at,
                                    from: snapshot_at + 1,
                                    to,
                                    bytes: wal.clone(),
                                });
                                self.cums += 1;
                            }
                            Frontier {
                                lineage,
                                epoch: 0,
                                revision,
                                base_snapshot_key: String::new(),
                                base_seq: snapshot_at,
                                base_checkpoint_cid: head.cid.clone(),
                                last_seq: segment_to.unwrap_or(snapshot_at),
                                publish_id: "00".repeat(16),
                                published_at: String::new(),
                                frontier_bytes: 0,
                            }
                        }
                        (PublishPlan::Segment { base_seq, to_seq }, Some(p)) => {
                            assert_eq!(p.base_seq, base_seq);
                            assert_eq!(p.base_checkpoint_cid, head.cid);
                            let marks = pg.marks_at([p.last_seq as i64, head.revision]);
                            let delta = have
                                .and_then(|h| plan_delta(h, &head, &marks, min_wal))
                                .and_then(|d| carve(wal, &d).map(|bytes| (d, bytes)));
                            let (from, to, bytes) = match delta {
                                Some((d, bytes)) => {
                                    assert_eq!(p.last_seq, d.from_seq - 1, "a delta is contiguous");
                                    self.deltas += 1;
                                    (d.from_seq, d.to_seq, bytes)
                                }
                                None => {
                                    assert!(p.last_seq < to_seq, "a cumulative segment advances");
                                    self.cums += 1;
                                    (base_seq + 1, to_seq, wal.clone())
                                }
                            };
                            self.segments.push(Seg {
                                lineage: p.lineage.clone(),
                                base: base_seq,
                                from,
                                to,
                                bytes,
                            });
                            Frontier {
                                revision,
                                last_seq: to,
                                ..p
                            }
                        }
                        (PublishPlan::Segment { .. }, None) => panic!("segment without a base"),
                    };
                    self.row = Some(next.clone());
                    next
                }

                /// A restore at the frontier: the highest cumulative segment,
                /// then the segments that start where the chain ends.
                fn restore(&self) -> Result<State, String> {
                    let f = self.row.as_ref().expect("published");
                    let on_base = |from: u64| {
                        self.segments
                            .iter()
                            .filter(|s| s.lineage == f.lineage && s.base == f.base_seq)
                            .filter(move |s| s.from == from && s.to <= f.last_seq)
                            .max_by_key(|s| s.to)
                    };
                    let mut wal = Vec::new();
                    let mut covered = f.base_seq;
                    while covered < f.last_seq {
                        let Some(s) = on_base(covered + 1) else {
                            return Err(format!("the chain reaches {covered}, not {}", f.last_seq));
                        };
                        wal.extend_from_slice(&s.bytes);
                        covered = s.to;
                    }
                    Ok(State {
                        cid: f.base_checkpoint_cid.clone(),
                        wal,
                    })
                }
            }

            #[derive(Debug, Clone)]
            struct ByteScript {
                base: Script,
                /// Per save: the WAL bytes it appends, and whether its mark
                /// was never written (a save from before marks existed).
                wal_lens: Vec<u8>,
                mark_missing: Vec<bool>,
                min_wal: u64,
            }

            fn byte_script() -> impl Strategy<Value = ByteScript> {
                script()
                    .prop_flat_map(|base| {
                        let n = base.checkpoints.len();
                        (
                            Just(base),
                            proptest::collection::vec(1u8..40, n),
                            proptest::collection::vec(proptest::bool::weighted(0.3), n),
                            prop_oneof![Just(0u64), Just(1), Just(20)],
                        )
                    })
                    .prop_map(|(base, wal_lens, mark_missing, min_wal)| ByteScript {
                        base,
                        wal_lens,
                        mark_missing,
                        min_wal,
                    })
            }

            /// The cumulative and the delta segments published.
            #[derive(Debug, PartialEq, Eq)]
            struct Published {
                cums: usize,
                deltas: usize,
            }

            fn run(bytes: ByteScript) -> Result<Published, TestCaseError> {
                let script = bytes.base.clone();
                let policy = Policy {
                    interval: 3 * S,
                    backoff_base: S,
                    backoff_max: 8 * S,
                };
                let t0 = Instant::now();
                let mut m = DbMachine::new(None);
                let mut model = Model::default();
                let mut pg = Pg::default();
                let mut head: Option<ArtifactHead> = None;
                let mut next_save = 0usize;
                let saves = script.checkpoints.len();
                let mut mailbox: VecDeque<(u64, Head)> = VecDeque::new();
                let mut job: Option<Job> = None;
                let active = script.noise.len() as u64;

                for tick in 0..(active + 400) {
                    let now = t0 + S * tick as u32;
                    let noisy = script.noise.get(tick as usize).copied();
                    let quiet = noisy.is_none();
                    let (save, fail, lose, delay) = noisy.unwrap_or((false, false, 0, 0));
                    if (save || quiet || next_save == 0) && next_save < saves {
                        let checkpoint = script.checkpoints[next_save] || next_save == 0;
                        let saved = pg.save(
                            checkpoint,
                            bytes.wal_lens[next_save],
                            bytes.mark_missing[next_save],
                        );
                        let (delivery, lag) = script.deliveries[next_save];
                        let copies = match delivery {
                            Delivery::Drop => 0,
                            Delivery::Once => 1,
                            Delivery::Twice => 2,
                        };
                        for i in 0..copies {
                            mailbox.push_back((tick + lag as u64 + i, saved.head()));
                        }
                        head = Some(saved);
                        next_save += 1;
                    }
                    let mut due: Vec<Head> = Vec::new();
                    mailbox.retain(|(at, h)| {
                        if *at <= tick {
                            due.push(h.clone());
                            false
                        } else {
                            true
                        }
                    });
                    due.reverse();
                    for h in due {
                        step(&mut m, Event::Notified(h), now, &policy);
                    }
                    if tick % script.scan_every == 0 {
                        if let Some(head) = &head {
                            step(&mut m, Event::Scanned(head.head()), now, &policy);
                        }
                    }
                    if job.as_ref().is_some_and(|j| j.completes_at <= tick) {
                        let j = job.take().unwrap();
                        let head = head.clone().expect("a job implies a head");
                        step(&mut m, Event::Scanned(head.head()), now, &policy);
                        let event = if fail && !quiet {
                            Event::Failed(Failure::Transient)
                        } else if j.have.as_ref().map(|f| f.revision)
                            != model.row.as_ref().map(|f| f.revision)
                        {
                            Event::Lost(model.row.clone())
                        } else {
                            match plan_publish(j.have.as_ref(), &head) {
                                None => Event::Lost(model.row.clone()),
                                Some(plan) => {
                                    let f =
                                        model.publish(plan, &pg, j.have.as_ref(), bytes.min_wal);
                                    // Every frontier restores PG's artifact at
                                    // its revision, byte for byte.
                                    let at = &pg.history[f.last_seq as usize - 1];
                                    let restored = model.restore();
                                    prop_assert_eq!(
                                        restored.as_ref(),
                                        Ok(at),
                                        "the frontier at {} restores PG's artifact",
                                        f.last_seq
                                    );
                                    if lose == 0 && !quiet {
                                        Event::Lost(model.row.clone())
                                    } else {
                                        Event::Published(f)
                                    }
                                }
                            }
                        };
                        step(&mut m, event, now, &policy);
                    }
                    for command in step(&mut m, Event::Tick { permit: true }, now, &policy) {
                        match command {
                            Command::Upload { have, .. } => {
                                prop_assert!(job.is_none(), "two uploads in flight");
                                job = Some(Job {
                                    have,
                                    completes_at: tick + delay as u64,
                                });
                            }
                            Command::Blocked(reason) => {
                                return Err(TestCaseError::fail(format!("blocked: {reason:?}")))
                            }
                        }
                    }
                }

                let head = head.expect("at least one save");
                prop_assert_eq!(&m.phase, &Phase::Clean);
                let have = m.have.clone().expect("published");
                prop_assert_eq!(have.last_seq, head.revision as u64);
                prop_assert_eq!(&have.base_checkpoint_cid, &head.cid);
                prop_assert_eq!(Some(have), model.row.clone());
                Ok(Published {
                    cums: model.cums,
                    deltas: model.deltas,
                })
            }

            proptest! {
                #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]
                #[test]
                fn mixed_cumulative_and_delta_chains_restore_the_pg_artifact_at_every_frontier(
                    s in byte_script()
                ) {
                    run(s)?;
                }
            }

            /// One generation, a save per tick, an upload every few ticks.
            fn steady(marks_missing: bool) -> ByteScript {
                let saves = 14;
                ByteScript {
                    base: Script {
                        checkpoints: vec![false; saves],
                        deliveries: vec![(Delivery::Once, 0); saves],
                        noise: vec![(true, false, 5, 0); saves + 6],
                        scan_every: 4,
                    },
                    wal_lens: vec![8; saves],
                    mark_missing: vec![marks_missing; saves],
                    min_wal: 0,
                }
            }

            #[test]
            fn marks_turn_the_segments_after_the_first_into_deltas() {
                let published = run(steady(false)).unwrap();
                // The bootstrap and the first append (the frontier still at
                // its snapshot) are cumulative; the rest are deltas.
                assert!(
                    published.cums >= 1 && published.deltas >= 1,
                    "{published:?}"
                );
            }

            #[test]
            fn without_marks_every_segment_is_cumulative() {
                let published = run(steady(true)).unwrap();
                assert_eq!(published.deltas, 0);
                assert!(published.cums >= 2, "{published:?}");
            }

            #[test]
            fn a_missing_mark_anywhere_falls_back_to_a_cumulative_segment_and_the_chain_still_restores(
            ) {
                // Whichever save lost its mark, every frontier restores PG's
                // artifact (`run` checks each publish), and where the missing
                // mark was one a publish needed, the chain mixes both kinds.
                let saves = steady(false).wal_lens.len();
                let mut mixed = false;
                for missing in 0..saves {
                    let mut bytes = steady(false);
                    bytes.mark_missing[missing] = true;
                    let published = run(bytes).unwrap();
                    mixed |= published.cums >= 2 && published.deltas >= 1;
                }
                assert!(mixed, "some missing mark forced a cumulative segment");
            }
        }
    }

    // ---- plan_delta ------------------------------------------------------

    mod delta_plan {
        use super::*;

        fn mark(revision: i64, cid: &str, wal_end_bytes: u64) -> WalMark {
            WalMark {
                revision,
                checkpoint_content_hash: cid.into(),
                wal_end_bytes,
                wal_prefix_sha256: [revision as u8; 32],
            }
        }

        /// A frontier on base 2 of checkpoint `a` that reached revision 5, after
        /// `revision` publishes.
        fn have(revision: i64) -> Frontier {
            let mut f = frontier(5, "a");
            f.base_seq = 2;
            f.revision = revision;
            f
        }

        fn plan(f: &Frontier, head: &ArtifactHead, marks: &[WalMark]) -> Option<DeltaPlan> {
            plan_delta(f, head, marks, 0)
        }

        fn grown() -> (ArtifactHead, Vec<WalMark>) {
            let mut head = artifact(8, "a", true);
            head.delta_bytes = 300;
            (head, vec![mark(5, "a", 100), mark(8, "a", 300)])
        }

        #[test]
        fn the_wal_between_the_frontier_and_the_head_is_a_delta() {
            let (head, marks) = grown();
            let delta = plan(&have(3), &head, &marks).expect("a delta");
            assert_eq!((delta.from_seq, delta.to_seq), (6, 8));
            assert_eq!(
                (delta.start.wal_end_bytes, delta.end.wal_end_bytes),
                (100, 300)
            );
            // Any order, any extra marks.
            let mut shuffled = marks.clone();
            shuffled.reverse();
            shuffled.push(mark(6, "a", 150));
            assert_eq!(plan(&have(3), &head, &shuffled), Some(delta));
        }

        #[test]
        fn a_missing_or_pruned_mark_is_a_cumulative_segment() {
            let (head, marks) = grown();
            assert_eq!(plan(&have(3), &head, &marks[..1]), None, "no head mark");
            assert_eq!(plan(&have(3), &head, &marks[1..]), None, "no frontier mark");
            assert_eq!(plan(&have(3), &head, &[]), None, "no marks at all");
        }

        #[test]
        fn marks_of_another_checkpoint_are_not_used() {
            let (head, mut marks) = grown();
            marks[0] = mark(5, "b", 100);
            assert_eq!(plan(&have(3), &head, &marks), None);
            let (head, mut marks) = grown();
            marks[1] = mark(8, "b", 300);
            assert_eq!(plan(&have(3), &head, &marks), None);
        }

        #[test]
        fn a_head_on_another_checkpoint_or_without_a_wal_is_not_a_delta() {
            let (head, marks) = grown();
            let mut other = head.clone();
            other.cid = "b".into();
            assert_eq!(plan(&have(3), &other, &marks), None);
            let mut bare = head.clone();
            bare.has_delta = false;
            assert_eq!(plan(&have(3), &bare, &marks), None);
        }

        #[test]
        fn a_wal_that_did_not_grow_or_shrank_is_a_cumulative_segment() {
            let (mut head, mut marks) = grown();
            marks[1] = mark(8, "a", 100);
            head.delta_bytes = 100;
            assert_eq!(plan(&have(3), &head, &marks), None, "zero growth");
            marks[1] = mark(8, "a", 60);
            head.delta_bytes = 60;
            assert_eq!(plan(&have(3), &head, &marks), None, "regression");
        }

        #[test]
        fn a_head_whose_wal_is_not_the_marked_one_is_a_cumulative_segment() {
            let (mut head, marks) = grown();
            head.delta_bytes = 301;
            assert_eq!(plan(&have(3), &head, &marks), None);
        }

        #[test]
        fn a_frontier_at_or_past_the_head_or_still_at_its_snapshot_plans_no_delta() {
            let (head, marks) = grown();
            let mut at_head = have(3);
            at_head.last_seq = 8;
            assert_eq!(plan(&at_head, &head, &marks), None);
            let mut at_snapshot = have(3);
            at_snapshot.last_seq = 2;
            assert_eq!(
                plan(&at_snapshot, &head, &[mark(2, "a", 0), marks[1].clone()]),
                None
            );
        }

        #[test]
        fn a_small_wal_is_uploaded_whole() {
            let (head, marks) = grown();
            assert!(plan_delta(&have(3), &head, &marks, 300).is_some());
            assert_eq!(plan_delta(&have(3), &head, &marks, 301), None);
            assert_eq!(
                plan_delta(&have(3), &head, &marks, DELTA_MIN_WAL_BYTES),
                None
            );
        }

        #[test]
        fn every_nth_publish_is_a_cumulative_segment() {
            let (head, marks) = grown();
            // The deltas between two cumulative segments are at most
            // MAX_DELTA_CHAIN - 1: the publish that would make the chain's
            // MAX_DELTA_CHAIN-th object is cumulative.
            assert!(plan(&have(MAX_DELTA_CHAIN - 2), &head, &marks).is_some());
            assert_eq!(plan(&have(MAX_DELTA_CHAIN - 1), &head, &marks), None);
            assert!(plan(&have(MAX_DELTA_CHAIN), &head, &marks).is_some());
            assert_eq!(plan(&have(2 * MAX_DELTA_CHAIN - 1), &head, &marks), None);
        }
    }
}

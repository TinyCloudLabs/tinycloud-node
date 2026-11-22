//! Per-DB upload state and the pure planner.
//!
//! `plan()` decides what the uploader should do with the newest capture,
//! given the cached manifest frontier and the upload policy. It performs
//! no I/O. The decision rules check the capture's cid against the frontier
//! first, then the revision.
//!
//! TC-1491.

use std::time::{Duration, Instant};

use super::super::manifest::Frontier;

/// The upload policy already lives in `super::super::policy::UploadPolicy`;
/// re-exported here so callers of the planner do not have to reach across
/// modules.
pub use super::super::policy::UploadPolicy;

/// What `plan` tells the uploader to do for one capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Nothing due: the capture is already covered by the published frontier,
    /// the space is not in the allowlist, or there is no capture.
    Idle,
    /// Publish the capture as a fresh snapshot in the current lineage.
    /// Carries the revision the snapshot is cut at and its `cid`.
    Snapshot {
        revision: i64,
        cid: String,
        base_seq: u64,
    },
    /// Append a cumulative-WAL segment. `from_seq = base_seq + 1`, which is
    /// the only valid shape for `wal-cum-v1` .
    Segment {
        base_seq: u64,
        from_seq: u64,
        to_seq: u64,
        cid: String,
    },
    /// The captured cid matches no current lineage; the uploader must open a
    /// new lineage via a lineage switch. Counted via
    /// `sql_store_lineage_switch_regression_total` when the revision
    /// regressed below the manifest's `last_seq`. The manifest's
    /// `LineageSwitch` CAS does not reject that regression itself, so the
    /// planner is what notices and counts it.
    Switch { revision: i64, cid: String },
    /// No capture in hand and no covered frontier: the DB needs to be
    /// bootstrapped from P. The bootstrap path lands in a later change; the
    /// planner only reports the shape.
    NeedsBootstrap,
}

/// What the uploader knows about one database between cycles.
#[derive(Debug, Clone)]
pub struct DbState {
    /// A pending `Checkpoint` capture waiting to be published as a
    /// snapshot. Invariant: if `Some`, `kind == Checkpoint`.
    pub pending_base: Option<CapturePlan>,
    /// A pending `Wal` capture waiting to be published as a segment.
    /// Invariant: if `Some`, `kind == Wal`; if `pending_base` is also
    /// `Some`, `pending_delta.revision > pending_base.revision` (the
    /// delta rides on top of the newer base).
    pub pending_delta: Option<CapturePlan>,
    /// When the oldest un-uploaded commit happened; `None` when idle.
    pub first_dirty_at: Option<Instant>,
    /// Bytes pending since the published frontier.
    pub pending_bytes: u64,
    /// A capture was shed (channel full, budget exceeded or spool full), so
    /// the next cycle must restart from P.
    pub needs_bootstrap: bool,
    /// Age of the last published snapshot, if any; `None` until the first
    /// snapshot is published or the frontier is read at boot.
    pub since_last_snapshot: Option<Duration>,
    /// Per-DB backoff. The timer consults `ready(now)` before selecting
    /// a DB to run this tick so a transient failure on one DB does not
    /// burn the per-tick budget.
    pub backoff: super::backoff::Backoff,
}

impl Default for DbState {
    fn default() -> Self {
        Self {
            pending_base: None,
            pending_delta: None,
            first_dirty_at: None,
            pending_bytes: 0,
            needs_bootstrap: false,
            since_last_snapshot: None,
            // 0 seed is fine: the timer only cares about the deadline,
            // and jitter is bounded. Tests that want determinism install
            // their own seed by overwriting the field directly.
            backoff: super::backoff::Backoff::new(0),
        }
    }
}

/// What the planner needs from the newest capture. Decoupled from
/// `super::Capture` so the planner is testable without `bytes::Bytes`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePlan {
    pub revision: i64,
    pub cid: String,
    pub kind: CaptureKindTag,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureKindTag {
    Wal,
    Checkpoint,
}

impl DbState {
    /// A fresh dirty mark from a capture. Supersedes the pending slot
    /// only when the incoming capture advances the revision, whatever
    /// the kind.
    ///
    /// The capture-hook ingress spawns a detached task per capture, so
    /// two captures can race through the per-DB upsert lock out of
    /// commit order. The data shape allows one pending `Checkpoint` AND
    /// one newer `Wal` to coexist: the cycle publishes the snapshot
    /// first and the segment second, so a `Checkpoint 5 -> Wal 6`
    /// sequence keeps both, and a `Wal 7` followed by a stale
    /// `Checkpoint 5` keeps the newer `Wal 7` and drops the older base.
    ///
    /// Rules, where `c` is the incoming capture:
    ///
    /// For a `Checkpoint c`:
    /// - If `pending_base` is `None` or `c.revision > pending_base.revision`,
    ///   install `c` as `pending_base`.
    /// - Then drop `pending_delta` if its revision is <= the installed
    ///   base's revision, because that delta is stale on the new base.
    /// - Else, ignore the incoming (older or equal checkpoint).
    ///
    /// For a `Wal c`:
    /// - If `pending_base` is `Some` and `c.revision <= pending_base.revision`,
    ///   ignore (stale delta on the newer base).
    /// - Else, install `c` as `pending_delta` if the slot is empty or
    ///   `c.revision > pending_delta.revision`; otherwise ignore.
    ///
    /// Edge case the planner must still check (no pending_base, but
    /// the manifest's frontier already published a newer checkpoint
    /// than the incoming WAL): the WAL installs as `pending_delta`
    /// here, because this function does not see the frontier. The
    /// planner MUST reject a delta whose `base_checkpoint_cid` is not
    /// the manifest's current base and MUST drop it via
    /// `clear_after_publish(current_revision)` rather than retry
    /// forever. A test covers this when the planner's cid check wires
    /// in (TC-1491).
    pub fn mark_capture(&mut self, c: CapturePlan, now: Instant) {
        if self.first_dirty_at.is_none() {
            self.first_dirty_at = Some(now);
        }
        match c.kind {
            CaptureKindTag::Checkpoint => {
                // A newer Checkpoint supersedes the pending base; a
                // stale Checkpoint arriving after a newer WAL or newer
                // Checkpoint is dropped. Compare against both slots:
                // the incoming revision must be greater than every
                // pending revision to install.
                let max_pending = self.max_pending_revision().unwrap_or(i64::MIN);
                if c.revision > max_pending {
                    // The new base makes an older or equal-revision
                    // delta stale (its from_seq would be <= the new
                    // base's base_seq).
                    if let Some(delta) = self.pending_delta.as_ref() {
                        if delta.revision <= c.revision {
                            self.pending_delta = None;
                        }
                    }
                    self.pending_base = Some(c);
                }
            }
            CaptureKindTag::Wal => {
                // A WAL at or before the pending base's revision is a
                // stale delta on an older base; drop it.
                if let Some(base) = self.pending_base.as_ref() {
                    if c.revision <= base.revision {
                        return;
                    }
                }
                let install = self
                    .pending_delta
                    .as_ref()
                    .is_none_or(|d| c.revision > d.revision);
                if install {
                    self.pending_delta = Some(c);
                }
            }
        }
        self.pending_bytes = self.recompute_pending_bytes();
    }

    /// Pending-bytes counter reflects the bytes the uploader must
    /// ship next (base + delta, when both are present).
    fn recompute_pending_bytes(&self) -> u64 {
        let base = self.pending_base.as_ref().map_or(0, |c| c.bytes);
        let delta = self.pending_delta.as_ref().map_or(0, |c| c.bytes);
        base.saturating_add(delta)
    }

    /// The capture the planner should act on next: `pending_base`
    /// first (the snapshot that publishes first), else `pending_delta`.
    pub fn next_to_publish(&self) -> Option<&CapturePlan> {
        self.pending_base.as_ref().or(self.pending_delta.as_ref())
    }

    /// The newest revision anything in the pending slots refers to.
    /// Used by the uploader to decide whether a publish is still fresh.
    pub fn max_pending_revision(&self) -> Option<i64> {
        let b = self.pending_base.as_ref().map(|c| c.revision);
        let d = self.pending_delta.as_ref().map(|c| c.revision);
        match (b, d) {
            (Some(a), Some(c)) => Some(a.max(c)),
            (Some(a), None) | (None, Some(a)) => Some(a),
            (None, None) => None,
        }
    }

    /// Clear state after a successful publish of `published_revision`.
    ///
    /// Clears only the pending slots whose revision is at or below
    /// `published_revision`, so a capture that arrived during the
    /// upload survives. The uploader passes the frontier's `last_seq`
    /// as `published_revision`.
    pub fn clear_after_publish(&mut self, published_revision: i64) {
        if let Some(base) = self.pending_base.as_ref() {
            if base.revision <= published_revision {
                self.pending_base = None;
            }
        }
        if let Some(delta) = self.pending_delta.as_ref() {
            if delta.revision <= published_revision {
                self.pending_delta = None;
            }
        }
        self.pending_bytes = self.recompute_pending_bytes();
        if self.pending_base.is_none() && self.pending_delta.is_none() {
            self.first_dirty_at = None;
            self.needs_bootstrap = false;
        }
    }
}

/// The pure decision function. No I/O, no clock reads beyond `now`.
///
/// Rules:
/// 1. `allowed = false` → `Idle`, the uploader drops any pending capture.
/// 2. No capture and no frontier → `NeedsBootstrap` (bootstrap lands in
///    a later change).
/// 3. No capture, frontier present → `Idle`.
/// 4. Frontier absent, capture present → `Snapshot` (first publish).
/// 5. Capture `revision <= frontier.last_seq` and same `cid`: `Idle`.
/// 6. Capture `cid != frontier.base_checkpoint_cid`: `Snapshot` in a fresh
///    chain of the same lineage; if the capture also regressed below
///    `last_seq`, the planner emits `Switch` (defensive).
/// 7. Otherwise the capture is a delta: `Segment` with `from_seq = base_seq + 1`.
pub fn plan(
    st: &DbState,
    frontier: Option<&Frontier>,
    _policy: &UploadPolicy,
    allowed: bool,
    _now: Instant,
) -> Action {
    if !allowed {
        return Action::Idle;
    }
    let Some(capture) = st.next_to_publish() else {
        return match frontier {
            Some(_) => Action::Idle,
            None => {
                if st.needs_bootstrap {
                    Action::NeedsBootstrap
                } else {
                    Action::Idle
                }
            }
        };
    };

    let Some(front) = frontier else {
        // No published frontier: a first snapshot is the only valid first
        // publish because a segment needs a published base. A `Wal` capture
        // without a matching frontier has no base to ride on, so the planner
        // refuses to publish it as a snapshot (it is not a snapshot's bytes).
        // The DB falls into `NeedsBootstrap`, which the follow-up uploader
        // satisfies via the paced P-read; an older WAL capture is left in
        // the slot and is replaced by a fresh checkpoint capture the next
        // time one is emitted.
        return match capture.kind {
            CaptureKindTag::Checkpoint => Action::Snapshot {
                revision: capture.revision,
                cid: capture.cid.clone(),
                base_seq: capture.revision.max(0) as u64,
            },
            CaptureKindTag::Wal => Action::NeedsBootstrap,
        };
    };

    // cid first: a checkpoint change means the chain needs a
    // new snapshot, whatever the revisions say.
    if front.base_checkpoint_cid != capture.cid {
        let regressed = (capture.revision as u64) < front.last_seq;
        if regressed {
            return Action::Switch {
                revision: capture.revision,
                cid: capture.cid.clone(),
            };
        }
        // A WAL capture whose cid does not match the frontier cannot become
        // a snapshot (its bytes are WAL frames, not a SQLite checkpoint); it
        // must wait for the next checkpoint capture or be bootstrapped from
        // P. Same reasoning as the frontier-absent WAL case above.
        return match capture.kind {
            CaptureKindTag::Checkpoint => Action::Snapshot {
                revision: capture.revision,
                cid: capture.cid.clone(),
                base_seq: capture.revision.max(0) as u64,
            },
            CaptureKindTag::Wal => Action::NeedsBootstrap,
        };
    }

    // Same cid: either already covered, or a delta segment on top.
    if (capture.revision as u64) <= front.last_seq {
        return Action::Idle;
    }

    Action::Segment {
        base_seq: front.base_seq,
        from_seq: front.base_seq + 1,
        to_seq: capture.revision as u64,
        cid: capture.cid.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sql::store::key::Lineage;

    fn policy() -> UploadPolicy {
        UploadPolicy::default()
    }

    fn capture(rev: i64, cid: &str, kind: CaptureKindTag, bytes: u64) -> CapturePlan {
        CapturePlan {
            revision: rev,
            cid: cid.into(),
            kind,
            bytes,
        }
    }

    fn frontier(base_seq: u64, last_seq: u64, cid: &str) -> Frontier {
        Frontier {
            lineage: Lineage::random(),
            epoch: 0,
            revision: 1,
            base_snapshot_key: format!("sql/v1/s/d/l/snap/{base_seq:020}-0000"),
            base_seq,
            base_checkpoint_cid: cid.into(),
            last_seq,
            publish_id: "00000000000000000000000000000000".into(),
            published_at: "2026-11-21T00:00:00.000000Z".into(),
            frontier_bytes: 100,
        }
    }

    #[test]
    fn allowlist_off_short_circuits_to_idle() {
        let st = DbState::default();
        assert_eq!(
            plan(&st, None, &policy(), false, Instant::now()),
            Action::Idle
        );
    }

    #[test]
    fn no_capture_with_frontier_is_idle() {
        let st = DbState::default();
        let f = frontier(5, 7, "cid-a");
        assert_eq!(
            plan(&st, Some(&f), &policy(), true, Instant::now()),
            Action::Idle
        );
    }

    #[test]
    fn no_capture_no_frontier_without_mark_is_idle() {
        let st = DbState::default();
        assert_eq!(
            plan(&st, None, &policy(), true, Instant::now()),
            Action::Idle
        );
    }

    #[test]
    fn no_capture_no_frontier_with_needs_bootstrap_is_needs_bootstrap() {
        let st = DbState {
            needs_bootstrap: true,
            ..DbState::default()
        };
        assert_eq!(
            plan(&st, None, &policy(), true, Instant::now()),
            Action::NeedsBootstrap
        );
    }

    #[test]
    fn capture_without_frontier_publishes_first_snapshot() {
        let mut st = DbState::default();
        st.mark_capture(
            capture(7, "cid-a", CaptureKindTag::Checkpoint, 100),
            Instant::now(),
        );
        assert_eq!(
            plan(&st, None, &policy(), true, Instant::now()),
            Action::Snapshot {
                revision: 7,
                cid: "cid-a".into(),
                base_seq: 7,
            }
        );
    }

    #[test]
    fn wal_capture_without_frontier_is_needs_bootstrap_not_snapshot() {
        // A Wal capture is not a snapshot's bytes; it cannot become a first
        // publish. The planner says `NeedsBootstrap` and the uploader must
        // read P instead.
        let mut st = DbState::default();
        st.mark_capture(
            capture(7, "cid-a", CaptureKindTag::Wal, 100),
            Instant::now(),
        );
        assert_eq!(
            plan(&st, None, &policy(), true, Instant::now()),
            Action::NeedsBootstrap
        );
    }

    #[test]
    fn wal_capture_with_mismatched_cid_is_needs_bootstrap_not_snapshot() {
        // After a cid change (P checkpointed) the only valid capture to
        // publish is a Checkpoint. A Wal capture still in the slot must
        // wait for the next checkpoint or bootstrap from P.
        let mut st = DbState::default();
        st.mark_capture(
            capture(9, "cid-b", CaptureKindTag::Wal, 100),
            Instant::now(),
        );
        let f = frontier(3, 5, "cid-a");
        assert_eq!(
            plan(&st, Some(&f), &policy(), true, Instant::now()),
            Action::NeedsBootstrap
        );
    }

    #[test]
    fn covered_revision_with_same_cid_is_idle() {
        let mut st = DbState::default();
        st.mark_capture(capture(5, "cid-a", CaptureKindTag::Wal, 10), Instant::now());
        let f = frontier(3, 5, "cid-a");
        assert_eq!(
            plan(&st, Some(&f), &policy(), true, Instant::now()),
            Action::Idle
        );
    }

    #[test]
    fn delta_in_same_cid_above_last_seq_emits_segment() {
        let mut st = DbState::default();
        st.mark_capture(capture(8, "cid-a", CaptureKindTag::Wal, 10), Instant::now());
        let f = frontier(3, 5, "cid-a");
        assert_eq!(
            plan(&st, Some(&f), &policy(), true, Instant::now()),
            Action::Segment {
                base_seq: 3,
                from_seq: 4,
                to_seq: 8,
                cid: "cid-a".into(),
            }
        );
    }

    #[test]
    fn cid_differs_emits_snapshot_at_captured_revision() {
        let mut st = DbState::default();
        st.mark_capture(
            capture(9, "cid-b", CaptureKindTag::Checkpoint, 100),
            Instant::now(),
        );
        let f = frontier(3, 5, "cid-a");
        assert_eq!(
            plan(&st, Some(&f), &policy(), true, Instant::now()),
            Action::Snapshot {
                revision: 9,
                cid: "cid-b".into(),
                base_seq: 9,
            }
        );
    }

    #[test]
    fn cid_differs_with_regressing_revision_emits_switch() {
        let mut st = DbState::default();
        st.mark_capture(
            capture(2, "cid-b", CaptureKindTag::Checkpoint, 100),
            Instant::now(),
        );
        let f = frontier(3, 5, "cid-a");
        assert_eq!(
            plan(&st, Some(&f), &policy(), true, Instant::now()),
            Action::Switch {
                revision: 2,
                cid: "cid-b".into(),
            }
        );
    }

    #[test]
    fn mark_capture_sets_first_dirty_at_once() {
        let t0 = Instant::now();
        let mut st = DbState::default();
        st.mark_capture(capture(1, "cid", CaptureKindTag::Wal, 10), t0);
        let t1 = t0 + Duration::from_secs(5);
        st.mark_capture(capture(2, "cid", CaptureKindTag::Wal, 20), t1);
        assert_eq!(st.first_dirty_at, Some(t0));
        // Cumulative WAL: the newest capture carries all the frames
        // from base_seq+1 to its revision, so pending_bytes is its
        // bytes, not the sum of all captures.
        assert_eq!(st.pending_bytes, 20);
    }

    #[test]
    fn checkpoint_capture_resets_pending_bytes() {
        let t0 = Instant::now();
        let mut st = DbState::default();
        st.mark_capture(capture(1, "cid", CaptureKindTag::Wal, 10), t0);
        st.mark_capture(capture(2, "cid-b", CaptureKindTag::Checkpoint, 1000), t0);
        assert_eq!(st.pending_bytes, 1000);
    }

    #[test]
    fn clear_after_publish_resets_state_when_the_pending_was_published() {
        let t0 = Instant::now();
        let mut st = DbState::default();
        st.mark_capture(capture(1, "cid", CaptureKindTag::Wal, 10), t0);
        st.needs_bootstrap = true;
        st.clear_after_publish(1);
        assert!(st.next_to_publish().is_none());
        assert!(st.first_dirty_at.is_none());
        assert_eq!(st.pending_bytes, 0);
        assert!(!st.needs_bootstrap);
    }

    #[test]
    fn clear_after_publish_keeps_captures_that_arrived_during_the_upload() {
        // Uploader starts publishing R=5; a WAL at R=7 arrives before
        // the CAS succeeds. clear_after_publish(5) must keep R=7 in
        // pending, and must NOT clear first_dirty_at, so the uploader
        // runs again on the next tick.
        let t0 = Instant::now();
        let mut st = DbState::default();
        st.mark_capture(capture(5, "cid", CaptureKindTag::Wal, 10), t0);
        st.mark_capture(capture(7, "cid", CaptureKindTag::Wal, 20), t0);
        st.clear_after_publish(5);
        assert_eq!(
            st.next_to_publish().map(|c| c.revision),
            Some(7),
            "a later capture must survive clear_after_publish of the older revision"
        );
        assert!(st.first_dirty_at.is_some());
    }

    #[test]
    fn out_of_order_wal_captures_keep_the_newest_revision_in_the_delta_slot() {
        // The ingress spawns a detached task per capture, so two wal
        // captures at revisions 5 and 7 can hit mark_capture in either
        // order. The newest revision must win so a clear_after_publish
        // against R=5 does not drop the state for R=7 and lose
        // commits 6-7.
        let t0 = Instant::now();
        let mut st = DbState::default();
        st.mark_capture(capture(7, "cid", CaptureKindTag::Wal, 20), t0);
        st.mark_capture(capture(5, "cid", CaptureKindTag::Wal, 10), t0);
        assert_eq!(st.next_to_publish().map(|c| c.revision), Some(7));
        assert!(st.pending_base.is_none());
    }

    #[test]
    fn checkpoint_5_then_wal_6_publishes_through_revision_6() {
        // A newer WAL on a pending (unpublished) checkpoint must NOT
        // be dropped: the cycle publishes the snapshot first and the
        // segment second. Without this, revision 6's commits are lost
        // on restore until the next write.
        let t0 = Instant::now();
        let mut st = DbState::default();
        st.mark_capture(capture(5, "cid-a", CaptureKindTag::Checkpoint, 100), t0);
        st.mark_capture(capture(6, "cid-a", CaptureKindTag::Wal, 20), t0);
        assert_eq!(
            st.pending_base.as_ref().map(|c| c.revision),
            Some(5),
            "the pending checkpoint survives"
        );
        assert_eq!(
            st.pending_delta.as_ref().map(|c| c.revision),
            Some(6),
            "the newer WAL rides on top of the base"
        );
        assert_eq!(st.max_pending_revision(), Some(6));
        // After the base publishes (R=5), the delta remains.
        st.clear_after_publish(5);
        assert_eq!(
            st.next_to_publish().map(|c| c.revision),
            Some(6),
            "the delta is the next to publish after the base lands"
        );
    }

    #[test]
    fn wal_7_then_stale_checkpoint_5_keeps_wal_7() {
        // The capture-hook ingress spawns a detached task per capture,
        // so a late-arriving stale Checkpoint 5 must NOT replace a
        // pending WAL 7. Keep the WAL; drop the stale checkpoint.
        let t0 = Instant::now();
        let mut st = DbState::default();
        st.mark_capture(capture(7, "cid-a", CaptureKindTag::Wal, 20), t0);
        st.mark_capture(capture(5, "cid-a", CaptureKindTag::Checkpoint, 100), t0);
        assert!(
            st.pending_base.is_none(),
            "the stale older checkpoint is dropped"
        );
        assert_eq!(st.pending_delta.as_ref().map(|c| c.revision), Some(7));
        assert_eq!(st.max_pending_revision(), Some(7));
    }

    #[test]
    fn upload_policy_due_uses_the_contract_defaults() {
        let p = policy();
        let now = Instant::now();
        assert!(!p.due(&crate::sql::store::policy::PendingState::default(), now));
        let pending = crate::sql::store::policy::PendingState {
            first_commit_at: Some(now - Duration::from_secs(61)),
            bytes: 1,
        };
        assert!(p.due(&pending, now));
    }
}

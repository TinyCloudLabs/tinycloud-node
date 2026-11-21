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
    /// The last capture seen for this DB (if any).
    pub pending: Option<CapturePlan>,
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
}

impl Default for DbState {
    fn default() -> Self {
        Self {
            pending: None,
            first_dirty_at: None,
            pending_bytes: 0,
            needs_bootstrap: false,
            since_last_snapshot: None,
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
    /// A fresh dirty mark from a capture. Updates pending slot, first-dirty
    /// time and pending-bytes counter. A checkpoint capture supersedes a
    /// pending WAL (the new base makes the old delta meaningless).
    pub fn mark_capture(&mut self, c: CapturePlan, now: Instant) {
        let is_checkpoint = matches!(c.kind, CaptureKindTag::Checkpoint);
        if self.first_dirty_at.is_none() {
            self.first_dirty_at = Some(now);
        }
        self.pending_bytes = self.pending_bytes.saturating_add(c.bytes);
        if is_checkpoint {
            // The new checkpoint is the new base: the pending-bytes counter
            // resets to this snapshot's size (the segment's base is gone).
            self.pending_bytes = c.bytes;
        }
        self.pending = Some(c);
    }

    /// Clear state after a successful publish. Called by the uploader.
    pub fn clear_after_publish(&mut self) {
        self.pending = None;
        self.first_dirty_at = None;
        self.pending_bytes = 0;
        self.needs_bootstrap = false;
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
    let Some(capture) = st.pending.as_ref() else {
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
        let mut st = DbState::default();
        st.needs_bootstrap = true;
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
        assert_eq!(st.pending_bytes, 30);
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
    fn clear_after_publish_resets_state() {
        let t0 = Instant::now();
        let mut st = DbState::default();
        st.mark_capture(capture(1, "cid", CaptureKindTag::Wal, 10), t0);
        st.needs_bootstrap = true;
        st.clear_after_publish();
        assert!(st.pending.is_none());
        assert!(st.first_dirty_at.is_none());
        assert_eq!(st.pending_bytes, 0);
        assert!(!st.needs_bootstrap);
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

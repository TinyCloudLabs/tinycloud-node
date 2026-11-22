//! Capture-hook ingress: the `ShadowSink` implementation the node
//! installs on `SqlService` that marks a database dirty in the uploader's
//! `RunState` and parks the newest capture on the DB's pending slot.
//!
//! The capture hook already runs inside `persist_write`'s per-DB
//! operation lock, after the save committed. This module is the thin
//! wrapper that takes the `Capture` from the hook, applies the rules
//! from the planner module (newest capture wins; a Checkpoint supersedes
//! a Wal), and bumps the per-DB `first_dirty_at`. It never blocks the
//! hook: the per-DB Mutex in the `RunState` is a tokio async Mutex, so
//! writes happen off the hook via `tokio::runtime::Handle::current().
//! spawn(...)`, with a channel-less handoff that costs one `try_lock`
//! acquire.
//!
//! For the uploader's test harness the ingress is `Send + Sync` and
//! holds only `Arc`s; wire-level fakes substitute for the live
//! `SqlService::with_shadow` seam.
//!
//! TC-1491.

use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;

use super::runloop::{DbKey, RunState};
use super::state::{CaptureKindTag, CapturePlan};
use super::{Capture, CaptureKind, ShadowSink};

/// The sink that translates captures into per-DB `DbState` mutations.
pub struct IngressSink {
    pub run_state: Arc<RunState>,
}

impl IngressSink {
    pub fn new(run_state: Arc<RunState>) -> Self {
        Self { run_state }
    }

    fn as_plan(capture: &Capture) -> CapturePlan {
        CapturePlan {
            revision: capture.revision,
            cid: capture.cid.clone(),
            kind: match capture.kind {
                CaptureKind::Wal(_) => CaptureKindTag::Wal,
                CaptureKind::Checkpoint(_) => CaptureKindTag::Checkpoint,
            },
            bytes: match &capture.kind {
                CaptureKind::Wal(b) | CaptureKind::Checkpoint(b) => b.len() as u64,
            },
        }
    }
}

impl ShadowSink for IngressSink {
    fn wants(&self, space: &str) -> bool {
        self.run_state.allowlist.contains(space)
    }

    fn captured(&self, capture: Capture) {
        let key: DbKey = (capture.space.clone(), capture.db_id.clone());
        let plan = Self::as_plan(&capture);
        let bytes: Bytes = match capture.kind {
            CaptureKind::Wal(b) | CaptureKind::Checkpoint(b) => b,
        };
        let run_state = Arc::clone(&self.run_state);
        let now = Instant::now();
        // Spawn the mutation so the hook returns immediately. On a
        // closed runtime (shutdown) the spawn fails silently; the
        // uploader is already draining.
        let Some(handle) = tokio::runtime::Handle::try_current().ok() else {
            return;
        };
        // `spawn` returns a JoinHandle; dropping it detaches the task,
        // which is what we want here (the task outlives the hook).
        drop(handle.spawn(async move {
            // Keep the bytes alive so the closure's lifetime is clear.
            let _body = bytes;
            run_state
                .upsert(key, |st| {
                    st.mark_capture(plan, now);
                })
                .await;
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn allowed(space: &str) -> BTreeSet<String> {
        [space.to_string()].into_iter().collect()
    }

    fn capture(space: &str, db_id: &str, revision: i64, cid: &str) -> Capture {
        Capture {
            space: space.into(),
            db_id: db_id.into(),
            revision,
            cid: cid.into(),
            kind: CaptureKind::Wal(Bytes::from_static(b"wal")),
        }
    }

    #[tokio::test]
    async fn wants_mirrors_the_allowlist() {
        let run_state = Arc::new(RunState::new(8, 2, allowed("space-a")));
        let sink = IngressSink::new(run_state);
        assert!(sink.wants("space-a"));
        assert!(!sink.wants("space-b"));
    }

    #[tokio::test]
    async fn captured_marks_the_db_dirty_on_the_run_state() {
        let run_state = Arc::new(RunState::new(8, 2, allowed("space-a")));
        let sink = IngressSink::new(Arc::clone(&run_state));
        sink.captured(capture("space-a", "main", 7, "cid-a"));
        // Let the spawned mutation run.
        for _ in 0..50 {
            if run_state
                .states
                .get(&("space-a".to_string(), "main".to_string()))
                .is_some()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        let entry = run_state
            .states
            .get(&("space-a".to_string(), "main".to_string()))
            .expect("the ingress inserted the state");
        let st = entry.value().lock().await;
        assert!(
            st.first_dirty_at.is_some(),
            "capture must set first_dirty_at"
        );
        assert_eq!(
            st.next_to_publish().map(|c| c.revision),
            Some(7),
            "pending capture must carry the captured revision"
        );
    }

    #[tokio::test]
    async fn captured_outside_the_runtime_is_a_no_op() {
        // No runtime: construct a run_state, then drop into a non-
        // async context.
        let run_state = Arc::new(RunState::new(8, 2, allowed("space-a")));
        let sink = IngressSink::new(Arc::clone(&run_state));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            // No tokio runtime on this thread.
            sink.captured(capture("space-a", "main", 1, "cid"));
            tx.send(()).unwrap();
        })
        .join()
        .ok();
        rx.recv().unwrap();
        // The state should NOT have been touched (no runtime to spawn on).
        assert!(run_state.states.is_empty());
    }
}

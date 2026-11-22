//! The SQL-store shadow uploader (TC-1491 P1).
//!
//! The save hook in `SqlService::persist_write` hands a [`Notice`] (space,
//! database, revision, checkpoint cid) to a [`ShadowSink`] after Postgres
//! accepted the save. It carries no bytes, never fails and never blocks: the
//! uploader pulls the payload from Postgres itself ([`source::ShadowSource`])
//! when the database's [`machine::DbMachine`] decides to upload.
//!
//! - `machine`: the pure per-database state machine and the publish planner.
//! - `source`: where the checkpoint and WAL are read from (`PgArtifactSource`).
//! - `budget`: scratch-disk reservations for streamed uploads.
//! - `scan`: the durable lag scan (artifact head vs manifest frontier).
//! - `scheduler`: the one task that steps the machines, runs uploads and drains.
//! - `restore`: the restore check (P2): rebuild a database from its frontier
//!   and compare it with Postgres at the same revision.
//!
//! `NoopSink` is the default; every `SqlService` holds one unless the node
//! runtime builds a shadow handle and calls `SqlService::with_shadow`.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};

pub mod budget;
pub mod machine;
pub mod metrics;
pub mod owner;
pub mod restore;
pub mod scan;
pub mod scheduler;
pub mod source;

pub use metrics::{NoticeResult, PublishResult, ShadowMetrics, UploadResult};

/// One durable save, as the hook saw it on the `Ok` arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub space: String,
    pub db_id: String,
    /// The revision the save landed as.
    pub revision: i64,
    /// The artifact's `checkpoint_content_hash` after the save.
    pub cid: String,
}

/// The save hook's seam. `notify` runs inside the per-database operation
/// lock: it must be synchronous, infallible and non-blocking.
pub trait ShadowSink: Send + Sync {
    fn notify(&self, notice: Notice);
}

/// Zero-cost default sink.
#[derive(Debug, Default)]
pub struct NoopSink;

impl ShadowSink for NoopSink {
    fn notify(&self, _notice: Notice) {}
}

/// `(space, db_id)`.
pub type DbKey = (String, String);

/// The real hook sink: a max-merge of the newest head per allowlisted
/// database, drained by the scheduler, plus a wake-up ping.
pub struct NoticeBoard {
    allowlist: super::policy::SpaceAllowlist,
    dirty: Mutex<HashMap<DbKey, machine::Head>>,
    wake: tokio::sync::Notify,
    metrics: std::sync::Arc<dyn ShadowMetrics>,
}

impl NoticeBoard {
    pub fn new(
        allowlist: super::policy::SpaceAllowlist,
        metrics: std::sync::Arc<dyn ShadowMetrics>,
    ) -> Self {
        Self {
            allowlist,
            dirty: Mutex::default(),
            wake: tokio::sync::Notify::new(),
            metrics,
        }
    }

    pub fn allowlist(&self) -> &super::policy::SpaceAllowlist {
        &self.allowlist
    }

    /// Everything notified since the last call.
    pub fn take(&self) -> HashMap<DbKey, machine::Head> {
        std::mem::take(&mut *self.dirty.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Resolves after the next `notify` (or immediately if one is pending).
    pub async fn notified(&self) {
        self.wake.notified().await
    }

    /// Wake the scheduler without a notice (shutdown).
    pub fn wake(&self) {
        self.wake.notify_one();
    }
}

impl ShadowSink for NoticeBoard {
    fn notify(&self, notice: Notice) {
        if !self.allowlist.allows(&notice.space) {
            self.metrics.notice(NoticeResult::Disallowed);
            return;
        }
        let head = machine::Head {
            revision: notice.revision,
            cid: notice.cid,
        };
        {
            let mut dirty = self.dirty.lock().unwrap_or_else(PoisonError::into_inner);
            let slot = dirty.entry((notice.space, notice.db_id));
            match slot {
                std::collections::hash_map::Entry::Occupied(mut held) => {
                    if head.revision >= held.get().revision {
                        held.insert(head);
                    }
                }
                std::collections::hash_map::Entry::Vacant(free) => {
                    free.insert(head);
                }
            }
        }
        self.metrics.notice(NoticeResult::Accepted);
        self.wake.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn notice(space: &str, revision: i64, cid: &str) -> Notice {
        Notice {
            space: space.into(),
            db_id: "main".into(),
            revision,
            cid: cid.into(),
        }
    }

    #[test]
    fn noop_sink_accepts_anything() {
        NoopSink.notify(notice("x", 1, "c"));
    }

    #[test]
    fn notice_board_max_merges_allowlisted_spaces_only() {
        let board = NoticeBoard::new(
            super::super::policy::SpaceAllowlist::new(["a".to_string()]),
            Arc::new(metrics::NoopMetrics),
        );
        board.notify(notice("a", 3, "c3"));
        board.notify(notice("a", 2, "c2"));
        board.notify(notice("b", 9, "c9"));
        let taken = board.take();
        assert_eq!(taken.len(), 1);
        assert_eq!(
            taken[&("a".to_string(), "main".to_string())],
            machine::Head {
                revision: 3,
                cid: "c3".into()
            }
        );
        assert!(board.take().is_empty(), "take drains");
    }

    #[tokio::test]
    async fn notify_wakes_the_scheduler() {
        let board = NoticeBoard::new(
            super::super::policy::SpaceAllowlist::new(["a".to_string()]),
            Arc::new(metrics::NoopMetrics),
        );
        board.notify(notice("a", 1, "c"));
        tokio::time::timeout(std::time::Duration::from_secs(1), board.notified())
            .await
            .expect("a stored permit wakes the waiter");
    }
}

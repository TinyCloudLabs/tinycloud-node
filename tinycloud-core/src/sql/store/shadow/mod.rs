//! The shadow uploader's capture seam and spool types.
//!
//! The capture hook (in `SqlService::persist_write`) hands the bytes it has
//! already written to Postgres to a [`ShadowSink`]. In the shadow phase
//! this is the only moment those bytes exist outside Postgres, so capturing
//! them here avoids a second read from Postgres. The sink's `captured` is
//! non-blocking: it does a bounded `try_send` onto the uploader's channel
//! and sheds on full.
//!
//! The planner, spool and uploader live in sibling modules. Nothing in this
//! module performs I/O on its own.
//!
//! `NoopSink` is the default; every `SqlService` holds one unless the node
//! runtime builds a `ShadowHandle` and calls [`SqlService::with_shadow`].
//! When `[sql_store] enabled = false` the service never leaves `NoopSink`,
//! no task is spawned, and `persist_write` loses nothing beyond the one
//! `wants()` call that returns false before any byte is cloned.
//!
//! TC-1491.

use bytes::Bytes;

pub mod metrics;
pub mod owner;
pub mod state;

pub use metrics::{CaptureResult, PublishResult, ShadowMetrics, UploadResult};
pub use state::{plan, Action, DbState, UploadPolicy};

/// The bytes a capture carries, together with its kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureKind {
    /// Cumulative WAL since the base checkpoint (format `wal-cum-v1`).
    Wal(Bytes),
    /// A full SQLite checkpoint (format `sqlite-v1`).
    Checkpoint(Bytes),
}

impl CaptureKind {
    pub fn as_bytes(&self) -> &Bytes {
        match self {
            Self::Wal(b) | Self::Checkpoint(b) => b,
        }
    }

    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }

    pub fn is_empty(&self) -> bool {
        self.as_bytes().is_empty()
    }

    /// Metric label; never leaks bytes or identifiers.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Wal(_) => "wal",
            Self::Checkpoint(_) => "checkpoint",
        }
    }
}

/// One commit's worth of bytes handed from the capture hook to the uploader.
///
/// The hook must have observed `persist_write` return `Ok`, so `revision` and
/// `cid` are what Postgres durably recorded for this save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capture {
    pub space: String,
    pub db_id: String,
    /// The revision this save landed as, from `saved.revision`.
    pub revision: i64,
    /// For a delta, the `checkpoint_content_hash` the WAL rides on.
    /// For a checkpoint, `saved.checkpoint_content_hash`.
    pub cid: String,
    pub kind: CaptureKind,
}

impl Capture {
    /// Bytes this capture occupies in the spool's accounting.
    pub fn byte_len(&self) -> usize {
        self.kind.len()
    }
}

/// The capture hook's seam. The implementation decides whether this space is
/// uploading (`wants`) and takes a copy if it is (`captured`).
///
/// Implementations must be cheap in both calls: `wants` is consulted before
/// any copy, and `captured` runs inside the per-DB operation lock. An
/// uploader implementation does a bounded `try_send` and returns immediately.
pub trait ShadowSink: Send + Sync {
    /// Whether this space is in the allowlist and the sink is still open. The
    /// hook calls this first and skips the copy when the answer is false, so
    /// an off flag, an empty allowlist or an open breaker leaves no bytes
    /// cloned.
    fn wants(&self, space: &str) -> bool;

    /// Deliver one capture. Must not block, must not `.await` beyond a
    /// bounded `try_send`; a full channel sheds (counted, never refused).
    fn captured(&self, capture: Capture);
}

/// Zero-cost default sink: `wants` is always false, `captured` never runs
/// because the hook does not reach it.
#[derive(Debug, Default)]
pub struct NoopSink;

impl ShadowSink for NoopSink {
    fn wants(&self, _space: &str) -> bool {
        false
    }

    fn captured(&self, _capture: Capture) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    #[test]
    fn noop_sink_never_wants_anything_and_captured_is_a_no_op() {
        let sink = NoopSink;
        assert!(!sink.wants("tinycloud:pkh:eip155:1:0x00:default"));
        sink.captured(Capture {
            space: "x".into(),
            db_id: "y".into(),
            revision: 1,
            cid: "cid".into(),
            kind: CaptureKind::Wal(Bytes::from_static(b"wal")),
        });
    }

    #[test]
    fn capture_kind_labels_and_byte_lengths_match_their_payload() {
        let wal = CaptureKind::Wal(Bytes::from_static(b"1234"));
        let snap = CaptureKind::Checkpoint(Bytes::from_static(b"12345678"));
        assert_eq!(wal.label(), "wal");
        assert_eq!(snap.label(), "checkpoint");
        assert_eq!(wal.len(), 4);
        assert_eq!(snap.len(), 8);
        assert!(!wal.is_empty());
    }

    /// A deliberately minimal sink that records every call; used by the
    /// capture-path tests in `service.rs`.
    #[derive(Debug, Default)]
    pub(crate) struct CountingSink {
        pub(crate) allow: Mutex<Vec<String>>,
        pub(crate) wants_calls: AtomicUsize,
        pub(crate) captured: Mutex<Vec<Capture>>,
    }

    impl CountingSink {
        pub(crate) fn allowing<I: IntoIterator<Item = String>>(spaces: I) -> Self {
            Self {
                allow: Mutex::new(spaces.into_iter().collect()),
                ..Self::default()
            }
        }
    }

    impl ShadowSink for CountingSink {
        fn wants(&self, space: &str) -> bool {
            self.wants_calls.fetch_add(1, Ordering::Relaxed);
            self.allow.lock().unwrap().iter().any(|s| s == space)
        }
        fn captured(&self, capture: Capture) {
            self.captured.lock().unwrap().push(capture);
        }
    }

    #[test]
    fn counting_sink_respects_its_allowlist() {
        let sink = CountingSink::allowing(["a".to_string()]);
        assert!(sink.wants("a"));
        assert!(!sink.wants("b"));
        assert_eq!(sink.wants_calls.load(Ordering::Relaxed), 2);
    }
}

pub mod bootstrap;
pub mod drain;
#[cfg(feature = "sql-store-failpoints")]
pub mod failpoints;
pub mod reconciler;
pub mod restore;
pub mod runloop;
pub mod sweep;
pub mod uploader;

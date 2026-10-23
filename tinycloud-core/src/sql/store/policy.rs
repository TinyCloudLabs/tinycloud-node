//! Upload and retention policy (TC-1491 contract, section 5). Data and pure
//! decisions only: nothing here uploads or deletes.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::{Duration, Instant},
};

/// When a database's un-uploaded commits become due, and when the node-wide
/// backlog is too large.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadPolicy {
    /// Upload this long after a database's first un-uploaded commit.
    pub interval: Duration,
    /// Or as soon as this many bytes are pending, checked between transactions.
    pub max_bytes: u64,
    /// Node-wide un-uploaded bytes at which the spool sheds (shadow phase) or
    /// writes are refused (`enforce_backlog_cap`, store-master).
    pub backlog_cap: u64,
    /// Cut a fresh snapshot at most this often.
    pub snapshot_every: Duration,
    /// An `uploaded` object older than this and unreferenced may be marked
    /// `orphan`.
    pub orphan_after: Duration,
    /// Refuse writes at the cap. Off in the shadow phase.
    pub enforce_backlog_cap: bool,
}

impl Default for UploadPolicy {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(60),
            max_bytes: 8 * 1024 * 1024,
            backlog_cap: 64 * 1024 * 1024,
            snapshot_every: Duration::from_secs(24 * 60 * 60),
            orphan_after: Duration::from_secs(24 * 60 * 60),
            enforce_backlog_cap: false,
        }
    }
}

/// What the uploader knows about one database's un-uploaded commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PendingState {
    /// When the oldest un-uploaded commit happened; `None` when idle.
    pub first_commit_at: Option<Instant>,
    pub bytes: u64,
}

impl UploadPolicy {
    /// An idle database (no pending commit) is never due.
    pub fn due(&self, pending: &PendingState, now: Instant) -> bool {
        let Some(first) = pending.first_commit_at else {
            return false;
        };
        pending.bytes >= self.max_bytes || now.saturating_duration_since(first) >= self.interval
    }

    pub fn backlog_exceeded(&self, total_pending_bytes: u64) -> bool {
        total_pending_bytes >= self.backlog_cap
    }

    /// A snapshot is due when none exists, or the last is `snapshot_every` old.
    pub fn snapshot_due(&self, since_last_snapshot: Option<Duration>) -> bool {
        since_last_snapshot.is_none_or(|age| age >= self.snapshot_every)
    }
}

/// Per-tier history window. Absent means keep all (the default until the tier
/// numbers are confirmed). Nothing deletes in the funded phase.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RetentionPolicy {
    default_days: Option<u32>,
    per_tier: BTreeMap<String, u32>,
}

impl RetentionPolicy {
    pub fn new(default_days: Option<u32>, per_tier: BTreeMap<String, u32>) -> Self {
        Self {
            default_days,
            per_tier,
        }
    }

    /// Days of history to keep for `tier`; `None` keeps everything.
    pub fn history_days(&self, tier: &str) -> Option<u32> {
        self.per_tier.get(tier).copied().or(self.default_days)
    }
}

/// Fail-closed allowlist (R8): empty means no space uploads.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpaceAllowlist(BTreeSet<String>);

impl SpaceAllowlist {
    pub fn new<I: IntoIterator<Item = String>>(spaces: I) -> Self {
        Self(spaces.into_iter().collect())
    }
    pub fn allows(&self, space: &str) -> bool {
        self.0.contains(space)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_60s_8mib() {
        let p = UploadPolicy::default();
        assert_eq!(p.interval, Duration::from_secs(60));
        assert_eq!(p.max_bytes, 8 * 1024 * 1024);
        assert!(!p.enforce_backlog_cap);
    }

    #[test]
    fn idle_database_is_never_due() {
        let p = UploadPolicy::default();
        let now = Instant::now();
        assert!(!p.due(&PendingState::default(), now + Duration::from_secs(3600)));
        // Bytes without a commit time cannot happen, but are still not due.
        assert!(!p.due(
            &PendingState {
                first_commit_at: None,
                bytes: u64::MAX
            },
            now
        ));
    }

    #[test]
    fn due_by_interval_or_by_size() {
        let p = UploadPolicy::default();
        let t0 = Instant::now();
        let pending = |bytes| PendingState {
            first_commit_at: Some(t0),
            bytes,
        };
        assert!(!p.due(&pending(1), t0 + Duration::from_secs(59)));
        assert!(p.due(&pending(1), t0 + Duration::from_secs(60)));
        assert!(!p.due(&pending(p.max_bytes - 1), t0));
        assert!(p.due(&pending(p.max_bytes), t0));
    }

    #[test]
    fn backlog_and_snapshot_thresholds() {
        let p = UploadPolicy::default();
        assert!(!p.backlog_exceeded(p.backlog_cap - 1));
        assert!(p.backlog_exceeded(p.backlog_cap));
        assert!(p.snapshot_due(None));
        assert!(!p.snapshot_due(Some(Duration::from_secs(10))));
        assert!(p.snapshot_due(Some(p.snapshot_every)));
    }

    #[test]
    fn retention_defaults_to_keep_all() {
        let none = RetentionPolicy::default();
        assert_eq!(none.history_days("free"), None);
        let policy = RetentionPolicy::new(None, [("free".to_string(), 7)].into());
        assert_eq!(policy.history_days("free"), Some(7));
        assert_eq!(policy.history_days("paid"), None);
        let with_default = RetentionPolicy::new(Some(30), [("free".to_string(), 7)].into());
        assert_eq!(with_default.history_days("paid"), Some(30));
        assert_eq!(with_default.history_days("free"), Some(7));
    }

    #[test]
    fn empty_allowlist_allows_nothing() {
        assert!(!SpaceAllowlist::default().allows("tinycloud:x"));
        let list = SpaceAllowlist::new(["tinycloud:x".to_string()]);
        assert!(list.allows("tinycloud:x"));
        assert!(!list.allows("tinycloud:y"));
    }
}

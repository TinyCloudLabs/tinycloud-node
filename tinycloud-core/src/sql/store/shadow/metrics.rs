//! Shadow-uploader metric names and label values. No space ID, DID,
//! database ID, key, object key or payload byte ever appears here. TC-1491.
//!
//! The Prometheus registration lives with the node; this file holds only the
//! names, the fixed label value sets and the sink trait, so the registration
//! cannot drift from the names the uploader emits.

/// Counter: `sql_store_notices_total{result}`.
pub const NOTICES_TOTAL: &str = "sql_store_notices_total";
/// Counter: `sql_store_uploads_total{kind,result}`.
pub const UPLOADS_TOTAL: &str = "sql_store_uploads_total";
/// Counter: `sql_store_uploaded_bytes_total{kind}`.
pub const UPLOADED_BYTES_TOTAL: &str = "sql_store_uploaded_bytes_total";
/// Counter: `sql_store_publish_total{result}`.
pub const PUBLISH_TOTAL: &str = "sql_store_publish_total";
/// Counter: `sql_store_blocked_total{reason}`.
pub const BLOCKED_TOTAL: &str = "sql_store_blocked_total";
/// Counter: `sql_store_regressions_total`: the lag scan saw PG below the
/// published frontier (a PG restore); the database blocks.
pub const REGRESSIONS_TOTAL: &str = "sql_store_regressions_total";
/// Counter: `sql_store_owner_marker_total{result}`.
pub const OWNER_MARKER_TOTAL: &str = "sql_store_owner_marker_total";
/// Gauge: `sql_store_dirty_databases`.
pub const DIRTY_DATABASES: &str = "sql_store_dirty_databases";
/// Gauge: `sql_store_oldest_dirty_age_seconds`.
pub const OLDEST_DIRTY_AGE_SECONDS: &str = "sql_store_oldest_dirty_age_seconds";
/// Gauge: `sql_store_inflight_bytes`.
pub const INFLIGHT_BYTES: &str = "sql_store_inflight_bytes";
/// Gauge: `sql_store_breaker_open`.
pub const BREAKER_OPEN: &str = "sql_store_breaker_open";
/// Histogram: `sql_store_cycle_seconds{stage}`.
pub const CYCLE_SECONDS: &str = "sql_store_cycle_seconds";

/// Counter: `sql_store_restore_checks_total{result}`, one per database the
/// restore check (`restore`) looked at.
pub const RESTORE_CHECKS_TOTAL: &str = "sql_store_restore_checks_total";
/// Counter: `sql_store_restore_segments_unverified_total`: segments a
/// frontier needs that the restore check did not read and replay.
pub const RESTORE_SEGMENTS_UNVERIFIED_TOTAL: &str = "sql_store_restore_segments_unverified_total";
/// Histogram: `sql_store_restore_check_seconds`, per database.
pub const RESTORE_CHECK_SECONDS: &str = "sql_store_restore_check_seconds";

/// Values of the `result` label on `sql_store_notices_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeResult {
    Accepted,
    Disallowed,
}

impl NoticeResult {
    pub fn label(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Disallowed => "disallowed",
        }
    }
}

/// Values of the `result` label on `sql_store_uploads_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadResult {
    Ok,
    /// The source moved on or failed; retried with backoff.
    SourceError,
    StoreError,
    CasLost,
    Blocked,
}

impl UploadResult {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::SourceError => "source_error",
            Self::StoreError => "store_error",
            Self::CasLost => "cas_lost",
            Self::Blocked => "blocked",
        }
    }
}

/// Values of the `result` label on `sql_store_publish_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PublishResult {
    Published,
    Lost,
    Failed,
}

impl PublishResult {
    pub fn label(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Lost => "lost",
            Self::Failed => "failed",
        }
    }
}

/// The restore check's verdict on one database; also the `result` label on
/// `sql_store_restore_checks_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreResult {
    /// Restored at the frontier, sound, and equal to Postgres's artifact at
    /// the same revision.
    Ok,
    /// Restored and sound, but not equal to Postgres's artifact.
    Mismatch,
    /// Postgres is not at the frontier's revision (or moved on mid-check):
    /// nothing was compared.
    NotComparable,
    /// The frontier could not be restored, or a copy was refused or unsound.
    Unreadable,
}

impl RestoreResult {
    pub const ALL: [Self; 4] = [
        Self::Ok,
        Self::Mismatch,
        Self::NotComparable,
        Self::Unreadable,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Mismatch => "mismatch",
            Self::NotComparable => "not_comparable",
            Self::Unreadable => "unreadable",
        }
    }
}

/// The uploader's metrics sink. In tests an in-memory implementation counts
/// calls; in production the node wires it to Prometheus.
pub trait ShadowMetrics: Send + Sync {
    fn notice(&self, result: NoticeResult);
    /// `kind` is a `machine::Work` label.
    fn upload(&self, kind: &'static str, result: UploadResult, bytes: u64);
    fn publish(&self, result: PublishResult);
    /// `reason` is a `machine::BlockReason` label.
    fn blocked(&self, reason: &'static str);
    fn regressed(&self);
    fn owner_marker(&self, result: &'static str);
    fn dirty_databases(&self, count: u64);
    fn oldest_dirty_age_seconds(&self, seconds: f64);
    fn inflight_bytes(&self, bytes: u64);
    fn breaker_open(&self, open: bool);
    fn record_cycle_seconds(&self, stage: &'static str, seconds: f64);
}

/// Null implementation; drops every call.
#[derive(Debug, Default)]
pub struct NoopMetrics;

impl ShadowMetrics for NoopMetrics {
    fn notice(&self, _: NoticeResult) {}
    fn upload(&self, _: &'static str, _: UploadResult, _: u64) {}
    fn publish(&self, _: PublishResult) {}
    fn blocked(&self, _: &'static str) {}
    fn regressed(&self) {}
    fn owner_marker(&self, _: &'static str) {}
    fn dirty_databases(&self, _: u64) {}
    fn oldest_dirty_age_seconds(&self, _: f64) {}
    fn inflight_bytes(&self, _: u64) {}
    fn breaker_open(&self, _: bool) {}
    fn record_cycle_seconds(&self, _: &'static str, _: f64) {}
}

/// The restore check's metrics sink (the check is not the uploader, so it
/// has its own).
pub trait RestoreMetrics: Send + Sync {
    fn restore_check(&self, result: RestoreResult, segments_unverified: u64, seconds: f64);
}

impl RestoreMetrics for NoopMetrics {
    fn restore_check(&self, _: RestoreResult, _: u64, _: f64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notice_result_labels_are_the_contract_vocabulary() {
        for (v, l) in [
            (NoticeResult::Accepted, "accepted"),
            (NoticeResult::Disallowed, "disallowed"),
        ] {
            assert_eq!(v.label(), l);
        }
    }

    #[test]
    fn upload_result_labels_are_the_contract_vocabulary() {
        for (v, l) in [
            (UploadResult::Ok, "ok"),
            (UploadResult::SourceError, "source_error"),
            (UploadResult::StoreError, "store_error"),
            (UploadResult::CasLost, "cas_lost"),
            (UploadResult::Blocked, "blocked"),
        ] {
            assert_eq!(v.label(), l);
        }
    }

    #[test]
    fn publish_result_labels_are_the_contract_vocabulary() {
        for (v, l) in [
            (PublishResult::Published, "published"),
            (PublishResult::Lost, "lost"),
            (PublishResult::Failed, "failed"),
        ] {
            assert_eq!(v.label(), l);
        }
    }

    #[test]
    fn restore_result_labels_match_their_serialised_form() {
        for (v, l) in [
            (RestoreResult::Ok, "ok"),
            (RestoreResult::Mismatch, "mismatch"),
            (RestoreResult::NotComparable, "not_comparable"),
            (RestoreResult::Unreadable, "unreadable"),
        ] {
            assert_eq!(v.label(), l);
            assert_eq!(serde_json::to_string(&v).unwrap(), format!("\"{l}\""));
        }
        assert_eq!(RestoreResult::ALL.len(), 4);
        RestoreMetrics::restore_check(&NoopMetrics, RestoreResult::Ok, 0, 0.1);
    }

    #[test]
    fn noop_metrics_never_panic_on_any_entrypoint() {
        let m = NoopMetrics;
        m.notice(NoticeResult::Accepted);
        m.upload("segment", UploadResult::Ok, 100);
        m.publish(PublishResult::Published);
        m.blocked("regressed");
        m.regressed();
        m.owner_marker("ok");
        m.dirty_databases(1);
        m.oldest_dirty_age_seconds(1.0);
        m.inflight_bytes(1);
        m.breaker_open(true);
        m.record_cycle_seconds("put", 0.1);
    }
}

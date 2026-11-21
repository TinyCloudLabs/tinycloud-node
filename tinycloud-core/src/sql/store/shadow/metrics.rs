//! Shadow-uploader metric names and label values. No space ID, DID,
//! database ID, key, object key or payload byte ever appears here. TC-1491.
//!
//! The actual Prometheus registration lives in the node server's
//! `prometheus.rs`-style module; this file holds only the names and the
//! fixed label value sets. The `log_label` helpers keep tracing calls
//! honest.
//!
//! The counters and gauges listed below are the ones the capture hook and
//! the uploader emit; the full registration (bootstrap totals, cycle
//! histograms, breaker gauge) rides with the uploader in later milestones.
//! Names and label vocabularies are pinned here so the registration code
//! cannot drift from what the contract documents.

/// Counter: `sql_store_captures_total{kind,result}`.
pub const CAPTURES_TOTAL: &str = "sql_store_captures_total";
/// Counter: `sql_store_uploads_total{kind,result}`.
pub const UPLOADS_TOTAL: &str = "sql_store_uploads_total";
/// Counter: `sql_store_uploaded_bytes_total{kind}`.
pub const UPLOADED_BYTES_TOTAL: &str = "sql_store_uploaded_bytes_total";
/// Counter: `sql_store_publish_total{result}`.
pub const PUBLISH_TOTAL: &str = "sql_store_publish_total";
/// Counter: `sql_store_shed_total`.
pub const SHED_TOTAL: &str = "sql_store_shed_total";
/// Counter: `sql_store_lineage_switch_regression_total`.
///
/// Incremented when the planner emits `Action::Switch` with
/// `capture.revision < frontier.last_seq`. The manifest's `LineageSwitch`
/// branch does not reject that regression itself, so the planner is the
/// one place that notices and counts it. A later slice tightens the
/// manifest; the counter stays.
pub const LINEAGE_SWITCH_REGRESSION_TOTAL: &str = "sql_store_lineage_switch_regression_total";
/// Counter: `sql_store_bootstrap_total{result}`.
pub const BOOTSTRAP_TOTAL: &str = "sql_store_bootstrap_total";
/// Counter: `sql_store_owner_marker_total{result}`.
pub const OWNER_MARKER_TOTAL: &str = "sql_store_owner_marker_total";
/// Counter: `sql_store_backlog_cap_exceeded_total`.
pub const BACKLOG_CAP_EXCEEDED_TOTAL: &str = "sql_store_backlog_cap_exceeded_total";
/// Gauge: `sql_store_backlog_bytes`.
pub const BACKLOG_BYTES: &str = "sql_store_backlog_bytes";
/// Gauge: `sql_store_spool_bytes`.
pub const SPOOL_BYTES: &str = "sql_store_spool_bytes";
/// Gauge: `sql_store_dirty_databases`.
pub const DIRTY_DATABASES: &str = "sql_store_dirty_databases";
/// Gauge: `sql_store_oldest_dirty_age_seconds`.
pub const OLDEST_DIRTY_AGE_SECONDS: &str = "sql_store_oldest_dirty_age_seconds";
/// Gauge: `sql_store_breaker_open`.
pub const BREAKER_OPEN: &str = "sql_store_breaker_open";
/// Histogram: `sql_store_cycle_seconds{stage}`.
pub const CYCLE_SECONDS: &str = "sql_store_cycle_seconds";

/// Values of the `result` label on `sql_store_captures_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureResult {
    Queued,
    Shed,
    NoAnchor,
    Disallowed,
}

impl CaptureResult {
    pub fn label(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Shed => "shed",
            Self::NoAnchor => "no_anchor",
            Self::Disallowed => "disallowed",
        }
    }
}

/// Values of the `result` label on `sql_store_uploads_total`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadResult {
    Ok,
    StoreError,
    CasLost,
    Blocked,
}

impl UploadResult {
    pub fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
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
    ObjectNotUploaded,
    Reconciled,
}

impl PublishResult {
    pub fn label(self) -> &'static str {
        match self {
            Self::Published => "published",
            Self::Lost => "lost",
            Self::ObjectNotUploaded => "object_not_uploaded",
            Self::Reconciled => "reconciled",
        }
    }
}

/// The uploader's shared metrics sink. In tests an in-memory implementation
/// counts calls; in production the node wires it to Prometheus.
pub trait ShadowMetrics: Send + Sync {
    fn capture(&self, kind: &'static str, result: CaptureResult);
    fn upload(&self, kind: &'static str, result: UploadResult, bytes: u64);
    fn publish(&self, result: PublishResult);
    fn shed(&self);
    /// Increments `sql_store_lineage_switch_regression_total` when the planner
    /// emits `Action::Switch` with `capture.revision < frontier.last_seq`.
    fn lineage_switch_regression(&self);
    fn owner_marker(&self, result: &'static str);
    fn backlog_bytes(&self, bytes: u64);
    fn spool_bytes(&self, bytes: u64);
    fn dirty_databases(&self, count: u64);
    fn oldest_dirty_age_seconds(&self, seconds: f64);
    fn breaker_open(&self, open: bool);
    fn record_cycle_seconds(&self, stage: &'static str, seconds: f64);
}

/// Null implementation; drops every call. Used by the capture hook's hot path
/// when no real sink is wired, so the hook never panics if the metric sink is
/// absent.
#[derive(Debug, Default)]
pub struct NoopMetrics;

impl ShadowMetrics for NoopMetrics {
    fn capture(&self, _: &'static str, _: CaptureResult) {}
    fn upload(&self, _: &'static str, _: UploadResult, _: u64) {}
    fn publish(&self, _: PublishResult) {}
    fn shed(&self) {}
    fn lineage_switch_regression(&self) {}
    fn owner_marker(&self, _: &'static str) {}
    fn backlog_bytes(&self, _: u64) {}
    fn spool_bytes(&self, _: u64) {}
    fn dirty_databases(&self, _: u64) {}
    fn oldest_dirty_age_seconds(&self, _: f64) {}
    fn breaker_open(&self, _: bool) {}
    fn record_cycle_seconds(&self, _: &'static str, _: f64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_result_labels_are_the_contract_vocabulary() {
        for (v, l) in [
            (CaptureResult::Queued, "queued"),
            (CaptureResult::Shed, "shed"),
            (CaptureResult::NoAnchor, "no_anchor"),
            (CaptureResult::Disallowed, "disallowed"),
        ] {
            assert_eq!(v.label(), l);
        }
    }

    #[test]
    fn upload_result_labels_are_the_contract_vocabulary() {
        for (v, l) in [
            (UploadResult::Ok, "ok"),
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
            (PublishResult::ObjectNotUploaded, "object_not_uploaded"),
            (PublishResult::Reconciled, "reconciled"),
        ] {
            assert_eq!(v.label(), l);
        }
    }

    #[test]
    fn noop_metrics_never_panic_on_any_entrypoint() {
        let m = NoopMetrics;
        m.capture("wal", CaptureResult::Queued);
        m.upload("snapshot", UploadResult::Ok, 100);
        m.publish(PublishResult::Published);
        m.shed();
        m.lineage_switch_regression();
        m.owner_marker("ok");
        m.backlog_bytes(1);
        m.spool_bytes(1);
        m.dirty_databases(1);
        m.oldest_dirty_age_seconds(1.0);
        m.breaker_open(true);
        m.record_cycle_seconds("put", 0.1);
    }
}

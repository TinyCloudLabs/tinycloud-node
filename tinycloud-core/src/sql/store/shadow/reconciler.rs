//! Reconciler: mark `uploaded` objects older than their retention as
//! `orphan`, and on the follow-up pass, mark every object in a
//! superseded lineage as `orphan` too.
//!
//! The reconciler is state-poll pure policy: given a database reference,
//! the current time, and an `orphan_after_secs` window, it computes the
//! `older_than` threshold the manifest's `mark_orphans` takes. Nothing
//! here opens a connection, reads a payload byte, or decides which
//! lineage is current. The caller — eventually the uploader run loop —
//! supplies the manifest handle and the per-database schedule.
//!
//! The orphan transition is a conditional update: `uploaded → orphan`
//! only when the row is still `uploaded` AND older than the threshold
//! AND not referenced by a published chain. A `published` row is never
//! touched. A `uploaded` row that has just been published between the
//! sweep and the mark is still marked `published` by the publish's own
//! conditional flip, and the reconciler's own WHERE clause is
//! `state = 'uploaded'`, so the two never collide.
//!
//! Slice 4's prefix delete reads the orphan set this reconciler
//! produces. Nothing in this module ever deletes an object.
//!
//! TC-1491.

use std::time::{Duration, SystemTime};

use time::{format_description::well_known::Rfc3339, OffsetDateTime};

/// The canonical form the manifest stores timestamps in
/// (`YYYY-MM-DDTHH:MM:SS.ffffffZ`). Public so callers can format their
/// own `older_than` values without re-deriving the format string.
pub const CANONICAL_TIMESTAMP_WIDTH: usize = 27;

/// The timestamp `mark_orphans`'s `older_than` parameter expects. Rows
/// with a `created_at` strictly less than this are candidates for the
/// `uploaded → orphan` transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrphanThreshold(String);

impl OrphanThreshold {
    /// The threshold `now - orphan_after`, formatted in the manifest's
    /// canonical form. `orphan_after` is expected to be shorter than the
    /// time since the Unix epoch; the production default is a day, so
    /// the production case is fine.
    pub fn new(now: SystemTime, orphan_after: Duration) -> Self {
        let offset = now
            .checked_sub(orphan_after)
            .unwrap_or(SystemTime::UNIX_EPOCH);
        let at = OffsetDateTime::from(offset);
        Self(canonical_format(at))
    }

    /// For tests that need a fixed threshold.
    pub fn from_rfc3339(text: &str) -> Option<Self> {
        OffsetDateTime::parse(text, &Rfc3339)
            .ok()
            .map(|at| Self(canonical_format(at)))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Fixed-width UTC form `YYYY-MM-DDTHH:MM:SS.ffffffZ`, matching the
/// manifest's own `canonical_format`.
fn canonical_format(at: OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:06}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second(),
        at.microsecond(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threshold_is_now_minus_the_window_in_canonical_form() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let th = OrphanThreshold::new(now, Duration::from_secs(24 * 60 * 60));
        // Deterministic math: 2_000_000_000 - 86400 seconds past the
        // epoch, in canonical form.
        let expected_secs = 2_000_000_000 - 86_400;
        let expected =
            canonical_format(OffsetDateTime::from_unix_timestamp(expected_secs as i64).unwrap());
        assert_eq!(th.as_str(), expected);
    }

    #[test]
    fn threshold_width_matches_the_canonical_timestamp_width() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(2_000_000_000);
        let th = OrphanThreshold::new(now, Duration::from_secs(60));
        assert_eq!(th.as_str().len(), CANONICAL_TIMESTAMP_WIDTH);
    }

    #[test]
    fn threshold_from_rfc3339_round_trips() {
        let th = OrphanThreshold::from_rfc3339("2026-11-22T00:00:00Z").unwrap();
        assert_eq!(th.as_str(), "2026-11-22T00:00:00.000000Z");
    }

    #[test]
    fn threshold_width_constant_matches_the_format_length() {
        let s = "2026-11-22T00:00:00.000000Z";
        assert_eq!(s.len(), CANONICAL_TIMESTAMP_WIDTH);
    }
}

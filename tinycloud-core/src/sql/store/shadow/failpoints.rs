//! Failpoint harness for the kill -9 tests.
//!
//! Compiled out in production builds (`sql-store-failpoints` feature).
//! The uploader's publish cycle checks a process-wide failpoint registry
//! at four points: `after_put`, `after_record`, `before_cas` and
//! `after_cas`. When a point is armed with a `Panic` action the uploader
//! panics in place, which kills the current node process so the crash
//! matrix in the private design note can be exercised against a real
//! binary.
//!
//! The registry is set from the environment
//! (`TINYCLOUD_SQL_STORE_FAILPOINT=after_put`) and from tests that arm a
//! single-shot failpoint. A `OneShot` arm is cleared on first trigger so
//! a fault-injection test never leaks into the next.
//!
//! TC-1491.

use std::sync::atomic::{AtomicU8, Ordering};

/// The four points where the uploader's publish cycle may be
/// deterministically cut short. See 1b-design §5.2 for the full matrix.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Point {
    AfterPut = 1,
    AfterRecord = 2,
    BeforeCas = 3,
    AfterCas = 4,
}

impl Point {
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "after_put" => Some(Self::AfterPut),
            "after_record" => Some(Self::AfterRecord),
            "before_cas" => Some(Self::BeforeCas),
            "after_cas" => Some(Self::AfterCas),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::AfterPut => "after_put",
            Self::AfterRecord => "after_record",
            Self::BeforeCas => "before_cas",
            Self::AfterCas => "after_cas",
        }
    }
}

static ARMED: AtomicU8 = AtomicU8::new(0);

/// Arm `point` to panic on the next hit. Returns the previously armed
/// point, if any.
pub fn arm(point: Point) -> Option<Point> {
    let previous = ARMED.swap(point as u8, Ordering::SeqCst);
    decode(previous)
}

/// Clear any armed failpoint.
pub fn disarm() -> Option<Point> {
    let previous = ARMED.swap(0, Ordering::SeqCst);
    decode(previous)
}

/// Read and clear the armed point. Used by the uploader at each cycle
/// point.
pub fn take() -> Option<Point> {
    disarm()
}

/// If the armed point is `point`, clear it and `panic!`. Otherwise do
/// nothing.
pub fn hit(point: Point) {
    if let Some(armed) = take() {
        if armed == point {
            panic!("tinycloud::sql_store failpoint hit at {}", point.as_str());
        } else {
            // Not this point: re-arm so the right one still fires.
            arm(armed);
        }
    }
}

fn decode(byte: u8) -> Option<Point> {
    match byte {
        1 => Some(Point::AfterPut),
        2 => Some(Point::AfterRecord),
        3 => Some(Point::BeforeCas),
        4 => Some(Point::AfterCas),
        _ => None,
    }
}

/// Arm from the environment variable
/// `TINYCLOUD_SQL_STORE_FAILPOINT`. Called at process startup; silently
/// ignores an unset or unknown value.
pub fn arm_from_env() {
    if let Ok(value) = std::env::var("TINYCLOUD_SQL_STORE_FAILPOINT") {
        if let Some(point) = Point::parse(&value) {
            arm(point);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    /// The failpoint registry is a process-wide atomic, so tests that
    /// touch it hold a shared lock to serialise against each other. The
    /// guard also disarms any leftover point on drop so a failed test
    /// does not leak state into the next.
    fn guard() -> impl Drop {
        struct Guard<'a>(#[allow(dead_code)] std::sync::MutexGuard<'a, ()>);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                let _ = disarm();
                std::env::remove_var("TINYCLOUD_SQL_STORE_FAILPOINT");
            }
        }
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let m = LOCK.get_or_init(|| Mutex::new(()));
        Guard(m.lock().unwrap_or_else(|e| e.into_inner()))
    }

    #[test]
    fn arm_sets_the_point_and_disarm_clears_it() {
        let _g = guard();
        assert_eq!(arm(Point::AfterPut), None);
        assert_eq!(disarm(), Some(Point::AfterPut));
        assert_eq!(take(), None);
    }

    #[test]
    fn point_parse_matches_as_str() {
        let _g = guard();
        for p in [
            Point::AfterPut,
            Point::AfterRecord,
            Point::BeforeCas,
            Point::AfterCas,
        ] {
            assert_eq!(Point::parse(p.as_str()), Some(p));
        }
        assert_eq!(Point::parse("unknown"), None);
    }

    #[test]
    fn hit_panics_only_at_the_armed_point() {
        let _g = guard();
        arm(Point::BeforeCas);

        // Hitting a different point is a no-op; the armed point persists.
        hit(Point::AfterPut);
        assert_eq!(take(), Some(Point::BeforeCas));

        // Hitting the armed point panics.
        arm(Point::BeforeCas);
        let caught =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| hit(Point::BeforeCas)));
        assert!(caught.is_err(), "hit at armed point must panic");
        assert_eq!(take(), None, "panic cleared the arm");
    }

    #[test]
    fn arm_from_env_reads_the_environment_variable() {
        let _g = guard();
        std::env::set_var("TINYCLOUD_SQL_STORE_FAILPOINT", "after_cas");
        arm_from_env();
        assert_eq!(take(), Some(Point::AfterCas));
    }

    #[test]
    fn arm_from_env_ignores_unknown_values() {
        let _g = guard();
        std::env::set_var("TINYCLOUD_SQL_STORE_FAILPOINT", "nonexistent");
        arm_from_env();
        assert_eq!(take(), None);
    }
}

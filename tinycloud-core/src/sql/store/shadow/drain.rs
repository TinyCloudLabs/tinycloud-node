//! Drain-on-shutdown policy for the shadow uploader.
//!
//! When the node receives a SIGTERM the uploader has a bounded deadline
//! to flush every dirty database it knows about. The actual flush uses
//! the uploader's own publication path; this module owns the policy: how
//! many databases run in parallel, which deadline wins, and what the
//! drain reports back.
//!
//! Three outcomes:
//! - [`DrainReport::Done`]: every dirty database completed before the
//!   deadline.
//! - [`DrainReport::Deadline`]: the deadline fired while some databases
//!   were still in flight. The report counts how many finished and how
//!   many were cut.
//!
//! The drain is intentionally cooperative. When a pending publish is
//! racing a new write it is the UPLOADER's choice to publish from the
//! newer capture; the drain only stops NEW publish cycles from starting.
//!
//! TC-1491.

use std::future::Future;
use std::time::Duration;

use futures::stream::{FuturesUnordered, StreamExt};

/// What the drain reports back to its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DrainReport {
    /// Every dirty database completed within the deadline. Carries the
    /// count for the log line.
    Done { completed: usize },
    /// The deadline fired while `remaining` databases were still in
    /// flight. `completed` finished before the cut.
    Deadline { completed: usize, remaining: usize },
}

impl DrainReport {
    pub fn completed(&self) -> usize {
        match self {
            Self::Done { completed } | Self::Deadline { completed, .. } => *completed,
        }
    }

    pub fn remaining(&self) -> usize {
        match self {
            Self::Done { .. } => 0,
            Self::Deadline { remaining, .. } => *remaining,
        }
    }
}

/// Run `tasks` concurrently, bounded by `parallelism`, until every one
/// completes or `deadline` fires, whichever comes first. The deadline is
/// a cap on the whole drain, not a per-task budget.
///
/// Each task's `Output` is discarded; the drain only reports how many
/// completed. If `parallelism` is zero the drain is a no-op that reports
/// every task as cut. If the task list is empty the drain reports
/// `Done { completed: 0 }` immediately.
pub async fn drain<F, O, I>(tasks: I, parallelism: usize, deadline: Duration) -> DrainReport
where
    F: Future<Output = O>,
    I: IntoIterator<Item = F>,
{
    let mut queue: Vec<F> = tasks.into_iter().collect();
    let total = queue.len();
    if total == 0 {
        return DrainReport::Done { completed: 0 };
    }
    if parallelism == 0 {
        return DrainReport::Deadline {
            completed: 0,
            remaining: total,
        };
    }

    let mut in_flight: FuturesUnordered<F> = FuturesUnordered::new();
    for _ in 0..parallelism.min(queue.len()) {
        in_flight.push(queue.pop().expect("queue non-empty"));
    }
    let mut completed = 0usize;
    let drain_future = async {
        while let Some(_outcome) = in_flight.next().await {
            completed += 1;
            if let Some(next) = queue.pop() {
                in_flight.push(next);
            }
        }
    };

    match tokio::time::timeout(deadline, drain_future).await {
        Ok(()) => DrainReport::Done { completed },
        Err(_) => {
            let remaining = total.saturating_sub(completed);
            DrainReport::Deadline {
                completed,
                remaining,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    #[tokio::test]
    async fn drain_of_an_empty_list_is_done_with_zero_completed() {
        let report = drain(
            std::iter::empty::<futures::future::Ready<()>>(),
            4,
            Duration::from_secs(1),
        )
        .await;
        assert_eq!(report, DrainReport::Done { completed: 0 });
    }

    #[tokio::test]
    async fn drain_completes_every_task_under_a_generous_deadline() {
        let counter = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let c = counter.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    c.fetch_add(1, Ordering::SeqCst);
                }
            })
            .collect();
        let report = drain(tasks, 4, Duration::from_secs(5)).await;
        assert_eq!(report, DrainReport::Done { completed: 8 });
        assert_eq!(counter.load(Ordering::SeqCst), 8);
    }

    #[tokio::test]
    async fn drain_cuts_at_the_deadline_and_reports_the_remaining() {
        let counter = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..4)
            .map(|_| {
                let c = counter.clone();
                async move {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    c.fetch_add(1, Ordering::SeqCst);
                }
            })
            .collect();
        // One parallel slot; each task takes 1 second; deadline is 150 ms.
        // Zero tasks can complete.
        let report = drain(tasks, 1, Duration::from_millis(150)).await;
        assert!(matches!(report, DrainReport::Deadline { .. }), "{report:?}");
        assert_eq!(report.completed(), 0);
        assert_eq!(report.remaining(), 4);
    }

    #[tokio::test]
    async fn drain_with_zero_parallelism_reports_every_task_cut() {
        let tasks: Vec<_> = (0..3)
            .map(|_| async { tokio::time::sleep(Duration::from_millis(1)).await })
            .collect();
        let report = drain(tasks, 0, Duration::from_secs(1)).await;
        assert_eq!(
            report,
            DrainReport::Deadline {
                completed: 0,
                remaining: 3,
            }
        );
    }

    #[tokio::test]
    async fn drain_runs_at_most_parallelism_tasks_at_once() {
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..8)
            .map(|_| {
                let in_flight = in_flight.clone();
                let peak = peak.clone();
                async move {
                    let n = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(n, Ordering::SeqCst);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                }
            })
            .collect();
        let _ = drain(tasks, 3, Duration::from_secs(5)).await;
        assert!(
            peak.load(Ordering::SeqCst) <= 3,
            "parallelism exceeded cap: peak={}",
            peak.load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn drain_partial_completion_at_the_deadline_is_counted() {
        // With a 100 ms deadline, parallelism 2, and 10 ms per task: at
        // least a handful finish, at most a handful remain. The exact
        // number is scheduler-dependent, but the two counts must sum to
        // the total.
        let counter = Arc::new(AtomicUsize::new(0));
        let tasks: Vec<_> = (0..40)
            .map(|_| {
                let c = counter.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    c.fetch_add(1, Ordering::SeqCst);
                }
            })
            .collect();
        let report = drain(tasks, 2, Duration::from_millis(100)).await;
        match report {
            DrainReport::Done { completed } => assert_eq!(completed, 40),
            DrainReport::Deadline {
                completed,
                remaining,
            } => {
                assert_eq!(completed + remaining, 40, "sum stays equal to total");
                assert!(remaining > 0, "deadline implies at least one cut");
            }
        }
    }
}

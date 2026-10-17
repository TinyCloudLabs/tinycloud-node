//! A request's deadline and its commit latch (TC-1274).
//!
//! `/invoke` runs its handler through [`run_with_deadline`]. Until the handler
//! reaches its first data write, the deadline may cut it: the handler future is
//! dropped at whatever `.await` it is parked on, and the request is answered
//! `request_timeout`, which promises the client that nothing was applied.
//! Every wait before that point is drop-safe (tokio guards, reads, read-only
//! transactions that roll back on drop).
//!
//! Each data write first calls [`latch`]. From then on the deadline no longer
//! cuts: the handler runs to completion and reports its true outcome, and a
//! completion past the deadline is logged as an overrun. The latch and the cut
//! are one compare-and-swap on the same state, so a write started on another
//! task (the SQL service's operation task) can never race a timeout answer.
//!
//! The context is task-local and does not cross `tokio::spawn`; code that
//! hands request work to a task carries it with [`current`] and [`within`].

use std::{
    future::Future,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::time::Instant;

const OPEN: u8 = 0;
const LATCHED: u8 = 1;
const CUT: u8 = 2;

tokio::task_local! {
    static CURRENT: Arc<RequestCancel>;
}

/// What a request was waiting on when its deadline was reached. Recorded by
/// the bounded waits so a timeout can say where the time went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Stage {
    Other = 0,
    LockWait = 1,
    Hydration = 2,
    ArtifactTransfer = 3,
}

impl Stage {
    pub fn as_str(self) -> &'static str {
        match self {
            Stage::Other => "other",
            Stage::LockWait => "lock_wait",
            Stage::Hydration => "hydration",
            Stage::ArtifactTransfer => "artifact_transfer",
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Stage::LockWait,
            2 => Stage::Hydration,
            3 => Stage::ArtifactTransfer,
            _ => Stage::Other,
        }
    }
}

/// One request's deadline and latch.
#[derive(Debug)]
pub struct RequestCancel {
    deadline: Instant,
    budget: Duration,
    state: AtomicU8,
    stage: AtomicU8,
}

impl RequestCancel {
    pub fn new(budget: Duration) -> Arc<Self> {
        Arc::new(Self {
            deadline: Instant::now() + budget,
            budget,
            state: AtomicU8::new(OPEN),
            stage: AtomicU8::new(Stage::Other as u8),
        })
    }

    pub fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Whether the request may still be cut by its deadline.
    pub fn is_open(&self) -> bool {
        self.state.load(Ordering::Acquire) == OPEN
    }

    pub fn is_latched(&self) -> bool {
        self.state.load(Ordering::Acquire) == LATCHED
    }

    /// Mark the request as having started a data write. False only if the
    /// deadline already cut it, in which case the write must not start.
    pub fn latch(&self) -> bool {
        match self
            .state
            .compare_exchange(OPEN, LATCHED, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(state) => state == LATCHED,
        }
    }

    /// Claim the timeout. False if a write has already latched the request.
    pub fn cut(&self) -> bool {
        match self
            .state
            .compare_exchange(OPEN, CUT, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => true,
            Err(state) => state == CUT,
        }
    }

    pub fn set_stage(&self, stage: Stage) {
        self.stage.store(stage as u8, Ordering::Relaxed);
    }

    pub fn stage(&self) -> Stage {
        Stage::from_u8(self.stage.load(Ordering::Relaxed))
    }

    /// Log the timeout answer. Called once by whoever claimed the cut.
    pub fn log_timeout(&self) {
        tracing::warn!(
            error_class = "request_timeout",
            stage = self.stage().as_str(),
            deadline_ms = self.budget.as_millis() as u64,
            "Request deadline exceeded"
        );
    }
}

/// The context installed for the current task, if any.
pub fn current() -> Option<Arc<RequestCancel>> {
    CURRENT.try_with(Arc::clone).ok()
}

/// Latch the current request before a data write; see [`RequestCancel::latch`].
/// Without a context there is no deadline to race, so this is true.
pub fn latch() -> bool {
    current().is_none_or(|context| context.latch())
}

/// Run `future` with `context` installed, if there is one.
pub async fn within<F: Future>(context: Option<Arc<RequestCancel>>, future: F) -> F::Output {
    match context {
        Some(context) => CURRENT.scope(context, future).await,
        None => future.await,
    }
}

/// The deadline cut the request before any data write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeadlineExceeded;

/// Run a request handler under `budget` (`None`: no deadline).
///
/// Before the handler latches, reaching the deadline drops it and returns
/// [`DeadlineExceeded`]. After it latches, the handler completes and its
/// result is returned, with a warning if that was past the deadline.
pub async fn run_with_deadline<F: Future>(
    budget: Option<Duration>,
    future: F,
) -> Result<F::Output, DeadlineExceeded> {
    let Some(budget) = budget else {
        return Ok(future.await);
    };
    let context = RequestCancel::new(budget);
    let started = Instant::now();
    let future = CURRENT.scope(Arc::clone(&context), future);
    tokio::pin!(future);
    tokio::select! {
        biased;
        output = &mut future => return Ok(output),
        _ = tokio::time::sleep_until(context.deadline()) => {}
    }
    if context.cut() {
        context.log_timeout();
        return Err(DeadlineExceeded);
    }
    let output = future.await;
    tracing::warn!(
        error_class = "deadline_overrun",
        elapsed_ms = started.elapsed().as_millis() as u64,
        deadline_ms = budget.as_millis() as u64,
        "Request completed after its deadline"
    );
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn an_unlatched_handler_is_cut_at_the_deadline() {
        let dropped = Arc::new(AtomicU8::new(0));
        struct OnDrop(Arc<AtomicU8>);
        impl Drop for OnDrop {
            fn drop(&mut self) {
                self.0.store(1, Ordering::SeqCst);
            }
        }
        let guard = OnDrop(Arc::clone(&dropped));
        let result = run_with_deadline(Some(Duration::from_secs(5)), async move {
            let _guard = guard;
            std::future::pending::<()>().await
        })
        .await;
        assert_eq!(result, Err(DeadlineExceeded));
        assert_eq!(dropped.load(Ordering::SeqCst), 1, "the handler was dropped");
    }

    #[tokio::test(start_paused = true)]
    async fn a_latched_handler_completes_with_its_result() {
        let result = run_with_deadline(Some(Duration::from_secs(5)), async {
            assert!(latch());
            tokio::time::sleep(Duration::from_secs(20)).await;
            "applied"
        })
        .await;
        assert_eq!(result, Ok("applied"));
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_on_another_task_cannot_latch_after_the_cut() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let result = run_with_deadline(Some(Duration::from_secs(5)), async move {
            let context = current();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(6)).await;
                let _ = tx.send(context.unwrap().latch());
            });
            std::future::pending::<()>().await
        })
        .await;
        assert_eq!(result, Err(DeadlineExceeded));
        assert!(!rx.await.unwrap(), "the late write must see the cut");
    }
}

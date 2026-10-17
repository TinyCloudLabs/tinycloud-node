//! TC-1274: the gentle online `epoch_head` backfill.
//!
//! One pass over every space, in ID order, after the node starts serving.
//! Each space is checked in its own short transaction under its sequence lock
//! (`SpaceDatabase::repair_epoch_heads`), and rewritten only when its cached
//! heads are not provably current, so the pass is idempotent and safe to run
//! on several nodes at once. Writes are correct without it; it only moves
//! each space's one-time history scan off that space's first write.
//!
//! Gentle on a loaded database: at most `spaces_per_second` spaces, and after
//! each space a pause at least as long as that space took. The first error
//! stops the pass with one log line; there is no retry. Logs carry counts
//! only, never space IDs or database error text.

use std::{future::Future, time::Duration};

use tinycloud_auth::resource::SpaceId;
use tinycloud_core::sea_orm::error::{DbErr, RuntimeErr, SqlxError};
use tokio::time::Instant;

use crate::{config::EpochHeadBackfillConfig, TinyCloud};

/// Spaces fetched per page.
const PAGE: u64 = 100;

/// What the backfill needs from the node's database.
#[async_trait::async_trait]
pub trait EpochHeadBackfillTarget {
    async fn page(&self, after: Option<&SpaceId>, limit: u64) -> Result<Vec<SpaceId>, DbErr>;
    async fn repair(&self, space: &SpaceId) -> Result<bool, DbErr>;
}

#[async_trait::async_trait]
impl EpochHeadBackfillTarget for TinyCloud {
    async fn page(&self, after: Option<&SpaceId>, limit: u64) -> Result<Vec<SpaceId>, DbErr> {
        self.epoch_head_backfill_page(after, limit).await
    }

    async fn repair(&self, space: &SpaceId) -> Result<bool, DbErr> {
        self.repair_epoch_heads(space).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackfillEnd {
    /// Every space was checked.
    Done,
    /// The node is shutting down.
    Shutdown,
    /// The first database error; the pass stopped there.
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackfillOutcome {
    pub end: BackfillEnd,
    pub checked: u64,
    pub repaired: u64,
}

/// SQLSTATE of a database error, if it has one: safe to log, unlike the
/// error text, which can quote row values.
fn sqlstate(error: &DbErr) -> Option<String> {
    match error {
        DbErr::Conn(RuntimeErr::SqlxError(SqlxError::Database(database)))
        | DbErr::Exec(RuntimeErr::SqlxError(SqlxError::Database(database)))
        | DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(database))) => {
            database.code().map(|code| code.into_owned())
        }
        _ => None,
    }
}

fn failed(stage: &'static str, error: &DbErr, checked: u64, repaired: u64) -> BackfillOutcome {
    ::tracing::error!(
        event = "epoch_head_backfill",
        phase = "stopped",
        stage,
        sqlstate = sqlstate(error).as_deref().unwrap_or("none"),
        checked,
        repaired,
        "epoch head backfill stopped at its first error; writes stay correct and repair each space on its next write"
    );
    BackfillOutcome {
        end: BackfillEnd::Failed,
        checked,
        repaired,
    }
}

/// Run one pass. `config` is validated (`spaces_per_second` and
/// `progress_every` are at least 1).
pub async fn run<T: EpochHeadBackfillTarget>(
    target: &T,
    config: &EpochHeadBackfillConfig,
    shutdown: impl Future<Output = ()>,
) -> BackfillOutcome {
    tokio::pin!(shutdown);
    let interval = Duration::from_secs(1) / config.spaces_per_second.max(1);
    let progress_every = u64::from(config.progress_every.max(1));
    let started = Instant::now();
    let (mut checked, mut repaired) = (0u64, 0u64);
    let mut after: Option<SpaceId> = None;
    ::tracing::info!(
        event = "epoch_head_backfill",
        phase = "start",
        spaces_per_second = config.spaces_per_second,
        "epoch head backfill started"
    );
    loop {
        let page = match target.page(after.as_ref(), PAGE).await {
            Ok(page) => page,
            Err(error) => return failed("page", &error, checked, repaired),
        };
        if page.is_empty() {
            ::tracing::info!(
                event = "epoch_head_backfill",
                phase = "done",
                checked,
                repaired,
                elapsed_ms = started.elapsed().as_millis() as u64,
                "epoch head backfill finished"
            );
            return BackfillOutcome {
                end: BackfillEnd::Done,
                checked,
                repaired,
            };
        }
        for space in page {
            let space_started = Instant::now();
            match target.repair(&space).await {
                Ok(rewrote) => repaired += u64::from(rewrote),
                Err(error) => return failed("repair", &error, checked, repaired),
            }
            checked += 1;
            if checked % progress_every == 0 {
                ::tracing::info!(
                    event = "epoch_head_backfill",
                    phase = "progress",
                    checked,
                    repaired,
                    elapsed_ms = started.elapsed().as_millis() as u64,
                    "epoch head backfill progress"
                );
            }
            after = Some(space);
            let pause = interval.max(space_started.elapsed());
            tokio::select! {
                _ = tokio::time::sleep(pause) => {}
                _ = &mut shutdown => {
                    ::tracing::info!(
                        event = "epoch_head_backfill",
                        phase = "shutdown",
                        checked,
                        repaired,
                        "epoch head backfill stopped for shutdown"
                    );
                    return BackfillOutcome { end: BackfillEnd::Shutdown, checked, repaired };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::Mutex;

    /// `spaces` in pages; `repair` takes `repair_cost` of (paused) time,
    /// rewrites every other space, and fails on space index `fail_at`.
    struct Fake {
        spaces: Vec<SpaceId>,
        repair_cost: Duration,
        fail_at: Option<usize>,
        repaired: Mutex<Vec<SpaceId>>,
    }

    impl Fake {
        fn new(count: usize) -> Self {
            let mut spaces = (0..count)
                .map(|_| {
                    let jwk = tinycloud_auth::ssi::jwk::JWK::generate_ed25519().unwrap();
                    let did = tinycloud_auth::resolver::DID_METHODS
                        .generate(&jwk, "key")
                        .unwrap();
                    SpaceId::new(did, "default".parse().unwrap())
                })
                .collect::<Vec<_>>();
            spaces.sort_by_key(|space| space.to_string());
            Self {
                spaces,
                repair_cost: Duration::ZERO,
                fail_at: None,
                repaired: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait::async_trait]
    impl EpochHeadBackfillTarget for Fake {
        async fn page(&self, after: Option<&SpaceId>, limit: u64) -> Result<Vec<SpaceId>, DbErr> {
            let start = match after {
                None => 0,
                Some(after) => self.spaces.iter().position(|s| s == after).unwrap() + 1,
            };
            Ok(self.spaces[start..]
                .iter()
                .take(limit as usize)
                .cloned()
                .collect())
        }

        async fn repair(&self, space: &SpaceId) -> Result<bool, DbErr> {
            tokio::time::sleep(self.repair_cost).await;
            let mut repaired = self.repaired.lock();
            if Some(repaired.len()) == self.fail_at {
                return Err(DbErr::Custom("boom".into()));
            }
            repaired.push(space.clone());
            Ok(repaired.len() % 2 == 1)
        }
    }

    fn config(spaces_per_second: u32) -> EpochHeadBackfillConfig {
        EpochHeadBackfillConfig {
            enabled: true,
            spaces_per_second,
            progress_every: 50,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn checks_every_space_once_across_pages_at_the_configured_rate() {
        let fake = Fake::new(250);
        let started = Instant::now();
        let outcome = run(&fake, &config(50), std::future::pending()).await;
        assert_eq!(
            outcome,
            BackfillOutcome {
                end: BackfillEnd::Done,
                checked: 250,
                repaired: 125
            }
        );
        assert_eq!(*fake.repaired.lock(), fake.spaces);
        assert!(started.elapsed() >= Duration::from_secs(5), "250 at 50/s");
    }

    #[tokio::test(start_paused = true)]
    async fn pauses_at_least_as_long_as_each_space_took() {
        let mut fake = Fake::new(3);
        fake.repair_cost = Duration::from_secs(2);
        let started = Instant::now();
        run(&fake, &config(100), std::future::pending()).await;
        // 3 × (2 s of work + at least 2 s of pause).
        assert!(
            started.elapsed() >= Duration::from_secs(12),
            "{:?}",
            started.elapsed()
        );
    }

    #[tokio::test(start_paused = true)]
    async fn stops_at_the_first_error_without_retrying() {
        let mut fake = Fake::new(10);
        fake.fail_at = Some(4);
        let outcome = run(&fake, &config(100), std::future::pending()).await;
        assert_eq!(
            outcome,
            BackfillOutcome {
                end: BackfillEnd::Failed,
                checked: 4,
                repaired: 2
            }
        );
        assert_eq!(fake.repaired.lock().len(), 4);
    }

    #[tokio::test(start_paused = true)]
    async fn stops_on_shutdown() {
        let fake = Fake::new(10);
        let outcome = run(
            &fake,
            &config(1),
            tokio::time::sleep(Duration::from_millis(2_500)),
        )
        .await;
        assert_eq!(outcome.end, BackfillEnd::Shutdown);
        assert_eq!(outcome.checked, 3);
    }
}

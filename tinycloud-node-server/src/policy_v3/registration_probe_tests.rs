//! TC-1836: a registration whose insert is skipped ends its write transaction,
//! so the space-sequence advisory lock it took inside that transaction is
//! released.
//!
//! The skip is injected in the database: a `BEFORE INSERT` trigger on
//! `policy_v3_registration` in the test's own schema returns NULL. PostgreSQL
//! then inserts nothing, sea-orm reports `Failed to find inserted item`, and the
//! handler answers `409 Conflict`. That path runs after `begin_write_transaction`,
//! `lock_space_sequences`, and `delegate_batch_in_transaction`.
//!
//! The fault is Rust-side on purpose: a statement that raises in PostgreSQL
//! aborts the transaction and frees its locks by itself, which would pass on
//! main as well. PostgreSQL only; the probe runs in CI, not locally.

use super::test_harness::*;
use super::unbound_source_tests::{boot, bound_source, grant_owner_key};
use super::*;
use std::future::Future;
use tinycloud_core::sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DbBackend, Statement, TryGetable,
};

const REFUSE_REGISTRATION_SQL: &str = "
CREATE FUNCTION tc1836_refuse_registration() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RETURN NULL;
END
$$;
CREATE TRIGGER tc1836_refuse_registration BEFORE INSERT ON policy_v3_registration
    FOR EACH ROW EXECUTE FUNCTION tc1836_refuse_registration();
";

/// Row counts the refused call must leave unchanged.
#[derive(Debug, PartialEq, Eq)]
struct Rows {
    delegations: i64,
    registrations: i64,
    roots: i64,
}

/// Runs `make` on its own thread and runtime, joined before returning, so the
/// probe never shares the test runtime. Mirrors core's `execute_blocking`.
fn probe_blocking<T, F>(make: impl FnOnce() -> F + Send + 'static) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: Future<Output = anyhow::Result<T>>,
{
    std::thread::spawn(move || -> anyhow::Result<T> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(make())
    })
    .join()
    .map_err(|_| anyhow::anyhow!("probe thread panicked"))?
}

async fn scalar<T: TryGetable>(db: &impl ConnectionTrait, sql: &str) -> anyhow::Result<T> {
    let row = db
        .query_one(Statement::from_string(DbBackend::Postgres, sql.to_owned()))
        .await?
        .ok_or_else(|| anyhow::anyhow!("no row for {sql}"))?;
    Ok(row.try_get_by_index::<T>(0)?)
}

fn install_refusal(url: String) -> anyhow::Result<()> {
    probe_blocking(move || async move {
        let db = Database::connect(ConnectOptions::new(url)).await?;
        db.execute_unprepared(REFUSE_REGISTRATION_SQL).await?;
        Ok(())
    })
}

fn rows(url: String) -> anyhow::Result<Rows> {
    probe_blocking(move || async move {
        let db = Database::connect(ConnectOptions::new(url)).await?;
        Ok(Rows {
            delegations: scalar(&db, "SELECT count(*) FROM delegation").await?,
            registrations: scalar(&db, "SELECT count(*) FROM policy_v3_registration").await?,
            roots: scalar(&db, "SELECT count(*) FROM policy_v3_root").await?,
        })
    })
}

/// Whether `key` can be taken from a fresh session right now, and the rows.
/// A lock leaked by the refused call would make the try fail.
fn key_free_and_rows(url: String, key: i64) -> anyhow::Result<(bool, Rows)> {
    probe_blocking(move || async move {
        let db = Database::connect(ConnectOptions::new(url)).await?;
        let free =
            scalar::<i32>(&db, &format!("SELECT pg_try_advisory_lock({key})::int")).await? == 1;
        if free {
            db.execute_unprepared(&format!("SELECT pg_advisory_unlock({key})"))
                .await?;
        }
        let rows = Rows {
            delegations: scalar(&db, "SELECT count(*) FROM delegation").await?,
            registrations: scalar(&db, "SELECT count(*) FROM policy_v3_registration").await?,
            roots: scalar(&db, "SELECT count(*) FROM policy_v3_root").await?,
        };
        Ok((free, rows))
    })
}

/// A refused registration releases the space-sequence lock it took, and
/// leaves the policy and delegation rows as they were.
#[tokio::test]
async fn postgres_refused_registration_releases_its_space_lock() -> anyhow::Result<()> {
    let test = "postgres_refused_registration_releases_its_space_lock";
    // TC-2242: the route refuses a pathless registration before it opens the
    // transaction, so the registration is path-bound (this needs named keys).
    let Some((h, _ledger)) = boot(Backend::Postgres, test).await? else {
        return Ok(());
    };
    let (source, leaf) = bound_source(&h, "immutable", Some(&"aa".repeat(32)));
    grant_owner_key(&h, &leaf).await?;
    let url = h.database_url().to_owned();
    install_refusal(url.clone())?;
    let before = rows(url.clone())?;

    let (status, body, _) = h.register_source(policy_window(), source, &leaf).await?;
    anyhow::ensure!(
        status == Status::Conflict,
        "refused register: {status} {body}"
    );
    anyhow::ensure!(
        body.contains("Failed to find inserted item"),
        "skipped insert did not surface as RecordNotFound: {body}"
    );

    // The only sequence space the registration locks is the content space:
    // the root delegations' kv ceiling names `content_resource`.
    let key = tinycloud_core::kv_sync::space_sequence_lock_key(&h.content_space);
    let (free, after) = key_free_and_rows(url, key)?;
    anyhow::ensure!(free, "space-sequence lock still held after refusal");
    anyhow::ensure!(after == before, "rows changed: {before:?} -> {after:?}");
    Ok(())
}

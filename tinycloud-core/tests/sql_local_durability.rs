//! TC-1491 slice 1a: local commit durability and the reservation made before
//! COMMIT. See `docs/sql-local-durability.md` for the contract these pin.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::DashMap;
use tinycloud_core::sql::database::{spawn_actor_with_policy, DatabaseHandle, GrowthPolicy};
use tinycloud_core::sql::durability::{
    create_dir_all_durable, CommitSeams, DurabilityPolicy, FreeSpace, Synchronous,
};
use tinycloud_core::sql::storage::{open_connection, promote_to_file, StorageMode};
use tinycloud_core::sql::{SqlError, SqlExecutionResult, SqlRequest, SqlResponse, SqlValue};

const SPACE: &str = "space";
const DB: &str = "durable";

/// Free space that tests set by hand.
#[derive(Debug)]
struct FakeFree(AtomicU64);

impl FakeFree {
    fn new(bytes: u64) -> Arc<Self> {
        Arc::new(Self(AtomicU64::new(bytes)))
    }
    fn set(&self, bytes: u64) {
        self.0.store(bytes, Ordering::SeqCst);
    }
}

impl FreeSpace for FakeFree {
    fn free_bytes(&self, _: &Path) -> std::io::Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

/// A policy with the headroom check ON (`min_free_bytes` is 0 = off by default,
/// so the tests that exercise the mechanism pass an explicit value).
fn policy_with(free: &Arc<FakeFree>, min_free_bytes: u64) -> DurabilityPolicy {
    assert!(min_free_bytes > 0);
    DurabilityPolicy {
        min_free_bytes,
        free_space: free.clone(),
        ..Default::default()
    }
}

/// A file-backed actor: with a zero threshold the first write promotes it.
fn actor(dir: &Path, db: &str, policy: DurabilityPolicy) -> DatabaseHandle {
    spawn_actor_with_policy(
        SPACE.into(),
        db.into(),
        dir.to_str().unwrap().into(),
        0,
        Arc::new(DashMap::new()),
        policy,
    )
}

fn exec(sql: &str) -> SqlRequest {
    SqlRequest::Execute {
        schema: None,
        sql: sql.into(),
        params: vec![],
    }
}

fn batch(statements: &[&str]) -> SqlRequest {
    SqlRequest::Batch {
        statements: statements
            .iter()
            .map(|sql| tinycloud_core::sql::types::SqlStatement {
                sql: (*sql).into(),
                params: vec![],
            })
            .collect(),
    }
}

async fn run(
    actor: &DatabaseHandle,
    request: SqlRequest,
    growth: GrowthPolicy,
) -> Result<SqlExecutionResult, SqlError> {
    actor
        .execute(request, None, "tinycloud.sql/admin".into(), growth)
        .await
}

async fn ok(actor: &DatabaseHandle, sql: &str) {
    run(actor, exec(sql), GrowthPolicy::Allow)
        .await
        .unwrap_or_else(|error| panic!("{sql}: {error}"));
}

async fn rows(actor: &DatabaseHandle, sql: &str) -> Vec<Vec<SqlValue>> {
    match run(
        actor,
        SqlRequest::Query {
            sql: sql.into(),
            params: vec![],
            max_rows: None,
            max_bytes: None,
        },
        GrowthPolicy::Allow,
    )
    .await
    .unwrap()
    .response
    {
        SqlResponse::Query(query) => query.rows,
        other => panic!("expected rows, got {other:?}"),
    }
}

async fn count(actor: &DatabaseHandle, table: &str) -> i64 {
    match rows(actor, &format!("SELECT count(*) FROM {table}")).await[0][0] {
        SqlValue::Integer(n) => n,
        ref other => panic!("{other:?}"),
    }
}

/// Six indexes: a short statement that dirties many pages. (The SQL parser
/// admits no triggers; indexes are the amplification a caller can cause.)
const AMPLIFIED_SCHEMA: &[&str] = &[
    "CREATE TABLE t (id INTEGER PRIMARY KEY, a TEXT, b TEXT, c TEXT, d TEXT, e TEXT, f TEXT)",
    "CREATE INDEX t_a ON t (a)",
    "CREATE INDEX t_b ON t (b)",
    "CREATE INDEX t_c ON t (c)",
    "CREATE INDEX t_d ON t (d)",
    "CREATE INDEX t_e ON t (e)",
    "CREATE INDEX t_f ON t (f)",
];
/// ~300 bytes of SQL text; adds 20 000 rows to seven b-trees.
const AMPLIFIED_INSERT: &str = "INSERT INTO t (a, b, c, d, e, f) \
    SELECT hex(randomblob(12)), hex(randomblob(12)), hex(randomblob(12)), \
    hex(randomblob(12)), hex(randomblob(12)), hex(randomblob(12)) \
    FROM seed s1, seed s2 LIMIT 20000";

/// 256 rows to cross-join, built by doubling.
async fn seed(actor: &DatabaseHandle) {
    ok(actor, "CREATE TABLE seed (x INTEGER)").await;
    ok(actor, "INSERT INTO seed VALUES (1)").await;
    for _ in 0..8 {
        ok(actor, "INSERT INTO seed SELECT x FROM seed").await;
    }
}

fn wal_len(dir: &Path, db: &str) -> u64 {
    std::fs::metadata(dir.join(SPACE).join(format!("{db}.db-wal")))
        .map(|m| m.len())
        .unwrap_or(0)
}

#[test]
fn synchronous_is_full_on_every_file_backed_connection_and_normal_on_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("a").join("b").join("x.db");
    let read = |conn: &rusqlite::Connection| -> i64 {
        conn.query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap()
    };
    // PRAGMA synchronous: 1 = NORMAL, 2 = FULL.
    let opened = open_connection(&StorageMode::File(path.clone()), Synchronous::Full).unwrap();
    assert_eq!(read(&opened), 2);
    let normal = open_connection(&StorageMode::File(path.clone()), Synchronous::Normal).unwrap();
    assert_eq!(read(&normal), 1);
    drop((opened, normal));

    let memory = open_connection(&StorageMode::InMemory, Synchronous::Full).unwrap();
    memory.execute_batch("CREATE TABLE t (v)").unwrap();
    for (setting, expected) in [(Synchronous::Full, 2), (Synchronous::Normal, 1)] {
        let target = dir.path().join(format!("promoted-{expected}.db"));
        let promoted = promote_to_file(&memory, &target, setting).unwrap();
        assert_eq!(read(&promoted), expected);
        let mode: String = promoted
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
    }
}

/// An actor runs under either `synchronous` setting through promotion to a
/// file and a reopen. The setting itself is asserted on the connections in
/// `synchronous_is_full_on_every_file_backed_connection_and_normal_on_request`:
/// since TC-1586 an admin can no longer read `PRAGMA synchronous` through the
/// actor (it is not on the PRAGMA allow-list).
#[tokio::test]
async fn an_actor_runs_under_either_synchronous_setting_after_promotion_and_reopen() {
    for setting in [Synchronous::Full, Synchronous::Normal] {
        let dir = tempfile::tempdir().unwrap();
        let policy = DurabilityPolicy {
            synchronous: setting,
            ..Default::default()
        };
        let first = actor(dir.path(), DB, policy.clone());
        ok(&first, "CREATE TABLE t (v INTEGER)").await; // promotes to a file
        ok(&first, "INSERT INTO t VALUES (1)").await;
        assert_eq!(
            rows(&first, "PRAGMA journal_mode").await[0][0],
            SqlValue::Text("wal".into())
        );
        first.shutdown().await.unwrap();
        let reopened = actor(dir.path(), DB, policy);
        assert_eq!(count(&reopened, "t").await, 1);
    }
}

#[tokio::test]
async fn an_amplified_transaction_is_rejected_before_commit_and_leaves_no_effects() {
    let dir = tempfile::tempdir().unwrap();
    // 1 MiB free, no floor: the SQL text is a few hundred bytes, but the pages
    // it dirties are several MiB.
    let free = FakeFree::new(1 << 20);
    let a = actor(dir.path(), DB, policy_with(&free, 1));
    free.set(64 << 20);
    for statement in AMPLIFIED_SCHEMA {
        ok(&a, statement).await;
    }
    seed(&a).await;
    ok(&a, "INSERT INTO t (a, b) VALUES ('keep', 'keep')").await;
    assert!(AMPLIFIED_INSERT.len() < 600);

    let checkpoint_before = a.checkpoint().await.unwrap();
    let export_before = a.export().await.unwrap();
    let wal_before = wal_len(dir.path(), DB);

    free.set(1 << 20);
    let refused = run(&a, exec(AMPLIFIED_INSERT), GrowthPolicy::Allow).await;
    assert!(
        matches!(refused, Err(SqlError::DiskHeadroom)),
        "{refused:?}"
    );

    // No effect anywhere: rows, the snapshot and export.
    free.set(64 << 20);
    assert_eq!(count(&a, "t").await, 1);
    assert_eq!(a.checkpoint().await.unwrap(), checkpoint_before);
    assert_eq!(a.export().await.unwrap(), export_before);
    // Not even a rolled-back frame set was committed, and what the rejected
    // transaction spilled before the gate is never replayed.
    assert!(wal_len(dir.path(), DB) >= wal_before);

    // The same statement fits when the disk has room.
    free.set(1 << 30);
    ok(&a, AMPLIFIED_INSERT).await;
    assert_eq!(count(&a, "t").await, 20_001);
}

#[tokio::test]
async fn a_batch_is_all_or_nothing_under_each_kind_of_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let free = FakeFree::new(64 << 20);
    let policy = DurabilityPolicy {
        // 32 pages of 4 KiB.
        max_database_bytes: 128 * 1024,
        min_free_bytes: 1,
        free_space: free.clone(),
        ..Default::default()
    };
    let a = actor(dir.path(), DB, policy);
    for statement in AMPLIFIED_SCHEMA {
        ok(&a, statement).await;
    }
    let baseline_checkpoint = a.checkpoint().await.unwrap();

    // 1. Size cap: the first statements apply, the last one passes the cap.
    let over_cap = run(
        &a,
        batch(&[
            "INSERT INTO t (a) VALUES ('first')",
            "INSERT INTO t (a) VALUES ('second')",
            "INSERT INTO t (a) VALUES (hex(zeroblob(200000)))",
        ]),
        GrowthPolicy::Allow,
    )
    .await;
    assert!(
        matches!(over_cap, Err(SqlError::DatabaseSizeLimit)),
        "{over_cap:?}"
    );
    assert_eq!(count(&a, "t").await, 0);

    // 2. Disk headroom at the gate.
    free.set(1 << 10);
    let no_room = run(
        &a,
        batch(&[
            "INSERT INTO t (a) VALUES ('first')",
            "INSERT INTO t (a) VALUES ('second')",
        ]),
        GrowthPolicy::Allow,
    )
    .await;
    assert!(
        matches!(no_room, Err(SqlError::DiskHeadroom)),
        "{no_room:?}"
    );
    free.set(64 << 20);
    assert_eq!(count(&a, "t").await, 0);

    // 3. The owner's budget.
    let over_budget = run(
        &a,
        batch(&[
            "INSERT INTO t (a) VALUES ('first')",
            "INSERT INTO t (a) VALUES (hex(zeroblob(40000)))",
        ]),
        GrowthPolicy::Budget(8192),
    )
    .await;
    assert!(
        matches!(over_budget, Err(SqlError::StorageWouldGrow)),
        "{over_budget:?}"
    );
    assert_eq!(count(&a, "t").await, 0);
    assert_eq!(a.checkpoint().await.unwrap(), baseline_checkpoint);

    // 4. A statement error after earlier statements.
    let broken = run(
        &a,
        batch(&[
            "INSERT INTO t (a) VALUES ('first')",
            "INSERT INTO nope VALUES (1)",
        ]),
        GrowthPolicy::Allow,
    )
    .await;
    assert!(broken.is_err());
    assert_eq!(count(&a, "t").await, 0);
    assert_eq!(a.checkpoint().await.unwrap(), baseline_checkpoint);

    // And the same batch passes when nothing is wrong.
    ok(&a, "INSERT INTO t (a) VALUES ('kept')").await;
    assert_eq!(count(&a, "t").await, 1);
}

/// TC-1585: a `WITH … INSERT` is a query to the parser but a write to the
/// node. It gets the transaction, the owner's budget, the size cap and the
/// pre-commit disk gate, and a refusal leaves nothing: no rows, no checkpoint
/// change, no reservation.
#[tokio::test]
async fn a_nested_write_is_bounded_before_commit_like_any_other_write() {
    const CTE_WRITE: &str =
        "WITH c AS (SELECT hex(zeroblob(40000)) AS v) INSERT INTO t (a) SELECT v FROM c";
    let query = |sql: &str| SqlRequest::Query {
        sql: sql.into(),
        params: vec![],
        max_rows: None,
        max_bytes: None,
    };
    let dir = tempfile::tempdir().unwrap();
    let free = FakeFree::new(64 << 20);
    let policy = DurabilityPolicy {
        // 32 pages of 4 KiB.
        max_database_bytes: 128 * 1024,
        min_free_bytes: 1,
        free_space: free.clone(),
        ..Default::default()
    };
    let a = actor(dir.path(), DB, policy.clone());
    for statement in AMPLIFIED_SCHEMA {
        ok(&a, statement).await;
    }
    let baseline_checkpoint = a.checkpoint().await.unwrap();
    let wal_before = wal_len(dir.path(), DB);

    // The owner's budget.
    let over_budget = run(&a, query(CTE_WRITE), GrowthPolicy::Budget(8192)).await;
    assert!(
        matches!(over_budget, Err(SqlError::StorageWouldGrow)),
        "{over_budget:?}"
    );
    // The per-database cap.
    let over_cap = run(
        &a,
        query("WITH c AS (SELECT hex(zeroblob(200000)) AS v) INSERT INTO t (a) SELECT v FROM c"),
        GrowthPolicy::Allow,
    )
    .await;
    assert!(
        matches!(over_cap, Err(SqlError::DatabaseSizeLimit)),
        "{over_cap:?}"
    );
    // The disk gate, at the pre-commit check.
    free.set(1 << 10);
    let no_room = run(
        &a,
        query("WITH c AS (SELECT hex(zeroblob(2000)) AS v) INSERT INTO t (a) SELECT v FROM c"),
        GrowthPolicy::Allow,
    )
    .await;
    assert!(
        matches!(no_room, Err(SqlError::DiskHeadroom)),
        "{no_room:?}"
    );
    free.set(64 << 20);

    assert_eq!(count(&a, "t").await, 0);
    assert_eq!(a.checkpoint().await.unwrap(), baseline_checkpoint);
    assert_eq!(wal_len(dir.path(), DB), wal_before);
    assert_eq!(policy.budget.reserved(), 0);

    // The same write is kept when it fits.
    let fits = run(
        &a,
        query("WITH c AS (SELECT 'small' AS v) INSERT INTO t (a) SELECT v FROM c"),
        GrowthPolicy::Budget(1 << 20),
    )
    .await;
    assert!(fits.is_ok(), "{fits:?}");
    assert_eq!(count(&a, "t").await, 1);
}

#[tokio::test]
async fn the_size_cap_and_owner_budget_are_enforced_by_sqlite_and_shrinking_writes_pass() {
    let dir = tempfile::tempdir().unwrap();
    let free = FakeFree::new(64 << 20);
    let policy = DurabilityPolicy {
        max_database_bytes: 64 * 4096,
        min_free_bytes: 1,
        free_space: free.clone(),
        ..Default::default()
    };
    let a = actor(dir.path(), DB, policy);
    ok(&a, "CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)").await;

    // Per-database cap: pages grow until the 64th, then the write is refused
    // whole, whatever its size.
    let mut stored = 0;
    loop {
        let result = run(
            &a,
            exec("INSERT INTO t (v) VALUES (zeroblob(30000))"),
            GrowthPolicy::Allow,
        )
        .await;
        match result {
            Ok(_) => stored += 1,
            Err(SqlError::DatabaseSizeLimit) => break,
            Err(other) => panic!("{other:?}"),
        }
        assert!(stored < 64, "the cap never bit");
    }
    assert!(stored >= 5, "stored only {stored}");
    assert_eq!(count(&a, "t").await, stored);
    let size = a.export().await.unwrap().len();
    assert!(size <= 64 * 4096, "database grew to {size}");

    // At the cap, a write that frees pages still passes.
    ok(&a, "DELETE FROM t WHERE id <= 2").await;
    assert_eq!(count(&a, "t").await, stored - 2);

    // Owner budget: one page left means a write needing several is refused,
    // a small one that fits in free pages is not.
    let refused = run(
        &a,
        exec("INSERT INTO t (v) VALUES (zeroblob(100000))"),
        GrowthPolicy::Budget(4096),
    )
    .await;
    assert!(
        matches!(refused, Err(SqlError::StorageWouldGrow)),
        "{refused:?}"
    );
    let small = run(
        &a,
        exec("INSERT INTO t (v) VALUES (zeroblob(100))"),
        GrowthPolicy::Budget(4096),
    )
    .await;
    assert!(small.is_ok(), "{small:?}");
    // A delete under a budget never needs one.
    let shrink = run(
        &a,
        exec("DELETE FROM t WHERE id > 100"),
        GrowthPolicy::Budget(1),
    )
    .await;
    assert!(shrink.is_ok(), "{shrink:?}");
}

/// The shipped defaults are off: no cap, no headroom check, no reservation
/// (the limits are Sam's decision, card `sql-storage-report-read`). `synchronous`
/// is the durability fix, not a limit, and defaults to FULL.
#[tokio::test]
async fn the_limits_are_off_by_default_but_the_same_policy_enforces_when_set() {
    let defaults = DurabilityPolicy::default();
    assert_eq!(defaults.max_database_bytes, 0);
    assert_eq!(defaults.min_free_bytes, 0);
    assert_eq!(defaults.synchronous, Synchronous::Full);

    let dir = tempfile::tempdir().unwrap();
    // A disk that reports no free space at all, and a blob bigger than any cap
    // below: with the defaults nothing refuses and nothing is reserved.
    let free = FakeFree::new(0);
    let off = DurabilityPolicy {
        free_space: free.clone(),
        ..Default::default()
    };
    let a = actor(dir.path(), "off", off.clone());
    ok(&a, "CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)").await;
    ok(&a, "INSERT INTO t (v) VALUES (zeroblob(3000000))").await;
    assert_eq!(count(&a, "t").await, 1);
    assert_eq!(off.budget.reserved(), 0, "nothing is reserved when off");

    // The same writes under explicit limits are refused.
    let on = DurabilityPolicy {
        max_database_bytes: 1 << 20,
        min_free_bytes: 1,
        free_space: free.clone(),
        ..Default::default()
    };
    let b = actor(dir.path(), "on", on.clone());
    free.set(1 << 30);
    ok(&b, "CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)").await;
    let capped = run(
        &b,
        exec("INSERT INTO t (v) VALUES (zeroblob(3000000))"),
        GrowthPolicy::Allow,
    )
    .await;
    assert!(
        matches!(capped, Err(SqlError::DatabaseSizeLimit)),
        "{capped:?}"
    );
    free.set(0);
    let no_room = run(
        &b,
        exec("INSERT INTO t (v) VALUES (zeroblob(10))"),
        GrowthPolicy::Allow,
    )
    .await;
    assert!(
        matches!(no_room, Err(SqlError::DiskHeadroom)),
        "{no_room:?}"
    );
}

#[tokio::test]
async fn disk_headroom_exhaustion_refuses_writes_and_recovers_without_residue() {
    let dir = tempfile::tempdir().unwrap();
    let free = FakeFree::new(64 << 20);
    let min_free = 8 << 20;
    let a = actor(dir.path(), DB, policy_with(&free, min_free));
    ok(&a, "CREATE TABLE t (v TEXT)").await;

    // The floor alone refuses: free space below it, whatever the write.
    free.set(min_free - 1);
    let refused = run(&a, exec("INSERT INTO t VALUES ('x')"), GrowthPolicy::Allow).await;
    assert!(
        matches!(refused, Err(SqlError::DiskHeadroom)),
        "{refused:?}"
    );
    // Reads and writes that touch nothing still answer.
    assert_eq!(count(&a, "t").await, 0);

    free.set(64 << 20);
    ok(&a, "INSERT INTO t VALUES ('x')").await;
    assert_eq!(count(&a, "t").await, 1);
}

#[tokio::test]
async fn concurrent_databases_share_one_reservation_budget() {
    let dir = tempfile::tempdir().unwrap();
    let free = FakeFree::new(64 << 20);
    let policy = policy_with(&free, 1);
    let a = actor(dir.path(), "a", policy.clone());
    let b = actor(dir.path(), "b", policy.clone());
    ok(&a, "CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)").await;
    ok(&b, "CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)").await;

    // `a` commits a large write: its checkpoint growth stays held until the
    // request's outcome is known (the service releases it after the save).
    ok(&a, "INSERT INTO t (v) VALUES (zeroblob(400000))").await;
    let held = policy.budget.reserved();
    assert!(held >= 390_000, "held {held}");
    assert_eq!(policy.budget.reserved_excluding("space/a"), 0);

    // 300 KB free: `b`'s small write fits alone, not next to `a`'s 400 KB.
    free.set(300_000);
    let refused = run(
        &b,
        exec("INSERT INTO t (v) VALUES (zeroblob(100))"),
        GrowthPolicy::Allow,
    )
    .await;
    assert!(
        matches!(refused, Err(SqlError::DiskHeadroom)),
        "{refused:?}"
    );
    assert_eq!(count(&b, "t").await, 0);

    // The outcome of `a`'s request is known: its reservation is released.
    policy.budget.release("space/a");
    ok(&b, "INSERT INTO t (v) VALUES (zeroblob(100))").await;
    assert_eq!(count(&b, "t").await, 1);
    // A write's own reservation is dropped when it is refused or done.
    policy.budget.release("space/b");
    assert_eq!(policy.budget.reserved(), 0);
}

#[tokio::test]
async fn a_database_over_the_cap_still_runs_writes_that_do_not_grow_it() {
    let dir = tempfile::tempdir().unwrap();
    let free = FakeFree::new(64 << 20);
    let big = actor(dir.path(), DB, policy_with(&free, 1));
    ok(&big, "CREATE TABLE t (id INTEGER PRIMARY KEY, v BLOB)").await;
    for _ in 0..10 {
        ok(&big, "INSERT INTO t (v) VALUES (zeroblob(30000))").await;
    }
    big.shutdown().await.unwrap();
    // The cap is now below the file's size.
    let small_cap = DurabilityPolicy {
        max_database_bytes: 4096,
        ..policy_with(&free, 1)
    };
    let a = actor(dir.path(), DB, small_cap);
    ok(&a, "UPDATE t SET v = zeroblob(10) WHERE id = 1").await;
    ok(&a, "DELETE FROM t WHERE id = 2").await;
    let grow = run(
        &a,
        exec("INSERT INTO t (v) VALUES (zeroblob(300000))"),
        GrowthPolicy::Allow,
    )
    .await;
    assert!(matches!(grow, Err(SqlError::DatabaseSizeLimit)), "{grow:?}");
}

#[test]
fn directories_created_for_a_database_are_made_durable() {
    let dir = tempfile::tempdir().unwrap();
    let nested = dir.path().join("sql").join("space").join("deeper");
    create_dir_all_durable(&nested).unwrap();
    assert!(nested.is_dir());
    // Idempotent on an existing path.
    create_dir_all_durable(&nested).unwrap();
}

/// The bound the gate relies on: whatever a transaction dirtied, COMMIT
/// appends no more to the WAL than one frame per page left in the page cache.
#[test]
fn the_unspilled_wal_bound_covers_what_commit_appends() {
    use tinycloud_core::sql::durability::{cache_used_bytes, unspilled_wal_bound};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bound.db");
    let conn = open_connection(&StorageMode::File(path.clone()), Synchronous::Full).unwrap();
    let wal = path.with_extension("db-wal");
    let wal_len = || std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
    let page_size: u64 = conn
        .query_row("PRAGMA page_size", [], |r| r.get(0))
        .unwrap();
    conn.execute_batch(
        "CREATE TABLE t (id INTEGER PRIMARY KEY, a, b, c, d); \
         CREATE INDEX ta ON t (a); CREATE INDEX tb ON t (b); \
         CREATE INDEX tc ON t (c); CREATE INDEX td ON t (d); \
         CREATE TABLE seed (x); INSERT INTO seed VALUES (1);",
    )
    .unwrap();
    for _ in 0..9 {
        conn.execute_batch("INSERT INTO seed SELECT x FROM seed")
            .unwrap();
    }
    let mut observed_spill = false;
    for rows in [1, 50, 1_000, 10_000, 100_000] {
        conn.execute_batch("SAVEPOINT s").unwrap();
        conn.execute(
            "INSERT INTO t (a, b, c, d) SELECT hex(randomblob(10)), hex(randomblob(10)), \
             hex(randomblob(10)), hex(randomblob(10)) FROM seed s1, seed s2 LIMIT ?1",
            [rows],
        )
        .unwrap();
        // Rewriting existing pages counts too.
        conn.execute("UPDATE t SET a = hex(randomblob(10)) WHERE id % 2 = 0", [])
            .unwrap();
        let before = wal_len();
        let bound = unspilled_wal_bound(cache_used_bytes(&conn), page_size);
        observed_spill |= before > 32;
        conn.execute_batch("RELEASE s").unwrap();
        let appended = wal_len() - before;
        assert!(
            appended <= bound,
            "{rows} rows: COMMIT appended {appended} bytes, bound was {bound}"
        );
    }
    assert!(
        observed_spill,
        "the cache never spilled; the test proved little"
    );
}

/// Indicative only (not a benchmark gate): p50/p99 of a small committed write
/// with `synchronous` NORMAL and FULL. Run with
/// `TC1491_LATENCY_DIR=<dir on the disk to measure> cargo test -p tinycloud-core
/// --test sql_local_durability latency -- --ignored --nocapture`.
#[test]
#[ignore]
fn synchronous_latency_indicative() {
    let base = std::env::var("TC1491_LATENCY_DIR").expect("TC1491_LATENCY_DIR");
    for round in 0..2 {
        for setting in [Synchronous::Normal, Synchronous::Full] {
            let dir = tempfile::tempdir_in(&base).unwrap();
            let conn =
                open_connection(&StorageMode::File(dir.path().join("lat.db")), setting).unwrap();
            conn.execute_batch("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
                .unwrap();
            let mut micros = Vec::with_capacity(1000);
            for i in 0..1000 {
                let start = std::time::Instant::now();
                conn.execute("INSERT INTO t (v) VALUES (?1)", [format!("value-{i}")])
                    .unwrap();
                micros.push(start.elapsed().as_micros() as u64);
            }
            micros.sort_unstable();
            println!(
                "round {round} {setting:?}: p50 {} us, p99 {} us, max {} us",
                micros[499], micros[989], micros[999]
            );
        }
    }
}

// ---- kill -9 ---------------------------------------------------------------

/// Where the child process dies.
#[derive(Clone, Copy, Debug)]
enum Kill {
    BeforeCommit,
    AfterCommit,
    BeforeResponse,
}

impl Kill {
    fn name(self) -> &'static str {
        match self {
            Kill::BeforeCommit => "before_commit",
            Kill::AfterCommit => "after_commit",
            Kill::BeforeResponse => "before_response",
        }
    }
}

const CHILD_ENV: &str = "TC1491_KILL_CHILD";
/// Request number (1-based, counted over commits) at which the child dies.
const KILL_AT: u64 = 6;

fn sigkill_self() -> ! {
    // SAFETY: plain syscall on our own pid.
    unsafe { libc::kill(libc::getpid(), libc::SIGKILL) };
    std::process::abort()
}

/// Entry point of the child process; a no-op test in the normal run.
#[test]
fn kill_child_entry() {
    let Ok(spec) = std::env::var(CHILD_ENV) else {
        return;
    };
    let mut parts = spec.split('|');
    let dir = PathBuf::from(parts.next().unwrap());
    let kill = parts.next().unwrap().to_string();

    // Commits are counted when their `after_commit` seam runs (the setup
    // CREATE TABLE is the first). The child dies in the sixth.
    let commits = Arc::new(AtomicU64::new(0));
    let fresh = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seam = |f: Box<dyn Fn() + Send + Sync>| Some(Arc::new(f) as Arc<dyn Fn() + Send + Sync>);
    let before_commit = {
        let (commits, kill) = (commits.clone(), kill.clone());
        seam(Box::new(move || {
            if kill == "before_commit" && commits.load(Ordering::SeqCst) + 1 == KILL_AT {
                sigkill_self();
            }
        }))
    };
    let after_commit = {
        let (commits, fresh, kill) = (commits.clone(), fresh.clone(), kill.clone());
        seam(Box::new(move || {
            let n = commits.fetch_add(1, Ordering::SeqCst) + 1;
            fresh.store(true, Ordering::SeqCst);
            if kill == "after_commit" && n == KILL_AT {
                sigkill_self();
            }
        }))
    };
    let before_response = {
        let (commits, fresh, kill) = (commits.clone(), fresh.clone(), kill.clone());
        seam(Box::new(move || {
            // Only the response that follows a commit; rejected requests and
            // reads answer without one.
            if fresh.swap(false, Ordering::SeqCst)
                && kill == "before_response"
                && commits.load(Ordering::SeqCst) == KILL_AT
            {
                sigkill_self();
            }
        }))
    };
    let policy = DurabilityPolicy {
        seams: CommitSeams {
            before_commit,
            after_commit,
            before_response,
        },
        ..Default::default()
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let a = actor(&dir, DB, policy);
        run(
            &a,
            exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER NOT NULL)"),
            GrowthPolicy::Allow,
        )
        .await
        .unwrap();
        println!("SETUP");
        for i in 1..=20_i64 {
            // Every third request is rejected after its first statement ran.
            let request = if i % 3 == 0 {
                batch(&[
                    &format!("INSERT INTO t (id, v) VALUES ({}, {})", 1000 + i, 1000 + i),
                    "INSERT INTO t (id, v) VALUES (NULL, NULL)",
                ])
            } else {
                exec(&format!("INSERT INTO t (id, v) VALUES ({i}, {i})"))
            };
            let result = run(&a, request, GrowthPolicy::Allow).await;
            match result {
                Ok(_) => println!("ACK {i}"),
                Err(_) => println!("REJECTED {i}"),
            }
        }
        println!("DONE");
    });
}

fn run_child(dir: &Path, kill: Kill) -> Vec<String> {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "kill_child_entry",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_ENV, format!("{}|{}", dir.display(), kill.name()))
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let lines: Vec<String> = BufReader::new(child.stdout.take().unwrap())
        .lines()
        .map_while(Result::ok)
        .collect();
    let status = child.wait().unwrap();
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(
        status.signal(),
        Some(libc::SIGKILL),
        "the child must die by SIGKILL: {status:?} {lines:?}"
    );
    lines
}

#[tokio::test(flavor = "multi_thread")]
async fn kill_minus_nine_at_each_commit_boundary_loses_no_acknowledged_write_and_keeps_no_rejected_one(
) {
    for kill in [Kill::BeforeCommit, Kill::AfterCommit, Kill::BeforeResponse] {
        let dir = tempfile::tempdir().unwrap();
        let lines = run_child(dir.path(), kill);
        assert!(
            lines.iter().any(|line| line.ends_with("SETUP")),
            "{kill:?} {lines:?}"
        );
        let acked: Vec<i64> = lines
            .iter()
            .filter_map(|l| l.strip_prefix("ACK "))
            .map(|n| n.parse().unwrap())
            .collect();
        let rejected: Vec<i64> = lines
            .iter()
            .filter_map(|l| l.strip_prefix("REJECTED "))
            .map(|n| n.parse().unwrap())
            .collect();
        assert!(!lines.contains(&"DONE".to_string()), "{kill:?}");
        assert!(
            !rejected.is_empty() && acked.len() >= 3,
            "{kill:?} {lines:?}"
        );

        // Reopen what the dead process left.
        let a = actor(dir.path(), DB, DurabilityPolicy::default());
        let present: Vec<i64> = rows(&a, "SELECT id FROM t ORDER BY id")
            .await
            .into_iter()
            .map(|row| match row[0] {
                SqlValue::Integer(n) => n,
                ref other => panic!("{other:?}"),
            })
            .collect();
        for id in &acked {
            assert!(present.contains(id), "{kill:?}: acknowledged {id} is lost");
        }
        for id in &rejected {
            assert!(
                !present.contains(id) && !present.contains(&(1000 + id)),
                "{kill:?}: rejected {id} (or its batch prefix) survived"
            );
        }
        // Whatever else is there is the single request in flight when the
        // process died: committed locally, never acknowledged ("unknown").
        let unexplained: Vec<_> = present.iter().filter(|id| !acked.contains(id)).collect();
        match kill {
            Kill::BeforeCommit => assert!(unexplained.is_empty(), "{kill:?} {unexplained:?}"),
            Kill::AfterCommit | Kill::BeforeResponse => {
                assert_eq!(unexplained.len(), 1, "{kill:?} {unexplained:?}")
            }
        }
    }
}

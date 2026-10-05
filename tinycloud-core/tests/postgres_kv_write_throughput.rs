//! TC-732: PostgreSQL KV write-throughput benchmark.
//!
//! Measures owner-root signed `tinycloud.kv/put` invocations through the
//! public `SpaceDatabase::invoke` API against a real PostgreSQL server, over a
//! matrix of concurrency (1, 8, 32) × target layout (every worker writes one
//! space, or worker `i` writes space `i % 32`). For each cell it reports
//! throughput, p50/p95 latency, errors (by kind), and `event_order` integrity:
//! the number of `(space, seq)` groups that carry more than one distinct epoch
//! (a duplicated per-space sequence number across concurrent epochs).
//!
//! This is a manual benchmark, not a regression gate: it is `#[ignore]`d,
//! never fails on put errors (only reports them), and skips — without
//! panicking, even when `CI` is set — when `TINYCLOUD_TEST_POSTGRES_URL` is
//! unset. Run it with:
//!
//! ```text
//! TINYCLOUD_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:55502/postgres \
//!   cargo test -p tinycloud-core --test postgres_kv_write_throughput -- --ignored --nocapture
//! ```

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::io::AsyncWriteExt;
use tinycloud_auth::resolver::DID_METHODS;
use tinycloud_auth::resource::{Path, Service, SpaceId};
use tinycloud_auth::ssi::claims::jwt::NumericDate;
use tinycloud_auth::ssi::dids::{DIDBuf, DIDURLBuf};
use tinycloud_auth::ssi::jwk::JWK;
use tinycloud_auth::ssi::ucan::Payload;
use tinycloud_auth::ucan_capabilities_object::{Ability, Capabilities};
use tinycloud_core::events::{Invocation, TinyCloudInvocation};
use tinycloud_core::keys::StaticSecret;
use tinycloud_core::models::space as space_model;
use tinycloud_core::sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
    DatabaseConnection, DbBackend, Statement,
};
use tinycloud_core::storage::memory::{MemoryStaging, MemoryStore};
use tinycloud_core::storage::HashBuffer;
use tinycloud_core::types::{Metadata, SpaceIdWrap};
use tinycloud_core::{SpaceDatabase, TxError, TxStoreError};

/// Production pool size mirrored by the benchmark connection pool.
const MAX_CONNECTIONS: u32 = 15;
/// Puts per matrix cell; divisible by every concurrency level so each worker
/// performs the same number of puts.
const PUTS_PER_CELL: usize = 640;
const CONCURRENCY: [usize; 3] = [1, 8, 32];
const SPACE_FANOUT: usize = 32;

type Db = SpaceDatabase<DatabaseConnection, MemoryStore, StaticSecret>;
type BoxError = Box<dyn std::error::Error + Send + Sync>;

#[derive(Clone, Copy)]
enum Layout {
    SameSpace,
    ManySpaces,
}

impl Layout {
    fn label(self) -> &'static str {
        match self {
            Layout::SameSpace => "same space",
            Layout::ManySpaces => "32 spaces",
        }
    }
}

/// One space owner: its signing key, verification method, and space id.
struct Owner {
    jwk: JWK,
    verification_method: String,
    did: String,
    space: SpaceId,
}

impl Owner {
    fn generate() -> Result<Self, BoxError> {
        let jwk = JWK::generate_ed25519()?;
        let did = DID_METHODS.generate(&jwk, "key")?.to_string();
        let fragment = did
            .rsplit_once(':')
            .map(|(_, fragment)| fragment.to_owned())
            .ok_or("did:key has no method-specific id")?;
        let verification_method = format!("{did}#{fragment}");
        let space = SpaceId::new(did.parse::<DIDBuf>()?, "default".parse()?);
        Ok(Self {
            jwk,
            verification_method,
            did,
            space,
        })
    }

    /// Sign an owner-root (no proofs) `tinycloud.kv/put` invocation on
    /// `{space}/kv/{key}` and decode it into the core event type.
    fn put_invocation(&self, key: &Path, nonce: String) -> Result<Invocation, BoxError> {
        let resource =
            self.space
                .clone()
                .to_resource("kv".parse::<Service>()?, Some(key.clone()), None, None);
        let mut caps = Capabilities::new();
        caps.with_action(
            resource.as_uri(),
            "tinycloud.kv/put".parse::<Ability>()?,
            [BTreeMap::<String, serde_json::Value>::new()],
        );
        let expiration = NumericDate::try_from_seconds(
            time::OffsetDateTime::now_utc().unix_timestamp() as f64 + 1_800.0,
        )?;
        let header = Payload {
            issuer: self.verification_method.parse::<DIDURLBuf>()?,
            audience: self.did.parse::<DIDBuf>()?,
            not_before: None,
            expiration,
            nonce: Some(nonce),
            facts: Some(Vec::<serde_json::Value>::new()),
            proof: vec![],
            attenuation: caps,
        }
        .sign(self.jwk.get_algorithm().unwrap_or_default(), &self.jwk)?
        .encode()?;
        Ok(Invocation::from_header_ser::<TinyCloudInvocation>(&header)?)
    }
}

/// A pre-signed put, ready to be staged and invoked.
struct PreparedPut {
    space: SpaceId,
    key: Path,
    invocation: Invocation,
    value: Vec<u8>,
}

#[derive(Default)]
struct WorkerReport {
    latencies: Vec<Duration>,
    ok: usize,
    errors: BTreeMap<String, (usize, String)>,
}

struct CellReport {
    layout: Layout,
    concurrency: usize,
    attempted: usize,
    ok: usize,
    wall: Duration,
    p50: Duration,
    p95: Duration,
    errors: BTreeMap<String, (usize, String)>,
    event_rows: i64,
    duplicate_seq_groups: i64,
}

type PutError = TxStoreError<MemoryStore, MemoryStaging, StaticSecret>;

/// Classify a put error by its variant (the error type is not `Debug`
/// because `StaticSecret` deliberately is not).
fn error_kind(error: &PutError) -> &'static str {
    match error {
        TxStoreError::Tx(TxError::Db(_)) => "Tx::Db",
        TxStoreError::Tx(TxError::EpochInsert(_)) => "Tx::EpochInsert",
        TxStoreError::Tx(TxError::SpaceNotFound) => "Tx::SpaceNotFound",
        TxStoreError::Tx(TxError::Ucan(_)) => "Tx::Ucan",
        TxStoreError::Tx(TxError::InvalidInvocation(_)) => "Tx::InvalidInvocation",
        TxStoreError::Tx(TxError::ChainTraversalLimitExceeded) => "Tx::ChainTraversalLimit",
        TxStoreError::Tx(_) => "Tx::other",
        TxStoreError::StoreRead(_) => "StoreRead",
        TxStoreError::StoreWrite(_) => "StoreWrite",
        TxStoreError::Io(_) => "Io",
        TxStoreError::MissingInput => "MissingInput",
        TxStoreError::KvPreconditionFailed => "KvPreconditionFailed",
        _ => "other",
    }
}

fn percentile(sorted: &[Duration], pct: usize) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let rank = (sorted.len() * pct).div_ceil(100).max(1);
    sorted[rank.min(sorted.len()) - 1]
}

async fn host_space(conn: &DatabaseConnection, space: &SpaceId) -> Result<(), BoxError> {
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(conn)
    .await?;
    Ok(())
}

/// Stage the value and invoke the put; on failure returns `(kind, message)`.
async fn run_put(db: &Db, put: PreparedPut) -> Result<(), (&'static str, String)> {
    let mut stage = HashBuffer::new(Vec::new());
    stage
        .write_all(&put.value)
        .await
        .map_err(|e| ("Stage", e.to_string()))?;
    let mut inputs = HashMap::new();
    inputs.insert((put.space, put.key), (Metadata(BTreeMap::new()), stage));
    db.invoke::<MemoryStaging>(put.invocation, inputs)
        .await
        .map(|_| ())
        .map_err(|e| (error_kind(&e), e.to_string()))
}

async fn integrity(conn: &DatabaseConnection, spaces: &[SpaceId]) -> Result<(i64, i64), BoxError> {
    let list = spaces
        .iter()
        .map(|space| format!("'{}'", space.to_string().replace('\'', "''")))
        .collect::<Vec<_>>()
        .join(", ");
    let rows = conn
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            format!("SELECT COUNT(*) AS c FROM event_order WHERE space IN ({list})"),
        ))
        .await?
        .ok_or("event_order count returned no row")?
        .try_get::<i64>("", "c")?;
    let duplicates = conn
        .query_one(Statement::from_string(
            DbBackend::Postgres,
            format!(
                "SELECT COUNT(*) AS c FROM (SELECT space, seq FROM event_order \
                 WHERE space IN ({list}) GROUP BY space, seq \
                 HAVING COUNT(DISTINCT epoch) > 1) d"
            ),
        ))
        .await?
        .ok_or("duplicate seq count returned no row")?
        .try_get::<i64>("", "c")?;
    Ok((rows, duplicates))
}

async fn run_cell(
    db: &Arc<Db>,
    conn: &DatabaseConnection,
    cell: usize,
    layout: Layout,
    concurrency: usize,
) -> Result<CellReport, BoxError> {
    let space_count = match layout {
        Layout::SameSpace => 1,
        Layout::ManySpaces => SPACE_FANOUT,
    };
    let owners = (0..space_count)
        .map(|_| Owner::generate())
        .collect::<Result<Vec<_>, _>>()?;
    for owner in &owners {
        host_space(conn, &owner.space).await?;
    }

    // Pre-sign (and decode) every invocation so signing is not timed.
    let per_worker = PUTS_PER_CELL / concurrency;
    let mut batches = Vec::with_capacity(concurrency);
    for worker in 0..concurrency {
        let owner = &owners[worker % space_count];
        let mut batch = Vec::with_capacity(per_worker);
        for n in 0..per_worker {
            let key: Path = format!("bench/c{cell}/w{worker}/k{n}").parse()?;
            let nonce = format!("urn:uuid:tc732-bench-{cell}-{worker}-{n}");
            let invocation = owner.put_invocation(&key, nonce)?;
            batch.push(PreparedPut {
                space: owner.space.clone(),
                key,
                invocation,
                value: format!("tc732 value {cell}/{worker}/{n}").into_bytes(),
            });
        }
        batches.push(batch);
    }

    let start = Instant::now();
    let handles = batches
        .into_iter()
        .map(|batch| {
            let db = Arc::clone(db);
            tokio::spawn(async move {
                let mut report = WorkerReport::default();
                for put in batch {
                    let put_start = Instant::now();
                    let result = run_put(&db, put).await;
                    report.latencies.push(put_start.elapsed());
                    match result {
                        Ok(()) => report.ok += 1,
                        Err((kind, message)) => {
                            let entry = report
                                .errors
                                .entry(kind.to_owned())
                                .or_insert_with(|| (0, message.chars().take(200).collect()));
                            entry.0 += 1;
                        }
                    }
                }
                report
            })
        })
        .collect::<Vec<_>>();

    let mut latencies = Vec::with_capacity(PUTS_PER_CELL);
    let mut ok = 0;
    let mut errors: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for handle in handles {
        let report = handle.await?;
        latencies.extend(report.latencies);
        ok += report.ok;
        for (kind, (count, example)) in report.errors {
            errors.entry(kind).or_insert((0, example)).0 += count;
        }
    }
    let wall = start.elapsed();
    latencies.sort_unstable();

    let spaces = owners.iter().map(|o| o.space.clone()).collect::<Vec<_>>();
    let (event_rows, duplicate_seq_groups) = integrity(conn, &spaces).await?;

    Ok(CellReport {
        layout,
        concurrency,
        attempted: latencies.len(),
        ok,
        wall,
        p50: percentile(&latencies, 50),
        p95: percentile(&latencies, 95),
        errors,
        event_rows,
        duplicate_seq_groups,
    })
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

fn print_table(reports: &[CellReport]) {
    println!();
    println!(
        "TC-732 PostgreSQL KV write throughput ({PUTS_PER_CELL} owner-root puts per cell, \
         pool max_connections = {MAX_CONNECTIONS}, profile = {})",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    println!();
    println!(
        "| layout | concurrency | puts | ok | errors | ok ops/s | p50 ms | p95 ms | \
         event_order rows | dup (space,seq) groups | error kinds |"
    );
    println!("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|");
    for r in reports {
        let error_count = r.attempted - r.ok;
        let kinds = if r.errors.is_empty() {
            "-".to_owned()
        } else {
            r.errors
                .iter()
                .map(|(kind, (count, _))| format!("{kind} ×{count}"))
                .collect::<Vec<_>>()
                .join("; ")
        };
        println!(
            "| {} | {} | {} | {} | {} | {:.1} | {:.2} | {:.2} | {} | {} | {} |",
            r.layout.label(),
            r.concurrency,
            r.attempted,
            r.ok,
            error_count,
            r.ok as f64 / r.wall.as_secs_f64(),
            ms(r.p50),
            ms(r.p95),
            r.event_rows,
            r.duplicate_seq_groups,
            kinds,
        );
    }
    let examples = reports
        .iter()
        .flat_map(|r| {
            r.errors.iter().map(move |(kind, (_, example))| {
                (
                    format!("{} c={}", r.layout.label(), r.concurrency),
                    kind,
                    example,
                )
            })
        })
        .collect::<Vec<_>>();
    if !examples.is_empty() {
        println!();
        println!("Error examples (first occurrence per kind):");
        for (cell, kind, example) in examples {
            println!("- [{cell}] {kind}: {example}");
        }
    }
    println!();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "manual benchmark; requires TINYCLOUD_TEST_POSTGRES_URL"]
async fn postgres_kv_write_throughput() {
    let database_url = match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!(
                "skipping postgres_kv_write_throughput: TINYCLOUD_TEST_POSTGRES_URL is unset"
            );
            return;
        }
    };

    let admin = Database::connect(ConnectOptions::new(database_url.clone()))
        .await
        .expect("connect to PostgreSQL benchmark database");
    let schema = format!(
        "tc732bench_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await
        .expect("create isolated TC-732 benchmark schema");

    let exercise: Result<Vec<CellReport>, BoxError> = async {
        let mut options = ConnectOptions::new(database_url);
        options
            .max_connections(MAX_CONNECTIONS)
            .sqlx_logging(false)
            .set_schema_search_path(schema.clone());
        let conn = Database::connect(options).await?;
        let db = Arc::new(
            SpaceDatabase::new(
                conn.clone(),
                MemoryStore::default(),
                StaticSecret::new(vec![0u8; 32]).map_err(|_| "static secret too short")?,
            )
            .await?,
        );

        // Untimed, unreported warm-up cell (pool connections, prepared
        // statements, PostgreSQL plan caches) on its own spaces, so the first
        // reported cell is not penalised by cold-start costs.
        run_cell(&db, &conn, 0, Layout::ManySpaces, 8).await?;

        let mut reports = Vec::new();
        let mut cell = 1;
        for layout in [Layout::SameSpace, Layout::ManySpaces] {
            for concurrency in CONCURRENCY {
                reports.push(run_cell(&db, &conn, cell, layout, concurrency).await?);
                cell += 1;
            }
        }
        conn.close().await?;
        Ok(reports)
    }
    .await;

    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await
        .expect("drop isolated TC-732 benchmark schema");

    let reports = exercise.expect("TC-732 benchmark harness failed");
    print_table(&reports);
}

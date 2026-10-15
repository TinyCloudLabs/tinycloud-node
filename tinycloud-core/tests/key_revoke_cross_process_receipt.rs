//! Two independent PostgreSQL clients must agree on the first self-revoke receipt.
use std::{
    process::{Child, Command, Stdio},
    time::Duration,
};

use tinycloud_core::{
    db::SpaceDatabase,
    keys::{public_key_to_did_key, Keypair, StaticSecret},
    migrations::Migrator,
    models::key_revocation::{self, KeyRevokeReceipt, KeyRevokeScope, VerifiedKeyRevoke},
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, DbBackend, EntityTrait, Statement, TransactionTrait,
    },
    sea_orm_migration::MigratorTrait,
    storage::memory::MemoryStore,
};
use tokio::time::{sleep, timeout, Instant};

const TEST: &str = "postgres_cross_process_self_revoke_returns_one_immutable_receipt";
const MARKER: &str = "TC1149_CROSS_PROCESS_WORKER";
const RECEIPT: &str = "TC1149_RECEIPT:";
const ERROR: &str = "TC1149-REVOKE-RESULT:";
const NONCE: &str = "tc1149-cross-process-identical-self-revoke";
const AUTHORIZATION_HASH: [u8; 32] = [19; 32];

fn target_did() -> String {
    public_key_to_did_key(Keypair::ed25519_from_bytes([37; 32]).unwrap().public())
}

fn request(now: i64) -> VerifiedKeyRevoke {
    let target_did = target_did();
    VerifiedKeyRevoke {
        issuer_did: target_did.clone(),
        target_did,
        scope: KeyRevokeScope::Global,
        nonce: NONCE.into(),
        authorization_hash: AUTHORIZATION_HASH,
        proof_cids: Vec::new(),
        not_before: now,
        valid_after: None,
        expires_at: now + 60,
    }
}

fn postgres_url() -> Option<String> {
    match std::env::var("TINYCLOUD_TEST_POSTGRES_URL") {
        Ok(url) if !url.trim().is_empty() => Some(url),
        _ => {
            assert!(
                std::env::var_os("CI").is_none(),
                "{TEST} requires TINYCLOUD_TEST_POSTGRES_URL in CI"
            );
            eprintln!("skipping {TEST}: TINYCLOUD_TEST_POSTGRES_URL is unset");
            None
        }
    }
}

fn connection_options(url: &str, schema: &str) -> ConnectOptions {
    let mut options = ConnectOptions::new(url);
    options
        .max_connections(1)
        .sqlx_logging(false)
        .set_schema_search_path(schema);
    options
}

// Drop is synchronous so cleanup also runs while an assertion is unwinding.
struct Schema {
    url: String,
    name: String,
    conn: DatabaseConnection,
}

impl Schema {
    async fn new(url: String) -> Self {
        let name = format!(
            "tc1149_receipt_{}_{}",
            std::process::id(),
            time::OffsetDateTime::now_utc().unix_timestamp_nanos()
        );
        let admin = Database::connect(ConnectOptions::new(&url))
            .await
            .expect("connect to PG");
        admin
            .execute_unprepared(&format!("CREATE SCHEMA {name}"))
            .await
            .expect("create isolated schema");
        admin.close().await.expect("close schema admin");
        let conn = Database::connect(connection_options(&url, &name))
            .await
            .expect("connect to isolated schema");
        let fixture = Self { url, name, conn };
        Migrator::up(&fixture.conn, None)
            .await
            .expect("migrate isolated schema");
        fixture
    }
}

impl Drop for Schema {
    fn drop(&mut self) {
        let url = self.url.clone();
        let name = self.name.clone();
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("schema cleanup runtime")
                .block_on(async move {
                    timeout(Duration::from_secs(10), async {
                        let admin = Database::connect(ConnectOptions::new(url)).await?;
                        // A failed assertion may leave a worker waiting on our row lock.
                        // Only sessions bearing this schema's two unique application names are killed.
                        let terminate = Statement::from_sql_and_values(
                            DbBackend::Postgres,
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
                             WHERE application_name IN ($1, $2) AND pid <> pg_backend_pid()",
                            vec![format!("{name}_one").into(), format!("{name}_two").into()],
                        );
                        admin.query_all(terminate).await?;
                        admin
                            .execute_unprepared(&format!("DROP SCHEMA IF EXISTS {name} CASCADE"))
                            .await?;
                        admin.close().await
                    })
                    .await
                })
        })
        .join();
        if !matches!(result, Ok(Ok(Ok(())))) {
            eprintln!("isolated PG receipt schema cleanup failed");
        }
    }
}

// Kill and reap both OS processes even if a parent assertion panics.
struct Workers(Vec<Option<Child>>);

impl Drop for Workers {
    fn drop(&mut self) {
        for child in self.0.iter_mut().flatten() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn worker(url: String, schema: String, label: &str, now: i64) {
    let conn = Database::connect(connection_options(&url, &schema))
        .await
        .expect("worker connects to its own PG pool");
    let db = SpaceDatabase::new(
        conn,
        MemoryStore::default(),
        StaticSecret::new(vec![0; 32]).unwrap(),
    )
    .await
    .expect("worker opens database");
    db.connection()
        .execute_unprepared(&format!("SET application_name = '{schema}_{label}'"))
        .await
        .expect("name worker PostgreSQL session");
    match db.revoke_key(request(now)).await {
        Ok(receipt) => println!("{RECEIPT}{}", serde_json::to_string(&receipt).unwrap()),
        Err(key_revocation::KeyRevokeError::Forbidden) => println!("{ERROR}403"),
        Err(key_revocation::KeyRevokeError::Conflict) => println!("{ERROR}409"),
        Err(key_revocation::KeyRevokeError::Db { .. }) => println!("{ERROR}503"),
    }
}

fn receipt_from(output: std::process::Output) -> KeyRevokeReceipt {
    assert!(
        output.status.success(),
        "cross-process revoke worker failed"
    );
    let text = std::str::from_utf8(&output.stdout).expect("worker stdout is UTF-8");
    let error = text.lines().find_map(|line| line.strip_prefix(ERROR));
    assert!(
        error.is_none(),
        "concurrent worker returned {error:?} instead of committed receipt"
    );
    let receipts: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix(RECEIPT))
        .collect();
    assert_eq!(
        receipts.len(),
        1,
        "worker must produce exactly one live receipt"
    );
    serde_json::from_str(receipts[0]).expect("worker receipt is valid JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_cross_process_self_revoke_returns_one_immutable_receipt() {
    if let Some(label) = std::env::var_os(MARKER) {
        let label = label.to_str().expect("worker label UTF-8");
        assert!(label == "one" || label == "two", "recognized worker label");
        let url = postgres_url().expect("worker requires PostgreSQL URL");
        let schema = std::env::var("TC1149_RECEIPT_SCHEMA").expect("parent supplies schema");
        let now = std::env::var("TC1149_RECEIPT_NOW")
            .expect("parent supplies signed time")
            .parse()
            .expect("valid signed time");
        worker(url, schema, label, now).await;
        return;
    }
    let Some(url) = postgres_url() else { return };
    let schema = Schema::new(url.clone()).await;
    let target = target_did();
    key_revocation::target::ActiveModel {
        target_did: Set(target.clone()),
    }
    .insert(&schema.conn)
    .await
    .expect("pre-create target lock row");
    let guard = schema
        .conn
        .begin()
        .await
        .expect("open shared-lock transaction");
    let locked = guard
        .query_one(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT target_did FROM key_revocation_target \
         WHERE target_did = $1 FOR SHARE",
            vec![target.clone().into()],
        ))
        .await
        .expect("hold PG shared row guard")
        .expect("target row exists");
    assert_eq!(locked.try_get::<String>("", "target_did").unwrap(), target);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let exe = std::env::current_exe().expect("current test executable");
    let mut workers = Workers(Vec::new());
    for label in ["one", "two"] {
        let mut command = Command::new(&exe);
        command
            .arg("--exact")
            .arg(TEST)
            .arg("--nocapture")
            .env(MARKER, label)
            .env("TC1149_RECEIPT_SCHEMA", &schema.name)
            .env("TC1149_RECEIPT_NOW", now.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        workers.0.push(Some(
            command.spawn().expect("spawn independent revoke worker"),
        ));
    }
    let observer = Database::connect(ConnectOptions::new(&url))
        .await
        .expect("independent PG activity observer");
    let one = format!("{}_one", schema.name);
    let two = format!("{}_two", schema.name);
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let blocked = observer
            .query_all(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT application_name, pid FROM pg_stat_activity \
             WHERE application_name IN ($1, $2) AND state = 'active' \
             AND wait_event_type = 'Lock' \
             AND query LIKE '%key_revocation_target%' AND query ILIKE '%FOR UPDATE%'",
                vec![one.clone().into(), two.clone().into()],
            ))
            .await
            .expect("inspect blocked worker backends");
        if blocked.len() == 2 {
            let mut names = Vec::new();
            let mut pids = Vec::new();
            for row in blocked {
                names.push(row.try_get::<String>("", "application_name").unwrap());
                pids.push(row.try_get::<i32>("", "pid").unwrap());
            }
            names.sort();
            assert_eq!(
                names,
                [one.clone(), two.clone()],
                "both named processes reach target SQL"
            );
            assert_ne!(
                pids[0], pids[1],
                "workers use different PostgreSQL backends"
            );
            break;
        }
        if Instant::now() >= deadline {
            let sessions = observer
                .query_all(Statement::from_sql_and_values(
                    DbBackend::Postgres,
                    "SELECT application_name, state, wait_event_type, query FROM pg_stat_activity \
                 WHERE application_name IN ($1, $2)",
                    vec![one.clone().into(), two.clone().into()],
                ))
                .await
                .expect("inspect named worker sessions");
            let waiting: Vec<_> = sessions
                .iter()
                .map(|row| {
                    let name: String = row.try_get("", "application_name").unwrap();
                    let state: String = row.try_get("", "state").unwrap();
                    let event: Option<String> = row.try_get("", "wait_event_type").unwrap();
                    let query: String = row.try_get("", "query").unwrap();
                    (
                        name,
                        state,
                        event,
                        query.contains("key_revocation_target"),
                        query.to_ascii_uppercase().contains("FOR UPDATE"),
                    )
                })
                .collect();
            let exits: Vec<_> = workers
                .0
                .iter_mut()
                .map(|child| {
                    child
                        .as_mut()
                        .unwrap()
                        .try_wait()
                        .unwrap()
                        .map(|status| status.code())
                })
                .collect();
            panic!("workers did not reach target row guard: sessions {waiting:?}, exit codes {exits:?}");
        }
        sleep(Duration::from_millis(20)).await;
    }
    guard.commit().await.expect("release FOR SHARE row guard");
    let mut receipts = Vec::new();
    let completion_deadline = Instant::now() + Duration::from_secs(20);
    for worker in &mut workers.0 {
        loop {
            if worker
                .as_mut()
                .unwrap()
                .try_wait()
                .expect("inspect worker status")
                .is_some()
            {
                break;
            }
            assert!(
                Instant::now() < completion_deadline,
                "blocked worker finishes after release"
            );
            sleep(Duration::from_millis(20)).await;
        }
        let child = worker.take().unwrap();
        receipts.push(receipt_from(
            child.wait_with_output().expect("read worker receipt"),
        ));
    }
    assert_eq!(
        receipts[0], receipts[1],
        "concurrent requests share the immutable first receipt"
    );
    assert!(receipts[0].revoked);
    assert_eq!(receipts[0].target_did, target);
    assert_eq!(receipts[0].scope, KeyRevokeScope::Global);
    let persisted = key_revocation::nonce::Entity::find_by_id((target.clone(), NONCE.into()))
        .one(&schema.conn)
        .await
        .expect("read durable nonce")
        .expect("receipt persisted");
    assert_eq!(persisted.authorization_hash, AUTHORIZATION_HASH.to_vec());
    assert_eq!(
        persisted.receipt_bytes,
        serde_json::to_vec(&receipts[0]).expect("serialize immutable receipt")
    );
    let fresh = SpaceDatabase::new(
        Database::connect(connection_options(&url, &schema.name))
            .await
            .expect("cold connection"),
        MemoryStore::default(),
        StaticSecret::new(vec![0; 32]).unwrap(),
    )
    .await
    .expect("cold database opens");
    assert_eq!(
        fresh
            .revoke_key(request(now))
            .await
            .expect("committed receipt replays"),
        receipts[0],
        "replay on fresh connection preserves first receipt"
    );
}

//! TC-2871: the space purge wired into the running node. Lifecycle is on only
//! with `TINYCLOUD_HOST_ID` and `TINYCLOUD_PURGE_LEDGER_KEYS` (JSON form);
//! startup verifies and reconciles the ledger before it serves; the spawned
//! worker completes an accepted purge; `tinycloud node purge-ledger reconcile`
//! runs the same pass once.
mod common;

use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use tinycloud::{
    config::{Config, PurgeLedgerKeys},
    space_lifecycle::{LifecycleRuntime, PurgeResponse},
    storage::{
        purge_ledger::{FsPurgeLedger, PurgeLedgerConfig, PurgeLedgerStore},
        purge_reconcile::PrefixStoreKind,
        sql_object::purge::SqlPhysicalPrefix,
    },
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    migrations::Migrator,
    models::space,
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ConnectionTrait, Database, DatabaseConnection,
        DbBackend, Statement,
    },
    sea_orm_migration::MigratorTrait,
    space_purge_ledger::{LedgerKeys, LedgerRecord},
    storage::either::Either,
};

const HOST: &str = "host-test";
const KEY_ID: &str = "plk-20261119";

fn ledger_secret() -> String {
    base64::encode_config([7u8; 32], base64::URL_SAFE_NO_PAD)
}

fn ledger_keys_json() -> String {
    format!(
        r#"{{"active_key_id":"{KEY_ID}","keys":{{"{KEY_ID}":"{}"}}}}"#,
        ledger_secret()
    )
}

fn node_config(datadir: &Path, database: &str) -> Config {
    let mut config = Config::default();
    config.storage.datadir = datadir.into();
    config.storage.database = Some(database.into());
    config.keys = serde_json::from_value(serde_json::json!({
        "type": "static",
        "secret": base64::encode_config([0x42; 32], base64::URL_SAFE_NO_PAD),
    }))
    .unwrap();
    config
}

/// The test figment; `ledger_keys` turns lifecycle on with host `host-test`.
fn figment(config: &Config, ledger_keys: Option<&str>) -> Figment {
    let figment = Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..Default::default()
    })
    .merge(Serialized::defaults(config));
    match ledger_keys {
        Some(keys) => figment
            .merge(Serialized::default("host_id", HOST))
            .merge(Serialized::default("purge_ledger_keys", keys)),
        None => figment,
    }
}

/// A PostgreSQL URL scoped to a fresh schema, and a connection to it.
async fn scoped_postgres(test: &str) -> Option<(String, DatabaseConnection)> {
    let url = common::postgres_test_url(test)?;
    let admin = Database::connect(url.as_str()).await.unwrap();
    let schema = format!("tc2871_wiring_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut scoped = reqwest::Url::parse(&url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    let db = Database::connect(scoped.as_str()).await.unwrap();
    Some((scoped.to_string(), db))
}

fn resolved_paths(figment: &Figment) -> (PathBuf, PathBuf) {
    let resolved =
        tinycloud::resolve_runtime_config(&figment.extract::<Config>().unwrap()).unwrap();
    let Either::B(blocks) = &resolved.storage.blocks else {
        panic!("filesystem blocks expected");
    };
    let Some(PurgeLedgerConfig::Local { path }) = &resolved.storage.purge_ledger else {
        panic!("local purge ledger expected");
    };
    (blocks.path().to_path_buf(), path.clone())
}

fn new_owner() -> (JWK, String) {
    let mut key = JWK::generate_secp256k1();
    key.algorithm = Some(Algorithm::ES256KR);
    let owner = DID_METHODS
        .generate(&key, "pkh:eip155")
        .unwrap()
        .to_string();
    (key, owner)
}

fn signed(key: &JWK, owner: &str, space: &SpaceId, id: &str) -> String {
    let now = OffsetDateTime::now_utc().unix_timestamp() as f64;
    make_invocation_from_uris(
        [(
            format!("{space}/space").parse().unwrap(),
            ["tinycloud.space/delete".parse().unwrap()],
        )],
        &Cid::default(),
        key,
        &format!("{owner}#blockchainAccountId"),
        now + 300.0,
        InvocationOptions {
            not_before: Some(now),
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            facts: Some(vec![
                serde_json::json!({"idempotency_key":id,"hostId":HOST}),
            ]),
            proof: Some(vec![]),
        },
    )
    .unwrap()
    .encode()
    .unwrap()
}

/// A signed acceptance for `space` with the prefixes this node's layout
/// signs, published `age` seconds ago.
fn acceptance(keys: &LedgerKeys, space: &SpaceId, purge_id: &str, age: i64) -> LedgerRecord {
    let digest = keys
        .target_hmac(KEY_ID, "space", &space.to_string())
        .unwrap();
    let record = keys
        .sign(
            KEY_ID,
            "space",
            &digest,
            purge_id,
            "purging",
            OffsetDateTime::now_utc().unix_timestamp() - age,
        )
        .unwrap();
    let mut prefixes = vec![
        (
            PrefixStoreKind::KvFileSystem,
            format!("{}/{}/", space.suffix(), space.name()),
        ),
        (
            PrefixStoreKind::SqlFileSystem,
            SqlPhysicalPrefix::for_space(space).as_str().to_owned(),
        ),
        (PrefixStoreKind::SqliteCache, format!("{space}/")),
    ];
    prefixes.extend(
        cfg!(feature = "duckdb").then(|| (PrefixStoreKind::DuckDbCache, format!("{space}/"))),
    );
    let prefixes = prefixes
        .into_iter()
        .map(|(kind, prefix)| keys.prefix_hmac(KEY_ID, kind.as_str(), &prefix).unwrap())
        .collect();
    keys.with_prefixes(record, prefixes).unwrap()
}

async fn publish(ledger_root: &Path, record: &LedgerRecord) {
    FsPurgeLedger::new(ledger_root.to_path_buf())
        .unwrap()
        .append_purge_record(&record.object_key().unwrap(), &record.to_bytes().unwrap())
        .await
        .unwrap();
}

async fn insert_space(db: &DatabaseConnection, space: &SpaceId) {
    space::ActiveModel {
        id: Set(space.clone().into()),
    }
    .insert(db)
    .await
    .unwrap();
}

fn write_kv(blocks_root: &Path, space: &SpaceId) -> PathBuf {
    let kv = blocks_root.join(space.suffix()).join(space.name().as_str());
    std::fs::create_dir_all(&kv).unwrap();
    for n in 0..3 {
        std::fs::write(kv.join(n.to_string()), b"kv bytes").unwrap();
    }
    kv
}

fn kv_is_empty(kv: &Path) -> bool {
    std::fs::read_dir(kv).map_or(true, |mut entries| entries.next().is_none())
}

async fn count(db: &DatabaseConnection, sql: &str) -> i64 {
    db.query_one(Statement::from_string(DbBackend::Postgres, sql))
        .await
        .unwrap()
        .unwrap()
        .try_get_by_index::<i64>(0)
        .unwrap()
}

/// Run the released binary with a scrubbed environment.
fn run_tinycloud(args: &[&str], env: &[(&str, &str)]) -> Output {
    let home = tempfile::tempdir().unwrap();
    Command::new(env!("CARGO_BIN_EXE_tinycloud"))
        .args(args)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path().join("xdg-config"))
        .env("XDG_DATA_HOME", home.path().join("xdg-data"))
        .env("XDG_STATE_HOME", home.path().join("xdg-state"))
        .env(
            "TINYCLOUD_NODE_CONFIG_ROOT",
            home.path().join("node-config"),
        )
        .envs(env.iter().copied())
        .current_dir(home.path())
        .output()
        .unwrap()
}

#[tokio::test]
async fn lifecycle_off_routes_404_and_nothing_is_wired() {
    let dir = tempfile::tempdir().unwrap();
    let figment = figment(&node_config(dir.path(), "sqlite::memory:"), None);
    let client = Client::tracked(tinycloud::app(&figment).await.unwrap())
        .await
        .unwrap();
    assert!(client.rocket().state::<LifecycleRuntime>().is_none());
    for path in [
        "/space/list",
        "/space/retire-owner",
        "/space/purge",
        "/space/purge/status",
    ] {
        let response = client
            .post(path)
            .header(ContentType::JSON)
            .body("{}")
            .dispatch()
            .await;
        assert_eq!(response.status(), Status::NotFound, "{path}");
    }
    let (_, ledger_root) = resolved_paths(&figment);
    assert!(
        !ledger_root.exists(),
        "an off node must not create a purge ledger"
    );
}

#[tokio::test]
async fn bare_ledger_key_is_refused_at_startup_without_echoing_it() {
    let dir = tempfile::tempdir().unwrap();
    let secret = ledger_secret();
    let figment = figment(&node_config(dir.path(), "sqlite::memory:"), Some(&secret));
    let Err(error) = tinycloud::app(&figment).await else {
        panic!("the bare-key form must stop the start");
    };
    let error = format!("{error:#}");
    assert!(error.contains("bare-key form is refused"), "{error}");
    assert!(!error.contains(&secret));
    assert!(!format!("{:?}", PurgeLedgerKeys::new(secret.clone())).contains(&secret));
}

#[test]
fn ledger_keys_env_takes_the_json_form_only() {
    let node_secret = base64::encode_config([0x42; 32], base64::URL_SAFE_NO_PAD);
    let secret = ledger_secret();
    let json = ledger_keys_json();
    let base = [
        ("TINYCLOUD_KEYS__TYPE", "static"),
        ("TINYCLOUD_KEYS__SECRET", node_secret.as_str()),
        ("TINYCLOUD_HOST_ID", "node-test-1"),
        (
            "TINYCLOUD_STORAGE__DATABASE",
            "postgres://127.0.0.1:1/unused",
        ),
    ];
    let bare = run_tinycloud(
        &["--validate-config"],
        &[
            &base[..],
            &[("TINYCLOUD_PURGE_LEDGER_KEYS", secret.as_str())],
        ]
        .concat(),
    );
    let stderr = String::from_utf8_lossy(&bare.stderr);
    assert_eq!(bare.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("bare-key form is refused"), "{stderr}");
    assert!(!stderr.contains(&secret));
    let valid = run_tinycloud(
        &["--validate-config"],
        &[&base[..], &[("TINYCLOUD_PURGE_LEDGER_KEYS", json.as_str())]].concat(),
    );
    let stderr = String::from_utf8_lossy(&valid.stderr);
    assert_eq!(valid.status.code(), Some(0), "stderr: {stderr}");
    assert!(!stderr.contains(&secret));
    let half = run_tinycloud(&["--validate-config"], &base);
    assert_eq!(half.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&half.stderr).contains("together, or neither"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lifecycle_on_accepts_a_purge_that_the_spawned_worker_completes() {
    let Some((url, db)) = scoped_postgres("lifecycle_on_accepts_a_purge").await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let keys_json = ledger_keys_json();
    let figment = figment(&node_config(dir.path(), &url), Some(&keys_json));
    let client = Client::tracked(tinycloud::app(&figment).await.unwrap())
        .await
        .unwrap();
    assert!(client.rocket().state::<LifecycleRuntime>().is_some());
    let (blocks_root, ledger_root) = resolved_paths(&figment);
    let keys = LedgerKeys::from_config(keys_json).unwrap();
    let (key, owner) = new_owner();
    let target: SpaceId = format!("tinycloud:{}:app", &owner[4..]).parse().unwrap();
    insert_space(&db, &target).await;
    let kv = write_kv(&blocks_root, &target);

    // A crash after the external ledger write and before the database commit
    // left this acceptance, published ten minutes ago (past the upload grace).
    // The owner's request finds it and binds the job to it.
    let purge_id = uuid::Uuid::new_v4().to_string();
    publish(&ledger_root, &acceptance(&keys, &target, &purge_id, 600)).await;
    let response = client
        .post("/space/purge")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&key, &owner, &target, &purge_id),
        ))
        .header(Header::new("Idempotency-Key", purge_id.clone()))
        .json(&serde_json::json!({"version":1,"space_id":target.to_string()}))
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Accepted);
    let accepted = response.into_json::<PurgeResponse>().await.unwrap();
    assert_eq!(accepted.purge_id, purge_id);
    assert_eq!(accepted.state, "purging");
    assert_eq!(accepted.host_id, HOST);

    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let complete = count(
            &db,
            &format!(
                "SELECT count(*) FROM space_purge_job WHERE purge_id='{purge_id}' AND phase='complete'"
            ),
        )
        .await;
        if complete == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the spawned worker did not complete the accepted purge"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(
        kv_is_empty(&kv),
        "the purge must remove the space's KV bytes"
    );
    assert_eq!(count(&db, "SELECT count(*) FROM space").await, 0);
    assert_eq!(
        count(&db, "SELECT count(*) FROM space_purge_tombstone").await,
        1
    );
    let status_key = uuid::Uuid::new_v4().to_string();
    let status = client
        .post("/space/purge/status")
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            signed(&key, &owner, &target, &status_key),
        ))
        .header(Header::new("Idempotency-Key", status_key))
        .json(&serde_json::json!({"version":1,"purge_id":purge_id,"space_id":target.to_string()}))
        .dispatch()
        .await;
    assert_eq!(status.status(), Status::Ok);
    assert_eq!(
        status.into_json::<PurgeResponse>().await.unwrap().state,
        "complete"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_ledger_record_stops_the_start() {
    let Some((url, _db)) = scoped_postgres("tampered_ledger_record_stops_the_start").await else {
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let keys_json = ledger_keys_json();
    let figment = figment(&node_config(dir.path(), &url), Some(&keys_json));
    let (_, ledger_root) = resolved_paths(&figment);
    let keys = LedgerKeys::from_config(keys_json.clone()).unwrap();
    let (_, owner) = new_owner();
    let target: SpaceId = format!("tinycloud:{}:app", &owner[4..]).parse().unwrap();
    let record = acceptance(&keys, &target, &uuid::Uuid::new_v4().to_string(), 600);
    let mut body: serde_json::Value = serde_json::from_slice(&record.to_bytes().unwrap()).unwrap();
    body["timestamp"] = serde_json::json!(record.timestamp + 1);
    FsPurgeLedger::new(ledger_root)
        .unwrap()
        .append_purge_record(
            &record.object_key().unwrap(),
            &serde_json::to_vec(&body).unwrap(),
        )
        .await
        .unwrap();
    let Err(error) = tinycloud::app(&figment).await else {
        panic!("a tampered ledger record must stop the start");
    };
    let error = format!("{error:#}");
    assert!(
        error.contains("purge ledger reconciliation failed")
            || error.contains("space lifecycle runtime unavailable"),
        "{error}"
    );
    assert!(!error.contains(&ledger_secret()), "{error}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_reconcile_is_idempotent_and_reports_counts_only() {
    let Some((url, db)) = scoped_postgres("cli_reconcile_is_idempotent").await else {
        return;
    };
    Migrator::up(&db, None).await.unwrap();
    let dir = tempfile::tempdir().unwrap();
    let datadir = dir.path().join("data");
    let config_path = dir.path().join("tinycloud.toml");
    std::fs::write(
        &config_path,
        format!(
            "[global.storage]\ndatadir = \"{}\"\ndatabase = \"{url}\"\n",
            datadir.display()
        ),
    )
    .unwrap();
    let keys_json = ledger_keys_json();
    let (blocks_root, ledger_root) =
        resolved_paths(&figment(&node_config(&datadir, &url), Some(&keys_json)));
    let keys = LedgerKeys::from_config(keys_json.clone()).unwrap();

    // The restored database misses everything the ledger holds: an accepted
    // purge of a live space, a completed purge, and an owner retirement.
    let (_, owner) = new_owner();
    let live: SpaceId = format!("tinycloud:{}:live", &owner[4..]).parse().unwrap();
    let gone: SpaceId = format!("tinycloud:{}:gone", &owner[4..]).parse().unwrap();
    insert_space(&db, &live).await;
    let kv = write_kv(&blocks_root, &live);
    let live_purge = uuid::Uuid::new_v4().to_string();
    publish(&ledger_root, &acceptance(&keys, &live, &live_purge, 600)).await;
    let gone_purge = uuid::Uuid::new_v4().to_string();
    let completed = keys
        .completion_from_acceptance(
            acceptance(&keys, &gone, &gone_purge, 900),
            OffsetDateTime::now_utc().unix_timestamp() - 600,
        )
        .unwrap();
    publish(&ledger_root, &completed).await;
    let (_, retired) = new_owner();
    let retirement_id = uuid::Uuid::new_v4().to_string();
    let retirement = keys
        .sign(
            KEY_ID,
            "owner",
            &keys.target_hmac(KEY_ID, "owner", &retired).unwrap(),
            &retirement_id,
            "retired",
            OffsetDateTime::now_utc().unix_timestamp() - 60,
        )
        .unwrap();
    publish(&ledger_root, &retirement).await;

    let config_arg = config_path.to_string_lossy().into_owned();
    let env = [
        ("TINYCLOUD_HOST_ID", HOST),
        ("TINYCLOUD_PURGE_LEDGER_KEYS", keys_json.as_str()),
    ];
    let reconcile = || {
        let output = run_tinycloud(
            &[
                "node",
                "purge-ledger",
                "reconcile",
                "--config",
                &config_arg,
                "--json",
            ],
            &env,
        );
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        assert_eq!(
            output.status.code(),
            Some(0),
            "stdout: {stdout} stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        for identity in [
            live.to_string(),
            gone.to_string(),
            owner.clone(),
            retired.clone(),
            live_purge.clone(),
            gone_purge.clone(),
            retirement_id.clone(),
        ] {
            assert!(!stdout.contains(&identity), "the report names an identity");
        }
        serde_json::from_str::<serde_json::Value>(&stdout).unwrap()
    };
    let state = || async {
        let mut counts = Vec::new();
        for table in [
            "space_purge_job",
            "space_purge_tombstone",
            "space_retirement",
            "space_purge_fence",
            "space_purge_ledger_copy",
        ] {
            counts.push(count(&db, &format!("SELECT count(*) FROM {table}")).await);
        }
        counts
    };

    let first = reconcile();
    assert_eq!(first["records"], 3);
    // Completion records are not copied; the acceptance and the retirement are.
    assert_eq!(first["repaired_copies"], 2);
    assert_eq!(first["owner_retirements"], 1);
    assert_eq!(first["space_fences"], 2);
    assert_eq!(first["tombstones_created"], 1);
    assert_eq!(first["purges_resumed"], 1);
    assert_eq!(first["purges_in_progress"], 0);
    assert_eq!(first["prefixes_purged"], 1);
    assert!(
        kv_is_empty(&kv),
        "the live space's signed KV prefix is purged"
    );
    let after_first = state().await;
    assert_eq!(&after_first[..3], &[1, 1, 1]);

    let second = reconcile();
    assert_eq!(second["records"], 3);
    assert_eq!(second["repaired_copies"], 0);
    assert_eq!(second["owner_retirements"], 1);
    assert_eq!(second["space_fences"], 2);
    assert_eq!(second["tombstones_created"], 0);
    assert_eq!(second["purges_resumed"], 0);
    assert_eq!(second["purges_in_progress"], 1);
    assert!(kv_is_empty(&kv));
    assert_eq!(state().await, after_first);
}

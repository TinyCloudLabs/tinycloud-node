//! TC-2871 erase-30 proof: the whole space purge on PostgreSQL and MinIO,
//! through the running node with lifecycle on (JSON ledger keys, host id).
//!
//! An owner with two spaces (KV through `/invoke`, SQL with chunked
//! checkpoints, SQL objects, an encryption network) retires; each space is
//! purged through `/space/purge` and the spawned worker erases it from
//! PostgreSQL and the data bucket. A restore of the pre-purge database and
//! objects is then erased again from the ledger alone, by the reconcile pass
//! that startup and `tinycloud node purge-ledger reconcile` run, and further
//! passes change nothing.
//!
//! Needs `TINYCLOUD_TEST_POSTGRES_URL` (gated as `common::postgres_test_url`),
//! `TC735_TEST_MINIO_ENDPOINT`, `TC735_TEST_MINIO_BUCKET` and the `AWS_*`
//! credentials; skips without the MinIO endpoint. The test creates its own
//! data and ledger (Object Lock) buckets and removes them at the end.
mod common;

use base64::URL_SAFE_NO_PAD;
use k256::ecdsa::SigningKey;
use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use time::OffsetDateTime;
use tinycloud::{
    config::Config,
    space_lifecycle::{reconcile::ReconcileReport, LifecycleRuntime, PurgeResponse},
    space_purge_executor::{PurgeSqlObjects, PurgeStores},
    storage::{
        purge_ledger::{PurgeLedgerConfig, PurgeLedgerStore, S3PurgeLedgerConfig},
        purge_reconcile::PrefixStoreKind,
        s3::S3BlockConfig,
        sql_object::purge::SqlPhysicalPrefix,
    },
};
use tinycloud_auth::{
    authorization::{make_invocation_from_uris, Cid, InvocationOptions},
    cacaos::{siwe::Message, siwe_cacao::Signature},
    identity::canonicalize_did,
    resolver::DID_METHODS,
    resource::{Path as KvPath, Service, SpaceId},
    siwe_recap::Ability,
    ssi::jwk::{Algorithm, JWK},
};
use tinycloud_core::{
    sea_orm::{ConnectionTrait, Database, DatabaseConnection, DbBackend, Statement},
    space_purge_database::{PURGED_BY_OWNER, PURGED_BY_SPACE},
    space_purge_fence::FenceError,
    space_purge_ledger::{LedgerKeys, LedgerRecord},
    sql::{SqlRequest, SqlService},
    storage::{either::Either, StorageConfig},
};
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SignedSession},
};

const HOST: &str = "host-test";
const KEY_ID: &str = "plk-20261119";
/// Lifecycle tables whose rows a reconcile pass creates; equal across
/// repeated passes when reconciliation is idempotent.
const LIFECYCLE_TABLES: &[&str] = &[
    "space_purge_job",
    "space_purge_tombstone",
    "space_purge_fence",
    "space_purge_ledger_copy",
    "space_retirement",
];

fn ledger_keys_json() -> String {
    format!(
        r#"{{"active_key_id":"{KEY_ID}","keys":{{"{KEY_ID}":"{}"}}}}"#,
        base64::encode_config([23u8; 32], URL_SAFE_NO_PAD)
    )
}

struct Stores {
    endpoint: String,
    data: String,
    ledger: String,
}

fn node_config(datadir: &Path, database: &str, stores: &Stores) -> Config {
    let mut config = Config::default();
    config.storage.datadir = datadir.into();
    config.storage.database = Some(database.into());
    config.storage.blocks = Either::A(S3BlockConfig {
        bucket: stores.data.clone(),
        endpoint: Some(stores.endpoint.parse().unwrap()),
    });
    config.storage.purge_ledger = Some(PurgeLedgerConfig::S3(S3PurgeLedgerConfig {
        bucket: stores.ledger.clone(),
        endpoint: Some(stores.endpoint.parse().unwrap()),
        region: None,
        access_key_id: None,
        secret_access_key: None,
    }));
    // File-backed SQL databases whose checkpoints are chunked in PostgreSQL.
    config.storage.sql.memory_threshold = 0u64.into();
    config.storage.sql.chunked_artifacts = true;
    config.storage.sql.chunked_artifact_max_bytes = 64 << 20;
    config.storage.sql.chunked_account_max_bytes = 256 << 20;
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config([0x42; 32], URL_SAFE_NO_PAD),
    }))
    .unwrap();
    config
}

fn figment(config: &Config) -> Figment {
    Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..Default::default()
    })
    .merge(Serialized::defaults(config))
    .merge(Serialized::default("host_id", HOST))
    .merge(Serialized::default("purge_ledger_keys", ledger_keys_json()))
}

fn resolved(figment: &Figment) -> Config {
    tinycloud::resolve_runtime_config(&figment.extract::<Config>().unwrap()).unwrap()
}

/// A PostgreSQL URL scoped to a fresh schema, the schema, and a connection.
async fn scoped_postgres(url: &str) -> (String, String, DatabaseConnection) {
    let admin = Database::connect(url).await.unwrap();
    let schema = format!("tc2871_e2e_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    admin.close().await.unwrap();
    let mut scoped = reqwest::Url::parse(url).unwrap();
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    let db = Database::connect(scoped.as_str()).await.unwrap();
    (scoped.to_string(), schema, db)
}

async fn count(
    db: &DatabaseConnection,
    sql: &str,
    values: Vec<tinycloud_core::sea_orm::Value>,
) -> i64 {
    db.query_one(Statement::from_sql_and_values(
        DbBackend::Postgres,
        sql,
        values,
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get_by_index::<i64>(0)
    .unwrap()
}

/// Rows of `table` whose text form names `needle` (any column).
async fn rows_naming(db: &DatabaseConnection, table: &str, needle: &str) -> i64 {
    count(
        db,
        &format!("SELECT count(*) FROM {table} r WHERE strpos(lower(r::text), lower($1)) > 0"),
        vec![needle.into()],
    )
    .await
}

/// A digest of every row of `table` that names `needle`.
async fn digest_naming(db: &DatabaseConnection, table: &str, needle: &str) -> String {
    db.query_one(Statement::from_sql_and_values(
        DbBackend::Postgres,
        format!(
            "SELECT coalesce(md5(string_agg(r::text, '|' ORDER BY r::text)), '') FROM {table} r
             WHERE strpos(lower(r::text), lower($1)) > 0"
        ),
        [needle.into()],
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get_by_index::<String>(0)
    .unwrap()
}

async fn space_digests(db: &DatabaseConnection, space: &SpaceId) -> Vec<String> {
    let mut digests = Vec::new();
    for (table, _) in PURGED_BY_SPACE {
        digests.push(digest_naming(db, table, &space.to_string()).await);
    }
    digests
}

/// Rows naming `space` in every table a space purge erases by space.
async fn space_rows(db: &DatabaseConnection, space: &SpaceId) -> BTreeMap<&'static str, i64> {
    let mut rows = BTreeMap::new();
    for (table, _) in PURGED_BY_SPACE {
        rows.insert(*table, rows_naming(db, table, &space.to_string()).await);
    }
    rows
}

async fn owner_rows(db: &DatabaseConnection, address: &str) -> BTreeMap<&'static str, i64> {
    let mut rows = BTreeMap::new();
    for (table, _) in PURGED_BY_OWNER {
        rows.insert(*table, rows_naming(db, table, address).await);
    }
    rows
}

async fn lifecycle_state(db: &DatabaseConnection) -> Vec<String> {
    let mut state = Vec::new();
    for table in LIFECYCLE_TABLES {
        state.push(digest_naming(db, table, "").await);
    }
    state
}

async fn base_tables(db: &DatabaseConnection, schema: &str) -> Vec<String> {
    db.query_all(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT table_name::text FROM information_schema.tables
         WHERE table_schema=$1 AND table_type='BASE TABLE' ORDER BY table_name",
        [schema.into()],
    ))
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.try_get_by_index::<String>(0).unwrap())
    .collect()
}

/// Copy every table of `schema` into the schema `snapshot`.
async fn snapshot_database(db: &DatabaseConnection, schema: &str, snapshot: &str) {
    db.execute_unprepared(&format!("CREATE SCHEMA {snapshot}"))
        .await
        .unwrap();
    for table in base_tables(db, schema).await {
        db.execute_unprepared(&format!(
            r#"CREATE TABLE {snapshot}."{table}" AS TABLE {schema}."{table}""#
        ))
        .await
        .unwrap();
    }
}

/// Replace every table of `schema` with its `snapshot` copy, as a restore
/// from a pre-purge backup does: the lifecycle tables come back empty.
async fn restore_database(db: &DatabaseConnection, schema: &str, snapshot: &str) {
    let tables = base_tables(db, schema).await;
    let tx = tinycloud_core::sea_orm::TransactionTrait::begin(db)
        .await
        .unwrap();
    tx.execute_unprepared("SET LOCAL session_replication_role = replica")
        .await
        .unwrap();
    let all = tables
        .iter()
        .map(|table| format!(r#"{schema}."{table}""#))
        .collect::<Vec<_>>()
        .join(",");
    tx.execute_unprepared(&format!("TRUNCATE {all}"))
        .await
        .unwrap();
    for table in base_tables(db, snapshot).await {
        let columns = tx
            .query_all(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT column_name::text FROM information_schema.columns
                 WHERE table_schema=$1 AND table_name=$2 AND is_generated='NEVER'
                 ORDER BY ordinal_position",
                [schema.into(), table.clone().into()],
            ))
            .await
            .unwrap()
            .into_iter()
            .map(|row| format!(r#""{}""#, row.try_get_by_index::<String>(0).unwrap()))
            .collect::<Vec<_>>()
            .join(",");
        tx.execute_unprepared(&format!(
            r#"INSERT INTO {schema}."{table}" ({columns}) OVERRIDING SYSTEM VALUE
               SELECT {columns} FROM {snapshot}."{table}""#
        ))
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

async fn list_keys(s3: &aws_sdk_s3::Client, bucket: &str, prefix: &str) -> Vec<String> {
    let mut pages = s3
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .into_paginator()
        .send();
    let mut keys = Vec::new();
    while let Some(page) = pages.try_next().await.unwrap() {
        keys.extend(
            page.contents()
                .iter()
                .filter_map(|o| o.key().map(str::to_owned)),
        );
    }
    keys
}

async fn get_object(s3: &aws_sdk_s3::Client, bucket: &str, key: &str) -> Vec<u8> {
    s3.get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .unwrap()
        .body
        .collect()
        .await
        .unwrap()
        .into_bytes()
        .to_vec()
}

async fn put_object(s3: &aws_sdk_s3::Client, bucket: &str, key: &str, body: Vec<u8>) {
    s3.put_object()
        .bucket(bucket)
        .key(key)
        .body(body.into())
        .send()
        .await
        .unwrap();
}

async fn objects(s3: &aws_sdk_s3::Client, bucket: &str, prefix: &str) -> BTreeMap<String, Vec<u8>> {
    let mut objects = BTreeMap::new();
    for key in list_keys(s3, bucket, prefix).await {
        let body = get_object(s3, bucket, &key).await;
        objects.insert(key, body);
    }
    objects
}

/// Every object of `space`: its KV prefix and its SQL object prefix.
async fn space_objects(
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    space: &SpaceId,
) -> BTreeMap<String, Vec<u8>> {
    let mut all = objects(s3, bucket, &format!("{space}/")).await;
    all.extend(objects(s3, bucket, SqlPhysicalPrefix::for_space(space).as_str()).await);
    all
}

/// Remove a bucket this test created, every object version first.
async fn remove_bucket(s3: &aws_sdk_s3::Client, bucket: &str) {
    loop {
        let listing = s3
            .list_object_versions()
            .bucket(bucket)
            .send()
            .await
            .unwrap();
        let versions = listing
            .versions()
            .iter()
            .map(|v| {
                (
                    v.key().map(str::to_owned),
                    v.version_id().map(str::to_owned),
                )
            })
            .chain(listing.delete_markers().iter().map(|m| {
                (
                    m.key().map(str::to_owned),
                    m.version_id().map(str::to_owned),
                )
            }))
            .collect::<Vec<_>>();
        if versions.is_empty() {
            break;
        }
        for (key, version) in versions {
            s3.delete_object()
                .bucket(bucket)
                .set_key(key)
                .set_version_id(version)
                .send()
                .await
                .unwrap();
        }
    }
    s3.delete_bucket().bucket(bucket).send().await.unwrap();
}

struct Owner {
    jwk: JWK,
    signing: SigningKey,
    did: String,
}

impl Owner {
    fn new() -> Self {
        let mut jwk = JWK::generate_secp256k1();
        jwk.algorithm = Some(Algorithm::ES256KR);
        let did = DID_METHODS
            .generate(&jwk, "pkh:eip155")
            .unwrap()
            .to_string();
        let d = serde_json::to_value(&jwk).unwrap()["d"]
            .as_str()
            .unwrap()
            .to_owned();
        let signing =
            SigningKey::from_slice(&base64::decode_config(d, URL_SAFE_NO_PAD).unwrap()).unwrap();
        Self { jwk, signing, did }
    }

    /// The EIP-55 `0x` address.
    fn address(&self) -> &str {
        self.did.rsplit(':').next().unwrap()
    }

    fn space(&self, name: &str) -> SpaceId {
        format!("tinycloud:{}:{name}", &self.did[4..])
            .parse()
            .unwrap()
    }

    fn sign(&self, message: &Message) -> [u8; 65] {
        let (signature, recovery) = self
            .signing
            .sign_prehash_recoverable(&message.eip191_hash().unwrap())
            .unwrap();
        let mut bytes = [0; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = recovery.to_byte();
        bytes
    }

    /// A lifecycle management proof for `action` on `resource`.
    fn proof(&self, action: &str, resource: &str, id: &str) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp() as f64;
        make_invocation_from_uris(
            [(resource.parse().unwrap(), [action.parse().unwrap()])],
            &Cid::default(),
            &self.jwk,
            &format!("{}#blockchainAccountId", self.did),
            now + 300.0,
            InvocationOptions {
                not_before: Some(now),
                nonce: Some(uuid::Uuid::new_v4().to_string()),
                facts: Some(vec![json!({"idempotency_key":id,"hostId":HOST})]),
                proof: Some(vec![]),
            },
        )
        .unwrap()
        .encode()
        .unwrap()
    }
}

async fn register(client: &Client, headers: &impl serde::Serialize) {
    let authorization = serde_json::to_value(headers).unwrap()["Authorization"]
        .as_str()
        .unwrap()
        .to_owned();
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", authorization))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "delegate: {body}");
}

/// Host `space` for `owner` and open a KV session on it, as the SDK does.
async fn sign_in(client: &Client, owner: &Owner, space: &SpaceId) -> Session {
    let peer = client
        .get(format!("/peer/generate/{space}"))
        .dispatch()
        .await
        .into_string()
        .await
        .unwrap();
    let rfc3339 = &time::format_description::well_known::Rfc3339;
    let now = OffsetDateTime::now_utc();
    let host = generate_host_siwe_message(
        serde_json::from_value(json!({
            "address": owner.address(),
            "chainId": 1, "domain": "localhost",
            "issuedAt": (now - time::Duration::minutes(1)).format(rfc3339).unwrap(),
            "spaceId": space,
            "peerId": peer,
        }))
        .unwrap(),
    )
    .unwrap();
    let signature = owner.sign(&host);
    let host: SignedMessage = serde_json::from_value(json!({
        "siwe": host.to_string(), "signature": format!("0x{}", hex::encode(signature)),
    }))
    .unwrap();
    register(client, &siwe_to_delegation_headers(host)).await;
    let session_key = ed25519_dalek::SigningKey::from_bytes(&rand_bytes());
    let jwk: JWK = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519",
        "d": base64::encode_config(session_key.to_bytes(), URL_SAFE_NO_PAD),
        "x": base64::encode_config(session_key.verifying_key().to_bytes(), URL_SAFE_NO_PAD),
    }))
    .unwrap();
    let prepared = prepare_session(
        serde_json::from_value(json!({
            "abilities": {"kv": {"": ["tinycloud.kv/put", "tinycloud.kv/get"]}},
            "address": owner.address(),
            "chainId": 1,
            "domain": "localhost",
            "issuedAt": (now - time::Duration::minutes(1)).format(rfc3339).unwrap(),
            "expirationTime": (now + time::Duration::hours(1)).format(rfc3339).unwrap(),
            "spaceId": space,
            "jwk": jwk,
            "nonce": uuid::Uuid::new_v4().simple().to_string(),
        }))
        .unwrap(),
    )
    .unwrap();
    let signature = owner.sign(&prepared.siwe);
    let session = complete_session_setup(SignedSession {
        session: prepared,
        signature: Signature::from(signature),
    })
    .unwrap();
    register(client, &session.delegation_header).await;
    session
}

fn rand_bytes() -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    bytes
}

async fn kv_put(client: &Client, session: &Session, key: &str, value: &[u8]) {
    let capability = session.space_id.clone().to_resource(
        "kv".parse::<Service>().unwrap(),
        Some(key.parse::<KvPath>().unwrap()),
        None,
        None,
    );
    let invocation = session
        .invoke_any(
            vec![(capability, ["tinycloud.kv/put".parse::<Ability>().unwrap()])],
            None,
        )
        .unwrap();
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", invocation.encode().unwrap()))
        .header(ContentType::Plain)
        .body(value)
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "kv put {key}: {body}");
}

async fn sql(service: &SqlService, space: &SpaceId, statement: &str) {
    service
        .execute(
            space,
            "main",
            SqlRequest::Execute {
                sql: statement.into(),
                params: vec![],
                schema: None,
            },
            None,
            "tinycloud.sql/admin".into(),
        )
        .await
        .unwrap();
}

/// A signed acceptance for `space` with the prefixes this node's S3 layout
/// signs, as the purge route builds it, published `age` seconds ago: past
/// the worker's upload grace, so the test need not wait five minutes.
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
        (PrefixStoreKind::KvS3, format!("{space}/")),
        (
            PrefixStoreKind::SqlS3,
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

async fn lifecycle_post(
    client: &Client,
    owner: &Owner,
    path: &str,
    action: &str,
    resource: &str,
    id: &str,
    body: Value,
) -> (Status, Value) {
    let response = client
        .post(path)
        .header(ContentType::JSON)
        .header(Header::new(
            "Authorization",
            owner.proof(action, resource, id),
        ))
        .header(Header::new("Idempotency-Key", id.to_owned()))
        .json(&body)
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_json::<Value>().await.unwrap_or(Value::Null);
    (status, body)
}

/// Purge `space` through the mounted route, bound to a pre-published aged
/// acceptance with the same purge ID.
async fn purge(
    client: &Client,
    ledger: &dyn PurgeLedgerStore,
    keys: &LedgerKeys,
    owner: &Owner,
    space: &SpaceId,
) -> String {
    let purge_id = uuid::Uuid::new_v4().to_string();
    let record = acceptance(keys, space, &purge_id, 900);
    ledger
        .append_purge_record(&record.object_key().unwrap(), &record.to_bytes().unwrap())
        .await
        .unwrap();
    let (status, body) = lifecycle_post(
        client,
        owner,
        "/space/purge",
        "tinycloud.space/delete",
        &format!("{space}/space"),
        &purge_id,
        json!({"version":1,"space_id":space.to_string()}),
    )
    .await;
    assert_eq!(status, Status::Accepted, "{body}");
    let accepted: PurgeResponse = serde_json::from_value(body).unwrap();
    assert_eq!(accepted.purge_id, purge_id);
    assert_eq!(accepted.state, "purging");
    assert_eq!(accepted.host_id, HOST);
    purge_id
}

async fn wait_complete(db: &DatabaseConnection, purge_ids: &[&str]) {
    let deadline = Instant::now() + Duration::from_secs(300);
    loop {
        let mut complete = 0;
        for id in purge_ids {
            complete += count(
                db,
                "SELECT count(*) FROM space_purge_job WHERE purge_id=$1 AND phase='complete'",
                vec![(*id).into()],
            )
            .await;
        }
        if complete == purge_ids.len() as i64 {
            return;
        }
        if Instant::now() > deadline {
            let jobs = db
                .query_all(Statement::from_string(
                    DbBackend::Postgres,
                    "SELECT phase, attempt_count::bigint, coalesce(last_error_code,'') FROM space_purge_job",
                ))
                .await
                .unwrap()
                .into_iter()
                .map(|row| {
                    (
                        row.try_get_by_index::<String>(0).unwrap(),
                        row.try_get_by_index::<i64>(1).unwrap(),
                        row.try_get_by_index::<String>(2).unwrap(),
                    )
                })
                .collect::<Vec<_>>();
            panic!("the purge worker did not complete {purge_ids:?}; jobs: {jobs:?}");
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Verified ledger records for `space` in `state`.
async fn ledger_records(
    ledger: &dyn PurgeLedgerStore,
    keys: &LedgerKeys,
    space: &SpaceId,
    state: &str,
) -> usize {
    let digest = hex::encode(
        keys.target_hmac(KEY_ID, "space", &space.to_string())
            .unwrap(),
    );
    let mut found = 0;
    for path in ledger.list_purge_records().await.unwrap() {
        let body = ledger.read_purge_record(&path).await.unwrap().unwrap();
        let record = keys.verify(&path, &body).unwrap();
        found += usize::from(record.target_hmac == digest && record.state == state);
    }
    found
}

/// A space is erased: no row names it in any table purged by space, no
/// object is left under its KV or SQL prefix, no SQL cache directory.
async fn assert_erased(
    db: &DatabaseConnection,
    s3: &aws_sdk_s3::Client,
    bucket: &str,
    datadir: &Path,
    space: &SpaceId,
) {
    let rows = space_rows(db, space).await;
    assert!(
        rows.values().all(|n| *n == 0),
        "rows left for {space}: {rows:?}"
    );
    let objects = space_objects(s3, bucket, space).await;
    assert!(objects.is_empty(), "objects left: {:?}", objects.keys());
    assert!(!datadir.join("sql").join(space.to_string()).exists());
}

async fn start(figment: &Figment) -> Client {
    Client::tracked(tinycloud::app(figment).await.unwrap())
        .await
        .unwrap()
}

/// Stop the node: its worker and reconciler end on shutdown.
async fn stop(client: Client) {
    client.rocket().shutdown().notify();
    drop(client);
    tokio::time::sleep(Duration::from_millis(500)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn erase30_owner_spaces_purge_and_restore_reconcile_on_postgres_and_minio() {
    let Ok(endpoint) = std::env::var("TC735_TEST_MINIO_ENDPOINT") else {
        return;
    };
    let Some(url) = common::postgres_test_url("erase30_space_purge_end_to_end") else {
        return;
    };
    // A client for bucket setup, from the configured test bucket.
    let s3 = S3BlockConfig {
        bucket: std::env::var("TC735_TEST_MINIO_BUCKET").unwrap(),
        endpoint: Some(endpoint.parse().unwrap()),
    }
    .open()
    .await
    .unwrap()
    .client;
    let run = uuid::Uuid::new_v4().simple().to_string();
    let stores = Stores {
        endpoint,
        data: format!("erase30-data-{}", &run[..12]),
        ledger: format!("erase30-ledger-{}", &run[..12]),
    };
    s3.create_bucket()
        .bucket(&stores.data)
        .send()
        .await
        .unwrap();
    // Production runs the ledger on an Object Lock bucket; so does the proof.
    s3.create_bucket()
        .bucket(&stores.ledger)
        .object_lock_enabled_for_bucket(true)
        .send()
        .await
        .unwrap();
    let (url, schema, db) = scoped_postgres(&url).await;
    let snapshot = format!("{schema}_snapshot");
    let dir = tempfile::tempdir().unwrap();
    let figment = figment(&node_config(dir.path(), &url, &stores));
    let config = resolved(&figment);
    let datadir = dir.path();
    let keys = LedgerKeys::from_config(ledger_keys_json()).unwrap();
    let ledger = config
        .storage
        .purge_ledger
        .as_ref()
        .unwrap()
        .open()
        .await
        .unwrap();
    let ledger: &dyn PurgeLedgerStore = &ledger;

    // 1. An owner with two spaces: KV through `/invoke`, SQL through the
    //    node's own service (checkpoints chunked in PostgreSQL), objects under
    //    the signed SQL prefix, and an encryption network.
    let client = start(&figment).await;
    assert!(client.rocket().state::<LifecycleRuntime>().is_some());
    let owner = Owner::new();
    let (a, b) = (owner.space("alpha"), owner.space("beta"));
    let service = client.rocket().state::<SqlService>().unwrap().clone();
    for space in [&a, &b] {
        let session = sign_in(&client, &owner, space).await;
        for n in 0..3 {
            kv_put(
                &client,
                &session,
                &format!("notes/{n}"),
                format!("private {space} {n}").as_bytes(),
            )
            .await;
        }
        sql(
            &service,
            space,
            "CREATE TABLE entries(id INTEGER, body TEXT)",
        )
        .await;
        sql(
            &service,
            space,
            "INSERT INTO entries VALUES (1, 'private row')",
        )
        .await;
        for n in 0..2 {
            put_object(
                &s3,
                &stores.data,
                &format!(
                    "{}db/lineage/snap/{n}",
                    SqlPhysicalPrefix::for_space(space).as_str()
                ),
                b"private SQL object".to_vec(),
            )
            .await;
        }
    }
    let canonical = canonicalize_did(&owner.did).unwrap();
    let network = format!("urn:tinycloud:encryption:{canonical}:default");
    for (statement, values) in [
        (
            "INSERT INTO encryption_network(network_id,owner_did,name,alg,key_version,public_key,state,threshold_n,threshold_t,key_backend,created_at,updated_at)
             VALUES($1,$2,'default','test',1,'\\x01','active',1,1,'local','now','now')",
            vec![network.clone().into(), canonical.clone().into()],
        ),
        (
            "INSERT INTO encryption_network_key(network_id,key_path,kind,state,public_key,created_at,updated_at)
             VALUES($1,'key','test','active','\\x01','now','now')",
            vec![network.clone().into()],
        ),
    ] {
        db.execute(Statement::from_sql_and_values(
            DbBackend::Postgres,
            statement,
            values,
        ))
        .await
        .unwrap();
    }
    for space in [&a, &b] {
        let rows = space_rows(&db, space).await;
        for table in [
            "space",
            "current_kv",
            "kv_write",
            "epoch",
            "database_artifact",
            "artifact_part",
            "artifact_chunk",
            "artifact_space_owner",
        ] {
            assert!(rows[table] > 0, "{table} has no row for {space}: {rows:?}");
        }
        let objects = space_objects(&s3, &stores.data, space).await;
        assert!(objects
            .keys()
            .any(|key| key.starts_with(&format!("{space}/"))));
        assert!(objects
            .keys()
            .any(|key| key.starts_with(SqlPhysicalPrefix::for_space(space).as_str())));
    }
    let owned = owner_rows(&db, owner.address()).await;
    for table in [
        "artifact_account",
        "encryption_network",
        "encryption_network_key",
    ] {
        assert!(owned[table] > 0, "{table}: {owned:?}");
    }

    // The pre-purge backup: the whole database and the data bucket.
    snapshot_database(&db, &schema, &snapshot).await;
    let backup = objects(&s3, &stores.data, "").await;
    let b_rows = space_digests(&db, &b).await;
    let b_objects = space_objects(&s3, &stores.data, &b).await;

    // 2. Retire the owner, then purge A through the mounted route.
    let retirement = uuid::Uuid::new_v4().to_string();
    let (status, body) = lifecycle_post(
        &client,
        &owner,
        "/space/retire-owner",
        "tinycloud.space/retire-owner",
        &owner.did,
        &retirement,
        json!({"version":1,"owner_did":owner.did}),
    )
    .await;
    assert_eq!(status, Status::Accepted, "{body}");
    let purge_a = purge(&client, ledger, &keys, &owner, &a).await;

    // 3. The spawned worker erases A; B and the owner's rows are untouched.
    wait_complete(&db, &[&purge_a]).await;
    assert_erased(&db, &s3, &stores.data, datadir, &a).await;
    assert_eq!(ledger_records(ledger, &keys, &a, "complete").await, 1);
    assert_eq!(space_digests(&db, &b).await, b_rows, "B's rows changed");
    assert_eq!(space_objects(&s3, &stores.data, &b).await, b_objects);
    assert_eq!(owner_rows(&db, owner.address()).await, owned);

    // 4. B is the owner's last space: its purge also removes the owner rows.
    let purge_b = purge(&client, ledger, &keys, &owner, &b).await;
    wait_complete(&db, &[&purge_b]).await;
    assert_erased(&db, &s3, &stores.data, datadir, &b).await;
    assert_eq!(ledger_records(ledger, &keys, &b, "complete").await, 1);
    let gone = owner_rows(&db, owner.address()).await;
    assert!(gone.values().all(|n| *n == 0), "owner rows left: {gone:?}");
    stop(client).await;

    // 5. Restore the pre-purge backup: A's (and B's) rows and objects return,
    //    and the database no longer holds any lifecycle state.
    restore_database(&db, &schema, &snapshot).await;
    for (key, body) in &backup {
        put_object(&s3, &stores.data, key, body.clone()).await;
    }
    assert_eq!(space_rows(&db, &a).await["space"], 1);
    assert!(!space_objects(&s3, &stores.data, &a).await.is_empty());
    assert_eq!(
        count(&db, "SELECT count(*) FROM space_purge_job", vec![]).await,
        0
    );

    // 6. `tinycloud node purge-ledger reconcile` (node stopped): from the
    //    ledger alone it re-fences both spaces and the owner, re-creates the
    //    tombstones, resumes both purges and erases the signed prefixes.
    let first = tinycloud::reconcile_purge_ledger(&config).await.unwrap();
    assert_eq!(first.records, 5, "{first:?}");
    assert_eq!(first.owner_retirements, 1, "{first:?}");
    assert_eq!(first.space_fences, 2, "{first:?}");
    assert_eq!(first.tombstones_created, 2, "{first:?}");
    assert_eq!(first.purges_resumed, 2, "{first:?}");
    // Counted per signed record: each space's acceptance and completion both
    // sign its KV and SQL prefixes.
    assert_eq!(first.prefixes_purged, 8, "{first:?}");
    assert_eq!(first.prefixes_deferred, 0, "{first:?}");
    for space in [&a, &b] {
        assert!(space_objects(&s3, &stores.data, space).await.is_empty());
    }

    //    The node starts only after its own reconcile pass; its worker then
    //    erases the restored rows of both resumed purges.
    let client = start(&figment).await;
    wait_complete(&db, &[&purge_a, &purge_b]).await;
    for space in [&a, &b] {
        assert_erased(&db, &s3, &stores.data, datadir, space).await;
    }
    let gone = owner_rows(&db, owner.address()).await;
    assert!(gone.values().all(|n| *n == 0), "owner rows left: {gone:?}");

    //    Space traffic stays refused while a reconcile pass runs and is
    //    admitted once it finishes. The held lifecycle operation keeps the
    //    pass inside its drain, so the refused state is observed, not raced.
    let runtime = client.rocket().state::<LifecycleRuntime>().unwrap().clone();
    let probe: SpaceId = "tinycloud:pkh:eip155:1:0x3333333333333333333333333333333333333333:probe"
        .parse()
        .unwrap();
    runtime.fence.check(&db, &probe).await.unwrap();
    let node_stores = Arc::new(PurgeStores {
        blocks: Either::A(
            S3BlockConfig {
                bucket: stores.data.clone(),
                endpoint: Some(stores.endpoint.parse().unwrap()),
            }
            .open()
            .await
            .unwrap(),
        ),
        ledger: Arc::new(
            config
                .storage
                .purge_ledger
                .as_ref()
                .unwrap()
                .open()
                .await
                .unwrap(),
        ),
        sql: service.clone(),
        #[cfg(feature = "duckdb")]
        duckdb: client
            .rocket()
            .state::<tinycloud_core::duckdb::DuckDbService>()
            .cloned(),
        sql_objects: PurgeSqlObjects::open(&config.storage).await.unwrap(),
        encryption: None,
    });
    let held = runtime.fence.lifecycle_operation().await;
    let pass = tokio::spawn({
        let (runtime, node_stores) = (runtime.clone(), node_stores.clone());
        async move { runtime.reconcile(&node_stores).await }
    });
    let deadline = Instant::now() + Duration::from_secs(30);
    while runtime.fence.check(&db, &probe).await.is_ok() {
        assert!(Instant::now() < deadline, "reconcile never left serving");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for _ in 0..10 {
        assert!(matches!(
            runtime.fence.check(&db, &probe).await,
            Err(FenceError::Unavailable)
        ));
        assert!(!pass.is_finished());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(held);
    let in_process: ReconcileReport = pass.await.unwrap().unwrap();
    runtime.fence.check(&db, &probe).await.unwrap();
    assert_eq!(in_process.purges_resumed, 0, "{in_process:?}");
    assert_eq!(in_process.tombstones_created, 0, "{in_process:?}");
    assert_eq!(in_process.repaired_copies, 0, "{in_process:?}");
    assert_eq!(in_process.purges_in_progress, 0, "{in_process:?}");
    assert_eq!(in_process.prefixes_purged, 0, "{in_process:?}");
    drop(node_stores);
    stop(client).await;

    // 7. Reconcile again, twice: nothing changes, nothing is erased twice.
    let state = lifecycle_state(&db).await;
    let second = tinycloud::reconcile_purge_ledger(&config).await.unwrap();
    assert_eq!(second, in_process);
    let third = tinycloud::reconcile_purge_ledger(&config).await.unwrap();
    assert_eq!(third, second);
    assert_eq!(lifecycle_state(&db).await, state);
    for space in [&a, &b] {
        assert_erased(&db, &s3, &stores.data, datadir, space).await;
        assert_eq!(ledger_records(ledger, &keys, space, "complete").await, 1);
    }

    db.execute_unprepared(&format!(
        "DROP SCHEMA {schema} CASCADE; DROP SCHEMA {snapshot} CASCADE"
    ))
    .await
    .unwrap();
    db.close().await.unwrap();
    remove_bucket(&s3, &stores.data).await;
    remove_bucket(&s3, &stores.ledger).await;
}

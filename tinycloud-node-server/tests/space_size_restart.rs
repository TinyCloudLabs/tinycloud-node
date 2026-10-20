//! TC-1578: block-store space sizes after a node restart.
//!
//! The S3 block store keeps a per-space byte map that it rebuilds at boot from
//! objects with bytes in them. A hosted space with no blocks therefore had no
//! entry after a restart, and with a storage limit configured every write to it
//! was refused with 404 "space not found" before the `space` table was read.
//! Re-hosting a space also reset an existing entry to zero.
//!
//! These tests run the real node (`tinycloud::app`) on a file-backed SQLite
//! database against an in-process S3 API, and "restart" it by booting a second
//! app on the same database file, S3 objects and SQL artifacts. No MinIO or
//! Docker is involved. The DuckDB case needs `--features duckdb`.

use anyhow::{anyhow, ensure, Context, Result};
use axum::{
    body::Bytes,
    extract::State,
    http::{Method, StatusCode, Uri},
    response::{IntoResponse, Response},
    Router,
};
use k256::ecdsa::SigningKey;
use parking_lot::Mutex;
use percent_encoding::percent_decode_str;
use rocket::{
    data::ByteUnit,
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, path::Path as FsPath, sync::Arc};
use tinycloud::{storage::s3::S3BlockConfig, BlockConfig, TinyCloud};
use tinycloud_auth::{
    cacaos::{
        siwe::{encode_eip55, Message},
        siwe_cacao::Signature,
    },
    resolver::DID_METHODS,
    resource::{Path, Service, SpaceId},
    siwe_recap::Ability,
    ssi::{
        dids::{DIDBuf, DIDURLBuf},
        jwk::JWK,
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SignedSession},
};

const BUCKET: &str = "tc1578";
const KEY_SEED: [u8; 32] = [57; 32];

// ---------------------------------------------------------------------------
// An in-process S3 API: the five operations the block store uses, path-style.
// Objects outlive the node booted on it, which is what a restart needs.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct MockS3 {
    objects: Arc<Mutex<BTreeMap<String, Vec<u8>>>>,
}

async fn s3_api(State(s3): State<MockS3>, method: Method, uri: Uri, body: Bytes) -> Response {
    let path = percent_decode_str(uri.path())
        .decode_utf8_lossy()
        .into_owned();
    let rest = path.trim_start_matches('/');
    let (bucket, key) = rest.split_once('/').unwrap_or((rest, ""));
    if bucket != BUCKET {
        return StatusCode::NOT_FOUND.into_response();
    }
    let mut objects = s3.objects.lock();
    match (method, key.is_empty()) {
        (Method::GET, true) => {
            let contents: String = objects
                .iter()
                .map(|(key, data)| {
                    format!(
                        "<Contents><Key>{key}</Key><Size>{}</Size></Contents>",
                        data.len()
                    )
                })
                .collect();
            let xml = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult>\
                 <Name>{BUCKET}</Name><KeyCount>{}</KeyCount><MaxKeys>1000</MaxKeys>\
                 <IsTruncated>false</IsTruncated>{contents}</ListBucketResult>",
                objects.len()
            );
            ([("content-type", "application/xml")], xml).into_response()
        }
        (Method::PUT, false) => {
            objects.insert(key.to_owned(), body.to_vec());
            ([("etag", "\"mock\"")], StatusCode::OK).into_response()
        }
        (Method::HEAD, false) => match objects.get(key) {
            Some(data) => {
                ([("content-length", data.len().to_string())], StatusCode::OK).into_response()
            }
            None => StatusCode::NOT_FOUND.into_response(),
        },
        (Method::GET, false) => match objects.get(key) {
            Some(data) => {
                ([("content-length", data.len().to_string())], data.clone()).into_response()
            }
            None => (
                StatusCode::NOT_FOUND,
                "<Error><Code>NoSuchKey</Code><Message>missing</Message></Error>",
            )
                .into_response(),
        },
        (Method::DELETE, false) => {
            objects.remove(key);
            StatusCode::NO_CONTENT.into_response()
        }
        _ => StatusCode::NOT_IMPLEMENTED.into_response(),
    }
}

async fn start_s3() -> Result<(MockS3, String)> {
    let s3 = MockS3::default();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let endpoint = format!("http://{}", listener.local_addr()?);
    let app = Router::new().fallback(s3_api).with_state(s3.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Ok((s3, endpoint))
}

// ---------------------------------------------------------------------------
// The node: one data directory, one S3 API, any number of boots.
// ---------------------------------------------------------------------------

struct Deployment {
    dir: tempfile::TempDir,
    s3: MockS3,
    endpoint: String,
    limit: u64,
}

impl Deployment {
    async fn new(limit: u64) -> Result<Self> {
        // The S3 client reads credentials from the AWS_* environment.
        std::env::set_var("AWS_ACCESS_KEY_ID", "tc1578");
        std::env::set_var("AWS_SECRET_ACCESS_KEY", "tc1578");
        std::env::set_var("AWS_REGION", "us-east-1");
        std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
        let (s3, endpoint) = start_s3().await?;
        Ok(Self {
            dir: tempfile::tempdir()?,
            s3,
            endpoint,
            limit,
        })
    }

    /// Boot a node. Calling this again is a restart: the database file, SQL
    /// artifacts and S3 objects are all still there, the in-memory state is not.
    async fn boot(&self) -> Result<Client> {
        let mut config = tinycloud::config::Config::default();
        config.storage.datadir = self.dir.path().to_path_buf();
        config.storage.limit = Some(ByteUnit::Byte(self.limit));
        config.storage.blocks = BlockConfig::A(serde_json::from_value::<S3BlockConfig>(json!({
            "bucket": BUCKET,
            "endpoint": self.endpoint,
        }))?);
        config.keys = serde_json::from_value(json!({
            "type": "static",
            "secret": base64::encode_config([57; 32], base64::URL_SAFE_NO_PAD),
        }))?;
        let figment = Figment::from(rocket::Config {
            log_level: rocket::config::LogLevel::Off,
            ..rocket::Config::default()
        })
        .merge(Serialized::defaults(&config));
        Ok(Client::tracked(tinycloud::app(&figment).await?).await?)
    }

    fn data_dir(&self) -> &FsPath {
        self.dir.path()
    }
}

// ---------------------------------------------------------------------------
// An account that hosts spaces and signs sessions for them.
// ---------------------------------------------------------------------------

struct Account {
    key: SigningKey,
    address: [u8; 20],
}

impl Account {
    fn new() -> Result<Self> {
        let key = SigningKey::from_bytes(&KEY_SEED.into())?;
        let public = key.verifying_key().to_encoded_point(false);
        let address: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..].try_into()?;
        Ok(Self { key, address })
    }

    fn address(&self) -> String {
        format!("0x{}", encode_eip55(&self.address))
    }

    fn space(&self, name: &str) -> Result<SpaceId> {
        Ok(format!("tinycloud:pkh:eip155:1:{}:{name}", self.address()).parse()?)
    }

    fn sign(&self, message: &Message) -> Result<[u8; 65]> {
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(&message.eip191_hash().map_err(|e| anyhow!("{e}"))?)?;
        let mut bytes = [0; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = recovery.to_byte();
        Ok(bytes)
    }

    /// Host `space` with a `tinycloud.space/host` delegation issued
    /// `age_minutes` ago; a different age is a different delegation, so a
    /// second call is a re-host of the same space.
    async fn host(&self, client: &Client, space: &SpaceId, age_minutes: i64) -> Result<()> {
        let peer = client
            .get(format!("/peer/generate/{space}"))
            .dispatch()
            .await
            .into_string()
            .await
            .context("peer DID")?;
        let rfc3339 = &time::format_description::well_known::Rfc3339;
        let issued = time::OffsetDateTime::now_utc() - time::Duration::minutes(age_minutes);
        let host = generate_host_siwe_message(serde_json::from_value(json!({
            "address": self.address(),
            "chainId": 1,
            "domain": "localhost",
            "issuedAt": issued.format(rfc3339)?,
            "spaceId": space,
            "peerId": peer,
        }))?)?;
        let signature = self.sign(&host)?;
        let host: SignedMessage = serde_json::from_value(json!({
            "siwe": host.to_string(), "signature": format!("0x{}", hex::encode(signature)),
        }))?;
        register(client, &siwe_to_delegation_headers(host)).await
    }

    /// A session that may use KV, SQL and DuckDB in `space`.
    async fn session(&self, client: &Client, space: &SpaceId) -> Result<Session> {
        let session_key = ed25519_dalek::SigningKey::from_bytes(&[58; 32]);
        let jwk: JWK = serde_json::from_value(json!({
            "kty": "OKP", "crv": "Ed25519",
            "d": base64::encode_config(session_key.to_bytes(), base64::URL_SAFE_NO_PAD),
            "x": base64::encode_config(session_key.verifying_key().to_bytes(), base64::URL_SAFE_NO_PAD),
        }))?;
        let rfc3339 = &time::format_description::well_known::Rfc3339;
        let now = time::OffsetDateTime::now_utc();
        let mut abilities = json!({
            "kv": {"": ["tinycloud.kv/put", "tinycloud.kv/get", "tinycloud.kv/del"]},
            "sql": {"main": ["tinycloud.sql/read", "tinycloud.sql/write"]},
        });
        if cfg!(feature = "duckdb") {
            abilities["duckdb"] =
                json!({"main": ["tinycloud.duckdb/read", "tinycloud.duckdb/write"]});
        }
        let prepared = prepare_session(serde_json::from_value(json!({
            "abilities": abilities,
            "address": self.address(),
            "chainId": 1,
            "domain": "localhost",
            "issuedAt": (now - time::Duration::minutes(1)).format(rfc3339)?,
            "expirationTime": (now + time::Duration::hours(1)).format(rfc3339)?,
            "spaceId": space,
            "jwk": jwk,
            "nonce": "tc1578",
        }))?)?;
        let signature = self.sign(&prepared.siwe)?;
        let session = complete_session_setup(SignedSession {
            session: prepared,
            signature: Signature::from(signature),
        })?;
        register(client, &session.delegation_header).await?;
        Ok(session)
    }
}

async fn register(client: &Client, headers: &impl serde::Serialize) -> Result<()> {
    let authorization = serde_json::to_value(headers)?["Authorization"]
        .as_str()
        .map(str::to_owned)
        .context("SDK delegation Authorization header")?;
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", authorization))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    ensure!(status == Status::Ok, "delegate: {status} {body}");
    Ok(())
}

struct Reply {
    status: Status,
    body: String,
}

impl Reply {
    fn error(&self) -> Option<String> {
        serde_json::from_str::<Value>(&self.body)
            .ok()?
            .get("error")?
            .as_str()
            .map(str::to_owned)
    }
}

async fn invoke(
    client: &Client,
    session: &Session,
    service: &str,
    path: &str,
    ability: &str,
    content_type: ContentType,
    body: Vec<u8>,
) -> Result<Reply> {
    let capability = (
        session.space_id.clone().to_resource(
            service.parse::<Service>()?,
            Some(path.parse::<Path>()?),
            None,
            None,
        ),
        [ability.parse::<Ability>()?],
    );
    let invocation = session.invoke_any([capability], None)?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", invocation.encode()?))
        .header(content_type)
        .body(body)
        .dispatch()
        .await;
    Ok(Reply {
        status: response.status(),
        body: response.into_string().await.unwrap_or_default(),
    })
}

async fn kv_put(client: &Client, session: &Session, key: &str, bytes: usize) -> Result<Reply> {
    invoke(
        client,
        session,
        "kv",
        key,
        "tinycloud.kv/put",
        ContentType::Plain,
        vec![b'x'; bytes],
    )
    .await
}

async fn sql_write(client: &Client, session: &Session) -> Result<Reply> {
    invoke(
        client,
        session,
        "sql",
        "main",
        "tinycloud.sql/write",
        ContentType::JSON,
        json!({"action": "execute", "sql": "CREATE TABLE t (v TEXT)", "params": []})
            .to_string()
            .into_bytes(),
    )
    .await
}

#[cfg(feature = "duckdb")]
async fn duckdb_write(client: &Client, session: &Session) -> Result<Reply> {
    invoke(
        client,
        session,
        "duckdb",
        "main",
        "tinycloud.duckdb/write",
        ContentType::JSON,
        json!({"action": "execute", "sql": "CREATE TABLE t (v TEXT)", "params": []})
            .to_string()
            .into_bytes(),
    )
    .await
}

/// Metered bytes for `space` as the node reports them (KV blocks + SQL/DuckDB).
async fn metered(client: &Client, space: &SpaceId) -> Result<Option<u64>> {
    client
        .rocket()
        .state::<TinyCloud>()
        .context("TinyCloud is managed")?
        .store_size(space)
        .await
        .map_err(|e| anyhow!("{e}"))
}

fn ok(reply: &Reply, what: &str) -> Result<()> {
    ensure!(
        reply.status == Status::Ok,
        "{what}: {} {}",
        reply.status,
        reply.body
    );
    Ok(())
}

/// Host an empty space, then restart; the first write must not need a block.
async fn restarted_with_empty_space(
    limit: u64,
) -> Result<(Deployment, Client, Account, SpaceId, Session)> {
    let node = Deployment::new(limit).await?;
    let account = Account::new()?;
    let space = account.space("empty")?;
    let first = node.boot().await?;
    account.host(&first, &space, 2).await?;
    let session = account.session(&first, &space).await?;
    ensure!(
        node.s3.objects.lock().is_empty(),
        "an empty space has no S3 objects"
    );
    drop(first);
    let client = node.boot().await?;
    Ok((node, client, account, space, session))
}

// ---------------------------------------------------------------------------
// The first write to an empty hosted space after a restart.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn first_kv_write_to_an_empty_space_succeeds_after_restart() -> Result<()> {
    let (_node, client, _account, space, session) = restarted_with_empty_space(10 << 20).await?;
    ok(
        &kv_put(&client, &session, "first", 100).await?,
        "first KV put",
    )?;
    ensure!(metered(&client, &space).await? == Some(100));
    Ok(())
}

#[tokio::test]
async fn first_sql_write_to_an_empty_space_succeeds_after_restart() -> Result<()> {
    let (_node, client, _account, space, session) = restarted_with_empty_space(10 << 20).await?;
    ok(&sql_write(&client, &session).await?, "first SQL write")?;
    ensure!(metered(&client, &space)
        .await?
        .is_some_and(|bytes| bytes > 0));
    Ok(())
}

#[cfg(feature = "duckdb")]
#[tokio::test]
async fn first_duckdb_write_to_an_empty_space_succeeds_after_restart() -> Result<()> {
    let (_node, client, _account, space, session) = restarted_with_empty_space(10 << 20).await?;
    ok(
        &duckdb_write(&client, &session).await?,
        "first DuckDB write",
    )?;
    ensure!(metered(&client, &space)
        .await?
        .is_some_and(|bytes| bytes > 0));
    Ok(())
}

// ---------------------------------------------------------------------------
// An unhosted space is still unknown.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn an_unhosted_space_is_still_not_found() -> Result<()> {
    let node = Deployment::new(10 << 20).await?;
    let client = node.boot().await?;
    // The owner of a `did:key` space is its own root authority, so the
    // invocation is valid and only the missing `space` row can refuse it.
    let owner = JWK::generate_ed25519()?;
    let did = DID_METHODS.generate(&owner, "key")?.to_string();
    let vm = format!("{did}#{}", did.rsplit_once(':').context("did")?.1);
    let space = SpaceId::new(did.parse::<DIDBuf>()?, "nowhere".parse()?);
    let mut capabilities = Capabilities::new();
    capabilities.with_action(
        space
            .clone()
            .to_resource(
                "kv".parse::<Service>()?,
                Some("k".parse::<Path>()?),
                None,
                None,
            )
            .as_uri(),
        "tinycloud.kv/put".parse::<Ability>()?,
        [BTreeMap::<String, Value>::new()],
    );
    let token = Payload {
        issuer: vm.parse::<DIDURLBuf>()?,
        audience: did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: tinycloud_auth::ssi::claims::jwt::NumericDate::try_from_seconds(
            time::OffsetDateTime::now_utc().unix_timestamp() as f64 + 200.0,
        )?,
        nonce: Some("urn:uuid:tc1578-unhosted".into()),
        facts: Some(Vec::<Value>::new()),
        proof: vec![],
        attenuation: capabilities,
    }
    .sign(owner.get_algorithm().unwrap_or_default(), &owner)?
    .encode()?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", token))
        .header(ContentType::Plain)
        .body("data")
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    ensure!(
        status == Status::NotFound && body.contains("space not found"),
        "unhosted space: {status} {body}"
    );
    ensure!(metered(&client, &space).await?.is_none());
    Ok(())
}

// ---------------------------------------------------------------------------
// The limit still applies once the entry exists.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn quota_is_enforced_on_a_space_initialised_after_restart() -> Result<()> {
    let (_node, client, _account, space, session) = restarted_with_empty_space(1000).await?;

    // A write larger than the whole limit is refused, not waved through.
    let reply = kv_put(&client, &session, "big", 1500).await?;
    ensure!(
        reply.status == Status::PayloadTooLarge
            && reply.error().as_deref() == Some("storage_limit_reached"),
        "oversized first write: {} {}",
        reply.status,
        reply.body
    );
    ensure!(metered(&client, &space).await? == Some(0));

    // Writes are counted from the initialised entry up to the limit ...
    ok(&kv_put(&client, &session, "a", 800).await?, "800 bytes")?;
    let reply = kv_put(&client, &session, "b", 300).await?;
    ensure!(
        reply.status == Status::PayloadTooLarge,
        "300 bytes over 200 left: {} {}",
        reply.status,
        reply.body
    );
    ok(&kv_put(&client, &session, "c", 200).await?, "200 bytes")?;
    ensure!(metered(&client, &space).await? == Some(1000));

    // ... and a space at its limit still refuses.
    let reply = kv_put(&client, &session, "d", 1).await?;
    ensure!(
        reply.status == Status::new(402)
            && reply.error().as_deref() == Some("storage_quota_exceeded"),
        "space at its limit: {} {}",
        reply.status,
        reply.body
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Boot seeding.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn boot_gives_every_hosted_space_a_size_entry() -> Result<()> {
    let node = Deployment::new(10 << 20).await?;
    let account = Account::new()?;
    let (empty, with_kv, with_both) = (
        account.space("empty")?,
        account.space("kv")?,
        account.space("both")?,
    );
    let first = node.boot().await?;
    for space in [&empty, &with_kv, &with_both] {
        account.host(&first, space, 2).await?;
    }
    let kv_session = account.session(&first, &with_kv).await?;
    let both_session = account.session(&first, &with_both).await?;
    ok(&kv_put(&first, &kv_session, "k", 300).await?, "kv put")?;
    ok(&kv_put(&first, &both_session, "k", 120).await?, "kv put")?;
    ok(&sql_write(&first, &both_session).await?, "sql write")?;
    let before = metered(&first, &with_both).await?.context("size")?;
    ensure!(before > 120, "SQL bytes are metered: {before}");
    drop(first);

    let client = node.boot().await?;
    // The empty space has no S3 object, and still has an entry.
    ensure!(
        metered(&client, &empty).await? == Some(0),
        "empty space after restart: {:?}",
        metered(&client, &empty).await?
    );
    // Bytes the store already had are not lowered ...
    ensure!(metered(&client, &with_kv).await? == Some(300));
    // ... and SQL bytes are counted once, not once more per seeded entry.
    ensure!(
        metered(&client, &with_both).await? == Some(before),
        "KV + SQL bytes before {before}, after {:?}",
        metered(&client, &with_both).await?
    );
    ensure!(
        node.data_dir().exists(),
        "the data directory outlives the boots"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Re-hosting a space that has data.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rehosting_a_space_keeps_its_metered_usage() -> Result<()> {
    let node = Deployment::new(1000).await?;
    let account = Account::new()?;
    let space = account.space("rehost")?;
    let client = node.boot().await?;
    account.host(&client, &space, 3).await?;
    let session = account.session(&client, &space).await?;
    ok(&kv_put(&client, &session, "a", 800).await?, "800 bytes")?;
    ensure!(metered(&client, &space).await? == Some(800));

    // A second, distinct host delegation for the same space.
    account.host(&client, &space, 2).await?;
    ensure!(
        metered(&client, &space).await? == Some(800),
        "re-hosting reset the usage to {:?}",
        metered(&client, &space).await?
    );
    let reply = kv_put(&client, &session, "b", 500).await?;
    ensure!(
        reply.status == Status::PayloadTooLarge,
        "the limit applies at the previous usage: {} {}",
        reply.status,
        reply.body
    );
    Ok(())
}

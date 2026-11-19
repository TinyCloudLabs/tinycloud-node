//! TC-2375: an `/invoke` KV write spends its invocation-replay row inside the
//! write transaction, so a write that rolls back leaves the signed request
//! retryable, and a write that commits answers the same request 409.
//!
//! Driven through the real node with SDK-signed invocations on in-memory
//! SQLite and, when an isolated PostgreSQL is configured (see
//! `common::postgres_test_url`), on PostgreSQL in a throwaway schema.

mod common;

use anyhow::{anyhow, ensure, Context, Result};
use k256::ecdsa::SigningKey;
use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::json;
use sha3::{Digest, Keccak256};
use tinycloud_auth::{
    cacaos::{
        siwe::{encode_eip55, Message},
        siwe_cacao::Signature,
    },
    resource::{Path, Service, SpaceId},
    siwe_recap::Ability,
    ssi::jwk::JWK,
};
use tinycloud_core::sea_orm::{ConnectionTrait, Database, DbBackend, Statement};
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SignedSession},
};

async fn node(database: &str) -> Result<(Client, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some(database.into());
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config([109; 32], base64::URL_SAFE_NO_PAD),
    }))?;
    let figment = Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    Ok((Client::tracked(tinycloud::app(&figment).await?).await?, dir))
}

fn sign(key: &SigningKey, message: &Message) -> Result<[u8; 65]> {
    let (signature, recovery) =
        key.sign_prehash_recoverable(&message.eip191_hash().map_err(|e| anyhow!("{e}"))?)?;
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(&signature.to_bytes());
    bytes[64] = recovery.to_byte();
    Ok(bytes)
}

fn authorization(headers: &impl serde::Serialize) -> Result<String> {
    serde_json::to_value(headers)?["Authorization"]
        .as_str()
        .map(str::to_owned)
        .context("SDK delegation Authorization header")
}

async fn register(client: &Client, headers: &impl serde::Serialize) -> Result<()> {
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", authorization(headers)?))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    ensure!(status == Status::Ok, "delegate: {status} {body}");
    Ok(())
}

/// A space and a session that may put, get, delete and read the metadata of
/// any key in it.
async fn sign_in(client: &Client) -> Result<Session> {
    let key = SigningKey::from_bytes(&[109; 32].into())?;
    let public = key.verifying_key().to_encoded_point(false);
    let address: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..].try_into()?;
    let space: SpaceId = format!(
        "tinycloud:pkh:eip155:1:0x{}:replay-row",
        encode_eip55(&address)
    )
    .parse()?;
    let peer = client
        .get(format!("/peer/generate/{space}"))
        .dispatch()
        .await
        .into_string()
        .await
        .context("peer DID")?;
    let rfc3339 = &time::format_description::well_known::Rfc3339;
    let now = time::OffsetDateTime::now_utc();
    let host = generate_host_siwe_message(serde_json::from_value(json!({
        "address": format!("0x{}", encode_eip55(&address)),
        "chainId": 1, "domain": "localhost",
        "issuedAt": (now - time::Duration::minutes(1)).format(rfc3339)?,
        "spaceId": space,
        "peerId": peer,
    }))?)?;
    let signature = sign(&key, &host)?;
    let host: SignedMessage = serde_json::from_value(json!({
        "siwe": host.to_string(), "signature": format!("0x{}", hex::encode(signature)),
    }))?;
    register(client, &siwe_to_delegation_headers(host)).await?;

    let session_key = ed25519_dalek::SigningKey::from_bytes(&[110; 32]);
    let jwk: JWK = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519",
        "d": base64::encode_config(session_key.to_bytes(), base64::URL_SAFE_NO_PAD),
        "x": base64::encode_config(session_key.verifying_key().to_bytes(), base64::URL_SAFE_NO_PAD),
    }))?;
    let prepared = prepare_session(serde_json::from_value(json!({
        "abilities": {"kv": {"": [
            "tinycloud.kv/put", "tinycloud.kv/get", "tinycloud.kv/del", "tinycloud.kv/metadata"
        ]}},
        "address": format!("0x{}", encode_eip55(&address)),
        "chainId": 1,
        "domain": "localhost",
        "issuedAt": (now - time::Duration::minutes(1)).format(rfc3339)?,
        "expirationTime": (now + time::Duration::hours(1)).format(rfc3339)?,
        "spaceId": space,
        "jwk": jwk,
        "nonce": "tc2375replay",
    }))?)?;
    let signature = sign(&key, &prepared.siwe)?;
    let session = complete_session_setup(SignedSession {
        session: prepared,
        signature: Signature::from(signature),
    })?;
    register(client, &session.delegation_header).await?;
    Ok(session)
}

/// One signed invocation of `ability` on `key`, as its `Authorization` value.
fn signed(session: &Session, ability: &str, key: &str) -> Result<String> {
    let ability: Ability = ability.parse()?;
    let capabilities = [(
        session.space_id.clone().to_resource(
            "kv".parse::<Service>()?,
            Some(key.parse::<Path>()?),
            None,
            None,
        ),
        [ability],
    )];
    Ok(session.invoke_any(capabilities, None)?.encode()?)
}

/// Send `authorization` with `body`, plus `headers`.
async fn send(
    client: &Client,
    authorization: &str,
    body: &[u8],
    headers: &[(&'static str, &'static str)],
) -> Result<(Status, String)> {
    let mut request = client
        .post("/invoke")
        .header(Header::new("Authorization", authorization.to_owned()))
        .header(ContentType::Plain)
        .body(body);
    for (name, value) in headers {
        request = request.header(Header::new(*name, *value));
    }
    let response = request.dispatch().await;
    Ok((
        response.status(),
        response.into_string().await.unwrap_or_default(),
    ))
}

/// The contract, on whichever database `client` runs on.
async fn replay_row_follows_the_write(client: &Client) -> Result<()> {
    let session = sign_in(client).await?;

    // A committed put spends its signed request: the same request is a replay.
    let first = signed(&session, "tinycloud.kv/put", "replay/a")?;
    let (status, body) = send(client, &first, b"one", &[]).await?;
    ensure!(status == Status::Ok, "first put: {status} {body}");
    let (status, body) = send(client, &first, b"one", &[]).await?;
    ensure!(
        status == Status::Conflict,
        "replay of a commit: {status} {body}"
    );

    // A put refused by its precondition commits only its replay row: a
    // leaked failed request, with the unsigned precondition header dropped,
    // cannot be reused to write a different body.
    let second = signed(&session, "tinycloud.kv/put", "replay/a")?;
    let (status, body) = send(client, &second, b"two", &[("If-None-Match", "*")]).await?;
    ensure!(
        status == Status::PreconditionFailed,
        "create-only put over an existing key: {status} {body}"
    );
    let (status, body) = send(client, &second, b"two", &[]).await?;
    ensure!(
        status == Status::Conflict,
        "the same request after a refused precondition: {status} {body}"
    );
    let read = signed(&session, "tinycloud.kv/get", "replay/a")?;
    let (status, body) = send(client, &read, b"", &[]).await?;
    ensure!(
        status == Status::Ok && body == "one",
        "readback after the refused write: {status} {body}"
    );

    // Identical requests racing each other (past the early refusal) commit
    // exactly once: the insert in the transaction decides.
    let racing = signed(&session, "tinycloud.kv/put", "replay/race")?;
    let replies =
        futures::future::join_all((0..8).map(|_| send(client, &racing, b"race", &[]))).await;
    let mut ok = 0;
    for reply in replies {
        let (status, body) = reply?;
        if status == Status::Ok {
            ok += 1;
        } else {
            ensure!(status == Status::Conflict, "racing put: {status} {body}");
        }
    }
    ensure!(ok == 1, "{ok} of 8 identical racing puts committed");

    // Same for a delete, which is a different ability on the same path.
    let delete = signed(&session, "tinycloud.kv/del", "replay/missing")?;
    let (status, body) = send(client, &delete, b"", &[]).await?;
    ensure!(
        status.class().is_success() || status == Status::NotFound,
        "delete: {status} {body}"
    );
    let (status, body) = send(client, &delete, b"", &[]).await?;
    ensure!(
        status == Status::Conflict || status == Status::NotFound,
        "delete replay: {status} {body}"
    );
    Ok(())
}

#[tokio::test]
async fn sqlite_replay_row_follows_the_write() -> Result<()> {
    let (client, _dir) = node("sqlite::memory:").await?;
    replay_row_follows_the_write(&client).await
}

/// TC-2986: a KV write mixed with a read in one invocation is refused with
/// 501 before any work. Before, the write committed and only then was the
/// invocation answered 501. Nothing is written, and the replay row is not
/// spent: the same request is refused the same way again, not answered 409.
#[tokio::test]
async fn a_write_mixed_with_a_read_is_refused_before_any_work() -> Result<()> {
    let (client, _dir) = node("sqlite::memory:").await?;
    let session = sign_in(&client).await?;
    let resource = |key: &str| -> Result<_> {
        Ok(session.space_id.clone().to_resource(
            "kv".parse::<Service>()?,
            Some(key.parse::<Path>()?),
            None,
            None,
        ))
    };
    let mixed = session
        .invoke_any(
            [
                (
                    resource("mixed/a")?,
                    ["tinycloud.kv/put".parse::<Ability>()?],
                ),
                (
                    resource("mixed/b")?,
                    ["tinycloud.kv/get".parse::<Ability>()?],
                ),
            ],
            None,
        )?
        .encode()?;
    for attempt in ["first", "resent"] {
        let (status, body) = send(&client, &mixed, b"mixed", &[]).await?;
        ensure!(
            status == Status::NotImplemented
                && body.contains(
                    "Multiple invocation outcomes require a homogeneous KV get or metadata batch"
                ),
            "{attempt} mixed write and read: {status} {body}"
        );
    }
    let read = signed(&session, "tinycloud.kv/get", "mixed/a")?;
    let (status, body) = send(&client, &read, b"", &[]).await?;
    ensure!(
        status == Status::NotFound,
        "nothing written: {status} {body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_replay_row_follows_the_write() -> Result<()> {
    let Some(url) = common::postgres_test_url("postgres_replay_row_follows_the_write") else {
        return Ok(());
    };
    let admin = Database::connect(url.as_str()).await?;
    let schema = format!(
        "tc2375_{}_{}",
        std::process::id(),
        time::OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("CREATE SCHEMA {schema}"),
        ))
        .await?;
    let mut scoped = reqwest::Url::parse(&url)?;
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    let result = async {
        let (client, _dir) = node(scoped.as_str()).await?;
        let result = replay_row_follows_the_write(&client).await;
        drop(client);
        result
    }
    .await;
    admin
        .execute(Statement::from_string(
            DbBackend::Postgres,
            format!("DROP SCHEMA {schema} CASCADE"),
        ))
        .await?;
    result
}

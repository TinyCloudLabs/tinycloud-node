//! TC-887 S3b through the real app: a node on filesystem blocks with
//! `at_rest.mode = "encrypt"` (self-host `escrow_none`) stores KV values sealed
//! under anonymous names and serves them back as plaintext, across a restart.
//! An `off` node on the same code stores them as before.

use std::path::{Path as FsPath, PathBuf};

use anyhow::{anyhow, ensure, Context, Result};
use k256::ecdsa::SigningKey;
use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
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
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SignedSession},
};

const MARKER: &str = "TC887-S3B-NODE-MARKER";

async fn node(dir: &FsPath, at_rest: Value) -> Result<Client> {
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.into();
    config.storage.database = Some(format!("sqlite:{}?mode=rwc", dir.join("caps.db").display()));
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config([113; 32], base64::URL_SAFE_NO_PAD),
    }))?;
    config.at_rest = serde_json::from_value(at_rest)?;
    let figment = Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    Ok(Client::tracked(tinycloud::app(&figment).await?).await?)
}

fn wallet() -> Result<(SigningKey, [u8; 20], SpaceId)> {
    let key = SigningKey::from_bytes(&[113; 32].into())?;
    let public = key.verifying_key().to_encoded_point(false);
    let digest = Keccak256::digest(&public.as_bytes()[1..]);
    let address: [u8; 20] = digest[12..].try_into()?;
    let space = format!(
        "tinycloud:pkh:eip155:1:0x{}:at-rest-fs",
        encode_eip55(&address)
    )
    .parse()?;
    Ok((key, address, space))
}

fn sign(key: &SigningKey, message: &Message) -> Result<[u8; 65]> {
    let (signature, recovery) =
        key.sign_prehash_recoverable(&message.eip191_hash().map_err(|e| anyhow!("{e}"))?)?;
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(&signature.to_bytes());
    bytes[64] = recovery.to_byte() + 27;
    Ok(bytes)
}

fn rfc3339(t: time::OffsetDateTime) -> Result<String> {
    Ok(t.format(&time::format_description::well_known::Rfc3339)?)
}

async fn delegate(client: &Client, headers: &impl serde::Serialize) -> Result<()> {
    let auth = serde_json::to_value(headers)?["Authorization"]
        .as_str()
        .map(str::to_owned)
        .context("Authorization header")?;
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", auth))
        .dispatch()
        .await;
    let status = response.status();
    ensure!(
        status == Status::Ok,
        "delegate: {status} {:?}",
        response.into_string().await
    );
    Ok(())
}

/// Host delegation for the space, then a KV session.
async fn session(client: &Client) -> Result<Session> {
    let (wallet, address, space) = wallet()?;
    let now = time::OffsetDateTime::now_utc();
    let peer = client
        .get(format!("/peer/generate/{space}"))
        .dispatch()
        .await;
    ensure!(peer.status() == Status::Ok, "peer generation");
    let host = generate_host_siwe_message(serde_json::from_value(json!({
        "address": format!("0x{}", encode_eip55(&address)),
        "chainId": 1, "domain": "localhost",
        "issuedAt": rfc3339(now - time::Duration::minutes(1))?,
        "spaceId": space,
        "peerId": peer.into_string().await.context("peer DID")?,
    }))?)?;
    let host_signature = sign(&wallet, &host)?;
    let host: SignedMessage = serde_json::from_value(json!({
        "siwe": host.to_string(), "signature": format!("0x{}", hex::encode(host_signature)),
    }))?;
    delegate(client, &siwe_to_delegation_headers(host)).await?;

    let key = ed25519_dalek::SigningKey::from_bytes(&[114; 32]);
    let jwk: JWK = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519",
        "d": base64::encode_config(key.to_bytes(), base64::URL_SAFE_NO_PAD),
        "x": base64::encode_config(key.verifying_key().to_bytes(), base64::URL_SAFE_NO_PAD),
    }))?;
    let prepared = prepare_session(serde_json::from_value(json!({
        "abilities": {"kv": {"": ["tinycloud.kv/put", "tinycloud.kv/get", "tinycloud.kv/del"]}},
        "address": format!("0x{}", encode_eip55(&address)),
        "chainId": 1, "domain": "localhost",
        "issuedAt": rfc3339(now - time::Duration::minutes(1))?,
        "expirationTime": rfc3339(now + time::Duration::hours(1))?,
        "spaceId": space, "jwk": jwk, "nonce": "tc887s3bnode",
    }))?)?;
    let signature = sign(&wallet, &prepared.siwe)?;
    let session = complete_session_setup(SignedSession {
        session: prepared,
        signature: Signature::from(signature),
    })?;
    delegate(client, &session.delegation_header).await?;
    Ok(session)
}

async fn invoke(
    client: &Client,
    session: &Session,
    path: &str,
    action: &str,
    body: &str,
) -> Result<(Status, String)> {
    invoke_in(client, session, &session.space_id, &[(path, action)], body).await
}

/// One invocation with several `(path, action)` capabilities in `space`.
async fn invoke_in(
    client: &Client,
    session: &Session,
    space: &SpaceId,
    caps: &[(&str, &str)],
    body: &str,
) -> Result<(Status, String)> {
    let mut targets = Vec::new();
    for (path, action) in caps {
        let resource = space.clone().to_resource(
            "kv".parse::<Service>()?,
            Some(path.parse::<Path>()?),
            None,
            None,
        );
        targets.push((resource, [action.parse::<Ability>()?]));
    }
    let invocation = session.invoke_any(targets, None)?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", invocation.encode()?))
        .header(ContentType::Plain)
        .body(body)
        .dispatch()
        .await;
    Ok((
        response.status(),
        response.into_string().await.unwrap_or_default(),
    ))
}

/// Rows in the node's `space_data_key` table.
fn data_key_rows(dir: &FsPath) -> Result<i64> {
    let db = rusqlite::Connection::open(dir.join("caps.db"))?;
    Ok(db.query_row("SELECT COUNT(*) FROM space_data_key", [], |r| r.get(0))?)
}

fn files(root: &FsPath) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else {
                out.push(path);
            }
        }
    }
    out
}

fn contains(bytes: &[u8], needle: &[u8]) -> bool {
    bytes.windows(needle.len()).any(|w| w == needle)
}

/// A short value and a multi-segment one (200 000 bytes, > 3 × 64 KiB).
fn values() -> Vec<(String, String)> {
    let big: String = std::iter::once(MARKER.to_string())
        .chain((0..20_000).map(|i| format!("{:09} ", i)))
        .collect();
    vec![
        ("notes/short".into(), format!("{MARKER} short value")),
        ("notes/big".into(), big),
    ]
}

/// Also the regression test for a SQLite deadlock: the first put in a new
/// space creates the space's data key, which must happen before the
/// invocation's write lock and transaction (`prepare_write`), not inside them.
#[tokio::test]
async fn an_encrypting_filesystem_node_seals_kv_values_and_serves_plaintext() -> Result<()> {
    tokio::time::timeout(std::time::Duration::from_secs(120), encrypting_node())
        .await
        .context("encrypting node test timed out (first-put deadlock?)")?
}

async fn encrypting_node() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let at_rest = json!({"mode": "encrypt", "escrow_none": true});
    {
        let client = node(dir.path(), at_rest.clone()).await?;
        let session = session(&client).await?;
        for (path, value) in values() {
            let (status, body) =
                invoke(&client, &session, &path, "tinycloud.kv/put", &value).await?;
            ensure!(status == Status::Ok, "put {path}: {status} {body}");
            let (status, body) = invoke(&client, &session, &path, "tinycloud.kv/get", "").await?;
            ensure!(
                status == Status::Ok && body == value,
                "get {path}: {status} {} bytes",
                body.len()
            );
        }
    }

    let blocks = dir.path().join("blocks");
    let stored = files(&blocks);
    ensure!(
        stored.len() == 2,
        "expected 2 stored blocks, got {stored:?}"
    );
    let (_, address, space) = wallet()?;
    let address = hex::encode(address);
    for file in &stored {
        let rel = file.strip_prefix(&blocks)?.to_string_lossy().to_lowercase();
        ensure!(rel.starts_with("v1/"), "not a sealed name: {rel}");
        ensure!(
            !rel.contains(&address) && !rel.contains("at-rest-fs"),
            "name leaks the space: {rel}"
        );
        let raw = std::fs::read(file)?;
        ensure!(
            !contains(&raw, MARKER.as_bytes()),
            "plaintext marker on disk in {rel}"
        );
        ensure!(raw.starts_with(b"TCE1"), "{rel} is not TCE1");
    }
    println!("sealed blocks for {space}: {stored:?}");

    // Restart with the same root: the keys come back from the database and
    // the sealed values read back.
    let client = node(dir.path(), at_rest).await?;
    let session = session(&client).await?;
    for (path, value) in values() {
        let (status, body) = invoke(&client, &session, &path, "tinycloud.kv/get", "").await?;
        ensure!(
            status == Status::Ok && body == value,
            "after restart, get {path}: {status}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_off_node_still_stores_plaintext_under_legacy_names() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let client = node(dir.path(), json!({})).await?;
    let session = session(&client).await?;
    let (path, value) = values().remove(0);
    let (status, body) = invoke(&client, &session, &path, "tinycloud.kv/put", &value).await?;
    ensure!(status == Status::Ok, "put: {status} {body}");
    let stored = files(&dir.path().join("blocks"));
    ensure!(stored.len() == 1, "{stored:?}");
    ensure!(!stored[0].to_string_lossy().contains("/v1/"), "{stored:?}");
    ensure!(
        contains(&std::fs::read(&stored[0])?, MARKER.as_bytes()),
        "off mode keeps plaintext"
    );
    Ok(())
}

/// TC-887 S3 review B1: an invocation the node refuses (spaces it does not
/// host, no authority there) creates no data key and no mirror object.
#[tokio::test]
async fn a_refused_put_creates_no_data_key_or_mirror_object() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let client = node(dir.path(), json!({"mode": "encrypt", "escrow_none": true})).await?;
    let session = session(&client).await?;
    let mirror = dir.path().join("at-rest");
    let (rows, mirrored) = (data_key_rows(dir.path())?, files(&mirror).len());
    let (_, address, _) = wallet()?;
    for n in 0..3 {
        let foreign: SpaceId = format!(
            "tinycloud:pkh:eip155:1:0x{}:never-hosted-{n}",
            encode_eip55(&address)
        )
        .parse()?;
        let (status, body) = invoke_in(
            &client,
            &session,
            &foreign,
            &[("notes/x", "tinycloud.kv/put")],
            "value",
        )
        .await?;
        ensure!(status != Status::Ok, "put to {foreign}: {status} {body}");
    }
    ensure!(
        data_key_rows(dir.path())? == rows,
        "refused puts created data keys"
    );
    ensure!(
        files(&mirror).len() == mirrored,
        "refused puts created mirror objects"
    );
    Ok(())
}

/// TC-887 S3 review B2: a mixed get + delete (the transaction path, under the
/// SQLite writer lock) of sealed values after the database lost the space's
/// data-key row (restored to before it; the mirror still holds it). The key
/// is put back before the lock, so the request completes instead of waiting
/// on the lock it holds.
#[tokio::test]
async fn a_mixed_read_and_delete_after_losing_the_data_key_row_completes() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let at_rest = json!({"mode": "encrypt", "escrow_none": true});
    {
        let client = node(dir.path(), at_rest.clone()).await?;
        let session = session(&client).await?;
        for (path, value) in values() {
            let (status, body) =
                invoke(&client, &session, &path, "tinycloud.kv/put", &value).await?;
            ensure!(status == Status::Ok, "put {path}: {status} {body}");
        }
    }
    rusqlite::Connection::open(dir.path().join("caps.db"))?
        .execute("DELETE FROM space_data_key", [])?;

    let client = node(dir.path(), at_rest).await?;
    let session = session(&client).await?;
    let (status, body) = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        invoke_in(
            &client,
            &session,
            &session.space_id,
            &[
                ("notes/short", "tinycloud.kv/get"),
                ("notes/big", "tinycloud.kv/del"),
            ],
            "",
        ),
    )
    .await
    .context("mixed get + del hung (key restore under the writer lock?)")??;
    ensure!(
        status != Status::ServiceUnavailable && status != Status::InternalServerError,
        "mixed get + del: {status} {body}"
    );
    ensure!(data_key_rows(dir.path())? == 1, "the data key is put back");
    let (path, value) = values().remove(0);
    let (status, body) = invoke(&client, &session, &path, "tinycloud.kv/get", "").await?;
    ensure!(
        status == Status::Ok && body == value,
        "get {path}: {status}"
    );
    Ok(())
}

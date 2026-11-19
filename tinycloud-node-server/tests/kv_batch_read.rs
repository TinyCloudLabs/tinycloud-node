//! TC-1274: a batch `kv/get` or `kv/metadata` invocation is answered from one
//! index lookup per space. Its response must be what a lookup per capability
//! gives: results in request order, duplicates answered each time, missing and
//! deleted keys not found, and the per-key `x-tinycloud-max-response-bytes`
//! check reporting the first oversized capability in request order.
//!
//! Driven through the real node on in-memory SQLite with SDK-signed
//! invocations. `postgres_round_trip_budget.rs` runs the same fixture on
//! PostgreSQL and counts the statements.

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

const ITEMS: usize = 100;
const DELETED: usize = 7;
const BIG: &str = "batch/big";
const HUGE: &str = "batch/huge";

async fn node() -> Result<(Client, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
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
        "tinycloud:pkh:eip155:1:0x{}:batch-read",
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
        "nonce": "tc1274batch",
    }))?)?;
    let signature = sign(&key, &prepared.siwe)?;
    let session = complete_session_setup(SignedSession {
        session: prepared,
        signature: Signature::from(signature),
    })?;
    register(client, &session.delegation_header).await?;
    Ok(session)
}

/// One invocation of `ability` over each of `keys`, in order.
async fn invoke(
    client: &Client,
    session: &Session,
    ability: &str,
    keys: &[String],
    body: &[u8],
    max_response_bytes: Option<u64>,
) -> Result<(Status, String)> {
    let ability: Ability = ability.parse()?;
    let capabilities = keys
        .iter()
        .map(|key| {
            Ok((
                session.space_id.clone().to_resource(
                    "kv".parse::<Service>()?,
                    Some(key.parse::<Path>()?),
                    None,
                    None,
                ),
                [ability.clone()],
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let invocation = session.invoke_any(capabilities, None)?;
    let mut request = client
        .post("/invoke")
        .header(Header::new("Authorization", invocation.encode()?))
        .header(ContentType::Plain)
        .body(body);
    if let Some(limit) = max_response_bytes {
        request = request.header(Header::new(
            "x-tinycloud-max-response-bytes",
            limit.to_string(),
        ));
    }
    let response = request.dispatch().await;
    Ok((
        response.status(),
        response.into_string().await.unwrap_or_default(),
    ))
}

fn key(index: usize) -> String {
    format!("batch/{index:03}")
}

/// What a read of `key` finds once the fixture is written.
fn value(key: &str) -> Option<Vec<u8>> {
    match key {
        BIG => Some(vec![b'b'; 64]),
        HUGE => Some(vec![b'h'; 128]),
        _ => {
            let index: usize = key.strip_prefix("batch/")?.parse().ok()?;
            (index < ITEMS && index != DELETED).then(|| format!("v{index}").into_bytes())
        }
    }
}

/// A permutation of the fixture, so present, deleted and request order all
/// vary, with a key repeated three times and two keys never written.
fn request() -> Vec<String> {
    let mut keys: Vec<String> = (0..ITEMS).map(|n| key(n * 37 % ITEMS)).collect();
    keys[10] = keys[3].clone();
    keys[90] = keys[3].clone();
    keys[50] = "batch/missing-a".to_owned();
    keys[51] = "batch/missing-b".to_owned();
    keys
}

/// An invocation's capabilities are a map: a repeated key is one capability,
/// and the order they are answered in is the map's, by resource.
fn capability_order(keys: &[String]) -> Vec<String> {
    let mut order = keys.to_vec();
    order.sort();
    order.dedup();
    order
}

/// The error for the first key, in `order`, whose value is over `limit`.
fn too_large(order: &[String], limit: usize) -> Option<String> {
    order.iter().find_map(|key| {
        let size = value(key)?.len();
        (size > limit).then(|| {
            format!("KV response is {size} bytes, exceeding the requested limit of {limit} bytes")
        })
    })
}

fn results(body: &str) -> Result<Vec<Value>> {
    Ok(serde_json::from_str::<Value>(body)?["results"]
        .as_array()
        .context("batch response has results")?
        .clone())
}

#[tokio::test]
async fn batch_reads_answer_as_a_lookup_per_key_would() -> Result<()> {
    let (client, _dir) = node().await?;
    let session = sign_in(&client).await?;

    for index in 0..ITEMS {
        let key = key(index);
        let value = value(&key).unwrap_or_else(|| b"to-delete".to_vec());
        let (status, body) =
            invoke(&client, &session, "tinycloud.kv/put", &[key], &value, None).await?;
        ensure!(status == Status::Ok, "put: {status} {body}");
    }
    for (key, bytes) in [(BIG, 64), (HUGE, 128)] {
        let value = value(key).context("oversized fixture")?;
        ensure!(value.len() == bytes);
        let (status, body) = invoke(
            &client,
            &session,
            "tinycloud.kv/put",
            &[key.to_owned()],
            &value,
            None,
        )
        .await?;
        ensure!(status == Status::Ok, "put: {status} {body}");
    }
    let (status, body) = invoke(
        &client,
        &session,
        "tinycloud.kv/del",
        &[key(DELETED)],
        b"",
        None,
    )
    .await?;
    ensure!(status == Status::Ok, "delete: {status} {body}");

    let keys = request();
    let order = capability_order(&keys);
    ensure!(
        order.len() == keys.len() - 2,
        "the repeated key is one capability"
    );
    let (status, body) = invoke(&client, &session, "tinycloud.kv/get", &keys, b"", None).await?;
    ensure!(status == Status::Ok, "batch get: {status} {body}");
    let found = results(&body)?;
    ensure!(
        found.len() == order.len(),
        "{} results for {} capabilities",
        found.len(),
        order.len()
    );
    let mut etags = std::collections::HashMap::new();
    for (key, result) in order.iter().zip(&found) {
        ensure!(
            result["key"] == key.as_str(),
            "order: {key} answered as {}",
            result["key"]
        );
        match value(key) {
            Some(expected) => {
                ensure!(result["ok"] == true, "{key} must be found: {result}");
                let data = base64::decode(result["dataBase64"].as_str().context("data")?)?;
                ensure!(data == expected, "{key} returned {data:?}");
                etags.insert(key.clone(), result["headers"]["etag"].clone());
            }
            None => ensure!(
                result["ok"] == false && result["error"]["code"] == "KV_NOT_FOUND",
                "{key} must not be found: {result}"
            ),
        }
    }
    // The deleted key and the two never written are "not found".
    ensure!(found.iter().filter(|r| r["ok"] == false).count() == 3);
    println!("TC-1274 batch get response order: {:?}", &order[..6]);

    let (status, body) =
        invoke(&client, &session, "tinycloud.kv/metadata", &keys, b"", None).await?;
    ensure!(status == Status::Ok, "batch head: {status} {body}");
    let heads = results(&body)?;
    ensure!(heads.len() == order.len());
    for (key, head) in order.iter().zip(&heads) {
        ensure!(
            head["key"] == key.as_str(),
            "order: {key} answered as {}",
            head["key"]
        );
        match etags.get(key) {
            Some(etag) => ensure!(
                head["ok"] == true
                    && head.get("dataBase64").is_none()
                    && head["headers"]["etag"] == *etag,
                "{key}: {head}"
            ),
            None => ensure!(head["ok"] == false, "{key}: {head}"),
        }
    }

    // The first oversized capability, in capability order, is the one
    // reported (not the largest), and a value of exactly the limit is not
    // oversized.
    for limit in [32, 64] {
        let keys = [key(1), HUGE.to_owned(), key(2), BIG.to_owned()];
        let expected = too_large(&capability_order(&keys), limit).context("an oversized key")?;
        let (status, body) = invoke(
            &client,
            &session,
            "tinycloud.kv/get",
            &keys,
            b"",
            Some(limit as u64),
        )
        .await?;
        ensure!(
            status == Status::PayloadTooLarge && body == expected,
            "limit {limit}: {status} {body} (expected {expected})"
        );
    }
    let keys = [key(1), BIG.to_owned(), key(2)];
    let (status, body) =
        invoke(&client, &session, "tinycloud.kv/get", &keys, b"", Some(64)).await?;
    ensure!(
        status == Status::Ok,
        "a value of exactly the limit: {status} {body}"
    );
    Ok(())
}

/// A batch of `ability` over `keys`, conditional on `if_none_match`: its
/// status, `ETag` and body.
async fn conditional_batch(
    client: &Client,
    session: &Session,
    ability: &str,
    keys: &[&str],
    if_none_match: Option<&str>,
) -> Result<(Status, Option<String>, String)> {
    let ability: Ability = ability.parse()?;
    let capabilities = keys
        .iter()
        .map(|key| {
            Ok((
                session.space_id.clone().to_resource(
                    "kv".parse::<Service>()?,
                    Some(key.parse::<Path>()?),
                    None,
                    None,
                ),
                [ability.clone()],
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let invocation = session.invoke_any(capabilities, None)?;
    let mut request = client
        .post("/invoke")
        .header(Header::new("Authorization", invocation.encode()?));
    if let Some(tag) = if_none_match {
        request = request.header(Header::new("If-None-Match", tag.to_owned()));
    }
    let response = request.dispatch().await;
    let status = response.status();
    let etag = response.headers().get_one("ETag").map(str::to_owned);
    Ok((
        status,
        etag,
        response.into_string().await.unwrap_or_default(),
    ))
}

async fn put(client: &Client, session: &Session, key: &str, value: &[u8]) -> Result<()> {
    let (status, body) = invoke(
        client,
        session,
        "tinycloud.kv/put",
        &[key.to_owned()],
        value,
        None,
    )
    .await?;
    ensure!(status == Status::Ok, "put {key}: {status} {body}");
    Ok(())
}

/// The value a batch response gives for `key`, `None` when not found.
fn found(body: &str, key: &str) -> Result<Option<Vec<u8>>> {
    let result = results(body)?
        .into_iter()
        .find(|result| result["key"] == key)
        .with_context(|| format!("{key} answered"))?;
    match result["dataBase64"].as_str() {
        Some(data) => Ok(Some(base64::decode(data)?)),
        None => Ok(None),
    }
}

/// TC-3217: a batch read carries the state it was read from as its `ETag`.
/// Sent back in `If-None-Match` while nothing in the space has changed, it
/// answers 304 with no body; any write or delete in the space, another key
/// set, or `kv/metadata` instead of `kv/get` answers 200 with fresh values.
#[tokio::test]
async fn conditional_batch_reads_answer_304_only_while_unchanged() -> Result<()> {
    let (client, _dir) = node().await?;
    let session = sign_in(&client).await?;
    put(&client, &session, "board/a", b"a1").await?;
    put(&client, &session, "board/b", b"b1").await?;
    let get = "tinycloud.kv/get";
    let board = ["board/a", "board/b"];

    let (status, first, body) = conditional_batch(&client, &session, get, &board, None).await?;
    ensure!(status == Status::Ok, "{status} {body}");
    let first = first.context("a batch read has an ETag")?;
    ensure!(first.starts_with("\"kv-batch-"), "{first}");
    ensure!(found(&body, "board/a")? == Some(b"a1".to_vec()));

    // Unchanged: 304, the same tag, no body.
    let (status, tag, body) =
        conditional_batch(&client, &session, get, &board, Some(&first)).await?;
    ensure!(status == Status::NotModified, "{status} {body}");
    ensure!(tag.as_deref() == Some(first.as_str()), "{tag:?}");
    ensure!(body.is_empty(), "{body}");

    // The same state does not answer another key set or ability.
    let (status, _, body) = conditional_batch(
        &client,
        &session,
        get,
        &["board/a", "board/c"],
        Some(&first),
    )
    .await?;
    ensure!(status == Status::Ok, "other keys: {status} {body}");
    let (status, _, body) = conditional_batch(
        &client,
        &session,
        "tinycloud.kv/metadata",
        &board,
        Some(&first),
    )
    .await?;
    ensure!(status == Status::Ok, "metadata: {status} {body}");

    // A write to a key outside the batch leaves its answer, and its state,
    // unchanged.
    put(&client, &session, "elsewhere", b"x").await?;
    let (status, tag, body) =
        conditional_batch(&client, &session, get, &board, Some(&first)).await?;
    ensure!(
        status == Status::NotModified,
        "after an unrelated write: {status} {body}"
    );
    ensure!(tag.as_deref() == Some(first.as_str()), "{tag:?}");

    // A changed value answers the new value.
    put(&client, &session, "board/a", b"a2").await?;
    let (status, third, body) =
        conditional_batch(&client, &session, get, &board, Some(&first)).await?;
    ensure!(status == Status::Ok, "after a write: {status} {body}");
    ensure!(found(&body, "board/a")? == Some(b"a2".to_vec()));
    let third = third.context("ETag")?;

    // A delete answers the key as not found.
    let (status, body) = invoke(
        &client,
        &session,
        "tinycloud.kv/del",
        &["board/b".to_owned()],
        b"",
        None,
    )
    .await?;
    ensure!(status.class().is_success(), "del: {status} {body}");
    let (status, fourth, body) =
        conditional_batch(&client, &session, get, &board, Some(&third)).await?;
    ensure!(status == Status::Ok, "after a delete: {status} {body}");
    ensure!(found(&body, "board/b")?.is_none());
    let fourth = fourth.context("ETag")?;

    let (status, _, body) =
        conditional_batch(&client, &session, get, &board, Some(&fourth)).await?;
    ensure!(status == Status::NotModified, "settled: {status} {body}");
    Ok(())
}

/// TC-3217: `If-None-Match: *` on a batch read is not a state, so it never
/// answers 304; and two key sets that differ only in keys never written have
/// different states.
#[tokio::test]
async fn conditional_batch_reads_never_match_a_wildcard_or_another_absent_key() -> Result<()> {
    let (client, _dir) = node().await?;
    let session = sign_in(&client).await?;
    put(&client, &session, "board/a", b"a1").await?;
    put(&client, &session, "board/b", b"b1").await?;
    let get = "tinycloud.kv/get";

    for wildcard in ["*", " * "] {
        let (status, _, body) = conditional_batch(
            &client,
            &session,
            get,
            &["board/a", "board/b"],
            Some(wildcard),
        )
        .await?;
        ensure!(
            status == Status::BadRequest,
            "{wildcard:?}: {status} {body}"
        );
    }

    let (status, tag, body) =
        conditional_batch(&client, &session, get, &["board/a", "board/x"], None).await?;
    ensure!(status == Status::Ok, "{status} {body}");
    let tag = tag.context("ETag")?;
    let (status, other, body) =
        conditional_batch(&client, &session, get, &["board/a", "board/y"], Some(&tag)).await?;
    ensure!(status == Status::Ok, "other absent key: {status} {body}");
    ensure!(other.as_deref() != Some(tag.as_str()), "{other:?}");
    Ok(())
}

/// TC-3217: a live key whose stored value can't be read is answered as not
/// found with no `ETag`, so a client never caches that answer under the state
/// of a key that is present.
#[tokio::test]
async fn a_batch_read_with_an_unreadable_value_has_no_etag() -> Result<()> {
    let (client, dir) = node().await?;
    let session = sign_in(&client).await?;
    put(&client, &session, "board/a", b"a1").await?;
    put(&client, &session, "board/b", b"b1").await?;
    let get = "tinycloud.kv/get";
    let board = ["board/a", "board/b"];

    let block = files(dir.path())
        .into_iter()
        .find(|file| std::fs::read(file).is_ok_and(|bytes| bytes == b"a1"))
        .context("the block of board/a")?;
    let aside = block.with_extension("aside");
    std::fs::rename(&block, &aside)?;
    let (status, etag, body) = conditional_batch(&client, &session, get, &board, None).await?;
    std::fs::rename(&aside, &block)?;
    ensure!(status == Status::Ok, "{status} {body}");
    ensure!(found(&body, "board/a")?.is_none(), "{body}");
    ensure!(etag.is_none(), "{etag:?}");

    let (status, etag, body) = conditional_batch(&client, &session, get, &board, None).await?;
    ensure!(status == Status::Ok, "{status} {body}");
    ensure!(found(&body, "board/a")? == Some(b"a1".to_vec()), "{body}");
    ensure!(etag.is_some(), "a readable batch has an ETag");
    Ok(())
}

/// Every file under `dir`.
fn files(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(files(&path));
        } else {
            out.push(path);
        }
    }
    out
}

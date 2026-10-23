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

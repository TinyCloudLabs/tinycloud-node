//! TC-3443: `POST /session/retire` through the real node. A signed-in
//! session key retires itself; from then on it invokes nothing and a new
//! delegation it signs is refused, while a child it made before keeps
//! working.

use anyhow::{anyhow, ensure, Context, Result};
use k256::ecdsa::SigningKey;
use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, HashMap};
use tinycloud_auth::{
    cacaos::{
        siwe::{encode_eip55, Message},
        siwe_cacao::Signature,
    },
    resolver::DID_METHODS,
    resource::{Path, Service, SpaceId},
    siwe_recap::Ability,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::keys::StaticSecret;
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SignedSession},
};

const SECRET: [u8; 32] = [77; 32];

async fn node(rate_limit_per_minute: u32) -> Result<(Client, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config(SECRET, base64::URL_SAFE_NO_PAD),
    }))?;
    config.session_retire.rate_limit_per_minute = rate_limit_per_minute;
    let figment = Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    let rocket = tinycloud::app_with_control(&figment, &config, None).await?;
    Ok((Client::tracked(rocket).await?, dir))
}

fn node_did() -> String {
    StaticSecret::new(SECRET.to_vec()).unwrap().node_did()
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
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

async fn post(client: &Client, path: &str, authorization: &str) -> (Status, String) {
    let response = client
        .post(path.to_owned())
        .remote("127.0.0.1:9000".parse().unwrap())
        .header(Header::new("Authorization", authorization.to_owned()))
        .header(ContentType::Plain)
        .dispatch()
        .await;
    (
        response.status(),
        response.into_string().await.unwrap_or_default(),
    )
}

/// A space and a session key that may get any key in it.
async fn sign_in(client: &Client) -> Result<Session> {
    let key = SigningKey::from_bytes(&[78; 32].into())?;
    let public = key.verifying_key().to_encoded_point(false);
    let address: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..].try_into()?;
    let space: SpaceId =
        format!("tinycloud:pkh:eip155:1:0x{}:retire", encode_eip55(&address)).parse()?;
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
    let (status, body) = post(
        client,
        "/delegate",
        &authorization(&siwe_to_delegation_headers(host))?,
    )
    .await;
    ensure!(status == Status::Ok, "host delegate: {status} {body}");

    let jwk = JWK::generate_ed25519()?;
    let prepared = prepare_session(serde_json::from_value(json!({
        "abilities": {"kv": {"": ["tinycloud.kv/get"]}},
        "address": format!("0x{}", encode_eip55(&address)),
        "chainId": 1,
        "domain": "localhost",
        "issuedAt": (now - time::Duration::minutes(1)).format(rfc3339)?,
        "expirationTime": (now + time::Duration::hours(1)).format(rfc3339)?,
        "spaceId": space,
        "jwk": jwk,
        "nonce": "tc3443retire",
    }))?)?;
    let signature = sign(&key, &prepared.siwe)?;
    let session = complete_session_setup(SignedSession {
        session: prepared,
        signature: Signature::from(signature),
    })?;
    let (status, body) = post(
        client,
        "/delegate",
        &authorization(&session.delegation_header)?,
    )
    .await;
    ensure!(status == Status::Ok, "session delegate: {status} {body}");
    Ok(session)
}

/// A `kv/get` delegation from `session` to a fresh key, and that key as a
/// session (for invoking under it).
fn child_of(session: &Session) -> Result<(String, Session)> {
    let jwk = JWK::generate_ed25519()?;
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    let abilities = HashMap::from([(
        "kv".parse::<Service>()?,
        HashMap::from([(
            "".parse::<Path>()?,
            vec!["tinycloud.kv/get".parse::<Ability>()?],
        )]),
    )]);
    let delegation = session.create_delegation(
        &did,
        &session.space_id,
        abilities,
        (now() + 600) as f64,
        None,
    )?;
    let mut child = session.clone();
    child.delegation_cid = delegation.cid.parse()?;
    child.jwk = jwk;
    child.verification_method = vm;
    Ok((delegation.delegation, child))
}

/// `session` reads a key in its space through `/invoke`.
async fn invoke(client: &Client, session: &Session) -> Result<(Status, String)> {
    let capabilities = [(
        session.space_id.clone().to_resource(
            "kv".parse::<Service>()?,
            Some("notes/a".parse::<Path>()?),
            None,
            None,
        ),
        ["tinycloud.kv/get".parse::<Ability>()?],
    )];
    let token = session.invoke_any(capabilities, None)?.encode()?;
    Ok(post(client, "/invoke", &token).await)
}

/// A retire UCAN signed by `key`, issued by `issuer`, with `edit` applied.
fn retire_token(key: &JWK, issuer: &str, edit: impl FnOnce(&mut Payload<Value>)) -> String {
    let mut caps = Capabilities::<Value>::new();
    caps.with_action(
        "urn:tinycloud:session:self".parse().unwrap(),
        "tinycloud.session/retire".parse().unwrap(),
        [BTreeMap::new()],
    );
    let mut payload = Payload::<Value> {
        issuer: issuer.parse().unwrap(),
        audience: node_did().parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now() - 1) as f64).unwrap()),
        expiration: NumericDate::try_from_seconds((now() + 60) as f64).unwrap(),
        nonce: Some(format!("retire-{}", rand::random::<u64>())),
        facts: None,
        proof: vec![],
        attenuation: caps,
    };
    edit(&mut payload);
    payload
        .sign(Algorithm::EdDSA, key)
        .unwrap()
        .encode()
        .unwrap()
}

fn session_retire_token(session: &Session, edit: impl FnOnce(&mut Payload<Value>)) -> String {
    retire_token(&session.jwk, &session.verification_method, edit)
}

#[tokio::test]
async fn retire_returns_the_first_retire_time_and_ends_only_the_session_key() -> Result<()> {
    let (client, _dir) = node(100).await?;
    let session = sign_in(&client).await?;
    let (early, early_child) = child_of(&session)?;
    let (status, body) = post(&client, "/delegate", &early).await;
    ensure!(status == Status::Ok, "pre-retire child: {status} {body}");
    let (status, body) = invoke(&client, &session).await?;
    ensure!(
        status != Status::Unauthorized,
        "before retire: {status} {body}"
    );

    let (status, body) = post(
        &client,
        "/session/retire",
        &format!("Bearer {}", session_retire_token(&session, |_| ())),
    )
    .await;
    ensure!(status == Status::Ok, "retire: {status} {body}");
    let first: Value = serde_json::from_str(&body)?;
    let did = session.verification_method.split('#').next().unwrap();
    ensure!(first["did"] == did, "{first}");
    let retired_at = first["retiredAt"].as_str().context("retiredAt")?;
    time::OffsetDateTime::parse(retired_at, &time::format_description::well_known::Rfc3339)?;

    // Without the Bearer prefix, a repeat answers the first retire time.
    let (status, body) = post(
        &client,
        "/session/retire",
        &session_retire_token(&session, |_| ()),
    )
    .await;
    ensure!(status == Status::Ok, "repeat retire: {status} {body}");
    let again: Value = serde_json::from_str(&body)?;
    ensure!(again == first, "{again} != {first}");

    // The session key itself invokes nothing.
    let (status, body) = invoke(&client, &session).await?;
    ensure!(
        status == Status::Unauthorized && body.starts_with("session_retired: "),
        "self invoke: {status} {body}"
    );
    // Its child stored before the retire still authorizes its holder.
    let (status, body) = invoke(&client, &early_child).await?;
    ensure!(
        status != Status::Unauthorized,
        "pre-retire child: {status} {body}"
    );
    // A child it signs now is refused.
    let (late, _) = child_of(&session)?;
    let (status, body) = post(&client, "/delegate", &late).await;
    ensure!(
        status == Status::Unauthorized && body.starts_with("session_retired: "),
        "post-retire child: {status} {body}"
    );
    // The stored child, resubmitted, answers as before.
    let (status, body) = post(&client, "/delegate", &early).await;
    ensure!(status == Status::Ok, "resubmitted child: {status} {body}");
    Ok(())
}

#[tokio::test]
async fn malformed_retire_requests_are_refused_401() -> Result<()> {
    let (client, _dir) = node(100).await?;
    let key = JWK::generate_ed25519()?;
    let did = DID_METHODS.generate(&key, "key")?.to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    let cases: Vec<(&str, String)> = vec![
        (
            "wrong audience",
            retire_token(&key, &vm, |p| {
                p.audience = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
                    .parse()
                    .unwrap()
            }),
        ),
        (
            "exp beyond 120 s",
            retire_token(&key, &vm, |p| {
                p.expiration = NumericDate::try_from_seconds((now() + 121) as f64).unwrap()
            }),
        ),
        (
            "non-did:key issuer",
            retire_token(&key, "did:web:example.com#key-1", |_| ()),
        ),
        (
            "wrong att",
            retire_token(&key, &vm, |p| {
                p.attenuation = Capabilities::new();
                p.attenuation.with_action(
                    "urn:tinycloud:session:self".parse().unwrap(),
                    "tinycloud.kv/get".parse().unwrap(),
                    [BTreeMap::new()],
                );
            }),
        ),
        ("not a UCAN", "Bearer nope".to_owned()),
    ];
    for (case, token) in cases {
        let (status, body) = post(&client, "/session/retire", &token).await;
        ensure!(
            status == Status::Unauthorized && body.starts_with("session_retire_invalid: "),
            "{case}: {status} {body}"
        );
    }
    let response = client
        .post("/session/retire")
        .remote("127.0.0.1:9000".parse().unwrap())
        .dispatch()
        .await;
    ensure!(response.status() == Status::Unauthorized, "missing header");
    Ok(())
}

#[tokio::test]
async fn retire_is_rate_limited_per_ip() -> Result<()> {
    let (client, _dir) = node(2).await?;
    let key = JWK::generate_ed25519()?;
    let did = DID_METHODS.generate(&key, "key")?.to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    for _ in 0..2 {
        let (status, body) =
            post(&client, "/session/retire", &retire_token(&key, &vm, |_| ())).await;
        ensure!(status == Status::Ok, "within the limit: {status} {body}");
    }
    let (status, body) = post(&client, "/session/retire", &retire_token(&key, &vm, |_| ())).await;
    ensure!(
        status == Status::TooManyRequests,
        "over the limit: {status} {body}"
    );
    Ok(())
}

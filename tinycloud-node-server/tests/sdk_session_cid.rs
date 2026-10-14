//! TC-1071: wallet signature import must address the delegation the node stores.
//! Drive the SDK's JSON and Rust entrypoints through the real node, not a hash-only oracle.

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
    session::{complete_session_setup, prepare_session, PreparedSession, Session, SignedSession},
};

async fn node() -> Result<(Client, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some("sqlite::memory:".into());
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config([107; 32], base64::URL_SAFE_NO_PAD),
    }))?;
    let figment = Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    Ok((Client::tracked(tinycloud::app(&figment).await?).await?, dir))
}

fn wallet() -> Result<(SigningKey, [u8; 20], SpaceId)> {
    let key = SigningKey::from_bytes(&[107; 32].into())?;
    let public = key.verifying_key().to_encoded_point(false);
    let digest = Keccak256::digest(&public.as_bytes()[1..]);
    let address = digest[12..].try_into()?;
    let space = format!(
        "tinycloud:pkh:eip155:1:0x{}:sdk-session-cid",
        encode_eip55(&address),
    )
    .parse()?;
    Ok((key, address, space))
}

fn sign(key: &SigningKey, message: &Message) -> Result<[u8; 65]> {
    let (signature, recovery) =
        key.sign_prehash_recoverable(&message.eip191_hash().map_err(|e| anyhow!("{e}"))?)?;
    ensure!(signature.normalize_s().is_none(), "fixture must be low-s");
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(&signature.to_bytes());
    bytes[64] = recovery.to_byte();
    Ok(bytes)
}

fn prepared(address: &[u8; 20], space: &SpaceId) -> Result<PreparedSession> {
    let now = time::OffsetDateTime::now_utc();
    // Throwaway, deterministic session key; no credentials or network DID resolution.
    let key = ed25519_dalek::SigningKey::from_bytes(&[108; 32]);
    let jwk: JWK = serde_json::from_value(json!({
        "kty": "OKP", "crv": "Ed25519",
        "d": base64::encode_config(key.to_bytes(), base64::URL_SAFE_NO_PAD),
        "x": base64::encode_config(key.verifying_key().to_bytes(), base64::URL_SAFE_NO_PAD),
    }))?;
    Ok(prepare_session(serde_json::from_value(json!({
        "abilities": {"kv": {"": ["tinycloud.kv/put", "tinycloud.kv/get"]}},
        "address": format!("0x{}", encode_eip55(address)),
        "chainId": 1,
        "domain": "localhost",
        "issuedAt": (now - time::Duration::minutes(1)).format(&time::format_description::well_known::Rfc3339)?,
        "expirationTime": (now + time::Duration::hours(1)).format(&time::format_description::well_known::Rfc3339)?,
        "spaceId": space,
        "jwk": jwk,
        "nonce": "tc1071session",
    }))?)?)
}

fn json_signed(prepared: &PreparedSession, signature: &str) -> Result<Value> {
    let mut signed = serde_json::to_value(prepared)?;
    signed["signature"] = signature.into();
    Ok(signed)
}

fn authorization(headers: &impl serde::Serialize) -> Result<String> {
    serde_json::to_value(headers)?["Authorization"]
        .as_str()
        .map(str::to_owned)
        .context("SDK delegation Authorization header")
}

async fn register(client: &Client, headers: &impl serde::Serialize) -> Result<Value> {
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", authorization(headers)?))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    ensure!(status == Status::Ok, "delegate: {status} {body}");
    Ok(serde_json::from_str(&body)?)
}

async fn invoke(
    client: &Client,
    session: &Session,
    path: &str,
    action: &str,
    body: &str,
) -> Result<(Status, String)> {
    let resource = session.space_id.clone().to_resource(
        "kv".parse::<Service>()?,
        Some(path.parse::<Path>()?),
        None,
        None,
    );
    let invocation = session.invoke_any([(resource, [action.parse::<Ability>()?])], None)?;
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

#[tokio::test]
async fn wallet_recovery_forms_register_and_invoke() -> Result<()> {
    let (client, _dir) = node().await?;
    let (wallet, address, space) = wallet()?;
    let peer = client
        .get(format!("/peer/generate/{space}"))
        .dispatch()
        .await;
    ensure!(peer.status() == Status::Ok, "peer generation");
    let host = generate_host_siwe_message(serde_json::from_value(json!({
        "address": format!("0x{}", encode_eip55(&address)),
        "chainId": 1, "domain": "localhost",
        "issuedAt": (time::OffsetDateTime::now_utc() - time::Duration::minutes(1)).format(&time::format_description::well_known::Rfc3339)?,
        "spaceId": space,
        "peerId": peer.into_string().await.context("peer DID")?,
    }))?)?;
    let host_signature = sign(&wallet, &host)?;
    let host: SignedMessage = serde_json::from_value(json!({
        "siwe": host.to_string(), "signature": format!("0x{}", hex::encode(host_signature)),
    }))?;
    register(&client, &siwe_to_delegation_headers(host)).await?;

    let mut failures = Vec::new();
    for recovery in [0, 1] {
        let mut prepared = prepared(&address, &space)?;
        let mut signature = None;
        // Select a genuine signature for each recovery parity, never alter its parity.
        for nonce in 0..256 {
            prepared.siwe.nonce = format!("tc1071{recovery}{nonce:03}");
            let candidate = sign(&wallet, &prepared.siwe)?;
            if candidate[64] == recovery {
                signature = Some(candidate);
                break;
            }
        }
        let signature = signature.context("signature with requested recovery parity")?;
        for v in [recovery + 27, recovery] {
            let mut bytes = signature;
            bytes[64] = v;
            for import in ["json", "rust"] {
                let session = if import == "json" {
                    let prefix = if v >= 27 { "" } else { "0x" };
                    let signed =
                        json_signed(&prepared, &format!("{prefix}{}", hex::encode(bytes)))?;
                    complete_session_setup(serde_json::from_value::<SignedSession>(signed)?)?
                } else {
                    complete_session_setup(SignedSession {
                        session: prepared.clone(),
                        signature: Signature::from(bytes),
                    })?
                };
                let registered = register(&client, &session.delegation_header).await?;
                let path = format!("tc1071/{import}/{v}");
                let value = format!("sdk-session-{import}-v{v}");
                let (status, body) =
                    invoke(&client, &session, &path, "tinycloud.kv/put", &value).await?;
                println!(
                    "{import} v={v}: SDK CID={} node CID={} invoke={status} {body}",
                    session.delegation_cid,
                    registered["cid"].as_str().unwrap_or_default()
                );
                if status != Status::Ok {
                    failures.push(format!("{import} v={v}: invoke={status} {body}"));
                    continue;
                }
                ensure!(
                    registered["cid"] == session.delegation_cid.to_string(),
                    "{import} v={v}: registered CID must match SDK proof"
                );
                let (status, body) =
                    invoke(&client, &session, &path, "tinycloud.kv/get", "").await?;
                println!("{import} v={v}: get={status} value={body:?}");
                ensure!(
                    status == Status::Ok && body == value,
                    "{import} v={v}: get={status} {body}"
                );
            }
        }
    }
    ensure!(
        failures.is_empty(),
        "SDK invocation failures:\n{}",
        failures.join("\n")
    );
    Ok(())
}

#[test]
fn wallet_import_and_rust_setup_reject_noncanonical_signatures() -> Result<()> {
    let (wallet, address, space) = wallet()?;
    let prepared = prepared(&address, &space)?;
    let bytes = sign(&wallet, &prepared.siwe)?;
    let signature = k256::ecdsa::Signature::from_slice(&bytes[..64])?;
    let (r, s) = signature.split_scalars();
    let high_s = k256::ecdsa::Signature::from_scalars(r.to_bytes(), (-s).to_bytes())?;
    let mut high_s_bytes = bytes;
    high_s_bytes[..64].copy_from_slice(&high_s.to_bytes());
    high_s_bytes[64] ^= 1;
    let mut cases = vec![("high-s".to_owned(), high_s_bytes.to_vec())];
    for v in [2, 26, 29, 35, 255] {
        let mut invalid = bytes;
        invalid[64] = v;
        cases.push((format!("invalid-v-{v}"), invalid.to_vec()));
    }
    for range in [0..32, 32..64] {
        for value in [0, 255] {
            let mut invalid = bytes;
            invalid[range.clone()].fill(value);
            cases.push((
                format!("invalid-scalar-{}-{value}", range.start),
                invalid.to_vec(),
            ));
        }
    }
    cases.push(("short".into(), bytes[..64].to_vec()));
    cases.push(("long".into(), [bytes.as_slice(), &[0]].concat()));
    for (label, bytes) in cases {
        for prefix in ["", "0x"] {
            let signed = json_signed(&prepared, &format!("{prefix}{}", hex::encode(&bytes)))?;
            ensure!(
                serde_json::from_value::<SignedSession>(signed).is_err(),
                "SDK accepted {label}"
            );
            let host = json!({"siwe": prepared.siwe.to_string(), "signature": format!("{prefix}{}", hex::encode(&bytes))});
            ensure!(
                serde_json::from_value::<SignedMessage>(host).is_err(),
                "host SDK accepted {label}"
            );
        }
        if let Ok(bytes) = <[u8; 65]>::try_from(bytes) {
            ensure!(
                matches!(
                    complete_session_setup(SignedSession {
                        session: prepared.clone(),
                        signature: Signature::from(bytes),
                    }),
                    Err(tinycloud_sdk_wasm::session::Error::InvalidSIWESignature(_))
                ),
                "Rust setup accepted {label}"
            );
        }
    }
    for signature in ["0xnothex", "0", "0x"] {
        ensure!(
            serde_json::from_value::<SignedSession>(json_signed(&prepared, signature)?).is_err(),
            "accepted malformed hex {signature}"
        );
    }
    Ok(())
}

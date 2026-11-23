//! The registry outage cache through the production HTTP application: what a
//! node admits while the signed registry is unreachable, and when it stops.
//! All identities and payloads are disposable TEST fixtures. Details: TC-2481.
use anyhow::Result;
use k256::ecdsa::SigningKey;
use parking_lot::RwLock;
use rocket::{
    figment::providers::Serialized,
    http::{Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::{collections::HashMap, future::IntoFuture, sync::Arc, time::Duration};
use tinycloud_auth::{
    authorization::HeaderEncode,
    cacaos::{
        siwe::{encode_eip55, Message, Version},
        siwe_cacao::{Header as CacaoHeader, Signature, SiweCacao},
    },
    resource::SpaceId,
};
use tinycloud_core::sea_orm::{ConnectionTrait, DbBackend, Statement};
use tinycloud_sdk_wasm::session::{
    complete_session_setup, prepare_session, Session, SessionConfig, SignedSession,
};

const WINDOW: u64 = 300;

fn sign(key: &SigningKey, message: &Message) -> Result<Signature> {
    let (signature, recovery) = key.sign_prehash_recoverable(&message.eip191_hash()?)?;
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
    bytes[64] = u8::from(recovery) + 27;
    Ok(bytes.into())
}

fn authorization(headers: impl serde::Serialize) -> String {
    serde_json::to_value(headers).unwrap()["Authorization"]
        .as_str()
        .unwrap()
        .to_owned()
}

struct Registry {
    origin: String,
    body: Arc<RwLock<(axum::http::StatusCode, String)>>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Registry {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Registry {
    async fn new() -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let origin = format!("http://{}", listener.local_addr()?);
        let body = Arc::new(RwLock::new((
            axum::http::StatusCode::NOT_FOUND,
            "{\"error\":\"location record not found\"}".into(),
        )));
        let shared = body.clone();
        let app = axum::Router::new().fallback(move || {
            let shared = shared.clone();
            async move {
                let (status, body) = shared.read().clone();
                (status, [(axum::http::header::CONNECTION, "close")], body)
            }
        });
        let task = tokio::spawn(async move {
            axum::serve(listener, app).into_future().await.unwrap();
        });
        Ok(Self { origin, body, task })
    }

    fn set(&self, status: axum::http::StatusCode, body: String) {
        *self.body.write() = (status, body);
    }

    fn down(&self, status: axum::http::StatusCode) {
        self.set(status, String::new());
    }

    /// Stop answering at all: the node's requests fail to connect.
    async fn stop(&mut self) {
        self.task.abort();
        let _ = (&mut self.task).await;
    }
}

struct Node {
    client: Client,
    _dir: tempfile::TempDir,
    did: String,
}

impl Node {
    async fn new(registry: Option<&Registry>, seed: u8, cache_seconds: u64) -> Result<Self> {
        let dir = tempfile::tempdir()?;
        let mut config = tinycloud::config::Config::default();
        config.storage.datadir = dir.path().into();
        config.storage.database = Some("sqlite::memory:".into());
        config.keys = serde_json::from_value(
            json!({"type":"static", "secret":base64::encode_config([seed; 32], base64::URL_SAFE_NO_PAD)}),
        )?;
        let mut value = serde_json::to_value(config)?;
        if let Some(registry) = registry {
            value["spaces"]["registry_v2"] = json!(registry.origin);
        }
        value["spaces"]["registry_cache_max_age_seconds"] = json!(cache_seconds);
        let config: tinycloud::config::Config = serde_json::from_value(value)?;
        let figment = rocket::Config::figment().merge(Serialized::defaults(&config));
        let client =
            Client::tracked(tinycloud::app_with_control(&figment, &config, None).await?).await?;
        let info: Value = client
            .get("/info")
            .dispatch()
            .await
            .into_json()
            .await
            .unwrap();
        let did = info["nodeId"].as_str().unwrap().to_owned();
        Ok(Self {
            client,
            _dir: dir,
            did,
        })
    }

    /// Move the registry admission's clock: time since the last confirmation.
    fn advance(&self, seconds: u64) {
        self.client
            .rocket()
            .state::<tinycloud::TinyCloud>()
            .unwrap()
            .registry_admission()
            .unwrap()
            .advance_clock(Duration::from_secs(seconds));
    }

    async fn delegate(&self, session: &Session) -> (Status, Value) {
        let response = self
            .client
            .post("/delegate")
            .header(Header::new(
                "Authorization",
                authorization(&session.delegation_header),
            ))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&body).unwrap_or(Value::String(body)),
        )
    }

    async fn writes(&self) -> Result<i64> {
        let db = self
            .client
            .rocket()
            .state::<tinycloud::TinyCloud>()
            .unwrap();
        let row = db
            .connection()
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT count(*) AS n FROM kv_write".to_owned(),
            ))
            .await?
            .unwrap();
        Ok(row.try_get("", "n")?)
    }

    async fn invoke(&self, session: &Session, action: &str, body: &str) -> Result<Status> {
        let header = session
            .invoke(
                [(
                    "kv".parse()?,
                    "item".parse()?,
                    None,
                    None,
                    [action.parse()?],
                )],
                None,
            )?
            .encode()?;
        let response = self
            .client
            .post("/invoke")
            .header(Header::new("Authorization", header))
            .body(body)
            .dispatch()
            .await;
        Ok(response.status())
    }

    async fn get(&self, session: &Session) -> Result<Status> {
        self.invoke(session, "tinycloud.kv/get", "").await
    }

    async fn put(&self, session: &Session) -> Result<Status> {
        self.invoke(session, "tinycloud.kv/put", "TEST ciphertext")
            .await
    }
}

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
    did: String,
    space: SpaceId,
}

impl Wallet {
    fn new() -> Result<Self> {
        let key = SigningKey::from_bytes(&[41; 32].into())?;
        let public = key.verifying_key().to_encoded_point(false);
        let address = Keccak256::digest(&public.as_bytes()[1..])[12..].try_into()?;
        let did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        let space = format!("tinycloud:{}:outage-cache-test", &did[4..]).parse()?;
        Ok(Self {
            key,
            address,
            did,
            space,
        })
    }

    fn session(&self) -> Result<Session> {
        let now = time::OffsetDateTime::now_utc();
        let prepared = prepare_session(SessionConfig {
            abilities: HashMap::from([(
                "kv".parse()?,
                HashMap::from([(
                    "".parse()?,
                    vec!["tinycloud.kv/get".parse()?, "tinycloud.kv/put".parse()?],
                )]),
            )]),
            space_abilities: None,
            raw_abilities: HashMap::new(),
            address: self.address,
            chain_id: 1,
            domain: "localhost".parse()?,
            issued_at: now.into(),
            space_id: self.space.clone(),
            additional_spaces: None,
            not_before: None,
            expiration_time: (now + time::Duration::hours(1)).into(),
            parents: None,
            jwk: None,
            delegate_uri: None,
            nonce: None,
            invocation_ttl_secs: None,
        })?;
        let signature = sign(&self.key, &prepared.siwe)?;
        Ok(complete_session_setup(SignedSession {
            session: prepared,
            signature,
        })?)
    }

    /// Publish the owner-signed record listing `node` in `mode`, or not at all.
    fn publish(
        &self,
        registry: &Registry,
        node: &Node,
        mode: Option<&str>,
        sequence: u64,
    ) -> Result<()> {
        // Independent serializer uses the frozen TS property order, not the Rust verifier.
        let entries = json!([{"did":node.did,"url":"https://box.invalid"}]);
        let members: Vec<_> = mode
            .into_iter()
            .map(|mode| json!({"did":node.did,"mode":mode}))
            .collect();
        let space_bytes = format!(
            "[{{\"space\":{},\"nodes\":{}}}]",
            serde_json::to_string(&self.space.to_string())?,
            serde_json::to_string(&members)?
        );
        let payload = format!(
            "{{\"version\":2,\"subject\":{},\"nodes\":{},\"spaces\":{},\"encryptionNode\":null,\"updated_at\":\"2026-11-03T20:00:00.000Z\",\"sequence\":{}}}",
            serde_json::to_string(&self.did)?,
            serde_json::to_string(&entries)?,
            space_bytes,
            sequence
        );
        let hash = Keccak256::digest(
            format!("\x19Ethereum Signed Message:\n{}{}", payload.len(), payload).as_bytes(),
        );
        let (signature, recovery) = self.key.sign_prehash_recoverable(&hash)?;
        let mut signed = signature.to_bytes().to_vec();
        signed.push(u8::from(recovery) + 27);
        let mut record: Value = serde_json::from_str(&payload)?;
        record["signature"] = json!(format!("0x{}", hex::encode(signed)));
        registry.set(
            axum::http::StatusCode::OK,
            json!({"record":record}).to_string(),
        );
        Ok(())
    }

    /// Revoke a delegation this wallet issued, through the node's `/revoke`.
    async fn revoke(&self, node: &Node, cid: &str) -> Result<Status> {
        let iso = |t: time::OffsetDateTime| {
            t.format(&time::format_description::well_known::Rfc3339)
                .unwrap()
        };
        let now = time::OffsetDateTime::now_utc();
        let message = Message {
            scheme: Some("https".parse()?),
            domain: "localhost".parse()?,
            address: self.address,
            statement: None,
            uri: format!("ucan:{cid}").parse()?,
            version: Version::V1,
            chain_id: 1,
            nonce: uuid::Uuid::new_v4().simple().to_string(),
            issued_at: iso(now).parse()?,
            expiration_time: Some(iso(now + time::Duration::minutes(5)).parse()?),
            not_before: None,
            request_id: None,
            resources: vec![],
        };
        let signature = sign(&self.key, &message)?;
        let revoke = tinycloud_auth::authorization::TinyCloudRevocation::Cacao(Box::new(
            SiweCacao::new(message.into(), signature, CacaoHeader),
        ))
        .encode()?;
        Ok(node
            .client
            .post("/revoke")
            .header(Header::new("Authorization", revoke))
            .dispatch()
            .await
            .status())
    }
}

/// A cache-enabled node with an activated read-write session whose last write
/// confirmed the current record; returns the delegation CID too.
async fn hosted(registry: &Registry, seed: u8) -> Result<(Node, Wallet, Session, String)> {
    let node = Node::new(Some(registry), seed, WINDOW).await?;
    let wallet = Wallet::new()?;
    wallet.publish(registry, &node, Some("read-write"), 1)?;
    let session = wallet.session()?;
    let (status, body) = node.delegate(&session).await;
    assert_eq!(status, Status::Ok, "{body}");
    let cid = body["cid"].as_str().expect("delegation cid").to_owned();
    assert_eq!(node.put(&session).await?, Status::Ok);
    Ok((node, wallet, session, cid))
}

#[tokio::test]
async fn outage_keeps_reads_and_writes_until_the_window_then_fails_closed() -> Result<()> {
    let registry = Registry::new().await?;
    let (node, _wallet, session, _) = hosted(&registry, 61).await?;
    for status in [
        axum::http::StatusCode::BAD_GATEWAY,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::http::StatusCode::GATEWAY_TIMEOUT,
    ] {
        registry.down(status);
        assert_eq!(node.get(&session).await?, Status::Ok, "{status}");
        assert_eq!(node.put(&session).await?, Status::Ok, "{status}");
    }
    // Requests served from the cache never extend it.
    node.advance(WINDOW - 1);
    assert_eq!(node.put(&session).await?, Status::Ok);
    node.advance(1);
    let before = node.writes().await?;
    assert_eq!(node.get(&session).await?, Status::ServiceUnavailable);
    assert_eq!(node.put(&session).await?, Status::ServiceUnavailable);
    assert_eq!(node.writes().await?, before);
    Ok(())
}

#[tokio::test]
async fn cache_expiry_mid_outage_fails_closed_without_a_registry() -> Result<()> {
    let mut registry = Registry::new().await?;
    let (node, _wallet, session, _) = hosted(&registry, 62).await?;
    registry.stop().await;
    node.advance(200);
    assert_eq!(node.get(&session).await?, Status::Ok);
    assert_eq!(node.put(&session).await?, Status::Ok);
    node.advance(99);
    assert_eq!(node.put(&session).await?, Status::Ok);
    node.advance(1);
    let before = node.writes().await?;
    assert_eq!(node.put(&session).await?, Status::ServiceUnavailable);
    assert_eq!(node.get(&session).await?, Status::ServiceUnavailable);
    assert_eq!(node.writes().await?, before);
    Ok(())
}

#[tokio::test]
async fn revocation_before_outage_is_never_served_from_cache() -> Result<()> {
    // Membership removed: the newer record is what the cache now holds, so
    // the outage cannot bring the old one back.
    let registry = Registry::new().await?;
    let (node, wallet, session, _) = hosted(&registry, 63).await?;
    wallet.publish(&registry, &node, None, 2)?;
    assert_eq!(node.get(&session).await?, Status::Forbidden);
    registry.down(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let before = node.writes().await?;
    assert_eq!(node.get(&session).await?, Status::Forbidden);
    assert_eq!(node.put(&session).await?, Status::Forbidden);
    assert_eq!(node.writes().await?, before);

    // Owner record withdrawn: the refusal discards the cached record.
    let registry = Registry::new().await?;
    let (node, _wallet, session, _) = hosted(&registry, 60).await?;
    registry.set(
        axum::http::StatusCode::NOT_FOUND,
        "{\"error\":\"location record not found\"}".into(),
    );
    assert_eq!(node.get(&session).await?, Status::ServiceUnavailable);
    registry.down(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let before = node.writes().await?;
    assert_eq!(node.get(&session).await?, Status::ServiceUnavailable);
    assert_eq!(node.put(&session).await?, Status::ServiceUnavailable);
    assert_eq!(node.writes().await?, before);

    // Downgraded to read-only: the cached record admits reads, never writes.
    let registry = Registry::new().await?;
    let (node, wallet, session, _) = hosted(&registry, 64).await?;
    wallet.publish(&registry, &node, Some("read-only"), 2)?;
    assert_eq!(node.get(&session).await?, Status::Ok);
    registry.down(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let before = node.writes().await?;
    assert_eq!(node.get(&session).await?, Status::Ok);
    assert_eq!(node.put(&session).await?, Status::Forbidden);
    assert_eq!(node.writes().await?, before);

    // An invalid answer is a refusal too, not an outage.
    let registry = Registry::new().await?;
    let (node, _wallet, session, _) = hosted(&registry, 65).await?;
    registry.set(axum::http::StatusCode::OK, "{}".into());
    assert_eq!(node.get(&session).await?, Status::ServiceUnavailable);
    registry.down(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(node.get(&session).await?, Status::ServiceUnavailable);
    Ok(())
}

#[tokio::test]
async fn revocation_during_outage_is_enforced_while_the_cache_admits() -> Result<()> {
    let registry = Registry::new().await?;
    let (node, wallet, session, cid) = hosted(&registry, 66).await?;
    registry.down(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(node.put(&session).await?, Status::Ok);
    // The owner revokes the session's delegation on this node mid-outage;
    // revocation needs no registry.
    assert_eq!(wallet.revoke(&node, &cid).await?, Status::Ok);
    let before = node.writes().await?;
    let put = node.put(&session).await?;
    assert!(put.class().is_client_error(), "{put}");
    let get = node.get(&session).await?;
    assert!(get.class().is_client_error(), "{get}");
    assert_eq!(node.writes().await?, before);

    // Membership removed while the registry was down: the first answer after
    // it returns refuses at once, and a second outage serves only that answer.
    let registry = Registry::new().await?;
    let (node, wallet, session, _) = hosted(&registry, 67).await?;
    registry.down(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(node.put(&session).await?, Status::Ok);
    wallet.publish(&registry, &node, None, 2)?;
    let before = node.writes().await?;
    assert_eq!(node.put(&session).await?, Status::Forbidden);
    registry.down(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(node.put(&session).await?, Status::Forbidden);
    assert_eq!(node.get(&session).await?, Status::Forbidden);
    assert_eq!(node.writes().await?, before);
    Ok(())
}

#[tokio::test]
async fn activation_during_outage_needs_the_live_registry() -> Result<()> {
    let registry = Registry::new().await?;
    let (node, wallet, _session, _) = hosted(&registry, 68).await?;
    registry.down(axum::http::StatusCode::SERVICE_UNAVAILABLE);
    let (status, body) = node.delegate(&wallet.session()?).await;
    assert_eq!(status, Status::ServiceUnavailable, "{body}");
    Ok(())
}

#[tokio::test]
async fn cache_window_is_bounded_and_requires_a_registry() -> Result<()> {
    let registry = Registry::new().await?;
    assert!(Node::new(Some(&registry), 69, WINDOW + 1).await.is_err());
    assert!(Node::new(None, 69, 60).await.is_err());
    Ok(())
}

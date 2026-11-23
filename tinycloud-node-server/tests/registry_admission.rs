//! Signed registry hosting admission through the production HTTP application.
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
use std::{collections::HashMap, future::IntoFuture, sync::Arc};
use tinycloud_auth::{
    cacaos::siwe::{encode_eip55, Message},
    resource::SpaceId,
};
use tinycloud_core::sea_orm::{ConnectionTrait, DbBackend, Statement};
use tinycloud_sdk_wasm::{
    host::{generate_host_siwe_message, siwe_to_delegation_headers, HostConfig, SignedMessage},
    session::{complete_session_setup, prepare_session, Session, SessionConfig, SignedSession},
};

fn sign(
    key: &SigningKey,
    message: &Message,
) -> Result<tinycloud_auth::cacaos::siwe_cacao::Signature> {
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
}
struct Node {
    client: Client,
    _dir: tempfile::TempDir,
    did: String,
}
impl Node {
    async fn new(registry: Option<&Registry>, seed: u8) -> Result<Self> {
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
    async fn delegate(&self, header: &str) -> (Status, Value) {
        let response = self
            .client
            .post("/delegate")
            .header(Header::new("Authorization", header.to_owned()))
            .dispatch()
            .await;
        let status = response.status();
        let body = response.into_string().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&body).unwrap_or(Value::String(body)),
        )
    }
    async fn count(&self, table: &str) -> Result<i64> {
        let db = self
            .client
            .rocket()
            .state::<tinycloud::TinyCloud>()
            .unwrap();
        let row = db
            .connection()
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                format!("SELECT count(*) AS n FROM {table}"),
            ))
            .await?
            .unwrap();
        Ok(row.try_get("", "n")?)
    }
    async fn invoke(
        &self,
        session: &Session,
        action: &str,
        body: &str,
    ) -> Result<(Status, String)> {
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
        let status = response.status();
        Ok((status, response.into_string().await.unwrap_or_default()))
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
        let key = SigningKey::from_bytes(&[37; 32].into())?;
        let public = key.verifying_key().to_encoded_point(false);
        let address = Keccak256::digest(&public.as_bytes()[1..])[12..].try_into()?;
        let did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        let space = format!("tinycloud:{}:registry-test", &did[4..]).parse()?;
        Ok(Self {
            key,
            address,
            did,
            space,
        })
    }
    async fn host(&self, node: &Node) -> Result<String> {
        let peer = node
            .client
            .get(format!("/peer/generate/{}", self.space))
            .dispatch()
            .await
            .into_string()
            .await
            .unwrap();
        let siwe = generate_host_siwe_message(HostConfig {
            address: self.address,
            chain_id: 1,
            domain: "localhost".parse()?,
            issued_at: time::OffsetDateTime::now_utc().into(),
            space_id: self.space.clone(),
            peer_id: peer,
        })?;
        let signature = sign(&self.key, &siwe)?;
        Ok(authorization(siwe_to_delegation_headers(SignedMessage {
            siwe,
            signature,
        })))
    }
    fn session(&self, mixed: bool) -> Result<Session> {
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
            raw_abilities: if mixed {
                HashMap::from([(
                    format!("urn:tinycloud:encryption:{}:default", self.did),
                    vec!["tinycloud.encryption/decrypt".parse()?],
                )])
            } else {
                HashMap::new()
            },
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
    fn publish(
        &self,
        registry: &Registry,
        nodes: &[&Node],
        member: Option<(&Node, &str)>,
        encryption: Option<&Node>,
        sequence: u64,
    ) -> Result<()> {
        // Independent serializer uses the frozen TS property order, not the Rust verifier.
        let mut entries: Vec<_> = nodes.iter().map(|node| json!({"did":node.did,"url":format!("https://{}.invalid", if node.did == nodes[0].did { "box" } else { "encryption" })})).collect();
        entries.sort_by_key(|node| node["did"].as_str().unwrap().to_owned());
        let members: Vec<_> = member
            .into_iter()
            .map(|(node, mode)| json!({"did":node.did,"mode":mode}))
            .collect();
        let node_bytes = serde_json::to_string(&entries)?;
        let space_bytes = format!(
            "[{{\"space\":{},\"nodes\":{}}}]",
            serde_json::to_string(&self.space.to_string())?,
            serde_json::to_string(&members)?
        );
        let payload = format!("{{\"version\":2,\"subject\":{},\"nodes\":{},\"spaces\":{},\"encryptionNode\":{},\"updated_at\":\"2026-11-03T20:00:00.000Z\",\"sequence\":{}}}", serde_json::to_string(&self.did)?, node_bytes, space_bytes, serde_json::to_string(&encryption.map(|node| &node.did))?, sequence);
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
}

#[tokio::test]
async fn configured_registry_refuses_absent_owner_before_hosting() -> Result<()> {
    let registry = Registry::new().await?;
    let node = Node::new(Some(&registry), 43).await?;
    let wallet = Wallet::new()?;
    let (status, body) = node.delegate(&wallet.host(&node).await?).await;
    assert_eq!(status, Status::Forbidden, "{body}");
    for table in [
        "space",
        "delegation",
        "epoch",
        "event_order",
        "kv_write",
        "kv_blob_generation",
        "kv_orphan_candidate",
    ] {
        assert_eq!(node.count(table).await?, 0, "{table}");
    }
    Ok(())
}

#[tokio::test]
async fn registry_membership_admits_session_and_enforces_current_mode() -> Result<()> {
    let registry = Registry::new().await?;
    let node = Node::new(Some(&registry), 44).await?;
    let wallet = Wallet::new()?;
    wallet.publish(&registry, &[&node], Some((&node, "read-write")), None, 1)?;
    let session = wallet.session(false)?;
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/put", "unregistered")
            .await?
            .0,
        Status::Unauthorized
    );
    assert_eq!(node.count("kv_write").await?, 0);
    let (status, body) = node
        .delegate(&authorization(&session.delegation_header))
        .await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["activated"], json!([wallet.space.to_string()]));
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/put", "TEST ciphertext")
            .await?
            .0,
        Status::Ok
    );
    wallet.publish(&registry, &[&node], Some((&node, "read-only")), None, 2)?;
    let (status, data) = node.invoke(&session, "tinycloud.kv/get", "").await?;
    assert_eq!(status, Status::Ok, "{data}");
    assert_eq!(data, "TEST ciphertext");
    let before = node.count("kv_write").await?;
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/put", "other").await?.0,
        Status::Forbidden
    );
    assert_eq!(node.count("kv_write").await?, before);
    wallet.publish(&registry, &[&node], None, None, 3)?;
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/get", "").await?.0,
        Status::Forbidden
    );
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/put", "other").await?.0,
        Status::Forbidden
    );
    assert_eq!(node.count("kv_write").await?, before);
    assert_eq!(
        node.delegate(&wallet.host(&node).await?).await.0,
        Status::Forbidden
    );
    wallet.publish(&registry, &[&node], Some((&node, "read-write")), None, 1)?;
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/get", "").await?.0,
        Status::ServiceUnavailable
    );
    Ok(())
}

#[tokio::test]
async fn mixed_grant_activates_only_data_member_and_encryption_grant_keeps_cid() -> Result<()> {
    let registry = Registry::new().await?;
    let data = Node::new(Some(&registry), 45).await?;
    let encryption = Node::new(Some(&registry), 46).await?;
    let wallet = Wallet::new()?;
    wallet.publish(
        &registry,
        &[&data, &encryption],
        Some((&data, "read-write")),
        Some(&encryption),
        1,
    )?;
    let session = wallet.session(true)?;
    let header = authorization(&session.delegation_header);
    let (status, body) = data.delegate(&header).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["activated"], json!([wallet.space.to_string()]));
    let (status, body) = encryption.delegate(&header).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(
        body["cid"],
        serde_json::to_value(session.delegation_cid.to_string())?
    );
    assert_eq!(body["activated"], json!([]));
    assert_eq!(body["skipped"], json!([wallet.space.to_string()]));
    assert_eq!(encryption.count("delegation").await?, 1);
    for table in [
        "space",
        "epoch",
        "event_order",
        "kv_write",
        "kv_blob_generation",
        "kv_orphan_candidate",
    ] {
        assert_eq!(encryption.count(table).await?, 0, "{table}");
    }
    assert_eq!(
        encryption
            .invoke(&session, "tinycloud.kv/put", "TEST")
            .await?
            .0,
        Status::Forbidden
    );
    assert_eq!(
        data.invoke(&session, "tinycloud.kv/put", "TEST").await?.0,
        Status::Ok
    );
    Ok(())
}

#[tokio::test]
async fn retained_mixed_grant_activates_new_membership_once() -> Result<()> {
    let registry = Registry::new().await?;
    let node = Node::new(Some(&registry), 52).await?;
    let wallet = Wallet::new()?;
    wallet.publish(&registry, &[&node], None, Some(&node), 1)?;
    let session = wallet.session(true)?;
    let header = authorization(&session.delegation_header);
    let cid = json!(session.delegation_cid.to_string());
    let space = json!([wallet.space.to_string()]);

    let (status, body) = node.delegate(&header).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["cid"], cid);
    assert_eq!(body["activated"], json!([]));
    assert_eq!(body["skipped"], space);
    assert_eq!(node.count("space").await?, 0);
    assert_eq!(node.count("epoch").await?, 0);
    assert_eq!(node.count("event_order").await?, 0);

    wallet.publish(
        &registry,
        &[&node],
        Some((&node, "read-write")),
        Some(&node),
        2,
    )?;
    let (status, body) = node.delegate(&header).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["cid"], cid);
    assert_eq!(body["activated"], space);
    assert_eq!(body["skipped"], json!([]));
    assert_eq!(node.count("space").await?, 1);
    assert_eq!(node.count("delegation").await?, 1);
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/put", "TEST retained grant")
            .await?
            .0,
        Status::Ok
    );
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/get", "").await?,
        (Status::Ok, "TEST retained grant".into())
    );
    let tables = ["epoch", "epoch_order", "event_order", "kv_write"];
    let mut counts = Vec::new();
    for table in tables {
        counts.push(node.count(table).await?);
    }

    let (status, body) = node.delegate(&header).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["cid"], cid);
    assert_eq!(body["activated"], json!([]));
    assert_eq!(body["skipped"], json!([]));
    assert_eq!(node.count("delegation").await?, 1);
    for (table, expected) in tables.into_iter().zip(&counts) {
        assert_eq!(node.count(table).await?, *expected, "{table}");
    }

    wallet.publish(&registry, &[&node], None, Some(&node), 3)?;
    let (status, body) = node.delegate(&header).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(body["cid"], cid);
    assert_eq!(body["activated"], json!([]));
    assert_eq!(body["skipped"], space);
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/put", "excluded")
            .await?
            .0,
        Status::Forbidden
    );
    for (table, expected) in tables.into_iter().zip(&counts) {
        assert_eq!(node.count(table).await?, *expected, "{table}");
    }
    Ok(())
}

#[tokio::test]
async fn unconfigured_node_retains_host_onboarding() -> Result<()> {
    let node = Node::new(None, 47).await?;
    let wallet = Wallet::new()?;
    let (status, body) = node.delegate(&wallet.host(&node).await?).await;
    assert_eq!(status, Status::Ok, "{body}");
    assert_eq!(node.count("space").await?, 1);
    Ok(())
}

#[tokio::test]
async fn prior_host_grant_cannot_override_current_registry() -> Result<()> {
    let registry = Registry::new().await?;
    let node = Node::new(Some(&registry), 48).await?;
    let wallet = Wallet::new()?;
    wallet.publish(&registry, &[&node], Some((&node, "read-write")), None, 1)?;
    let host = wallet.host(&node).await?;
    assert_eq!(node.delegate(&host).await.0, Status::Ok);
    let session = wallet.session(false)?;
    assert_eq!(
        node.delegate(&authorization(&session.delegation_header))
            .await
            .0,
        Status::Ok
    );
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/put", "TEST").await?.0,
        Status::Ok
    );
    let before = node.count("kv_write").await?;
    wallet.publish(&registry, &[&node], None, None, 2)?;
    assert_eq!(node.delegate(&host).await.0, Status::Forbidden);
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/get", "").await?.0,
        Status::Forbidden
    );
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/put", "other").await?.0,
        Status::Forbidden
    );
    assert_eq!(node.count("kv_write").await?, before);
    Ok(())
}

#[tokio::test]
async fn unavailable_or_invalid_current_record_never_authorizes_data() -> Result<()> {
    let mut registry = Registry::new().await?;
    let node = Node::new(Some(&registry), 49).await?;
    let wallet = Wallet::new()?;
    wallet.publish(&registry, &[&node], Some((&node, "read-write")), None, 1)?;
    let session = wallet.session(false)?;
    assert_eq!(
        node.delegate(&authorization(&session.delegation_header))
            .await
            .0,
        Status::Ok
    );
    let before = node.count("kv_write").await?;
    let current = registry.body.read().1.clone();
    let mut tampered: Value = serde_json::from_str(&current)?;
    tampered["record"]["spaces"][0]["nodes"][0]["mode"] = json!("read-only");
    for (status, response) in [
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, String::new()),
        (axum::http::StatusCode::OK, "{}".into()),
        (axum::http::StatusCode::OK, tampered.to_string()),
        (axum::http::StatusCode::OK, " ".repeat(65537)),
        (
            axum::http::StatusCode::NOT_FOUND,
            "{\"error\":\"location record not found\"}".into(),
        ),
    ] {
        registry.set(status, response);
        assert_eq!(
            node.invoke(&session, "tinycloud.kv/put", "TEST").await?.0,
            Status::ServiceUnavailable
        );
        assert_eq!(node.count("kv_write").await?, before);
    }
    registry.set(axum::http::StatusCode::OK, current);
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/put", "TEST").await?.0,
        Status::Ok
    );
    registry.task.abort();
    let _ = (&mut registry.task).await;
    assert_eq!(
        node.invoke(&session, "tinycloud.kv/get", "").await?.0,
        Status::ServiceUnavailable
    );
    Ok(())
}

#[tokio::test]
async fn mixed_grant_decrypts_only_on_encryption_destination_without_data_replica() -> Result<()> {
    use tinycloud_auth::{
        ssi::{claims::jwt::NumericDate, ucan::Payload},
        ucan_capabilities_object::{Ability, Capabilities},
    };
    use tinycloud_core::encryption_network::{
        backend::wrap_to_public_key, canonical::canonical_hash, protocol::DECRYPT_REQUEST_TYPE,
        CreateNetworkRequest, EncryptionService, Threshold,
    };
    use x25519_dalek::{PublicKey, StaticSecret};
    let registry = Registry::new().await?;
    let data = Node::new(Some(&registry), 50).await?;
    let encryption = Node::new(Some(&registry), 51).await?;
    let wallet = Wallet::new()?;
    wallet.publish(
        &registry,
        &[&data, &encryption],
        Some((&data, "read-write")),
        Some(&encryption),
        1,
    )?;
    let session = wallet.session(true)?;
    assert_eq!(
        encryption
            .delegate(&authorization(&session.delegation_header))
            .await
            .0,
        Status::Ok
    );
    let service = encryption
        .client
        .rocket()
        .state::<EncryptionService>()
        .unwrap();
    let descriptor = service
        .create_one_of_one_network(CreateNetworkRequest {
            name: "default".into(),
            owner_did: wallet.did.clone(),
            threshold: Threshold::one_of_one(),
        })
        .await?;
    let network = descriptor.network_id.to_string();
    for (node, expected) in [(&data, Status::Forbidden), (&encryption, Status::Ok)] {
        let response = node
            .client
            .get(format!("/encryption/networks/{network}"))
            .dispatch()
            .await;
        assert_eq!(response.status(), expected);
    }
    let expected = vec![0xcd; 32];
    let wrapped = base64::encode(wrap_to_public_key(
        &descriptor.public_encryption_key,
        &expected,
    )?);
    let receiver = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let public = base64::encode(PublicKey::from(&receiver).to_bytes());
    let wrapped_hash = canonical_hash(&json!(wrapped));
    let receiver_hash = canonical_hash(&json!(public));
    let body = json!({
        "type":DECRYPT_REQUEST_TYPE,"targetNode":encryption.did,"networkId":network,
        "alg":descriptor.alg,"keyVersion":1,"encryptedSymmetricKey":wrapped,
        "encryptedSymmetricKeyHash":wrapped_hash,"receiverPublicKey":public,
        "receiverPublicKeyHash":receiver_hash
    });
    let facts = json!({
        "type":DECRYPT_REQUEST_TYPE,"targetNode":encryption.did,"networkId":network,
        "alg":descriptor.alg,"keyVersion":1,"bodyHash":canonical_hash(&body),
        "encryptedSymmetricKeyHash":wrapped_hash,"receiverPublicKeyHash":receiver_hash
    });
    let mut caps = Capabilities::<Value>::new();
    caps.with_action(
        network.parse()?,
        "tinycloud.encryption/decrypt".parse::<Ability>()?,
        [],
    );
    let header = Payload {
        issuer: session.verification_method.parse()?,
        audience: encryption.did.parse()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(
            (time::OffsetDateTime::now_utc() + time::Duration::minutes(1)).unix_timestamp() as f64,
        )?,
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        facts: Some(vec![facts]),
        proof: vec![session.delegation_cid],
        attenuation: caps,
    }
    .sign(
        session.jwk.get_algorithm().unwrap_or_default(),
        &session.jwk,
    )?
    .encode()?;
    let response = encryption
        .client
        .post(format!("/encryption/networks/{network}/decrypt"))
        .header(rocket::http::ContentType::JSON)
        .header(Header::new("Authorization", header.clone()))
        .body(body.to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Ok);
    let response: Value = response.into_json().await.unwrap();
    let sealed = base64::decode(response["wrappedKey"].as_str().unwrap())?;
    let peer = PublicKey::from(<[u8; 32]>::try_from(&sealed[..32])?);
    let shared = receiver.diffie_hellman(&peer);
    assert_eq!(
        tinycloud_core::ColumnEncryption::new(*shared.as_bytes()).decrypt_legacy(&sealed[32..])?,
        expected
    );
    assert_eq!(encryption.count("space").await?, 0);
    assert_eq!(encryption.count("kv_write").await?, 0);
    registry.set(axum::http::StatusCode::SERVICE_UNAVAILABLE, "{}".into());
    let response = encryption
        .client
        .post(format!("/encryption/networks/{network}/decrypt"))
        .header(rocket::http::ContentType::JSON)
        .header(Header::new("Authorization", header))
        .body(body.to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::ServiceUnavailable);
    assert_eq!(encryption.count("space").await?, 0);
    assert_eq!(encryption.count("kv_write").await?, 0);
    Ok(())
}

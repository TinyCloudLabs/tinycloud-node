//! Real HTTP handlers and databases: renewal validity must reach every entrypoint.
mod common;
#[allow(dead_code)]
#[path = "support/owner_lease.rs"]
mod setup;

use anyhow::{ensure, Context, Result};
use rocket::{
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::{collections::BTreeMap, time::Duration};
use tinycloud_auth::{
    authorization::{
        make_invocation_from_uris, HeaderEncode, InvocationOptions, TinyCloudDelegation,
        TinyCloudInvocation,
    },
    cacaos::{
        siwe::{Message, Version},
        siwe_cacao::{Header as CacaoHeader, Signature, SiweCacao},
    },
    resolver::DID_METHODS,
    siwe_recap::Capability,
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    encryption_network::{
        backend::wrap_to_public_key,
        canonical::canonical_hash,
        protocol::{DECRYPT_ACTION, DECRYPT_REQUEST_TYPE},
        types::ALG_X25519_AES256GCM,
        CreateNetworkRequest, EncryptionService, Threshold,
    },
    events::Invocation,
    hash::{hash, Hash},
    keys::StaticSecret,
    renewal::{RenewalSigner, StampIssue, StampRecord, RENEWER_KEY_CONTEXT},
    sea_orm::{ConnectionTrait, Statement},
};

fn owner() -> (k256::ecdsa::SigningKey, [u8; 20], String) {
    let key = k256::ecdsa::SigningKey::from_bytes(&[0x11; 32].into()).unwrap();
    let pubkey = key.verifying_key().to_encoded_point(false);
    let address: [u8; 20] = Keccak256::digest(&pubkey.as_bytes()[1..])[12..]
        .try_into()
        .unwrap();
    let did = format!(
        "did:pkh:eip155:1:0x{}",
        tinycloud_auth::cacaos::siwe::encode_eip55(&address)
    );
    (key, address, did)
}
fn grant(audience: &str, caps: &[(String, &str)], start: i64, end: i64) -> Result<String> {
    let (key, address, _) = owner();
    let iso = |t: i64| {
        time::OffsetDateTime::from_unix_timestamp(t)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let message = Message {
        scheme: Some("https".parse()?),
        domain: "renewed-invoke.invalid".parse()?,
        address,
        statement: None,
        uri: audience.parse()?,
        version: Version::V1,
        chain_id: 1,
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        issued_at: iso(start).parse()?,
        expiration_time: Some(iso(end).parse()?),
        not_before: None,
        request_id: None,
        resources: vec![],
    };
    let mut recap = Capability::<Value>::new();
    for (resource, action) in caps {
        recap.with_action(resource.parse()?, action.parse()?, [BTreeMap::new()]);
    }
    let message = recap.build_message(message)?;
    let (signature, recovery) = key.sign_prehash_recoverable(&message.eip191_hash()?)?;
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
    bytes[64] = u8::from(recovery) + 27;
    Ok(TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
        message.into(),
        Signature::from(bytes),
        CacaoHeader,
    )))
    .encode()?)
}
fn invocation(
    key: &JWK,
    node: &str,
    resource: &str,
    action: &str,
    proof: &str,
    facts: Vec<Value>,
) -> Result<String> {
    let issuer = DID_METHODS
        .generate(key, "key")
        .context("holder DID")?
        .to_string();
    let method = format!("{issuer}#{}", issuer.rsplit(':').next().unwrap());
    let mut caps = Capabilities::<Value>::new();
    caps.with_action(resource.parse()?, action.parse()?, [BTreeMap::new()]);
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    Ok(Payload::<Value> {
        issuer: method.parse()?,
        audience: node.parse()?,
        not_before: Some(NumericDate::try_from_seconds((now - 1) as f64)?),
        expiration: NumericDate::try_from_seconds((now + 60) as f64)?,
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        facts: Some(facts),
        proof: vec![proof.parse()?],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, key)?
    .encode()?)
}
async fn register(client: &Client, token: &str) -> Result<Hash> {
    let event = tinycloud_core::events::Delegation::from_header_ser::<TinyCloudDelegation>(token)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let id = hash(event.serialized_bytes());
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", token.to_owned()))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    ensure!(status == Status::Ok, "register {status}: {body}");
    Ok(id)
}
struct Lease {
    original: Hash,
    cid: String,
    lease: Hash,
    lease_cid: String,
    stamp: StampRecord,
}
async fn admit(
    client: &Client,
    holder: &str,
    caps: &[(String, &str)],
    original_end: i64,
    lease_end: i64,
) -> Result<Lease> {
    let db = client.rocket().state::<tinycloud::TinyCloud>().unwrap();
    let identity = db.renewal_identity().unwrap();
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let original = register(client, &grant(holder, caps, now - 120, original_end)?).await?;
    let cid = original.to_cid(0x55).to_string();
    let lease = register(
        client,
        &grant(
            &identity.renewer_did,
            &[(format!("urn:cid:{cid}"), "tinycloud.delegation/renew")],
            now - 1,
            lease_end,
        )?,
    )
    .await?;
    let lease_cid = lease.to_cid(0x55).to_string();
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let seed = secret.derive_key(RENEWER_KEY_CONTEXT);
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    let renewer: JWK = serde_json::from_value(
        json!({"kty":"OKP","crv":"Ed25519","alg":"EdDSA","x":base64::encode_config(signing.verifying_key().to_bytes(),base64::URL_SAFE_NO_PAD),"d":base64::encode_config(seed,base64::URL_SAFE_NO_PAD)}),
    )?;
    let vm = format!(
        "{}#{}",
        identity.renewer_did,
        identity.renewer_did.rsplit(':').next().unwrap()
    );
    let signed = make_invocation_from_uris(
        [(
            format!("urn:cid:{cid}").parse()?,
            ["tinycloud.delegation/renew".parse()?],
        )],
        &lease.to_cid(0x55),
        &renewer,
        &vm,
        (now + 60) as f64,
        InvocationOptions {
            nonce: Some(uuid::Uuid::new_v4().to_string()),
            proof: Some(vec![lease.to_cid(0x55)]),
            ..Default::default()
        },
    )?;
    let event = Invocation::from_header_ser::<TinyCloudInvocation>(&signed.encode()?)
        .map_err(|e| anyhow::anyhow!("{e:?}"))?;
    let replay_hash = event.content_hash();
    let stamp = db
        .issue_renewal_stamp(StampIssue {
            invocation: event.0,
            original_cid: cid.clone(),
            lease_cid: lease_cid.clone(),
            replay_hash,
            replay_expires_at: now + 60,
        })
        .await?;
    Ok(Lease {
        original,
        cid,
        lease,
        lease_cid,
        stamp,
    })
}
struct Requests<'a> {
    client: &'a Client,
    key: &'a JWK,
    node: String,
    kv: String,
    hooks: String,
    query: String,
    network: String,
    decrypt: Value,
    facts: Value,
    space: String,
}
impl Requests<'_> {
    async fn check(&self, proof: &str, allowed: bool) -> Result<()> {
        let cases = [
            (
                "kv-put",
                "/invoke".to_string(),
                self.kv.as_str(),
                "tinycloud.kv/put",
                Some(Value::String("renewed-value".into())),
                false,
            ),
            (
                "kv-get",
                "/invoke".into(),
                self.kv.as_str(),
                "tinycloud.kv/get",
                None,
                false,
            ),
            (
                "hooks-list",
                format!(
                    "/hooks/webhooks?space={}&service=kv",
                    percent_encoding::utf8_percent_encode(
                        &self.space,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ),
                self.hooks.as_str(),
                "tinycloud.hooks/list",
                None,
                true,
            ),
            (
                "account-query",
                "/delegation/query".into(),
                self.query.as_str(),
                "tinycloud.delegation/list",
                Some(json!({})),
                false,
            ),
            (
                "decrypt-direct",
                format!(
                    "/encryption/networks/{}/decrypt",
                    percent_encoding::utf8_percent_encode(
                        &self.network,
                        percent_encoding::NON_ALPHANUMERIC
                    )
                ),
                self.network.as_str(),
                DECRYPT_ACTION,
                Some(self.decrypt.clone()),
                false,
            ),
            (
                "decrypt-invoke",
                "/invoke".into(),
                self.network.as_str(),
                DECRYPT_ACTION,
                Some(self.decrypt.clone()),
                false,
            ),
        ];
        let mut refusals = Vec::new();
        for (name, url, resource, action, body, get) in cases {
            let facts = if name.starts_with("decrypt") {
                vec![self.facts.clone()]
            } else {
                vec![]
            };
            let auth = invocation(self.key, &self.node, resource, action, proof, facts)?;
            let mut request = if get {
                self.client.get(url)
            } else {
                self.client.post(url)
            };
            request = request.header(Header::new("Authorization", auth));
            if name == "kv-put" {
                request = request.body("renewed-value");
            } else if let Some(body) = body {
                request = request.header(ContentType::JSON).body(body.to_string());
            }
            let response = request.dispatch().await;
            let status = response.status();
            let text = response.into_string().await.unwrap_or_default();
            if allowed {
                if status != Status::Ok {
                    refusals.push(format!("{name} should authorize: {status}: {text}"));
                }
                if name == "kv-get" && status == Status::Ok {
                    ensure!(text == "renewed-value", "unexpected value: {text}");
                }
            } else {
                if status != Status::Unauthorized && status != Status::Forbidden {
                    refusals.push(format!("{name} should refuse: {status}: {text}"));
                }
            }
        }
        ensure!(refusals.is_empty(), "{}", refusals.join("; "));
        Ok(())
    }
}
async fn wait_until(second: i64) {
    while time::OffsetDateTime::now_utc().unix_timestamp() < second {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
async fn corrupt(
    client: &Client,
    lease: &Lease,
    cid: &str,
    bytes: &[u8],
    signature: &[u8],
) -> Result<()> {
    let conn = client
        .rocket()
        .state::<tinycloud::TinyCloud>()
        .unwrap()
        .connection();
    let hash = Hash::from(cid.parse::<tinycloud_auth::authorization::Cid>()?);
    conn.execute(Statement::from_sql_and_values(conn.get_database_backend(),"UPDATE renewal_stamp SET cid=$1,signed_bytes=$2,signature=$3 WHERE original_canonical=$4 AND lease_cid=$5",[Vec::<u8>::from(hash).into(),bytes.to_vec().into(),signature.to_vec().into(),Vec::<u8>::from(lease.original).into(),Vec::<u8>::from(lease.lease).into()])).await?;
    Ok(())
}
async fn exercise(url: Option<&str>) -> Result<()> {
    let (client, _dir) = setup::node(url).await;
    let db = client.rocket().state::<tinycloud::TinyCloud>().unwrap();
    let identity = db.renewal_identity().unwrap();
    let node = identity.stable_node_did.clone();
    let (_, _, owner_did) = owner();
    let space = format!(
        "tinycloud:{}:auth{}",
        owner_did.strip_prefix("did:").unwrap(),
        uuid::Uuid::new_v4().simple()
    );
    let kv = format!("{space}/kv/value");
    let hooks = format!("{space}/hooks/kv");
    let query = format!(
        "tinycloud:{}:account/delegation",
        owner_did.strip_prefix("did:").unwrap()
    );
    let peer = client
        .get(format!("/peer/generate/{space}"))
        .dispatch()
        .await
        .into_string()
        .await
        .context("peer DID")?;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    register(
        &client,
        &grant(
            &peer,
            &[(format!("{space}/space"), "tinycloud.space/host")],
            now - 1,
            now + 3600,
        )?,
    )
    .await?;
    let encryption = client.rocket().state::<EncryptionService>().unwrap();
    let descriptor = encryption
        .create_one_of_one_network(CreateNetworkRequest {
            name: format!("net{}", uuid::Uuid::new_v4().simple()),
            owner_did,
            threshold: Threshold::one_of_one(),
        })
        .await?;
    let network = descriptor.network_id.to_string();
    let wrapped = wrap_to_public_key(&descriptor.public_encryption_key, &[0xCD; 32])?;
    let receiver = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
    let receiver = base64::encode(x25519_dalek::PublicKey::from(&receiver).to_bytes());
    let encrypted = base64::encode(wrapped);
    let receiver_hash = canonical_hash(&json!(receiver));
    let encrypted_hash = canonical_hash(&json!(encrypted));
    let decrypt = json!({"type":DECRYPT_REQUEST_TYPE,"targetNode":node,"networkId":network,"alg":ALG_X25519_AES256GCM,"keyVersion":1,"encryptedSymmetricKey":encrypted,"encryptedSymmetricKeyHash":encrypted_hash,"receiverPublicKey":receiver,"receiverPublicKeyHash":receiver_hash});
    let facts = json!({"type":DECRYPT_REQUEST_TYPE,"targetNode":node,"networkId":network,"alg":ALG_X25519_AES256GCM,"keyVersion":1,"bodyHash":canonical_hash(&decrypt),"encryptedSymmetricKeyHash":encrypted_hash,"receiverPublicKeyHash":receiver_hash});
    let key = JWK::generate_ed25519()?;
    let holder = DID_METHODS
        .generate(&key, "key")
        .context("holder DID")?
        .to_string();
    let caps = vec![
        (kv.clone(), "tinycloud.kv/get"),
        (kv.clone(), "tinycloud.kv/put"),
        (hooks.clone(), "tinycloud.hooks/list"),
        (query.clone(), "tinycloud.delegation/list"),
        (network.clone(), DECRYPT_ACTION),
    ];
    let start = time::OffsetDateTime::now_utc().unix_timestamp();
    let end = start + 8;
    let expires = admit(&client, &holder, &caps, end, start + 24).await?;
    let revoked = admit(&client, &holder, &caps, end, start + 120).await?;
    let requests = Requests {
        client: &client,
        key: &key,
        node,
        kv,
        hooks,
        query,
        network,
        decrypt,
        facts,
        space,
    };
    requests.check(&expires.cid, true).await?;
    ensure!(
        time::OffsetDateTime::now_utc().unix_timestamp() < end,
        "fixture setup exceeded original lifetime"
    );
    wait_until(end + 1).await;
    // A forged signature and a valid signature naming another original are both ineffective.
    corrupt(
        &client,
        &expires,
        &expires.stamp.cid,
        &expires.stamp.signed_bytes,
        &[0; 64],
    )
    .await?;
    requests.check(&expires.cid, false).await?;
    let secret = StaticSecret::new(vec![0x42; 32]).unwrap();
    let signer = RenewalSigner::from_seed(
        secret.derive_key(RENEWER_KEY_CONTEXT),
        requests.node.clone(),
        identity.epoch,
    );
    let stamp_end = time::OffsetDateTime::from_unix_timestamp(expires.stamp.new_end)?
        .format(&time::format_description::well_known::Rfc3339)?;
    let (foreign, signature, cid) = signer.sign_stamp(
        &revoked.cid,
        &expires.lease_cid,
        1,
        &expires.lease_cid,
        &stamp_end,
    )?;
    corrupt(&client, &expires, &cid, &foreign, &signature).await?;
    requests.check(&expires.cid, false).await?;
    corrupt(
        &client,
        &expires,
        &expires.stamp.cid,
        &expires.stamp.signed_bytes,
        &expires.stamp.signature,
    )
    .await?;
    requests.check(&expires.cid, true).await?;
    requests.check(&revoked.cid, true).await?;
    // A real owner revoke must remove renewal-added authority at every entrypoint.
    let (signing, address, _) = owner();
    let iso = |t: i64| {
        time::OffsetDateTime::from_unix_timestamp(t)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let message = Message {
        scheme: Some("https".parse()?),
        domain: "renewed-invoke.invalid".parse()?,
        address,
        statement: None,
        uri: format!("ucan:{}", revoked.lease_cid).parse()?,
        version: Version::V1,
        chain_id: 1,
        nonce: uuid::Uuid::new_v4().simple().to_string(),
        issued_at: iso(start).parse()?,
        expiration_time: Some(iso(start + 300).parse()?),
        not_before: None,
        request_id: None,
        resources: vec![],
    };
    let (sig, recovery) = signing.sign_prehash_recoverable(&message.eip191_hash()?)?;
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(sig.to_bytes().as_ref());
    bytes[64] = u8::from(recovery) + 27;
    let revoke = tinycloud_auth::authorization::TinyCloudRevocation::Cacao(Box::new(
        SiweCacao::new(message.into(), Signature::from(bytes), CacaoHeader),
    ))
    .encode()?;
    let response = client
        .post("/revoke")
        .header(Header::new("Authorization", revoke))
        .dispatch()
        .await;
    let status = response.status();
    let text = response.into_string().await.unwrap_or_default();
    ensure!(status == Status::Ok, "revoke {status}: {text}");
    requests.check(&revoked.cid, false).await?;
    wait_until(start + 24).await;
    requests.check(&expires.cid, false).await?;
    Ok(())
}

#[tokio::test]
async fn sqlite_renewal_reaches_every_http_authorization_entrypoint() -> Result<()> {
    let dir = tempfile::tempdir()?;
    let url = format!("sqlite:{}?mode=rwc", dir.path().join("auth.db").display());
    exercise(Some(&url)).await
}
#[tokio::test]
async fn postgres_renewal_reaches_every_http_authorization_entrypoint() -> Result<()> {
    let Some(url) =
        common::postgres_test_url("postgres_renewal_reaches_every_http_authorization_entrypoint")
    else {
        return Ok(());
    };
    use tinycloud_core::sea_orm::{Database, DatabaseBackend};
    let admin = Database::connect(&url).await?;
    let version = admin
        .query_one(Statement::from_string(
            DatabaseBackend::Postgres,
            "SHOW server_version_num",
        ))
        .await?
        .context("PG version")?
        .try_get::<String>("", "server_version_num")?;
    ensure!(version.starts_with("16"), "requires PG16");
    let schema = format!("renewed_auth_{}", uuid::Uuid::new_v4().simple());
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await?;
    let mut scoped = reqwest::Url::parse(&url)?;
    scoped
        .query_pairs_mut()
        .append_pair("options", &format!("-c search_path={schema}"));
    let result = exercise(Some(scoped.as_str())).await;
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await?;
    result
}

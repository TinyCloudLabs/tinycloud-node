//! TC-3810: HTTP-level tests for wallet-signed CACAO delegation mode
//! (`xyz.tinycloud.policy/delegationMode`).
//!
//! Verifies 401 `terminal-parent-cannot-redelegate` on both `POST /delegate`
//! and `POST /invoke` (KV read, KV write, and encryption decrypt), zero replay
//! spend and zero data mutation on refusal, 401 refusal of malformed modes at
//! parse time, direct use of terminal CACAOs, and unchanged attenuable CACAOs.

use anyhow::{anyhow, Result};
use k256::ecdsa::SigningKey;
use rocket::{
    figment::{providers::Serialized, Figment},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudInvocation},
    cacaos::{
        siwe::{encode_eip55, Message, Version},
        siwe_cacao::{Eip191, Payload as CacaoPayload, Signature, SiweCacao},
    },
    ipld_core::cid::Cid,
    resolver::DID_METHODS,
    resource::SpaceId,
    siwe_recap::{Capability as RecapCapability, DelegationModeFact, RESOURCE_PREFIX},
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload as UcanPayload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::Hash,
    keys::StaticSecret,
    models::{
        abilities, actor, delegation, delegation_cid_alias, delegation_mode, invocation_replay,
    },
    relationships::parent_delegations,
    sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, EntityTrait, PaginatorTrait},
};

const SECRET: [u8; 32] = [88; 32];

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
    did: String,
}

impl Wallet {
    fn from_seed(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let address: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..]
            .try_into()
            .unwrap();
        let did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        Self { key, address, did }
    }

    fn sign_message(&self, message: &Message) -> Result<SiweCacao> {
        let (sig, recovery) = self
            .key
            .sign_prehash_recoverable(&message.eip191_hash().map_err(|e| anyhow!("{e}"))?)?;
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&sig.to_bytes());
        bytes[64] = u8::from(recovery) + 27;
        Ok(CacaoPayload::from(message.clone()).sign::<Eip191>(Signature::from(bytes)))
    }
}

fn verification_method(key: &JWK) -> (String, String) {
    let did = DID_METHODS.generate(key, "key").unwrap().to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    (did, vm)
}

fn node_did() -> String {
    StaticSecret::new(SECRET.to_vec()).unwrap().node_did()
}

fn base_siwe_message(wallet: &Wallet, audience: &str, nonce: &str) -> Message {
    let now = OffsetDateTime::now_utc();
    Message {
        scheme: Some("https".parse().unwrap()),
        domain: "openkey.tinycloud.invalid".parse().unwrap(),
        address: wallet.address,
        statement: None,
        uri: audience.parse().unwrap(),
        version: Version::V1,
        chain_id: 1,
        nonce: nonce.to_string(),
        issued_at: now.into(),
        expiration_time: Some((now + time::Duration::hours(2)).into()),
        not_before: Some((now - time::Duration::minutes(2)).into()),
        request_id: None,
        resources: vec![],
    }
}

fn signed_cacao_token(
    wallet: &Wallet,
    audience: &str,
    grants: &[(&str, &str)],
    parents: &[Cid],
    mode: Option<DelegationModeFact>,
    nonce: &str,
) -> Result<(String, Cid)> {
    let mut recap = RecapCapability::<Value>::new();
    for (resource, ability) in grants {
        recap.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    let recap = recap.with_proofs(parents);
    let recap = match mode {
        Some(m) => recap.with_delegation_mode(m),
        None => recap,
    };
    let message = recap.build_message(base_siwe_message(wallet, audience, nonce))?;
    let cacao = wallet.sign_message(&message)?;
    let token = TinyCloudDelegation::Cacao(Box::new(cacao)).encode()?;
    let (_, canonical) = TinyCloudDelegation::decode(&token)?;
    let cid = tinycloud_core::hash::hash(&canonical).to_cid(0x55);
    Ok((token, cid))
}

fn signed_cacao_malformed_mode(
    wallet: &Wallet,
    audience: &str,
    grants: &[(&str, &str)],
    raw_tail: &str,
    nonce: &str,
) -> Result<String> {
    let mut recap = RecapCapability::<Value>::new();
    for (resource, ability) in grants {
        recap.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    let statement = recap.to_statement();
    let att_json = serde_json::to_string(recap.abilities())?;
    let raw_recap = format!(r#"{{"att":{att_json},"prf":[],{raw_tail}}}"#);
    let encoded = base64::encode_config(raw_recap.as_bytes(), base64::URL_SAFE_NO_PAD);
    let mut message = base_siwe_message(wallet, audience, nonce);
    message.statement = Some(statement);
    message
        .resources
        .push(format!("{RESOURCE_PREFIX}{encoded}").parse().unwrap());
    let cacao = wallet.sign_message(&message)?;
    Ok(TinyCloudDelegation::Cacao(Box::new(cacao)).encode()?)
}

fn signed_ucan_delegation(
    issuer: &JWK,
    audience: &str,
    grants: &[(&str, &str)],
    parents: &[Cid],
) -> Result<(String, Cid, Vec<u8>)> {
    let mut caps = Capabilities::<Value>::new();
    for (resource, ability) in grants {
        caps.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = UcanPayload::<Value> {
        issuer: verification_method(issuer).1.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 15) as f64)?),
        expiration: NumericDate::try_from_seconds((now + 1200) as f64)?,
        nonce: Some(format!("tc3810-http-del-{}", rand::random::<u64>())),
        facts: None,
        proof: parents.to_vec(),
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, issuer)?
    .encode()?;
    let bytes = token.as_bytes().to_vec();
    let cid = tinycloud_core::hash::hash(&bytes).to_cid(0x55);
    Ok((token, cid, bytes))
}

fn signed_invocation(
    issuer: &JWK,
    audience: &str,
    grants: &[(&str, &str)],
    parents: &[Cid],
    facts: Option<Vec<Value>>,
) -> Result<String> {
    let mut caps = Capabilities::<Value>::new();
    for (resource, ability) in grants {
        caps.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let (_, vm) = verification_method(issuer);
    let token = UcanPayload::<Value> {
        issuer: vm.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds((now - 60) as f64)?),
        expiration: NumericDate::try_from_seconds((now + 60) as f64)?,
        nonce: Some(format!("tc3810-http-inv-{}", rand::random::<u64>())),
        facts,
        proof: parents.to_vec(),
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, issuer)?
    .encode()?;
    let _ = TinyCloudInvocation::decode(&token)?;
    Ok(token)
}

async fn start_node() -> Result<(Client, String, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let db_url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("node.sqlite").display()
    );
    let mut config = tinycloud::config::Config::default();
    config.storage.datadir = dir.path().into();
    config.storage.database = Some(db_url.clone());
    config.keys = serde_json::from_value(json!({
        "type": "static",
        "secret": base64::encode_config(SECRET, base64::URL_SAFE_NO_PAD),
    }))?;
    config.encryption_network.named_keys_v1 = true;
    config.encryption_network.deletion_ledger_path = Some(dir.path().join("deletions.jsonl"));
    let figment = Figment::from(rocket::Config {
        log_level: rocket::config::LogLevel::Off,
        ..rocket::Config::default()
    })
    .merge(Serialized::defaults(&config));
    let rocket = tinycloud::app_with_control(&figment, &config, None).await?;
    Ok((Client::tracked(rocket).await?, db_url, dir))
}

async fn post_auth(
    client: &Client,
    path: &str,
    auth: &str,
    body: Option<&str>,
    content_type: ContentType,
) -> (Status, String) {
    let mut req = client
        .post(path.to_owned())
        .remote("127.0.0.1:9000".parse().unwrap())
        .header(Header::new("Authorization", auth.to_owned()))
        .header(content_type);
    if let Some(body) = body {
        req = req.body(body);
    }
    let response = req.dispatch().await;
    (
        response.status(),
        response.into_string().await.unwrap_or_default(),
    )
}

#[tokio::test]
async fn http_terminal_cacao_delegate_invoke_replay_and_malformed_mode() -> Result<()> {
    let (client, db_url, _dir) = start_node().await?;
    let db = Database::connect(&db_url).await?;

    let wallet = Wallet::from_seed(0x61);
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        wallet.did.strip_prefix("did:").unwrap()
    )
    .parse()?;
    let space_res = format!("{space}/space");
    let kv_res = space
        .clone()
        .to_resource("kv".parse()?, Some("secrets/alpha".parse()?), None, None)
        .to_string();
    let kv_put_res = space
        .clone()
        .to_resource("kv".parse()?, Some("secrets/beta".parse()?), None, None)
        .to_string();
    let network_res = format!("urn:tinycloud:encryption:{}:default", wallet.did);
    let secret_key_res = format!("{network_res}/secrets/alpha");

    let app_key = JWK::generate_ed25519()?;
    let (app_did, _) = verification_method(&app_key);
    let sub_key = JWK::generate_ed25519()?;
    let (sub_did, _) = verification_method(&sub_key);

    // Host space + seed initial KV entry using an attenuable owner session.
    let owner_sess = JWK::generate_ed25519()?;
    let (owner_sess_did, _) = verification_method(&owner_sess);
    let (host_tok, host_cid) = signed_cacao_token(
        &wallet,
        &owner_sess_did,
        &[
            (&space_res, "tinycloud.space/host"),
            (&kv_res, "tinycloud.kv/put"),
            (&kv_res, "tinycloud.kv/get"),
        ],
        &[],
        Some(DelegationModeFact::Attenuable),
        "httphost001",
    )?;
    let (status, body) = post_auth(&client, "/delegate", &host_tok, None, ContentType::Plain).await;
    assert_eq!(status, Status::Ok, "host delegate: {body}");

    let seed_put = signed_invocation(
        &owner_sess,
        &node_did(),
        &[(&kv_res, "tinycloud.kv/put")],
        &[host_cid],
        None,
    )?;
    let (status, body) = post_auth(
        &client,
        "/invoke",
        &seed_put,
        Some("hello-secret"),
        ContentType::Plain,
    )
    .await;
    assert_eq!(status, Status::Ok, "seed kv put: {body}");

    // 1. Register terminal CACAO T -> 200 OK.
    let (t_tok, t_cid) = signed_cacao_token(
        &wallet,
        &app_did,
        &[
            (&kv_res, "tinycloud.kv/get"),
            (&kv_put_res, "tinycloud.kv/put"),
            (&network_res, "tinycloud.encryption/decrypt"),
            (&secret_key_res, "tinycloud.encryption/decrypt"),
        ],
        &[],
        Some(DelegationModeFact::Terminal),
        "httpterm001",
    )?;
    let (status, body) = post_auth(&client, "/delegate", &t_tok, None, ContentType::Plain).await;
    assert_eq!(status, Status::Ok, "terminal cacao delegate: {body}");

    // 2. Direct invocation of T (KV get) succeeds -> 200 OK.
    let direct_get = signed_invocation(
        &app_key,
        &node_did(),
        &[(&kv_res, "tinycloud.kv/get")],
        &[t_cid],
        None,
    )?;
    let (status, body) = post_auth(&client, "/invoke", &direct_get, None, ContentType::Plain).await;
    assert_eq!(status, Status::Ok, "direct kv get: {body}");
    assert_eq!(body, "hello-secret");

    // 3. UCAN child of T -> 401 terminal-parent-cannot-redelegate, not stored.
    let (ucan_child_tok, ucan_child_cid, ucan_child_bytes) = signed_ucan_delegation(
        &app_key,
        &sub_did,
        &[
            (&kv_res, "tinycloud.kv/get"),
            (&kv_put_res, "tinycloud.kv/put"),
            (&network_res, "tinycloud.encryption/decrypt"),
            (&secret_key_res, "tinycloud.encryption/decrypt"),
        ],
        &[t_cid],
    )?;
    let (status, body) = post_auth(
        &client,
        "/delegate",
        &ucan_child_tok,
        None,
        ContentType::Plain,
    )
    .await;
    assert_eq!(status, Status::Unauthorized, "ucan child delegate: {body}");
    assert_eq!(body, "terminal-parent-cannot-redelegate");
    assert!(
        delegation::Entity::find_by_id(Hash::from(ucan_child_cid))
            .one(&db)
            .await?
            .is_none(),
        "refused child must not be stored"
    );

    // 4. Malformed-mode CACAO -> 401 at header decode, nothing written.
    let before_count = delegation::Entity::find().count(&db).await?;
    for bad_tail in [
        r#""xyz.tinycloud.policy/delegationMode":null"#,
        r#""xyz.tinycloud.policy/delegationMode":"bogus""#,
        r#""xyz.tinycloud.policy/delegationMode":"terminal","xyz.tinycloud.policy/delegationMode":"attenuable""#,
    ] {
        let bad_tok = signed_cacao_malformed_mode(
            &wallet,
            &app_did,
            &[(&kv_res, "tinycloud.kv/get")],
            bad_tail,
            "httpbad0001",
        )?;
        let (status, _body) =
            post_auth(&client, "/delegate", &bad_tok, None, ContentType::Plain).await;
        assert_eq!(status, Status::Unauthorized, "bad tail {bad_tail}");
    }
    assert_eq!(delegation::Entity::find().count(&db).await?, before_count);

    // 5. Insert a simulated legacy child of T directly into the DB, then test
    // HTTP /invoke for KV read, KV write, and encryption decrypt: all must
    // return 401 `terminal-parent-cannot-redelegate` with ZERO replay spend and
    // ZERO data mutation, and reposting the legacy child on /delegate must ALSO
    // return 401 (not already-registered 200).
    let legacy_hash = Hash::from(ucan_child_cid);
    for did in [&app_did, &sub_did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(&db)
        .await
        .ok();
    }
    let now = OffsetDateTime::now_utc();
    delegation::ActiveModel {
        id: Set(legacy_hash),
        delegator: Set(app_did.clone()),
        delegatee: Set(sub_did.clone()),
        expiry: Set(Some(now + time::Duration::hours(1))),
        issued_at: Set(None),
        not_before: Set(Some(now - time::Duration::minutes(1))),
        facts: Set(None),
        serialization: Set(ucan_child_bytes),
        serialization_format: Set(0),
        first_seen_at: Set(Some(now)),
    }
    .insert(&db)
    .await?;
    delegation_cid_alias::ActiveModel {
        id: Set(legacy_hash),
        canonical: Set(legacy_hash),
        encrypted: Set(false),
    }
    .insert(&db)
    .await?;
    for (res, ab) in [
        (&kv_res, "tinycloud.kv/get"),
        (&kv_put_res, "tinycloud.kv/put"),
        (&network_res, "tinycloud.encryption/decrypt"),
        (&secret_key_res, "tinycloud.encryption/decrypt"),
    ] {
        abilities::ActiveModel {
            delegation: Set(legacy_hash),
            resource: Set(res.parse().unwrap()),
            ability: Set(ab.to_string().try_into().unwrap()),
            caveats: Set(Default::default()),
        }
        .insert(&db)
        .await?;
    }
    parent_delegations::ActiveModel {
        child: Set(legacy_hash),
        parent: Set(Hash::from(t_cid)),
    }
    .insert(&db)
    .await?;

    // Repost legacy child -> 401 terminal-parent-cannot-redelegate (NOT 200).
    let (status, body) = post_auth(
        &client,
        "/delegate",
        &ucan_child_tok,
        None,
        ContentType::Plain,
    )
    .await;
    assert_eq!(status, Status::Unauthorized, "repost legacy child: {body}");
    assert_eq!(body, "terminal-parent-cannot-redelegate");

    // KV read via legacy child -> 401 terminal-parent-cannot-redelegate.
    // (KV reads spend their replay row up front, matching main's replay contract.)
    let inv_read = signed_invocation(
        &sub_key,
        &node_did(),
        &[(&kv_res, "tinycloud.kv/get")],
        &[ucan_child_cid],
        None,
    )?;
    let (status, body) = post_auth(&client, "/invoke", &inv_read, None, ContentType::Plain).await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "kv read via legacy child: {body}"
    );
    assert_eq!(body, "terminal-parent-cannot-redelegate");

    let replay_before = invocation_replay::Entity::find().count(&db).await?;

    // KV write via legacy child -> 401, no replay spend, no data written.
    let inv_write = signed_invocation(
        &sub_key,
        &node_did(),
        &[(&kv_put_res, "tinycloud.kv/put")],
        &[ucan_child_cid],
        None,
    )?;
    let (status, body) = post_auth(
        &client,
        "/invoke",
        &inv_write,
        Some("must-not-write"),
        ContentType::Plain,
    )
    .await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "kv put via legacy child: {body}"
    );
    assert_eq!(body, "terminal-parent-cannot-redelegate");
    assert_eq!(
        invocation_replay::Entity::find().count(&db).await?,
        replay_before,
        "kv put refusal must not spend a replay row"
    );

    // Encryption decrypt via legacy child -> 401, no replay spend.
    let inv_decrypt = signed_invocation(
        &sub_key,
        &node_did(),
        &[(&secret_key_res, "tinycloud.encryption/decrypt")],
        &[ucan_child_cid],
        Some(vec![json!({
            "type": "tinycloud.encryption/decrypt-request/v1",
            "keyPath": "secrets/alpha",
            "networkId": format!("urn:tinycloud:encryption:{}:default", wallet.did),
        })]),
    )?;
    let (status, body) = post_auth(
        &client,
        "/invoke",
        &inv_decrypt,
        Some("{}"),
        ContentType::JSON,
    )
    .await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "decrypt via legacy child: {body}"
    );
    assert_eq!(body, "terminal-parent-cannot-redelegate");
    assert_eq!(
        invocation_replay::Entity::find().count(&db).await?,
        replay_before,
        "decrypt refusal must not spend a replay row"
    );

    // Dedicated /encryption/networks/<network_id>/decrypt route via legacy
    // child of terminal CACAO -> 401 terminal-parent-cannot-redelegate, zero
    // replay spend.
    let inv_net_decrypt = signed_invocation(
        &sub_key,
        &node_did(),
        &[(&network_res, "tinycloud.encryption/decrypt")],
        &[ucan_child_cid],
        None,
    )?;
    let net_decrypt_body = json!({ "networkId": network_res }).to_string();
    let (status, body) = post_auth(
        &client,
        &format!("/encryption/networks/{network_res}/decrypt"),
        &inv_net_decrypt,
        Some(&net_decrypt_body),
        ContentType::JSON,
    )
    .await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "dedicated encryption decrypt via legacy child: {body}"
    );
    assert_eq!(body, "terminal-parent-cannot-redelegate");
    assert_eq!(
        invocation_replay::Entity::find().count(&db).await?,
        replay_before,
        "dedicated encryption decrypt refusal must not spend a replay row"
    );

    // 6. Confirm kv_put_res was never written (owner read -> 404).
    let (verify_tok, verify_cid) = signed_cacao_token(
        &wallet,
        &owner_sess_did,
        &[(&kv_put_res, "tinycloud.kv/get")],
        &[],
        None,
        "httpver0001",
    )?;
    let (status, _) = post_auth(&client, "/delegate", &verify_tok, None, ContentType::Plain).await;
    assert_eq!(status, Status::Ok);
    let check_get = signed_invocation(
        &owner_sess,
        &node_did(),
        &[(&kv_put_res, "tinycloud.kv/get")],
        &[verify_cid],
        None,
    )?;
    let (status, _) = post_auth(&client, "/invoke", &check_get, None, ContentType::Plain).await;
    assert_eq!(status, Status::NotFound, "refused put must not mutate KV");

    // 7. Attenuable CACAO (absent field) still allows child UCAN + invoke.
    let (ok_child_tok, ok_child_cid, _) = signed_ucan_delegation(
        &owner_sess,
        &sub_did,
        &[(&kv_res, "tinycloud.kv/get")],
        &[host_cid],
    )?;
    let (status, body) = post_auth(
        &client,
        "/delegate",
        &ok_child_tok,
        None,
        ContentType::Plain,
    )
    .await;
    assert_eq!(status, Status::Ok, "attenuable child delegate: {body}");
    let ok_inv = signed_invocation(
        &sub_key,
        &node_did(),
        &[(&kv_res, "tinycloud.kv/get")],
        &[ok_child_cid],
        None,
    )?;
    let (status, body) = post_auth(&client, "/invoke", &ok_inv, None, ContentType::Plain).await;
    assert_eq!(status, Status::Ok, "attenuable child invoke: {body}");
    assert_eq!(body, "hello-secret");

    Ok(())
}

/// TC-3810 (P2): `/delegation/status` enforces the same delegation-mode rules
/// as `/invoke` on proof-bearing status grants: an `invalid`-marked status
/// grant returns 401, a status grant whose strict ancestor is terminal returns
/// 401, while a valid status grant (attenuable or direct terminal) and
/// proofless party access remain unaffected.
#[tokio::test]
async fn http_delegation_status_enforces_invalid_and_terminal_ancestor_proofs() -> Result<()> {
    let (client, db_url, _dir) = start_node().await?;
    let db = Database::connect(&db_url).await?;

    let wallet = Wallet::from_seed(0x73);
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        wallet.did.strip_prefix("did:").unwrap()
    )
    .parse()?;
    let space_res = format!("{space}/space");
    let del_scope_res = format!("{space}/delegation");
    let kv_res = space
        .clone()
        .to_resource("kv".parse()?, Some("secrets/status".parse()?), None, None)
        .to_string();

    let target_holder = JWK::generate_ed25519()?;
    let (target_holder_did, _) = verification_method(&target_holder);
    let (target_tok, target_cid) = signed_cacao_token(
        &wallet,
        &target_holder_did,
        &[
            (&space_res, "tinycloud.space/host"),
            (&kv_res, "tinycloud.kv/get"),
        ],
        &[],
        Some(DelegationModeFact::Attenuable),
        "sttarget001",
    )?;
    let (status, body) =
        post_auth(&client, "/delegate", &target_tok, None, ContentType::Plain).await;
    assert_eq!(status, Status::Ok, "target delegate: {body}");
    let target_status_res = format!("urn:cid:{target_cid}");
    let status_body = json!({ "cid": target_cid.to_string() }).to_string();

    // 1. Invalid-marked status grant on `<space>/delegation` -> 401 invalid-delegation-mode.
    // `delegation.facts` is left `None`; the mark lives exclusively in `delegation_mode`.
    let bad_holder = JWK::generate_ed25519()?;
    let (bad_holder_did, _) = verification_method(&bad_holder);
    let bad_tok = signed_cacao_malformed_mode(
        &wallet,
        &bad_holder_did,
        &[(&del_scope_res, "tinycloud.delegation/status")],
        r#""xyz.tinycloud.policy/delegationMode":"bogus""#,
        "stbad000001",
    )?;
    let (_, bad_bytes) = TinyCloudDelegation::decode(&bad_tok)?;
    let bad_hash = tinycloud_core::hash::hash(&bad_bytes);
    let bad_cid = bad_hash.to_cid(0x55);
    for did in [&wallet.did, &bad_holder_did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(&db)
        .await
        .ok();
    }
    let now = OffsetDateTime::now_utc();
    delegation::ActiveModel {
        id: Set(bad_hash),
        delegator: Set(wallet.did.clone()),
        delegatee: Set(bad_holder_did.clone()),
        expiry: Set(Some(now + time::Duration::hours(1))),
        issued_at: Set(Some(now)),
        not_before: Set(Some(now - time::Duration::minutes(1))),
        facts: Set(None),
        serialization: Set(bad_bytes),
        serialization_format: Set(0),
        first_seen_at: Set(Some(now)),
    }
    .insert(&db)
    .await?;
    delegation_cid_alias::ActiveModel {
        id: Set(bad_hash),
        canonical: Set(bad_hash),
        encrypted: Set(false),
    }
    .insert(&db)
    .await?;
    delegation_mode::ActiveModel {
        delegation_id: Set(bad_hash),
        mode: Set("invalid".to_string()),
    }
    .insert(&db)
    .await?;
    abilities::ActiveModel {
        delegation: Set(bad_hash),
        resource: Set(del_scope_res.parse().unwrap()),
        ability: Set("tinycloud.delegation/status"
            .to_string()
            .try_into()
            .unwrap()),
        caveats: Set(Default::default()),
    }
    .insert(&db)
    .await?;

    let inv_bad = signed_invocation(
        &bad_holder,
        &node_did(),
        &[(&target_status_res, "tinycloud.delegation/status")],
        &[bad_cid],
        None,
    )?;
    let (status, body) = post_auth(
        &client,
        "/delegation/status",
        &inv_bad,
        Some(&status_body),
        ContentType::JSON,
    )
    .await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "invalid-marked status grant must return 401: {body}"
    );
    assert_eq!(body, "invalid-delegation-mode");

    // 1b. Deleting the `delegation_mode` row (unmarked) STILL returns 401
    // invalid-delegation-mode via fail-closed derive-on-read.
    delegation_mode::Entity::delete_by_id(bad_hash)
        .exec(&db)
        .await?;
    let inv_bad_unmarked = signed_invocation(
        &bad_holder,
        &node_did(),
        &[(&target_status_res, "tinycloud.delegation/status")],
        &[bad_cid],
        None,
    )?;
    let (status, body) = post_auth(
        &client,
        "/delegation/status",
        &inv_bad_unmarked,
        Some(&status_body),
        ContentType::JSON,
    )
    .await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "unmarked malformed status grant must fail closed with 401: {body}"
    );
    assert_eq!(body, "invalid-delegation-mode");

    // 2. Status grant whose strict ancestor is a terminal CACAO -> 401 terminal-parent-cannot-redelegate.
    let term_holder = JWK::generate_ed25519()?;
    let (term_holder_did, _) = verification_method(&term_holder);
    let sub_holder = JWK::generate_ed25519()?;
    let (sub_holder_did, _) = verification_method(&sub_holder);
    let (term_tok, term_cid) = signed_cacao_token(
        &wallet,
        &term_holder_did,
        &[(&del_scope_res, "tinycloud.delegation/status")],
        &[],
        Some(DelegationModeFact::Terminal),
        "stterm00001",
    )?;
    let (status, body) = post_auth(&client, "/delegate", &term_tok, None, ContentType::Plain).await;
    assert_eq!(status, Status::Ok, "terminal status grant delegate: {body}");

    let (_, child_cid, child_bytes) = signed_ucan_delegation(
        &term_holder,
        &sub_holder_did,
        &[(&del_scope_res, "tinycloud.delegation/status")],
        &[term_cid],
    )?;
    let child_hash = Hash::from(child_cid);
    for did in [&term_holder_did, &sub_holder_did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(&db)
        .await
        .ok();
    }
    delegation::ActiveModel {
        id: Set(child_hash),
        delegator: Set(term_holder_did.clone()),
        delegatee: Set(sub_holder_did.clone()),
        expiry: Set(Some(now + time::Duration::hours(1))),
        issued_at: Set(None),
        not_before: Set(Some(now - time::Duration::minutes(1))),
        facts: Set(None),
        serialization: Set(child_bytes),
        serialization_format: Set(0),
        first_seen_at: Set(Some(now)),
    }
    .insert(&db)
    .await?;
    delegation_cid_alias::ActiveModel {
        id: Set(child_hash),
        canonical: Set(child_hash),
        encrypted: Set(false),
    }
    .insert(&db)
    .await?;
    abilities::ActiveModel {
        delegation: Set(child_hash),
        resource: Set(del_scope_res.parse().unwrap()),
        ability: Set("tinycloud.delegation/status"
            .to_string()
            .try_into()
            .unwrap()),
        caveats: Set(Default::default()),
    }
    .insert(&db)
    .await?;
    parent_delegations::ActiveModel {
        child: Set(child_hash),
        parent: Set(Hash::from(term_cid)),
    }
    .insert(&db)
    .await?;

    let inv_term_child = signed_invocation(
        &sub_holder,
        &node_did(),
        &[(&target_status_res, "tinycloud.delegation/status")],
        &[child_cid],
        None,
    )?;
    let (status, body) = post_auth(
        &client,
        "/delegation/status",
        &inv_term_child,
        Some(&status_body),
        ContentType::JSON,
    )
    .await;
    assert_eq!(
        status,
        Status::Unauthorized,
        "status grant with terminal ancestor must return 401: {body}"
    );
    assert_eq!(body, "terminal-parent-cannot-redelegate");

    // 3. Valid status grants (direct terminal leaf AND attenuable grant) succeed -> 200 OK.
    let inv_direct_term = signed_invocation(
        &term_holder,
        &node_did(),
        &[(&target_status_res, "tinycloud.delegation/status")],
        &[term_cid],
        None,
    )?;
    let (status, body) = post_auth(
        &client,
        "/delegation/status",
        &inv_direct_term,
        Some(&status_body),
        ContentType::JSON,
    )
    .await;
    assert_eq!(status, Status::Ok, "direct terminal status grant: {body}");
    let parsed: Value = serde_json::from_str(&body)?;
    assert_eq!(parsed["active"], json!(true));

    let ok_holder = JWK::generate_ed25519()?;
    let (ok_holder_did, _) = verification_method(&ok_holder);
    let (ok_tok, ok_cid) = signed_cacao_token(
        &wallet,
        &ok_holder_did,
        &[(&del_scope_res, "tinycloud.delegation/status")],
        &[],
        None,
        "stok0000001",
    )?;
    let (status, body) = post_auth(&client, "/delegate", &ok_tok, None, ContentType::Plain).await;
    assert_eq!(status, Status::Ok, "valid status grant delegate: {body}");
    let inv_ok = signed_invocation(
        &ok_holder,
        &node_did(),
        &[(&target_status_res, "tinycloud.delegation/status")],
        &[ok_cid],
        None,
    )?;
    let (status, body) = post_auth(
        &client,
        "/delegation/status",
        &inv_ok,
        Some(&status_body),
        ContentType::JSON,
    )
    .await;
    assert_eq!(status, Status::Ok, "valid status grant: {body}");
    let parsed: Value = serde_json::from_str(&body)?;
    assert_eq!(parsed["active"], json!(true));

    // 4. Proofless party access (target's delegatee, parents = []) remains unaffected -> 200 OK.
    let inv_party = signed_invocation(
        &target_holder,
        &node_did(),
        &[(&target_status_res, "tinycloud.delegation/status")],
        &[],
        None,
    )?;
    let (status, body) = post_auth(
        &client,
        "/delegation/status",
        &inv_party,
        Some(&status_body),
        ContentType::JSON,
    )
    .await;
    assert_eq!(status, Status::Ok, "proofless party status access: {body}");
    let parsed: Value = serde_json::from_str(&body)?;
    assert_eq!(parsed["active"], json!(true));

    Ok(())
}

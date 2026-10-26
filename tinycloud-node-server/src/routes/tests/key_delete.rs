//! Owner-signed `key.delete` credentials through real routes: they are never
//! accepted as delegations or as revocations.

use super::*;
use k256::ecdsa::SigningKey;
use rocket::http::Status;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation},
    cacaos::{
        siwe::{encode_eip55, Message, TimeStamp, Version},
        siwe_cacao::{Eip191, Payload as CacaoPayload, Signature},
    },
    siwe_recap::Capability as Recap,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::models::revocation;
use tinycloud_core::sea_orm::PaginatorTrait;

const KEY_DELETE: &str = "tinycloud.encryption/key.delete";
const KEY_CREATE: &str = "tinycloud.encryption/key.create";
const KEY_DELETE_URI_PREFIX: &str = "urn:tinycloud:encryption:key-delete:";

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
}

impl Wallet {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let address = Keccak256::digest(&public.as_bytes()[1..])[12..]
            .try_into()
            .unwrap();
        Self { key, address }
    }

    fn did(&self) -> String {
        format!("did:pkh:eip155:1:0x{}", encode_eip55(&self.address))
    }

    fn sign(&self, message: &Message) -> Signature {
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(&message.eip191_hash().unwrap())
            .unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        bytes[64] = u8::from(recovery) + 27;
        Signature::from(bytes)
    }

    /// A SIWE CACAO carrying one ReCap capability, valid for `lifetime` seconds.
    fn cacao(
        &self,
        resource: &str,
        ability: &str,
        lead: Option<String>,
        uri: &str,
        nonce: &str,
        lifetime: i64,
    ) -> String {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let stamp = |unix: i64| TimeStamp::from(OffsetDateTime::from_unix_timestamp(unix).unwrap());
        let mut recap = Recap::<Value>::default();
        recap
            .with_action_convert(resource, ability, Vec::<BTreeMap<String, Value>>::new())
            .unwrap();
        let message = recap
            .build_message(Message {
                scheme: None,
                domain: "example.com".parse().unwrap(),
                address: self.address,
                statement: lead,
                uri: uri.parse().unwrap(),
                version: Version::V1,
                chain_id: 1,
                nonce: nonce.to_string(),
                issued_at: stamp(now),
                expiration_time: Some(stamp(now + lifetime)),
                not_before: None,
                request_id: None,
                resources: vec![],
            })
            .unwrap();
        let signature = self.sign(&message);
        let cacao = CacaoPayload::from(message).sign::<Eip191>(signature);
        TinyCloudDelegation::Cacao(Box::new(cacao))
            .encode()
            .unwrap()
    }
}

fn prefix_urn(owner: &str, id: &str) -> String {
    format!("urn:tinycloud:encryption:{owner}:default/apps/{id}/")
}

fn key_urn(owner: &str, path: &str) -> String {
    format!("urn:tinycloud:encryption:{owner}:default/{path}")
}

/// A UCAN signed by the fixture owner naming `ability` on `resource`.
fn owner_ucan(
    fixture: &KvSyncFixture,
    audience: &str,
    resource: &str,
    ability: &str,
) -> Result<String> {
    let mut capabilities = Capabilities::new();
    capabilities.with_action(
        resource.parse()?,
        ability.parse::<UcanAbility>()?,
        [BTreeMap::<String, Value>::new()],
    );
    Ok(Payload {
        issuer: fixture.owner_vm.parse::<DIDURLBuf>()?,
        audience: audience.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(
            OffsetDateTime::now_utc().unix_timestamp() as f64 + 200.0,
        )?,
        nonce: Some(fixture.next_nonce()),
        facts: Some(vec![json!({"type": "tinycloud.encryption.key-admin/v1"})]),
        proof: vec![],
        attenuation: capabilities,
    }
    .sign(
        fixture.owner.get_algorithm().unwrap_or_default(),
        &fixture.owner,
    )?
    .encode()?)
}

async fn fixture() -> Result<KvSyncFixture> {
    let mut config = Config::default();
    config.encryption_network.named_keys_v1 = true;
    KvSyncFixture::new_configured(config, |rocket| rocket.mount("/", rocket::routes![revoke])).await
}

async fn post(fixture: &KvSyncFixture, uri: &str, auth: String) -> (Status, String) {
    let response = fixture
        .client
        .post(uri.to_string())
        .header(rocket::http::Header::new("Authorization", auth))
        .dispatch()
        .await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

fn owner_did(fixture: &KvSyncFixture) -> String {
    KvSyncFixture::did_of(&fixture.owner_vm)
}

#[tokio::test]
async fn delegate_refuses_key_delete_on_every_target_shape() -> Result<()> {
    let fixture = fixture().await?;
    let did_key_owner = owner_did(&fixture);
    let device = fixture.device_did();
    let wallet = Wallet::new(3);
    let wallet_did = wallet.did();

    // Positive control: the same owners can delegate key.create on the prefix,
    // so a refusal below is the refusal of key.delete.
    let control = owner_ucan(
        &fixture,
        &device,
        &prefix_urn(&did_key_owner, "foo"),
        KEY_CREATE,
    )?;
    let (status, body) = post(&fixture, "/delegate", control).await;
    assert_eq!(status, Status::Ok, "{body}");
    let control = wallet.cacao(
        &prefix_urn(&wallet_did, "com.example.foo"),
        KEY_CREATE,
        None,
        &device,
        "control0001",
        3600,
    );
    let (status, body) = post(&fixture, "/delegate", control).await;
    assert_eq!(status, Status::Ok, "{body}");

    for (label, ucan_resource, cacao_resource) in [
        (
            "app prefix",
            prefix_urn(&did_key_owner, "foo"),
            prefix_urn(&wallet_did, "com.example.foo"),
        ),
        (
            "deeper prefix",
            format!("urn:tinycloud:encryption:{did_key_owner}:default/apps/foo/x/"),
            format!("urn:tinycloud:encryption:{wallet_did}:default/apps/com.example.foo/x/"),
        ),
        (
            "exact key",
            key_urn(&did_key_owner, "apps/foo/token"),
            key_urn(&wallet_did, "apps/com.example.foo/token"),
        ),
        (
            "reserved segment prefix",
            format!("urn:tinycloud:encryption:{did_key_owner}:default/apps/"),
            format!("urn:tinycloud:encryption:{wallet_did}:default/apps/"),
        ),
        (
            "other prefix",
            format!("urn:tinycloud:encryption:{did_key_owner}:default/secrets/"),
            format!("urn:tinycloud:encryption:{wallet_did}:default/secrets/"),
        ),
    ] {
        let ucan = owner_ucan(&fixture, &device, &ucan_resource, KEY_DELETE)?;
        let (status, body) = post(&fixture, "/delegate", ucan).await;
        assert_eq!(status, Status::Unauthorized, "ucan {label}: {body}");
        assert!(
            body.contains("key-delete-not-delegable"),
            "ucan {label}: {body}"
        );

        let cacao = wallet.cacao(
            &cacao_resource,
            KEY_DELETE,
            None,
            &device,
            "nonce0001",
            3600,
        );
        let (status, body) = post(&fixture, "/delegate", cacao).await;
        assert_eq!(status, Status::Unauthorized, "cacao {label}: {body}");
        assert!(
            body.contains("key-delete-not-delegable"),
            "cacao {label}: {body}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_owner_delete_credential_is_not_a_delegation() -> Result<()> {
    let fixture = fixture().await?;
    let wallet = Wallet::new(3);
    let wallet_did = wallet.did();
    let prefix = prefix_urn(&wallet_did, "com.example.foo");
    let credential = wallet.cacao(
        &prefix,
        KEY_DELETE,
        Some(format!("Delete all TinyCloud keys under {prefix}.")),
        &format!("{KEY_DELETE_URI_PREFIX}{}", fixture.node_did),
        "nonce0002",
        300,
    );
    let (status, body) = post(&fixture, "/delegate", credential).await;
    assert_eq!(status, Status::Unauthorized, "{body}");
    assert!(body.contains("key-delete-not-delegable"), "{body}");
    Ok(())
}

#[tokio::test]
async fn revoke_refuses_owner_delete_credentials() -> Result<()> {
    let fixture = fixture().await?;
    let wallet = Wallet::new(3);
    let wallet_did = wallet.did();
    let prefix = prefix_urn(&wallet_did, "foo");
    let cacao = wallet.cacao(
        &prefix,
        KEY_DELETE,
        Some(format!("Delete all TinyCloud keys under {prefix}.")),
        &format!("{KEY_DELETE_URI_PREFIX}{}", fixture.node_did),
        "nonce0003",
        300,
    );
    let (status, body) = post(&fixture, "/revoke", cacao).await;
    assert_eq!(status, Status::Forbidden, "cacao: {body}");

    let ucan = owner_ucan(
        &fixture,
        &fixture.node_did,
        &prefix_urn(&owner_did(&fixture), "foo"),
        KEY_DELETE,
    )?;
    let (status, body) = post(&fixture, "/revoke", ucan).await;
    assert_eq!(status, Status::Forbidden, "ucan: {body}");

    // The cause is structural: neither credential names a delegation to
    // revoke (a revocation targets `ucan:<cid>`), so neither is a revocation.
    use tinycloud_auth::authorization::TinyCloudRevocation;
    use tinycloud_core::util::{RevocationError, RevocationInfo};
    let cacao = wallet.cacao(
        &prefix,
        KEY_DELETE,
        Some(format!("Delete all TinyCloud keys under {prefix}.")),
        &format!("{KEY_DELETE_URI_PREFIX}{}", fixture.node_did),
        "nonce0004",
        300,
    );
    let ucan = owner_ucan(
        &fixture,
        &fixture.node_did,
        &prefix_urn(&owner_did(&fixture), "foo"),
        KEY_DELETE,
    )?;
    for (label, header) in [("cacao", &cacao), ("ucan", &ucan)] {
        let (decoded, _) = TinyCloudRevocation::decode(header)?;
        assert!(
            matches!(
                RevocationInfo::try_from(decoded),
                Err(RevocationError::InvalidTarget)
            ),
            "{label}"
        );
    }

    assert_eq!(
        revocation::Entity::find().count(&fixture.conn).await?,
        0,
        "no revocation is stored"
    );
    Ok(())
}

// ------------------------------------------------------------ delete route

use super::encryption_keys::{
    created_key, describe_auth, describe_get, invoke_named, post_json, setup, DecryptCase,
};
use tinycloud_core::encryption_network::{
    deletion_ledger, key_id::KeyLocation, CreateNetworkRequest, EncryptionService, NetworkId,
    Threshold, KEY_BLOCK_ACTION,
};
use tinycloud_core::models::encryption_audit;

fn delete_url(network: &str) -> String {
    format!("/encryption/networks/{network}/key-actions/delete")
}

fn unix_now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

/// A UCAN by the fixture owner with the given capabilities and facts, valid
/// from `nbf` until `exp`.
fn delete_ucan(
    fixture: &KvSyncFixture,
    audience: &str,
    caps: &[(&str, &str)],
    facts: Vec<Value>,
    nbf: Option<i64>,
    exp: i64,
) -> Result<String> {
    let mut capabilities = Capabilities::new();
    for (resource, ability) in caps {
        capabilities.with_action(
            resource.parse()?,
            ability.parse::<UcanAbility>()?,
            [BTreeMap::<String, Value>::new()],
        );
    }
    Ok(Payload {
        issuer: fixture.owner_vm.parse::<DIDURLBuf>()?,
        audience: audience.parse::<DIDBuf>()?,
        not_before: nbf
            .map(|t| NumericDate::try_from_seconds(t as f64))
            .transpose()?,
        expiration: NumericDate::try_from_seconds(exp as f64)?,
        nonce: Some(fixture.next_nonce()),
        facts: Some(facts),
        proof: vec![],
        attenuation: capabilities,
    }
    .sign(
        fixture.owner.get_algorithm().unwrap_or_default(),
        &fixture.owner,
    )?
    .encode()?)
}

/// A UCAN delete invocation by the fixture owner for `key_path` (a prefix
/// keeps its trailing `/`), signed now and valid for 300 seconds.
fn delete_auth(fixture: &KvSyncFixture, network: &str, key_path: &str) -> Result<String> {
    let now = unix_now();
    delete_ucan(
        fixture,
        &fixture.node_did,
        &[(key_uri_for(network, key_path).as_str(), KEY_DELETE)],
        vec![admin_fact(&fixture.node_did, network, key_path)],
        Some(now),
        now + 300,
    )
}

async fn delete_with(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
    auth: &str,
) -> (Status, String) {
    post_json(
        &fixture.client,
        &delete_url(network),
        auth,
        &json!({ "keyPath": key_path }),
    )
    .await
}

fn ledger_paths(fixture: &KvSyncFixture) -> Vec<String> {
    let dir = fixture
        .client
        .rocket()
        .state::<LedgerDir>()
        .expect("ledger directory is managed");
    deletion_ledger::read(&dir.0.path().join("deletion-ledger.jsonl"))
        .expect("ledger reads")
        .records
        .into_iter()
        .filter_map(|record| match record {
            deletion_ledger::Record::Intent(intent) => Some(intent.keys),
            _ => None,
        })
        .flatten()
        .map(|key| key.key_path)
        .collect()
}

async fn deleted_audit_rows(fixture: &KvSyncFixture) -> Result<usize> {
    Ok(encryption_audit::Entity::find()
        .filter(encryption_audit::Column::Outcome.eq("deleted"))
        .all(&fixture.conn)
        .await?
        .len())
}

fn service(fixture: &KvSyncFixture) -> &EncryptionService {
    fixture
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed")
}

#[tokio::test]
async fn a_did_key_owner_deletes_an_app_prefix_and_decrypt_is_refused_after() -> Result<()> {
    let (fixture, network) = setup().await?;
    let public = created_key(&fixture, &network, "apps/foo/a").await;
    created_key(&fixture, &network, "apps/foo/b").await;
    let sibling = created_key(&fixture, &network, "apps/foobar/x").await;
    created_key(&fixture, &network, "docs/a").await;
    let (status, text) = invoke_named(
        &fixture,
        &network,
        "apps/foo/a",
        &DecryptCase::wrapped_to(&public),
    )
    .await;
    assert_eq!(status, Status::Ok, "{text}");

    let auth = delete_auth(&fixture, &network, "apps/foo/")?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/", &auth).await;
    assert_eq!(status, Status::Ok, "{text}");
    let view: Value = serde_json::from_str(&text)?;
    assert_eq!(
        view,
        json!({
            "keyPath": "apps/foo/",
            "state": "deleted",
            "deleted": ["apps/foo/a", "apps/foo/b"],
            "alreadyDeleted": [],
            "count": 2,
        })
    );

    let (status, text) = invoke_named(
        &fixture,
        &network,
        "apps/foo/a",
        &DecryptCase::wrapped_to(&public),
    )
    .await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_deleted"), "{text}");
    // A sibling app id and a key outside apps/ are untouched.
    let (status, text) = invoke_named(
        &fixture,
        &network,
        "apps/foobar/x",
        &DecryptCase::wrapped_to(&sibling),
    )
    .await;
    assert_eq!(status, Status::Ok, "{text}");
    let describe = describe_auth(&fixture, &network, "apps/foo/b", KEY_CREATE)?;
    let (status, text) = describe_get(&fixture, &network, "apps/foo/b", &describe).await;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(serde_json::from_str::<Value>(&text)?["state"], "deleted");

    assert_eq!(deleted_audit_rows(&fixture).await?, 2);
    assert_eq!(ledger_paths(&fixture), vec!["apps/foo/a", "apps/foo/b"]);
    Ok(())
}

#[tokio::test]
async fn per_key_delete_is_idempotent_and_refuses_a_deterministic_key() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "apps/foo/a").await;
    created_key(&fixture, &network, "docs/a").await;

    let auth = delete_auth(&fixture, &network, "apps/foo/a")?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/a", &auth).await;
    assert_eq!(status, Status::Ok, "{text}");
    let view: Value = serde_json::from_str(&text)?;
    assert_eq!(view["deleted"], json!(["apps/foo/a"]));
    assert_eq!(view["keyPath"], "apps/foo/a");

    let auth = delete_auth(&fixture, &network, "apps/foo/a")?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/a", &auth).await;
    assert_eq!(status, Status::Ok, "{text}");
    let view: Value = serde_json::from_str(&text)?;
    assert_eq!(view["deleted"], json!([]));
    assert_eq!(view["alreadyDeleted"], json!(["apps/foo/a"]));
    assert_eq!(view["count"], 0);

    let auth = delete_auth(&fixture, &network, "apps/foo/missing")?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/missing", &auth).await;
    assert_eq!(status, Status::NotFound, "{text}");
    assert!(text.starts_with("key_not_found"), "{text}");

    let auth = delete_auth(&fixture, &network, "docs/a")?;
    let (status, text) = delete_with(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Conflict, "{text}");
    assert!(text.starts_with("key_not_deletable"), "{text}");
    assert_eq!(deleted_audit_rows(&fixture).await?, 1);
    assert_eq!(ledger_paths(&fixture), vec!["apps/foo/a"]);
    Ok(())
}

#[tokio::test]
async fn a_signature_is_used_once_even_when_the_delete_failed() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "docs/a").await;
    created_key(&fixture, &network, "apps/foo/a").await;

    // A delete that fails after verification (a deterministic key) burns the
    // signature: the same header is refused, not answered 409 again.
    let auth = delete_auth(&fixture, &network, "docs/a")?;
    let (status, text) = delete_with(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Conflict, "{text}");
    let (status, text) = delete_with(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("owner_only"), "{text}");
    assert!(text.contains("already used"), "{text}");

    // A delete that succeeded cannot be replayed either.
    let auth = delete_auth(&fixture, &network, "apps/foo/")?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/", &auth).await;
    assert_eq!(status, Status::Ok, "{text}");
    let (status, text) = delete_with(&fixture, &network, "apps/foo/", &auth).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.contains("already used"), "{text}");
    Ok(())
}

#[tokio::test]
async fn delete_refuses_a_credential_that_does_not_match_the_request() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "apps/foo/a").await;
    created_key(&fixture, &network, "apps/bar/a").await;
    let refused = |status: Status, text: &str, reason: &str| {
        assert_eq!(status, Status::Forbidden, "{text}");
        assert!(text.starts_with("owner_only"), "{text}");
        assert!(text.contains(reason), "wanted {reason:?}: {text}");
    };
    let not_the_target = "not key.delete on exactly the requested target";

    // The body names another prefix than the credential.
    let auth = delete_auth(&fixture, &network, "apps/foo/")?;
    let (status, text) = delete_with(&fixture, &network, "apps/bar/", &auth).await;
    refused(status, &text, not_the_target);

    // The body names the key, the credential its prefix.
    let auth = delete_auth(&fixture, &network, "apps/foo/")?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/a", &auth).await;
    refused(status, &text, not_the_target);

    // key.block is not key.delete.
    let now = unix_now();
    let mut block_fact = admin_fact(&fixture.node_did, &network, "apps/foo/");
    block_fact["action"] = json!(KEY_BLOCK_ACTION);
    let block = delete_ucan(
        &fixture,
        &fixture.node_did,
        &[(
            key_uri_for(&network, "apps/foo/").as_str(),
            KEY_BLOCK_ACTION,
        )],
        vec![block_fact],
        Some(now),
        now + 300,
    )?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/", &block).await;
    refused(status, &text, not_the_target);

    // A credential addressed to another node.
    let other_node = delete_ucan(
        &fixture,
        "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        &[(key_uri_for(&network, "apps/foo/").as_str(), KEY_DELETE)],
        vec![admin_fact(&fixture.node_did, &network, "apps/foo/")],
        Some(now),
        now + 300,
    )?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/", &other_node).await;
    refused(status, &text, "audience is not this node");

    // A credential for another network than the URL names.
    let auth = delete_auth(&fixture, &network, "apps/foo/")?;
    let other_network = format!("{}x", network);
    let (status, text) = delete_with(&fixture, &other_network, "apps/foo/", &auth).await;
    refused(status, &text, not_the_target);

    // A UCAN without nbf has no start to measure its lifetime from.
    let no_nbf = delete_ucan(
        &fixture,
        &fixture.node_did,
        &[(key_uri_for(&network, "apps/foo/").as_str(), KEY_DELETE)],
        vec![admin_fact(&fixture.node_did, &network, "apps/foo/")],
        None,
        now + 300,
    )?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/", &no_nbf).await;
    refused(status, &text, "must carry nbf");

    // A long-lived UCAN is refused for its whole life, also near its end.
    let long_lived = delete_ucan(
        &fixture,
        &fixture.node_did,
        &[(key_uri_for(&network, "apps/foo/").as_str(), KEY_DELETE)],
        vec![admin_fact(&fixture.node_did, &network, "apps/foo/")],
        Some(now - 35_760),
        now + 240,
    )?;
    let (status, text) = delete_with(&fixture, &network, "apps/foo/", &long_lived).await;
    refused(status, &text, "lifetime exceeds 300 seconds");

    // No Authorization header.
    let response = fixture
        .client
        .post(delete_url(&network))
        .header(rocket::http::ContentType::JSON)
        .body(json!({ "keyPath": "apps/foo/" }).to_string())
        .dispatch()
        .await;
    assert_eq!(response.status(), Status::Unauthorized);

    // Nothing above deleted anything.
    assert_eq!(deleted_audit_rows(&fixture).await?, 0);
    assert!(ledger_paths(&fixture).is_empty());
    Ok(())
}

fn key_uri_for(network: &str, path: &str) -> String {
    format!("{network}/{path}")
}

fn admin_fact(node_did: &str, network: &str, key_path: &str) -> Value {
    json!({
        "type": "tinycloud.encryption.key-admin/v1",
        "targetNode": node_did,
        "networkId": network,
        "keyPath": key_path,
        "action": KEY_DELETE,
        "bodyHash": tinycloud_core::encryption_network::canonical::canonical_hash(
            &json!({ "keyPath": key_path })
        ),
    })
}

#[tokio::test]
async fn delete_key_paths_outside_the_two_accepted_shapes_are_bad_requests() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "apps/foo/a").await;
    let auth = delete_auth(&fixture, &network, "apps/foo/")?;
    for key_path in [
        "apps/",
        "apps//",
        "apps/foo/x/",
        "apps/foo//",
        "apps/foo",
        "apps/Foo/",
        "apps",
        "secrets/",
        "secrets/x/",
        "appsx/y/",
        "/",
        "",
    ] {
        let (status, text) = delete_with(&fixture, &network, key_path, &auth).await;
        assert_eq!(status, Status::BadRequest, "{key_path:?}: {text}");
        assert!(text.starts_with("key_path_invalid"), "{key_path:?}: {text}");
    }
    // These never reached the credential: it is still unused.
    let (status, text) = delete_with(&fixture, &network, "apps/foo/", &auth).await;
    assert_eq!(status, Status::Ok, "{text}");
    Ok(())
}

#[tokio::test]
async fn delete_body_that_is_not_a_key_path_object_is_a_bad_request() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = post_json(
        &fixture.client,
        &delete_url(&network),
        "x",
        &json!({ "path": "apps/foo/" }),
    )
    .await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(text.starts_with("request body is malformed"), "{text}");
    Ok(())
}

// ------------------------------------------------------------ did:pkh owner

/// A network owned by `wallet`, with `paths` created as deletable keys.
async fn wallet_network(
    fixture: &KvSyncFixture,
    wallet: &Wallet,
    paths: &[&str],
) -> Result<NetworkId> {
    let service = service(fixture);
    let network = service
        .create_one_of_one_network(CreateNetworkRequest {
            name: "default".to_string(),
            owner_did: wallet.did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .network_id;
    for path in paths {
        service
            .create_key(&KeyLocation::new(&network, path)?, true)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    Ok(network)
}

fn prefix_credential(
    fixture: &KvSyncFixture,
    wallet: &Wallet,
    network: &NetworkId,
    id: &str,
    nonce: &str,
) -> String {
    let prefix = format!("{network}/apps/{id}/");
    wallet.cacao(
        &prefix,
        KEY_DELETE,
        Some(format!("Delete all TinyCloud keys under {prefix}.")),
        &format!("{KEY_DELETE_URI_PREFIX}{}", fixture.node_did),
        nonce,
        300,
    )
}

#[tokio::test]
async fn a_did_pkh_owner_deletes_an_app_prefix_with_a_siwe_credential() -> Result<()> {
    let (fixture, _) = setup().await?;
    let wallet = Wallet::new(5);
    let network = wallet_network(
        &fixture,
        &wallet,
        &["apps/foo/a", "apps/foo/b", "apps/bar/a"],
    )
    .await?;
    let credential = prefix_credential(&fixture, &wallet, &network, "foo", "pkhnonce001");

    let (status, text) =
        delete_with(&fixture, &network.to_string(), "apps/foo/", &credential).await;
    assert_eq!(status, Status::Ok, "{text}");
    let view: Value = serde_json::from_str(&text)?;
    assert_eq!(view["deleted"], json!(["apps/foo/a", "apps/foo/b"]));
    assert_eq!(view["count"], 2);
    assert_eq!(ledger_paths(&fixture), vec!["apps/foo/a", "apps/foo/b"]);

    // The same credential is used up.
    let (status, text) =
        delete_with(&fixture, &network.to_string(), "apps/foo/", &credential).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.contains("already used"), "{text}");
    Ok(())
}

#[tokio::test]
async fn a_did_pkh_credential_must_match_the_request_and_the_node() -> Result<()> {
    let (fixture, _) = setup().await?;
    let wallet = Wallet::new(5);
    let other = Wallet::new(6);
    let network = wallet_network(&fixture, &wallet, &["apps/foo/a", "apps/bar/a"]).await?;
    let url_network = network.to_string();
    let prefix = format!("{network}/apps/foo/");
    let uri = format!("{KEY_DELETE_URI_PREFIX}{}", fixture.node_did);
    let lead = format!("Delete all TinyCloud keys under {prefix}.");

    let refused: Vec<(&str, String, &str)> = vec![
        (
            "another wallet signs",
            {
                let other_network = NetworkId::new(other.did(), "default".to_string())?;
                let p = format!("{other_network}/apps/foo/");
                other.cacao(&p, KEY_DELETE, Some(format!("Delete all TinyCloud keys under {p}.")), &uri, "n-other-01", 300)
            },
            "apps/foo/",
        ),
        (
            "the credential names another prefix",
            prefix_credential(&fixture, &wallet, &network, "bar", "n-prefix-01"),
            "apps/foo/",
        ),
        (
            "another node",
            wallet.cacao(
                &prefix,
                KEY_DELETE,
                Some(lead.clone()),
                &format!("{KEY_DELETE_URI_PREFIX}did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"),
                "n-node-001",
                300,
            ),
            "apps/foo/",
        ),
        (
            "another ability",
            wallet.cacao(&prefix, KEY_BLOCK_ACTION, Some(lead.clone()), &uri, "n-ability-1", 300),
            "apps/foo/",
        ),
        (
            "the statement does not state the delete",
            wallet.cacao(&prefix, KEY_DELETE, Some("Sign in.".to_string()), &uri, "n-stmt-001", 300),
            "apps/foo/",
        ),
        (
            "a lifetime over 300 seconds",
            wallet.cacao(&prefix, KEY_DELETE, Some(lead.clone()), &uri, "n-life-001", 301),
            "apps/foo/",
        ),
    ];
    for (label, credential, key_path) in refused {
        let (status, text) = delete_with(&fixture, &url_network, key_path, &credential).await;
        assert_eq!(status, Status::Forbidden, "{label}: {text}");
        assert!(text.starts_with("owner_only"), "{label}: {text}");
    }
    assert!(ledger_paths(&fixture).is_empty());
    assert_eq!(deleted_audit_rows(&fixture).await?, 0);

    // A credential for the prefix refuses to delete one key of it.
    let credential = prefix_credential(&fixture, &wallet, &network, "foo", "n-ok-000001");
    let (status, text) = delete_with(&fixture, &url_network, "apps/foo/a", &credential).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    Ok(())
}

#[tokio::test]
async fn delete_refuses_a_network_id_that_is_not_in_canonical_form() -> Result<()> {
    let (fixture, _) = setup().await?;
    let wallet = Wallet::new(5);
    let network = wallet_network(&fixture, &wallet, &["apps/foo/a"]).await?;
    let credential = prefix_credential(&fixture, &wallet, &network, "foo", "n-canon-0001");
    // The same owner address in lower case names the same network but is not
    // the canonical spelling of its id.
    let lowercase = network.to_string().to_lowercase();
    assert_ne!(lowercase, network.to_string());
    let (status, text) = delete_with(&fixture, &lowercase, "apps/foo/", &credential).await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(text.contains("canonical form"), "{text}");
    assert!(ledger_paths(&fixture).is_empty());

    // Nothing was consumed: the credential still deletes through the canonical id.
    let (status, text) =
        delete_with(&fixture, &network.to_string(), "apps/foo/", &credential).await;
    assert_eq!(status, Status::Ok, "{text}");
    Ok(())
}

#[tokio::test]
async fn delete_body_with_another_field_is_a_bad_request() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = post_json(
        &fixture.client,
        &delete_url(&network),
        "x",
        &json!({ "keyPath": "apps/foo/", "extra": true }),
    )
    .await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(text.starts_with("request body is malformed"), "{text}");
    Ok(())
}

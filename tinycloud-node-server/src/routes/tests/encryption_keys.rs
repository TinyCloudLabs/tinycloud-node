//! Route-level tests for key create, public key GET, authenticated describe
//! GET, and key block/unblock. Requests are native UCAN invocations signed by
//! the fixture owner and sent through Rocket's local client.

use super::*;
use rocket::http::{ContentType, Header, Status};
use serde_json::{json, Value};
use tinycloud_auth::ssi::claims::jwt::NumericDate;
use tinycloud_core::encryption::ColumnEncryption;
use tinycloud_core::encryption_network::{
    backend::wrap_to_public_key,
    canonical::canonical_hash,
    key_id::KeyLocation,
    protocol::{DECRYPT_ACTION, DECRYPT_REQUEST_TYPE, KEY_ADMIN_TYPE, KEY_DESCRIBE_TYPE},
    types::ALG_X25519_AES256GCM,
    CreateNetworkRequest, EncryptionService, NetworkId, Threshold, KEY_BLOCK_ACTION,
    KEY_CREATE_ACTION, KEY_UNBLOCK_ACTION,
};
use tinycloud_core::models::encryption_audit;
use x25519_dalek::{PublicKey, StaticSecret};

/// Owner DID: the `did:key` part of the owner verification method.
pub(super) fn owner_did(fixture: &KvSyncFixture) -> String {
    fixture
        .owner_vm
        .split('#')
        .next()
        .unwrap_or_default()
        .to_string()
}

/// Fixture with the key routes mounted, named keys on, and one active 1-of-1
/// network.
pub(super) async fn setup() -> Result<(KvSyncFixture, String)> {
    setup_with(true).await
}

/// As [`setup`], with `[encryption_network] named_keys_v1` set to
/// `named_keys`. The fixture mounts the key handlers either way; production
/// mounting is covered by `policy_v3::named_keys_gate_tests`. What this
/// setting changes here is what `/delegate` and `/invoke` accept.
async fn setup_with(named_keys: bool) -> Result<(KvSyncFixture, String)> {
    let mut config = Config::default();
    config.encryption_network.named_keys_v1 = named_keys;
    let fixture = KvSyncFixture::new_configured(config, |rocket| {
        rocket
            .mount(
                "/",
                rocket::routes![
                    crate::routes::encryption::create_network,
                    crate::routes::encryption::create_encryption_key,
                    crate::routes::encryption::describe_encryption_key,
                    crate::routes::encryption::public_encryption_key,
                    crate::routes::encryption::block_encryption_key,
                    crate::routes::encryption::unblock_encryption_key,
                    crate::routes::encryption::delete_encryption_key,
                    crate::routes::encryption::decrypt
                ],
            )
            .manage(crate::routes::public::RateLimiter::new(
                &crate::config::PublicSpacesConfig::default(),
            ))
    })
    .await?;
    let service = fixture
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed");
    let network = service
        .create_one_of_one_network(CreateNetworkRequest {
            name: "net".to_string(),
            owner_did: owner_did(&fixture),
            threshold: Threshold::one_of_one(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    let network_id = network.network_id.to_string();
    Ok((fixture, network_id))
}

/// Owner-issued invocation to `audience` with `caps` (resource, ability), the
/// given facts, and the given expiration. No proof chain.
fn signed(
    fixture: &KvSyncFixture,
    audience: &str,
    caps: &[(&str, &str)],
    facts: Vec<Value>,
    expiration: NumericDate,
) -> Result<String> {
    use tinycloud_auth::ssi::{
        dids::{DIDBuf, DIDURLBuf},
        ucan::Payload,
    };
    use tinycloud_auth::ucan_capabilities_object::Capabilities;
    let mut capabilities = Capabilities::new();
    for (uri, action) in caps {
        capabilities.with_action(
            uri.parse()?,
            action.parse::<UcanAbility>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
    }
    Ok(Payload {
        issuer: fixture.owner_vm.parse::<DIDURLBuf>()?,
        audience: audience.parse::<DIDBuf>()?,
        not_before: None,
        expiration,
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

/// Current-expiry invocation to `audience`.
pub(super) fn invocation(
    fixture: &KvSyncFixture,
    audience: &str,
    caps: &[(&str, &str)],
    facts: Vec<Value>,
) -> Result<String> {
    signed(fixture, audience, caps, facts, test_invocation_expiration())
}

fn key_uri(network: &str, key_path: &str) -> String {
    format!("{network}/{key_path}")
}

/// Key-admin facts. `body_hash` is passed in so tests can break it.
fn admin_fact_for(
    target_node: &str,
    network: &str,
    key_path: &str,
    action: &str,
    body_hash: &str,
) -> Value {
    json!({
        "type": KEY_ADMIN_TYPE,
        "targetNode": target_node,
        "networkId": network,
        "keyPath": key_path,
        "action": action,
        "bodyHash": body_hash,
    })
}

/// Key-describe facts.
fn describe_fact_for(target_node: &str, network: &str, key_path: &str) -> Value {
    json!({
        "type": KEY_DESCRIBE_TYPE,
        "targetNode": target_node,
        "networkId": network,
        "keyPath": key_path,
    })
}

/// A valid key-admin invocation for `body` on the exact key, with `action`
/// as both the capability ability and the fact action.
pub(super) fn admin_auth(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
    action: &str,
    body: &Value,
) -> Result<String> {
    let cap = key_uri(network, key_path);
    invocation(
        fixture,
        &fixture.node_did,
        &[(cap.as_str(), action)],
        vec![admin_fact_for(
            &fixture.node_did,
            network,
            key_path,
            action,
            &canonical_hash(body),
        )],
    )
}

/// A valid describe invocation on the exact key with `ability`.
pub(super) fn describe_auth(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
    ability: &str,
) -> Result<String> {
    let cap = key_uri(network, key_path);
    invocation(
        fixture,
        &fixture.node_did,
        &[(cap.as_str(), ability)],
        vec![describe_fact_for(&fixture.node_did, network, key_path)],
    )
}

fn keys_url(network: &str) -> String {
    format!("/encryption/networks/{network}/keys")
}

fn key_url(network: &str, key_path: &str) -> String {
    format!("/encryption/networks/{network}/keys/{key_path}")
}

fn action_url(network: &str, action: &str) -> String {
    format!("/encryption/networks/{network}/key-actions/{action}")
}

pub(super) async fn post_json(
    client: &rocket::local::asynchronous::Client,
    uri: &str,
    auth: &str,
    body: &Value,
) -> (Status, String) {
    let response = client
        .post(uri.to_string())
        .header(ContentType::JSON)
        .header(Header::new("Authorization", auth.to_string()))
        .body(body.to_string())
        .dispatch()
        .await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

async fn get(
    client: &rocket::local::asynchronous::Client,
    uri: &str,
    auth: Option<&str>,
) -> (Status, String) {
    // The public route reads the client IP; the local client has none unless set.
    let mut request = client
        .get(uri.to_string())
        .remote("127.0.0.1:0".parse().expect("valid socket address"));
    if let Some(auth) = auth {
        request = request.header(Header::new("Authorization", auth.to_string()));
    }
    let response = request.dispatch().await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

/// POST a create request on the exact key with a valid invocation.
pub(super) async fn create(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
    deletable: bool,
) -> Result<(Status, String)> {
    let body = json!({"keyPath": key_path, "deletable": deletable});
    let auth = admin_auth(fixture, network, key_path, KEY_CREATE_ACTION, &body)?;
    Ok(post_json(&fixture.client, &keys_url(network), &auth, &body).await)
}

/// POST a block or unblock request on the exact key with a valid invocation.
async fn key_action(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
    action: &str,
) -> Result<(Status, String)> {
    let ability = match action {
        "block" => KEY_BLOCK_ACTION,
        "unblock" => KEY_UNBLOCK_ACTION,
        other => panic!("unknown key action {other}"),
    };
    let body = json!({"keyPath": key_path});
    let auth = admin_auth(fixture, network, key_path, ability, &body)?;
    Ok(post_json(&fixture.client, &action_url(network, action), &auth, &body).await)
}

/// Public GET of a key, no `Authorization` header.
async fn public_get(fixture: &KvSyncFixture, network: &str, key_path: &str) -> (Status, String) {
    get(&fixture.client, &key_url(network, key_path), None).await
}

/// Authenticated describe GET of a key.
pub(super) async fn describe_get(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
    auth: &str,
) -> (Status, String) {
    get(&fixture.client, &key_url(network, key_path), Some(auth)).await
}

fn field_names(value: &Value) -> Vec<String> {
    let mut fields: Vec<String> = value
        .as_object()
        .expect("object body")
        .keys()
        .cloned()
        .collect();
    fields.sort();
    fields
}

fn state_of(text: &str) -> Result<String> {
    Ok(serde_json::from_str::<Value>(text)?["state"]
        .as_str()
        .unwrap_or_default()
        .to_string())
}

// ---------------------------------------------------------------- success

#[tokio::test]
async fn key_lifecycle_round_trips_through_every_route() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key = "docs/a";

    let (status, text) = create(&fixture, &network, key, false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let created: Value = serde_json::from_str(&text)?;
    assert_eq!(created["state"], "active");
    let public_key = created["publicEncryptionKey"].clone();

    let (status, text) = public_get(&fixture, &network, key).await;
    assert_eq!(status, Status::Ok, "public: {text}");
    let public: Value = serde_json::from_str(&text)?;
    assert_eq!(
        field_names(&public),
        vec![
            "alg",
            "keyPath",
            "keyVersion",
            "networkId",
            "publicEncryptionKey"
        ]
    );
    assert_eq!(public["publicEncryptionKey"], public_key);

    let auth = describe_auth(&fixture, &network, key, KEY_CREATE_ACTION)?;
    let (status, text) = describe_get(&fixture, &network, key, &auth).await;
    assert_eq!(status, Status::Ok, "describe: {text}");
    assert_eq!(state_of(&text)?, "active");

    let (status, text) = key_action(&fixture, &network, key, "block").await?;
    assert_eq!(status, Status::Ok, "block: {text}");
    assert_eq!(state_of(&text)?, "blocked");

    let (status, text) = public_get(&fixture, &network, key).await;
    assert_eq!(status, Status::Ok, "public while blocked: {text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["publicEncryptionKey"],
        public_key
    );

    let (status, text) = key_action(&fixture, &network, key, "unblock").await?;
    assert_eq!(status, Status::Ok, "unblock: {text}");
    assert_eq!(state_of(&text)?, "active");
    Ok(())
}

#[tokio::test]
async fn create_is_idempotent_for_an_identical_active_key() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, first) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "first create: {first}");
    let (status, second) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "second create: {second}");
    assert_eq!(first, second);
    Ok(())
}

#[tokio::test]
async fn describe_returns_the_full_descriptor_for_each_permitted_ability() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key = "docs/a";
    let (status, text) = create(&fixture, &network, key, false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    for ability in [
        DECRYPT_ACTION,
        KEY_CREATE_ACTION,
        KEY_BLOCK_ACTION,
        KEY_UNBLOCK_ACTION,
    ] {
        let auth = describe_auth(&fixture, &network, key, ability)?;
        let (status, text) = describe_get(&fixture, &network, key, &auth).await;
        assert_eq!(status, Status::Ok, "describe with {ability}: {text}");
        let body: Value = serde_json::from_str(&text)?;
        assert_eq!(body["state"], "active");
        assert_eq!(body["networkId"], network);
        assert_eq!(body["keyPath"], key);
        assert_eq!(body["alg"], "x25519-aes256gcm/v1");
        assert_eq!(body["keyVersion"], 1);
        assert!(body["publicEncryptionKey"]
            .as_str()
            .is_some_and(|s| !s.is_empty()));
        assert!(body["kind"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(body["createdAt"].as_str().is_some_and(|s| !s.is_empty()));
        assert!(body["updatedAt"].as_str().is_some_and(|s| !s.is_empty()));
    }
    Ok(())
}

#[tokio::test]
async fn public_shape_is_identical_for_missing_blocked_and_active_keys() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, active) = create(&fixture, &network, "shape/active", false).await?;
    assert_eq!(status, Status::Ok, "active create: {active}");
    let (status, blocked) = create(&fixture, &network, "shape/blocked", false).await?;
    assert_eq!(status, Status::Ok, "blocked create: {blocked}");
    let (status, text) = key_action(&fixture, &network, "shape/blocked", "block").await?;
    assert_eq!(status, Status::Ok, "block: {text}");

    let mut shapes = Vec::new();
    for key in ["shape/active", "shape/blocked", "shape/missing"] {
        let (status, text) = public_get(&fixture, &network, key).await;
        assert_eq!(status, Status::Ok, "public {key}: {text}");
        let body: Value = serde_json::from_str(&text)?;
        assert_eq!(body["alg"], "x25519-aes256gcm/v1", "alg for {key}");
        assert!(body["keyVersion"].is_number(), "keyVersion for {key}");
        shapes.push(field_names(&body));
    }
    assert!(
        shapes.windows(2).all(|pair| pair[0] == pair[1]),
        "{shapes:?}"
    );
    Ok(())
}

#[tokio::test]
async fn block_and_unblock_are_idempotent() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");

    for _ in 0..2 {
        let (status, text) = key_action(&fixture, &network, "docs/a", "block").await?;
        assert_eq!(status, Status::Ok, "block: {text}");
        assert_eq!(state_of(&text)?, "blocked");
    }
    for _ in 0..2 {
        let (status, text) = key_action(&fixture, &network, "docs/a", "unblock").await?;
        assert_eq!(status, Status::Ok, "unblock: {text}");
        assert_eq!(state_of(&text)?, "active");
    }
    Ok(())
}

// ----------------------------------------------------------------- create

#[tokio::test]
async fn create_refuses_wrong_audience() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let cap = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &owner_did(&fixture),
        &[(cap.as_str(), KEY_CREATE_ACTION)],
        vec![admin_fact_for(
            &fixture.node_did,
            &network,
            "docs/a",
            KEY_CREATE_ACTION,
            &canonical_hash(&body),
        )],
    )?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_wrong_target_node() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let cap = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(cap.as_str(), KEY_CREATE_ACTION)],
        vec![admin_fact_for(
            &owner_did(&fixture),
            &network,
            "docs/a",
            KEY_CREATE_ACTION,
            &canonical_hash(&body),
        )],
    )?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_expired_invocation() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let cap = key_uri(&network, "docs/a");
    let expired = NumericDate::try_from_seconds(
        time::OffsetDateTime::now_utc().unix_timestamp() as f64 - 3600.0,
    )?;
    let auth = signed(
        &fixture,
        &fixture.node_did,
        &[(cap.as_str(), KEY_CREATE_ACTION)],
        vec![admin_fact_for(
            &fixture.node_did,
            &network,
            "docs/a",
            KEY_CREATE_ACTION,
            &canonical_hash(&body),
        )],
        expired,
    )?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_a_capability_for_another_ability() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let cap = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(cap.as_str(), DECRYPT_ACTION)],
        vec![admin_fact_for(
            &fixture.node_did,
            &network,
            "docs/a",
            KEY_CREATE_ACTION,
            &canonical_hash(&body),
        )],
    )?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_a_capability_on_a_prefix() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let prefix = format!("{network}/docs/");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(prefix.as_str(), KEY_CREATE_ACTION)],
        vec![admin_fact_for(
            &fixture.node_did,
            &network,
            "docs/a",
            KEY_CREATE_ACTION,
            &canonical_hash(&body),
        )],
    )?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_a_capability_on_the_bare_network() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(network.as_str(), KEY_CREATE_ACTION)],
        vec![admin_fact_for(
            &fixture.node_did,
            &network,
            "docs/a",
            KEY_CREATE_ACTION,
            &canonical_hash(&body),
        )],
    )?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_two_capabilities() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let cap = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[
            (cap.as_str(), KEY_CREATE_ACTION),
            (key_uri(&network, "docs/b").as_str(), KEY_CREATE_ACTION),
        ],
        vec![admin_fact_for(
            &fixture.node_did,
            &network,
            "docs/a",
            KEY_CREATE_ACTION,
            &canonical_hash(&body),
        )],
    )?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_a_missing_body_hash() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let cap = key_uri(&network, "docs/a");
    let fact = json!({
        "type": KEY_ADMIN_TYPE,
        "targetNode": fixture.node_did,
        "networkId": network,
        "keyPath": "docs/a",
        "action": KEY_CREATE_ACTION,
    });
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(cap.as_str(), KEY_CREATE_ACTION)],
        vec![fact],
    )?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(text.contains("bodyHash"), "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_a_mismatched_body_hash() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let other = json!({"keyPath": "docs/b", "deletable": false});
    let auth = admin_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION, &other)?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_a_replayed_invocation() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": false});
    let auth = admin_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION, &body)?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Ok, "first: {text}");
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "replay: {text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_a_grammar_invalid_key_path() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/Bad", "deletable": false});
    let auth = admin_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION, &body)?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(text.starts_with("key_path_invalid"), "{text}");
    Ok(())
}

#[tokio::test]
async fn create_requires_the_deletable_flag_to_match_the_path() -> Result<()> {
    let (fixture, network) = setup().await?;
    for (path, deletable) in [("docs/a", true), ("apps/foo/x", false)] {
        let (status, text) = create(&fixture, &network, path, deletable).await?;
        assert_eq!(status, Status::BadRequest, "{path} {deletable}: {text}");
        assert!(text.starts_with("key_path_invalid"), "{text}");
        let auth = describe_auth(&fixture, &network, path, KEY_CREATE_ACTION)?;
        let (status, text) = describe_get(&fixture, &network, path, &auth).await;
        assert_eq!(status, Status::NotFound, "no key after refusal: {text}");
        assert!(text.starts_with("key_not_found"), "{text}");
    }
    // An omitted flag is `false`.
    let body = json!({"keyPath": "apps/foo/x"});
    let auth = admin_auth(&fixture, &network, "apps/foo/x", KEY_CREATE_ACTION, &body)?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::BadRequest, "{text}");

    let (status, text) = create(&fixture, &network, "apps/foo/x", true).await?;
    assert_eq!(status, Status::Ok, "{text}");
    let value: Value = serde_json::from_str(&text)?;
    assert_eq!(value["kind"], "deletable");
    assert_eq!(value["state"], "active");
    assert_eq!(value["keyVersion"], 1);
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(
        serde_json::from_str::<Value>(&text)?["kind"],
        "deterministic"
    );
    Ok(())
}

#[tokio::test]
async fn create_rejects_unknown_body_fields() -> Result<()> {
    let (fixture, network) = setup().await?;
    for body in [
        json!({"keyPath": "docs/a", "shreddable": true}),
        json!({"keyPath": "docs/a", "shreddable": false}),
    ] {
        let auth = admin_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION, &body)?;
        let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
        assert_eq!(status, Status::BadRequest, "{body}: {text}");
        assert!(
            text.starts_with("request body is malformed: "),
            "{body}: {text}"
        );
    }
    let auth = describe_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION)?;
    let (status, text) = describe_get(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::NotFound, "no key after refusal: {text}");
    assert!(text.starts_with("key_not_found"), "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_a_path_that_exists_in_blocked_state() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let (status, text) = key_action(&fixture, &network, "docs/a", "block").await?;
    assert_eq!(status, Status::Ok, "block: {text}");
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Conflict, "{text}");
    assert!(text.starts_with("key_exists"), "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_an_unknown_network() -> Result<()> {
    let (fixture, _network) = setup().await?;
    let absent = NetworkId::new(owner_did(&fixture), "absent")?.to_string();
    let (status, text) = create(&fixture, &absent, "docs/a", false).await?;
    assert_eq!(status, Status::NotFound, "{text}");
    assert!(text.starts_with("network_not_found"), "{text}");
    Ok(())
}

#[tokio::test]
async fn create_refuses_once_the_network_key_cap_is_reached() -> Result<()> {
    let (fixture, network) = setup().await?;
    let service = fixture
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed");
    let network_id: NetworkId = network.parse()?;
    for index in 0..tinycloud_core::encryption_network::keys::DEFAULT_KEY_CAP_PER_NETWORK {
        let loc = KeyLocation::new(&network_id, &format!("fill/{index}"))
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        service
            .create_key(&loc, false)
            .await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    let (status, text) = create(&fixture, &network, "docs/over", false).await?;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_limit_exceeded"), "{text}");
    Ok(())
}

// --------------------------------------------------------- public and describe

/// Full error text for a percent-escape on a key route URL.
const PERCENT_KEY_ROUTE_ERROR: &str = "key_path_invalid: percent-encoding is not accepted in key route URLs (send the network id and key path unencoded)";

/// The network id with its last colon percent-encoded, as a client would send it.
fn percent_encoded_network(network: &str) -> String {
    let (head, name) = network.rsplit_once(':').expect("network id has a colon");
    format!("{head}%3A{name}")
}

#[tokio::test]
async fn public_get_refuses_a_percent_in_the_key_path() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = public_get(&fixture, &network, "docs%41").await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert_eq!(text, PERCENT_KEY_ROUTE_ERROR);
    Ok(())
}

#[tokio::test]
async fn describe_refuses_a_percent_in_the_key_path() -> Result<()> {
    let (fixture, network) = setup().await?;
    let auth = describe_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION)?;
    let (status, text) = describe_get(&fixture, &network, "docs%41", &auth).await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert_eq!(text, PERCENT_KEY_ROUTE_ERROR);
    Ok(())
}

#[tokio::test]
async fn public_get_refuses_a_percent_escape_in_the_network_id() -> Result<()> {
    let (fixture, network) = setup().await?;
    let encoded = percent_encoded_network(&network);
    let (status, text) = public_get(&fixture, &encoded, "docs/a").await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert_eq!(text, PERCENT_KEY_ROUTE_ERROR);
    Ok(())
}

#[tokio::test]
async fn describe_refuses_a_percent_escape_in_the_network_id() -> Result<()> {
    let (fixture, network) = setup().await?;
    let auth = describe_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION)?;
    let encoded = percent_encoded_network(&network);
    let (status, text) = describe_get(&fixture, &encoded, "docs/a", &auth).await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert_eq!(text, PERCENT_KEY_ROUTE_ERROR);
    Ok(())
}

#[tokio::test]
async fn public_get_of_a_clean_raw_path_with_a_colon_network_id_succeeds() -> Result<()> {
    let (fixture, network) = setup().await?;
    assert!(network.contains(':'), "{network}");
    let (status, text) = public_get(&fixture, &network, "docs/a").await;
    assert_eq!(status, Status::Ok, "{text}");
    Ok(())
}

#[tokio::test]
async fn public_get_refuses_a_grammar_invalid_key_path() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = public_get(&fixture, &network, "docs/Bad").await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(text.starts_with("key_path_invalid"), "{text}");
    Ok(())
}

#[tokio::test]
async fn key_paths_outside_the_grammar_are_refused_as_received() -> Result<()> {
    let (fixture, network) = setup().await?;
    let auth = describe_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION)?;
    for key_path in [
        "docs//a",
        "docs/a/",
        "docs/x/../a",
        "docs/./a",
        "docs%2fa",
        ".hidden/a",
        "docs/a:",
        "docs/*a",
    ] {
        let (status, text) = public_get(&fixture, &network, key_path).await;
        assert_eq!(status, Status::BadRequest, "public {key_path}: {text}");
        assert!(
            text.starts_with("key_path_invalid"),
            "public {key_path}: {text}"
        );
        let (status, text) = describe_get(&fixture, &network, key_path, &auth).await;
        assert_eq!(status, Status::BadRequest, "describe {key_path}: {text}");
        assert!(
            text.starts_with("key_path_invalid"),
            "describe {key_path}: {text}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn key_routes_refuse_a_network_id_that_is_not_canonical() -> Result<()> {
    let (fixture, _) = setup().await?;
    let network =
        "urn:tinycloud:encryption:did:pkh:eip155:1:0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266:net";
    let (status, text) = public_get(&fixture, network, "docs/a").await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(
        text.starts_with("network id is not in canonical form"),
        "{text}"
    );
    Ok(())
}

#[tokio::test]
async fn public_get_is_rate_limited_per_client_ip() -> Result<()> {
    let (fixture, network) = setup().await?;
    let mut limited = None;
    for _ in 0..40 {
        let (status, text) = public_get(&fixture, &network, "docs/a").await;
        if status == Status::TooManyRequests {
            limited = Some(text);
            break;
        }
    }
    let text = limited.ok_or_else(|| anyhow::anyhow!("no request was rate limited"))?;
    assert_eq!(text, "Rate limit exceeded");
    Ok(())
}

#[tokio::test]
async fn describe_missing_key_is_not_found() -> Result<()> {
    let (fixture, network) = setup().await?;
    let auth = describe_auth(&fixture, &network, "docs/absent", KEY_CREATE_ACTION)?;
    let (status, text) = describe_get(&fixture, &network, "docs/absent", &auth).await;
    assert_eq!(status, Status::NotFound, "{text}");
    assert!(text.starts_with("key_not_found"), "{text}");
    Ok(())
}

#[tokio::test]
async fn describe_refuses_admin_facts() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let body = json!({"keyPath": "docs/a"});
    let cap = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(cap.as_str(), KEY_CREATE_ACTION)],
        vec![admin_fact_for(
            &fixture.node_did,
            &network,
            "docs/a",
            KEY_CREATE_ACTION,
            &canonical_hash(&body),
        )],
    )?;
    let (status, text) = describe_get(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn describe_refuses_a_capability_on_a_prefix() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let prefix = format!("{network}/docs/");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(prefix.as_str(), KEY_CREATE_ACTION)],
        vec![describe_fact_for(&fixture.node_did, &network, "docs/a")],
    )?;
    let (status, text) = describe_get(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn describe_refuses_two_capabilities() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let cap = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[
            (cap.as_str(), KEY_CREATE_ACTION),
            (cap.as_str(), DECRYPT_ACTION),
        ],
        vec![describe_fact_for(&fixture.node_did, &network, "docs/a")],
    )?;
    let (status, text) = describe_get(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn describe_refuses_a_capability_outside_the_describe_abilities() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let auth = describe_auth(&fixture, &network, "docs/a", "tinycloud.kv/get")?;
    let (status, text) = describe_get(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn describe_refuses_a_wrong_target_node() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let cap = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(cap.as_str(), KEY_CREATE_ACTION)],
        vec![describe_fact_for(&owner_did(&fixture), &network, "docs/a")],
    )?;
    let (status, text) = describe_get(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn describe_refuses_a_replayed_invocation() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let auth = describe_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION)?;
    let (status, text) = describe_get(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Ok, "first: {text}");
    let (status, text) = describe_get(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Unauthorized, "replay: {text}");
    Ok(())
}

#[tokio::test]
async fn describe_without_an_authorization_header_returns_the_public_shape() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let (status, text) = public_get(&fixture, &network, "docs/a").await;
    assert_eq!(status, Status::Ok, "{text}");
    let body: Value = serde_json::from_str(&text)?;
    assert_eq!(
        field_names(&body),
        vec![
            "alg",
            "keyPath",
            "keyVersion",
            "networkId",
            "publicEncryptionKey"
        ]
    );
    Ok(())
}

// ----------------------------------------------------------- block/unblock

#[tokio::test]
async fn unblock_refuses_a_block_capability() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let body = json!({"keyPath": "docs/a"});
    let cap = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(cap.as_str(), KEY_BLOCK_ACTION)],
        vec![admin_fact_for(
            &fixture.node_did,
            &network,
            "docs/a",
            KEY_UNBLOCK_ACTION,
            &canonical_hash(&body),
        )],
    )?;
    let (status, text) = post_json(
        &fixture.client,
        &action_url(&network, "unblock"),
        &auth,
        &body,
    )
    .await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn block_refuses_a_body_hash_for_another_body() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let signed_body = json!({"keyPath": "docs/b"});
    let auth = admin_auth(&fixture, &network, "docs/a", KEY_BLOCK_ACTION, &signed_body)?;
    let sent_body = json!({"keyPath": "docs/a"});
    let (status, text) = post_json(
        &fixture.client,
        &action_url(&network, "block"),
        &auth,
        &sent_body,
    )
    .await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

/// Stores a delegation from the owner to the device over encryption URIs.
/// Returns the delegation hash to cite as `proof`.
async fn grant_owner_to_device(
    fixture: &KvSyncFixture,
    label: &str,
    abilities: &[(&str, &str)],
) -> Result<tinycloud_core::hash::Hash> {
    use std::str::FromStr;
    use tinycloud_core::models::{abilities as ability_model, delegation};
    use tinycloud_core::sea_orm::{ActiveModelTrait, ActiveValue::Set};
    use tinycloud_core::types::{Ability, Caveats, Resource};

    let id = tinycloud_core::hash::hash(format!("key-delegation-{label}").as_bytes());
    delegation::ActiveModel {
        id: Set(id),
        delegator: Set(owner_did(fixture)),
        delegatee: Set(fixture.device_did()),
        expiry: Set(None),
        issued_at: Set(None),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(label.as_bytes().to_vec()),
    }
    .insert(&fixture.conn)
    .await?;
    for (uri, action) in abilities {
        ability_model::ActiveModel {
            delegation: Set(id),
            resource: Set(Resource::from_str(uri).map_err(|e| anyhow::anyhow!("{e}"))?),
            ability: Set(Ability::try_from(action.to_string()).unwrap()),
            caveats: Set(Caveats(Default::default())),
        }
        .insert(&fixture.conn)
        .await?;
    }
    Ok(id)
}

/// Device-signed invocation to `audience` that cites `proof`.
fn delegated_invocation(
    fixture: &KvSyncFixture,
    proof: tinycloud_core::hash::Hash,
    audience: &str,
    caps: &[(&str, &str)],
    facts: Vec<Value>,
) -> Result<String> {
    use tinycloud_auth::ssi::{
        dids::{DIDBuf, DIDURLBuf},
        ucan::Payload,
    };
    use tinycloud_auth::ucan_capabilities_object::Capabilities;
    let mut capabilities = Capabilities::new();
    for (uri, action) in caps {
        capabilities.with_action(
            uri.parse()?,
            action.parse::<UcanAbility>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
    }
    Ok(Payload {
        issuer: fixture.device_vm.parse::<DIDURLBuf>()?,
        audience: audience.parse::<DIDBuf>()?,
        not_before: None,
        expiration: test_invocation_expiration(),
        nonce: Some(fixture.next_nonce()),
        facts: Some(facts),
        proof: vec![proof.to_cid(0x55)],
        attenuation: capabilities,
    }
    .sign(
        fixture.device.get_algorithm().unwrap_or_default(),
        &fixture.device,
    )?
    .encode()?)
}

/// Delegated key-admin invocation for `body` on the exact key.
fn delegated_admin_auth(
    fixture: &KvSyncFixture,
    proof: tinycloud_core::hash::Hash,
    network: &str,
    key_path: &str,
    action: &str,
    body: &Value,
) -> Result<String> {
    let cap = key_uri(network, key_path);
    delegated_invocation(
        fixture,
        proof,
        &fixture.node_did,
        &[(cap.as_str(), action)],
        vec![admin_fact_for(
            &fixture.node_did,
            network,
            key_path,
            action,
            &canonical_hash(body),
        )],
    )
}

#[tokio::test]
async fn owner_delegated_create_and_block_work_for_the_granted_key() -> Result<()> {
    let (fixture, network) = setup().await?;
    let cap = key_uri(&network, "docs/a");
    let proof = grant_owner_to_device(
        &fixture,
        "create-block-a",
        &[
            (cap.as_str(), KEY_CREATE_ACTION),
            (cap.as_str(), KEY_BLOCK_ACTION),
        ],
    )
    .await?;

    let body = json!({"keyPath": "docs/a", "deletable": false});
    let auth = delegated_admin_auth(
        &fixture,
        proof,
        &network,
        "docs/a",
        KEY_CREATE_ACTION,
        &body,
    )?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Ok, "create: {text}");

    let body = json!({"keyPath": "docs/a"});
    let auth = delegated_admin_auth(&fixture, proof, &network, "docs/a", KEY_BLOCK_ACTION, &body)?;
    let (status, text) = post_json(
        &fixture.client,
        &action_url(&network, "block"),
        &auth,
        &body,
    )
    .await;
    assert_eq!(status, Status::Ok, "block: {text}");
    Ok(())
}

#[tokio::test]
async fn delegate_for_another_key_or_prefix_is_refused() -> Result<()> {
    let (fixture, network) = setup().await?;
    let other_key = key_uri(&network, "docs/b");
    let other_prefix = format!("{network}/other/");
    let proof_key = grant_owner_to_device(
        &fixture,
        "other-key",
        &[(other_key.as_str(), KEY_CREATE_ACTION)],
    )
    .await?;
    let proof_prefix = grant_owner_to_device(
        &fixture,
        "other-prefix",
        &[(other_prefix.as_str(), KEY_CREATE_ACTION)],
    )
    .await?;

    let body = json!({"keyPath": "docs/a", "deletable": false});
    for proof in [proof_key, proof_prefix] {
        let auth = delegated_admin_auth(
            &fixture,
            proof,
            &network,
            "docs/a",
            KEY_CREATE_ACTION,
            &body,
        )?;
        let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
        assert_eq!(status, Status::Unauthorized, "{text}");
    }
    Ok(())
}

/// Creates a second active network owned by the fixture node DID. Its key
/// URNs name a different owner from the fixture owner.
async fn other_owner_network(fixture: &KvSyncFixture) -> Result<String> {
    let service = fixture
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed");
    let network = service
        .create_one_of_one_network(CreateNetworkRequest {
            name: "net".to_string(),
            owner_did: fixture.node_did.to_string(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(network.network_id.to_string())
}

/// Sends one request for `docs/a` on `network` through `route` (`create`,
/// `describe`, `block` or `unblock`). The invocation carries a single
/// capability on `resource` with the route's own ability.
async fn request_with_capability_on(
    fixture: &KvSyncFixture,
    network: &str,
    route: &str,
    resource: &str,
) -> Result<(Status, String)> {
    let key_path = "docs/a";
    if route == "describe" {
        let auth = invocation(
            fixture,
            &fixture.node_did,
            &[(resource, KEY_CREATE_ACTION)],
            vec![describe_fact_for(&fixture.node_did, network, key_path)],
        )?;
        return Ok(describe_get(fixture, network, key_path, &auth).await);
    }
    let (action, url, body) = match route {
        "create" => (
            KEY_CREATE_ACTION,
            keys_url(network),
            json!({"keyPath": key_path, "deletable": false}),
        ),
        "block" => (
            KEY_BLOCK_ACTION,
            action_url(network, "block"),
            json!({"keyPath": key_path}),
        ),
        "unblock" => (
            KEY_UNBLOCK_ACTION,
            action_url(network, "unblock"),
            json!({"keyPath": key_path}),
        ),
        other => panic!("unknown key route {other}"),
    };
    let fact = admin_fact_for(
        &fixture.node_did,
        network,
        key_path,
        action,
        &canonical_hash(&body),
    );
    let auth = invocation(
        fixture,
        &fixture.node_did,
        &[(resource, action)],
        vec![fact],
    )?;
    Ok(post_json(&fixture.client, &url, &auth, &body).await)
}

/// For `route`, a capability on a prefix, on a different key of the same
/// owner, or on a key of another owner is refused with 401. The target key
/// keeps its state.
async fn assert_off_key_capabilities_are_refused(route: &str) -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let other_network = other_owner_network(&fixture).await?;
    let cases = [
        ("a prefix", format!("{network}/docs/")),
        (
            "a different key of the same owner",
            key_uri(&network, "docs/b"),
        ),
        ("a key of another owner", key_uri(&other_network, "docs/a")),
    ];
    for (case, resource) in &cases {
        let (status, text) =
            request_with_capability_on(&fixture, &network, route, resource).await?;
        assert_eq!(status, Status::Unauthorized, "{route} with {case}: {text}");
    }
    let auth = describe_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION)?;
    let (status, text) = describe_get(&fixture, &network, "docs/a", &auth).await;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(state_of(&text)?, "active");
    Ok(())
}

#[tokio::test]
async fn create_refuses_capabilities_outside_the_exact_key() -> Result<()> {
    assert_off_key_capabilities_are_refused("create").await
}

#[tokio::test]
async fn describe_refuses_capabilities_outside_the_exact_key() -> Result<()> {
    assert_off_key_capabilities_are_refused("describe").await
}

#[tokio::test]
async fn block_refuses_capabilities_outside_the_exact_key() -> Result<()> {
    assert_off_key_capabilities_are_refused("block").await
}

#[tokio::test]
async fn unblock_refuses_capabilities_outside_the_exact_key() -> Result<()> {
    assert_off_key_capabilities_are_refused("unblock").await
}

#[tokio::test]
async fn block_and_unblock_of_a_missing_key_are_not_found() -> Result<()> {
    let (fixture, network) = setup().await?;
    for action in ["block", "unblock"] {
        let (status, text) = key_action(&fixture, &network, "docs/absent", action).await?;
        assert_eq!(status, Status::NotFound, "{action}: {text}");
        assert!(text.starts_with("key_not_found"), "{action}: {text}");
    }
    Ok(())
}

#[tokio::test]
async fn block_refuses_a_missing_body_hash() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "create: {text}");
    let body = json!({"keyPath": "docs/a"});
    let cap = key_uri(&network, "docs/a");
    let fact = json!({
        "type": KEY_ADMIN_TYPE,
        "targetNode": fixture.node_did,
        "networkId": network,
        "keyPath": "docs/a",
        "action": KEY_BLOCK_ACTION,
    });
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(cap.as_str(), KEY_BLOCK_ACTION)],
        vec![fact],
    )?;
    let (status, text) = post_json(
        &fixture.client,
        &action_url(&network, "block"),
        &auth,
        &body,
    )
    .await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(text.contains("bodyHash"), "{text}");
    Ok(())
}

#[tokio::test]
async fn key_route_bodies_that_do_not_parse_are_named_by_the_route() -> Result<()> {
    let (fixture, network) = setup().await?;
    let body = json!({"keyPath": "docs/a", "deletable": "true"});
    let auth = admin_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION, &body)?;
    let (status, text) = post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
    assert_eq!(status, Status::BadRequest, "create: {text}");
    assert!(
        text.starts_with("request body is malformed: "),
        "create: {text}"
    );

    let body = json!({"keyPath": 7});
    let auth = admin_auth(&fixture, &network, "docs/a", KEY_BLOCK_ACTION, &body)?;
    let (status, text) = post_json(
        &fixture.client,
        &action_url(&network, "block"),
        &auth,
        &body,
    )
    .await;
    assert_eq!(status, Status::BadRequest, "block: {text}");
    assert!(
        text.starts_with("request body is malformed: "),
        "block: {text}"
    );
    Ok(())
}

const DIRECT_DECRYPT_ABILITY: &str = "tinycloud.encryption/decrypt";

fn decrypt_url(network: &str) -> String {
    format!("/encryption/networks/{network}/decrypt")
}

#[tokio::test]
async fn direct_decrypt_refuses_a_body_key_path() -> Result<()> {
    let (fixture, network) = setup().await?;
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(network.as_str(), DIRECT_DECRYPT_ABILITY)],
        vec![],
    )?;
    let body = json!({"keyPath": "apps/alpha"});
    let (status, text) = post_json(&fixture.client, &decrypt_url(&network), &auth, &body).await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(text.starts_with("key_path_invalid: "), "{text}");
    Ok(())
}

/// Receiver key pair and a symmetric key wrapped to one recipient public key.
pub(super) struct DecryptCase {
    receiver: StaticSecret,
    receiver_public: [u8; 32],
    wrapped: Vec<u8>,
    symmetric: Vec<u8>,
}

impl DecryptCase {
    pub(super) fn wrapped_to(recipient_public: &[u8]) -> Self {
        let symmetric = vec![0xCD; 32];
        let wrapped = wrap_to_public_key(recipient_public, &symmetric).expect("wrap to recipient");
        let receiver = StaticSecret::random_from_rng(rand::rngs::OsRng);
        let receiver_public = PublicKey::from(&receiver).to_bytes();
        Self {
            receiver,
            receiver_public,
            wrapped,
            symmetric,
        }
    }

    /// Opens a `wrappedKey` response with the receiver secret, using the wire envelope directly.
    fn open(&self, wrapped: &[u8]) -> Vec<u8> {
        let (ephemeral, sealed) = wrapped.split_at(32);
        let peer = PublicKey::from(<[u8; 32]>::try_from(ephemeral).expect("32-byte ephemeral key"));
        let shared = self.receiver.diffie_hellman(&peer);
        assert!(
            shared.was_contributory(),
            "response ephemeral key is non-contributory"
        );
        ColumnEncryption::new(*shared.as_bytes())
            .decrypt_strict(sealed)
            .expect("response opens with the receiver secret")
    }
}

/// Well-formed decrypt body and matching facts. `key_path` names the key; `None` is the root key.
fn decrypt_request(
    fixture: &KvSyncFixture,
    network: &str,
    case: &DecryptCase,
    key_path: Option<&str>,
) -> (Value, Value) {
    let encrypted = base64::encode(&case.wrapped);
    let receiver = base64::encode(case.receiver_public);
    let encrypted_hash = canonical_hash(&Value::String(encrypted.clone()));
    let receiver_hash = canonical_hash(&Value::String(receiver.clone()));
    let mut body = json!({
        "type": DECRYPT_REQUEST_TYPE,
        "targetNode": fixture.node_did,
        "networkId": network,
        "alg": ALG_X25519_AES256GCM,
        "keyVersion": 1,
        "encryptedSymmetricKey": encrypted,
        "encryptedSymmetricKeyHash": encrypted_hash,
        "receiverPublicKey": receiver,
        "receiverPublicKeyHash": receiver_hash,
    });
    if let Some(key_path) = key_path {
        body["keyPath"] = json!(key_path);
    }
    let mut facts = json!({
        "type": DECRYPT_REQUEST_TYPE,
        "targetNode": fixture.node_did,
        "networkId": network,
        "bodyHash": canonical_hash(&body),
        "encryptedSymmetricKeyHash": encrypted_hash,
        "receiverPublicKeyHash": receiver_hash,
        "alg": ALG_X25519_AES256GCM,
        "keyVersion": 1,
    });
    if let Some(key_path) = key_path {
        facts["keyPath"] = json!(key_path);
    }
    (body, facts)
}

/// `decrypt_request` with the receiver key replaced by `receiver`, hashes kept consistent so
/// only the receiver key itself is malformed.
fn decrypt_request_with_receiver(
    fixture: &KvSyncFixture,
    network: &str,
    case: &DecryptCase,
    key_path: Option<&str>,
    receiver: &[u8],
) -> (Value, Value) {
    let (mut body, mut facts) = decrypt_request(fixture, network, case, key_path);
    let receiver_hash = canonical_hash(&Value::String(base64::encode(receiver)));
    body["receiverPublicKey"] = json!(base64::encode(receiver));
    body["receiverPublicKeyHash"] = json!(receiver_hash);
    facts["receiverPublicKeyHash"] = json!(receiver_hash);
    facts["bodyHash"] = json!(canonical_hash(&body));
    (body, facts)
}

/// POST a decrypt body to `/invoke`.
async fn invoke(fixture: &KvSyncFixture, auth: &str, body: &Value) -> (Status, String) {
    post_json(&fixture.client, "/invoke", auth, body).await
}

/// Owner-authorized named-key decrypt over `/invoke`.
pub(super) async fn invoke_named(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
    case: &DecryptCase,
) -> (Status, String) {
    let (body, facts) = decrypt_request(fixture, network, case, Some(key_path));
    let resource = key_uri(network, key_path);
    let auth = invocation(
        fixture,
        &fixture.node_did,
        &[(resource.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )
    .expect("decrypt invocation");
    invoke(fixture, &auth, &body).await
}

/// Device invocation under `proof` decrypting `key_path` over `/invoke`.
async fn device_decrypt(
    fixture: &KvSyncFixture,
    proof: tinycloud_core::hash::Hash,
    network: &str,
    key_path: &str,
    case: &DecryptCase,
) -> (Status, String) {
    let (body, facts) = decrypt_request(fixture, network, case, Some(key_path));
    let resource = key_uri(network, key_path);
    let auth = delegated_invocation(
        fixture,
        proof,
        &fixture.node_did,
        &[(resource.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )
    .expect("delegated decrypt invocation");
    invoke(fixture, &auth, &body).await
}

/// Creates a named key (deletable under `apps/`) and returns its public key
/// from the authenticated describe GET.
pub(super) async fn created_key(fixture: &KvSyncFixture, network: &str, key_path: &str) -> Vec<u8> {
    let (status, text) = create(fixture, network, key_path, key_path.starts_with("apps/"))
        .await
        .expect("create invocation");
    assert_eq!(status, Status::Ok, "{text}");
    described_public_key(fixture, network, key_path).await
}

/// Public key of an existing key from the authenticated describe GET.
async fn described_public_key(fixture: &KvSyncFixture, network: &str, key_path: &str) -> Vec<u8> {
    let auth = describe_auth(fixture, network, key_path, KEY_CREATE_ACTION).expect("describe auth");
    let (status, text) = describe_get(fixture, network, key_path, &auth).await;
    assert_eq!(status, Status::Ok, "{text}");
    let value: Value = serde_json::from_str(&text).expect("descriptor json");
    base64::decode(
        value["publicEncryptionKey"]
            .as_str()
            .expect("publicEncryptionKey"),
    )
    .expect("public key base64")
}

/// Root network public key from the encryption service.
async fn root_public_key(fixture: &KvSyncFixture, network: &str) -> Vec<u8> {
    let service = fixture
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("encryption service is managed");
    let id: NetworkId = network.parse().expect("network id");
    service
        .get_network(&id)
        .await
        .expect("network exists")
        .public_encryption_key
}

/// Audit `key_path` recorded for the decrypt with `request_hash`.
async fn audit_key_path(fixture: &KvSyncFixture, request_hash: &str) -> Option<String> {
    encryption_audit::Entity::find_by_id(request_hash.to_string())
        .one(&fixture.conn)
        .await
        .expect("audit query")
        .and_then(|row| row.key_path)
}

#[tokio::test]
async fn named_key_decrypt_over_invoke_round_trips_and_audits_key_path() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let case = DecryptCase::wrapped_to(&key_public);
    let (body, facts) = decrypt_request(&fixture, &network, &case, Some("docs/a"));
    let resource = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(resource.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Ok, "{text}");
    let response: Value = serde_json::from_str(&text)?;
    let wrapped = base64::decode(response["wrappedKey"].as_str().expect("wrappedKey"))?;
    assert_eq!(case.open(&wrapped), case.symmetric);
    let request_hash = response["requestHash"].as_str().expect("requestHash");
    assert_eq!(
        audit_key_path(&fixture, request_hash).await.as_deref(),
        Some("docs/a")
    );
    Ok(())
}

#[tokio::test]
async fn direct_route_refuses_a_named_key_capability_with_a_well_formed_body() -> Result<()> {
    let (fixture, network) = setup().await?;
    let root_public = root_public_key(&fixture, &network).await;
    let case = DecryptCase::wrapped_to(&root_public);
    let (body, facts) = decrypt_request(&fixture, &network, &case, None);
    let resource = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(resource.as_str(), DIRECT_DECRYPT_ABILITY)],
        vec![facts],
    )?;
    let (status, text) = post_json(&fixture.client, &decrypt_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    assert!(!text.contains("wrappedKey"), "{text}");
    Ok(())
}

#[tokio::test]
async fn direct_route_refuses_a_malformed_or_low_order_receiver() -> Result<()> {
    let (fixture, network) = setup().await?;
    let root_public = root_public_key(&fixture, &network).await;
    let case = DecryptCase::wrapped_to(&root_public);
    for receiver in [vec![0x11u8; 31], vec![0u8; 32]] {
        let (body, facts) =
            decrypt_request_with_receiver(&fixture, &network, &case, None, &receiver);
        let auth = invocation(
            &fixture,
            &fixture.node_did,
            &[(network.as_str(), DIRECT_DECRYPT_ABILITY)],
            vec![facts],
        )?;
        let (status, text) = post_json(&fixture.client, &decrypt_url(&network), &auth, &body).await;
        assert_eq!(status, Status::BadRequest, "{text}");
        assert!(text.starts_with("receiver_key_invalid: "), "{text}");
        assert!(!text.contains("wrappedKey"), "{text}");
        assert!(!text.contains(&base64::encode(&case.symmetric)), "{text}");
    }
    Ok(())
}

#[tokio::test]
async fn invoke_refuses_a_malformed_or_low_order_receiver_before_unwrap() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let case = DecryptCase::wrapped_to(&key_public);
    let resource = key_uri(&network, "docs/a");
    for receiver in [vec![0x11u8; 31], vec![0u8; 32]] {
        let (body, facts) =
            decrypt_request_with_receiver(&fixture, &network, &case, Some("docs/a"), &receiver);
        let auth = invocation(
            &fixture,
            &fixture.node_did,
            &[(resource.as_str(), DECRYPT_ACTION)],
            vec![facts],
        )?;
        let (status, text) = invoke(&fixture, &auth, &body).await;
        assert_eq!(status, Status::BadRequest, "{text}");
        assert!(text.starts_with("receiver_key_invalid: "), "{text}");
        assert!(!text.contains("wrappedKey"), "{text}");
        assert!(!text.contains(&base64::encode(&case.symmetric)), "{text}");
    }
    Ok(())
}

#[tokio::test]
async fn invoke_refuses_a_blocked_key_even_with_a_valid_wrap() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let (status, text) = key_action(&fixture, &network, "docs/a", "block").await?;
    assert_eq!(status, Status::Ok, "block: {text}");
    let case = DecryptCase::wrapped_to(&key_public);
    let (status, text) = invoke_named(&fixture, &network, "docs/a", &case).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(!text.contains("wrappedKey"), "{text}");
    Ok(())
}

#[tokio::test]
async fn invoke_refuses_a_key_prefix_as_the_decrypt_target() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "apps/foo/x").await;
    let case = DecryptCase::wrapped_to(&key_public);
    let (body, facts) = decrypt_request(&fixture, &network, &case, Some("apps/foo/x"));
    let prefix = format!("{network}/apps/foo/");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(prefix.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(!text.contains("wrappedKey"), "{text}");
    Ok(())
}

/// `InvalidBody` from invocation facts is 403 on `/invoke` and 400 on the direct route.
#[tokio::test]
async fn invoke_fact_errors_stay_forbidden_and_direct_route_stays_bad_request() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let case = DecryptCase::wrapped_to(&key_public);
    let resource = key_uri(&network, "docs/a");
    let (body, _) = decrypt_request(&fixture, &network, &case, Some("docs/a"));
    for facts in [vec![], vec![json!({ "type": DECRYPT_REQUEST_TYPE })]] {
        let auth = invocation(
            &fixture,
            &fixture.node_did,
            &[(resource.as_str(), DECRYPT_ACTION)],
            facts,
        )?;
        let (status, text) = invoke(&fixture, &auth, &body).await;
        assert_eq!(status, Status::Forbidden, "{text}");
        assert!(!text.contains("wrappedKey"), "{text}");
    }
    let root_public = root_public_key(&fixture, &network).await;
    let root_case = DecryptCase::wrapped_to(&root_public);
    let (body, _) = decrypt_request(&fixture, &network, &root_case, None);
    for facts in [vec![], vec![json!({ "type": DECRYPT_REQUEST_TYPE })]] {
        let auth = invocation(
            &fixture,
            &fixture.node_did,
            &[(network.as_str(), DIRECT_DECRYPT_ABILITY)],
            facts,
        )?;
        let (status, text) = post_json(&fixture.client, &decrypt_url(&network), &auth, &body).await;
        assert_eq!(status, Status::BadRequest, "{text}");
    }
    Ok(())
}

#[tokio::test]
async fn invoke_refuses_sibling_ciphertext_as_key_unwrap_failed() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "docs/a").await;
    let sibling_public = created_key(&fixture, &network, "docs/b").await;
    let case = DecryptCase::wrapped_to(&sibling_public);
    let (status, text) = invoke_named(&fixture, &network, "docs/a", &case).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_unwrap_failed"), "{text}");
    Ok(())
}

#[tokio::test]
async fn wrong_version_byte_is_refused_after_block_and_unblock() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let mut case = DecryptCase::wrapped_to(&key_public);
    case.wrapped[32] = 0x02;
    let (status, text) = key_action(&fixture, &network, "docs/a", "block").await?;
    assert_eq!(status, Status::Ok, "{text}");
    let (status, text) = invoke_named(&fixture, &network, "docs/a", &case).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_blocked"), "{text}");
    let (status, text) = key_action(&fixture, &network, "docs/a", "unblock").await?;
    assert_eq!(status, Status::Ok, "{text}");
    let (status, text) = invoke_named(&fixture, &network, "docs/a", &case).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_unwrap_failed"), "{text}");
    // Restoring the version byte isolates the refusal to the flipped byte.
    case.wrapped[32] = 0x01;
    let (status, text) = invoke_named(&fixture, &network, "docs/a", &case).await;
    assert_eq!(status, Status::Ok, "{text}");
    Ok(())
}

#[tokio::test]
async fn invoke_refuses_a_non_contributory_ephemeral_key_as_key_unwrap_failed() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let mut case = DecryptCase::wrapped_to(&key_public);
    // An all-zero ephemeral key gives an all-zero X25519 shared secret.
    case.wrapped[..32].fill(0);
    let (status, text) = invoke_named(&fixture, &network, "docs/a", &case).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_unwrap_failed"), "{text}");
    Ok(())
}

#[tokio::test]
async fn revoked_network_refuses_named_and_root_decrypt() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let root_public = root_public_key(&fixture, &network).await;
    let service = fixture
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("encryption service is managed");
    let id: NetworkId = network.parse()?;
    service.revoke_network(&id).await.expect("revoke network");
    let case = DecryptCase::wrapped_to(&key_public);
    let (status, text) = invoke_named(&fixture, &network, "docs/a", &case).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    let root_case = DecryptCase::wrapped_to(&root_public);
    let (body, facts) = decrypt_request(&fixture, &network, &root_case, None);
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(network.as_str(), DIRECT_DECRYPT_ABILITY)],
        vec![facts],
    )?;
    let (status, text) = post_json(&fixture.client, &decrypt_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    Ok(())
}

#[tokio::test]
async fn replayed_named_key_decrypt_is_a_conflict() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let case = DecryptCase::wrapped_to(&key_public);
    let (body, facts) = decrypt_request(&fixture, &network, &case, Some("docs/a"));
    let resource = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(resource.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Ok, "{text}");
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Conflict, "{text}");
    Ok(())
}

#[tokio::test]
async fn bare_network_grant_cannot_decrypt_a_named_key() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let case = DecryptCase::wrapped_to(&key_public);
    let (body, facts) = decrypt_request(&fixture, &network, &case, Some("docs/a"));
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(network.as_str(), DECRYPT_ACTION)],
        vec![facts.clone()],
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(!text.contains("wrappedKey"), "{text}");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(network.as_str(), DIRECT_DECRYPT_ABILITY)],
        vec![facts],
    )?;
    let (status, text) = post_json(&fixture.client, &decrypt_url(&network), &auth, &body).await;
    assert_eq!(status, Status::BadRequest, "{text}");
    assert!(text.starts_with("key_path_invalid: "), "{text}");
    Ok(())
}

#[tokio::test]
async fn named_key_grant_cannot_decrypt_the_root_key_over_invoke() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "docs/a").await;
    let root_public = root_public_key(&fixture, &network).await;
    let case = DecryptCase::wrapped_to(&root_public);
    let (body, facts) = decrypt_request(&fixture, &network, &case, None);
    let resource = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(resource.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(!text.contains("wrappedKey"), "{text}");
    Ok(())
}

#[tokio::test]
async fn invoke_refuses_a_key_path_that_differs_from_the_capability() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "docs/a").await;
    let docs_b_public = created_key(&fixture, &network, "docs/b").await;
    let case = DecryptCase::wrapped_to(&docs_b_public);
    let (body, facts) = decrypt_request(&fixture, &network, &case, Some("docs/b"));
    let resource = key_uri(&network, "docs/a");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(resource.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(!text.contains("wrappedKey"), "{text}");
    assert!(text.contains("key_path_invalid"), "{text}");
    Ok(())
}

#[tokio::test]
async fn prefix_grant_covers_keys_at_any_depth_but_not_a_sibling_prefix() -> Result<()> {
    let (fixture, network) = setup().await?;
    let inside = created_key(&fixture, &network, "apps/foo/x").await;
    let deep = created_key(&fixture, &network, "apps/foo/deep/y").await;
    let sibling = created_key(&fixture, &network, "apps/foobar/x").await;
    let prefix = format!("{network}/apps/foo/");
    let proof = grant_owner_to_device(
        &fixture,
        "apps-foo-prefix",
        &[(prefix.as_str(), DECRYPT_ACTION)],
    )
    .await?;
    let (status, text) = device_decrypt(
        &fixture,
        proof,
        &network,
        "apps/foo/x",
        &DecryptCase::wrapped_to(&inside),
    )
    .await;
    assert_eq!(status, Status::Ok, "{text}");
    let (status, text) = device_decrypt(
        &fixture,
        proof,
        &network,
        "apps/foo/deep/y",
        &DecryptCase::wrapped_to(&deep),
    )
    .await;
    assert_eq!(status, Status::Ok, "{text}");
    let (status, text) = device_decrypt(
        &fixture,
        proof,
        &network,
        "apps/foobar/x",
        &DecryptCase::wrapped_to(&sibling),
    )
    .await;
    assert_eq!(status, Status::Forbidden, "{text}");
    Ok(())
}

#[tokio::test]
async fn delegate_granted_key_a_cannot_decrypt_key_b_over_invoke() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_a_public = created_key(&fixture, &network, "docs/a").await;
    let key_b_public = created_key(&fixture, &network, "docs/b").await;
    let resource_a = key_uri(&network, "docs/a");
    let proof = grant_owner_to_device(
        &fixture,
        "docs-a-decrypt-only",
        &[(resource_a.as_str(), DECRYPT_ACTION)],
    )
    .await?;
    // Body keyPath and capability both name docs/b; the delegation covers only docs/a.
    let (status, text) = device_decrypt(
        &fixture,
        proof,
        &network,
        "docs/b",
        &DecryptCase::wrapped_to(&key_b_public),
    )
    .await;
    assert_eq!(status, Status::Forbidden, "{text}");
    // Positive control: the same delegation decrypts docs/a.
    let (status, text) = device_decrypt(
        &fixture,
        proof,
        &network,
        "docs/a",
        &DecryptCase::wrapped_to(&key_a_public),
    )
    .await;
    assert_eq!(status, Status::Ok, "{text}");
    Ok(())
}

#[tokio::test]
async fn decrypt_invocation_that_is_expired_or_misaddressed_is_refused() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let case = DecryptCase::wrapped_to(&key_public);
    let (body, facts) = decrypt_request(&fixture, &network, &case, Some("docs/a"));
    let resource = key_uri(&network, "docs/a");
    let caps = [(resource.as_str(), DECRYPT_ACTION)];
    let expired = NumericDate::try_from_seconds(
        time::OffsetDateTime::now_utc().unix_timestamp() as f64 - 3600.0,
    )?;
    let auth = signed(
        &fixture,
        &fixture.node_did,
        &caps,
        vec![facts.clone()],
        expired,
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Unauthorized, "{text}");
    let auth = invocation(&fixture, &fixture.device_did(), &caps, vec![facts])?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.contains("audience"), "{text}");
    Ok(())
}

#[tokio::test]
async fn root_key_unwrap_failure_on_the_direct_route_is_forbidden_not_a_server_error() -> Result<()>
{
    let (fixture, network) = setup().await?;
    let stranger = PublicKey::from(&StaticSecret::random_from_rng(rand::rngs::OsRng)).to_bytes();
    let case = DecryptCase::wrapped_to(&stranger);
    let (body, facts) = decrypt_request(&fixture, &network, &case, None);
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(network.as_str(), DIRECT_DECRYPT_ABILITY)],
        vec![facts],
    )?;
    let (status, text) = post_json(&fixture.client, &decrypt_url(&network), &auth, &body).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_unwrap_failed"), "{text}");
    Ok(())
}

#[tokio::test]
async fn doubled_network_segment_in_a_key_url_is_a_bad_request() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "docs/a").await;
    for url in [
        format!("/encryption/networks//{network}/keys/apps/networks/{network}/keys/docs/a"),
        format!("/encryption//networks/{network}/keys/docs/a"),
    ] {
        let (status, text) = get(&fixture.client, &url, None).await;
        assert_eq!(status, Status::BadRequest, "{url}: {text}");
    }
    Ok(())
}

const NAMED_KEYS_UNAVAILABLE: &str =
    "named_keys_unavailable: named keys are not enabled on this node";

/// `POST /delegate` of `caps` (resource, ability), signed by the fixture
/// owner with no proofs, to the fixture device.
async fn delegate_caps(fixture: &KvSyncFixture, caps: &[(&str, &str)]) -> Result<(Status, String)> {
    use tinycloud_auth::ssi::{
        dids::{DIDBuf, DIDURLBuf},
        ucan::Payload,
    };
    use tinycloud_auth::ucan_capabilities_object::Capabilities;
    let mut capabilities = Capabilities::new();
    for (uri, action) in caps {
        capabilities.with_action(
            uri.parse()?,
            action.parse::<UcanAbility>()?,
            [std::collections::BTreeMap::<String, Value>::new()],
        );
    }
    let token = Payload {
        issuer: fixture.owner_vm.parse::<DIDURLBuf>()?,
        audience: fixture.device_did().parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some(fixture.next_nonce()),
        facts: Some(Vec::<Value>::new()),
        proof: vec![],
        attenuation: capabilities,
    }
    .sign(
        fixture.owner.get_algorithm().unwrap_or_default(),
        &fixture.owner,
    )?
    .encode()?;
    let response = fixture
        .client
        .post("/delegate")
        .header(Header::new("Authorization", token))
        .dispatch()
        .await;
    let status = response.status();
    Ok((status, response.into_string().await.unwrap_or_default()))
}

async fn stored_delegations(fixture: &KvSyncFixture) -> Result<u64> {
    use tinycloud_core::sea_orm::{EntityTrait, PaginatorTrait};
    Ok(tinycloud_core::models::delegation::Entity::find()
        .count(&fixture.conn)
        .await?)
}

/// With named keys off, `/delegate` refuses every capability on a key or a
/// key prefix, including a grant the key's owner signs with no proofs, and
/// stores nothing. A grant on the bare network is unaffected.
#[tokio::test]
async fn delegate_refuses_named_key_resources_when_named_keys_are_off() -> Result<()> {
    let (fixture, network) = setup_with(false).await?;
    let key = key_uri(&network, "docs/a");
    let prefix = format!("{network}/docs/");
    let before = stored_delegations(&fixture).await?;
    let cases: [(&str, Vec<(&str, &str)>); 5] = [
        ("key", vec![(key.as_str(), DECRYPT_ACTION)]),
        ("prefix", vec![(prefix.as_str(), DECRYPT_ACTION)]),
        ("key create", vec![(key.as_str(), KEY_CREATE_ACTION)]),
        ("prefix block", vec![(prefix.as_str(), KEY_BLOCK_ACTION)]),
        (
            "network and key",
            vec![
                (network.as_str(), DECRYPT_ACTION),
                (key.as_str(), DECRYPT_ACTION),
            ],
        ),
    ];
    for (label, caps) in cases {
        let (status, text) = delegate_caps(&fixture, &caps).await?;
        assert_eq!(status, Status::Unauthorized, "{label}: {text}");
        assert_eq!(text, NAMED_KEYS_UNAVAILABLE, "{label}");
    }
    assert_eq!(stored_delegations(&fixture).await?, before);

    let (status, text) = delegate_caps(&fixture, &[(network.as_str(), DECRYPT_ACTION)]).await?;
    assert_eq!(status, Status::Ok, "bare network grant: {text}");
    assert_eq!(stored_delegations(&fixture).await?, before + 1);
    Ok(())
}

/// With named keys on, the same owner-signed grants on a key and on a key
/// prefix are admitted.
#[tokio::test]
async fn delegate_admits_named_key_resources_when_named_keys_are_on() -> Result<()> {
    let (fixture, network) = setup().await?;
    let key = key_uri(&network, "docs/a");
    let prefix = format!("{network}/docs/");
    for (label, resource) in [("key", key.as_str()), ("prefix", prefix.as_str())] {
        let (status, text) = delegate_caps(&fixture, &[(resource, DECRYPT_ACTION)]).await?;
        assert_eq!(status, Status::Ok, "{label}: {text}");
    }
    Ok(())
}

/// With named keys off, `/invoke` answers 403 with the code for a decrypt
/// on a key or a key prefix, even for a key that exists; the bare network
/// decrypt on the same route is not refused with it.
#[tokio::test]
async fn invoke_refuses_named_key_resources_when_named_keys_are_off() -> Result<()> {
    let (fixture, network) = setup_with(false).await?;
    let key_public = created_key(&fixture, &network, "docs/a").await;
    let case = DecryptCase::wrapped_to(&key_public);
    let (status, text) = invoke_named(&fixture, &network, "docs/a", &case).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert_eq!(text, NAMED_KEYS_UNAVAILABLE);

    let prefix = format!("{network}/docs/");
    let (body, facts) = decrypt_request(&fixture, &network, &case, Some("docs/a"));
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(prefix.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert_eq!(text, NAMED_KEYS_UNAVAILABLE);

    let root_public = root_public_key(&fixture, &network).await;
    let case = DecryptCase::wrapped_to(&root_public);
    let (body, facts) = decrypt_request(&fixture, &network, &case, None);
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(network.as_str(), DIRECT_DECRYPT_ABILITY)],
        vec![facts],
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Ok, "bare network decrypt: {text}");
    Ok(())
}

// ------------------------------------------------------------ app keys

fn app_key_vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../../tinycloud-core/tests/fixtures/encryption/app-key-vectors.json"
    ))
    .expect("vector file parses")
}

fn key_row_filter(network: &str, key_path: &str) -> (String, String) {
    (network.to_string(), key_path.to_string())
}

async fn stored_key_row(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
) -> Option<tinycloud_core::models::encryption_network_key::Model> {
    use tinycloud_core::sea_orm::EntityTrait;
    tinycloud_core::models::encryption_network_key::Entity::find_by_id(key_row_filter(
        network, key_path,
    ))
    .one(&fixture.conn)
    .await
    .expect("key row query")
}

/// Writes a state and seed straight into a key row, as a delete would.
async fn force_key_row(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
    state: &str,
    sealed_seed: Option<Vec<u8>>,
) {
    use tinycloud_core::sea_orm::{ActiveModelTrait, ActiveValue::Set};
    let mut row: tinycloud_core::models::encryption_network_key::ActiveModel =
        stored_key_row(fixture, network, key_path)
            .await
            .expect("row exists")
            .into();
    row.state = Set(state.to_string());
    row.sealed_seed = Set(sealed_seed);
    row.update(&fixture.conn).await.expect("row update");
}

/// Status, headers (sorted, without the per-request id) and body of a GET.
async fn get_full(fixture: &KvSyncFixture, uri: &str) -> (Status, Vec<(String, String)>, String) {
    let response = fixture
        .client
        .get(uri.to_string())
        .remote("127.0.0.1:0".parse().expect("valid socket address"))
        .dispatch()
        .await;
    let status = response.status();
    let mut headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter(|h| !h.name().as_str().eq_ignore_ascii_case("x-request-id"))
        .map(|h| (h.name().to_string(), h.value().to_string()))
        .collect();
    headers.sort();
    (
        status,
        headers,
        response.into_string().await.unwrap_or_default(),
    )
}

/// Decrypt of `case` for `key_path` at `version`, authorized by the owner.
async fn invoke_named_at_version(
    fixture: &KvSyncFixture,
    network: &str,
    key_path: &str,
    case: &DecryptCase,
    version: i64,
) -> (Status, String) {
    let (mut body, mut facts) = decrypt_request(fixture, network, case, Some(key_path));
    body["keyVersion"] = json!(version);
    facts["keyVersion"] = json!(version);
    facts["bodyHash"] = json!(canonical_hash(&body));
    let resource = key_uri(network, key_path);
    let auth = invocation(
        fixture,
        &fixture.node_did,
        &[(resource.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )
    .expect("decrypt invocation");
    invoke(fixture, &auth, &body).await
}

#[tokio::test]
async fn apps_key_paths_follow_the_shared_depth_vectors_on_the_create_route() -> Result<()> {
    let (fixture, network) = setup().await?;
    let vectors = app_key_vectors();
    let cases = vectors["nodeKeyPathUnderApps"].as_array().unwrap();
    assert_eq!(cases.len(), 10);
    for case in cases {
        let path = case["keyPath"].as_str().unwrap();
        let accepted = case["accepted"].as_bool().unwrap();
        let deletable = path.split('/').next() == Some("apps");
        if accepted {
            let (status, text) = create(&fixture, &network, path, deletable).await?;
            assert_eq!(status, Status::Ok, "{path}: {text}");
            let kind = serde_json::from_str::<Value>(&text)?["kind"].clone();
            assert_eq!(
                kind,
                if deletable {
                    "deletable"
                } else {
                    "deterministic"
                }
            );
        } else {
            // The body names a path the grammar refuses while the invocation
            // is valid for another key.
            let body = json!({"keyPath": path, "deletable": deletable});
            let auth = admin_auth(&fixture, &network, "docs/a", KEY_CREATE_ACTION, &body)?;
            let (status, text) =
                post_json(&fixture.client, &keys_url(&network), &auth, &body).await;
            assert_eq!(status, Status::BadRequest, "{path}: {text}");
            assert!(text.starts_with("key_path_invalid"), "{path}: {text}");
            // The same path as the invocation's own resource is refused too.
            let (status, text) = create(&fixture, &network, path, deletable).await?;
            assert_ne!(status, Status::Ok, "{path}: {text}");
            assert!(
                stored_key_row(&fixture, &network, path).await.is_none(),
                "{path} stored"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn apps_prefix_depth_is_enforced_for_delegation_and_invocation() -> Result<()> {
    let (fixture, network) = setup().await?;
    let before = stored_delegations(&fixture).await?;
    let vectors = app_key_vectors();
    let cases = vectors["prefixValid"].as_array().unwrap();
    assert_eq!(cases.len(), 9);
    let mut admitted = 0;
    for case in cases {
        let prefix = case["prefix"].as_str().unwrap();
        let valid = case["valid"].as_bool().unwrap();
        let resource = format!("{network}/{prefix}");
        for ability in [DECRYPT_ACTION, KEY_CREATE_ACTION, KEY_BLOCK_ACTION] {
            let (status, text) = delegate_caps(&fixture, &[(resource.as_str(), ability)]).await?;
            assert_eq!(status == Status::Ok, valid, "{prefix} {ability}: {text}");
            admitted += usize::from(valid);
        }
    }
    assert_eq!(
        stored_delegations(&fixture).await?,
        before + admitted as u64
    );

    // A key with fewer than three segments under `apps/` is refused as a
    // grant and as a decrypt target.
    for path in ["apps", "apps/foo"] {
        let resource = key_uri(&network, path);
        let (status, text) =
            delegate_caps(&fixture, &[(resource.as_str(), DECRYPT_ACTION)]).await?;
        assert_ne!(status, Status::Ok, "{path}: {text}");
        let case = DecryptCase::wrapped_to(&root_public_key(&fixture, &network).await);
        let (status, text) = invoke_named(&fixture, &network, path, &case).await;
        assert_eq!(status, Status::Forbidden, "{path}: {text}");
    }
    // A prefix is never an invocation target, whatever its depth.
    let case = DecryptCase::wrapped_to(&root_public_key(&fixture, &network).await);
    let (body, facts) = decrypt_request(&fixture, &network, &case, Some("apps/foo/x"));
    let prefix = format!("{network}/apps/foo/");
    let auth = invocation(
        &fixture,
        &fixture.node_did,
        &[(prefix.as_str(), DECRYPT_ACTION)],
        vec![facts],
    )?;
    let (status, text) = invoke(&fixture, &auth, &body).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    Ok(())
}

#[tokio::test]
async fn public_get_under_apps_is_one_uniform_not_found() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "apps/foo/active").await;
    created_key(&fixture, &network, "apps/foo/blocked").await;
    let (status, text) = key_action(&fixture, &network, "apps/foo/blocked", "block").await?;
    assert_eq!(status, Status::Ok, "{text}");
    created_key(&fixture, &network, "apps/foo/gone").await;
    force_key_row(&fixture, &network, "apps/foo/gone", "deleted", None).await;
    let other_owner = other_owner_network(&fixture).await?;
    let absent = NetworkId::new(owner_did(&fixture), "absent")?.to_string();

    let mut seen = Vec::new();
    for (net, path) in [
        (&network, "apps/foo/active"),
        (&network, "apps/foo/blocked"),
        (&network, "apps/foo/gone"),
        (&network, "apps/foo/missing"),
        (&network, "apps/foo/deep/er/missing"),
        (&network, "apps/nobody/missing"),
        (&other_owner, "apps/foo/active"),
        (&other_owner, "apps/foo/missing"),
        (&absent, "apps/foo/missing"),
    ] {
        seen.push(get_full(&fixture, &key_url(net, path)).await);
        let (status, _, body) = seen.last().unwrap();
        assert_eq!(*status, Status::NotFound, "{net} {path}: {body}");
    }
    assert!(
        seen.windows(2).all(|pair| pair[0] == pair[1]),
        "answers differ: {seen:?}"
    );
    assert!(seen[0].2.starts_with("key_not_found"), "{}", seen[0].2);
    assert!(!seen[0].2.contains("foo") && !seen[0].2.contains(&network));

    // Outside `apps/` a missing key still answers with its derived public key.
    let (status, text) = public_get(&fixture, &network, "docs/never-created").await;
    assert_eq!(status, Status::Ok, "{text}");
    created_key(&fixture, &network, "appsx/y").await;
    let (status, text) = public_get(&fixture, &network, "appsx/y").await;
    assert_eq!(status, Status::Ok, "{text}");
    Ok(())
}

#[tokio::test]
async fn describe_returns_app_keys_with_their_kind_and_state() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "apps/foo/x", true).await?;
    assert_eq!(status, Status::Ok, "{text}");
    let created: Value = serde_json::from_str(&text)?;
    let auth = describe_auth(&fixture, &network, "apps/foo/x", DECRYPT_ACTION)?;
    let (status, text) = describe_get(&fixture, &network, "apps/foo/x", &auth).await;
    assert_eq!(status, Status::Ok, "{text}");
    let described: Value = serde_json::from_str(&text)?;
    assert_eq!(described, created);
    assert_eq!(described["kind"], "deletable");

    force_key_row(&fixture, &network, "apps/foo/x", "deleted", None).await;
    let auth = describe_auth(&fixture, &network, "apps/foo/x", DECRYPT_ACTION)?;
    let (status, text) = describe_get(&fixture, &network, "apps/foo/x", &auth).await;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(state_of(&text)?, "deleted");
    Ok(())
}

#[tokio::test]
async fn deleted_app_key_is_refused_by_block_unblock_and_decrypt_and_reinstalled_by_create(
) -> Result<()> {
    let (fixture, network) = setup().await?;
    let key = "apps/foo/x";
    let old_public = created_key(&fixture, &network, key).await;
    let old_case = DecryptCase::wrapped_to(&old_public);
    let (status, text) = invoke_named(&fixture, &network, key, &old_case).await;
    assert_eq!(status, Status::Ok, "decrypt before delete: {text}");
    let value: Value = serde_json::from_str(&text)?;
    assert_eq!(value["keyVersion"], 1);

    force_key_row(&fixture, &network, key, "deleted", None).await;
    for action in ["block", "unblock"] {
        let (status, text) = key_action(&fixture, &network, key, action).await?;
        assert_eq!(status, Status::Forbidden, "{action}: {text}");
        assert!(text.starts_with("key_deleted"), "{action}: {text}");
    }
    let row = stored_key_row(&fixture, &network, key).await.unwrap();
    assert_eq!(row.state, "deleted");
    assert!(row.sealed_seed.is_none());
    let (status, text) = invoke_named(&fixture, &network, key, &old_case).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_deleted"), "{text}");

    // Create reuses the row with a new seed and the next version.
    let (status, text) = create(&fixture, &network, key, true).await?;
    assert_eq!(status, Status::Ok, "{text}");
    let value: Value = serde_json::from_str(&text)?;
    assert_eq!(
        (value["state"].as_str(), value["keyVersion"].as_i64()),
        (Some("active"), Some(2))
    );
    let new_public = described_public_key(&fixture, &network, key).await;
    assert_ne!(new_public, old_public);
    assert!(stored_key_row(&fixture, &network, key)
        .await
        .unwrap()
        .sealed_seed
        .is_some());

    // Ciphertext for the earlier key is refused at the earlier version and
    // cannot be opened at the current one.
    let (status, text) = invoke_named_at_version(&fixture, &network, key, &old_case, 1).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_deleted"), "{text}");
    let old_case = DecryptCase::wrapped_to(&old_public);
    let (status, text) = invoke_named_at_version(&fixture, &network, key, &old_case, 2).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_unwrap_failed"), "{text}");
    // The new key decrypts at version 2 only.
    let new_case = DecryptCase::wrapped_to(&new_public);
    let (status, text) = invoke_named_at_version(&fixture, &network, key, &new_case, 1).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_deleted"), "{text}");
    let new_case = DecryptCase::wrapped_to(&new_public);
    let (status, text) = invoke_named_at_version(&fixture, &network, key, &new_case, 2).await;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(serde_json::from_str::<Value>(&text)?["keyVersion"], 2);
    Ok(())
}

#[tokio::test]
async fn deleted_row_that_is_not_deletable_stays_deleted_on_create() -> Result<()> {
    let (fixture, network) = setup().await?;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Ok, "{text}");
    force_key_row(&fixture, &network, "docs/a", "deleted", None).await;
    let (status, text) = create(&fixture, &network, "docs/a", false).await?;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("key_deleted"), "{text}");
    let (status, text) = key_action(&fixture, &network, "docs/a", "unblock").await?;
    assert_eq!(status, Status::Forbidden, "{text}");
    let row = stored_key_row(&fixture, &network, "docs/a").await.unwrap();
    assert_eq!((row.state.as_str(), row.key_version), ("deleted", 1));
    Ok(())
}

#[tokio::test]
async fn concurrent_creates_of_one_app_key_make_one_key() -> Result<()> {
    let (fixture, network) = setup().await?;
    let results = futures::future::join_all((0..4).map(|_| {
        let fixture = &fixture;
        let network = &network;
        async move { create(fixture, network, "apps/foo/x", true).await }
    }))
    .await;
    let statuses: Vec<Status> = results.into_iter().map(|r| r.unwrap().0).collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == Status::Ok).count(),
        1,
        "{statuses:?}"
    );
    assert!(statuses
        .iter()
        .all(|s| *s == Status::Ok || *s == Status::Conflict));
    let row = stored_key_row(&fixture, &network, "apps/foo/x")
        .await
        .unwrap();
    assert_eq!((row.state.as_str(), row.key_version), ("active", 1));
    Ok(())
}

#[tokio::test]
async fn concurrent_reinstall_creates_bump_the_version_once() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "apps/foo/x").await;
    force_key_row(&fixture, &network, "apps/foo/x", "deleted", None).await;
    let results = futures::future::join_all((0..4).map(|_| {
        let fixture = &fixture;
        let network = &network;
        async move { create(fixture, network, "apps/foo/x", true).await }
    }))
    .await;
    let statuses: Vec<Status> = results.into_iter().map(|r| r.unwrap().0).collect();
    assert_eq!(
        statuses.iter().filter(|s| **s == Status::Ok).count(),
        1,
        "{statuses:?}"
    );
    let row = stored_key_row(&fixture, &network, "apps/foo/x")
        .await
        .unwrap();
    assert_eq!((row.state.as_str(), row.key_version), ("active", 2));
    Ok(())
}

#[tokio::test]
async fn concurrent_block_and_unblock_leave_a_consistent_key() -> Result<()> {
    let (fixture, network) = setup().await?;
    created_key(&fixture, &network, "apps/foo/x").await;
    let results = futures::future::join_all((0..6).map(|i| {
        let fixture = &fixture;
        let network = &network;
        async move {
            let action = if i % 2 == 0 { "block" } else { "unblock" };
            key_action(fixture, network, "apps/foo/x", action).await
        }
    }))
    .await;
    for result in results {
        let (status, text) = result?;
        assert_eq!(status, Status::Ok, "{text}");
    }
    let row = stored_key_row(&fixture, &network, "apps/foo/x")
        .await
        .unwrap();
    assert!(matches!(row.state.as_str(), "active" | "blocked"));
    assert!(row.sealed_seed.is_some());
    Ok(())
}

/// With named keys off, app key and app prefix resources are refused like
/// every other key resource.
#[tokio::test]
async fn app_key_resources_are_refused_when_named_keys_are_off() -> Result<()> {
    let (fixture, network) = setup_with(false).await?;
    let before = stored_delegations(&fixture).await?;
    let key = key_uri(&network, "apps/foo/x");
    let prefix = format!("{network}/apps/foo/");
    for resource in [key.as_str(), prefix.as_str()] {
        for ability in [DECRYPT_ACTION, KEY_CREATE_ACTION, KEY_BLOCK_ACTION] {
            let (status, text) = delegate_caps(&fixture, &[(resource, ability)]).await?;
            assert_eq!(status, Status::Unauthorized, "{resource} {ability}: {text}");
            assert_eq!(text, NAMED_KEYS_UNAVAILABLE);
        }
    }
    assert_eq!(stored_delegations(&fixture).await?, before);
    let case = DecryptCase::wrapped_to(&root_public_key(&fixture, &network).await);
    let (status, text) = invoke_named(&fixture, &network, "apps/foo/x", &case).await;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert_eq!(text, NAMED_KEYS_UNAVAILABLE);
    Ok(())
}

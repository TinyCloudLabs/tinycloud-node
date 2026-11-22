//! TC-3798: keys under `secrets/` are seeded (deletable) keys, one per
//! secret. Booted through `app_with_control` with named keys on, on SQLite and
//! PostgreSQL. The owner is a did:key space owner; the grants are UCANs.
//!
//! - an exact-key grant opens only its own key: not a sibling, not the
//!   network, not a key below an exact key of the same name;
//! - an exact `key.create` grant creates only its own key; a `secrets/` prefix
//!   grant creates any key below it;
//! - the unauthenticated public GET never answers with a key under `secrets/`;
//! - the node refuses to start with a deterministic row under `secrets/`;
//! - a holder's re-delegation can attenuate its grant and can't widen it.

use super::test_harness::*;
use super::*;
use rocket::http::{ContentType, Header};
use serde_json::json;
use std::collections::BTreeMap;
use tinycloud_auth::{
    siwe_recap::Ability as RecapAbility, ssi::claims::jwt::NumericDate, ssi::ucan::Payload,
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::encryption_network::{
    backend::{
        wrap_to_public_key, wrap_to_public_key_with_context, KeyWrapContext, KeyWrapPurpose,
        KeyWrapVersion,
    },
    canonical::canonical_hash,
    protocol::{DECRYPT_ACTION, DECRYPT_REQUEST_TYPE, KEY_ADMIN_TYPE, KEY_DESCRIBE_TYPE},
    types::{ALG_X25519_AES256GCM, ALG_X25519_HKDF_AES256GCM},
    CreateNetworkRequest, Threshold, KEY_CREATE_ACTION,
};

type Cid = tinycloud_auth::ipld_core::cid::Cid;

const KEY_NOT_FOUND: &str = "key_not_found";

/// A harness with named keys on and the owner's `mainnet` network created.
async fn secrets_harness(backend: Backend, test: &str) -> anyhow::Result<Option<Harness>> {
    let ledger_dir = tempfile::tempdir()?;
    let ledger_path = ledger_dir.path().join("deletion-ledger.jsonl");
    let Some(h) = Harness::new_with(backend, Shape::KeySession, test, |config| {
        config.encryption_network.named_keys_v1 = true;
        config.encryption_network.deletion_ledger_path = Some(ledger_path.clone());
    })
    .await?
    else {
        return Ok(None);
    };
    // The ledger is opened at boot and stays open; the directory may go.
    drop(ledger_dir);
    h.client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed")
        .create_one_of_one_network(CreateNetworkRequest {
            name: "mainnet".to_string(),
            owner_did: h.space_owner.did().to_string(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    Ok(Some(h))
}

fn window() -> Window {
    Window::until(now() + Duration::hours(1))
}

fn key(h: &Harness, path: &str) -> String {
    format!("{}/{path}", h.network)
}

/// An invocation by `signer` to the node of `caps`, carrying `facts` and
/// citing `proof` (`None`: the signer is the owner and cites nothing).
fn invocation(
    h: &Harness,
    signer: &Signer,
    caps: &[(String, &str)],
    facts: Vec<Value>,
    proof: Option<&str>,
) -> anyhow::Result<String> {
    let Signer::Key { jwk, vm, .. } = signer else {
        anyhow::bail!("invocations are signed by keys");
    };
    let mut attenuation = Capabilities::<Value>::new();
    for (resource, ability) in caps {
        attenuation.with_action(
            resource.parse()?,
            ability.parse::<RecapAbility>()?,
            [BTreeMap::<String, Value>::new()],
        );
    }
    let at = now();
    Ok(Payload {
        issuer: vm.parse()?,
        audience: h.node_did().parse()?,
        not_before: Some(NumericDate::try_from_seconds(at.unix_timestamp() as f64)?),
        expiration: NumericDate::try_from_seconds(
            (at + Duration::seconds(30)).unix_timestamp() as f64
        )?,
        nonce: Some(unique("tc3798invoke")),
        facts: Some(facts),
        proof: proof
            .map(|cid| cid.parse::<Cid>())
            .transpose()?
            .into_iter()
            .collect(),
        attenuation,
    }
    .sign(Algorithm::EdDSA, jwk)?
    .encode()?)
}

async fn post(h: &Harness, uri: &str, auth: &str, body: &Value) -> (Status, String) {
    let response = h
        .client
        .post(uri.to_string())
        .header(ContentType::JSON)
        .header(Header::new("Authorization", auth.to_string()))
        .body(body.to_string())
        .dispatch()
        .await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

async fn get(h: &Harness, uri: &str, auth: Option<&str>) -> (Status, String) {
    let mut request = h
        .client
        .get(uri.to_string())
        .remote("127.0.0.1:0".parse().expect("socket address"));
    if let Some(auth) = auth {
        request = request.header(Header::new("Authorization", auth.to_string()));
    }
    let response = request.dispatch().await;
    let status = response.status();
    (status, response.into_string().await.unwrap_or_default())
}

/// `key.create` of `path` (deletable) by `signer`; the invocation names the
/// exact key.
async fn create(
    h: &Harness,
    signer: &Signer,
    proof: Option<&str>,
    path: &str,
) -> anyhow::Result<(Status, String)> {
    let body = json!({"keyPath": path, "deletable": true});
    let facts = vec![json!({
        "type": KEY_ADMIN_TYPE,
        "targetNode": h.node_did(),
        "networkId": h.network,
        "keyPath": path,
        "action": KEY_CREATE_ACTION,
        "bodyHash": canonical_hash(&body),
    })];
    let auth = invocation(
        h,
        signer,
        &[(key(h, path), KEY_CREATE_ACTION)],
        facts,
        proof,
    )?;
    Ok(post(
        h,
        &format!("/encryption/networks/{}/keys", h.network),
        &auth,
        &body,
    )
    .await)
}

/// The owner creates `path` and returns its public key from the
/// authenticated describe GET.
async fn owner_created(h: &Harness, path: &str) -> anyhow::Result<Vec<u8>> {
    let (status, text) = create(h, &h.space_owner, None, path).await?;
    anyhow::ensure!(status == Status::Ok, "create {path}: {status} {text}");
    owner_described(h, path).await
}

/// The public key of `path` from the owner's authenticated describe GET.
async fn owner_described(h: &Harness, path: &str) -> anyhow::Result<Vec<u8>> {
    let (status, text) = describe(h, &h.space_owner, None, path).await?;
    anyhow::ensure!(status == Status::Ok, "describe {path}: {status} {text}");
    let descriptor: Value = serde_json::from_str(&text)?;
    Ok(base64::decode(
        descriptor["publicEncryptionKey"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("no publicEncryptionKey"))?,
    )?)
}

/// A decrypt the capability check refuses: 403, no wrapped key.
fn assert_decrypt_refused(what: &str, (status, text): &(Status, String)) {
    assert_eq!(*status, Status::Forbidden, "{what}: {text}");
    assert!(text.starts_with("Unauthorized Action"), "{what}: {text}");
}

/// Authenticated describe GET of `path` under a `decrypt` capability.
async fn describe(
    h: &Harness,
    signer: &Signer,
    proof: Option<&str>,
    path: &str,
) -> anyhow::Result<(Status, String)> {
    let facts = vec![json!({
        "type": KEY_DESCRIBE_TYPE,
        "targetNode": h.node_did(),
        "networkId": h.network,
        "keyPath": path,
    })];
    let auth = invocation(h, signer, &[(key(h, path), DECRYPT_ACTION)], facts, proof)?;
    Ok(get(
        h,
        &format!("/encryption/networks/{}/keys/{path}", h.network),
        Some(&auth),
    )
    .await)
}

/// A symmetric key wrapped to one public key, and the receiver that opens the
/// node's answer.
struct Wrapped {
    receiver: x25519_dalek::StaticSecret,
    alg: &'static str,
    wrapped: Vec<u8>,
    symmetric: Vec<u8>,
}

impl Wrapped {
    /// A v1 wrap to `public`.
    fn to(public: &[u8]) -> Self {
        let symmetric = vec![0x5Cu8; 32];
        Self {
            receiver: x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
            alg: ALG_X25519_AES256GCM,
            wrapped: wrap_to_public_key(public, &symmetric).expect("wrap to the key"),
            symmetric,
        }
    }

    /// A v2 wrap to `public` whose header names `network` and `key_path` at
    /// version 1.
    fn v2_to(public: &[u8], network: &str, key_path: &str) -> Self {
        let symmetric = vec![0x5Cu8; 32];
        let context = KeyWrapContext {
            purpose: KeyWrapPurpose::NetworkKey,
            network_id: network,
            key_path,
            key_version: 1,
            metadata: None,
        };
        Self {
            receiver: x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
            alg: ALG_X25519_HKDF_AES256GCM,
            wrapped: wrap_to_public_key_with_context(
                public,
                &symmetric,
                &context,
                KeyWrapVersion::V2,
            )
            .expect("v2 wrap to the key"),
            symmetric,
        }
    }

    fn open(&self, answer: &str) -> anyhow::Result<Vec<u8>> {
        let answer: Value = serde_json::from_str(answer)?;
        let wrapped = base64::decode(
            answer["wrappedKey"]
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("no wrappedKey"))?,
        )?;
        let (ephemeral, sealed) = wrapped.split_at(32);
        let peer = x25519_dalek::PublicKey::from(<[u8; 32]>::try_from(ephemeral)?);
        let shared = self.receiver.diffie_hellman(&peer);
        tinycloud_core::encryption::ColumnEncryption::new(*shared.as_bytes())
            .decrypt_legacy(sealed)
            .map_err(|error| anyhow::anyhow!("{error}"))
    }
}

/// The two decrypt routes.
#[derive(Clone, Copy, Debug)]
enum Route {
    Invoke,
    Direct,
}

/// Decrypt over `/invoke`. `path` names the key, `None` the network's root
/// key; the capability names the same target.
async fn decrypt(
    h: &Harness,
    signer: &Signer,
    proof: Option<&str>,
    path: Option<&str>,
    case: &Wrapped,
) -> anyhow::Result<(Status, String)> {
    decrypt_at(h, Route::Invoke, signer, proof, path, path, case).await
}

/// Decrypt over `route` under a `decrypt` capability on `cap_path` (`None`:
/// the bare network), with `body_path` as the body's and facts' `keyPath`.
async fn decrypt_at(
    h: &Harness,
    route: Route,
    signer: &Signer,
    proof: Option<&str>,
    cap_path: Option<&str>,
    body_path: Option<&str>,
    case: &Wrapped,
) -> anyhow::Result<(Status, String)> {
    let encrypted = base64::encode(&case.wrapped);
    let receiver = base64::encode(x25519_dalek::PublicKey::from(&case.receiver).to_bytes());
    let encrypted_hash = canonical_hash(&Value::String(encrypted.clone()));
    let receiver_hash = canonical_hash(&Value::String(receiver.clone()));
    let mut body = json!({
        "type": DECRYPT_REQUEST_TYPE,
        "targetNode": h.node_did(),
        "networkId": h.network,
        "alg": case.alg,
        "keyVersion": 1,
        "encryptedSymmetricKey": encrypted,
        "encryptedSymmetricKeyHash": encrypted_hash,
        "receiverPublicKey": receiver,
        "receiverPublicKeyHash": receiver_hash,
    });
    if let Some(path) = body_path {
        body["keyPath"] = json!(path);
    }
    let mut facts = json!({
        "type": DECRYPT_REQUEST_TYPE,
        "targetNode": h.node_did(),
        "networkId": h.network,
        "bodyHash": canonical_hash(&body),
        "encryptedSymmetricKeyHash": encrypted_hash,
        "receiverPublicKeyHash": receiver_hash,
        "alg": case.alg,
        "keyVersion": 1,
    });
    if let Some(path) = body_path {
        facts["keyPath"] = json!(path);
    }
    let resource = match cap_path {
        Some(path) => key(h, path),
        None => h.network.clone(),
    };
    let auth = invocation(h, signer, &[(resource, DECRYPT_ACTION)], vec![facts], proof)?;
    let uri = match route {
        Route::Invoke => "/invoke".to_string(),
        Route::Direct => format!("/encryption/networks/{}/decrypt", h.network),
    };
    Ok(post(h, &uri, &auth, &body).await)
}

/// The root network public key.
async fn root_public_key(h: &Harness) -> anyhow::Result<Vec<u8>> {
    Ok(h.client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed")
        .get_network(&h.network.parse()?)
        .await
        .map_err(|error| anyhow::anyhow!("{error}"))?
        .public_encryption_key)
}

/// The space owner grants `grants` to `holder` and returns the CID.
async fn grant(h: &Harness, holder: &Signer, grants: &[(String, &str)]) -> anyhow::Result<String> {
    h.import(
        h.space_owner
            .delegate(holder.did(), grants, window(), &[])?,
    )
    .await
}

async fn key_row_exists(h: &Harness, path: &str) -> anyhow::Result<bool> {
    use tinycloud_core::encryption_network::key_id::KeyLocation;
    let found = h
        .client
        .rocket()
        .state::<EncryptionService>()
        .expect("EncryptionService is managed")
        .describe_key(&KeyLocation::new(&h.network.parse()?, path)?)
        .await;
    match found {
        Ok(_) => Ok(true),
        Err(EncryptionServiceError::KeyNotFound) => Ok(false),
        Err(error) => Err(anyhow::anyhow!("{error}")),
    }
}

/// A seeded `secrets/x`: the owner creates it as a deletable key and reads
/// its public key from the descriptor; a symmetric key wrapped to it is
/// opened for a did:key holding only an exact-key `decrypt` grant. The same
/// grant opens neither the sibling `secrets/y` nor the network's root key.
async fn exact_secret_grant_decrypts_its_own_seeded_key_only(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = secrets_harness(
        backend,
        "exact_secret_grant_decrypts_its_own_seeded_key_only",
    )
    .await?
    else {
        return Ok(());
    };
    let (status, text) = create(&h, &h.space_owner, None, "secrets/x").await?;
    assert_eq!(status, Status::Ok, "{text}");
    let created: Value = serde_json::from_str(&text)?;
    assert_eq!(created["kind"], "deletable");
    assert_eq!(created["state"], "active");
    assert_eq!(created["keyVersion"], 1);
    let x_public = owner_described(&h, "secrets/x").await?;
    assert_eq!(base64::encode(&x_public), created["publicEncryptionKey"]);
    let y_public = owner_created(&h, "secrets/y").await?;

    let gateway = Signer::key();
    let proof = grant(&h, &gateway, &[(key(&h, "secrets/x"), DECRYPT_ACTION)]).await?;

    // The holder reads the descriptor and decrypts under the exact grant.
    let (status, text) = describe(&h, &gateway, Some(&proof), "secrets/x").await?;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(serde_json::from_str::<Value>(&text)?["kind"], "deletable");
    let case = Wrapped::to(&x_public);
    let (status, text) = decrypt(&h, &gateway, Some(&proof), Some("secrets/x"), &case).await?;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(case.open(&text)?, case.symmetric);

    // The sibling key is refused.
    let refused = decrypt(
        &h,
        &gateway,
        Some(&proof),
        Some("secrets/y"),
        &Wrapped::to(&y_public),
    )
    .await?;
    assert_decrypt_refused("sibling", &refused);
    // The bare network is refused.
    let root = root_public_key(&h).await?;
    let refused = decrypt(&h, &gateway, Some(&proof), None, &Wrapped::to(&root)).await?;
    assert_decrypt_refused("network", &refused);
    Ok(())
}
on_both_backends!(exact_secret_grant_decrypts_its_own_seeded_key_only);

/// An exact `key.create` grant on `secrets/x` creates `secrets/x` and
/// nothing else, and a `secrets/` prefix grant creates any key below it.
async fn key_create_grants_cover_their_exact_key_or_everything_below_the_prefix(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = secrets_harness(
        backend,
        "key_create_grants_cover_their_exact_key_or_everything_below_the_prefix",
    )
    .await?
    else {
        return Ok(());
    };
    let exact_holder = Signer::key();
    let exact = grant(
        &h,
        &exact_holder,
        &[(key(&h, "secrets/x"), KEY_CREATE_ACTION)],
    )
    .await?;
    let (status, text) = create(&h, &exact_holder, Some(&exact), "secrets/y").await?;
    assert_eq!(status, Status::Unauthorized, "{text}");
    assert!(!key_row_exists(&h, "secrets/y").await?);
    let (status, text) = create(&h, &exact_holder, Some(&exact), "secrets/x").await?;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(serde_json::from_str::<Value>(&text)?["kind"], "deletable");

    let prefix_holder = Signer::key();
    let prefix = grant(
        &h,
        &prefix_holder,
        &[(format!("{}/secrets/", h.network), KEY_CREATE_ACTION)],
    )
    .await?;
    for path in ["secrets/y", "secrets/scoped/acme/token"] {
        let (status, text) = create(&h, &prefix_holder, Some(&prefix), path).await?;
        assert_eq!(status, Status::Ok, "{path}: {text}");
        let created: Value = serde_json::from_str(&text)?;
        assert_eq!(created["kind"], "deletable", "{path}");
        assert_eq!(created["keyPath"], path);
    }
    // The prefix covers nothing outside `secrets/`.
    let (status, text) = create(&h, &prefix_holder, Some(&prefix), "apps/acme/token").await?;
    assert_eq!(status, Status::Unauthorized, "{text}");
    assert!(!key_row_exists(&h, "apps/acme/token").await?);
    Ok(())
}
on_both_backends!(key_create_grants_cover_their_exact_key_or_everything_below_the_prefix);

/// The secret named SCOPED has the exact key `secrets/scoped`. A grant on
/// that key covers neither the scoped secrets' keys below
/// `secrets/scoped/` for decrypt nor for create.
async fn a_grant_on_the_exact_key_secrets_scoped_opens_nothing_below_it(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = secrets_harness(
        backend,
        "a_grant_on_the_exact_key_secrets_scoped_opens_nothing_below_it",
    )
    .await?
    else {
        return Ok(());
    };
    let scoped_public = owner_created(&h, "secrets/scoped").await?;
    let below_public = owner_created(&h, "secrets/scoped/acme/token").await?;
    let holder = Signer::key();
    let proof = grant(
        &h,
        &holder,
        &[
            (key(&h, "secrets/scoped"), DECRYPT_ACTION),
            (key(&h, "secrets/scoped"), KEY_CREATE_ACTION),
        ],
    )
    .await?;
    let case = Wrapped::to(&scoped_public);
    let (status, text) = decrypt(&h, &holder, Some(&proof), Some("secrets/scoped"), &case).await?;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(case.open(&text)?, case.symmetric);

    let refused = decrypt(
        &h,
        &holder,
        Some(&proof),
        Some("secrets/scoped/acme/token"),
        &Wrapped::to(&below_public),
    )
    .await?;
    assert_decrypt_refused("below the exact key", &refused);
    let (status, text) = create(&h, &holder, Some(&proof), "secrets/scoped/acme/other").await?;
    assert_eq!(status, Status::Unauthorized, "{text}");
    assert!(!key_row_exists(&h, "secrets/scoped/acme/other").await?);
    Ok(())
}
on_both_backends!(a_grant_on_the_exact_key_secrets_scoped_opens_nothing_below_it);

/// The unauthenticated public GET answers `key_not_found` for every key
/// under `secrets/`, created or not, exactly as under `apps/`; a key whose
/// first segment only starts with `secrets` still has a derived public key.
async fn public_get_never_answers_with_a_secret_key(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = secrets_harness(backend, "public_get_never_answers_with_a_secret_key").await?
    else {
        return Ok(());
    };
    owner_created(&h, "secrets/x").await?;
    owner_created(&h, "apps/acme/token").await?;
    let mut answers = Vec::new();
    for path in [
        "secrets/x",
        "secrets/missing",
        "secrets/scoped/acme/missing",
        "secrets",
        "apps/acme/token",
    ] {
        let answer = get(
            &h,
            &format!("/encryption/networks/{}/keys/{path}", h.network),
            None,
        )
        .await;
        assert_eq!(answer.0, Status::NotFound, "{path}: {}", answer.1);
        assert!(answer.1.starts_with(KEY_NOT_FOUND), "{path}: {}", answer.1);
        answers.push(answer);
    }
    assert!(
        answers.windows(2).all(|pair| pair[0] == pair[1]),
        "answers differ: {answers:?}"
    );
    let (status, text) = get(
        &h,
        &format!("/encryption/networks/{}/keys/secretsx/y", h.network),
        None,
    )
    .await;
    assert_eq!(status, Status::Ok, "{text}");
    Ok(())
}
on_both_backends!(public_get_never_answers_with_a_secret_key);

/// The node refuses to start while a key row at `secrets` or under
/// `secrets/` is not a deletable key, and starts once the row is gone.
async fn startup_refuses_a_non_deletable_key_row_under_secrets(
    backend: Backend,
) -> anyhow::Result<()> {
    use tinycloud_core::models::encryption_network_key;
    use tinycloud_core::sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, ModelTrait};

    let Some(h) = secrets_harness(
        backend,
        "startup_refuses_a_non_deletable_key_row_under_secrets",
    )
    .await?
    else {
        return Ok(());
    };
    owner_created(&h, "secrets/x").await?;
    h.boot_again(|_| {})
        .await
        .expect("boots with a deletable secret key");

    let db = Database::connect(h.database_url()).await?;
    let row = |path: &str| encryption_network_key::ActiveModel {
        network_id: Set(h.network.clone()),
        key_path: Set(path.to_string()),
        kind: Set("deterministic".to_string()),
        state: Set("active".to_string()),
        public_key: Set(vec![7u8; 32]),
        sealed_seed: Set(None),
        key_version: Set(1),
        created_at: Set("2026-01-01T00:00:00Z".to_string()),
        updated_at: Set("2026-01-01T00:00:00Z".to_string()),
    };
    // A first segment that only starts with `secrets` is an ordinary path.
    row("secretsx/y").insert(&db).await?;
    h.boot_again(|_| {})
        .await
        .expect("boots with an ordinary row");

    for path in ["secrets/old", "secrets"] {
        let stray = row(path).insert(&db).await?;
        let Err(error) = h.boot_again(|_| {}).await else {
            panic!("a deterministic row at {path} stops the start");
        };
        assert!(
            error
                .to_string()
                .contains("1 key rows under secrets/ are not deletable keys"),
            "{path}: {error}"
        );
        stray.delete(&db).await?;
    }
    h.boot_again(|_| {})
        .await
        .expect("boots once the rows are gone");
    Ok(())
}
on_both_backends!(startup_refuses_a_non_deletable_key_row_under_secrets);

/// A holder of an exact `secrets/x` decrypt grant (the gateway) re-delegates
/// it to an agent, which decrypts `secrets/x`. A re-delegation that names a
/// sibling key, the `secrets/` prefix, the bare network or another ability
/// is refused, and nothing it names opens.
async fn a_re_delegated_secret_grant_attenuates_and_cannot_widen(
    backend: Backend,
) -> anyhow::Result<()> {
    let Some(h) = secrets_harness(
        backend,
        "a_re_delegated_secret_grant_attenuates_and_cannot_widen",
    )
    .await?
    else {
        return Ok(());
    };
    let x_public = owner_created(&h, "secrets/x").await?;
    let y_public = owner_created(&h, "secrets/y").await?;
    let gateway = Signer::key();
    let gateway_grant = grant(&h, &gateway, &[(key(&h, "secrets/x"), DECRYPT_ACTION)]).await?;
    let gateway_cid: Cid = gateway_grant.parse()?;

    let agent = Signer::key();
    let agent_grant = h
        .import(gateway.delegate(
            agent.did(),
            &[(key(&h, "secrets/x"), DECRYPT_ACTION)],
            Window::until(now() + Duration::minutes(30)),
            &[gateway_cid],
        )?)
        .await?;
    let case = Wrapped::to(&x_public);
    let (status, text) = decrypt(&h, &agent, Some(&agent_grant), Some("secrets/x"), &case).await?;
    assert_eq!(status, Status::Ok, "{text}");
    assert_eq!(case.open(&text)?, case.symmetric);
    let refused = decrypt(
        &h,
        &agent,
        Some(&agent_grant),
        Some("secrets/y"),
        &Wrapped::to(&y_public),
    )
    .await?;
    assert_decrypt_refused("agent on a sibling", &refused);

    let wider = Signer::key();
    for (what, grants) in [
        ("sibling key", vec![(key(&h, "secrets/y"), DECRYPT_ACTION)]),
        (
            "secrets prefix",
            vec![(format!("{}/secrets/", h.network), DECRYPT_ACTION)],
        ),
        ("bare network", vec![(h.network.clone(), DECRYPT_ACTION)]),
        (
            "another ability",
            vec![(key(&h, "secrets/x"), KEY_CREATE_ACTION)],
        ),
    ] {
        let (status, body) = h
            .delegate(gateway.delegate(wider.did(), &grants, window(), &[gateway_cid])?)
            .await;
        assert_eq!(status, Status::Unauthorized, "{what}: {body}");
    }
    // A grant to the gateway does not let anyone else decrypt.
    let (status, text) = decrypt(
        &h,
        &wider,
        Some(&gateway_grant),
        Some("secrets/x"),
        &Wrapped::to(&x_public),
    )
    .await?;
    assert_eq!(status, Status::Forbidden, "{text}");
    assert!(text.starts_with("Unauthorized Invoker"), "{text}");
    Ok(())
}
on_both_backends!(a_re_delegated_secret_grant_attenuates_and_cannot_widen);

/// A grant of `decrypt` on the bare network opens the network's root key and
/// nothing wrapped to a secret's key: neither the secret key's v1 wrap, its
/// v2 wrap, nor a v2 wrap to it whose header is shaped like a root wrap, on
/// `/invoke` or on the direct route; a `keyPath` under a network capability
/// is refused.
async fn a_bare_network_grant_opens_no_secret_key_wrap(backend: Backend) -> anyhow::Result<()> {
    let Some(h) = secrets_harness(backend, "a_bare_network_grant_opens_no_secret_key_wrap").await?
    else {
        return Ok(());
    };
    let x_public = owner_created(&h, "secrets/x").await?;
    let root = root_public_key(&h).await?;
    let holder = Signer::key();
    let proof = grant(&h, &holder, &[(h.network.clone(), DECRYPT_ACTION)]).await?;

    for route in [Route::Invoke, Route::Direct] {
        // The grant is live: it opens a wrap to the root key.
        let case = Wrapped::to(&root);
        let (status, text) =
            decrypt_at(&h, route, &holder, Some(&proof), None, None, &case).await?;
        assert_eq!(status, Status::Ok, "{route:?} root: {text}");
        assert_eq!(case.open(&text)?, case.symmetric, "{route:?}");

        for (what, case) in [
            ("v1 wrap", Wrapped::to(&x_public)),
            (
                "v2 wrap",
                Wrapped::v2_to(&x_public, &h.network, "secrets/x"),
            ),
            (
                "v2 wrap with a root header",
                Wrapped::v2_to(&x_public, &h.network, ""),
            ),
        ] {
            let (status, text) =
                decrypt_at(&h, route, &holder, Some(&proof), None, None, &case).await?;
            assert_eq!(status, Status::Forbidden, "{route:?} {what}: {text}");
            assert!(
                text.starts_with("key_unwrap_failed"),
                "{route:?} {what}: {text}"
            );
            assert!(!text.contains("wrappedKey"), "{route:?} {what}: {text}");

            // Naming the secret's key under the network capability: `/invoke`
            // answers its refusals 403, the direct route 400.
            let (status, text) = decrypt_at(
                &h,
                route,
                &holder,
                Some(&proof),
                None,
                Some("secrets/x"),
                &case,
            )
            .await?;
            let refused = match route {
                Route::Invoke => Status::Forbidden,
                Route::Direct => Status::BadRequest,
            };
            assert_eq!(status, refused, "{route:?} {what} keyPath: {text}");
            assert!(
                text.starts_with("key_path_invalid"),
                "{route:?} {what} keyPath: {text}"
            );
        }
    }
    Ok(())
}
on_both_backends!(a_bare_network_grant_opens_no_secret_key_wrap);

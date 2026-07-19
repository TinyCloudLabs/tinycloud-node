//! P1 deploy-path gate (compute-service-implementation-plan.md, P1 section).
//!
//! Exercises the live P1 handlers against a REAL booted node
//! (`tinycloud::app`), asserting on the actual persisted rows via a second,
//! independent DB connection (the pattern proven by `compute_skeleton`):
//!
//!   * successful deploy persists artifact + D_fn + quota mirror;
//!   * injected-failure rollback in BOTH directions (no artifact without a
//!     valid delegation; no delegation without a successful artifact save;
//!     the mirror only moves after commit);
//!   * quota-exceeded deploy → 402;
//!   * handshake determinism (same CID+space → same routine DID) and
//!     idempotence / no side effects;
//!   * wrong-ability RoutineDid rejection (a non-`compute/deploy` capability
//!     presenting a `RoutineDid` body → 403);
//!   * superseded-D_fn revocation on re-deploy;
//!   * scope-selection rejections (multi-space caps; a cap that does not
//!     cover the body's function resource).
//!
//! Declared with `required-features = ["compute"]` in Cargo.toml so a plain
//! `cargo test` skips it and an explicit request without the feature errors
//! (C5 gate discipline).

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use base64::{encode_config, URL_SAFE_NO_PAD};
use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use tempfile::TempDir;
use tinycloud_auth::{
    authorization::Cid as AuthCid,
    resolver::DID_METHODS,
    resource::{Path as AuthPath, ResourceId, Service, SpaceId},
    siwe_recap::Ability as UcanAbility,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    hash::{hash, Hash},
    models::{
        abilities, actor, database_artifact, delegation as deleg_model, revocation as revoc_model,
        space as space_model,
    },
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, ConnectionTrait, Database,
        DatabaseConnection, EntityTrait, QueryFilter,
    },
    types::{Ability, Caveats, Resource, SpaceIdWrap},
};

/// A booted node plus a second DB connection to inspect persisted rows.
struct Env {
    rocket: rocket::Rocket<rocket::Build>,
    conn: DatabaseConnection,
    _tempdir: TempDir,
}

async fn boot() -> Result<Env> {
    let tempdir = TempDir::new()?;
    let datadir = tempdir.path().join("data");
    let db_url = format!("sqlite:{}", datadir.join("caps.db").display());
    let secret = encode_config([11u8; 32], URL_SAFE_NO_PAD);
    let config_overlay = format!(
        r#"
[storage]
datadir = "{}"

[keys]
type = "Static"
secret = "{}"
"#,
        datadir.display(),
        secret
    );
    let figment = rocket::Config::figment()
        .merge(Serialized::defaults(tinycloud::config::Config::default()))
        .merge(Toml::string(&config_overlay));
    let mut tinycloud_config = figment.extract::<tinycloud::config::Config>()?;
    tinycloud_config.storage.resolve();
    let rocket = tinycloud::app(&figment, &tinycloud_config, None).await?;
    let conn = Database::connect(ConnectOptions::new(db_url)).await?;
    Ok(Env {
        rocket,
        conn,
        _tempdir: tempdir,
    })
}

/// The space owner + a deployer holding a real `compute/deploy` grant.
struct Fixture {
    space: SpaceId,
    space_str: String,
    owner_jwk: JWK,
    owner_vm: String,
    holder_jwk: JWK,
    holder_did: String,
    holder_vm: String,
    parent_cid: AuthCid,
}

fn keypair() -> Result<(JWK, String, String)> {
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let frag = did
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    let vm = format!("{did}#{frag}");
    Ok((jwk, did, vm))
}

/// Create the space, seed actors, and seed an owner->holder
/// `compute/deploy` grant on `<space>/compute/` (space-wide, so it covers any
/// concrete function path).
async fn setup(conn: &DatabaseConnection, space_name: &str, holder_ability: &str) -> Result<Fixture> {
    let (owner_jwk, owner_did, owner_vm) = keypair()?;
    let owner_key_did = DID_METHODS.generate(&owner_jwk, "key")?;
    let space = SpaceId::new(owner_key_did, space_name.parse().map_err(|e| anyhow::anyhow!("{e:?}"))?);
    let space_str = space.to_string();
    // The space DID must equal the owner DID so the owner is root authority.
    assert_eq!(space.did().to_string(), owner_did);

    space_model::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(conn)
    .await?;

    let (holder_jwk, holder_did, holder_vm) = keypair()?;
    for did in [&owner_did, &holder_did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(conn)
        .await?;
    }

    // owner -> holder, compute/deploy on the whole compute service
    // (`<space>/compute`, path = None) so it authorizes any concrete function
    // path (a None-path base extends to any child path in `ResourceId::extends`).
    let grant_resource: ResourceId =
        space.clone().to_resource("compute".parse::<Service>()?, None, None, None);
    let parent_hash = hash(format!("compute-deploy-parent:{space_name}").as_bytes());
    deleg_model::ActiveModel {
        id: Set(parent_hash),
        delegator: Set(owner_did.clone()),
        delegatee: Set(holder_did.clone()),
        expiry: Set(None),
        issued_at: Set(None),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(format!("compute-deploy-parent:{space_name}").into_bytes()),
    }
    .insert(conn)
    .await?;
    abilities::ActiveModel {
        delegation: Set(parent_hash),
        resource: Set(Resource::TinyCloud(grant_resource)),
        ability: Set(Ability::try_from(holder_ability.to_string()).map_err(|e| anyhow::anyhow!("{e:?}"))?),
        caveats: Set(Caveats(BTreeMap::new())),
    }
    .insert(conn)
    .await?;

    Ok(Fixture {
        space,
        space_str,
        owner_jwk,
        owner_vm,
        holder_jwk,
        holder_did,
        holder_vm,
        parent_cid: parent_hash.to_cid(0x55),
    })
}

/// Sign a compute invocation by the holder, citing the seeded parent grant,
/// declaring `ability` on `<space>/compute/<function_path>`.
fn sign_invocation(fx: &Fixture, ability: &str, function_path: &str, nonce: &str) -> Result<String> {
    let resource: ResourceId = fx.space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some(function_path.parse::<AuthPath>()?),
        None,
        None,
    );
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        ability.parse::<UcanAbility>()?,
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    let invocation = Payload {
        issuer: fx.holder_vm.parse::<DIDURLBuf>()?,
        audience: fx.holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![fx.parent_cid],
        attenuation: caps,
    }
    .sign(fx.holder_jwk.get_algorithm().unwrap_or_default(), &fx.holder_jwk)?;
    Ok(invocation.encode()?)
}

/// Build the deploy-time `D_fn` UCAN, signed by the OWNER (root authority for
/// the space's kv resources, so no parent is needed). Every capability row
/// carries the `computeFunctionBinding` caveat naming `content_cid`.
fn build_dfn(
    fx: &Fixture,
    routine_did: &str,
    content_cid: &str,
    kv_specs: &[(&str, &str)], // (ability, kv path)
) -> Result<String> {
    let mut binding_nb: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    binding_nb.insert(
        "computeFunctionBinding".to_string(),
        serde_json::json!({ "functionCid": content_cid }),
    );

    let mut caps = Capabilities::new();
    for (ability, kv_path) in kv_specs {
        let resource: ResourceId = fx.space.clone().to_resource(
            "kv".parse::<Service>()?,
            Some(kv_path.parse::<AuthPath>()?),
            None,
            None,
        );
        caps.with_action(
            resource.as_uri(),
            ability.parse::<UcanAbility>()?,
            [binding_nb.clone()],
        );
    }

    let dfn = Payload {
        issuer: fx.owner_vm.parse::<DIDURLBuf>()?,
        audience: routine_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some(format!("urn:uuid:dfn-{content_cid}")),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![],
        attenuation: caps,
    }
    .sign(fx.owner_jwk.get_algorithm().unwrap_or_default(), &fx.owner_jwk)?;
    Ok(dfn.encode()?)
}

fn content_cid_of(wasm: &[u8]) -> String {
    hash(wasm).to_cid(0x55).to_string()
}

fn hash_from_cid(cid_str: &str) -> Result<Hash> {
    let cid: AuthCid = cid_str.parse()?;
    Ok(Hash::from(cid))
}

async fn post_invoke(client: &Client, auth: &str, body: &str) -> (Status, String) {
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth.to_string()))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    (status, body)
}

/// Fetch the routine DID for (space, content_cid) via the read-only handshake.
async fn handshake(client: &Client, fx: &Fixture, content_cid: &str, nonce: &str) -> Result<String> {
    let auth = sign_invocation(fx, "tinycloud.compute/deploy", content_cid, nonce)?;
    let body = format!(r#"{{"action":"routine_did","content_cid":"{content_cid}"}}"#);
    let (status, resp) = post_invoke(client, &auth, &body).await;
    assert_eq!(status, Status::Ok, "handshake failed: {resp}");
    let json: serde_json::Value = serde_json::from_str(&resp)?;
    Ok(json["routine_did"].as_str().context("no routine_did")?.to_string())
}

// --- Tests -----------------------------------------------------------------

#[tokio::test]
async fn successful_deploy_persists_artifact_delegation_and_quota_mirror() -> Result<()> {
    let env = boot().await?;
    let fx = setup(&env.conn, "deploy-success", "tinycloud.compute/deploy").await?;
    let tinycloud = env
        .rocket
        .state::<tinycloud::TinyCloud>()
        .context("TinyCloud state")?
        .clone();
    let client = Client::tracked(env.rocket).await?;

    let wasm = b"\0asm-fixture-v1".to_vec();
    let content_cid = content_cid_of(&wasm);
    let routine_did = handshake(&client, &fx, &content_cid, "urn:uuid:hs-1").await?;
    let dfn = build_dfn(&fx, &routine_did, &content_cid, &[("tinycloud.kv/get", "in/")])?;

    let auth = sign_invocation(&fx, "tinycloud.compute/deploy", "report", "urn:uuid:dep-1")?;
    let body = format!(
        r#"{{"action":"deploy","function":"report","wasm_b64":"{}","grant":"{}"}}"#,
        base64::encode(&wasm),
        dfn
    );
    let (status, resp) = post_invoke(&client, &auth, &body).await;
    assert_eq!(status, Status::Ok, "deploy failed: {resp}");
    let ack: serde_json::Value = serde_json::from_str(&resp)?;
    assert_eq!(ack["content_cid"].as_str(), Some(content_cid.as_str()));
    let grant_cid = ack["routine_did_grant"].as_str().context("grant cid")?.to_string();

    // Artifact row persisted (service tag "compute", name = function).
    let artifact = database_artifact::Entity::find_by_id((
        "compute".to_string(),
        fx.space_str.clone(),
        "report".to_string(),
    ))
    .one(&env.conn)
    .await?
    .context("artifact row must exist after deploy")?;
    assert_eq!(artifact.content_hash, content_cid);

    // D_fn delegation row persisted.
    let dfn_hash = hash_from_cid(&grant_cid)?;
    assert!(
        deleg_model::Entity::find_by_id(dfn_hash)
            .one(&env.conn)
            .await?
            .is_some(),
        "D_fn delegation row must exist after deploy"
    );

    // Quota mirror moved: store_size folds the compute artifact.
    let size = tinycloud
        .store_size(&fx.space)
        .await
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .context("store_size Some after deploy")?;
    assert!(
        size >= wasm.len() as u64,
        "store_size ({size}) must include the {} deployed bytes",
        wasm.len()
    );
    Ok(())
}

#[tokio::test]
async fn rollback_no_artifact_when_dfn_verification_fails() -> Result<()> {
    let env = boot().await?;
    let fx = setup(&env.conn, "rollback-dfn", "tinycloud.compute/deploy").await?;
    let client = Client::tracked(env.rocket).await?;

    let wasm = b"\0asm-rollback-dfn".to_vec();
    let content_cid = content_cid_of(&wasm);
    let routine_did = handshake(&client, &fx, &content_cid, "urn:uuid:hs-r1").await?;
    let mut dfn = build_dfn(&fx, &routine_did, &content_cid, &[("tinycloud.kv/get", "in/")])?;
    // Corrupt the JWT signature (last char) so verify() fails mid-transaction.
    let last = dfn.pop().unwrap();
    dfn.push(if last == 'A' { 'B' } else { 'A' });

    let auth = sign_invocation(&fx, "tinycloud.compute/deploy", "report", "urn:uuid:dep-r1")?;
    let body = format!(
        r#"{{"action":"deploy","function":"report","wasm_b64":"{}","grant":"{}"}}"#,
        base64::encode(&wasm),
        dfn
    );
    let (status, resp) = post_invoke(&client, &auth, &body).await;
    assert_ne!(status, Status::Ok, "a bad-signature D_fn must not deploy: {resp}");

    // No artifact row, no D_fn delegation row.
    assert!(
        database_artifact::Entity::find_by_id((
            "compute".to_string(),
            fx.space_str.clone(),
            "report".to_string(),
        ))
        .one(&env.conn)
        .await?
        .is_none(),
        "no artifact must be persisted when the D_fn fails verification"
    );
    let dfn_hash = hash(dfn.as_bytes());
    assert!(
        deleg_model::Entity::find_by_id(dfn_hash)
            .one(&env.conn)
            .await?
            .is_none(),
        "no delegation must be persisted when the D_fn fails verification"
    );
    Ok(())
}

#[tokio::test]
async fn rollback_no_delegation_when_artifact_save_fails() -> Result<()> {
    let env = boot().await?;
    let fx = setup(&env.conn, "rollback-artifact", "tinycloud.compute/deploy").await?;

    let wasm = b"\0asm-rollback-artifact".to_vec();
    let content_cid = content_cid_of(&wasm);

    // Injected artifact-save failure: a UNIQUE index on content_hash plus a
    // pre-existing row carrying the SAME content_hash under a DIFFERENT PK.
    // The deploy's artifact INSERT (new PK, duplicate content_hash) then
    // violates the index mid-transaction, AFTER the D_fn was processed in the
    // same tx -- so the delegation must roll back.
    env.conn
        .execute_unprepared(
            "CREATE UNIQUE INDEX test_unique_content_hash ON database_artifact(content_hash)",
        )
        .await?;
    database_artifact::ActiveModel {
        service: Set("other".to_string()),
        space: Set(fx.space_str.clone()),
        name: Set("decoy".to_string()),
        revision: Set(1),
        content_hash: Set(content_cid.clone()),
        payload: Set(vec![1, 2, 3]),
        size_bytes: Set(3),
        backend: Set("storage.database".to_string()),
        storage_mode: Set("database-blob".to_string()),
        created_at: Set("2020-01-01T00:00:00Z".to_string()),
        updated_at: Set("2020-01-01T00:00:00Z".to_string()),
    }
    .insert(&env.conn)
    .await?;

    let client = Client::tracked(env.rocket).await?;
    let routine_did = handshake(&client, &fx, &content_cid, "urn:uuid:hs-r2").await?;
    let dfn = build_dfn(&fx, &routine_did, &content_cid, &[("tinycloud.kv/get", "in/")])?;
    let dfn_hash = hash(dfn.as_bytes());

    let auth = sign_invocation(&fx, "tinycloud.compute/deploy", "report", "urn:uuid:dep-r2")?;
    let body = format!(
        r#"{{"action":"deploy","function":"report","wasm_b64":"{}","grant":"{}"}}"#,
        base64::encode(&wasm),
        dfn
    );
    let (status, resp) = post_invoke(&client, &auth, &body).await;
    assert_ne!(status, Status::Ok, "artifact-insert failure must fail the deploy: {resp}");

    // The D_fn delegation row rolled back with the failed artifact insert.
    assert!(
        deleg_model::Entity::find_by_id(dfn_hash)
            .one(&env.conn)
            .await?
            .is_none(),
        "the D_fn delegation must roll back when the artifact save fails"
    );
    // No compute artifact row for (compute, space, report).
    assert!(
        database_artifact::Entity::find_by_id((
            "compute".to_string(),
            fx.space_str.clone(),
            "report".to_string(),
        ))
        .one(&env.conn)
        .await?
        .is_none(),
        "no compute artifact row after a failed deploy"
    );
    Ok(())
}

#[tokio::test]
async fn quota_exceeded_deploy_is_rejected() -> Result<()> {
    let env = boot().await?;
    let fx = setup(&env.conn, "deploy-quota", "tinycloud.compute/deploy").await?;
    let client = Client::tracked(env.rocket).await?;

    // Deploy #1 with no limit -> establishes the SqlSizes footprint.
    let wasm1 = b"\0asm-quota-v1-payload".to_vec();
    let cid1 = content_cid_of(&wasm1);
    let rd1 = handshake(&client, &fx, &cid1, "urn:uuid:hs-q1").await?;
    let dfn1 = build_dfn(&fx, &rd1, &cid1, &[("tinycloud.kv/get", "in/")])?;
    let auth1 = sign_invocation(&fx, "tinycloud.compute/deploy", "fn1", "urn:uuid:dep-q1")?;
    let (s1, r1) = post_invoke(
        &client,
        &auth1,
        &format!(
            r#"{{"action":"deploy","function":"fn1","wasm_b64":"{}","grant":"{}"}}"#,
            base64::encode(&wasm1),
            dfn1
        ),
    )
    .await;
    assert_eq!(s1, Status::Ok, "deploy #1 should succeed: {r1}");

    // Set a per-space limit smaller than the current footprint. The managed
    // QuotaCache is reachable via the running rocket instance.
    let quota = client
        .rocket()
        .state::<tinycloud::quota::QuotaCache>()
        .context("QuotaCache state")?;
    quota.set_limit(&fx.space, 1).await;

    // Deploy #2 -> over quota -> 402.
    let wasm2 = b"\0asm-quota-v2-payload".to_vec();
    let cid2 = content_cid_of(&wasm2);
    let rd2 = handshake(&client, &fx, &cid2, "urn:uuid:hs-q2").await?;
    let dfn2 = build_dfn(&fx, &rd2, &cid2, &[("tinycloud.kv/get", "in/")])?;
    let auth2 = sign_invocation(&fx, "tinycloud.compute/deploy", "fn2", "urn:uuid:dep-q2")?;
    let (s2, r2) = post_invoke(
        &client,
        &auth2,
        &format!(
            r#"{{"action":"deploy","function":"fn2","wasm_b64":"{}","grant":"{}"}}"#,
            base64::encode(&wasm2),
            dfn2
        ),
    )
    .await;
    assert_eq!(s2.code, 402, "over-quota deploy must 402: {r2}");
    Ok(())
}

#[tokio::test]
async fn handshake_is_deterministic_and_side_effect_free() -> Result<()> {
    let env = boot().await?;
    let fx = setup(&env.conn, "handshake-det", "tinycloud.compute/deploy").await?;
    let client = Client::tracked(env.rocket).await?;

    let content_cid = content_cid_of(b"\0asm-handshake");
    let a = handshake(&client, &fx, &content_cid, "urn:uuid:hd-1").await?;
    let b = handshake(&client, &fx, &content_cid, "urn:uuid:hd-2").await?;
    assert_eq!(a, b, "same (space, content_cid) must return the same routine_did");
    assert!(a.starts_with("did:key:z"), "expected a did:key, got {a}");

    // A different CID yields a different DID.
    let other = handshake(&client, &fx, &content_cid_of(b"\0asm-other"), "urn:uuid:hd-3").await?;
    assert_ne!(a, other);

    // No artifact row was created by the read-only handshake.
    assert!(
        database_artifact::Entity::find()
            .filter(database_artifact::Column::Space.eq(fx.space_str.clone()))
            .one(&env.conn)
            .await?
            .is_none(),
        "the RoutineDid handshake must not persist any artifact"
    );
    Ok(())
}

#[tokio::test]
async fn routine_did_rejects_non_deploy_ability() -> Result<()> {
    let env = boot().await?;
    // Holder is granted compute/execute ONLY.
    let fx = setup(&env.conn, "routine-did-wrong-ability", "tinycloud.compute/execute").await?;
    let client = Client::tracked(env.rocket).await?;

    let content_cid = content_cid_of(b"\0asm-wrong-ability");
    // Present a compute/execute capability with a RoutineDid body (requires
    // compute/deploy).
    let auth = sign_invocation(&fx, "tinycloud.compute/execute", &content_cid, "urn:uuid:wa-1")?;
    let body = format!(r#"{{"action":"routine_did","content_cid":"{content_cid}"}}"#);
    let (status, resp) = post_invoke(&client, &auth, &body).await;
    assert_eq!(
        status,
        Status::Forbidden,
        "a compute/execute capability must not authorize a RoutineDid body: {resp}"
    );
    assert!(resp.starts_with("Unauthorized Action:"), "got: {resp}");
    Ok(())
}

#[tokio::test]
async fn superseded_dfn_is_revoked_on_redeploy() -> Result<()> {
    let env = boot().await?;
    let fx = setup(&env.conn, "redeploy-revoke", "tinycloud.compute/deploy").await?;
    let client = Client::tracked(env.rocket).await?;

    // Deploy v1.
    let wasm1 = b"\0asm-redeploy-v1".to_vec();
    let cid1 = content_cid_of(&wasm1);
    let rd1 = handshake(&client, &fx, &cid1, "urn:uuid:rr-hs1").await?;
    let dfn1 = build_dfn(&fx, &rd1, &cid1, &[("tinycloud.kv/get", "in/")])?;
    let (s1, r1) = post_invoke(
        &client,
        &sign_invocation(&fx, "tinycloud.compute/deploy", "report", "urn:uuid:rr-d1")?,
        &format!(
            r#"{{"action":"deploy","function":"report","wasm_b64":"{}","grant":"{}"}}"#,
            base64::encode(&wasm1),
            dfn1
        ),
    )
    .await;
    assert_eq!(s1, Status::Ok, "deploy v1: {r1}");
    let ack1: serde_json::Value = serde_json::from_str(&r1)?;
    let grant1_cid = ack1["routine_did_grant"].as_str().context("grant1")?.to_string();
    let grant1_hash = hash_from_cid(&grant1_cid)?;

    // Deploy v2 (different bytes -> different CID) to the SAME function name.
    let wasm2 = b"\0asm-redeploy-v2-different".to_vec();
    let cid2 = content_cid_of(&wasm2);
    assert_ne!(cid1, cid2);
    let rd2 = handshake(&client, &fx, &cid2, "urn:uuid:rr-hs2").await?;
    let dfn2 = build_dfn(&fx, &rd2, &cid2, &[("tinycloud.kv/get", "in/")])?;
    let (s2, r2) = post_invoke(
        &client,
        &sign_invocation(&fx, "tinycloud.compute/deploy", "report", "urn:uuid:rr-d2")?,
        &format!(
            r#"{{"action":"deploy","function":"report","wasm_b64":"{}","grant":"{}"}}"#,
            base64::encode(&wasm2),
            dfn2
        ),
    )
    .await;
    assert_eq!(s2, Status::Ok, "deploy v2: {r2}");
    let ack2: serde_json::Value = serde_json::from_str(&r2)?;
    assert_eq!(
        ack2["superseded_content_cid"].as_str(),
        Some(cid1.as_str()),
        "re-deploy must report the superseded content CID"
    );
    assert_eq!(
        ack2["superseded_grant"].as_str(),
        Some(grant1_cid.as_str()),
        "re-deploy must report the superseded D_fn CID"
    );

    // The v1 D_fn is now revoked.
    let revoked = revoc_model::Entity::find()
        .filter(revoc_model::Column::Revoked.eq(grant1_hash))
        .one(&env.conn)
        .await?;
    assert!(revoked.is_some(), "the superseded v1 D_fn must be revoked after re-deploy");
    Ok(())
}

#[tokio::test]
async fn scope_selection_rejects_multi_space_capabilities() -> Result<()> {
    let env = boot().await?;

    // Two spaces (distinct owners) that BOTH grant compute/deploy to the SAME
    // holder, so a multi-space invocation passes layer (a) chain validation --
    // and is then rejected by compute's scope selection (a single request may
    // only target one space). Without the scope selector this would be a
    // confused-deputy: a multi-space session silently mixing spaces.
    let (holder_jwk, holder_did, holder_vm) = keypair()?;

    let seed_space = |name: &str| -> Result<(SpaceId, String)> {
        let (owner_jwk, owner_did, _vm) = keypair()?;
        let owner_key_did = DID_METHODS.generate(&owner_jwk, "key")?;
        let space =
            SpaceId::new(owner_key_did, name.parse().map_err(|e| anyhow::anyhow!("{e:?}"))?);
        Ok((space, owner_did))
    };

    let (space_a, owner_a) = seed_space("scope-multi-a")?;
    let (space_b, owner_b) = seed_space("scope-multi-b")?;

    for space in [&space_a, &space_b] {
        space_model::ActiveModel {
            id: Set(SpaceIdWrap(space.clone())),
        }
        .insert(&env.conn)
        .await?;
    }
    for did in [&owner_a, &owner_b, &holder_did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(&env.conn)
        .await?;
    }

    let mut parents = Vec::new();
    for (space, owner_did, tag) in [(&space_a, &owner_a, "a"), (&space_b, &owner_b, "b")] {
        let grant_resource: ResourceId =
            space.clone().to_resource("compute".parse()?, None, None, None);
        let parent_hash = hash(format!("multi-space-parent-{tag}").as_bytes());
        deleg_model::ActiveModel {
            id: Set(parent_hash),
            delegator: Set(owner_did.clone()),
            delegatee: Set(holder_did.clone()),
            expiry: Set(None),
            issued_at: Set(None),
            not_before: Set(None),
            facts: Set(None),
            serialization: Set(format!("multi-space-parent-{tag}").into_bytes()),
        }
        .insert(&env.conn)
        .await?;
        abilities::ActiveModel {
            delegation: Set(parent_hash),
            resource: Set(Resource::TinyCloud(grant_resource)),
            ability: Set(Ability::try_from("tinycloud.compute/deploy".to_string())
                .map_err(|e| anyhow::anyhow!("{e:?}"))?),
            caveats: Set(Caveats(BTreeMap::new())),
        }
        .insert(&env.conn)
        .await?;
        parents.push(parent_hash.to_cid(0x55));
    }

    let client = Client::tracked(env.rocket).await?;

    let res_a: ResourceId =
        space_a.clone().to_resource("compute".parse()?, Some("report".parse()?), None, None);
    let res_b: ResourceId =
        space_b.clone().to_resource("compute".parse()?, Some("report".parse()?), None, None);
    let mut caps = Capabilities::new();
    caps.with_action(
        res_a.as_uri(),
        "tinycloud.compute/deploy".parse::<UcanAbility>()?,
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    caps.with_action(
        res_b.as_uri(),
        "tinycloud.compute/deploy".parse::<UcanAbility>()?,
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    let invocation = Payload {
        issuer: holder_vm.parse::<DIDURLBuf>()?,
        audience: holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some("urn:uuid:multi-space".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: parents,
        attenuation: caps,
    }
    .sign(holder_jwk.get_algorithm().unwrap_or_default(), &holder_jwk)?;
    let auth = invocation.encode()?;

    let body = r#"{"action":"routine_did","content_cid":"report"}"#;
    let (status, resp) = post_invoke(&client, &auth, body).await;
    assert_eq!(
        status,
        Status::BadRequest,
        "compute caps spanning multiple spaces must be rejected: {resp}"
    );
    assert!(resp.contains("multiple spaces"), "got: {resp}");
    Ok(())
}

#[tokio::test]
async fn scope_selection_rejects_uncovered_function_resource() -> Result<()> {
    let env = boot().await?;
    // Holder granted compute/deploy on a SPECIFIC function ("alpha") only, not
    // space-wide.
    let (owner_jwk, owner_did, _owner_vm) = keypair()?;
    let owner_key_did = DID_METHODS.generate(&owner_jwk, "key")?;
    let space = SpaceId::new(owner_key_did, "scope-uncovered".parse().map_err(|e| anyhow::anyhow!("{e:?}"))?);
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(&env.conn)
    .await?;
    let (holder_jwk, holder_did, holder_vm) = keypair()?;
    for did in [&owner_did, &holder_did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(&env.conn)
        .await?;
    }
    let grant_resource: ResourceId =
        space.clone().to_resource("compute".parse()?, Some("alpha".parse()?), None, None);
    let parent_hash = hash(b"scope-uncovered-parent");
    deleg_model::ActiveModel {
        id: Set(parent_hash),
        delegator: Set(owner_did.clone()),
        delegatee: Set(holder_did.clone()),
        expiry: Set(None),
        issued_at: Set(None),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(b"scope-uncovered-parent".to_vec()),
    }
    .insert(&env.conn)
    .await?;
    abilities::ActiveModel {
        delegation: Set(parent_hash),
        resource: Set(Resource::TinyCloud(grant_resource)),
        ability: Set(Ability::try_from("tinycloud.compute/deploy".to_string()).map_err(|e| anyhow::anyhow!("{e:?}"))?),
        caveats: Set(Caveats(BTreeMap::new())),
    }
    .insert(&env.conn)
    .await?;
    let parent_cid = parent_hash.to_cid(0x55);

    let client = Client::tracked(env.rocket).await?;

    // Invocation declares compute/deploy on "alpha" (covered by the grant),
    // but the deploy BODY targets function "beta" -- the held cap does not
    // cover beta, so scope selection must reject it.
    let res_alpha: ResourceId =
        space.clone().to_resource("compute".parse()?, Some("alpha".parse()?), None, None);
    let mut caps = Capabilities::new();
    caps.with_action(
        res_alpha.as_uri(),
        "tinycloud.compute/deploy".parse::<UcanAbility>()?,
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    let invocation = Payload {
        issuer: holder_vm.parse::<DIDURLBuf>()?,
        audience: holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some("urn:uuid:uncovered".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![parent_cid],
        attenuation: caps,
    }
    .sign(holder_jwk.get_algorithm().unwrap_or_default(), &holder_jwk)?;
    let auth = invocation.encode()?;

    let wasm = b"\0asm-uncovered".to_vec();
    let body = format!(
        r#"{{"action":"deploy","function":"beta","wasm_b64":"{}","grant":"x"}}"#,
        base64::encode(&wasm),
    );
    let (status, resp) = post_invoke(&client, &auth, &body).await;
    assert_eq!(
        status,
        Status::Forbidden,
        "a cap for function 'alpha' must not authorize a deploy of 'beta': {resp}"
    );
    assert!(resp.starts_with("Unauthorized Action:"), "got: {resp}");
    Ok(())
}

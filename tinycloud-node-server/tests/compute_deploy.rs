//! P1 deploy-path gate (compute-service-implementation-plan.md, P1 section):
//! `cargo test -p tinycloud-node --test compute_deploy --features compute`.
//!
//! Declared with `required-features = ["compute"]` so a plain `cargo test`
//! skips it and an explicit `--test compute_deploy` without `--features
//! compute` errors instead of silently reporting zero tests (C5).
//!
//! Covers, per the plan's P1 verify block + the judge-mandated scope fix:
//!   * successful deploy persists the artifact + the `D_fn` (with the
//!     `computeFunctionBinding` caveat) + bumps the quota mirror;
//!   * atomic rollback -- a `D_fn` that fails verification leaves NO artifact
//!     row (direction: no artifact without delegation);
//!   * quota-exceeded deploy -> 402, and a deploy bumps `store_size` so a
//!     following over-limit deploy 402s (mirror-after-commit, observed via the
//!     quota gate);
//!   * `RoutineDid` handshake determinism (same (space, CID) -> same DID; a
//!     different CID -> a different DID) and idempotence (no side effects);
//!   * wrong-ability `RoutineDid` rejection (a `compute/execute` cap presenting
//!     a `RoutineDid` body -> 403);
//!   * superseded-`D_fn` revocation on re-deploy;
//!   * scope-selection rejections (multi-space, uncovered function).
//!
//! Every capability presented is backed by a REAL delegation chain (a space
//! owner's root authority, or an owner->holder delegation), so layer-(a)
//! authorization runs for real, not against self-declared attenuation.
//!
//! The deploy `D_fn`s are minted here exactly as a client would: the routine
//! DID is derived with the SAME classic secret the booted node uses
//! (`[11u8; 32]`), so `D_fn.delegatee == routine_did`.

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
    models::{
        abilities, actor, database_artifact, delegation as deleg_model, revocation as revo_model,
        space as space_model,
    },
    sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, Database,
        DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    },
    types::{Ability, Caveats, Resource, SpaceIdWrap},
};

/// The node's classic identity secret in these tests (matches `boot()`).
const NODE_SECRET: [u8; 32] = [11u8; 32];

fn far_future() -> f64 {
    4_102_444_800.0
}

/// Boot a real `tinycloud::app(...)` against a file-backed sqlite DB (so a
/// second connection can seed/inspect rows directly) with an optional storage
/// limit. Mirrors the compute_skeleton boot helper.
async fn boot_with_limit(
    limit: Option<&str>,
) -> Result<(rocket::Rocket<rocket::Build>, DatabaseConnection, TempDir)> {
    let tempdir = TempDir::new()?;
    let datadir = tempdir.path().join("data");
    let db_url = format!("sqlite:{}", datadir.join("caps.db").display());
    let secret = encode_config(NODE_SECRET, URL_SAFE_NO_PAD);
    let limit_line = limit
        .map(|l| format!("limit = \"{l}\"\n"))
        .unwrap_or_default();
    let config_overlay = format!(
        r#"
[storage]
datadir = "{}"
{}
[keys]
type = "Static"
secret = "{}"
"#,
        datadir.display(),
        limit_line,
        secret
    );
    let figment = rocket::Config::figment()
        .merge(Serialized::defaults(tinycloud::config::Config::default()))
        .merge(Toml::string(&config_overlay));
    let mut tinycloud_config = figment.extract::<tinycloud::config::Config>()?;
    tinycloud_config.storage.resolve();
    let rocket = tinycloud::app(&figment, &tinycloud_config, None).await?;
    let conn = Database::connect(ConnectOptions::new(db_url)).await?;
    Ok((rocket, conn, tempdir))
}

async fn boot() -> Result<(rocket::Rocket<rocket::Build>, DatabaseConnection, TempDir)> {
    boot_with_limit(None).await
}

/// A space plus the owner's signing material. The owner's did:key is the
/// space's base DID, so the owner is the root authority over the space and can
/// mint `D_fn`s and invoke `compute/deploy` with no parent proof.
struct Owner {
    space: SpaceId,
    jwk: JWK,
    vm: String,
    did: String,
}

fn make_owner(name: &str) -> Result<Owner> {
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = did.rsplit_once(':').context("did fragment")?.1.to_string();
    let vm = format!("{did}#{fragment}");
    let space = SpaceId::new(did.parse::<DIDBuf>()?, name.parse().map_err(|e| anyhow::anyhow!("{e:?}"))?);
    // Sanity: the space's base DID is the owner DID (root authority).
    assert_eq!(space.did().to_string(), did);
    Ok(Owner {
        space,
        jwk,
        vm,
        did,
    })
}

async fn seed_space_and_actors(
    conn: &DatabaseConnection,
    space: &SpaceId,
    extra_dids: &[String],
) -> Result<()> {
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(conn)
    .await?;
    let mut dids = vec![space.did().to_string()];
    dids.extend(extra_dids.iter().cloned());
    for did in dids {
        // Actors may already exist (e.g. an owner shared across helpers).
        let _ = actor::ActiveModel { id: Set(did) }.insert(conn).await;
    }
    Ok(())
}

fn content_cid(wasm: &[u8]) -> String {
    tinycloud_core::hash::hash(wasm).to_cid(0x55).to_string()
}

/// Obtain the routine DID the way a real client does: the read-only
/// `RoutineDid` handshake (§6.2/F2). This is deliberately NOT a client-side
/// re-derivation -- the node's secret is not known to the client (and in this
/// environment is supplied via `TINYCLOUD_KEYS_SECRET`, not the test config),
/// so the handshake is the ONLY correct way to learn `routine_did` before
/// binding `D_fn.delegatee`.
async fn handshake_routine_did(
    client: &Client,
    owner: &Owner,
    cid: &str,
    nonce: &str,
) -> Result<String> {
    let auth = owner_compute_invocation(owner, cid, "tinycloud.compute/deploy", nonce)?;
    let body = serde_json::json!({ "action": "routine_did", "content_cid": cid }).to_string();
    let (status, text) = post_invoke(client, &auth, body).await;
    anyhow::ensure!(
        status == Status::Ok,
        "routine_did handshake failed ({status}): {text}"
    );
    let v: serde_json::Value = serde_json::from_str(&text)?;
    Ok(v["routine_did"]
        .as_str()
        .context("routine_did missing")?
        .to_string())
}

/// Mint a `D_fn` (owner -> routine_did) granting `kv/get` on `in/` with the
/// `computeFunctionBinding` caveat naming `content_cid`. Owner is root
/// authority, so no parent proof is needed.
fn mint_d_fn(owner: &Owner, routine_did: &str, content_cid: &str, nonce: &str) -> Result<String> {
    mint_d_fn_signed_by(owner, &owner.jwk, routine_did, content_cid, nonce)
}

/// As `mint_d_fn`, but signs with `signer_jwk`. When `signer_jwk` is NOT the
/// owner's key, the D_fn still DECODES cleanly (valid structure) but fails
/// signature verification INSIDE the deploy transaction -- exercising the true
/// transaction-rollback path (`delegation::process`'s `verify()`), not a
/// pre-transaction decode reject.
fn mint_d_fn_signed_by(
    owner: &Owner,
    signer_jwk: &JWK,
    routine_did: &str,
    content_cid: &str,
    nonce: &str,
) -> Result<String> {
    let kv_resource: ResourceId = owner.space.clone().to_resource(
        "kv".parse::<Service>()?,
        Some("in/".parse::<AuthPath>()?),
        None,
        None,
    );
    let mut binding = std::collections::BTreeMap::<String, serde_json::Value>::new();
    binding.insert(
        "computeFunctionBinding".to_string(),
        serde_json::json!({ "functionCid": content_cid }),
    );
    let mut caps = Capabilities::new();
    caps.with_action(
        kv_resource.as_uri(),
        "tinycloud.kv/get".parse::<UcanAbility>()?,
        [binding],
    );
    let ucan = Payload {
        issuer: owner.vm.parse::<DIDURLBuf>()?,
        audience: routine_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(far_future())?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: Vec::new(),
        attenuation: caps,
    }
    .sign(signer_jwk.get_algorithm().unwrap_or_default(), signer_jwk)?;
    Ok(ucan.encode()?)
}

/// Sign a compute invocation as `owner` (root authority, no proof) citing
/// `<space>/compute/<path>` with `ability`.
fn owner_compute_invocation(
    owner: &Owner,
    path: &str,
    ability: &str,
    nonce: &str,
) -> Result<String> {
    let resource: ResourceId = owner.space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some(path.parse::<AuthPath>()?),
        None,
        None,
    );
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        ability.parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );
    let ucan = Payload {
        issuer: owner.vm.parse::<DIDURLBuf>()?,
        audience: owner.did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(far_future())?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: Vec::new(),
        attenuation: caps,
    }
    .sign(owner.jwk.get_algorithm().unwrap_or_default(), &owner.jwk)?;
    Ok(ucan.encode()?)
}

fn deploy_body(function: &str, wasm: &[u8], grant: &str) -> String {
    serde_json::json!({
        "action": "deploy",
        "function": function,
        "wasm_b64": encode_config(wasm, base64::STANDARD),
        "grant": grant,
    })
    .to_string()
}

async fn post_invoke(client: &Client, auth: &str, body: String) -> (Status, String) {
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth.to_string()))
        .header(ContentType::JSON)
        .body(body)
        .dispatch()
        .await;
    let status = response.status();
    let text = response.into_string().await.unwrap_or_default();
    (status, text)
}

// ---------------------------------------------------------------------------
// Happy path
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deploy_persists_artifact_delegation_and_binding_caveat() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("deploy-happy")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;

    let wasm = b"\x00asm\x01\x00\x00\x00happy".to_vec();
    let cid = content_cid(&wasm);
    let client = Client::tracked(rocket).await?;
    let rdid = handshake_routine_did(&client, &owner, &cid, "urn:uuid:hs-happy").await?;
    let grant = mint_d_fn(&owner, &rdid, &cid, "urn:uuid:dfn-happy")?;
    let auth = owner_compute_invocation(&owner, "hello", "tinycloud.compute/deploy", "urn:uuid:inv-happy")?;

    let (status, body) = post_invoke(&client, &auth, deploy_body("hello", &wasm, &grant)).await;
    assert_eq!(status, Status::Ok, "deploy must succeed: {body}");

    let ack: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(ack["content_cid"], cid, "ack must return the function CID");
    assert_eq!(ack["routine_did"], rdid, "ack must return the routine DID");
    assert_eq!(ack["revision"], 1);
    assert_eq!(ack["function"], "hello");

    // Artifact persisted under (compute, space, function).
    let artifact = database_artifact::Entity::find_by_id((
        "compute".to_string(),
        owner.space.to_string(),
        "hello".to_string(),
    ))
    .one(&conn)
    .await?
    .context("artifact row must exist after deploy")?;
    assert_eq!(artifact.content_hash, cid);
    assert_eq!(artifact.payload, wasm, "stored payload must equal the deployed bytes");

    // D_fn persisted through the standard delegation path, with the binding
    // caveat on its ability row.
    let dfn = deleg_model::Entity::find()
        .filter(deleg_model::Column::Delegatee.eq(rdid.clone()))
        .one(&conn)
        .await?
        .context("D_fn delegation must be persisted with delegatee == routine_did")?;
    let ability_rows = abilities::Entity::find()
        .filter(abilities::Column::Delegation.eq(dfn.id))
        .all(&conn)
        .await?;
    assert!(!ability_rows.is_empty(), "D_fn must persist ability rows");
    let has_binding = ability_rows.iter().any(|row| {
        row.caveats.0.values().any(|v| {
            v.get("computeFunctionBinding")
                .and_then(|b| b.get("functionCid"))
                .map(|fc| fc == &serde_json::Value::String(cid.clone()))
                .unwrap_or(false)
        })
    });
    assert!(has_binding, "D_fn ability rows must carry the computeFunctionBinding caveat");
    Ok(())
}

// ---------------------------------------------------------------------------
// Atomic rollback: bad D_fn -> no artifact (no artifact without delegation)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deploy_with_unverifiable_grant_rolls_back_no_artifact() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("deploy-rollback")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;

    let wasm = b"\x00asm\x01\x00\x00\x00rollback".to_vec();
    let cid = content_cid(&wasm);
    let client = Client::tracked(rocket).await?;
    let rdid = handshake_routine_did(&client, &owner, &cid, "urn:uuid:hs-bad").await?;
    // Sign the D_fn with a key that is NOT the owner's, so it decodes cleanly
    // but fails signature verification INSIDE the deploy transaction -- the
    // true rollback path, not a pre-transaction decode reject.
    let mut wrong_signer = JWK::generate_ed25519()?;
    wrong_signer.algorithm = Some(Algorithm::EdDSA);
    let grant = mint_d_fn_signed_by(&owner, &wrong_signer, &rdid, &cid, "urn:uuid:dfn-bad")?;
    let auth = owner_compute_invocation(&owner, "hello", "tinycloud.compute/deploy", "urn:uuid:inv-bad")?;

    let (status, body) = post_invoke(&client, &auth, deploy_body("hello", &wasm, &grant)).await;
    assert_ne!(status, Status::Ok, "a tampered D_fn must not deploy: {body}");

    // The transaction rolled back: NO artifact row, NO delegation row.
    let artifact = database_artifact::Entity::find_by_id((
        "compute".to_string(),
        owner.space.to_string(),
        "hello".to_string(),
    ))
    .one(&conn)
    .await?;
    assert!(artifact.is_none(), "a failed D_fn must leave no artifact row");
    let dfn = deleg_model::Entity::find()
        .filter(deleg_model::Column::Delegatee.eq(rdid))
        .one(&conn)
        .await?;
    assert!(dfn.is_none(), "a failed deploy must leave no delegation row");
    Ok(())
}

// ---------------------------------------------------------------------------
// Quota: deploy bumps store_size; over-limit deploy -> 402
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deploy_enforces_quota_and_mirror_updates_after_commit() -> Result<()> {
    // A fresh space's FIRST deploy must be admitted (used = 0) up to the
    // limit; the committed deploy bumps the mirror so a second deploy that
    // would cross the limit is rejected with 402 -- proving both the quota
    // gate AND mirror-after-commit.
    let (rocket, conn, _tempdir) = boot_with_limit(Some("140 B")).await?;
    let owner = make_owner("deploy-quota")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    let client = Client::tracked(rocket).await?;

    // First deploy: 100-byte payload, fits under 140.
    let wasm_a = vec![7u8; 100];
    let cid_a = content_cid(&wasm_a);
    let rdid_a = handshake_routine_did(&client, &owner, &cid_a, "urn:uuid:hs-qa").await?;
    let grant_a = mint_d_fn(&owner, &rdid_a, &cid_a, "urn:uuid:dfn-qa")?;
    let auth_a = owner_compute_invocation(&owner, "a", "tinycloud.compute/deploy", "urn:uuid:inv-qa")?;
    let (status_a, body_a) = post_invoke(&client, &auth_a, deploy_body("a", &wasm_a, &grant_a)).await;
    assert_eq!(status_a, Status::Ok, "first deploy must fit under quota: {body_a}");

    // Second deploy: another 100-byte payload. Mirror now holds 100, limit is
    // 140, remaining 40 < 100 -> 402.
    let wasm_b = vec![9u8; 100];
    let cid_b = content_cid(&wasm_b);
    let rdid_b = handshake_routine_did(&client, &owner, &cid_b, "urn:uuid:hs-qb").await?;
    let grant_b = mint_d_fn(&owner, &rdid_b, &cid_b, "urn:uuid:dfn-qb")?;
    let auth_b = owner_compute_invocation(&owner, "b", "tinycloud.compute/deploy", "urn:uuid:inv-qb")?;
    let (status_b, body_b) = post_invoke(&client, &auth_b, deploy_body("b", &wasm_b, &grant_b)).await;
    assert_eq!(
        status_b,
        Status::new(402),
        "second deploy must 402 once the mirror counts the first: {body_b}"
    );

    // The 402'd deploy left NO artifact for "b" (rejected before the txn).
    let artifact_b = database_artifact::Entity::find_by_id((
        "compute".to_string(),
        owner.space.to_string(),
        "b".to_string(),
    ))
    .one(&conn)
    .await?;
    assert!(artifact_b.is_none(), "an over-quota deploy must not persist an artifact");
    Ok(())
}

// ---------------------------------------------------------------------------
// RoutineDid handshake: determinism + idempotence
// ---------------------------------------------------------------------------

#[tokio::test]
async fn routine_did_handshake_is_deterministic_and_side_effect_free() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("routine-did")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    let client = Client::tracked(rocket).await?;

    let cid = content_cid(b"some-wasm-bytes");
    let handshake = |nonce: &str| -> Result<(String, String)> {
        let auth = owner_compute_invocation(&owner, &cid, "tinycloud.compute/deploy", nonce)?;
        let body = serde_json::json!({ "action": "routine_did", "content_cid": cid }).to_string();
        Ok((auth, body))
    };

    let (auth1, body1) = handshake("urn:uuid:rd-1")?;
    let (s1, b1) = post_invoke(&client, &auth1, body1).await;
    assert_eq!(s1, Status::Ok, "handshake must succeed: {b1}");
    let (auth2, body2) = handshake("urn:uuid:rd-2")?;
    let (s2, b2) = post_invoke(&client, &auth2, body2).await;
    assert_eq!(s2, Status::Ok);
    let v1: serde_json::Value = serde_json::from_str(&b1)?;
    let v2: serde_json::Value = serde_json::from_str(&b2)?;
    assert_eq!(v1["routine_did"], v2["routine_did"], "same (space, CID) must return the same DID");
    assert!(
        v1["routine_did"].as_str().unwrap().starts_with("did:key:"),
        "routine_did must be a did:key"
    );
    assert_eq!(v1["content_cid"], cid, "handshake echoes the content CID");

    // Different CID -> different routine_did (per-(space, function) identity).
    let cid2 = content_cid(b"other-wasm-bytes");
    let auth = owner_compute_invocation(&owner, &cid2, "tinycloud.compute/deploy", "urn:uuid:rd-3")?;
    let body = serde_json::json!({ "action": "routine_did", "content_cid": cid2 }).to_string();
    let (s3, b3) = post_invoke(&client, &auth, body).await;
    assert_eq!(s3, Status::Ok);
    let v3: serde_json::Value = serde_json::from_str(&b3)?;
    assert_ne!(v3["routine_did"], v1["routine_did"]);

    // Side-effect-free: no artifact and no delegation were created.
    assert_eq!(
        database_artifact::Entity::find().all(&conn).await?.len(),
        0,
        "the handshake must not create artifacts"
    );
    assert_eq!(
        deleg_model::Entity::find().all(&conn).await?.len(),
        0,
        "the handshake must not create delegations"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Wrong-ability RoutineDid rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn routine_did_body_under_execute_ability_is_rejected() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("routine-did-wrong-ability")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    let client = Client::tracked(rocket).await?;

    let cid = content_cid(b"wasm");
    // Present a compute/EXECUTE capability with a RoutineDid body (requires
    // compute/deploy). Scope selection must reject: the covering-cap search
    // fails ability_matches(execute, deploy).
    let auth = owner_compute_invocation(&owner, &cid, "tinycloud.compute/execute", "urn:uuid:rd-wrong")?;
    let body = serde_json::json!({ "action": "routine_did", "content_cid": cid }).to_string();
    let (status, body) = post_invoke(&client, &auth, body).await;
    assert_eq!(status, Status::Forbidden, "execute cap must not authorize a RoutineDid body: {body}");
    assert!(body.starts_with("Unauthorized Action:"), "expected the standard prefix, got: {body}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Superseded-D_fn revocation on re-deploy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redeploy_revokes_the_superseded_grant() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("redeploy-revoke")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    let client = Client::tracked(rocket).await?;

    // Deploy v1.
    let wasm_v1 = b"\x00asm\x01\x00\x00\x00v1".to_vec();
    let cid_v1 = content_cid(&wasm_v1);
    let rdid_v1 = handshake_routine_did(&client, &owner, &cid_v1, "urn:uuid:hs-v1").await?;
    let grant_v1 = mint_d_fn(&owner, &rdid_v1, &cid_v1, "urn:uuid:dfn-v1")?;
    let auth_v1 = owner_compute_invocation(&owner, "app", "tinycloud.compute/deploy", "urn:uuid:inv-v1")?;
    let (s1, b1) = post_invoke(&client, &auth_v1, deploy_body("app", &wasm_v1, &grant_v1)).await;
    assert_eq!(s1, Status::Ok, "v1 deploy must succeed: {b1}");

    let dfn_v1 = deleg_model::Entity::find()
        .filter(deleg_model::Column::Delegatee.eq(rdid_v1.clone()))
        .one(&conn)
        .await?
        .context("v1 D_fn must exist")?;
    // Not revoked yet.
    assert_eq!(
        revo_model::Entity::find()
            .filter(revo_model::Column::Revoked.eq(dfn_v1.id))
            .count(&conn)
            .await?,
        0,
        "v1 D_fn must be live before re-deploy"
    );

    // Re-deploy the SAME function with NEW bytes -> new CID -> new routine_did.
    let wasm_v2 = b"\x00asm\x01\x00\x00\x00v2-different".to_vec();
    let cid_v2 = content_cid(&wasm_v2);
    assert_ne!(cid_v1, cid_v2);
    let rdid_v2 = handshake_routine_did(&client, &owner, &cid_v2, "urn:uuid:hs-v2").await?;
    let grant_v2 = mint_d_fn(&owner, &rdid_v2, &cid_v2, "urn:uuid:dfn-v2")?;
    let auth_v2 = owner_compute_invocation(&owner, "app", "tinycloud.compute/deploy", "urn:uuid:inv-v2")?;
    let (s2, b2) = post_invoke(&client, &auth_v2, deploy_body("app", &wasm_v2, &grant_v2)).await;
    assert_eq!(s2, Status::Ok, "v2 re-deploy must succeed: {b2}");

    // The superseded v1 D_fn must now be revoked.
    let revoked = revo_model::Entity::find()
        .filter(revo_model::Column::Revoked.eq(dfn_v1.id))
        .count(&conn)
        .await?;
    assert!(revoked >= 1, "re-deploy must revoke the superseded v1 D_fn");
    Ok(())
}

// ---------------------------------------------------------------------------
// Scope selection: multi-space + uncovered function
// ---------------------------------------------------------------------------

/// Delegate `compute/deploy` on `<space>/compute/<function>` from the space
/// owner to `holder`, seeding the parent delegation row directly. Returns the
/// parent CID the holder cites.
async fn delegate_compute_deploy(
    conn: &DatabaseConnection,
    owner: &Owner,
    holder_did: &str,
    function: &str,
    tag: &str,
) -> Result<AuthCid> {
    let resource: ResourceId = owner.space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some(function.parse::<AuthPath>()?),
        None,
        None,
    );
    let parent_hash = tinycloud_core::hash::hash(format!("compute-deploy-parent:{tag}").as_bytes());
    deleg_model::ActiveModel {
        id: Set(parent_hash),
        delegator: Set(owner.did.clone()),
        delegatee: Set(holder_did.to_string()),
        expiry: Set(None),
        issued_at: Set(None),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(format!("compute-deploy-parent:{tag}").into_bytes()),
    }
    .insert(conn)
    .await?;
    abilities::ActiveModel {
        delegation: Set(parent_hash),
        resource: Set(Resource::TinyCloud(resource)),
        ability: Set(Ability::try_from("tinycloud.compute/deploy".to_string()).map_err(|e| anyhow::anyhow!("{e:?}"))?),
        caveats: Set(Caveats(std::collections::BTreeMap::new())),
    }
    .insert(conn)
    .await?;
    Ok(parent_hash.to_cid(0x55))
}

#[tokio::test]
async fn scope_selection_rejects_caps_spanning_multiple_spaces() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;

    // Two spaces, two owners, one neutral holder granted compute/deploy in
    // BOTH. The holder presents both caps in a single Deploy invocation.
    let owner_a = make_owner("scope-multi-a")?;
    let owner_b = make_owner("scope-multi-b")?;
    let mut holder_jwk = JWK::generate_ed25519()?;
    holder_jwk.algorithm = Some(Algorithm::EdDSA);
    let holder_did = DID_METHODS.generate(&holder_jwk, "key")?.to_string();
    let holder_frag = holder_did.rsplit_once(':').context("frag")?.1.to_string();
    let holder_vm = format!("{holder_did}#{holder_frag}");

    seed_space_and_actors(&conn, &owner_a.space, &[holder_did.clone()]).await?;
    seed_space_and_actors(&conn, &owner_b.space, &[holder_did.clone()]).await?;
    let parent_a = delegate_compute_deploy(&conn, &owner_a, &holder_did, "fn", "multi-a").await?;
    let parent_b = delegate_compute_deploy(&conn, &owner_b, &holder_did, "fn", "multi-b").await?;

    // Invocation citing BOTH parents, attenuation covering both spaces.
    let res_a: ResourceId = owner_a
        .space
        .clone()
        .to_resource("compute".parse()?, Some("fn".parse()?), None, None);
    let res_b: ResourceId = owner_b
        .space
        .clone()
        .to_resource("compute".parse()?, Some("fn".parse()?), None, None);
    let mut caps = Capabilities::new();
    caps.with_action(
        res_a.as_uri(),
        "tinycloud.compute/deploy".parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );
    caps.with_action(
        res_b.as_uri(),
        "tinycloud.compute/deploy".parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );
    let auth = Payload {
        issuer: holder_vm.parse::<DIDURLBuf>()?,
        audience: holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(far_future())?,
        nonce: Some("urn:uuid:scope-multi".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![parent_a, parent_b],
        attenuation: caps,
    }
    .sign(holder_jwk.get_algorithm().unwrap_or_default(), &holder_jwk)?
    .encode()?;

    // Scope selection rejects BEFORE the D_fn is processed, so the delegatee
    // is irrelevant here -- a throwaway did:key suffices.
    let wasm = b"\x00asm\x01\x00\x00\x00multi".to_vec();
    let cid = content_cid(&wasm);
    let dummy_did = DID_METHODS.generate(&JWK::generate_ed25519()?, "key")?.to_string();
    let grant = mint_d_fn(&owner_a, &dummy_did, &cid, "urn:uuid:dfn-multi")?;

    let client = Client::tracked(rocket).await?;
    let (status, body) = post_invoke(&client, &auth, deploy_body("fn", &wasm, &grant)).await;
    assert_eq!(
        status,
        Status::BadRequest,
        "compute caps spanning multiple spaces must be rejected: {body}"
    );
    assert!(body.contains("multiple spaces"), "expected the multi-space message, got: {body}");
    Ok(())
}

#[tokio::test]
async fn scope_selection_rejects_body_targeting_uncovered_function() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("scope-uncovered")?;

    let mut holder_jwk = JWK::generate_ed25519()?;
    holder_jwk.algorithm = Some(Algorithm::EdDSA);
    let holder_did = DID_METHODS.generate(&holder_jwk, "key")?.to_string();
    let holder_frag = holder_did.rsplit_once(':').context("frag")?.1.to_string();
    let holder_vm = format!("{holder_did}#{holder_frag}");
    seed_space_and_actors(&conn, &owner.space, &[holder_did.clone()]).await?;

    // Holder is granted compute/deploy ONLY on function "x".
    let parent = delegate_compute_deploy(&conn, &owner, &holder_did, "x", "uncovered").await?;
    let res_x: ResourceId = owner
        .space
        .clone()
        .to_resource("compute".parse()?, Some("x".parse()?), None, None);
    let mut caps = Capabilities::new();
    caps.with_action(
        res_x.as_uri(),
        "tinycloud.compute/deploy".parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );
    let auth = Payload {
        issuer: holder_vm.parse::<DIDURLBuf>()?,
        audience: holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(far_future())?,
        nonce: Some("urn:uuid:scope-uncovered".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![parent],
        attenuation: caps,
    }
    .sign(holder_jwk.get_algorithm().unwrap_or_default(), &holder_jwk)?
    .encode()?;

    // But the Deploy body targets function "y" -- NOT covered by the "x" cap.
    // Scope selection rejects before the D_fn is processed; delegatee is moot.
    let wasm = b"\x00asm\x01\x00\x00\x00uncovered".to_vec();
    let cid = content_cid(&wasm);
    let dummy_did = DID_METHODS.generate(&JWK::generate_ed25519()?, "key")?.to_string();
    let grant = mint_d_fn(&owner, &dummy_did, &cid, "urn:uuid:dfn-uncovered")?;

    let client = Client::tracked(rocket).await?;
    let (status, body) = post_invoke(&client, &auth, deploy_body("y", &wasm, &grant)).await;
    assert_eq!(
        status,
        Status::Forbidden,
        "a cap for function x must not authorize a deploy of function y: {body}"
    );
    assert!(body.starts_with("Unauthorized Action:"), "expected the standard prefix, got: {body}");
    Ok(())
}

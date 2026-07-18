// P0 walking-skeleton gate (specs/compute-service-implementation-plan.md).
//
// Boots a real node (`tinycloud::app`) with the `compute` feature on and
// drives `/invoke` over an in-process Rocket client, mirroring the existing
// `w1_rocket_http_invoke_enforces_chain_constrained_sql_and_revoke` pattern
// in `tinycloud-node-server/src/routes/mod.rs` (a hand-built delegation +
// signed invocation, no policy-engine machinery needed).
//
// Asserts (per the plan's P0 verify block):
//   * `/info` lists "compute" once the feature is compiled in.
//   * an enabled dispatch reaches `handle_compute_invoke` (distinct 501 body
//     from the feature-disabled path, see `compute_disabled.rs`).
//   * the request-variant -> ability mapping is enforced both ways (an
//     `execute` capability presenting a `deploy` body is rejected, and vice
//     versa), covering all four `ComputeRequest` variants against their
//     required ability.
//   * a `list` body is rejected while `tinycloud.compute/list` stays
//     reserved (no server-side listing handler exists in the MVP, C9).

#![cfg(feature = "compute")]

use anyhow::{Context, Result};
use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
    Build, Rocket,
};
use serde_json::json;
use std::collections::BTreeMap;
use tempfile::TempDir;
use tinycloud_auth::{
    authorization::Cid as AuthCid,
    resolver::DID_METHODS,
    resource::{ResourceId, Service, SpaceId},
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
    hash::Hash,
    models::{abilities, actor, delegation as deleg_model, space as space_model},
    sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection},
    types::{Ability, Caveats, Resource, SpaceIdWrap},
};

async fn boot_app() -> Result<(Rocket<Build>, DatabaseConnection, TempDir)> {
    let tempdir = TempDir::new()?;
    let datadir = tempdir.path().join("data");
    let db_path = datadir.join("caps.db");
    let db_url = format!("sqlite:{}", db_path.display());
    let secret = base64::encode_config([11u8; 32], base64::URL_SAFE_NO_PAD);
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
    Ok((rocket, conn, tempdir))
}

fn test_space_id(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap())
}

fn compute_resource(space: &SpaceId) -> Result<ResourceId> {
    Ok(space
        .clone()
        .to_resource("compute".parse::<Service>()?, None, None, None))
}

struct Holder {
    jwk: JWK,
    did: String,
    verification_method: String,
}

fn new_holder() -> Result<Holder> {
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = did
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    let verification_method = format!("{did}#{fragment}");
    Ok(Holder {
        jwk,
        did,
        verification_method,
    })
}

/// Insert a space + a single-hop delegation granting `ability` on the
/// space's compute resource to a freshly generated holder. Returns the
/// holder (for signing invocations) and the parent delegation CID.
async fn grant_compute_ability(
    conn: &DatabaseConnection,
    space: &SpaceId,
    ability: &str,
    delegation_seed: &[u8],
) -> Result<(Holder, AuthCid)> {
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(conn)
    .await
    .ok(); // idempotent across multiple grants in the same test

    let holder = new_holder()?;
    let owner_did = space.did().to_string();
    for did in [&owner_did, &holder.did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(conn)
        .await
        .ok();
    }

    let parent_hash: Hash = tinycloud_core::hash::hash(delegation_seed);
    deleg_model::ActiveModel {
        id: Set(parent_hash),
        delegator: Set(owner_did),
        delegatee: Set(holder.did.clone()),
        expiry: Set(None),
        issued_at: Set(None),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(delegation_seed.to_vec()),
    }
    .insert(conn)
    .await?;

    let resource = compute_resource(space)?;
    abilities::ActiveModel {
        delegation: Set(parent_hash),
        resource: Set(Resource::TinyCloud(resource)),
        ability: Set(Ability::try_from(ability.to_string()).unwrap()),
        caveats: Set(Caveats(BTreeMap::new())),
    }
    .insert(conn)
    .await?;

    Ok((holder, parent_hash.to_cid(0x55)))
}

fn signing_key_algorithm(jwk: &JWK) -> Algorithm {
    jwk.get_algorithm().unwrap_or_default()
}

fn sign_invocation(
    holder: &Holder,
    parent_cid: AuthCid,
    resource: &ResourceId,
    ability: &str,
    nonce: &str,
) -> Result<String> {
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        ability.parse::<UcanAbility>()?,
        [BTreeMap::<String, serde_json::Value>::new()],
    );
    let invocation = Payload {
        issuer: holder.verification_method.parse::<DIDURLBuf>()?,
        audience: holder.did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![parent_cid],
        attenuation: caps,
    }
    .sign(signing_key_algorithm(&holder.jwk), &holder.jwk)?;
    Ok(invocation.encode()?)
}

#[tokio::test]
async fn info_lists_compute_feature() -> Result<()> {
    let (rocket, _conn, _tempdir) = boot_app().await?;
    let client = Client::tracked(rocket).await?;
    let response = client.get("/info").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    let features = body["features"]
        .as_array()
        .context("features must be an array")?;
    assert!(
        features.iter().any(|f| f == "compute"),
        "expected \"compute\" in /info features, got {features:?}"
    );
    Ok(())
}

#[tokio::test]
async fn enabled_dispatch_reaches_handler_for_execute() -> Result<()> {
    let (rocket, conn, _tempdir) = boot_app().await?;
    let space = test_space_id("p0-execute");
    let (holder, parent_cid) = grant_compute_ability(
        &conn,
        &space,
        "tinycloud.compute/execute",
        b"p0-execute-grant",
    )
    .await?;
    let resource = compute_resource(&space)?;
    let auth_header = sign_invocation(
        &holder,
        parent_cid,
        &resource,
        "tinycloud.compute/execute",
        "urn:uuid:00000000-0000-4000-8000-0000000000e1",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&json!({
            "action": "execute",
            "function": "report-generator"
        }))?)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::NotImplemented,
        "P0 has no live execute handler yet: {body}"
    );
    assert!(
        body.contains("not implemented"),
        "expected the P0 skeleton not-implemented message, got: {body}"
    );
    assert!(
        !body.contains("not enabled on this node"),
        "an enabled dispatch must not fall through to the feature-disabled message: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn execute_capability_rejects_deploy_body() -> Result<()> {
    let (rocket, conn, _tempdir) = boot_app().await?;
    let space = test_space_id("p0-wrong-ability-1");
    let (holder, parent_cid) = grant_compute_ability(
        &conn,
        &space,
        "tinycloud.compute/execute",
        b"p0-wrong-ability-1-grant",
    )
    .await?;
    let resource = compute_resource(&space)?;
    // The invocation's own attenuation claims `execute` (matching what was
    // delegated, so the chain-verification step in `verify_auth` passes);
    // `compute_caps` in the dispatch is extracted from THIS claimed
    // attenuation. The ability-mapping check must then reject it against
    // the `deploy` body below.
    let auth_header = sign_invocation(
        &holder,
        parent_cid,
        &resource,
        "tinycloud.compute/execute",
        "urn:uuid:00000000-0000-4000-8000-0000000000e2",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&json!({
            "action": "deploy",
            "function": "report-generator",
            "wasm_b64": "AAAA"
        }))?)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::Forbidden,
        "an execute-only capability presenting a deploy body must be rejected: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn deploy_capability_rejects_execute_body() -> Result<()> {
    let (rocket, conn, _tempdir) = boot_app().await?;
    let space = test_space_id("p0-wrong-ability-2");
    let (holder, parent_cid) = grant_compute_ability(
        &conn,
        &space,
        "tinycloud.compute/deploy",
        b"p0-wrong-ability-2-grant",
    )
    .await?;
    let resource = compute_resource(&space)?;
    let auth_header = sign_invocation(
        &holder,
        parent_cid,
        &resource,
        "tinycloud.compute/deploy",
        "urn:uuid:00000000-0000-4000-8000-0000000000e3",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&json!({
            "action": "execute",
            "function": "report-generator"
        }))?)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::Forbidden,
        "a deploy-only capability presenting an execute body must be rejected: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn deploy_capability_rejects_routine_did_handshake_without_deploy() -> Result<()> {
    // RoutineDid requires compute/deploy per the normative mapping (§7.1
    // erratum, C1) — an execute-only holder must not be able to run the
    // handshake either.
    let (rocket, conn, _tempdir) = boot_app().await?;
    let space = test_space_id("p0-wrong-ability-3");
    let (holder, parent_cid) = grant_compute_ability(
        &conn,
        &space,
        "tinycloud.compute/execute",
        b"p0-wrong-ability-3-grant",
    )
    .await?;
    let resource = compute_resource(&space)?;
    let auth_header = sign_invocation(
        &holder,
        parent_cid,
        &resource,
        "tinycloud.compute/execute",
        "urn:uuid:00000000-0000-4000-8000-0000000000e4",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&json!({
            "action": "routine_did",
            "content_cid": "bafyreiexample"
        }))?)
        .dispatch()
        .await;

    assert_eq!(response.status(), Status::Forbidden);
    Ok(())
}

#[tokio::test]
async fn list_body_rejected_while_reserved() -> Result<()> {
    let (rocket, conn, _tempdir) = boot_app().await?;
    let space = test_space_id("p0-list");
    let (holder, parent_cid) =
        grant_compute_ability(&conn, &space, "tinycloud.compute/list", b"p0-list-grant").await?;
    let resource = compute_resource(&space)?;
    let auth_header = sign_invocation(
        &holder,
        parent_cid,
        &resource,
        "tinycloud.compute/list",
        "urn:uuid:00000000-0000-4000-8000-0000000000e5",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(serde_json::to_string(&json!({ "action": "list" }))?)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    // A held `compute/list` capability satisfies the mapping (list requires
    // list), so this must NOT be the 403 wrong-ability path — but there is
    // still no server-side listing handler in the MVP (C9), so it must not
    // succeed either.
    assert_ne!(
        status,
        Status::Forbidden,
        "list ability must satisfy its own mapping: {body}"
    );
    assert_ne!(
        status,
        Status::Ok,
        "no listing handler exists in P0: {body}"
    );
    assert_eq!(
        status,
        Status::NotImplemented,
        "unexpected status for a reserved list body: {body}"
    );
    Ok(())
}

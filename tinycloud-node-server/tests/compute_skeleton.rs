//! P0 walking-skeleton gate (compute-service-implementation-plan.md, P0
//! section): with the `compute` feature ON, `/invoke` dispatches
//! `tinycloud.compute/*` requests through the NORMATIVE request-variant ->
//! required-ability mapping (compute-service.md §7.1 erratum, Codex C1).
//!
//! This target only makes sense with the `compute` feature enabled --
//! `ComputeRequest`/`ComputeService` don't exist without it. It is declared
//! with `required-features = ["compute"]` in `tinycloud-node-server/Cargo.toml`
//! so a plain `cargo test` skips it (not a silent zero-tests no-op) and an
//! explicit `--test compute_skeleton` without `--features compute` errors
//! (the C5 failure mode the plan bans).
//!
//! Asserts, per the plan's P0 verify block:
//!   * `/version` lists `"compute"` in its `features` array.
//!   * an enabled dispatch reaches the handler (a body/ability match returns
//!     `501` with a "not implemented yet" message distinct from the
//!     service-disabled message -- proving the request cleared the ability
//!     gate and reached `handle_compute_invoke`, not the top-level 501).
//!   * a wrong-ability request is rejected: an `Execute` capability
//!     presenting a `Deploy` body -> 403, and vice versa.
//!   * a `List` body is rejected while reserved (no server-side listing
//!     handler exists in the MVP) even when the presented capability
//!     legitimately holds `compute/list`.
//!
//! Every capability presented below is backed by a REAL delegation chain
//! (space owner -> holder, persisted as `delegation`/`ability` rows) so the
//! ability-mapping checks are exercised on top of genuine `layer (a)`
//! authorization (`tinycloud-core/src/models/invocation.rs::validate`), not
//! merely on the invocation's self-declared attenuation.

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
    models::{abilities, actor, delegation as deleg_model, space as space_model},
    sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection},
    types::{Ability, Caveats, Resource, SpaceIdWrap},
};

fn test_space_id(name: &str) -> Result<SpaceId> {
    let jwk = JWK::generate_ed25519()?;
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key")?;
    Ok(SpaceId::new(
        did,
        name.parse().map_err(|e| anyhow::anyhow!("{e:?}"))?,
    ))
}

/// Boot a real `tinycloud::app(...)` against a file-backed sqlite DB (so a
/// second, independent connection can seed delegation/ability rows directly,
/// bypassing `/delegate`), matching the pattern already proven by the
/// w5-policy-runtime and m1-realdata e2e suites.
async fn boot() -> Result<(rocket::Rocket<rocket::Build>, DatabaseConnection, TempDir)> {
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
    Ok((rocket, conn, tempdir))
}

/// Everything needed to sign compute invocations against one space/holder,
/// with the given ability already delegated by the space owner.
struct Fixture {
    holder_did: String,
    holder_vm: String,
    holder_jwk: JWK,
    parent_cid: AuthCid,
    resource: ResourceId,
}

async fn grant_compute_ability(
    conn: &DatabaseConnection,
    space_name: &str,
    ability: &str,
) -> Result<Fixture> {
    let space = test_space_id(space_name)?;
    space_model::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(conn)
    .await?;

    let mut holder_jwk = JWK::generate_ed25519()?;
    holder_jwk.algorithm = Some(Algorithm::EdDSA);
    let holder_did = DID_METHODS.generate(&holder_jwk, "key")?.to_string();
    let fragment = holder_did
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    let holder_vm = format!("{holder_did}#{fragment}");

    let owner_did = space.did().to_string();
    for did in [&owner_did, &holder_did] {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(conn)
        .await?;
    }

    let resource: ResourceId = space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some("hello".parse::<AuthPath>()?),
        None,
        None,
    );

    let parent_hash = tinycloud_core::hash::hash(
        format!("compute-skeleton-parent:{space_name}:{ability}").as_bytes(),
    );
    deleg_model::ActiveModel {
        id: Set(parent_hash),
        delegator: Set(owner_did),
        delegatee: Set(holder_did.clone()),
        expiry: Set(None),
        issued_at: Set(None),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(format!("compute-skeleton-parent:{space_name}:{ability}").into_bytes()),
    }
    .insert(conn)
    .await?;

    abilities::ActiveModel {
        delegation: Set(parent_hash),
        resource: Set(Resource::TinyCloud(resource.clone())),
        ability: Set(Ability::try_from(ability.to_string()).map_err(|e| anyhow::anyhow!("{e:?}"))?),
        caveats: Set(Caveats(std::collections::BTreeMap::new())),
    }
    .insert(conn)
    .await?;

    Ok(Fixture {
        holder_did,
        holder_vm,
        holder_jwk,
        parent_cid: parent_hash.to_cid(0x55),
        resource,
    })
}

/// Sign an invocation citing `fixture`'s granted delegation, declaring
/// `ability` in its attenuation (this is the invoker's SELF-DECLARED
/// request -- chain validation proves it is actually backed by the grant).
fn sign_invocation(fixture: &Fixture, ability: &str, nonce: &str) -> Result<String> {
    let mut capabilities = Capabilities::new();
    capabilities.with_action(
        fixture.resource.as_uri(),
        ability.parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );
    let invocation = Payload {
        issuer: fixture.holder_vm.parse::<DIDURLBuf>()?,
        audience: fixture.holder_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0)?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![fixture.parent_cid],
        attenuation: capabilities,
    }
    .sign(
        fixture.holder_jwk.get_algorithm().unwrap_or_default(),
        &fixture.holder_jwk,
    )?;
    Ok(invocation.encode()?)
}

#[tokio::test]
async fn version_lists_compute_feature() -> Result<()> {
    let (rocket, _conn, _tempdir) = boot().await?;
    let client = Client::tracked(rocket).await?;
    let response = client.get("/version").dispatch().await;
    assert_eq!(response.status(), Status::Ok);
    let body: serde_json::Value = serde_json::from_str(&response.into_string().await.unwrap())?;
    let features = body["features"]
        .as_array()
        .context("features must be an array")?;
    assert!(
        features.iter().any(|f| f == "compute"),
        "expected \"compute\" in /version features, got {features:?}"
    );
    Ok(())
}

#[tokio::test]
async fn enabled_dispatch_reaches_the_handler_for_execute() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let fixture = grant_compute_ability(
        &conn,
        "compute-skeleton-execute",
        "tinycloud.compute/execute",
    )
    .await?;
    let auth_header = sign_invocation(
        &fixture,
        "tinycloud.compute/execute",
        "urn:uuid:00000000-0000-4000-8000-0000000000e1",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(r#"{"action":"execute","function":"hello"}"#)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    // Reaching the handler means: NOT the service-disabled 501, and NOT a
    // 403 ability-mismatch. As of P2 the Execute handler is LIVE, so an
    // execute against a function that was never deployed reaches the handler
    // and returns 404 "no compute function deployed" -- proof the ability
    // gate passed AND the live handler ran (the P0 501 pin was updated on the
    // P2 activation, the conscious act mirroring the registry active-flip).
    assert_eq!(status, Status::NotFound, "unexpected response: {body}");
    assert!(
        body.contains("no compute function deployed"),
        "expected the live-handler undeployed-function message, got {body:?}"
    );
    assert_ne!(
        body, "Compute support is not enabled on this node",
        "must not be the service-disabled message when the feature is on"
    );
    Ok(())
}

#[tokio::test]
async fn deploy_capability_rejects_execute_body() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let fixture = grant_compute_ability(
        &conn,
        "compute-skeleton-deploy-vs-exec",
        "tinycloud.compute/deploy",
    )
    .await?;
    let auth_header = sign_invocation(
        &fixture,
        "tinycloud.compute/deploy",
        "urn:uuid:00000000-0000-4000-8000-0000000000e2",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(r#"{"action":"execute","function":"hello"}"#)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::Forbidden,
        "a compute/deploy capability must not authorize an Execute body: {body}"
    );
    assert!(
        body.starts_with("Unauthorized Action:"),
        "expected the node's established rejection prefix, got: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn execute_capability_rejects_deploy_body() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let fixture = grant_compute_ability(
        &conn,
        "compute-skeleton-exec-vs-deploy",
        "tinycloud.compute/execute",
    )
    .await?;
    let auth_header = sign_invocation(
        &fixture,
        "tinycloud.compute/execute",
        "urn:uuid:00000000-0000-4000-8000-0000000000e3",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(r#"{"action":"deploy","function":"hello","wasm_b64":"AA=="}"#)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::Forbidden,
        "a compute/execute capability must not authorize a Deploy body: {body}"
    );
    assert!(
        body.starts_with("Unauthorized Action:"),
        "expected the node's established rejection prefix, got: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn execute_capability_rejects_routine_did_body() -> Result<()> {
    // RoutineDid requires compute/deploy too (§7.1 erratum) -- same mapping
    // as Deploy, exercised separately since it is a distinct wire variant.
    let (rocket, conn, _tempdir) = boot().await?;
    let fixture = grant_compute_ability(
        &conn,
        "compute-skeleton-exec-vs-routine-did",
        "tinycloud.compute/execute",
    )
    .await?;
    let auth_header = sign_invocation(
        &fixture,
        "tinycloud.compute/execute",
        "urn:uuid:00000000-0000-4000-8000-0000000000e4",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(r#"{"action":"routine_did","content_cid":"bafyexample"}"#)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(
        status,
        Status::Forbidden,
        "a compute/execute capability must not authorize a RoutineDid body: {body}"
    );
    assert!(
        body.starts_with("Unauthorized Action:"),
        "expected the node's established rejection prefix, got: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn deploy_capability_reaches_handler_for_routine_did() -> Result<()> {
    // P1 update: `RoutineDid` is now a LIVE handler (the read-only F2
    // handshake), so a `compute/deploy` holder gets a `200` with the derived
    // routine DID -- no longer the P0 `501 not implemented yet`. This asserts
    // the space-scoped `compute/deploy` cap reaches AND satisfies the live
    // handshake (the content CID need not match the granted function-path,
    // §6.2). The wrong-ability rejections above still guard the mapping.
    let (rocket, conn, _tempdir) = boot().await?;
    let fixture = grant_compute_ability(
        &conn,
        "compute-skeleton-routine-did",
        "tinycloud.compute/deploy",
    )
    .await?;
    let auth_header = sign_invocation(
        &fixture,
        "tinycloud.compute/deploy",
        "urn:uuid:00000000-0000-4000-8000-0000000000e5",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(r#"{"action":"routine_did","content_cid":"bafyexample"}"#)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    assert_eq!(status, Status::Ok, "unexpected response: {body}");
    let json: serde_json::Value = serde_json::from_str(&body)?;
    assert!(
        json["routine_did"]
            .as_str()
            .is_some_and(|d| d.starts_with("did:key:")),
        "handshake must return a did:key routine_did, got {body:?}"
    );
    assert_eq!(json["content_cid"], "bafyexample");
    Ok(())
}

#[tokio::test]
async fn list_body_is_rejected_while_reserved_even_with_list_ability() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let fixture =
        grant_compute_ability(&conn, "compute-skeleton-list", "tinycloud.compute/list").await?;
    let auth_header = sign_invocation(
        &fixture,
        "tinycloud.compute/list",
        "urn:uuid:00000000-0000-4000-8000-0000000000e6",
    )?;

    let client = Client::tracked(rocket).await?;
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth_header))
        .header(ContentType::JSON)
        .body(r#"{"action":"list"}"#)
        .dispatch()
        .await;

    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    // No server-side listing handler exists in the MVP (§12.1/C9) -- even a
    // legitimately-held compute/list capability must be rejected, not
    // succeed with 200.
    assert_ne!(
        status,
        Status::Ok,
        "list must not succeed while reserved: {body}"
    );
    assert_eq!(
        status,
        Status::NotImplemented,
        "unexpected response: {body}"
    );
    assert!(
        body.contains("reserved"),
        "expected a reserved-service message, got {body:?}"
    );
    Ok(())
}

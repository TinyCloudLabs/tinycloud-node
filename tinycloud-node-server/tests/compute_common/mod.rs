//! Shared P2 compute-execute test harness (compute-service-implementation-plan.md
//! P2). Included via `mod compute_common;` in each P2 integration test.
//!
//! Every capability presented is backed by a REAL delegation chain (the space
//! owner's root authority), so layer-(a) authorization runs for real. Routine
//! `D_fn`s are minted exactly as a client would: `routine_did` is learned from
//! the node via the read-only `RoutineDid` handshake (§6.2/F2), never
//! re-derived client-side (the node secret is config-supplied, not known to
//! the "client").
//!
//! Some helpers are only used by a subset of the P2 test files; each test
//! crate compiles this module independently, so `#[allow(dead_code)]` keeps
//! the unused-in-this-crate helpers from warning.
#![allow(dead_code)]

use anyhow::{Context, Result};
use base64::{encode_config, URL_SAFE_NO_PAD};
use rocket::{
    figment::providers::{Format, Serialized, Toml},
    http::{ContentType, Header, Status},
    local::asynchronous::Client,
};
use std::collections::BTreeMap;
use tempfile::TempDir;
use tinycloud_auth::{
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
    models::{actor, space as space_model},
    sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection},
    types::SpaceIdWrap,
};

pub const NODE_SECRET: [u8; 32] = [11u8; 32];

pub fn far_future() -> f64 {
    4_102_444_800.0
}

/// The A.1 fixture's `D_fn` grant, as a set of (ability, resource-path) rows.
/// The compute SQL host surface targets the fixed db name "db" (§ Appendix
/// A.1: `resource path: db`).
pub const A1_GRANT: &[(&str, &str)] = &[
    ("tinycloud.kv/get", "in/"),
    ("tinycloud.kv/put", "out/"),
    ("tinycloud.kv/del", "out/"),
    ("tinycloud.sql/read", "db"),
    ("tinycloud.sql/write", "db"),
];

/// Boot a real `tinycloud::app(...)` with an optional `[storage.compute]`
/// overlay (so tests can set tiny fuel/duration/memory ceilings). A second
/// raw `DatabaseConnection` is returned for direct row seeding/inspection.
pub async fn boot_with_compute_overlay(
    compute_overlay: &str,
) -> Result<(rocket::Rocket<rocket::Build>, DatabaseConnection, TempDir)> {
    let tempdir = TempDir::new()?;
    let datadir = tempdir.path().join("data");
    let db_url = format!("sqlite:{}", datadir.join("caps.db").display());
    let secret = encode_config(NODE_SECRET, URL_SAFE_NO_PAD);
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
        compute_overlay,
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

pub async fn boot() -> Result<(rocket::Rocket<rocket::Build>, DatabaseConnection, TempDir)> {
    boot_with_compute_overlay("").await
}

pub struct Owner {
    pub space: SpaceId,
    pub jwk: JWK,
    pub vm: String,
    pub did: String,
}

pub fn make_owner(name: &str) -> Result<Owner> {
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = did.rsplit_once(':').context("did fragment")?.1.to_string();
    let vm = format!("{did}#{fragment}");
    let space = SpaceId::new(
        did.parse::<DIDBuf>()?,
        name.parse().map_err(|e| anyhow::anyhow!("{e:?}"))?,
    );
    Ok(Owner {
        space,
        jwk,
        vm,
        did,
    })
}

pub async fn seed_space_and_actors(
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
        let _ = actor::ActiveModel { id: Set(did) }.insert(conn).await;
    }
    Ok(())
}

pub fn content_cid(wasm: &[u8]) -> String {
    tinycloud_core::hash::hash(wasm).to_cid(0x55).to_string()
}

/// Directly-seeded spaces (inserted via sea-orm, not created through a
/// hosting event) never trigger the block store's `StorageSetup::create`, so
/// the FileSystem block directory for KV writes does not exist. Create it
/// here to mirror what real space creation would do. The default blocks path
/// is `<datadir>/blocks`, and the per-object path is
/// `blocks/<space.suffix()>/<space.name()>/<hash>`.
pub fn ensure_block_dir(tempdir: &TempDir, space: &SpaceId) -> Result<()> {
    let dir = tempdir
        .path()
        .join("data")
        .join("blocks")
        .join(space.suffix())
        .join(space.name().as_str());
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// Compile a checked-in `.wat` fixture to a WASM module (deterministic,
/// reproducible source -- no opaque binaries).
pub fn wat_to_wasm(wat: &str) -> Result<Vec<u8>> {
    Ok(wat::parse_str(wat)?)
}

/// Compile a `.wat` fixture with a unique data-segment `salt` injected, so
/// the resulting WASM has a DISTINCT content CID (and therefore a distinct
/// derived routine identity) from the same fixture with a different salt.
/// Needed whenever two functions in one space must NOT share a routine
/// identity -- e.g. a granting vs a non-granting deploy of the same guest
/// (identical bytes share one CID -> one routine_did -> one pooled D_fn set,
/// the same-bytes hazard, §5.1).
pub fn wat_to_wasm_salted(wat: &str, salt: &str) -> Result<Vec<u8>> {
    // Inject a unique, unused data segment right after the memory declaration.
    let needle_2 = "(memory (export \"memory\") 2)";
    let needle_1 = "(memory (export \"memory\") 1)";
    let injected = if wat.contains(needle_2) {
        wat.replacen(
            needle_2,
            &format!("{needle_2}\n  (data (i32.const 0x9000) \"salt-{salt}\")"),
            1,
        )
    } else if wat.contains(needle_1) {
        wat.replacen(
            needle_1,
            &format!("{needle_1}\n  (data (i32.const 0x9000) \"salt-{salt}\")"),
            1,
        )
    } else {
        anyhow::bail!("fixture has no recognized memory declaration to salt");
    };
    Ok(wat::parse_str(injected)?)
}

fn binding_notabene(content_cid: &str) -> BTreeMap<String, serde_json::Value> {
    let mut binding = BTreeMap::new();
    binding.insert(
        "computeFunctionBinding".to_string(),
        serde_json::json!({ "functionCid": content_cid }),
    );
    binding
}

/// Mint a `D_fn` (owner -> routine_did) granting the given (ability,
/// resource-path) rows, each carrying the `computeFunctionBinding` caveat
/// naming `content_cid` (§6.2/D2). Owner is root authority (no parent proof).
pub fn mint_d_fn_grant(
    owner: &Owner,
    routine_did: &str,
    content_cid: &str,
    grant: &[(&str, &str)],
    nonce: &str,
) -> Result<String> {
    let mut caps = Capabilities::new();
    for (ability, path) in grant {
        let (service, _) = ability
            .strip_prefix("tinycloud.")
            .and_then(|a| a.split_once('/'))
            .context("ability must be tinycloud.<service>/<action>")?;
        let resource: ResourceId = owner.space.clone().to_resource(
            service.parse::<Service>()?,
            Some(path.parse::<AuthPath>()?),
            None,
            None,
        );
        caps.with_action(
            resource.as_uri(),
            ability.parse::<UcanAbility>()?,
            [binding_notabene(content_cid)],
        );
    }
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
    .sign(owner.jwk.get_algorithm().unwrap_or_default(), &owner.jwk)?;
    Ok(ucan.encode()?)
}

/// Mint an owner-signed compute invocation (root authority, no proof) citing
/// `<space>/compute/<path>` with `ability`. Optionally attach a `computeCaveats`
/// caveat map echoed onto the invocation (the F1 invoker-side echo, §6.3).
pub fn owner_compute_invocation_with_caveats(
    owner: &Owner,
    path: &str,
    ability: &str,
    compute_caveats: Option<&serde_json::Value>,
    nonce: &str,
) -> Result<String> {
    let resource: ResourceId = owner.space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some(path.parse::<AuthPath>()?),
        None,
        None,
    );
    let notabene = match compute_caveats {
        Some(cv) => {
            let mut m = BTreeMap::new();
            m.insert("computeCaveats".to_string(), cv.clone());
            m
        }
        None => BTreeMap::new(),
    };
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        ability.parse::<UcanAbility>()?,
        [notabene],
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

pub fn owner_compute_invocation(
    owner: &Owner,
    path: &str,
    ability: &str,
    nonce: &str,
) -> Result<String> {
    owner_compute_invocation_with_caveats(owner, path, ability, None, nonce)
}

pub async fn post_invoke(client: &Client, auth: &str, body: String) -> (Status, String) {
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

/// The read-only `RoutineDid` handshake (§6.2/F2).
pub async fn handshake_routine_did(
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

pub fn deploy_body(function: &str, wasm: &[u8], grant: &str) -> String {
    serde_json::json!({
        "action": "deploy",
        "function": function,
        "wasm_b64": encode_config(wasm, base64::STANDARD),
        "grant": grant,
    })
    .to_string()
}

/// Full deploy: handshake -> mint the given grant -> POST deploy. Returns the
/// routine_did and content CID. Panics via `?` on any non-200.
pub async fn deploy_function(
    client: &Client,
    owner: &Owner,
    function: &str,
    wasm: &[u8],
    grant: &[(&str, &str)],
    tag: &str,
) -> Result<(String, String)> {
    let cid = content_cid(wasm);
    let rdid = handshake_routine_did(client, owner, &cid, &format!("urn:uuid:hs-{tag}")).await?;
    let d_fn = mint_d_fn_grant(owner, &rdid, &cid, grant, &format!("urn:uuid:dfn-{tag}"))?;
    let auth = owner_compute_invocation(
        owner,
        function,
        "tinycloud.compute/deploy",
        &format!("urn:uuid:dep-{tag}"),
    )?;
    let (status, body) = post_invoke(client, &auth, deploy_body(function, wasm, &d_fn)).await;
    anyhow::ensure!(status == Status::Ok, "deploy failed ({status}): {body}");
    Ok((rdid, cid))
}

/// Submit an extra owner->routine_did delegation via the standard
/// `/delegate` path (used to construct the cite-all multi-`D_fn` case, §5.1/F5).
pub async fn post_delegate(client: &Client, grant: &str) -> (Status, String) {
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", grant.to_string()))
        .dispatch()
        .await;
    let status = response.status();
    let text = response.into_string().await.unwrap_or_default();
    (status, text)
}

/// Build a `compute/execute` body.
pub fn execute_body(function: &str, input: serde_json::Value) -> String {
    serde_json::json!({
        "action": "execute",
        "function": function,
        "input": input,
    })
    .to_string()
}

/// A non-owner principal that holds a `compute/execute` delegation (used to
/// test chain-derived `ComputeCaveats` §6.3 and the invoker-side echo).
pub struct Holder {
    pub jwk: JWK,
    pub vm: String,
    pub did: String,
}

pub fn make_holder() -> Result<Holder> {
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = did.rsplit_once(':').context("did fragment")?.1.to_string();
    let vm = format!("{did}#{fragment}");
    Ok(Holder { jwk, vm, did })
}

/// Owner delegates `compute/execute` on `<space>/compute/<function>` to the
/// holder, optionally attaching a `computeCaveats` caveat map (§6.3 -- the
/// chain SSOT for the enforced allowlist/ceilings). Returns the encoded
/// delegation header for POST /delegate.
pub fn mint_execute_delegation(
    owner: &Owner,
    holder_did: &str,
    function: &str,
    compute_caveats: Option<&serde_json::Value>,
    nonce: &str,
) -> Result<String> {
    let resource: ResourceId = owner.space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some(function.parse::<AuthPath>()?),
        None,
        None,
    );
    let notabene = match compute_caveats {
        Some(cv) => {
            let mut m = BTreeMap::new();
            m.insert("computeCaveats".to_string(), cv.clone());
            m
        }
        None => BTreeMap::new(),
    };
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        "tinycloud.compute/execute".parse::<UcanAbility>()?,
        [notabene],
    );
    let ucan = Payload {
        issuer: owner.vm.parse::<DIDURLBuf>()?,
        audience: holder_did.parse::<DIDBuf>()?,
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

/// The holder invokes `compute/execute`, citing `parent_cid` (the
/// owner->holder delegation) as proof. Optionally echoes a `computeCaveats`
/// map onto the invocation capability (the F1 invoker-side echo, §6.3): the
/// containment check rejects the invocation if the chain caveat is not
/// echoed verbatim.
pub fn holder_execute_invocation(
    holder: &Holder,
    owner: &Owner,
    function: &str,
    parent_cid: &str,
    echo_caveats: Option<&serde_json::Value>,
    nonce: &str,
) -> Result<String> {
    use tinycloud_auth::authorization::Cid as AuthCid;
    let resource: ResourceId = owner.space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some(function.parse::<AuthPath>()?),
        None,
        None,
    );
    let notabene = match echo_caveats {
        Some(cv) => {
            let mut m = BTreeMap::new();
            m.insert("computeCaveats".to_string(), cv.clone());
            m
        }
        None => BTreeMap::new(),
    };
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        "tinycloud.compute/execute".parse::<UcanAbility>()?,
        [notabene],
    );
    let proof: AuthCid = parent_cid.parse().context("parse parent cid")?;
    let ucan = Payload {
        issuer: holder.vm.parse::<DIDURLBuf>()?,
        audience: holder.did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(far_future())?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: vec![proof],
        attenuation: caps,
    }
    .sign(holder.jwk.get_algorithm().unwrap_or_default(), &holder.jwk)?;
    Ok(ucan.encode()?)
}

/// POST a delegation and return its CID (from the DelegateResponse).
pub async fn delegate_and_get_cid(client: &Client, grant: &str) -> Result<String> {
    let (status, text) = post_delegate(client, grant).await;
    anyhow::ensure!(status == Status::Ok, "delegate failed ({status}): {text}");
    let v: serde_json::Value = serde_json::from_str(&text)?;
    Ok(v["cid"]
        .as_str()
        .context("delegate cid missing")?
        .to_string())
}

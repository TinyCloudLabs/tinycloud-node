//! Shared harness for the P2 compute integration tests
//! (`compute_execute`, `compute_abi`, `compute_e2e`). Boots a real
//! `tinycloud::app(...)`, mints real delegation chains, deploys the
//! checked-in WAT fixtures through the REAL deploy path, and drives
//! `execute` over HTTP. No mocks -- this is what catches serde/action-name/
//! wire-format drift (per the agent's testing-guide).
//!
//! The fixtures are checked-in WAT text (`tests/fixtures/compute/*.wat`);
//! the node's wasmtime backend is built with the `wat` feature, so the
//! deployed artifact bytes ARE the WAT source (deterministic, no opaque
//! binaries) and the executor compiles them directly.
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
use tinycloud_core::sea_orm::{ConnectOptions, Database, DatabaseConnection};

/// The node's classic identity secret in these tests (matches `boot()`).
pub const NODE_SECRET: [u8; 32] = [11u8; 32];

pub fn far_future() -> f64 {
    4_102_444_800.0
}

/// Boot a real node with tunable compute limits. `fuel`, `max_duration_ms`
/// ceilings, and `max_memory` let individual tests exercise the fuel /
/// epoch / memory-limit traps deterministically without a wall-clock
/// dependency in the ASSERTION (the guest loops; the limit fires).
#[derive(Default)]
pub struct BootOptions {
    pub max_fuel: Option<u64>,
    pub max_duration_ceiling_ms: Option<u64>,
    pub default_max_duration_ms: Option<u64>,
    pub max_memory: Option<String>,
    pub max_memory_ceiling: Option<String>,
    /// Override the node identity secret (rotation tests boot the SAME
    /// datadir twice with DIFFERENT secrets to simulate a dstack seed
    /// rotation, §6.2/F1.5).
    pub secret: Option<[u8; 32]>,
}

pub async fn boot_with(
    opts: BootOptions,
) -> Result<(rocket::Rocket<rocket::Build>, DatabaseConnection, TempDir)> {
    let tempdir = TempDir::new()?;
    let (rocket, conn) = boot_at(tempdir.path(), opts).await?;
    Ok((rocket, conn, tempdir))
}

/// Boot at an explicit base dir (so a test can reboot the SAME datadir with a
/// different secret -- the rotation-tripwire simulation).
pub async fn boot_at(
    base: &std::path::Path,
    opts: BootOptions,
) -> Result<(rocket::Rocket<rocket::Build>, DatabaseConnection)> {
    let datadir = base.join("data");
    let db_url = format!("sqlite:{}", datadir.join("caps.db").display());
    let secret = encode_config(opts.secret.unwrap_or(NODE_SECRET), URL_SAFE_NO_PAD);

    let mut compute_lines = String::new();
    if let Some(f) = opts.max_fuel {
        compute_lines.push_str(&format!("max_fuel = {f}\n"));
    }
    if let Some(c) = opts.max_duration_ceiling_ms {
        compute_lines.push_str(&format!("max_duration_ceiling_ms = {c}\n"));
    }
    if let Some(d) = opts.default_max_duration_ms {
        compute_lines.push_str(&format!("default_max_duration_ms = {d}\n"));
    }
    if let Some(m) = &opts.max_memory {
        compute_lines.push_str(&format!("default_max_memory = \"{m}\"\n"));
    }
    if let Some(m) = &opts.max_memory_ceiling {
        compute_lines.push_str(&format!("max_memory_ceiling = \"{m}\"\n"));
    }

    let config_overlay = format!(
        r#"
[storage]
datadir = "{}"
[storage.compute]
{}
[keys]
type = "Static"
secret = "{}"
"#,
        datadir.display(),
        compute_lines,
        secret
    );
    let figment = rocket::Config::figment()
        .merge(Serialized::defaults(tinycloud::config::Config::default()))
        .merge(Toml::string(&config_overlay));
    let mut tinycloud_config = figment.extract::<tinycloud::config::Config>()?;
    tinycloud_config.storage.resolve();
    let rocket = tinycloud::app(&figment, &tinycloud_config, None).await?;
    let conn = Database::connect(ConnectOptions::new(db_url)).await?;
    Ok((rocket, conn))
}

pub async fn boot() -> Result<(rocket::Rocket<rocket::Build>, DatabaseConnection, TempDir)> {
    boot_with(BootOptions::default()).await
}

/// A space owner (root authority over the space).
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
    assert_eq!(space.did().to_string(), did);
    Ok(Owner {
        space,
        jwk,
        vm,
        did,
    })
}

/// A non-owner holder identity (e.g. a compute/execute invoker with NO data
/// caps, compute-service.md §6.1).
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

pub async fn seed_space_and_actors(
    conn: &DatabaseConnection,
    space: &SpaceId,
    extra_dids: &[String],
) -> Result<()> {
    use tinycloud_core::models::{actor, space as space_model};
    use tinycloud_core::sea_orm::ActiveModelTrait;
    use tinycloud_core::sea_orm::ActiveValue::Set;
    use tinycloud_core::types::SpaceIdWrap;

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

/// These tests insert the `space` row directly (via `seed_space_and_actors`)
/// rather than through the node's space-creation flow, so the file-backed
/// block store's per-space directory (`data/blocks/<suffix>/<name>`) is never
/// created and the first KV blob write would ENOENT. Create it up front. The
/// path mirrors `FileSystemStore::create` (`space.suffix()` /
/// `space.name()`) under the resolved default blocks dir (`data/blocks`).
pub fn ensure_space_storage(tempdir: &TempDir, space: &SpaceId) -> Result<()> {
    let dir = tempdir
        .path()
        .join("data")
        .join("blocks")
        .join(space.suffix())
        .join(space.name().as_str());
    std::fs::create_dir_all(dir)?;
    Ok(())
}

pub fn load_fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/compute")
        .join(name);
    std::fs::read(path).expect("fixture exists")
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

/// POST /invoke with a raw (non-JSON) body -- used to seed a KV value where
/// the body IS the stored blob.
pub async fn post_invoke_raw(client: &Client, auth: &str, body: Vec<u8>) -> (Status, String) {
    let response = client
        .post("/invoke")
        .header(Header::new("Authorization", auth.to_string()))
        .body(body)
        .dispatch()
        .await;
    let status = response.status();
    let text = response.into_string().await.unwrap_or_default();
    (status, text)
}

/// Sign an owner-issued compute invocation on `<space>/compute/<path>`.
pub fn owner_compute_invocation(
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
    sign_invocation(
        &owner.vm,
        &owner.did,
        &owner.jwk,
        resource,
        ability,
        Vec::new(),
        None,
        nonce,
    )
}

/// Sign a KV invocation (used to seed values as the owner).
pub fn owner_kv_invocation(owner: &Owner, key: &str, ability: &str, nonce: &str) -> Result<String> {
    let resource: ResourceId = owner.space.clone().to_resource(
        "kv".parse::<Service>()?,
        Some(key.parse::<AuthPath>()?),
        None,
        None,
    );
    sign_invocation(
        &owner.vm,
        &owner.did,
        &owner.jwk,
        resource,
        ability,
        Vec::new(),
        None,
        nonce,
    )
}

/// Seed a KV value as the owner (a normal `kv/put`, outside any routine).
pub async fn seed_kv(
    client: &Client,
    owner: &Owner,
    key: &str,
    value: &[u8],
    nonce: &str,
) -> Result<()> {
    let auth = owner_kv_invocation(owner, key, "tinycloud.kv/put", nonce)?;
    let (status, body) = post_invoke_raw(client, &auth, value.to_vec()).await;
    anyhow::ensure!(status == Status::Ok, "seed kv failed ({status}): {body}");
    Ok(())
}

/// The RoutineDid handshake (§6.2/F2): learn the routine DID the node
/// derives for `(space, content_cid)`.
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

/// One (service, path, ability) grant line for a `D_fn`.
#[derive(Clone, Copy)]
pub struct GrantSpec {
    pub service: &'static str,
    pub path: &'static str,
    pub ability: &'static str,
}

/// Mint a `D_fn` (owner -> routine_did) granting each `GrantSpec` with the
/// `computeFunctionBinding` caveat naming `content_cid` on every ability row
/// (§5.1/§6.2/D2). Owner is root authority, so no parent proof is needed.
pub fn mint_d_fn(
    owner: &Owner,
    routine_did: &str,
    content_cid: &str,
    grants: &[GrantSpec],
    nonce: &str,
) -> Result<String> {
    let mut binding = BTreeMap::<String, serde_json::Value>::new();
    binding.insert(
        "computeFunctionBinding".to_string(),
        serde_json::json!({ "functionCid": content_cid }),
    );

    let mut caps = Capabilities::new();
    for g in grants {
        let resource: ResourceId = owner.space.clone().to_resource(
            g.service.parse::<Service>()?,
            Some(g.path.parse::<AuthPath>()?),
            None,
            None,
        );
        caps.with_action(
            resource.as_uri(),
            g.ability.parse::<UcanAbility>()?,
            [binding.clone()],
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

/// The A.1 fixture grant: kv/get in/, kv/put out/, kv/del out/, sql/read db,
/// sql/write db (granted, never exercised).
pub fn fixture_grants() -> Vec<GrantSpec> {
    vec![
        GrantSpec {
            service: "kv",
            path: "in/",
            ability: "tinycloud.kv/get",
        },
        GrantSpec {
            service: "kv",
            path: "out/",
            ability: "tinycloud.kv/put",
        },
        GrantSpec {
            service: "kv",
            path: "out/",
            ability: "tinycloud.kv/del",
        },
        GrantSpec {
            service: "sql",
            path: "db",
            ability: "tinycloud.sql/read",
        },
        GrantSpec {
            service: "sql",
            path: "db",
            ability: "tinycloud.sql/write",
        },
    ]
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

/// Deploy `wasm` under `function` with a `D_fn` granting `grants`. Returns
/// the deploy ack. Uses the real deploy path (handshake + atomic deploy).
pub async fn deploy_fixture(
    client: &Client,
    owner: &Owner,
    function: &str,
    wasm: &[u8],
    grants: &[GrantSpec],
    tag: &str,
) -> Result<serde_json::Value> {
    let cid = content_cid(wasm);
    let rdid = handshake_routine_did(client, owner, &cid, &format!("urn:uuid:hs-{tag}")).await?;
    let grant = mint_d_fn(owner, &rdid, &cid, grants, &format!("urn:uuid:dfn-{tag}"))?;
    let auth = owner_compute_invocation(
        owner,
        function,
        "tinycloud.compute/deploy",
        &format!("urn:uuid:dep-{tag}"),
    )?;
    let (status, body) = post_invoke(client, &auth, deploy_body(function, wasm, &grant)).await;
    anyhow::ensure!(status == Status::Ok, "deploy failed ({status}): {body}");
    Ok(serde_json::from_str(&body)?)
}

/// Build an `execute` request body.
pub fn execute_body(function: &str, input: serde_json::Value) -> String {
    serde_json::json!({
        "action": "execute",
        "function": function,
        "input": input,
    })
    .to_string()
}

/// Sign a compute/execute invocation for `function`, optionally echoing a
/// `computeCaveats` nota-bene (invoker-side echo, §6.3) and optionally citing
/// a parent delegation CID (for a holder delegated compute/execute).
#[allow(clippy::too_many_arguments)]
pub fn compute_execute_invocation(
    signer_vm: &str,
    signer_did: &str,
    signer_jwk: &JWK,
    space: &SpaceId,
    function: &str,
    compute_caveats_echo: Option<serde_json::Value>,
    parent: Option<tinycloud_auth::authorization::Cid>,
    nonce: &str,
) -> Result<String> {
    let resource: ResourceId = space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some(function.parse::<AuthPath>()?),
        None,
        None,
    );
    let nota_bene = match compute_caveats_echo {
        Some(v) => {
            let mut m = BTreeMap::<String, serde_json::Value>::new();
            m.insert("computeCaveats".to_string(), v);
            vec![m]
        }
        None => Vec::new(),
    };
    sign_invocation(
        signer_vm,
        signer_did,
        signer_jwk,
        resource,
        "tinycloud.compute/execute",
        nota_bene,
        parent,
        nonce,
    )
}

/// Low-level invocation signer.
#[allow(clippy::too_many_arguments)]
pub fn sign_invocation(
    signer_vm: &str,
    signer_did: &str,
    signer_jwk: &JWK,
    resource: ResourceId,
    ability: &str,
    nota_bene: Vec<BTreeMap<String, serde_json::Value>>,
    parent: Option<tinycloud_auth::authorization::Cid>,
    nonce: &str,
) -> Result<String> {
    let mut caps = Capabilities::new();
    let nb = if nota_bene.is_empty() {
        vec![BTreeMap::<String, serde_json::Value>::new()]
    } else {
        nota_bene
    };
    caps.with_action(resource.as_uri(), ability.parse::<UcanAbility>()?, nb);
    let ucan = Payload {
        issuer: signer_vm.parse::<DIDURLBuf>()?,
        audience: signer_did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(far_future())?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: parent.into_iter().collect(),
        attenuation: caps,
    }
    .sign(signer_jwk.get_algorithm().unwrap_or_default(), signer_jwk)?;
    Ok(ucan.encode()?)
}

/// Delegate `compute/execute` on `function` from owner to holder, optionally
/// carrying a `computeCaveats` caveat (chain-derived enforcement, §6.3).
/// Returns the encoded delegation header AND its CID (for the holder's
/// invocation `proof`).
pub fn delegate_compute_execute(
    owner: &Owner,
    holder_did: &str,
    function: &str,
    compute_caveats: Option<serde_json::Value>,
    nonce: &str,
) -> Result<(String, tinycloud_auth::authorization::Cid)> {
    let resource: ResourceId = owner.space.clone().to_resource(
        "compute".parse::<Service>()?,
        Some(function.parse::<AuthPath>()?),
        None,
        None,
    );
    let nb = match compute_caveats {
        Some(v) => {
            let mut m = BTreeMap::<String, serde_json::Value>::new();
            m.insert("computeCaveats".to_string(), v);
            vec![m]
        }
        None => vec![BTreeMap::<String, serde_json::Value>::new()],
    };
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        "tinycloud.compute/execute".parse::<UcanAbility>()?,
        nb,
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
    let encoded = ucan.encode()?;
    let cid = delegation_cid(&encoded)?;
    Ok((encoded, cid))
}

/// Submit a delegation header to `/delegate` so it persists on the chain.
pub async fn submit_delegation(client: &Client, encoded: &str) -> Result<()> {
    let response = client
        .post("/delegate")
        .header(Header::new("Authorization", encoded.to_string()))
        .dispatch()
        .await;
    let status = response.status();
    let body = response.into_string().await.unwrap_or_default();
    anyhow::ensure!(status == Status::Ok, "delegate failed ({status}): {body}");
    Ok(())
}

/// Compute the CID of an encoded delegation header (its content hash), for
/// use as an invocation `proof`.
pub fn delegation_cid(encoded: &str) -> Result<tinycloud_auth::authorization::Cid> {
    use tinycloud_core::events::Delegation;
    let del =
        Delegation::from_header_ser::<tinycloud_auth::authorization::TinyCloudDelegation>(encoded)
            .map_err(|e| anyhow::anyhow!("decode delegation: {e:?}"))?;
    Ok(del.content_hash().to_cid(0x55))
}

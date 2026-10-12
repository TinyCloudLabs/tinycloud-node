//! TC-780 (N1) reproduction, run against the REAL node authorization and
//! `/invoke` path — not a unit test of `db_name_from_path`.
//!
//! Two defects are pinned by asserting the CORRECT behavior, so both tests are
//! expected to FAIL on `main` until N2 lands:
//!
//! 1. **Cross-app database sharing.** `SqlService::db_name_from_path`
//!    (`tinycloud-core/src/sql/service.rs`) and
//!    `DuckDbService::db_name_from_path` (`tinycloud-core/src/duckdb/service.rs`)
//!    key databases by `(space, last_path_segment)`. Within one space,
//!    `appA/connectors` and `appB/connectors` therefore open the SAME database:
//!    rows the owner writes under `appB/connectors` are returned to a holder
//!    whose grant only covers `appA/connectors`.
//!
//! 2. **Descendant authorization.** `ResourceId::extends`
//!    (`tinycloud-auth/src/resource.rs`) treats a capability path as a prefix:
//!    a grant for the exact path `appA/connectors` (no trailing slash) also
//!    authorizes an invocation on `appA/connectors/private`, which opens a
//!    completely different database (`private`) that the grant never named.
//!
//! The third invocation in each test (`appB/connectors` read) is a control that
//! passes today: a grant on one path must NOT authorize a sibling path — this
//! stays true before and after N2.
//!
//! Space bootstrap mirrors `tc119_registry_wire_paths.rs`: the owner's
//! delegation is persisted directly as a node row, the holder signs UCAN
//! invocations citing it as `prf`, and every call goes through the real
//! `/invoke` route — signature verification, chain containment (`extends`),
//! ability matching, `select_database_scope`, `db_name_from_path`, and the
//! per-service database layer are all exercised on the wire.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
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
    duckdb::{DuckDbRequest, DuckDbValue},
    hash::Hash,
    models::{abilities, actor, space},
    sea_orm::{ActiveModelTrait, ActiveValue::Set, ConnectOptions, Database, DatabaseConnection},
    sql::{SqlRequest, SqlValue},
    types::{Ability, Caveats, Resource, SpaceIdWrap},
};

const FAR_FUTURE_SECONDS: f64 = 4_102_444_800.0; // 2100-01-01
/// Value written under `appA/connectors`. The holder's exact-path grant must
/// return it — a read that is rejected or empty is an over-narrowed grant,
/// not correct isolation.
const APP_A_ROW: &str = "appa-owned-row";
/// Value only ever written under `appB/connectors`. Any read path that returns
/// it proves cross-app data sharing.
const APP_B_SECRET: &str = "appb-only-row";

/// A fresh space plus the owner's signing key so the owner can self-invoke
/// (root authority: no delegation proof needed for their own space).
fn space_identity(name: &str) -> Result<(JWK, String, String, SpaceId)> {
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?;
    let did_string = did.to_string();
    let fragment = did_string
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    let vm = format!("{did_string}#{fragment}");
    Ok((jwk, did_string, vm, SpaceId::new(did, name.parse()?)))
}

fn holder_identity() -> Result<(JWK, String, String)> {
    let mut jwk = JWK::generate_ed25519()?;
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key")?.to_string();
    let fragment = did
        .rsplit_once(':')
        .context("missing did:key fragment")?
        .1
        .to_string();
    Ok((jwk, did.clone(), format!("{did}#{fragment}")))
}

/// Boot a real node against a temp datadir and return (client, node metadata
/// connection, space id). Kept per-test: the process-global logger can only be
/// initialized once per process *target*, and separate #[tokio::test]s in one
/// binary each need their own app instance anyway.
async fn boot_node(
    tempdir: &TempDir,
    space_id: &SpaceId,
    extra_actor_dids: &[String],
) -> Result<(Client, DatabaseConnection)> {
    let datadir = tempdir.path().join("data");
    std::fs::create_dir_all(&datadir)?;
    let db_url = format!("sqlite:{}", datadir.join("caps.db").display());
    let secret = URL_SAFE_NO_PAD.encode([9u8; 32]);
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
    let tinycloud_config = figment.extract::<tinycloud::config::Config>()?;
    let rocket = tinycloud::app_with_control(&figment, &tinycloud_config, None).await?;
    let conn = Database::connect(ConnectOptions::new(db_url)).await?;

    space::ActiveModel {
        id: Set(SpaceIdWrap(space_id.clone())),
    }
    .insert(&conn)
    .await?;
    for did in extra_actor_dids {
        actor::ActiveModel {
            id: Set(did.clone()),
        }
        .insert(&conn)
        .await?;
    }

    Ok((Client::tracked(rocket).await?, conn))
}

/// Persist a root-authority delegation row + one ability row, the way
/// `delegation::process` would have. The delegator is the space owner, so the
/// grant is self-authorizing. Same construction as the tc119 wire test.
async fn persist_grant(
    conn: &DatabaseConnection,
    delegation_hash: Hash,
    owner_did: &str,
    holder_did: &str,
    resource: &ResourceId,
    ability: &str,
) -> Result<()> {
    tinycloud_core::models::delegation::ActiveModel {
        id: Set(delegation_hash),
        delegator: Set(owner_did.to_string()),
        delegatee: Set(holder_did.to_string()),
        expiry: Set(Some(time::OffsetDateTime::from_unix_timestamp(
            FAR_FUTURE_SECONDS as i64,
        )?)),
        issued_at: Set(Some(time::OffsetDateTime::UNIX_EPOCH)),
        not_before: Set(None),
        facts: Set(None),
        serialization: Set(format!("tc780-n1-test-row:{ability}").into_bytes()),
    }
    .insert(conn)
    .await?;

    abilities::ActiveModel {
        delegation: Set(delegation_hash),
        resource: Set(Resource::TinyCloud(resource.clone())),
        ability: Set(Ability::try_from(ability.to_string()).unwrap()),
        caveats: Set(Caveats(BTreeMap::new())),
    }
    .insert(conn)
    .await?;
    Ok(())
}

/// Build a UCAN invocation Authorization header. `proofs` empty = root
/// authority (owner) self-invocation; otherwise cite the persisted grant.
fn invocation(
    invoker_jwk: &JWK,
    invoker_did: &str,
    invoker_vm: &str,
    proofs: Vec<AuthCid>,
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
    let payload = Payload {
        issuer: invoker_vm.parse::<DIDURLBuf>()?,
        audience: invoker_did.parse::<DIDBuf>()?,
        not_before: None,
        // Must stay under the node's default 300 s invocation lifetime cap
        // (`config.invocation.max_lifetime_secs`), else /invoke rejects the
        // token before the authorization checks this test exists to exercise.
        expiration: NumericDate::try_from_seconds(
            time::OffsetDateTime::now_utc().unix_timestamp() as f64 + 250.0,
        )?,
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: proofs,
        attenuation: caps,
    }
    .sign(invoker_jwk.get_algorithm().unwrap_or_default(), invoker_jwk)?;
    Ok(payload.encode()?)
}

fn db_resource(space_id: &SpaceId, service: &str, path: &str) -> Result<ResourceId> {
    Ok(space_id.clone().to_resource(
        service.parse::<Service>()?,
        Some(path.parse::<AuthPath>()?),
        None,
        None,
    ))
}

/// Dispatch a JSON-bodied `/invoke` and return (status, body).
async fn invoke_json(
    client: &Client,
    header: String,
    body: &serde_json::Value,
) -> (Status, String) {
    let resp = client
        .post("/invoke")
        .header(Header::new("Authorization", header))
        .header(ContentType::JSON)
        .body(body.to_string())
        .dispatch()
        .await;
    let status = resp.status();
    let body = resp.into_string().await.unwrap_or_default();
    (status, body)
}

/// Bundled invoker identity for readability.
struct Invoker {
    jwk: JWK,
    did: String,
    vm: String,
}

/// Append a failure description when `ok` is false. Collecting rather than
/// panicking means one red run reports EVERY broken guarantee, not just the
/// first — both defects surface in the same failure output.
fn check(failures: &mut Vec<String>, ok: bool, detail: impl std::fmt::Display) {
    if !ok {
        failures.push(detail.to_string());
    }
}

fn sql_write_body(row: &str) -> serde_json::Value {
    serde_json::to_value(SqlRequest::Execute {
        schema: Some(vec!["CREATE TABLE IF NOT EXISTS t (v TEXT)".to_string()]),
        sql: "INSERT INTO t (v) VALUES (?)".to_string(),
        params: vec![SqlValue::Text(row.to_string())],
    })
    .expect("SqlRequest serializes")
}

fn duckdb_write_body(row: &str) -> serde_json::Value {
    serde_json::to_value(DuckDbRequest::Execute {
        sql: "INSERT INTO t (v) VALUES (?)".to_string(),
        params: vec![DuckDbValue::Text(row.to_string())],
        schema: Some(vec!["CREATE TABLE IF NOT EXISTS t (v TEXT)".to_string()]),
    })
    .expect("DuckDbRequest serializes")
}

/// Per-engine parameters for the shared scenario driver.
struct Engine {
    service: &'static str,
    write_ability: &'static str,
    read_ability: &'static str,
    grant_seed: &'static [u8],
    nonce_prefix: &'static str,
    /// Builds the Execute body writing `row` into `t`. The DDL is `IF NOT
    /// EXISTS` because on main BOTH owner writes land in the same `connectors`
    /// database — the second write must still succeed so the two rows coexist.
    write_body: fn(&str) -> serde_json::Value,
    read_body: serde_json::Value,
}

/// Run the full repro for one engine and return every violated guarantee.
/// An empty Vec is the correct (post-N2) outcome.
async fn run_scenario(engine: &Engine, space_name: &str, tempdir: &TempDir) -> Result<Vec<String>> {
    let (owner_jwk, owner_did, owner_vm, space_id) = space_identity(space_name)?;
    let owner = Invoker {
        jwk: owner_jwk,
        did: owner_did,
        vm: owner_vm,
    };
    let (holder_jwk, holder_did, holder_vm) = holder_identity()?;
    let holder = Invoker {
        jwk: holder_jwk,
        did: holder_did,
        vm: holder_vm,
    };
    let (client, conn) =
        boot_node(tempdir, &space_id, &[owner.did.clone(), holder.did.clone()]).await?;

    let mut failures: Vec<String> = Vec::new();

    // The OWNER writes under BOTH paths through the real invoke path — root
    // authority means no grant row is needed. On main these land in the same
    // `connectors` database; after N2 they are separate databases.
    let appa = db_resource(&space_id, engine.service, "appA/connectors")?;
    let appb = db_resource(&space_id, engine.service, "appB/connectors")?;
    for (resource, row, nonce_suffix) in [(&appa, APP_A_ROW, "05"), (&appb, APP_B_SECRET, "01")] {
        let (status, body) = invoke_json(
            &client,
            invocation(
                &owner.jwk,
                &owner.did,
                &owner.vm,
                vec![],
                resource,
                engine.write_ability,
                &format!(
                    "urn:uuid:00000000-0000-4000-8000-{}{nonce_suffix}",
                    engine.nonce_prefix
                ),
            )?,
            &(engine.write_body)(row),
        )
        .await;
        if status != Status::Ok {
            // Seed failed — the rest of the scenario is meaningless. This is a
            // harness bug, not the defect, so bail loudly.
            return Err(anyhow::anyhow!(
                "owner write of {row:?} under {} must succeed (got {status}): {body}",
                resource.path().map(|p| p.as_str()).unwrap_or("<none>"),
            ));
        }
    }

    // The holder is granted `<engine>/read` on the EXACT path
    // `appA/connectors` — no trailing slash.
    let holder_grant = tinycloud_core::hash::hash(engine.grant_seed);
    persist_grant(
        &conn,
        holder_grant,
        &owner.did,
        &holder.did,
        &appa,
        engine.read_ability,
    )
    .await?;

    // (1) Cross-app isolation, in both directions of correctness: the exact-
    // path grant must SUCCEED and return appA's own row (an over-narrowed fix
    // that rejects or empties this read is also wrong), AND it must not leak
    // appB's row. On main both paths resolve to the `connectors` database, so
    // the response contains BOTH rows.
    let (status, body) = invoke_json(
        &client,
        invocation(
            &holder.jwk,
            &holder.did,
            &holder.vm,
            vec![holder_grant.to_cid(0x55)],
            &appa,
            engine.read_ability,
            &format!("urn:uuid:00000000-0000-4000-8000-{}02", engine.nonce_prefix),
        )?,
        &engine.read_body,
    )
    .await;
    check(
        &mut failures,
        status == Status::Ok && body.contains(APP_A_ROW),
        format!(
            "the exact-path grant on appA/connectors must authorize a read \
             returning its own row (expected 200 with {APP_A_ROW:?}, got \
             {status}): {body}"
        ),
    );
    check(
        &mut failures,
        !body.contains(APP_B_SECRET),
        format!(
            "appA/connectors must NOT read data written under appB/connectors \
             (status {status}); the two paths share the `connectors` database: {body}"
        ),
    );

    // (2) Exact-path authorization: a grant for `appA/connectors` (no trailing
    // slash) must NOT authorize `appA/connectors/private`. On main `extends`
    // accepts descendants, authorization passes, and the request reaches the
    // `private` database — so the status is not 401.
    let appa_private = db_resource(&space_id, engine.service, "appA/connectors/private")?;
    let (status, body) = invoke_json(
        &client,
        invocation(
            &holder.jwk,
            &holder.did,
            &holder.vm,
            vec![holder_grant.to_cid(0x55)],
            &appa_private,
            engine.read_ability,
            &format!("urn:uuid:00000000-0000-4000-8000-{}03", engine.nonce_prefix),
        )?,
        &engine.read_body,
    )
    .await;
    check(
        &mut failures,
        status == Status::Unauthorized,
        format!(
            "an exact-path grant for appA/connectors must NOT authorize \
             appA/connectors/private (expected 401, got {status}): {body}"
        ),
    );

    // Control (passes today): the same grant must NOT authorize the sibling
    // path `appB/connectors` — resource matching rejects it outright. This
    // guards the N2 fix from over-narrowing grants.
    let (status, body) = invoke_json(
        &client,
        invocation(
            &holder.jwk,
            &holder.did,
            &holder.vm,
            vec![holder_grant.to_cid(0x55)],
            &appb,
            engine.read_ability,
            &format!("urn:uuid:00000000-0000-4000-8000-{}04", engine.nonce_prefix),
        )?,
        &engine.read_body,
    )
    .await;
    check(
        &mut failures,
        status == Status::Unauthorized,
        format!(
            "a grant for appA/connectors must NOT authorize appB/connectors \
             (expected 401, got {status}): {body}"
        ),
    );

    Ok(failures)
}

/// SQL path-isolation repro (TC-780 N1, engine = sql). On main the returned
/// failure list names both defects: `sql/service.rs` `db_name_from_path`
/// collapses `appA/connectors` and `appB/connectors` to the same `connectors`
/// database, and `ResourceId::extends` (`models/invocation.rs`) authorizes
/// descendants of an exact-path grant.
#[tokio::test]
async fn sql_paths_do_not_share_databases_and_grants_are_exact() -> Result<()> {
    let tempdir = TempDir::new()?;
    let engine = Engine {
        service: "sql",
        write_ability: "tinycloud.sql/write",
        read_ability: "tinycloud.sql/read",
        grant_seed: b"tc780-n1-sql-read-appA-connectors",
        nonce_prefix: "000000000a",
        write_body: sql_write_body,
        read_body: serde_json::to_value(SqlRequest::Query {
            sql: "SELECT v FROM t".to_string(),
            params: vec![],
            max_rows: None,
            max_bytes: None,
        })?,
    };
    let failures = run_scenario(&engine, "tc780-n1-sql", &tempdir).await?;
    assert!(
        failures.is_empty(),
        "SQL path isolation violated:\n  - {}",
        failures.join("\n  - ")
    );
    Ok(())
}

/// DuckDB path-isolation repro — same defects through `duckdb/service.rs`
/// `db_name_from_path` (last segment, or `default`) plus the same
/// `ResourceId::extends` descendant acceptance.
#[tokio::test]
async fn duckdb_paths_do_not_share_databases_and_grants_are_exact() -> Result<()> {
    let tempdir = TempDir::new()?;
    let engine = Engine {
        service: "duckdb",
        write_ability: "tinycloud.duckdb/write",
        read_ability: "tinycloud.duckdb/read",
        grant_seed: b"tc780-n1-duckdb-read-appA-connectors",
        nonce_prefix: "000000000b",
        write_body: duckdb_write_body,
        read_body: serde_json::to_value(DuckDbRequest::Query {
            sql: "SELECT v FROM t".to_string(),
            params: vec![],
        })?,
    };
    let failures = run_scenario(&engine, "tc780-n1-duckdb", &tempdir).await?;
    assert!(
        failures.is_empty(),
        "DuckDB path isolation violated:\n  - {}",
        failures.join("\n  - ")
    );
    Ok(())
}

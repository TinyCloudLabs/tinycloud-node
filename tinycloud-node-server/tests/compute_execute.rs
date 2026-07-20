//! P2 enforcement matrix gate (compute-service-implementation-plan.md P2):
//! `cargo test -p tinycloud-node --test compute_execute --features compute`.
//!
//! Every advertised control gets a focused test (C6): per-import allowed/
//! denied under granting/non-granting `D_fn` (all four imports), the SQL
//! statement-level authorizer still applying under a granted ability, cite-all
//! multi-`D_fn` selection, the chain-derived `functions` allowlist, fuel
//! exhaustion, epoch timeout, memory-growth failure, input-schema rejection,
//! numeric-ceiling rejection, the `routine-identity-rotated` tripwire (a
//! DISTINCT 409, not a 403), and the invoker-side caveat echo (§6.3).

mod compute_common;
use compute_common::*;

use anyhow::Result;
use rocket::{http::Status, local::asynchronous::Client};
use tinycloud_core::sea_orm::{
    ActiveModelTrait, ActiveValue::Set, DatabaseConnection, EntityTrait,
};

const P_GET: &str = include_str!("fixtures/compute/passthrough_storage_get.wat");
const P_PUT: &str = include_str!("fixtures/compute/passthrough_storage_put.wat");
const P_DEL: &str = include_str!("fixtures/compute/passthrough_storage_del.wat");
const P_SQL: &str = include_str!("fixtures/compute/passthrough_sql_query.wat");
const SPIN: &str = include_str!("fixtures/compute/spin.wat");
const MEMBOMB: &str = include_str!("fixtures/compute/memory_bomb.wat");

/// Execute `function` as the owner (root authority) and return the parsed
/// `{result, manifest}` response (asserting a 200).
async fn owner_execute(
    client: &Client,
    owner: &Owner,
    function: &str,
    input: serde_json::Value,
    tag: &str,
) -> Result<serde_json::Value> {
    let auth = owner_compute_invocation(
        owner,
        function,
        "tinycloud.compute/execute",
        &format!("urn:uuid:exec-{tag}"),
    )?;
    let (status, body) = post_invoke(client, &auth, execute_body(function, input)).await;
    anyhow::ensure!(status == Status::Ok, "execute must 200 ({status}): {body}");
    Ok(serde_json::from_str(&body)?)
}

/// Seed a KV value as the owner (for storage_get tests).
async fn seed_kv(client: &Client, owner: &Owner, key: &str, value: &[u8]) -> Result<()> {
    use tinycloud_auth::{
        resource::{Path as AuthPath, ResourceId, Service},
        siwe_recap::Ability as UcanAbility,
        ssi::{
            claims::jwt::NumericDate,
            dids::{DIDBuf, DIDURLBuf},
            ucan::Payload,
        },
        ucan_capabilities_object::Capabilities,
    };
    let resource: ResourceId = owner.space.clone().to_resource(
        "kv".parse::<Service>()?,
        Some(key.parse::<AuthPath>()?),
        None,
        None,
    );
    let mut caps = Capabilities::new();
    caps.with_action(
        resource.as_uri(),
        "tinycloud.kv/put".parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );
    let ucan = Payload {
        issuer: owner.vm.parse::<DIDURLBuf>()?,
        audience: owner.did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(far_future())?,
        nonce: Some(format!("urn:uuid:seed-{key}")),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: Vec::new(),
        attenuation: caps,
    }
    .sign(owner.jwk.get_algorithm().unwrap_or_default(), &owner.jwk)?;
    let response = client
        .post("/invoke")
        .header(rocket::http::Header::new("Authorization", ucan.encode()?))
        .header(rocket::http::ContentType::Bytes)
        .body(value)
        .dispatch()
        .await;
    anyhow::ensure!(
        response.status() == Status::Ok,
        "seed kv {key} failed: {}",
        response.into_string().await.unwrap_or_default()
    );
    Ok(())
}

// ===========================================================================
// Per-import allowed / denied (all four imports)
// ===========================================================================

#[tokio::test]
async fn storage_get_allowed_and_denied() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-get")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42").await?;

    // granting D_fn (kv/get on in/)
    let wasm = wat_to_wasm(P_GET)?;
    deploy_function(
        &client,
        &owner,
        "getfn",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "get-ok",
    )
    .await?;
    let v = owner_execute(
        &client,
        &owner,
        "getfn",
        serde_json::json!({"key": "in/x"}),
        "get-ok",
    )
    .await?;
    assert_eq!(v["result"]["ok"], true, "granted get must succeed");
    assert_eq!(v["result"]["value"], "42");
    assert_eq!(v["manifest"]["calls"][0]["granted"], true);

    // non-granting D_fn (only kv/put, no get)
    // Distinct bytes -> distinct routine identity, so the non-granting D_fn
    // is the ONLY grant this routine has (identical bytes would share the
    // granting routine identity, the same-bytes hazard §5.1).
    let wasm2 = wat_to_wasm_salted(P_GET, "getno")?;
    deploy_function(
        &client,
        &owner,
        "getfn2",
        &wasm2,
        &[("tinycloud.kv/put", "out/")],
        "get-no",
    )
    .await?;
    let v = owner_execute(
        &client,
        &owner,
        "getfn2",
        serde_json::json!({"key": "in/x"}),
        "get-no",
    )
    .await?;
    assert_eq!(v["result"]["ok"], false, "ungranted get must fail closed");
    assert_eq!(v["result"]["error"]["code"], "ability-denied");
    assert_eq!(v["manifest"]["calls"][0]["granted"], false);
    Ok(())
}

#[tokio::test]
async fn storage_put_allowed_and_denied() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-put")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let wasm = wat_to_wasm(P_PUT)?;
    deploy_function(
        &client,
        &owner,
        "putfn",
        &wasm,
        &[("tinycloud.kv/put", "out/")],
        "put-ok",
    )
    .await?;
    let v = owner_execute(
        &client,
        &owner,
        "putfn",
        serde_json::json!({"key": "out/y", "value": "84"}),
        "put-ok",
    )
    .await?;
    assert_eq!(v["result"]["ok"], true, "granted put must succeed");
    assert_eq!(v["manifest"]["calls"][0]["granted"], true);

    let wasm_no = wat_to_wasm_salted(P_PUT, "putno")?;
    deploy_function(
        &client,
        &owner,
        "putfn2",
        &wasm_no,
        &[("tinycloud.kv/get", "in/")],
        "put-no",
    )
    .await?;
    let v = owner_execute(
        &client,
        &owner,
        "putfn2",
        serde_json::json!({"key": "out/y", "value": "84"}),
        "put-no",
    )
    .await?;
    assert_eq!(v["result"]["ok"], false, "ungranted put must fail closed");
    assert_eq!(v["manifest"]["calls"][0]["granted"], false);
    Ok(())
}

#[tokio::test]
async fn storage_del_allowed_and_denied() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-del")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    // Seed the key so the granted delete removes a real value (deleting a
    // missing key is a distinct, observable no-such-key envelope).
    seed_kv(&client, &owner, "out/y", b"v").await?;

    let wasm = wat_to_wasm(P_DEL)?;
    deploy_function(
        &client,
        &owner,
        "delfn",
        &wasm,
        &[("tinycloud.kv/del", "out/")],
        "del-ok",
    )
    .await?;
    let v = owner_execute(
        &client,
        &owner,
        "delfn",
        serde_json::json!({"key": "out/y"}),
        "del-ok",
    )
    .await?;
    assert_eq!(v["result"]["ok"], true, "granted del must succeed");
    assert_eq!(v["manifest"]["calls"][0]["granted"], true);

    let wasm_no = wat_to_wasm_salted(P_DEL, "delno")?;
    deploy_function(
        &client,
        &owner,
        "delfn2",
        &wasm_no,
        &[("tinycloud.kv/get", "in/")],
        "del-no",
    )
    .await?;
    let v = owner_execute(
        &client,
        &owner,
        "delfn2",
        serde_json::json!({"key": "out/y"}),
        "del-no",
    )
    .await?;
    assert_eq!(v["result"]["ok"], false, "ungranted del must fail closed");
    assert_eq!(v["manifest"]["calls"][0]["granted"], false);
    Ok(())
}

#[tokio::test]
async fn sql_query_allowed_and_denied() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-sql")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let wasm = wat_to_wasm(P_SQL)?;
    let query = serde_json::json!({"action": "query", "sql": "SELECT 1 AS n", "params": []});

    deploy_function(
        &client,
        &owner,
        "sqlfn",
        &wasm,
        &[("tinycloud.sql/read", "db")],
        "sql-ok",
    )
    .await?;
    let v = owner_execute(&client, &owner, "sqlfn", query.clone(), "sql-ok").await?;
    assert_eq!(
        v["result"]["rowCount"], 1,
        "granted sql read must return rows"
    );
    assert_eq!(v["manifest"]["calls"][0]["granted"], true);
    assert_eq!(v["manifest"]["calls"][0]["ability"], "tinycloud.sql/read");

    let wasm_no = wat_to_wasm_salted(P_SQL, "sqlno")?;
    deploy_function(
        &client,
        &owner,
        "sqlfn2",
        &wasm_no,
        &[("tinycloud.kv/get", "in/")],
        "sql-no",
    )
    .await?;
    let v = owner_execute(&client, &owner, "sqlfn2", query, "sql-no").await?;
    assert_eq!(v["result"]["ok"], false, "ungranted sql must fail closed");
    assert_eq!(v["result"]["error"]["code"], "ability-denied");
    assert_eq!(v["manifest"]["calls"][0]["granted"], false);
    Ok(())
}

/// The EXISTING create_authorizer still applies: a granted `sql/write` does
/// NOT let a routine run an out-of-policy statement (ATTACH is always denied).
#[tokio::test]
async fn sql_statement_authorizer_still_applies_under_granted_ability() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-sqlstmt")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let wasm = wat_to_wasm(P_SQL)?;
    deploy_function(
        &client,
        &owner,
        "sqlstmt",
        &wasm,
        &[("tinycloud.sql/write", "db")],
        "sqlstmt",
    )
    .await?;
    // ATTACH is denied by the statement-level authorizer even though the
    // sql/write ABILITY is granted -> a `sql-denied` envelope, granted:true.
    let req = serde_json::json!({"action": "execute", "sql": "ATTACH DATABASE 'evil.db' AS evil", "params": []});
    let v = owner_execute(&client, &owner, "sqlstmt", req, "sqlstmt").await?;
    assert_eq!(
        v["result"]["ok"], false,
        "out-of-policy statement must be rejected"
    );
    // The ability WAS granted; the rejection is statement-level, not an
    // ability denial.
    assert_eq!(
        v["manifest"]["calls"][0]["granted"], true,
        "sql/write ability was granted"
    );
    assert_eq!(v["result"]["error"]["code"], "sql-denied");
    Ok(())
}

// ===========================================================================
// cite-all multi-D_fn selection (§5.1/F5)
// ===========================================================================

#[tokio::test]
async fn cite_all_selects_across_multiple_d_fns() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-citeall")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42").await?;

    // Deploy with D_fn #1 granting ONLY kv/get.
    let wasm = wat_to_wasm(P_GET)?;
    let (rdid, cid) = deploy_function(
        &client,
        &owner,
        "multi",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "ca",
    )
    .await?;

    // Separately delegate D_fn #2 (owner->routine_did) granting kv/put, with
    // the SAME binding caveat -- a distinct live delegation to the same
    // routine identity (a re-grant with wider caps, §5.1/F5).
    let d_fn2 = mint_d_fn_grant(
        &owner,
        &rdid,
        &cid,
        &[("tinycloud.kv/put", "out/")],
        "urn:uuid:dfn2-ca",
    )?;
    let (status, text) = post_delegate(&client, &d_fn2).await;
    assert_eq!(status, Status::Ok, "second D_fn delegate: {text}");

    // The get succeeds via D_fn #1 (proves cite-all still authorizes it when
    // more than one D_fn is live).
    let v = owner_execute(
        &client,
        &owner,
        "multi",
        serde_json::json!({"key": "in/x"}),
        "ca",
    )
    .await?;
    assert_eq!(
        v["result"]["ok"], true,
        "get authorized via cite-all across 2 live D_fns"
    );
    Ok(())
}

// ===========================================================================
// chain-derived functions allowlist + invoker-side echo (§6.3)
// ===========================================================================

#[tokio::test]
async fn functions_allowlist_from_chain_is_enforced() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-allow")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42").await?;

    let wasm = wat_to_wasm(P_GET)?;
    deploy_function(
        &client,
        &owner,
        "allowed",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "al1",
    )
    .await?;
    deploy_function(
        &client,
        &owner,
        "blocked",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "al2",
    )
    .await?;

    let holder = make_holder()?;
    let caveats = serde_json::json!({ "functions": ["allowed"] });

    // Delegate compute/execute on "allowed" WITH the functions allowlist caveat.
    let deleg = mint_execute_delegation(
        &owner,
        &holder.did,
        "allowed",
        Some(&caveats),
        "urn:uuid:al-deleg",
    )?;
    let parent = delegate_and_get_cid(&client, &deleg).await?;

    // Holder executes "allowed" echoing the caveat -> succeeds.
    let inv = holder_execute_invocation(
        &holder,
        &owner,
        "allowed",
        &parent,
        Some(&caveats),
        "urn:uuid:al-ok",
    )?;
    let (status, body) = post_invoke(
        &client,
        &inv,
        execute_body("allowed", serde_json::json!({"key": "in/x"})),
    )
    .await;
    assert_eq!(status, Status::Ok, "allowed function must execute: {body}");

    // Delegate compute/execute on "blocked" (different resource) but with the
    // SAME allowlist caveat that names only "allowed" -> executing "blocked"
    // is refused by the chain-derived allowlist.
    let deleg_b = mint_execute_delegation(
        &owner,
        &holder.did,
        "blocked",
        Some(&caveats),
        "urn:uuid:bl-deleg",
    )?;
    let parent_b = delegate_and_get_cid(&client, &deleg_b).await?;
    let inv_b = holder_execute_invocation(
        &holder,
        &owner,
        "blocked",
        &parent_b,
        Some(&caveats),
        "urn:uuid:bl-no",
    )?;
    let (status, body) = post_invoke(
        &client,
        &inv_b,
        execute_body("blocked", serde_json::json!({"key": "in/x"})),
    )
    .await;
    assert_eq!(
        status,
        Status::Forbidden,
        "function not in allowlist must be 403: {body}"
    );
    Ok(())
}

/// Invoker-side echo (§6.3): a `compute/execute` delegation carrying a
/// non-SQL `computeCaveats` map MUST be echoed on the invocation, or
/// `validate()` rejects it before the handler runs.
#[tokio::test]
async fn invoker_side_caveat_echo_is_enforced() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-echo")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42").await?;

    let wasm = wat_to_wasm(P_GET)?;
    deploy_function(
        &client,
        &owner,
        "echofn",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "echo",
    )
    .await?;

    let holder = make_holder()?;
    let caveats = serde_json::json!({ "functions": ["echofn"] });
    let deleg = mint_execute_delegation(
        &owner,
        &holder.did,
        "echofn",
        Some(&caveats),
        "urn:uuid:echo-deleg",
    )?;
    let parent = delegate_and_get_cid(&client, &deleg).await?;

    // NOT echoing the chain caveat -> validate() rejects (containment).
    let inv_bad = holder_execute_invocation(
        &holder,
        &owner,
        "echofn",
        &parent,
        None,
        "urn:uuid:echo-bad",
    )?;
    let (status, _body) = post_invoke(
        &client,
        &inv_bad,
        execute_body("echofn", serde_json::json!({"key": "in/x"})),
    )
    .await;
    assert_ne!(
        status,
        Status::Ok,
        "un-echoed caveated invocation must be rejected"
    );

    // Echoing it verbatim -> succeeds.
    let inv_ok = holder_execute_invocation(
        &holder,
        &owner,
        "echofn",
        &parent,
        Some(&caveats),
        "urn:uuid:echo-ok",
    )?;
    let (status, body) = post_invoke(
        &client,
        &inv_ok,
        execute_body("echofn", serde_json::json!({"key": "in/x"})),
    )
    .await;
    assert_eq!(status, Status::Ok, "echoed invocation must succeed: {body}");
    Ok(())
}

// ===========================================================================
// resource limits: fuel, epoch, memory
// ===========================================================================

#[tokio::test]
async fn fuel_exhaustion_traps() -> Result<()> {
    // Tiny CPU (fuel) ceiling; normal duration. The spinning guest runs out
    // of fuel and traps.
    let (rocket, conn, tempdir) =
        boot_with_compute_overlay("[storage.compute]\nmax_fuel_ceiling = 200000\n").await?;
    let owner = make_owner("exec-fuel")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let wasm = wat_to_wasm(SPIN)?;
    deploy_function(
        &client,
        &owner,
        "spin",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "fuel",
    )
    .await?;
    let auth =
        owner_compute_invocation(&owner, "spin", "tinycloud.compute/execute", "urn:uuid:fuel")?;
    let (status, body) =
        post_invoke(&client, &auth, execute_body("spin", serde_json::json!({}))).await;
    assert_eq!(
        status,
        Status::UnprocessableEntity,
        "fuel exhaustion must trap: {body}"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn epoch_timeout_traps() -> Result<()> {
    // Huge fuel ceiling so fuel never runs out; tiny default duration so the
    // epoch deadline trips the spinning guest.
    let (rocket, conn, tempdir) = boot_with_compute_overlay(
        "[storage.compute]\nmax_fuel_ceiling = 1000000000000\ndefault_max_duration_ms = 40\n",
    )
    .await?;
    let owner = make_owner("exec-epoch")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let wasm = wat_to_wasm(SPIN)?;
    deploy_function(
        &client,
        &owner,
        "spin",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "epoch",
    )
    .await?;
    let auth = owner_compute_invocation(
        &owner,
        "spin",
        "tinycloud.compute/execute",
        "urn:uuid:epoch",
    )?;
    let (status, body) =
        post_invoke(&client, &auth, execute_body("spin", serde_json::json!({}))).await;
    assert_eq!(
        status,
        Status::UnprocessableEntity,
        "epoch deadline must trap: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn memory_growth_past_limit_fails() -> Result<()> {
    // Small memory ceiling so the growth-bomb guest is denied and traps.
    let (rocket, conn, tempdir) = boot_with_compute_overlay(
        "[storage.compute]\ndefault_max_memory_bytes = 4194304\nmax_memory_bytes_ceiling = 4194304\n",
    )
    .await?;
    let owner = make_owner("exec-mem")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let wasm = wat_to_wasm(MEMBOMB)?;
    deploy_function(
        &client,
        &owner,
        "membomb",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "mem",
    )
    .await?;
    let auth = owner_compute_invocation(
        &owner,
        "membomb",
        "tinycloud.compute/execute",
        "urn:uuid:mem",
    )?;
    let (status, body) = post_invoke(
        &client,
        &auth,
        execute_body("membomb", serde_json::json!({})),
    )
    .await;
    assert_eq!(
        status,
        Status::UnprocessableEntity,
        "memory-growth past the limit must trap: {body}"
    );
    Ok(())
}

// ===========================================================================
// input schema + numeric ceilings (§10.1)
// ===========================================================================

#[tokio::test]
async fn input_schema_rejection() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-schema")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42").await?;

    let wasm = wat_to_wasm(P_GET)?;
    deploy_function(
        &client,
        &owner,
        "schemafn",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "sch",
    )
    .await?;

    let holder = make_holder()?;
    // Require input to be an object with a required string `key`.
    let caveats = serde_json::json!({
        "functions": ["schemafn"],
        "inputs": { "type": "object", "required": ["key"], "properties": { "key": { "type": "string" } } }
    });
    let deleg = mint_execute_delegation(
        &owner,
        &holder.did,
        "schemafn",
        Some(&caveats),
        "urn:uuid:sch-deleg",
    )?;
    let parent = delegate_and_get_cid(&client, &deleg).await?;

    // Bad input (missing required `key`) -> 400.
    let inv_bad = holder_execute_invocation(
        &holder,
        &owner,
        "schemafn",
        &parent,
        Some(&caveats),
        "urn:uuid:sch-bad",
    )?;
    let (status, body) = post_invoke(
        &client,
        &inv_bad,
        execute_body("schemafn", serde_json::json!({"nope": 1})),
    )
    .await;
    assert_eq!(
        status,
        Status::BadRequest,
        "schema-invalid input must be 400: {body}"
    );

    // Good input -> 200.
    let inv_ok = holder_execute_invocation(
        &holder,
        &owner,
        "schemafn",
        &parent,
        Some(&caveats),
        "urn:uuid:sch-ok",
    )?;
    let (status, body) = post_invoke(
        &client,
        &inv_ok,
        execute_body("schemafn", serde_json::json!({"key": "in/x"})),
    )
    .await;
    assert_eq!(
        status,
        Status::Ok,
        "schema-valid input must succeed: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn numeric_ceiling_rejection() -> Result<()> {
    // Config ceiling for maxMemory is small; a chain caveat asking for more
    // is rejected on ingest (no silent clamp).
    let (rocket, conn, tempdir) =
        boot_with_compute_overlay("[storage.compute]\nmax_memory_bytes_ceiling = 8388608\n")
            .await?;
    let owner = make_owner("exec-ceiling")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42").await?;

    let wasm = wat_to_wasm(P_GET)?;
    deploy_function(
        &client,
        &owner,
        "ceilfn",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "ceil",
    )
    .await?;

    let holder = make_holder()?;
    // maxMemory well above the 8 MiB ceiling.
    let caveats = serde_json::json!({ "functions": ["ceilfn"], "maxMemory": 1073741824u64 });
    let deleg = mint_execute_delegation(
        &owner,
        &holder.did,
        "ceilfn",
        Some(&caveats),
        "urn:uuid:ceil-deleg",
    )?;
    let parent = delegate_and_get_cid(&client, &deleg).await?;
    let inv = holder_execute_invocation(
        &holder,
        &owner,
        "ceilfn",
        &parent,
        Some(&caveats),
        "urn:uuid:ceil",
    )?;
    let (status, body) = post_invoke(
        &client,
        &inv,
        execute_body("ceilfn", serde_json::json!({"key": "in/x"})),
    )
    .await;
    assert_eq!(
        status,
        Status::BadRequest,
        "over-ceiling caveat must be rejected: {body}"
    );
    Ok(())
}

// ===========================================================================
// routine-identity-rotated tripwire (§6.2/F1.5) -- a DISTINCT 409, not 403
// ===========================================================================

#[tokio::test]
async fn routine_identity_rotated_is_distinct_error() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("exec-rotate")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42").await?;

    let wasm = wat_to_wasm(P_GET)?;
    let (rdid, _cid) = deploy_function(
        &client,
        &owner,
        "rotate",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "rot",
    )
    .await?;

    // Simulate a dstack seed rotation: the D_fn's delegatee no longer matches
    // the (now re-derived) routine DID. We flip the persisted delegation's
    // delegatee to a bogus DID, leaving the binding caveat intact -- exactly
    // the on-disk signature of a rotation (a live D_fn bound to this CID, but
    // under an identity the node can no longer derive).
    rotate_delegatee(&conn, &rdid).await?;

    let auth = owner_compute_invocation(
        &owner,
        "rotate",
        "tinycloud.compute/execute",
        "urn:uuid:rot",
    )?;
    let (status, body) = post_invoke(
        &client,
        &auth,
        execute_body("rotate", serde_json::json!({"key": "in/x"})),
    )
    .await;
    // 409 Conflict -- the distinct routine-identity-rotated code, NOT a 403.
    assert_eq!(
        status,
        Status::Conflict,
        "rotation must be a distinct 409: {body}"
    );
    assert_ne!(status, Status::Forbidden, "must NOT be a generic 403");
    assert!(
        body.contains("routine-identity-rotated"),
        "error must name the rotation: {body}"
    );
    Ok(())
}

/// Flip every delegation whose delegatee is `rdid` to a bogus DID (simulating
/// a seed rotation), leaving ability rows -- including the binding caveat --
/// untouched.
async fn rotate_delegatee(conn: &DatabaseConnection, rdid: &str) -> Result<()> {
    use tinycloud_core::models::{actor, delegation as deleg_model};
    use tinycloud_core::sea_orm::{ColumnTrait, QueryFilter};
    // `delegation.delegatee` is an FK onto `actor.id`; insert the bogus rotated
    // identity as an actor first.
    let bogus = "did:key:z6MkBogusRotatedIdentityAaaaaaaaaaaaaaaaaaaaaaaa".to_string();
    let _ = actor::ActiveModel {
        id: Set(bogus.clone()),
    }
    .insert(conn)
    .await;
    let rows = deleg_model::Entity::find()
        .filter(deleg_model::Column::Delegatee.eq(rdid))
        .all(conn)
        .await?;
    anyhow::ensure!(!rows.is_empty(), "expected a live D_fn to rotate");
    for row in rows {
        let mut active: deleg_model::ActiveModel = row.into();
        active.delegatee = Set(bogus.clone());
        active.update(conn).await?;
    }
    Ok(())
}

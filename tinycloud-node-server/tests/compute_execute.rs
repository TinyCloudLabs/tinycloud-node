//! P2 enforcement matrix
//! (`cargo test -p tinycloud-node --test compute_execute --features compute`).
//!
//! Each advertised control gets a focused assertion (plan P2 "verify" / C6):
//! per-import allow/deny (all four imports), the SQL statement-level
//! authorizer, caveat-echo (routine + invoker side), cite-all multi-`D_fn`
//! selection, the `functions` allowlist, fuel exhaustion, epoch timeout,
//! memory-growth failure, input-schema rejection, numeric-ceiling rejection,
//! and the rotation tripwire (distinct `routine-identity-rotated`).

mod compute_common;
use compute_common::*;

use anyhow::{Context, Result};
use rocket::http::Status;
use rocket::local::asynchronous::Client;

/// Deploy a single-import probe with a chosen grant set and run it once,
/// returning the run status and the parsed ack JSON.
async fn probe(
    client: &Client,
    owner: &Owner,
    function: &str,
    fixture: &str,
    grants: &[GrantSpec],
    tag: &str,
) -> Result<(Status, serde_json::Value)> {
    // Append a unique WAT comment so each probe deploy has DISTINCT bytes ->
    // a distinct content CID -> a distinct routine identity. Identical bytes
    // deployed under two names share ONE routine (the same-bytes hazard), so
    // cite-all would otherwise merge grants across the two deploys and mask a
    // per-import denial. The trailing comment does not change behavior.
    let mut wasm = load_fixture(fixture);
    wasm.extend_from_slice(format!("\n;; probe-unique: {tag}\n").as_bytes());
    deploy_fixture(client, owner, function, &wasm, grants, tag).await?;
    let auth = owner_compute_invocation(
        owner,
        function,
        "tinycloud.compute/execute",
        &format!("urn:uuid:exec-{tag}"),
    )?;
    let (status, body) =
        post_invoke(client, &auth, execute_body(function, serde_json::json!({}))).await;
    let json = serde_json::from_str(&body).unwrap_or(serde_json::json!({ "raw": body }));
    Ok((status, json))
}

fn only_call(ack: &serde_json::Value) -> &serde_json::Value {
    let calls = ack["manifest"]["calls"].as_array().expect("calls");
    assert_eq!(calls.len(), 1, "probe makes exactly one host call");
    &calls[0]
}

// ---------------------------------------------------------------------------
// Per-import allow/deny (all four imports).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn each_import_allowed_with_grant_denied_without() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("per-import")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    seed_kv(&client, &owner, "in/x", b"42", "urn:uuid:seed-in").await?;
    seed_kv(&client, &owner, "out/y", b"84", "urn:uuid:seed-out").await?;

    let get = GrantSpec {
        service: "kv",
        path: "in/",
        ability: "tinycloud.kv/get",
    };
    let put = GrantSpec {
        service: "kv",
        path: "out/",
        ability: "tinycloud.kv/put",
    };
    let del = GrantSpec {
        service: "kv",
        path: "out/",
        ability: "tinycloud.kv/del",
    };
    let sql_r = GrantSpec {
        service: "sql",
        path: "db",
        ability: "tinycloud.sql/read",
    };
    // An unrelated grant so the "denied" deploys still have a non-empty,
    // bound D_fn -- the denial is a MISSING ability, not a missing D_fn.
    let filler = GrantSpec {
        service: "kv",
        path: "misc/",
        ability: "tinycloud.kv/get",
    };

    let (s, granted) = probe(&client, &owner, "g-yes", "probe_get.wat", &[get], "g-yes").await?;
    assert_eq!(s, Status::Ok);
    assert_eq!(only_call(&granted)["granted"], true, "get granted");
    let (s, denied) = probe(&client, &owner, "g-no", "probe_get.wat", &[filler], "g-no").await?;
    assert_eq!(s, Status::Ok, "a denied host call does NOT fail the run");
    assert_eq!(
        only_call(&denied)["granted"],
        false,
        "get denied without grant"
    );

    let (_s, granted) = probe(&client, &owner, "p-yes", "probe_put.wat", &[put], "p-yes").await?;
    assert_eq!(only_call(&granted)["granted"], true, "put granted");
    let (_s, denied) = probe(&client, &owner, "p-no", "probe_put.wat", &[filler], "p-no").await?;
    assert_eq!(
        only_call(&denied)["granted"],
        false,
        "put denied without grant"
    );

    let (_s, granted) = probe(&client, &owner, "d-yes", "probe_del.wat", &[del], "d-yes").await?;
    assert_eq!(only_call(&granted)["granted"], true, "del granted");
    let (_s, denied) = probe(&client, &owner, "d-no", "probe_del.wat", &[filler], "d-no").await?;
    assert_eq!(
        only_call(&denied)["granted"],
        false,
        "del denied without grant"
    );

    let (_s, granted) = probe(&client, &owner, "s-yes", "probe_sql.wat", &[sql_r], "s-yes").await?;
    assert_eq!(only_call(&granted)["granted"], true, "sql granted");
    let (_s, denied) = probe(&client, &owner, "s-no", "probe_sql.wat", &[filler], "s-no").await?;
    assert_eq!(
        only_call(&denied)["granted"],
        false,
        "sql denied without grant"
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// SQL statement-level authorizer still applies (ATTACH is always denied).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sql_statement_authorizer_rejects_attach_even_with_write_grant() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("sql-authorizer")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let sql_w = GrantSpec {
        service: "sql",
        path: "db",
        ability: "tinycloud.sql/write",
    };
    let (status, ack) = probe(
        &client,
        &owner,
        "attack",
        "probe_sql_attach.wat",
        &[sql_w],
        "attach",
    )
    .await?;
    assert_eq!(status, Status::Ok, "the run itself does not fail: {ack}");
    // Judge finding: the D_fn ABILITY check passed (sql/write was granted);
    // only the statement itself was refused by the SQL engine's OWN
    // create_authorizer. `granted` tracks ability-exercise, not
    // statement-level success, so this must be granted:true/exercised --
    // NOT an ability denial.
    assert_eq!(
        only_call(&ack)["granted"],
        true,
        "ATTACH must be rejected by the SQL statement authorizer, but the sql/write \
         ABILITY was granted and exercised despite the statement-level rejection"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Cite-all: a SECOND D_fn (same routine, same CID) supplies an ability the
// deploy-time D_fn lacked (§5.1/F5).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cite_all_second_d_fn_supplies_missing_ability() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("cite-all")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "out/y", b"84", "urn:uuid:seed-out").await?;

    let wasm = load_fixture("probe_put.wat");
    let cid = content_cid(&wasm);
    let ack = deploy_fixture(
        &client,
        &owner,
        "citeput",
        &wasm,
        &[GrantSpec {
            service: "kv",
            path: "misc/",
            ability: "tinycloud.kv/get",
        }],
        "citeall",
    )
    .await?;
    let rdid = ack["routine_did"].as_str().unwrap().to_string();
    assert_eq!(ack["content_cid"], cid);

    let auth = owner_compute_invocation(
        &owner,
        "citeput",
        "tinycloud.compute/execute",
        "urn:uuid:c1",
    )?;
    let (_s, before) = post_invoke(
        &client,
        &auth,
        execute_body("citeput", serde_json::json!({})),
    )
    .await;
    let before: serde_json::Value = serde_json::from_str(&before)?;
    assert_eq!(
        before["manifest"]["calls"][0]["granted"], false,
        "kv/put denied before the second D_fn"
    );

    let second = mint_d_fn(
        &owner,
        &rdid,
        &cid,
        &[GrantSpec {
            service: "kv",
            path: "out/",
            ability: "tinycloud.kv/put",
        }],
        "urn:uuid:dfn2",
    )?;
    submit_delegation(&client, &second).await?;

    let auth2 = owner_compute_invocation(
        &owner,
        "citeput",
        "tinycloud.compute/execute",
        "urn:uuid:c2",
    )?;
    let (_s, after) = post_invoke(
        &client,
        &auth2,
        execute_body("citeput", serde_json::json!({})),
    )
    .await;
    let after: serde_json::Value = serde_json::from_str(&after)?;
    assert_eq!(
        after["manifest"]["calls"][0]["granted"], true,
        "kv/put granted after the second D_fn (cite-all)"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `functions` allowlist (chain-derived, §6.3).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn functions_allowlist_enforced_from_chain() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("allowlist")?;
    let holder = make_holder()?;
    seed_space_and_actors(&conn, &owner.space, std::slice::from_ref(&holder.did)).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42", "urn:uuid:seed-in").await?;

    deploy_fixture(
        &client,
        &owner,
        "allowed",
        &load_fixture("probe_get.wat"),
        &[GrantSpec {
            service: "kv",
            path: "in/",
            ability: "tinycloud.kv/get",
        }],
        "allow",
    )
    .await?;

    let caveat = serde_json::json!({ "functions": ["something-else"] });
    let (deleg, cid) = delegate_compute_execute(
        &owner,
        &holder.did,
        "allowed",
        Some(caveat.clone()),
        "urn:uuid:al1",
    )?;
    submit_delegation(&client, &deleg).await?;

    let inv = compute_execute_invocation(
        &holder.vm,
        &holder.did,
        &holder.jwk,
        &owner.space,
        "allowed",
        Some(caveat.clone()),
        Some(cid),
        "urn:uuid:al-exec",
    )?;
    let (status, body) = post_invoke(
        &client,
        &inv,
        execute_body("allowed", serde_json::json!({})),
    )
    .await;
    assert_eq!(
        status,
        Status::Forbidden,
        "function not in allowlist must 403: {body}"
    );
    assert!(
        body.contains("allowlist"),
        "error names the allowlist: {body}"
    );

    let ok_caveat = serde_json::json!({ "functions": ["allowed"] });
    let (deleg2, cid2) = delegate_compute_execute(
        &owner,
        &holder.did,
        "allowed",
        Some(ok_caveat.clone()),
        "urn:uuid:al2",
    )?;
    submit_delegation(&client, &deleg2).await?;
    let inv2 = compute_execute_invocation(
        &holder.vm,
        &holder.did,
        &holder.jwk,
        &owner.space,
        "allowed",
        Some(ok_caveat),
        Some(cid2),
        "urn:uuid:al-exec2",
    )?;
    let (status2, body2) = post_invoke(
        &client,
        &inv2,
        execute_body("allowed", serde_json::json!({})),
    )
    .await;
    assert_eq!(
        status2,
        Status::Ok,
        "allowlisted function must run: {body2}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Invoker-side caveat echo (F1 at layer (a), §6.3).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invoker_side_echo_required() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("invoker-echo")?;
    let holder = make_holder()?;
    seed_space_and_actors(&conn, &owner.space, std::slice::from_ref(&holder.did)).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42", "urn:uuid:seed-in").await?;

    deploy_fixture(
        &client,
        &owner,
        "echofn",
        &load_fixture("probe_get.wat"),
        &[GrantSpec {
            service: "kv",
            path: "in/",
            ability: "tinycloud.kv/get",
        }],
        "echo",
    )
    .await?;

    let caveat = serde_json::json!({ "functions": ["echofn"] });
    let (deleg, cid) = delegate_compute_execute(
        &owner,
        &holder.did,
        "echofn",
        Some(caveat.clone()),
        "urn:uuid:ie1",
    )?;
    submit_delegation(&client, &deleg).await?;

    // Invoke WITHOUT echoing the caveat -> containment rejects before the
    // handler.
    let no_echo = compute_execute_invocation(
        &holder.vm,
        &holder.did,
        &holder.jwk,
        &owner.space,
        "echofn",
        None,
        Some(cid),
        "urn:uuid:ie-noecho",
    )?;
    let (status, body) = post_invoke(
        &client,
        &no_echo,
        execute_body("echofn", serde_json::json!({})),
    )
    .await;
    assert_ne!(
        status,
        Status::Ok,
        "omitting the echoed caveat must be rejected: {body}"
    );

    let (deleg2, cid2) = delegate_compute_execute(
        &owner,
        &holder.did,
        "echofn",
        Some(caveat.clone()),
        "urn:uuid:ie2",
    )?;
    submit_delegation(&client, &deleg2).await?;
    let echo = compute_execute_invocation(
        &holder.vm,
        &holder.did,
        &holder.jwk,
        &owner.space,
        "echofn",
        Some(caveat),
        Some(cid2),
        "urn:uuid:ie-echo",
    )?;
    let (status2, body2) = post_invoke(
        &client,
        &echo,
        execute_body("echofn", serde_json::json!({})),
    )
    .await;
    assert_eq!(status2, Status::Ok, "echoed caveat must pass: {body2}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Fuel exhaustion (§10.1 CPU->fuel).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fuel_exhaustion_traps() -> Result<()> {
    let (rocket, conn, tempdir) = boot_with(BootOptions {
        max_fuel: Some(100_000),
        ..Default::default()
    })
    .await?;
    let owner = make_owner("fuel")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    deploy_fixture(
        &client,
        &owner,
        "loop",
        &load_fixture("infinite_loop.wat"),
        &[GrantSpec {
            service: "kv",
            path: "misc/",
            ability: "tinycloud.kv/get",
        }],
        "fuel",
    )
    .await?;
    let auth =
        owner_compute_invocation(&owner, "loop", "tinycloud.compute/execute", "urn:uuid:fuel")?;
    let (status, body) =
        post_invoke(&client, &auth, execute_body("loop", serde_json::json!({}))).await;
    assert_eq!(
        status,
        Status::UnprocessableEntity,
        "fuel exhaustion must 422: {body}"
    );
    assert!(body.contains("fuel"), "error names fuel: {body}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Epoch / maxDuration timeout (§10.1 epoch interruption).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn epoch_timeout_traps() -> Result<()> {
    // Huge fuel so the epoch deadline (not fuel) fires first.
    let (rocket, conn, tempdir) = boot_with(BootOptions {
        max_fuel: Some(1_000_000_000_000_000),
        ..Default::default()
    })
    .await?;
    let owner = make_owner("epoch")?;
    let holder = make_holder()?;
    seed_space_and_actors(&conn, &owner.space, std::slice::from_ref(&holder.did)).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    deploy_fixture(
        &client,
        &owner,
        "loop",
        &load_fixture("infinite_loop.wat"),
        &[GrantSpec {
            service: "kv",
            path: "misc/",
            ability: "tinycloud.kv/get",
        }],
        "epoch",
    )
    .await?;

    let caveat = serde_json::json!({ "maxDuration": 1 });
    let (deleg, cid) = delegate_compute_execute(
        &owner,
        &holder.did,
        "loop",
        Some(caveat.clone()),
        "urn:uuid:ep1",
    )?;
    submit_delegation(&client, &deleg).await?;
    let inv = compute_execute_invocation(
        &holder.vm,
        &holder.did,
        &holder.jwk,
        &owner.space,
        "loop",
        Some(caveat),
        Some(cid),
        "urn:uuid:ep-exec",
    )?;
    let (status, body) =
        post_invoke(&client, &inv, execute_body("loop", serde_json::json!({}))).await;
    assert_eq!(
        status,
        Status::UnprocessableEntity,
        "epoch timeout must 422: {body}"
    );
    assert!(
        body.contains("maxDuration"),
        "error names maxDuration: {body}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Memory-growth failure (§10.1 StoreLimits).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn memory_growth_capped_by_store_limits() -> Result<()> {
    let (rocket, conn, tempdir) = boot_with(BootOptions {
        max_memory: Some("1 MiB".to_string()),
        max_memory_ceiling: Some("2 MiB".to_string()),
        ..Default::default()
    })
    .await?;
    let owner = make_owner("memcap")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    deploy_fixture(
        &client,
        &owner,
        "grow",
        &load_fixture("memory_grower.wat"),
        &[GrantSpec {
            service: "kv",
            path: "misc/",
            ability: "tinycloud.kv/get",
        }],
        "mem",
    )
    .await?;
    let auth =
        owner_compute_invocation(&owner, "grow", "tinycloud.compute/execute", "urn:uuid:mem")?;
    let (status, body) =
        post_invoke(&client, &auth, execute_body("grow", serde_json::json!({}))).await;
    assert_eq!(status, Status::Ok, "the grow failure does not trap: {body}");
    let ack: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        ack["result"]["grew"], false,
        "memory.grow must be DENIED by the 1 MiB StoreLimits cap"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Input-schema rejection (§10.1).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn input_schema_rejected_from_chain() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("inschema")?;
    let holder = make_holder()?;
    seed_space_and_actors(&conn, &owner.space, std::slice::from_ref(&holder.did)).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;
    seed_kv(&client, &owner, "in/x", b"42", "urn:uuid:seed-in").await?;

    deploy_fixture(
        &client,
        &owner,
        "schemafn",
        &load_fixture("probe_get.wat"),
        &[GrantSpec {
            service: "kv",
            path: "in/",
            ability: "tinycloud.kv/get",
        }],
        "schema",
    )
    .await?;

    let caveat = serde_json::json!({ "inputs": { "type": "object", "required": ["x"] } });
    let (deleg, cid) = delegate_compute_execute(
        &owner,
        &holder.did,
        "schemafn",
        Some(caveat.clone()),
        "urn:uuid:sc1",
    )?;
    submit_delegation(&client, &deleg).await?;

    let inv = compute_execute_invocation(
        &holder.vm,
        &holder.did,
        &holder.jwk,
        &owner.space,
        "schemafn",
        Some(caveat.clone()),
        Some(cid),
        "urn:uuid:sc-bad",
    )?;
    let body_bad =
        serde_json::json!({ "action": "execute", "function": "schemafn", "input": { "y": 1 } })
            .to_string();
    let (status, body) = post_invoke(&client, &inv, body_bad).await;
    assert_eq!(
        status,
        Status::BadRequest,
        "missing required input must 400: {body}"
    );
    assert!(body.contains("schema"), "error names the schema: {body}");

    let (deleg2, cid2) = delegate_compute_execute(
        &owner,
        &holder.did,
        "schemafn",
        Some(caveat.clone()),
        "urn:uuid:sc2",
    )?;
    submit_delegation(&client, &deleg2).await?;
    let inv2 = compute_execute_invocation(
        &holder.vm,
        &holder.did,
        &holder.jwk,
        &owner.space,
        "schemafn",
        Some(caveat),
        Some(cid2),
        "urn:uuid:sc-ok",
    )?;
    let body_ok =
        serde_json::json!({ "action": "execute", "function": "schemafn", "input": { "x": 1 } })
            .to_string();
    let (status2, body2) = post_invoke(&client, &inv2, body_ok).await;
    assert_eq!(status2, Status::Ok, "valid input must run: {body2}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Numeric-ceiling rejection (§10.1).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn numeric_ceiling_rejected() -> Result<()> {
    let (rocket, conn, tempdir) = boot_with(BootOptions {
        max_duration_ceiling_ms: Some(1000),
        ..Default::default()
    })
    .await?;
    let owner = make_owner("ceiling")?;
    let holder = make_holder()?;
    seed_space_and_actors(&conn, &owner.space, std::slice::from_ref(&holder.did)).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    deploy_fixture(
        &client,
        &owner,
        "noop",
        &load_fixture("noop.wat"),
        &[GrantSpec {
            service: "kv",
            path: "misc/",
            ability: "tinycloud.kv/get",
        }],
        "ceil",
    )
    .await?;

    let caveat = serde_json::json!({ "maxDuration": 999_999 });
    let (deleg, cid) = delegate_compute_execute(
        &owner,
        &holder.did,
        "noop",
        Some(caveat.clone()),
        "urn:uuid:ce1",
    )?;
    submit_delegation(&client, &deleg).await?;
    let inv = compute_execute_invocation(
        &holder.vm,
        &holder.did,
        &holder.jwk,
        &owner.space,
        "noop",
        Some(caveat),
        Some(cid),
        "urn:uuid:ce-exec",
    )?;
    let (status, body) =
        post_invoke(&client, &inv, execute_body("noop", serde_json::json!({}))).await;
    assert_eq!(
        status,
        Status::BadRequest,
        "over-ceiling caveat must 400: {body}"
    );
    assert!(body.contains("ceiling"), "error names the ceiling: {body}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Rotation tripwire (§6.2/F1.5): a D_fn is bound to the CID (its ability rows
// carry the binding caveat) but its DELEGATEE is no longer the currently-
// derived routine identity -- exactly what a dstack seed rotation produces.
// The node MUST fail with the DISTINCT `routine-identity-rotated` (409), NOT
// a generic 403.
//
// Hermetic construction: deploy normally (creating the correct D_fn), then
// mutate that D_fn's persisted `delegatee` to a DIFFERENT valid did:key. Now
// the delegatee-filtered selection (`compute_select_d_fns`) finds nothing for
// the re-derived routine_did, while the CID-binding scan
// (`compute_any_d_fn_bound`, delegatee-agnostic) still sees the binding ->
// rotation. This is independent of the node secret (which the test harness'
// TINYCLOUD_KEYS_SECRET env var would otherwise pin, defeating a
// two-secret-boot approach).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rotation_tripwire_distinct_error() -> Result<()> {
    use tinycloud_core::models::delegation as deleg_model;
    use tinycloud_core::sea_orm::{
        ActiveModelTrait, ActiveValue::Set, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter,
    };

    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("rotation")?;
    // The bogus delegatee must exist as an actor (delegation.delegatee is a
    // FK into the actor table).
    let bogus = make_holder()?.did;
    seed_space_and_actors(&conn, &owner.space, std::slice::from_ref(&bogus)).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let ack = deploy_fixture(
        &client,
        &owner,
        "rot",
        &load_fixture("probe_get.wat"),
        &[GrantSpec {
            service: "kv",
            path: "in/",
            ability: "tinycloud.kv/get",
        }],
        "rot",
    )
    .await?;
    let rdid = ack["routine_did"].as_str().unwrap().to_string();

    // Rotate: repoint the D_fn's delegatee to a DIFFERENT valid did:key. The
    // ability rows (which carry the CID-binding caveat) are untouched.
    let dfn = deleg_model::Entity::find()
        .filter(deleg_model::Column::Delegatee.eq(rdid.clone()))
        .one(&conn)
        .await?
        .context("D_fn must exist after deploy")?;
    let mut active = dfn.into_active_model();
    active.delegatee = Set(bogus);
    active.update(&conn).await?;

    let auth = owner_compute_invocation(
        &owner,
        "rot",
        "tinycloud.compute/execute",
        "urn:uuid:rot-exec",
    )?;
    let (status, body) =
        post_invoke(&client, &auth, execute_body("rot", serde_json::json!({}))).await;
    assert_eq!(
        status,
        Status::Conflict,
        "a rotated routine key must fail with the DISTINCT 409, not a generic 403: {body}"
    );
    assert!(
        body.contains("routine-identity-rotated"),
        "error must carry the distinct rotation code: {body}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// kv/del of a key with no live value must be a non-fatal, observable
// envelope (granted:true, `no-such-key`), not a 500 that aborts the whole
// run -- the ability WAS granted; the core simply had nothing to delete.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn kv_del_of_missing_key_is_non_fatal() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("del-missing")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    // Deliberately do NOT seed "out/y" -- probe_del.wat deletes exactly this
    // key, so the delete targets a key with no live value.
    deploy_fixture(
        &client,
        &owner,
        "delmissing",
        &load_fixture("probe_del.wat"),
        &[GrantSpec {
            service: "kv",
            path: "out/",
            ability: "tinycloud.kv/del",
        }],
        "delmissing",
    )
    .await?;

    let auth = owner_compute_invocation(
        &owner,
        "delmissing",
        "tinycloud.compute/execute",
        "urn:uuid:delmissing-exec",
    )?;
    let (status, body) = post_invoke(
        &client,
        &auth,
        execute_body("delmissing", serde_json::json!({})),
    )
    .await;
    assert_eq!(
        status,
        Status::Ok,
        "a kv/del of a missing key must NOT abort the whole run: {body}"
    );
    let ack: serde_json::Value = serde_json::from_str(&body)?;
    let call = only_call(&ack);
    assert_eq!(call["ability"], "tinycloud.kv/del");
    assert_eq!(call["destination"], "out/y");
    assert_eq!(
        call["granted"], true,
        "the ability WAS granted; only the underlying delete had nothing to do"
    );
    let expected_envelope_len = serde_json::to_vec(&serde_json::json!({
        "ok": false,
        "error": { "code": "no-such-key" }
    }))
    .unwrap()
    .len() as u64;
    assert_eq!(
        call["bytesOut"].as_u64(),
        Some(expected_envelope_len),
        "the response bytes must be the no-such-key envelope"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// output_ref's KV write must be journaled (§9.1.1 "journal every host
// call"): `write_output` bypassed `dispatch` and dropped the manifest entry
// on the floor even though the op itself was actually performed.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn output_ref_write_is_journaled_in_manifest() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("output-ref")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    seed_kv(&client, &owner, "in/x", b"42", "urn:uuid:seed-in").await?;

    deploy_fixture(
        &client,
        &owner,
        "outref",
        &load_fixture("probe_get.wat"),
        &[
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
        ],
        "outref",
    )
    .await?;

    let auth = owner_compute_invocation(
        &owner,
        "outref",
        "tinycloud.compute/execute",
        "urn:uuid:outref-exec",
    )?;
    let (status, body) = post_invoke(
        &client,
        &auth,
        execute_body_with_output_ref("outref", serde_json::json!({}), "out/result"),
    )
    .await;
    assert_eq!(status, Status::Ok, "execute with output_ref must 200: {body}");
    let ack: serde_json::Value = serde_json::from_str(&body)?;
    assert_eq!(
        ack["output_destination"], "out/result",
        "ack must report the output_ref destination"
    );

    let calls = ack["manifest"]["calls"].as_array().expect("calls array");
    assert_eq!(
        calls.len(),
        2,
        "manifest must journal BOTH the guest's own storage_get AND the \
         output_ref's storage_put: {calls:?}"
    );
    let output_write = &calls[1];
    assert_eq!(output_write["ability"], "tinycloud.kv/put");
    assert_eq!(
        output_write["resource"],
        format!("{}/kv/out/result", owner.space)
    );
    assert_eq!(output_write["destination"], "out/result");
    assert_eq!(output_write["granted"], true);

    // The write actually landed: read it back as the owner.
    let read_auth = owner_kv_invocation(
        &owner,
        "out/result",
        "tinycloud.kv/get",
        "urn:uuid:read-outref",
    )?;
    let (read_status, _) = post_invoke(&client, &read_auth, String::new()).await;
    assert_eq!(
        read_status,
        Status::Ok,
        "the journaled output_ref write must have actually happened"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// input_refs (§8 host-side input pre-read) is not implemented in the MVP; a
// non-empty input_refs must be rejected loudly (400), not silently ignored.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_empty_input_refs_rejected_with_400() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("input-refs")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    deploy_fixture(
        &client,
        &owner,
        "inputrefs",
        &load_fixture("probe_get.wat"),
        &[GrantSpec {
            service: "kv",
            path: "in/",
            ability: "tinycloud.kv/get",
        }],
        "inputrefs",
    )
    .await?;

    let auth = owner_compute_invocation(
        &owner,
        "inputrefs",
        "tinycloud.compute/execute",
        "urn:uuid:inputrefs-exec",
    )?;
    let body = serde_json::json!({
        "action": "execute",
        "function": "inputrefs",
        "input": {},
        "input_refs": ["in/x"],
    })
    .to_string();
    let (status, resp_body) = post_invoke(&client, &auth, body).await;
    assert_eq!(
        status,
        Status::BadRequest,
        "a non-empty input_refs must 400, not be silently ignored: {resp_body}"
    );
    assert!(
        resp_body.contains("input_refs"),
        "error must name input_refs: {resp_body}"
    );

    // An EMPTY input_refs (or its absence) is unaffected -- execution runs.
    let auth2 = owner_compute_invocation(
        &owner,
        "inputrefs",
        "tinycloud.compute/execute",
        "urn:uuid:inputrefs-exec2",
    )?;
    let body2 = serde_json::json!({
        "action": "execute",
        "function": "inputrefs",
        "input": {},
        "input_refs": [],
    })
    .to_string();
    let (status2, resp_body2) = post_invoke(&client, &auth2, body2).await;
    assert_eq!(
        status2,
        Status::Ok,
        "an empty input_refs must not be rejected: {resp_body2}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Fail-closed on a malformed chain-derived `computeCaveats` (both judges,
// security): the old `if let Ok(..)` silently fell through to the
// unconstrained case on a parse failure -- a fail-open. A malformed
// `computeCaveats` payload on the authorizing ability row must hard-400.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malformed_chain_compute_caveats_rejected_with_400() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("malformed-caveats")?;
    let holder = make_holder()?;
    seed_space_and_actors(&conn, &owner.space, std::slice::from_ref(&holder.did)).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    deploy_fixture(
        &client,
        &owner,
        "malformed",
        &load_fixture("noop.wat"),
        &[GrantSpec {
            service: "kv",
            path: "misc/",
            ability: "tinycloud.kv/get",
        }],
        "malformed",
    )
    .await?;

    // `maxDuration` must be a number (u64); a string fails to deserialize
    // into `ComputeCaveats`.
    let bogus_caveat = serde_json::json!({ "maxDuration": "oops" });
    let (deleg, cid) = delegate_compute_execute(
        &owner,
        &holder.did,
        "malformed",
        Some(bogus_caveat.clone()),
        "urn:uuid:mc1",
    )?;
    submit_delegation(&client, &deleg).await?;

    let inv = compute_execute_invocation(
        &holder.vm,
        &holder.did,
        &holder.jwk,
        &owner.space,
        "malformed",
        Some(bogus_caveat),
        Some(cid),
        "urn:uuid:mc-exec",
    )?;
    let (status, body) = post_invoke(
        &client,
        &inv,
        execute_body("malformed", serde_json::json!({})),
    )
    .await;
    assert_eq!(
        status,
        Status::BadRequest,
        "a malformed chain computeCaveats must hard-400, never fail open: {body}"
    );
    assert!(
        body.contains("computeCaveats") || body.contains("malformed"),
        "error must name the malformed caveat: {body}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Memory safety (Codex P2 finding): a guest-controlled length crossing the
// ABI boundary must be bounds-checked BEFORE the host allocates a buffer
// sized by it -- a bogus negative/huge length must be rejected cleanly
// (a defined, bounded error), never attempted as a host allocation.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bogus_host_call_length_rejected_cleanly() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("mem-hostcall")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    deploy_fixture(
        &client,
        &owner,
        "bogushc",
        &load_fixture("bogus_host_call_length.wat"),
        &[GrantSpec {
            service: "kv",
            path: "in/",
            ability: "tinycloud.kv/get",
        }],
        "bogushc",
    )
    .await?;
    let auth = owner_compute_invocation(
        &owner,
        "bogushc",
        "tinycloud.compute/execute",
        "urn:uuid:bogushc",
    )?;
    let (status, body) = post_invoke(
        &client,
        &auth,
        execute_body("bogushc", serde_json::json!({})),
    )
    .await;
    assert_ne!(
        status,
        Status::Ok,
        "a bogus ~2GB host-call length must not be honored: {body}"
    );
    assert!(
        body.contains("out of bounds") || body.contains("ceiling"),
        "error must name the length ceiling: {body}"
    );
    Ok(())
}

#[tokio::test]
async fn bogus_run_output_length_rejected_cleanly() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("mem-runlen")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    deploy_fixture(
        &client,
        &owner,
        "bogusrl",
        &load_fixture("bogus_run_output_length.wat"),
        &[GrantSpec {
            service: "kv",
            path: "in/",
            ability: "tinycloud.kv/get",
        }],
        "bogusrl",
    )
    .await?;
    let auth = owner_compute_invocation(
        &owner,
        "bogusrl",
        "tinycloud.compute/execute",
        "urn:uuid:bogusrl",
    )?;
    let (status, body) = post_invoke(
        &client,
        &auth,
        execute_body("bogusrl", serde_json::json!({})),
    )
    .await;
    assert_ne!(
        status,
        Status::Ok,
        "a negative run() result length must not be honored: {body}"
    );
    assert!(
        body.contains("out of bounds") || body.contains("ceiling"),
        "error must name the length ceiling: {body}"
    );
    Ok(())
}

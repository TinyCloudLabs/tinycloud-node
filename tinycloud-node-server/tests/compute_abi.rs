//! P2 Appendix A conformance fixture, end-to-end
//! (`cargo test -p tinycloud-node --test compute_abi --features compute`).
//!
//! Runs the pinned `compute_fixture.wat` through the REAL deploy + execute
//! path and asserts the Appendix A contract EXACTLY: the A.3 five-step
//! scenario result, the A.4 denial (op-not-performed + manifest
//! `granted:false`), and the A.5 manifest byte-for-byte (5 entries + the
//! granted-but-unexercised set = {sql/write}). Plus the forbidden-import
//! link-error fixture (a distinct, separately-tested case per A.4's note).
//!
//! Determinism (A.6): the scenario is re-run and asserted byte-identical.

mod compute_common;
use compute_common::*;

use anyhow::Result;
use rocket::http::Status;
use rocket::local::asynchronous::Client;

/// Canonical-JSON byte lengths of the A.3 request payloads (deterministic).
const REQ_LEN_GET: u64 = 14; // {"key":"in/x"}
const REQ_LEN_PUT: u64 = 28; // {"key":"out/y","value":"84"}
const REQ_LEN_SQL: u64 = 52; // {"action":"query","sql":"SELECT 1 AS n","params":[]}
const REQ_LEN_DEL: u64 = 15; // {"key":"out/y"}
const REQ_LEN_SECRET: u64 = 30; // {"key":"secret/z","value":"x"}

/// Canonical-JSON byte lengths of the A.3 response payloads.
const RESP_LEN_GET: u64 = 24; // {"ok":true,"value":"42"}
const RESP_LEN_PUT: u64 = 11; // {"ok":true}
const RESP_LEN_SQL: u64 = 43; // {"columns":["n"],"rows":[[1]],"rowCount":1}
const RESP_LEN_DEL: u64 = 11; // {"ok":true}

async fn deploy_and_seed(client: &Client, owner: &Owner) -> Result<()> {
    // A.2 preconditions: seed in/x = "42" (a normal KV put by the owner).
    seed_kv(client, owner, "in/x", b"42", "urn:uuid:seed-inx").await?;
    // Deploy the fixture with the A.1 grant.
    let wasm = load_fixture("compute_fixture.wat");
    deploy_fixture(client, owner, "fixture", &wasm, &fixture_grants(), "abi").await?;
    Ok(())
}

async fn run_execute(client: &Client, owner: &Owner, nonce: &str) -> (Status, String) {
    let auth = owner_compute_invocation(owner, "fixture", "tinycloud.compute/execute", nonce)
        .expect("sign execute");
    post_invoke(client, &auth, execute_body("fixture", serde_json::json!({}))).await
}

#[tokio::test]
async fn appendix_a_conformance_fixture_end_to_end() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("abi-conformance")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_space_storage(&_tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    deploy_and_seed(&client, &owner).await?;

    let (status, body) = run_execute(&client, &owner, "urn:uuid:exec-abi-1").await;
    assert_eq!(status, Status::Ok, "execute must 200: {body}");
    let ack: serde_json::Value = serde_json::from_str(&body)?;

    // --- A.3: the run result exactly. ---
    let expected_result = serde_json::json!({
        "got": "42",
        "put": true,
        "sql_n": 1,
        "deleted": true,
        "denied": "tinycloud.kv/put"
    });
    assert_eq!(
        ack["result"], expected_result,
        "run result must equal A.3's exactly"
    );

    // --- A.5: the manifest, byte-for-byte. ---
    let manifest = &ack["manifest"];
    let calls = manifest["calls"].as_array().expect("calls array");
    assert_eq!(calls.len(), 5, "manifest must have 5 host-call entries");

    let space_prefix = owner.space.to_string();

    // Entry 1: kv/get in/x -> inline, granted.
    assert_call(
        &calls[0],
        "tinycloud.kv/get",
        &format!("{space_prefix}/kv/in/x"),
        REQ_LEN_GET,
        RESP_LEN_GET,
        "inline",
        true,
    );
    // Entry 2: kv/put out/y -> destination out/y, granted.
    assert_call(
        &calls[1],
        "tinycloud.kv/put",
        &format!("{space_prefix}/kv/out/y"),
        REQ_LEN_PUT,
        RESP_LEN_PUT,
        "out/y",
        true,
    );
    // Entry 3: sql/read db -> inline, granted.
    assert_call(
        &calls[2],
        "tinycloud.sql/read",
        &format!("{space_prefix}/sql/db"),
        REQ_LEN_SQL,
        RESP_LEN_SQL,
        "inline",
        true,
    );
    // Entry 4: kv/del out/y -> destination out/y, granted.
    assert_call(
        &calls[3],
        "tinycloud.kv/del",
        &format!("{space_prefix}/kv/out/y"),
        REQ_LEN_DEL,
        RESP_LEN_DEL,
        "out/y",
        true,
    );
    // Entry 5: kv/put secret/z -> DENIED (granted:false), op NOT performed.
    let secret_resource = format!("{space_prefix}/kv/secret/z");
    let expected_denial_len = serde_json::to_vec(&serde_json::json!({
        "ok": false,
        "error": {
            "code": "ability-denied",
            "ability": "tinycloud.kv/put",
            "resource": secret_resource
        }
    }))
    .unwrap()
    .len() as u64;
    assert_call(
        &calls[4],
        "tinycloud.kv/put",
        &secret_resource,
        REQ_LEN_SECRET,
        expected_denial_len,
        "",
        false,
    );

    // Capability sets (A.5).
    let granted = str_set(&manifest["granted"]);
    let exercised = str_set(&manifest["exercised"]);
    assert_eq!(
        granted,
        set(&[
            "tinycloud.kv/del",
            "tinycloud.kv/get",
            "tinycloud.kv/put",
            "tinycloud.sql/read",
            "tinycloud.sql/write",
        ]),
        "granted set must be the full A.1 grant"
    );
    assert_eq!(
        exercised,
        set(&[
            "tinycloud.kv/del",
            "tinycloud.kv/get",
            "tinycloud.kv/put",
            "tinycloud.sql/read",
        ]),
        "exercised set must exclude the never-called sql/write"
    );
    let unexercised = str_vec(&ack["grantedButUnexercised"]);
    assert_eq!(
        unexercised,
        vec!["tinycloud.sql/write".to_string()],
        "granted-but-unexercised must be exactly {{sql/write}} (the scope-down signal)"
    );

    // --- A.4: the denial did NOT perform the op. out/y was written (step 2)
    // then deleted (step 4); secret/z must NEVER exist. Read it back as the
    // owner and assert absent. ---
    let read_auth =
        owner_kv_invocation(&owner, "secret/z", "tinycloud.kv/get", "urn:uuid:read-secret")?;
    let (read_status, _read_body) = post_invoke(&client, &read_auth, String::new()).await;
    assert_eq!(
        read_status,
        Status::NotFound,
        "the denied kv/put must NOT have created secret/z"
    );

    // --- A.6 determinism: a second run is byte-identical (result + manifest).
    let (status2, body2) = run_execute(&client, &owner, "urn:uuid:exec-abi-2").await;
    assert_eq!(status2, Status::Ok, "second execute must 200: {body2}");
    let ack2: serde_json::Value = serde_json::from_str(&body2)?;
    assert_eq!(ack2["result"], ack["result"], "result must be deterministic");
    assert_eq!(
        ack2["manifest"], ack["manifest"],
        "manifest must be byte-identical across runs (fuel-metered, no wall-clock field)"
    );

    Ok(())
}

/// The forbidden-import fixture (§10.1, A.4 note): a module importing outside
/// the four-function "tinycloud" surface fails at INSTANTIATION (a link
/// error) -- distinct from the A.4 ability-denial envelope. Deploy succeeds
/// (deploy does not validate the module), execute fails with the link error.
#[tokio::test]
async fn forbidden_import_fails_at_instantiation() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("abi-forbidden")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    let client = Client::tracked(rocket).await?;

    let wasm = load_fixture("forbidden_import.wat");
    // A minimal grant (kv/get) so the failure is unambiguously the link
    // error, not a missing-grant path.
    let grants = vec![GrantSpec {
        service: "kv",
        path: "in/",
        ability: "tinycloud.kv/get",
    }];
    deploy_fixture(&client, &owner, "forbidden", &wasm, &grants, "forbidden").await?;

    let auth = owner_compute_invocation(
        &owner,
        "forbidden",
        "tinycloud.compute/execute",
        "urn:uuid:exec-forbidden",
    )?;
    let (status, body) = post_invoke(&client, &auth, execute_body("forbidden", serde_json::json!({})))
        .await;
    assert_ne!(status, Status::Ok, "a forbidden import must not execute");
    assert!(
        body.contains("outside the tinycloud host surface") || body.contains("import"),
        "the error must name the forbidden-import link failure: {body}"
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn assert_call(
    entry: &serde_json::Value,
    ability: &str,
    resource: &str,
    bytes_in: u64,
    bytes_out: u64,
    destination: &str,
    granted: bool,
) {
    assert_eq!(entry["ability"], ability, "call ability");
    assert_eq!(entry["resource"], resource, "call resource");
    assert_eq!(
        entry["bytesIn"].as_u64(),
        Some(bytes_in),
        "call bytesIn for {ability}"
    );
    assert_eq!(
        entry["bytesOut"].as_u64(),
        Some(bytes_out),
        "call bytesOut for {ability}"
    );
    assert_eq!(entry["destination"], destination, "call destination");
    assert_eq!(entry["granted"], granted, "call granted flag");
}

fn str_set(v: &serde_json::Value) -> std::collections::BTreeSet<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn str_vec(v: &serde_json::Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn set(items: &[&str]) -> std::collections::BTreeSet<String> {
    items.iter().map(|s| s.to_string()).collect()
}

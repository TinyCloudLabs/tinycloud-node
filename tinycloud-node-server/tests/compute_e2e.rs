//! P2 full-HTTP E2E acceptance gate
//! (`cargo test -p tinycloud-node --test compute_e2e --features compute`).
//!
//! The whole least-privilege story end-to-end through the real Rocket stack:
//! deploy the Appendix A fixture via the REAL deploy path (A.1 grant), an
//! INVOKER holding ONLY `compute/execute` (zero data caps) runs it, and we
//! assert the result, the manifest's exercised imports, a denial, AND that
//! the invoker genuinely holds no data capabilities of its own.
//!
//! (Uses Rocket's in-process `Client`, which dispatches through the full
//! routing/guard/responder stack -- the same code an ephemeral-port bind
//! would exercise, minus the socket. The true cross-repo ephemeral-port
//! bind + SDK drive is the P3-SDK stage.)

mod compute_common;
use compute_common::*;

use anyhow::Result;
use rocket::http::Status;
use rocket::local::asynchronous::Client;

#[tokio::test]
async fn least_privilege_invoker_executes_over_data_it_cannot_touch() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("e2e")?;
    let invoker = make_holder()?;
    seed_space_and_actors(&conn, &owner.space, &[invoker.did.clone()]).await?;
    ensure_space_storage(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    // PART 1 — the space owner seeds inputs and deploys the routine with its
    // OWN attenuated data grant (A.1).
    seed_kv(&client, &owner, "in/x", b"42", "urn:uuid:e2e-seed").await?;
    let deploy_ack = {
        let wasm = load_fixture("compute_fixture.wat");
        deploy_fixture(&client, &owner, "report", &wasm, &fixture_grants(), "e2e").await?
    };
    assert_eq!(deploy_ack["function"], "report");

    // PART 2 — the owner delegates ONLY compute/execute to the invoker. NO
    // kv/sql caps travel to the invoker; the routine carries its own grant.
    let (deleg, cid) =
        delegate_compute_execute(&owner, &invoker.did, "report", None, "urn:uuid:e2e-deleg")?;
    submit_delegation(&client, &deleg).await?;

    // PART 3 — BEFORE running: prove the invoker holds ZERO data caps. A
    // direct kv/get on the routine's input path must fail (the invoker has
    // no kv delegation of its own -> unauthorized).
    let direct = sign_invocation(
        &invoker.vm,
        &invoker.did,
        &invoker.jwk,
        owner.space.clone().to_resource(
            "kv".parse().unwrap(),
            Some("in/x".parse().unwrap()),
            None,
            None,
        ),
        "tinycloud.kv/get",
        Vec::new(),
        None,
        "urn:uuid:e2e-directkv",
    )?;
    let (direct_status, _direct_body) = post_invoke(&client, &direct, String::new()).await;
    assert_ne!(
        direct_status,
        Status::Ok,
        "the invoker must NOT be able to read space data directly"
    );

    // PART 4 — the invoker executes the routine (citing only its
    // compute/execute delegation). The routine reads/writes/queries the
    // owner's data under ITS OWN grant.
    let inv = compute_execute_invocation(
        &invoker.vm,
        &invoker.did,
        &invoker.jwk,
        &owner.space,
        "report",
        None,
        Some(cid),
        "urn:uuid:e2e-exec",
    )?;
    let (status, body) =
        post_invoke(&client, &inv, execute_body("report", serde_json::json!({}))).await;
    assert_eq!(status, Status::Ok, "least-privilege execute must succeed: {body}");
    let ack: serde_json::Value = serde_json::from_str(&body)?;

    // Result matches the A.3 scenario.
    assert_eq!(
        ack["result"],
        serde_json::json!({
            "got": "42", "put": true, "sql_n": 1, "deleted": true, "denied": "tinycloud.kv/put"
        }),
        "the routine's result must equal A.3"
    );

    // Manifest shows the four exercised imports + a denial.
    let calls = ack["manifest"]["calls"].as_array().unwrap();
    assert_eq!(calls.len(), 5, "five host calls journaled");
    let exercised: std::collections::BTreeSet<String> = ack["manifest"]["exercised"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    for ability in [
        "tinycloud.kv/get",
        "tinycloud.kv/put",
        "tinycloud.kv/del",
        "tinycloud.sql/read",
    ] {
        assert!(exercised.contains(ability), "manifest must show {ability} exercised");
    }
    // The denial: the fifth call (kv/put on secret/) is NOT granted.
    assert_eq!(
        calls[4]["granted"], false,
        "the ungranted kv/put must be denied (fail-closed on the data)"
    );
    // The scope-down signal.
    assert_eq!(
        ack["grantedButUnexercised"],
        serde_json::json!(["tinycloud.sql/write"]),
        "granted-but-unexercised must be exactly {{sql/write}}"
    );

    // PART 5 — AFTER running: the invoker STILL holds zero data caps (running
    // a routine does not leak the routine's authority to the invoker).
    let direct2 = sign_invocation(
        &invoker.vm,
        &invoker.did,
        &invoker.jwk,
        owner.space.clone().to_resource(
            "kv".parse().unwrap(),
            Some("out/y".parse().unwrap()),
            None,
            None,
        ),
        "tinycloud.kv/get",
        Vec::new(),
        None,
        "urn:uuid:e2e-directkv2",
    )?;
    let (direct2_status, _b) = post_invoke(&client, &direct2, String::new()).await;
    assert_ne!(
        direct2_status,
        Status::Ok,
        "executing a routine must not grant the invoker any data capability"
    );

    Ok(())
}

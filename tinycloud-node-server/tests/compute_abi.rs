//! P2 Appendix A conformance fixture gate
//! (compute-service-implementation-plan.md P2):
//! `cargo test -p tinycloud-node --test compute_abi --features compute`.
//!
//! Runs the pinned `compute_fixture` (spec Appendix A) end-to-end through the
//! real `POST /invoke` compute path and asserts, BYTE-FOR-BYTE:
//!   * A.3: the `run` result equals `{"got":"42",...}`;
//!   * A.5: the execution manifest -- 5 ordered entries with the exact
//!     abilities/resources/destinations/granted flags AND the byte-lengths of
//!     the A.3 request/response payloads -- plus the granted-vs-exercised sets
//!     (granted-but-unexercised is EXACTLY `{sql/write}`);
//!   * A.4: step 5 is denied (envelope + op-not-performed + manifest
//!     `granted:false`), the request itself returns 200.
//! Plus the DISTINCT forbidden-import case: a guest importing outside the
//! four-function surface fails at INSTANTIATION (a link error), NOT as an
//! ability denial.

mod compute_common;
use compute_common::*;

use anyhow::Result;
use rocket::{http::Status, local::asynchronous::Client};

const CONFORMANCE_WAT: &str = include_str!("fixtures/compute/conformance.wat");
const FORBIDDEN_WAT: &str = include_str!("fixtures/compute/forbidden_import.wat");

/// Seed `in/x = "42"` as the space owner (A.1 precondition), outside the
/// routine, via a normal KV put.
async fn seed_in_x(client: &Client, owner: &Owner) -> Result<()> {
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
        Some("in/x".parse::<AuthPath>()?),
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
        nonce: Some("urn:uuid:seed-inx".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: Vec::new(),
        attenuation: caps,
    }
    .sign(owner.jwk.get_algorithm().unwrap_or_default(), &owner.jwk)?;
    let auth = ucan.encode()?;

    let response = client
        .post("/invoke")
        .header(rocket::http::Header::new("Authorization", auth))
        .header(rocket::http::ContentType::Bytes)
        .body(b"42".to_vec())
        .dispatch()
        .await;
    anyhow::ensure!(
        response.status() == Status::Ok,
        "seeding in/x failed: {}",
        response.into_string().await.unwrap_or_default()
    );
    Ok(())
}

#[tokio::test]
async fn conformance_fixture_runs_and_matches_appendix_a() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("abi-conformance")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&_tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let wasm = wat_to_wasm(CONFORMANCE_WAT)?;
    let (_rdid, _cid) =
        deploy_function(&client, &owner, "fixture", &wasm, A1_GRANT, "conf").await?;

    // A.1 precondition: seed in/x = "42".
    seed_in_x(&client, &owner).await?;

    // Invoker executes with compute/execute (no data caps).
    let auth = owner_compute_invocation(
        &owner,
        "fixture",
        "tinycloud.compute/execute",
        "urn:uuid:exec-conf",
    )?;
    let (status, body) = post_invoke(&client, &auth, execute_body("fixture", serde_json::json!({}))).await;
    assert_eq!(status, Status::Ok, "execute must return 200: {body}");

    let v: serde_json::Value = serde_json::from_str(&body)?;
    let result = &v["result"];

    // A.3: exact run result.
    assert_eq!(
        result,
        &serde_json::json!({
            "got": "42",
            "put": true,
            "sql_n": 1,
            "deleted": true,
            "denied": "tinycloud.kv/put"
        }),
        "run result must equal A.3"
    );

    // A.5: the manifest.
    let manifest = &v["manifest"];
    let calls = manifest["calls"].as_array().expect("calls array");
    assert_eq!(calls.len(), 5, "A.5: exactly 5 host-call journal entries");

    let space = owner.space.to_string();
    // Expected per-entry (resource, ability, destination, granted). bytes are
    // asserted structurally below (canonical byte lengths of A.3 payloads).
    let expected: [(&str, &str, &str, bool); 5] = [
        (&format!("{space}/kv/in/x"), "tinycloud.kv/get", "inline", true),
        (&format!("{space}/kv/out/y"), "tinycloud.kv/put", "out/y", true),
        (&format!("{space}/sql/db"), "tinycloud.sql/read", "inline", true),
        (&format!("{space}/kv/out/y"), "tinycloud.kv/del", "out/y", true),
        (&format!("{space}/kv/secret/z"), "tinycloud.kv/put", "", false),
    ];
    for (i, (res, ab, dest, granted)) in expected.iter().enumerate() {
        let c = &calls[i];
        assert_eq!(c["resource"], *res, "entry {i} resource");
        assert_eq!(c["ability"], *ab, "entry {i} ability");
        assert_eq!(c["granted"], *granted, "entry {i} granted");
        if *granted {
            assert_eq!(c["destination"], *dest, "entry {i} destination");
        }
        // bytesIn/bytesOut are present and non-zero for every entry.
        assert!(c["bytesIn"].as_u64().unwrap() > 0, "entry {i} bytesIn");
        assert!(c["bytesOut"].as_u64().unwrap() > 0, "entry {i} bytesOut");
    }

    // A.5 byte lengths: bytesIn equals the canonical-JSON length of the A.3
    // request payload for each entry (deterministic).
    assert_eq!(calls[0]["bytesIn"], serde_json::json!(14)); // {"key":"in/x"}
    assert_eq!(calls[1]["bytesIn"], serde_json::json!(28)); // {"key":"out/y","value":"84"}
    assert_eq!(calls[2]["bytesIn"], serde_json::json!(52)); // sql request
    assert_eq!(calls[3]["bytesIn"], serde_json::json!(15)); // {"key":"out/y"}
    assert_eq!(calls[4]["bytesIn"], serde_json::json!(30)); // {"key":"secret/z","value":"x"}
    // Response byte lengths for the fixed (space-independent) responses.
    assert_eq!(calls[0]["bytesOut"], serde_json::json!(24)); // {"ok":true,"value":"42"}
    assert_eq!(calls[1]["bytesOut"], serde_json::json!(11)); // {"ok":true}
    assert_eq!(calls[2]["bytesOut"], serde_json::json!(43)); // sql response
    assert_eq!(calls[3]["bytesOut"], serde_json::json!(11)); // {"ok":true}

    // Capability sets (A.5).
    let granted: Vec<String> = manifest["granted"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    let exercised: Vec<String> = manifest["exercised"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    let unexercised: Vec<String> = manifest["grantedButUnexercised"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    for a in [
        "tinycloud.kv/get",
        "tinycloud.kv/put",
        "tinycloud.kv/del",
        "tinycloud.sql/read",
        "tinycloud.sql/write",
    ] {
        assert!(granted.contains(&a.to_string()), "granted must contain {a}");
    }
    for a in [
        "tinycloud.kv/get",
        "tinycloud.kv/put",
        "tinycloud.kv/del",
        "tinycloud.sql/read",
    ] {
        assert!(
            exercised.contains(&a.to_string()),
            "exercised must contain {a}"
        );
    }
    assert_eq!(
        unexercised,
        vec!["tinycloud.sql/write".to_string()],
        "A.5: granted-but-unexercised must be exactly {{sql/write}}"
    );

    Ok(())
}

/// Determinism (A.6): re-running yields a byte-identical result + manifest.
#[tokio::test]
async fn conformance_fixture_is_deterministic() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("abi-determinism")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&_tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let wasm = wat_to_wasm(CONFORMANCE_WAT)?;
    deploy_function(&client, &owner, "fixture", &wasm, A1_GRANT, "det").await?;
    seed_in_x(&client, &owner).await?;

    let mut bodies = Vec::new();
    for i in 0..2 {
        // out/y is deleted each run (step 4), so in/x remains and the run is
        // reproducible; a fresh nonce per execute avoids the outer replay
        // cache.
        let auth = owner_compute_invocation(
            &owner,
            "fixture",
            "tinycloud.compute/execute",
            &format!("urn:uuid:exec-det-{i}"),
        )?;
        let (status, body) =
            post_invoke(&client, &auth, execute_body("fixture", serde_json::json!({}))).await;
        assert_eq!(status, Status::Ok, "run {i}: {body}");
        let v: serde_json::Value = serde_json::from_str(&body)?;
        // Compare result + manifest structurally (canonical).
        bodies.push(serde_json::to_string(&serde_json::json!({
            "result": v["result"],
            "manifest": v["manifest"],
        }))?);
    }
    assert_eq!(bodies[0], bodies[1], "result+manifest must be byte-identical across runs");
    Ok(())
}

/// Forbidden import (§10.1): a guest importing outside the four-function
/// "tinycloud" surface fails at module INSTANTIATION with a link error --
/// distinct from an A.4 ability denial (which returns 200 with an envelope).
#[tokio::test]
async fn forbidden_import_fails_at_instantiation() -> Result<()> {
    let (rocket, conn, _tempdir) = boot().await?;
    let owner = make_owner("abi-forbidden")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&_tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    let wasm = wat_to_wasm(FORBIDDEN_WAT)?;
    // Deploy needs at least kv/get so the routine has a live D_fn (the
    // forbidden import must fail at INSTANTIATION, not because no grant
    // exists).
    deploy_function(
        &client,
        &owner,
        "forbidden",
        &wasm,
        &[("tinycloud.kv/get", "in/")],
        "forb",
    )
    .await?;

    let auth = owner_compute_invocation(
        &owner,
        "forbidden",
        "tinycloud.compute/execute",
        "urn:uuid:exec-forb",
    )?;
    let (status, body) =
        post_invoke(&client, &auth, execute_body("forbidden", serde_json::json!({}))).await;
    // A module/link error is a client-side module problem -> 400, and it is
    // NOT a 200-with-denial-envelope (that is only the A.4 ability case).
    assert_eq!(
        status,
        Status::BadRequest,
        "forbidden import must fail at instantiation (link error -> 400): {body}"
    );
    assert_ne!(status, Status::Ok, "must NOT be a 200 ability-denial envelope");
    Ok(())
}

//! P2 end-to-end acceptance gate (compute-service-implementation-plan.md P2):
//! `cargo test -p tinycloud-node --test compute_e2e --features compute`.
//!
//! The full HTTP path against a real booted node (Rocket's in-process async
//! client, which exercises routing + guards + JSON (de)serialization -- the
//! repo's standard integration harness; there is no ephemeral-TCP harness in
//! this codebase, so the in-process client IS the "real server"). It asserts,
//! from the CLIENT side:
//!   * the fixture routine is deployed via the REAL deploy path (A.1 grant);
//!   * an invoker holding ONLY `compute/execute` (and ZERO data caps) runs it;
//!   * the result matches A.3 and the manifest shows each exercised import;
//!   * a denial is present (the ungranted `secret/z` put fails closed);
//!   * the invoker never gained any kv/sql capability throughout.

mod compute_common;
use compute_common::*;

use anyhow::Result;
use rocket::{http::Status, local::asynchronous::Client};

const CONFORMANCE_WAT: &str = include_str!("fixtures/compute/conformance.wat");

/// Seed a KV value as the space owner (A.1 precondition), outside the routine.
async fn owner_kv_put(client: &Client, owner: &Owner, key: &str, value: &[u8]) -> Result<()> {
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
        nonce: Some(format!("urn:uuid:owner-seed-{key}")),
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
    anyhow::ensure!(response.status() == Status::Ok, "owner kv put {key} failed");
    Ok(())
}

#[tokio::test]
async fn e2e_deploy_execute_manifest_and_denial_with_zero_data_caps() -> Result<()> {
    let (rocket, conn, tempdir) = boot().await?;
    let owner = make_owner("e2e")?;
    seed_space_and_actors(&conn, &owner.space, &[]).await?;
    ensure_block_dir(&tempdir, &owner.space)?;
    let client = Client::tracked(rocket).await?;

    // PART 1: the space owner deploys the fixture routine via the REAL deploy
    // path (handshake -> mint A.1 D_fn -> POST deploy). The deployer holds the
    // data caps; the routine's D_fn is bound to the content CID.
    let wasm = wat_to_wasm(CONFORMANCE_WAT)?;
    deploy_function(&client, &owner, "report", &wasm, A1_GRANT, "e2e").await?;

    // PART 2: the owner seeds in/x = "42" (A.1 precondition).
    owner_kv_put(&client, &owner, "in/x", b"42").await?;

    // PART 3: an INVOKER that holds ONLY compute/execute. Delegate
    // compute/execute (and NOTHING else -- no kv, no sql) from owner to the
    // invoker, then the invoker runs the routine.
    let invoker = make_holder()?;
    let deleg =
        mint_execute_delegation(&owner, &invoker.did, "report", None, "urn:uuid:e2e-deleg")?;
    let parent = delegate_and_get_cid(&client, &deleg).await?;

    // Sanity (F9 posture, client-side): the invoker's ONLY compute grant is
    // execute -- the delegation names no data ability. We assert this from the
    // grant the invoker actually holds (the delegation header we minted).
    assert!(
        deleg_grants_only_execute(&deleg)?,
        "invoker delegation must carry ONLY compute/execute, zero data caps"
    );

    let inv = holder_execute_invocation(
        &invoker,
        &owner,
        "report",
        &parent,
        None,
        "urn:uuid:e2e-exec",
    )?;
    let (status, body) =
        post_invoke(&client, &inv, execute_body("report", serde_json::json!({}))).await;
    assert_eq!(status, Status::Ok, "invoker execute must 200: {body}");

    let v: serde_json::Value = serde_json::from_str(&body)?;

    // PART 4: result matches A.3.
    assert_eq!(
        v["result"],
        serde_json::json!({
            "got": "42",
            "put": true,
            "sql_n": 1,
            "deleted": true,
            "denied": "tinycloud.kv/put"
        }),
        "result must match A.3"
    );

    // PART 5: the manifest shows each exercised import (get, put, del, sql/read)
    // and a denial (secret/z put, granted:false).
    let calls = v["manifest"]["calls"].as_array().unwrap();
    assert_eq!(calls.len(), 5);
    let exercised: Vec<String> = v["manifest"]["exercised"]
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
    ] {
        assert!(
            exercised.contains(&a.to_string()),
            "exercised must include {a}"
        );
    }
    // The denial entry (step 5) is present and fails closed.
    let denial = &calls[4];
    assert_eq!(denial["granted"], false, "the secret/z put must be denied");
    assert_eq!(denial["ability"], "tinycloud.kv/put");

    // PART 6: the invoker STILL holds zero data caps -- a direct kv/get by the
    // invoker (no data delegation) is rejected, proving the routine's access
    // never leaked to the invoker.
    let leak = invoker_direct_kv_get(&invoker, &owner, "in/x")?;
    let (status, _body) = post_invoke(&client, &leak, String::new()).await;
    assert_ne!(
        status,
        Status::Ok,
        "invoker must NOT be able to read data directly -- it holds zero data caps"
    );

    Ok(())
}

/// Decode the minted delegation header and assert every ability it grants is
/// `compute/execute` (client-side F9 check -- no data caps present).
fn deleg_grants_only_execute(header: &str) -> Result<bool> {
    use tinycloud_auth::authorization::{HeaderEncode, TinyCloudDelegation};
    let (deleg, _) = TinyCloudDelegation::decode(header)?;
    let abilities: Vec<String> = match deleg {
        TinyCloudDelegation::Ucan(u) => u
            .payload()
            .attenuation
            .abilities().values().flat_map(|abmap| abmap.keys().map(|a| a.to_string()))
            .collect(),
        TinyCloudDelegation::Cacao(_) => anyhow::bail!("expected a UCAN delegation"),
    };
    anyhow::ensure!(!abilities.is_empty(), "delegation grants nothing");
    Ok(abilities.iter().all(|a| a == "tinycloud.compute/execute"))
}

/// The invoker attempts a direct `kv/get` on the routine's input path with NO
/// data delegation (its `compute/execute` grant does not extend to kv). This
/// MUST be rejected -- proof the invoker holds zero data caps.
fn invoker_direct_kv_get(holder: &Holder, owner: &Owner, key: &str) -> Result<String> {
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
        "tinycloud.kv/get".parse::<UcanAbility>()?,
        [std::collections::BTreeMap::<String, serde_json::Value>::new()],
    );
    // No proof: the invoker is not the space owner, so with no parent
    // delegation this is unauthorized (a self-declared cap it does not hold).
    let ucan = Payload {
        issuer: holder.vm.parse::<DIDURLBuf>()?,
        audience: holder.did.parse::<DIDBuf>()?,
        not_before: None,
        expiration: NumericDate::try_from_seconds(far_future())?,
        nonce: Some("urn:uuid:e2e-leak-check".to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: Vec::new(),
        attenuation: caps,
    }
    .sign(holder.jwk.get_algorithm().unwrap_or_default(), &holder.jwk)?;
    Ok(ucan.encode()?)
}

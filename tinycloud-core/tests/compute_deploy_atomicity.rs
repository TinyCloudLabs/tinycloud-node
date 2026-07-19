//! P1 atomic-deploy-primitive gate, ROLLBACK DIRECTION B
//! (compute-service-implementation-plan.md P1: "injected-failure rollback in
//! BOTH directions ... no delegation without artifact; mirror only after
//! commit"). The server `compute_deploy` suite covers direction A (a `D_fn`
//! that fails verification leaves no artifact) end-to-end over HTTP. This
//! direction -- an ARTIFACT-save failure must roll back the already-processed
//! `D_fn` -- needs a deterministically-injected artifact I/O failure, which is
//! only cleanly reachable at the core level where the test controls the DB
//! connection. It exercises the SAME `SpaceDatabase::deploy_compute_function`
//! primitive the server calls (the plan flags the transaction seam as a CORE
//! primitive, not a service-module change), so this is the right altitude.
//!
//! Declared with `required-features = ["compute"]` (C5): a plain `cargo test`
//! skips it rather than silently reporting zero tests.

use tinycloud_auth::{
    authorization::TinyCloudDelegation,
    resolver::DID_METHODS,
    resource::{Path as AuthPath, ResourceId, Service, SpaceId},
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    events::Delegation,
    keys::StaticSecret,
    models::delegation as deleg_model,
    sea_orm::{
        ColumnTrait, ConnectionTrait, Database, DatabaseConnection, EntityTrait, PaginatorTrait,
        QueryFilter,
    },
    storage::memory::MemoryStore,
    ComputeDeployError, SpaceDatabase, SqlSizes,
};

type Db = SpaceDatabase<DatabaseConnection, MemoryStore, StaticSecret>;

struct Owner {
    space: SpaceId,
    jwk: JWK,
    vm: String,
}

fn make_owner(name: &str) -> Owner {
    let mut jwk = JWK::generate_ed25519().unwrap();
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key").unwrap().to_string();
    let fragment = did.rsplit_once(':').unwrap().1.to_string();
    let vm = format!("{did}#{fragment}");
    let space = SpaceId::new(did.parse::<DIDBuf>().unwrap(), name.parse().unwrap());
    Owner { space, jwk, vm }
}

fn random_did() -> String {
    DID_METHODS
        .generate(&JWK::generate_ed25519().unwrap(), "key")
        .unwrap()
        .to_string()
}

/// Mint a root-authority `D_fn` (owner -> delegatee) granting `kv/get` on
/// `in/` with the `computeFunctionBinding` caveat. Returns the encoded
/// `Delegation` event.
fn mint_d_fn(owner: &Owner, delegatee: &str, content_cid: &str, nonce: &str) -> Delegation {
    let kv_resource: ResourceId = owner.space.clone().to_resource(
        "kv".parse::<Service>().unwrap(),
        Some("in/".parse::<AuthPath>().unwrap()),
        None,
        None,
    );
    let mut binding = std::collections::BTreeMap::<String, serde_json::Value>::new();
    binding.insert(
        "computeFunctionBinding".to_string(),
        serde_json::json!({ "functionCid": content_cid }),
    );
    let mut caps = Capabilities::new();
    caps.with_action(
        kv_resource.as_uri(),
        "tinycloud.kv/get".parse().unwrap(),
        [binding],
    );
    let encoded = Payload {
        issuer: owner.vm.parse::<DIDURLBuf>().unwrap(),
        audience: delegatee.parse::<DIDBuf>().unwrap(),
        not_before: None,
        expiration: NumericDate::try_from_seconds(4_102_444_800.0).unwrap(),
        nonce: Some(nonce.to_string()),
        facts: Some(Vec::<serde_json::Value>::new()),
        proof: Vec::new(),
        attenuation: caps,
    }
    .sign(owner.jwk.get_algorithm().unwrap_or_default(), &owner.jwk)
    .unwrap()
    .encode()
    .unwrap();
    Delegation::from_header_ser::<TinyCloudDelegation>(&encoded).unwrap()
}

async fn make_db(sizes: SqlSizes) -> (Db, DatabaseConnection) {
    // File-backed sqlite so the test's cloned connection and the
    // SpaceDatabase share one on-disk DB (an injected `DROP TABLE` on one is
    // visible to the other). `sqlite::memory:` would give separate DBs.
    let tempfile = std::env::temp_dir().join(format!("tc-compute-atomicity-{}.db", uuid_like()));
    let url = format!("sqlite:{}?mode=rwc", tempfile.display());
    let conn = Database::connect(&url).await.unwrap();
    let db = SpaceDatabase::new(
        conn.clone(),
        MemoryStore::default(),
        StaticSecret::new(vec![5u8; 32]).unwrap(),
    )
    .await
    .unwrap()
    .with_sql_sizes(sizes);
    (db, conn)
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{n}")
}

#[tokio::test]
async fn artifact_failure_rolls_back_the_delegation_and_leaves_mirror_untouched() {
    let sizes = SqlSizes::new();
    let (db, conn) = make_db(sizes.clone()).await;
    let owner = make_owner("atomicity");
    let space_str = owner.space.to_string();

    // --- Baseline: a successful deploy establishes a known store_size. ---
    let wasm1 = b"\x00asm\x01\x00\x00\x00one".to_vec();
    let cid1 = tinycloud_core::hash::hash(&wasm1).to_cid(0x55).to_string();
    let routine1 = random_did();
    let dfn1 = mint_d_fn(&owner, &routine1, &cid1, "urn:uuid:atom-1");
    // NB: `ComputeDeployError` cannot be `{:?}`-formatted (its `K = StaticSecret`
    // deliberately has no `Debug`), so we match rather than `.expect(...)`.
    let (_result, artifact, previous) = match db
        .deploy_compute_function(dfn1, &space_str, "fn", wasm1.clone())
        .await
    {
        Ok(ok) => ok,
        Err(_) => panic!("baseline deploy must succeed"),
    };
    assert!(previous.is_none(), "first deploy has no predecessor");

    let baseline = db
        .store_size(&owner.space)
        .await
        .unwrap()
        .expect("store_size after a committed deploy must be Some");
    assert_eq!(baseline, artifact.size_bytes.max(0) as u64);
    assert_eq!(
        deleg_model::Entity::find()
            .filter(deleg_model::Column::Delegatee.eq(routine1.clone()))
            .count(&conn)
            .await
            .unwrap(),
        1,
        "baseline D_fn must be persisted"
    );

    // --- Inject an artifact-save failure: drop the artifact table. ---
    conn.execute_unprepared("DROP TABLE database_artifact")
        .await
        .expect("drop artifact table");

    // --- Second deploy: a VALID D_fn, but the artifact save now fails. ---
    let wasm2 = b"\x00asm\x01\x00\x00\x00two-different".to_vec();
    let cid2 = tinycloud_core::hash::hash(&wasm2).to_cid(0x55).to_string();
    let routine2 = random_did();
    let dfn2 = mint_d_fn(&owner, &routine2, &cid2, "urn:uuid:atom-2");
    match db
        .deploy_compute_function(dfn2, &space_str, "fn2", wasm2)
        .await
    {
        Err(ComputeDeployError::Artifact(_)) => {}
        Err(_) => panic!("expected an artifact error, got a different ComputeDeployError"),
        Ok(_) => panic!("artifact save must fail with the table dropped"),
    }

    // Direction B: the valid D_fn2 that WAS processed inside the transaction
    // is rolled back -- NO delegation row for routine2.
    assert_eq!(
        deleg_model::Entity::find()
            .filter(deleg_model::Column::Delegatee.eq(routine2))
            .count(&conn)
            .await
            .unwrap(),
        0,
        "an artifact failure must roll back the delegation (no delegation without artifact)"
    );

    // Mirror-after-commit: the rolled-back deploy left store_size unchanged.
    let after = db
        .store_size(&owner.space)
        .await
        .unwrap()
        .expect("store_size still reflects the baseline");
    assert_eq!(
        after, baseline,
        "a rolled-back deploy must not bump the size mirror"
    );
}

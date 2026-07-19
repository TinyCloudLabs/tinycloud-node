//! P1 dstack-simulator routine-key determinism test
//! (compute-service-implementation-plan.md P1, C11 defect b).
//!
//! The dstack `RoutineKeyDeriver` adapter (`compute_keys::DstackRoutineKeyDeriver`)
//! lives in the SERVER crate because `dstack::get_key` talks to the TEE daemon
//! over a Unix socket -- `tinycloud-core` cannot reach it. This target
//! exercises that adapter against the dstack SIMULATOR.
//!
//! Declared `required-features = ["compute", "dstack"]` so it compiles only
//! when both are on (the adapter is `#[cfg(all(compute, dstack))]`) and errors
//! if requested without them (C5 gate discipline).
//!
//! ## IMPORTANT -- this is a DEPLOYMENT-READINESS GATE, not a pure unit test.
//! The simulator only proves the derivation is deterministic within a single
//! running daemon. The REAL invariant the compute service depends on --
//! `routine_did` stability across CVM redeploys (compute-service.md §6.2 boxed
//! note; a prior DID-drift incident in OpenCredentials shows this is NOT
//! guaranteed) -- MUST be verified empirically on the target CVM (derive,
//! redeploy, re-derive, assert equality). That is a release precondition,
//! separate from this in-process check.
//!
//! When `DSTACK_SIMULATOR_ENDPOINT` is not set, this test SKIPS with a loud,
//! flagged message rather than silently passing (the simulator is not
//! available in every CI/dev environment).

use tinycloud_auth::{resolver::DID_METHODS, resource::SpaceId, ssi::dids::DIDBuf, ssi::jwk::JWK};
use tinycloud::compute_keys::DstackRoutineKeyDeriver;
use tinycloud_core::compute::RoutineKeyDeriver;

fn test_space(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap())
}

fn simulator_available() -> bool {
    // Mirror `dstack::is_available`: the socket path from
    // DSTACK_SIMULATOR_ENDPOINT (or the default) must exist.
    tinycloud::dstack::is_available()
}

#[tokio::test]
async fn dstack_routine_did_is_deterministic() {
    if std::env::var("DSTACK_SIMULATOR_ENDPOINT").is_err() && !simulator_available() {
        eprintln!(
            "\n================================================================\n\
             SKIPPED: compute_routine_key::dstack_routine_did_is_deterministic\n\
             DSTACK_SIMULATOR_ENDPOINT is unset and no dstack socket is reachable.\n\
             This is the dstack-adapter determinism check (C11 defect b).\n\
             *** FLAG: cross-CVM-redeploy routine_did stability is a DEPLOYMENT-\n\
             READINESS GATE that MUST be verified empirically on the target CVM\n\
             (compute-service.md §6.2). This simulator test does not prove it. ***\n\
             ================================================================\n"
        );
        return;
    }

    let deriver = DstackRoutineKeyDeriver;
    let space = test_space("dstack-determinism");

    let first = deriver
        .derive_routine_did(&space, "bafyfixedcid")
        .await
        .expect("dstack derivation should succeed when the simulator is reachable");
    let second = deriver
        .derive_routine_did(&space, "bafyfixedcid")
        .await
        .expect("dstack derivation should succeed on the second call");
    assert_eq!(
        first, second,
        "the dstack adapter must derive the same routine_did for the same (space, cid)"
    );
    assert!(first.starts_with("did:key:z"), "expected a did:key, got {first}");

    // Distinct CIDs must derive distinct DIDs.
    let other = deriver
        .derive_routine_did(&space, "bafyOTHERcid")
        .await
        .expect("dstack derivation should succeed for a different cid");
    assert_ne!(first, other);
}

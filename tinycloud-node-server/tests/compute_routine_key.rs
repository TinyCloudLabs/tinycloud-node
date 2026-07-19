//! P1 dstack routine-key determinism gate (compute-service-implementation-plan.md
//! P1, Codex C11 defect b): the dstack-simulator `RoutineKeyDeriver` adapter
//! lives in the SERVER crate (`dstack::get_key` is server-only), so its
//! machine-checked determinism test lands here.
//!
//! `cargo test -p tinycloud-node --test compute_routine_key --features compute,dstack`
//! (with `DSTACK_SIMULATOR_ENDPOINT` pointed at a running dstack simulator).
//!
//! Declared with `required-features = ["compute", "dstack"]` (C5): a bare
//! `--test compute_routine_key` without BOTH features errors instead of
//! silently reporting zero tests.
//!
//! IMPORTANT (flagged per the plan): the SIMULATOR test only proves the
//! adapter is deterministic FOR A FIXED SEED within one process. It does NOT
//! prove the real cross-CVM-redeploy `routine_did` stability -- that is a
//! **deployment-readiness gate** (§6.2 box, "VERIFY EMPIRICALLY"): derive
//! `routine_did` for a fixed CID, redeploy the CVM, re-derive, assert equality.
//! Record that as a release precondition, separate from this machine gate. A
//! prior OpenCredentials DID-drift incident showed dstack-derived key material
//! can shift across deploys, which would silently invalidate every `D_fn`.
//!
//! When no simulator is reachable this test ENV-GATED-SKIPS with a prominent
//! message rather than failing, since the simulator is external infrastructure.

use tinycloud_auth::{
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::{dids::DIDBuf, jwk::JWK},
};
use tinycloud_core::compute::RoutineKeyDeriver;

fn space(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap())
}

/// Whether a dstack simulator socket is reachable (`DSTACK_SIMULATOR_ENDPOINT`
/// or the default `/var/run/dstack.sock`).
fn simulator_available() -> bool {
    tinycloud::dstack::is_available()
}

#[tokio::test]
async fn dstack_routine_key_is_deterministic_when_simulator_available() {
    if !simulator_available() {
        eprintln!(
            "\n================================================================\n\
             SKIPPED: compute_routine_key -- no dstack simulator reachable.\n\
             Set DSTACK_SIMULATOR_ENDPOINT to a running simulator socket to run\n\
             this gate. The REAL cross-CVM-redeploy routine_did stability check\n\
             is a DEPLOYMENT-READINESS gate (compute-service.md §6.2), not a unit\n\
             test -- it must be verified empirically on the target CVM before\n\
             relying on derived-key routine identity in production.\n\
             ================================================================\n"
        );
        return;
    }

    let deriver = tinycloud::compute::DstackRoutineKeyDeriver::new();
    let sp = space("dstack-determinism");
    let cid = "bafyroutinecid";

    let seed1 = deriver
        .derive_routine_seed(&sp, cid)
        .await
        .expect("dstack derive #1");
    let seed2 = deriver
        .derive_routine_seed(&sp, cid)
        .await
        .expect("dstack derive #2");
    assert_eq!(
        seed1, seed2,
        "the dstack adapter must derive the same seed for the same (space, cid)"
    );

    let did1 = deriver
        .derive_routine_did(&sp, cid)
        .await
        .expect("dstack routine_did #1");
    assert!(did1.starts_with("did:key:"));

    // A different content CID must derive a different seed.
    let other = deriver
        .derive_routine_seed(&sp, "bafyOTHERcid")
        .await
        .expect("dstack derive other");
    assert_ne!(seed1, other, "distinct CIDs must derive distinct seeds");
}

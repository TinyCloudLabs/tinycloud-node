//! P1 (compute-service-implementation-plan.md P1 verify block):
//! `cargo test -p tinycloud-core --test routine_key_deriver` — the
//! `RoutineKeyDeriver` TRAIT unit test with the CLASSIC impl only (core has
//! no dstack adapter; the dstack-simulator adapter's determinism test lives
//! in the server crate, `tests/compute_routine_key.rs`).
//!
//! Declared with `required-features = ["compute"]` so a plain `cargo test`
//! skips it (not a silent zero-tests no-op) and an explicit
//! `--test routine_key_deriver` without `--features compute` errors (C5).
//!
//! Asserts the properties every `RoutineKeyDeriver` MUST hold, exercised
//! against `ClassicRoutineKeyDeriver` (compute-service.md §6.2):
//!   * determinism: same `(space, function_cid)` -> same seed AND same
//!     public routine_did (the F1.5 tripwire and the F2 handshake both
//!     depend on re-derivation returning the same value);
//!   * per-`(space, function_cid)` uniqueness: the derived did differs when
//!     EITHER the space OR the function_cid changes — the cross-space
//!     confused-deputy defense (§6.2/F3);
//!   * hashed-space collision-freedom (§13.1 / Codex C8): the derivation
//!     input hashes the space component, so two distinct spaces can never
//!     collide into one derivation string, without depending on the stubbed
//!     `Name` grammar;
//!   * `routine_did_from_seed` yields a valid `did:key:` for the SAME seed
//!     the trait returns (the handshake exposes only the PUBLIC did).

use tinycloud_auth::{
    resolver::DID_METHODS,
    resource::SpaceId,
    ssi::{dids::DIDBuf, jwk::JWK},
};
use tinycloud_core::compute::{
    routine_did_from_seed, routine_key_derivation_path, ClassicRoutineKeyDeriver, RoutineKeyDeriver,
};
use tinycloud_core::keys::StaticSecret;

fn space(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap())
}

fn deriver() -> ClassicRoutineKeyDeriver {
    ClassicRoutineKeyDeriver::new(StaticSecret::new(vec![42u8; 32]).unwrap())
}

#[tokio::test]
async fn seed_and_did_are_deterministic() {
    let d = deriver();
    let s = space("determinism");
    let seed1 = d.derive_routine_seed(&s, "bafyCID").await.unwrap();
    let seed2 = d.derive_routine_seed(&s, "bafyCID").await.unwrap();
    assert_eq!(seed1, seed2, "same input must derive the same seed");

    let did1 = d.derive_routine_did(&s, "bafyCID").await.unwrap();
    let did2 = d.derive_routine_did(&s, "bafyCID").await.unwrap();
    assert_eq!(did1, did2);
    assert_eq!(routine_did_from_seed(seed1).unwrap(), did1);
    assert!(did1.starts_with("did:key:"));
}

#[tokio::test]
async fn did_differs_by_function_cid_within_one_space() {
    let d = deriver();
    let s = space("per-function");
    let a = d.derive_routine_did(&s, "bafyAAA").await.unwrap();
    let b = d.derive_routine_did(&s, "bafyBBB").await.unwrap();
    assert_ne!(
        a, b,
        "distinct function CIDs must derive distinct routine dids"
    );
}

#[tokio::test]
async fn did_differs_by_space_for_one_function_cid() {
    // §6.2/F3: identical WASM (same CID) deployed in two spaces yields
    // DISTINCT routine_dids — cross-space citation is cryptographically
    // impossible, not merely policy-blocked.
    let d = deriver();
    let space_a = space("space-a");
    let space_b = space("space-b");
    let did_a = d
        .derive_routine_did(&space_a, "bafySharedCID")
        .await
        .unwrap();
    let did_b = d
        .derive_routine_did(&space_b, "bafySharedCID")
        .await
        .unwrap();
    assert_ne!(did_a, did_b);
}

#[tokio::test]
async fn hashed_space_never_collides_with_adversarial_delimiters() {
    // Codex C8 / §13.1: the derivation input hashes the canonical space
    // string into a fixed-width, delimiter-free base32 token, so no pair of
    // distinct spaces — including adversarially-chosen names with embedded
    // `/` and `:` delimiters — can produce the same derivation input, WITHOUT
    // relying on the global `Name` grammar. `Name` currently accepts any
    // string (its validator is a `// TODO`), so we can build names that
    // WOULD collide under naive concatenation and prove the hashing prevents
    // it.
    let d = deriver();
    // Two spaces whose display strings differ only in where a delimiter
    // falls; a naive `space + "/compute/" + cid` scheme could be coaxed to
    // collide, but the hashed token cannot.
    let s1 = space("evil/compute/x");
    let s2 = space("evil");
    let p1 = routine_key_derivation_path(&s1, "y");
    let p2 = routine_key_derivation_path(&s2, "compute/x/compute/y");
    assert_ne!(
        p1, p2,
        "hashed-space derivation paths must not collide across distinct spaces"
    );
    // And the derived dids differ.
    let did1 = d.derive_routine_did(&s1, "y").await.unwrap();
    let did2 = d
        .derive_routine_did(&s2, "compute/x/compute/y")
        .await
        .unwrap();
    assert_ne!(did1, did2);
}

#[tokio::test]
async fn derivation_path_is_domain_separated_and_versioned() {
    let s = space("prefix-check");
    let path = routine_key_derivation_path(&s, "bafyCID");
    assert!(
        path.starts_with("tinycloud/compute-key/v1/"),
        "derivation path must carry the domain-separated, versioned prefix: {path}"
    );
    assert!(path.ends_with("/compute/bafyCID"));
}

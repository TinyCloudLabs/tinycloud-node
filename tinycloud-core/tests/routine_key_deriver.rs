//! `RoutineKeyDeriver` trait unit test, classic impl only
//! (compute-service-implementation-plan.md P1 section — core has no dstack
//! adapter; that lives in the server crate and is exercised by
//! `tinycloud-node`'s `compute_routine_key` integration test instead).
//!
//! This target only makes sense with the `compute` feature enabled --
//! `RoutineKeyDeriver`/`ClassicRoutineKeyDeriver` don't exist without it. It
//! is declared with `required-features = ["compute"]` in
//! `tinycloud-core/Cargo.toml` so a plain `cargo test` skips it (not a
//! silent zero-tests no-op) and an explicit `--test routine_key_deriver`
//! without `--features compute` errors, matching the C5 gate discipline used
//! for the server-crate compute test targets.

use std::sync::Arc;
use tinycloud_auth::{resolver::DID_METHODS, resource::SpaceId, ssi::dids::DIDBuf, ssi::jwk::JWK};
use tinycloud_core::compute::{
    routine_key_derivation_path, ClassicRoutineKeyDeriver, RoutineKeyDeriver,
};
use tinycloud_core::keys::StaticSecret;

fn test_space(name: &str) -> SpaceId {
    let jwk = JWK::generate_ed25519().unwrap();
    let did: DIDBuf = DID_METHODS.generate(&jwk, "key").unwrap();
    SpaceId::new(did, name.parse().unwrap())
}

fn deriver(secret_byte: u8) -> ClassicRoutineKeyDeriver {
    ClassicRoutineKeyDeriver::new(StaticSecret::new(vec![secret_byte; 32]).unwrap())
}

#[tokio::test]
async fn derivation_is_deterministic_for_same_space_and_cid() {
    let space = test_space("determinism");
    let d = deriver(1);
    let first = d.derive_routine_did(&space, "bafyfixedcid").await.unwrap();
    let second = d.derive_routine_did(&space, "bafyfixedcid").await.unwrap();
    assert_eq!(
        first, second,
        "same (space, function_cid) must derive the same routine_did"
    );
    assert!(
        first.starts_with("did:key:z"),
        "expected a did:key, got {first}"
    );
}

#[tokio::test]
async fn distinct_function_cids_derive_distinct_dids() {
    let space = test_space("distinct-fn");
    let d = deriver(2);
    let a = d.derive_routine_did(&space, "bafyAAA").await.unwrap();
    let b = d.derive_routine_did(&space, "bafyBBB").await.unwrap();
    assert_ne!(a, b);
}

/// F3 cross-space isolation (compute-service.md §6.2/F3, §13.1 test
/// obligation): identical function CID deployed in two distinct spaces must
/// derive DISTINCT routine DIDs, so a space-B execution can never
/// cryptographically produce space-A's routine key.
#[tokio::test]
async fn distinct_spaces_derive_distinct_dids_for_the_same_function_cid() {
    let d = deriver(3);
    let space_a = test_space("space-a");
    let space_b = test_space("space-b");
    let a = d.derive_routine_did(&space_a, "bafySAME").await.unwrap();
    let b = d.derive_routine_did(&space_b, "bafySAME").await.unwrap();
    assert_ne!(
        a, b,
        "identical WASM deployed in two spaces must not share a routine_did"
    );
}

/// Codex C8/defect a: the space component is HASHED (fixed-width,
/// delimiter-free base32 of its blake3 digest) before entering the
/// derivation string, so two adversarially-chosen space names that would
/// concatenate to the same raw string (if the space were embedded
/// unhashed) still cannot collide. Exercise via the derivation-path string
/// itself: two distinct space names never produce the same path for the
/// same function_cid, even when one space's name embeds delimiter-like
/// substrings that could confuse a naive concatenation.
#[tokio::test]
async fn space_hashing_prevents_delimiter_confusion_collisions() {
    // These two (space-name, function_cid) pairs would concatenate to the
    // same raw string under naive "space/compute/" string-building if the
    // space component were NOT hashed first.
    let space_a = test_space("foo");
    let space_b = test_space("foo-x");
    let path_a = routine_key_derivation_path(&space_a, "bar-cid");
    let path_b = routine_key_derivation_path(&space_b, "bar-cid");
    assert_ne!(path_a, path_b);

    // The hashed space token is fixed-width regardless of the input space
    // name's length.
    let short = routine_key_derivation_path(&test_space("a"), "cid");
    let long = routine_key_derivation_path(
        &test_space("a-much-much-much-longer-space-name-than-the-other-one"),
        "cid",
    );
    let token = |s: &str| {
        s.strip_prefix("tinycloud/compute-key/v1/")
            .unwrap()
            .split("/compute/")
            .next()
            .unwrap()
            .to_string()
    };
    assert_eq!(
        token(&short).len(),
        token(&long).len(),
        "hashed space token must be fixed-width regardless of space-name length"
    );
    // Delimiter-free: no '/' or ':' in the hashed token (base32-lower, no
    // padding, plus the multibase prefix char).
    let t = token(&short);
    assert!(!t.contains('/') && !t.contains(':'));
    assert!(t
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
}

#[tokio::test]
async fn distinct_secrets_derive_distinct_dids() {
    let space = test_space("distinct-secret");
    let a = deriver(9)
        .derive_routine_did(&space, "bafyfixedcid")
        .await
        .unwrap();
    let b = deriver(10)
        .derive_routine_did(&space, "bafyfixedcid")
        .await
        .unwrap();
    assert_ne!(
        a, b,
        "different node secret material must derive different routine DIDs"
    );
}

#[tokio::test]
async fn dyn_trait_object_is_usable() {
    let space = test_space("dyn-object");
    let d: Arc<dyn RoutineKeyDeriver> = Arc::new(deriver(4));
    let did = d.derive_routine_did(&space, "bafycid").await.unwrap();
    assert!(did.starts_with("did:key:z"));
}

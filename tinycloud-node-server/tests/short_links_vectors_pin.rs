//! The links API vectors this repository tests against are a byte-identical
//! copy of `docs/specs/short-links-api-vectors.json` in samgbafa/tinycloud-dev
//! at the pinned commit. A vector change is made there first; this copy and
//! the pin below change together, in one commit.

use sha2::{Digest, Sha256};

/// samgbafa/tinycloud-dev, the commit the copy is taken from.
const SOURCE_COMMIT: &str = "ae7349958f232ef4afc4e7586353265d7f34f1ef";
const SHA256: &str = "59641c44536e5f53d7230205ff7d277bd5441cc8ddac10b7bee63f1d2358f3e6";

#[test]
fn the_vectors_copy_is_the_pinned_file() {
    let copy = include_bytes!("fixtures/short-links-api-vectors.json");
    assert_eq!(
        hex::encode(Sha256::digest(copy)),
        SHA256,
        "tests/fixtures/short-links-api-vectors.json differs from \
         docs/specs/short-links-api-vectors.json at {SOURCE_COMMIT}"
    );
}

//! The links API vectors this repository tests against are a byte-identical
//! copy of `docs/specs/short-links-api-vectors.json` in samgbafa/tinycloud-dev
//! at the pinned commit. A vector change is made there first; this copy and
//! the pin below change together, in one commit.

use sha2::{Digest, Sha256};

/// samgbafa/tinycloud-dev, the commit the copy is taken from.
const SOURCE_COMMIT: &str = "b079f38943d64953819890d994ad3f36fbdd84be";
const SHA256: &str = "72db4cd91ba0ae9c530d541ad0f7b1a05c76b8de942b0fe247f1356ff5899d25";

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

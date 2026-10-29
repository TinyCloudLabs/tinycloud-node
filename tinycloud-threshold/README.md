# tinycloud-threshold

BLS12-381 identity-based wrapping of 32-byte data keys and context-bound encrypted threshold key derivation.

The crate is a workspace member with `publish = false`. No other workspace crate depends on it; the node server remains the default member. Release-plz neither releases nor publishes it.

## S0.1 surface

- Bounded, canonical scalar, point, identity, ciphertext, request and share encodings.
- Boneh–Franklin FullIdent wrapping and unwrapping with the TinyCloud domains in [SPEC.md](SPEC.md).
- Capability-asserted derivation requests, individual member-share verification, lowest-index threshold interpolation and reader unmasking.
- Keys retain their identity and certificate/generation context. Shares carry both the key-context digest and the request digest.
- The blst FFI boundary is confined to `src/curve.rs`; its header inventories the entry points and buffer invariants.

`KeyContext`, `PublicKeySet` and `KeyShare` have no public S0.1 constructor. The dealer exists only under `#[cfg(test)]`. Certificate, ceremony, storage and node-runtime paths are outside this slice. Their protocol contracts are recorded in SPEC.md §§3.7–3.12.

The §3.6 request-digest amendment is explicit in SPEC.md. It makes an identity or transport-key transplant a context mismatch before share equations are evaluated.

`combine` accepts at most `2*n` raw share entries, where `n` is the validated current member count. Duplicates count toward this limit. An oversized input returns `CombineError::TooManyShares`, naming no member, before request/share binding checks or algebra. Within the limit, the existing binding-first checks and member deduplication remain unchanged.

## Checks

Use the workspace's pinned Rust 1.97.1 toolchain:

```sh
cargo test --locked -p tinycloud-threshold
cargo test -p tinycloud-threshold checkpoint_2of3 -- --nocapture
cargo clippy -p tinycloud-threshold --all-targets -- -D warnings
cargo fmt --all -- --check
PROPTEST_CASES=1024 cargo test --locked -p tinycloud-threshold --release
cargo deny --manifest-path tinycloud-threshold/Cargo.toml --locked --config tinycloud-threshold/deny.toml check licenses bans advisories sources
```

The `threshold` job in `.github/workflows/rust.yml` runs the full release suite, the explicitly selected cargo-deny policy and the independent primitive checker. Workspace test, build, formatting and clippy jobs also include this member.

The checkpoint prints nine executed outcomes. Required RFC tests are separately named `rfc9380_appendix_j_g1_sswu_ro`, `rfc9380_appendix_j_g2_sswu_ro` and `rfc9380_appendix_k1_expand_xmd_sha256`.

## Vectors

`vectors/v1/primitives.json` records fixed test seeds and test scalars, frozen domains, hash/group/pairing bytes, FullIdent inputs and outputs, a 2-of-3 derivation and named error cases. These are public test values, not deployment keys. `primitive_vectors_regenerate_byte_for_byte` regenerates the file in memory and compares its complete bytes. To update it deliberately:

```sh
TC_THRESHOLD_REGEN_VECTORS=1 cargo test -p tinycloud-threshold primitive_vectors_regenerate_byte_for_byte
```

`rfc9380-{g1,g2,k1}.json` contains the published Appendix J.9.1, J.10.1 and K.1 cases. The separate-session checker consumes SPEC.md and the JSON vector format, without consulting the Rust implementation. Its CI entry point is `bun install --frozen-lockfile && bun run check` in `vectors/check/`.

## Dependencies and licence

This crate uses the workspace's [TinyCloud EGPL v1.5](../LICENSE.md) through `license-file`. Production dependencies: `blst` (Apache-2.0), `sha2` (MIT OR Apache-2.0), `zeroize` (Apache-2.0 OR MIT), `subtle` (BSD-3-Clause), `rand_core` (MIT OR Apache-2.0), and `thiserror` (MIT OR Apache-2.0). Development dependencies: `proptest`, `rand_chacha`, `serde`, `serde_json`, and `hex` (MIT OR Apache-2.0).

The crate-scoped `deny.toml` includes development and build dependencies. It allows Apache-2.0, MIT, BSD-3-Clause, ISC and Unicode-3.0, with a hash-pinned EGPL clarification and exception for this crate only. Registry sources are restricted to crates.io.

# tinycloud-threshold

BLS12-381 identity-based wrapping of 32-byte data keys and context-bound encrypted threshold key derivation.

The crate is a workspace member with `publish = false`. No other workspace crate depends on it; the node server remains the default member. Release-plz neither releases nor publishes it.

## Implemented surface through S0.4

- Bounded, canonical scalar, point, identity, ciphertext, request and share encodings.
- Boneh–Franklin FullIdent wrapping and unwrapping with the TinyCloud domains in [SPEC.md](SPEC.md).
- Capability-asserted derivation requests, individual member-share verification, lowest-index threshold interpolation and reader unmasking.
- Keys retain their identity and certificate/generation context. Shares carry both the key-context digest and the request digest.
- The blst FFI boundary is confined to `src/curve.rs`; its header inventories the entry points and buffer invariants.
- Owner-authorized ceremony envelopes and closed rounds with signed recipient/dealer cohorts and retained authenticated payload-decode outcomes.
- Externally anchored certificates, pinned succession and certificate-bound candidate shares.
- Signed response fault classification, readiness receipts and all-holder or explicit outage-budget activation verification.
- Ceremony-scoped RFC 9180 sealed dealings.
- Genesis DKG (GJKR New-DKG) over owner-closed rounds: consume-self member states for dealing, complaints, answers, Feldman extraction, the common R5 round and R6 reconstruction, and `dkg_verify_transcript`, which recomputes the outcome from the raw signed round records.
- Redistribution for reshare and refresh over owner-closed rounds R1–R3: Feldman dealings from the current certificate's members to an authorized cohort with a new threshold, complaints and answers, deterministic selection of the first t eligible dealers, and `reshare_verify_transcript`. The master public key is unchanged; the output is a candidate for the successor certificate.

`VerifiedCertificate` supplies `KeyContext` and `PublicKeySet`; `KeyShare::bind` validates a candidate against its certificate. Raw candidate-scalar construction remains crate-private, and the dealer exists only under `#[cfg(test)]`. Redistribution does not erase earlier shares; old and new shares carry different key contexts. Durable storage, retirement and node-runtime paths remain separate slices. Their contracts and the implemented canonical byte layouts are recorded in [SPEC.md](SPEC.md).

The §3.6 request-digest amendment is explicit in SPEC.md. It makes an identity or transport-key transplant a context mismatch before share equations are evaluated.

## Checks

Use the workspace's pinned Rust 1.97.1 toolchain:

```sh
cargo test --locked -p tinycloud-threshold
cargo test -p tinycloud-threshold checkpoint_2of3 -- --nocapture
cargo test --locked -p tinycloud-threshold certificate_authorization_share_fault_activation_smoke -- --nocapture
cargo clippy -p tinycloud-threshold --all-targets -- -D warnings
cargo fmt --all -- --check
PROPTEST_CASES=1024 cargo test --locked -p tinycloud-threshold --release
cargo deny --manifest-path tinycloud-threshold/Cargo.toml --locked --config tinycloud-threshold/deny.toml check licenses bans advisories sources
```

The `threshold` job in `.github/workflows/rust.yml` runs the full release suite, the explicitly selected cargo-deny policy and the independent primitive checker. Workspace test, build, formatting and clippy jobs also include this member.

The `checkpoint_2of3` filter runs three checkpoints: the test-dealer checkpoint prints nine executed outcomes, `checkpoint_2of3_dkg` prints five outcomes for a signed 2-of-3 DKG with one reconstructed dealer, its certificate binding and threshold derivation, and `checkpoint_2of3_reshare` prints six outcomes for a DKG genesis redistributed to 3-of-4 and a refused redistribution below t valid dealers. Required RFC tests are separately named `rfc9380_appendix_j_g1_sswu_ro`, `rfc9380_appendix_j_g2_sswu_ro` and `rfc9380_appendix_k1_expand_xmd_sha256`.

## Vectors

`vectors/v1/primitives.json` records fixed test seeds and test scalars, frozen domains, hash/group/pairing bytes, FullIdent inputs and outputs, a 2-of-3 derivation and named error cases. These are public test values, not deployment keys. `primitive_vectors_regenerate_byte_for_byte` regenerates the file in memory and compares its complete bytes. To update it deliberately:

```sh
TC_THRESHOLD_REGEN_VECTORS=1 cargo test -p tinycloud-threshold primitive_vectors_regenerate_byte_for_byte
```

`rfc9380-{g1,g2,k1}.json` contains the published Appendix J.9.1, J.10.1 and K.1 cases. The separate-session checker consumes SPEC.md and the JSON vector format, without consulting the Rust implementation. Its CI entry point is `bun install --frozen-lockfile && bun run check` in `vectors/check/`.

`vectors/v1/cert-core.json` contains 18 certificate, lineage, share-binding, fault and activation cases. The certificate vector test replays these cases through the verification APIs with real test signatures.

`vectors/v1/dkg-genesis.json` contains six genesis DKG transcripts from fixed seeds: the signed ceremony statement, the initial transcript link, every owner closure and member message, and either the recomputed QUAL, disqualification reasons, reconstructed dealers, commitments, public shares and transcript hash, or the expected error. It lists the Ed25519 test keys for its DIDs. `dkg_vectors_regenerate_byte_for_byte_and_replay` regenerates the file in memory, compares its complete bytes and replays every case through `dkg_verify_transcript`. To update it deliberately:

```sh
TC_THRESHOLD_REGEN_VECTORS=1 cargo test -p tinycloud-threshold dkg_vectors_regenerate_byte_for_byte_and_replay
```

`vectors/v1/reshare.json` contains five redistribution transcripts from fixed seeds: the current certificate, the signed ceremony statement, the initial transcript link, every owner closure and member message, and either the recomputed dealers, exclusion reasons, commitments, public shares and transcript hash, or the expected error. `reshare_vectors_regenerate_byte_for_byte_and_replay` regenerates the file in memory, compares its complete bytes and replays every case through `reshare_verify_transcript`. To update it deliberately:

```sh
TC_THRESHOLD_REGEN_VECTORS=1 cargo test -p tinycloud-threshold reshare_vectors_regenerate_byte_for_byte_and_replay
```

## Dependencies and licence

This crate uses the workspace's [TinyCloud EGPL v1.5](../LICENSE.md) through `license-file`. Production dependencies: `blst` (Apache-2.0), `sha2` (MIT OR Apache-2.0), `zeroize` (Apache-2.0 OR MIT), `subtle` (BSD-3-Clause), `rand_core` (MIT OR Apache-2.0), and `thiserror` (MIT OR Apache-2.0). Development dependencies: `proptest`, `rand_chacha`, `serde`, `serde_json`, and `hex` (MIT OR Apache-2.0).

Certificate tests additionally use development-only `ed25519-dalek = "=2.2.0"` for signing and verification. It is included in the crate-scoped dependency policy below.

The crate-scoped `deny.toml` includes development and build dependencies. It allows Apache-2.0, MIT, BSD-3-Clause, ISC and Unicode-3.0, with a hash-pinned EGPL clarification and exception for this crate only. Registry sources are restricted to crates.io.

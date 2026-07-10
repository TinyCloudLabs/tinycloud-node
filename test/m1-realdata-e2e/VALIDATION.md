# Validation record

Observed locally on 2026-07-10 from the ticket worktree after the Rust and
documentation changes in this follow-up. All commands used the shared ticket
target directory; the policy-engine dependency remained pinned by this crate's
lockfile and manifest.

## Cross-layer contract proof

```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true \
CARGO_TARGET_DIR=/Users/pmess/conductor/workspaces/tinycloud-node/.smithers-data-exchange/cargo-target \
cargo test --manifest-path test/m1-realdata-e2e/Cargo.toml
```

Observed result:

```text
running 2 tests
test evidence_verification_path_rejects_direct_wall_clock_reads ... ok
test deterministic_cross_layer_contract_is_observed_from_real_operations ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

## Strict lint

```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true \
CARGO_TARGET_DIR=/Users/pmess/conductor/workspaces/tinycloud-node/.smithers-data-exchange/cargo-target \
cargo clippy --manifest-path test/m1-realdata-e2e/Cargo.toml --all-targets -- -D warnings
```

Observed result: exit status 0 with no warnings.

## Native data-plane dependency guard

```sh
CARGO_TARGET_DIR=/Users/pmess/conductor/workspaces/tinycloud-node/.smithers-data-exchange/cargo-target \
cargo test -p tinycloud-node --test w1_native_contract data_plane_has_zero_policy_dependency
```

Observed result:

```text
running 1 test
test data_plane_has_zero_policy_dependency ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 7 filtered out
```

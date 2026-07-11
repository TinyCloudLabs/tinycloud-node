# Validation record

Observed locally on 2026-07-11 from the m1-g-08 ticket worktree. All commands
used the shared ticket target directory. The vendored grant vectors, generator,
and actual g-07 engine source remain content-hash pinned in `vendor/MANIFEST.json`.

## Cross-layer contract proof

```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true \
CARGO_TARGET_DIR=/Users/pmess/conductor/workspaces/tinycloud-node/.smithers-data-exchange/cargo-target \
cargo test --manifest-path test/m1-realdata-e2e/Cargo.toml
```

Observed result:

```text
running 3 tests
test evidence_verification_path_rejects_direct_wall_clock_reads ... ok
test evidence_verification_uses_fixture_time_under_hostile_ambient ... ok
test deterministic_cross_layer_contract_is_observed_from_real_operations ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

running 3 tests
test frozen_plane_has_native_identity_shape_and_layer_partition ... ok
test generator_default_instant_is_the_cross_plane_byte_anchor ... ok
test live_plane_semantically_corresponds_to_every_frozen_case ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

The deterministic cross-layer test now also contains the serialized real-node
grant observation so the node's process-global logger is initialized exactly
once. That observation executes 13 node-layer vector identities, four actual
engine grants, one separately labeled expired-ACCEPT longevity observation,
and the owner-seeded SQL/KV reads.

## Strict lint

```sh
CARGO_NET_GIT_FETCH_WITH_CLI=true \
CARGO_TARGET_DIR=/Users/pmess/conductor/workspaces/tinycloud-node/.smithers-data-exchange/cargo-target \
cargo clippy --manifest-path test/m1-realdata-e2e/Cargo.toml --all-targets -- -D warnings
```

Observed result: exit status 0 with no warnings.

## Ticket validateCommands

The first ticket command (`cargo fmt --check`, strict `cargo clippy`, then the
excluded-crate tests) exited 0. The second ticket command also exited 0:

```sh
CARGO_TARGET_DIR=/Users/pmess/conductor/workspaces/tinycloud-node/.smithers-data-exchange/cargo-target \
cargo check --workspace
```

Observed result: the full workspace finished the dev profile successfully.

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

# W5 Policy Runtime Node E2E

This excluded crate verifies the cross-repo W5 runtime flow without adding the
private `policy-engine` branch dependency to the default tinycloud-node
workspace or CI path. Its `tinycloud-node` dependency enables the `duckdb`
feature so `tests/sql_isolation.rs` exercises both engines' path→database
resolution (the TC-780 N1 reproduction, red until the N2 fix).

Run it explicitly:

```sh
cargo test --manifest-path test/w5-policy-runtime-node-e2e/Cargo.toml
```

CI runs the same command in the `w5-node-e2e` job in `.github/workflows/rust.yml`.

The checked-in lockfile is intentional: tinycloud-node currently relies on a
locked transitive yanked crate, so this standalone harness needs its own lockfile
just like the main workspace.

# TC-887 at-rest harness (S0)

A real `tinycloud` node on native PostgreSQL and native MinIO, plus the checks
that show what reaches storage. No Docker or containers. Everything binds
`127.0.0.1` on free ports. Each run lives in its own directory
(`~/scratch/tc887/harness-run-*`, mode 0700). `down` stops only the PIDs that
`up` recorded, and only if `/proc/<pid>/exe` is still the binary it started.

| Piece | What runs |
|---|---|
| PostgreSQL | native `initdb`/`pg_ctl` (newest `/usr/lib/postgresql/*/bin`, or `PG_BIN`), scram password auth, TCP only. Holds the node's capability DB, including `database_artifact` |
| MinIO | `minio` `RELEASE.2025-09-07T16-13-09Z`; bucket `tinycloud-blocks` is created with `mc` `RELEASE.2025-08-13T08-35-41Z` |
| Node | `target/debug/tinycloud` with `TINYCLOUD_STORAGE__DATABASE` = PG and `TINYCLOUD_STORAGE__BLOCKS__TYPE=S3` (bucket, endpoint, `AWS_*` creds, region `us-east-1`), `TINYCLOUD_KEYS__TYPE=Static` with a per-run secret |

Secrets (PG password, MinIO root credentials, node Static root) are generated
per run into `secrets/` and the 0600 files `harness.env` (read by the checks)
and `node.env` (the node's entire environment). They are never put on argv or
in logs. `state.json` (ports, PIDs, binaries, log paths, `env_file`) holds no
secrets.

## Prerequisites

- Linux x86_64, `bash`, `curl`, `python3`, Rust toolchain from `rust-toolchain.toml`.
- Native PostgreSQL server binaries (`initdb`, `pg_ctl`, `postgres`, `psql`).
  Ubuntu: `postgresql-14` or newer. Set `PG_BIN` to pick a version.
- MinIO and mc: `harness.sh bins` downloads the pinned community releases from
  their (archived) GitHub releases into `~/.cache/tc887-harness/bin` and checks
  the sha256 pinned in the script. dl.min.io no longer serves community builds
  (HTTP 410). To work offline, place binaries with the pinned sha256 there.

## Use

```sh
scripts/at-rest-harness/harness.sh up            # builds the node (nice -n 10, -j 8), prints state.json path
scripts/at-rest-harness/harness.sh test green    # the harness works: writes reach MinIO and PG (passes)
scripts/at-rest-harness/harness.sh test red      # the TC-887 at-rest property (FAILS until S3/S4)
scripts/at-rest-harness/harness.sh down --purge  # stop recorded PIDs, remove the run dir
```

`up --no-build` reuses an already-built binary (or set `TC887_NODE_BIN`).
`status` prints the state file and `logs` tails the harness logs. Commands act
on `~/scratch/tc887/harness-latest` unless `TC887_HARNESS_STATE` or an explicit
state path / run dir is given. Overrides: `TC887_SCRATCH_ROOT`, `TC887_RUN_DIR`,
`TC887_{PG,MINIO,MINIO_CONSOLE,NODE}_PORT`, `TC887_BIN_DIR`, `TC887_CARGO_JOBS`.

## Checks

`tinycloud-node-server/tests/at_rest_harness.rs`, all `#[ignore]`d so that
`cargo test --workspace` stays green. `harness.sh test` runs them with
`--ignored` and fails if the filter matched the wrong number of tests. Each
check signs in like the SDK (host SIWE delegation, then a session delegation)
on a fresh random wallet and space, and writes a unique marker through `/invoke`.

| Test | Asserts | Today |
|---|---|---|
| `green_kv_put_reaches_minio` | the KV put round-trips through the node and adds a non-empty object to the bucket | pass |
| `green_sql_write_reaches_postgres` | create + insert + insert round-trips, and a `database_artifact` row with a payload exists | pass |
| `red_kv_blocks_are_sealed_in_minio` | no raw object contains the marker; no object key contains the space id or wallet address | **fail**: key is `{space}/{b64url(blake3)}`, body is plaintext |
| `red_sql_artifacts_are_sealed_in_postgres` | `payload` doesn't start with `SQLite format 3\0`; neither `payload` nor `delta_payload` contains a marker | **fail**: plaintext SQLite checkpoint/WAL |

The RED checks also run the green precondition first, so a RED result is never
a harness no-op.

## Not covered

The dstack simulator (`DSTACK_SIMULATOR_ENDPOINT`). No native simulator is
installed here, so the node runs with a per-run Static root; S1 adds a
Dstack-root variant.

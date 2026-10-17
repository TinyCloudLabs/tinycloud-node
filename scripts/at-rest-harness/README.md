# TC-887 at-rest harness (S0)

A real `tinycloud` node on native PostgreSQL and native MinIO, plus the checks
that show what reaches storage. No Docker or containers. Everything binds
loopback on free ports. Each run lives in its own directory
(`$TC887_SCRATCH_ROOT/harness-run-*`, default `~/scratch/tc887`, mode 0700).
Every process the harness starts leads its own process group (`setsid`; the
postmaster calls `setsid` itself). The state file records each PID with its
kernel start time, and `down` signals only those groups.

| Piece | What runs |
|---|---|
| PostgreSQL | native `initdb`/`pg_ctl` (newest `/usr/lib/postgresql/*/bin`, or `PG_BIN`), scram password auth, TCP only. Holds the node's capability DB, including `database_artifact` |
| MinIO | `minio` `RELEASE.2025-09-07T16-13-09Z`; bucket `tinycloud-blocks` is created with `mc` `RELEASE.2025-08-13T08-35-41Z` |
| Node | a copy of `target/debug/tinycloud` with `TINYCLOUD_STORAGE__DATABASE` = PG, `TINYCLOUD_STORAGE__BLOCKS__TYPE=S3` (bucket, endpoint, `AWS_*` creds, region `us-east-1`), `TINYCLOUD_STORAGE__SQL__MEMORY_THRESHOLD=0` (file-backed SQL, so writes after the first checkpoint are saved as WAL deltas), and `TINYCLOUD_KEYS__TYPE=Static` with a per-run secret |

Secrets (PG password, MinIO root credentials, node Static root) are generated
per run into `secrets/` and the 0600 files `harness.env` (read by the checks)
and `node.env` (the node's entire environment). They are never put on argv or
in logs. `state.json` (ports, PIDs and start times, binaries, log paths,
`env_file`, at-rest settings) holds no secrets.

## Prerequisites

- Linux x86_64 (the pinned MinIO/mc are linux-amd64; other hosts are refused), `bash`, `curl`, `python3`, and the Rust toolchain from `rust-toolchain.toml`.
- Native PostgreSQL server binaries (`initdb`, `pg_ctl`, `postgres`, `psql`).
  Ubuntu: `postgresql-14` or newer. The version is not pinned: the harness uses
  the newest one installed, or `PG_BIN`.
- MinIO and mc: `harness.sh bins` downloads the pinned community releases from
  their (archived) GitHub releases into `~/.cache/tc887-harness/bin` and checks
  the sha256 pinned in the script. dl.min.io no longer serves community builds
  (HTTP 410). To work offline, place binaries with the pinned sha256 there.

## Use

```sh
STATE=$(scripts/at-rest-harness/harness.sh up)    # builds the node (nice -n 10, -j 8); prints the state path last
scripts/at-rest-harness/harness.sh test green "$STATE"            # writes reach MinIO and PG (passes)
scripts/at-rest-harness/harness.sh test red --expect red "$STATE" # exit 0 only if both RED checks (kv, sql) fail as RED
scripts/at-rest-harness/harness.sh down --purge "$STATE"          # stop this run's processes, remove its dir
```

Every command after `up` needs the explicit `STATE` (the state.json path or its
run dir). Nothing defaults to a "latest" run, so concurrent runs on a shared
host can't act on each other.

- `up --no-build` reuses an already-built binary (or set `TC887_NODE_BIN`).
- If `up` fails, times out (SIGTERM) or is interrupted (SIGINT), it stops
  every process it started. It keeps the run dir with its logs; remove it with
  `down --purge`. A SIGKILL of `up` can't be trapped: then run `down STATE`
  (the state file is written after each start).
- `status STATE` prints the state file and `logs STATE` tails the logs.
- Overrides: `TC887_SCRATCH_ROOT`, `TC887_RUN_DIR` (must be named
  `harness-run-*`), `TC887_{PG,MINIO,MINIO_CONSOLE,NODE}_PORT`, `TC887_BIN_DIR`,
  `TC887_CARGO_JOBS`, `TC887_NODE_READY_SECS`.
- Ports are picked by binding port 0 and releasing it, so another process can
  take one before the harness does. A collision makes `up` fail cleanly; it
  can't produce a false green, because the checks talk to MinIO and PG directly.

`test` runs each check (`kv`, `sql`) on its own and compares each with its
expectation. `--expect` takes `green` or `red` (both checks) or a per-check
list such as `kv=green,sql=red`; a check left out keeps its default. `test`
exits 0 only if every check matches:

| Exit | Meaning |
|---|---|
| 0 | every check as expected (`KV RED as expected` … / `RED as expected: both …`) |
| 3 | a check didn't match: `KV red check UNEXPECTEDLY PASSED under expect kv=red`, or `KV red check still RED … but expected kv=green` (per check) |
| 4 | a check errored: compile failure, harness failure, a precondition (`harness no-op`/`harness gap`) or a node error, i.e. not a RED finding (per check; wins over 3) |

Defaults: `test green` expects `kv=green,sql=green`. `test red` expects
`kv=red,sql=red`, or `kv=green,sql=red` if the run was started with
`TC887_AT_REST_MODE=encrypt` or `strict`, because S3 seals KV before S4 seals
SQL. When S4 lands, the SQL default flips to green (`default_expect` in
`harness.sh`). CI runs `test red --expect red` until S3 lands.

## At-rest mode

The names are S1's (key continuity). They are defined in one marked block at
the top of `harness.sh`:

| Harness env (at `up`) | Node env written to `node.env` |
|---|---|
| `TC887_AT_REST_MODE` (`off`/`encrypt`/`strict`) | `TINYCLOUD_AT_REST__MODE` |
| `TC887_AT_REST_ESCROW_NONE` (`true`/`false`: the Static self-host acknowledgement that no escrow exists, plan §5) | `TINYCLOUD_AT_REST__ESCROW_NONE` |

If either is unset, the harness sets nothing and the node runs its default
(today: no encryption at rest). Other values are refused before anything
starts. The simplest encrypting node is the harness's Static root plus
`TC887_AT_REST_MODE=encrypt TC887_AT_REST_ESCROW_NONE=true`.

## Checks

`tinycloud-node-server/tests/at_rest_harness.rs`. The harness checks are
`#[ignore]`d, so `cargo test --workspace` stays green. `harness.sh test` runs
them with `--ignored` and checks the count and the outcome. Each check signs in
like the SDK (host SIWE delegation, then a session delegation) on two fresh
random wallets and spaces, and writes the same plaintext into both through
`/invoke`:
- a short value carrying a unique marker;
- a 64 KiB value of the marker repeated, which compresses well.

SQL runs the same two batches in both spaces: create + insert (a checkpoint),
then insert (a WAL delta).

| Test | Asserts | Today |
|---|---|---|
| `green_kv_put_reaches_minio` | every put round-trips through the node and adds a non-empty object to the bucket | pass |
| `green_sql_write_reaches_postgres` | the writes round-trip, and `database_artifact` has a `payload` and a non-NULL `delta_payload` | pass |
| `red_kv_blocks_are_sealed_in_minio` | object keys contain no space id, wallet address or blake3 fingerprint of the value (b64url padded/unpadded, base64 padded/unpadded, hex; raw digest and multihash); raw bytes hold no marker; each put's objects together are at least as large as the value; the 64 KiB object doesn't compress (zlib ratio > 0.95); every object of a put in one space shares no 32-byte run with every object of the same put in the other (equal object counts required) | **fail** |
| `red_sql_artifacts_are_sealed_in_postgres` | `payload` doesn't start with `SQLite format 3\0` and `delta_payload` doesn't start with the WAL magic; neither holds a marker, compresses (ratio > 0.95) or is smaller than the 64 KiB value it holds; the two spaces' payloads and deltas share no 32-byte run | **fail** |

The RED checks re-run the green preconditions first, so a RED result is never
a harness no-op. The 32-byte limit: two sealed blobs of the same plaintext
share only fixed TCE1 header fields (≤ 20 contiguous bytes), while any
deterministic transform (encoding, XOR, compression, an unsalted cipher) keeps
runs as long as the data. The reasoning is in the test's `MAX_SHARED_RUN` doc.
The size floor holds because TCE1 never shrinks data. It catches strong
compressors (xz, bz2) whose output neither compresses further nor repeats
across writes once a per-write salt (SQLite's WAL salts) is mixed in.
`selftest_predicates_flag_deterministic_transforms_not_ciphertext` runs in plain
`cargo test` and checks the predicates offline: base64, XOR and zlib are
flagged, a salted deflate-9 blob is flagged by the size floor, and sealed-like
random blobs pass.

## Not covered

- The dstack simulator (`DSTACK_SIMULATOR_ENDPOINT`). No native simulator is
  installed here, so the node runs with a per-run Static root; S1 adds a
  Dstack-root variant.
- DuckDB artifacts (`service=duckdb`, an opt-in feature): S4 follow-up.

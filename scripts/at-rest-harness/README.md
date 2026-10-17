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
| `red_kv_blocks_are_sealed_in_minio` | object keys contain no identity of any space the harness created (space id or wallet address: raw, lowercase, hex, base64 and base64url at any alignment, of the text and of the bytes) and no blake3 fingerprint of the value (b64url padded/unpadded, base64 padded/unpadded, hex; raw digest and multihash); raw bytes hold no marker; each put's objects together are at least as large as the value; the 64 KiB object doesn't compress (zlib ratio > 0.95); every object of a put in one space shares no 32-byte run with every object of the same put in the other (equal object counts required); every `_tc/` key-mirror object passes the checks below | **fail** |
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

### At-rest key mirror (`_tc/…` objects)

With at-rest keys on, the node writes control objects next to its blocks. The
KV RED check reads them twice: from the boot snapshot `up` saves
(`boot-snapshot/`, before any test write) and from the bucket after its puts.
Every one must pass all of these, or the check is RED:

- **Name.** Exactly one of `_tc/at-rest/ark-<generation, 10 digits>-<ark id,
  32 lowercase hex>.json`, `escrow-<EFP, 64 hex>.json`, `record-<EFP, 64
  hex>.json` or `dek-<tag, 32 hex>-<data key id, 10 digits>.json`, numbers ≥ 1.
  Any other `_tc/` object is RED.
- **Typed schema** per kind (S1's `MirroredArk`, `MirroredDek`,
  `EscrowBundle`, `VerificationRecord`): exactly the fields, integers as
  integers, `created_at`/`verified_at` strict RFC 3339 (≤ 35 chars), ids as
  exact lowercase hex, `sealed`/`chain`/`wrapped` as canonical base64 of 60
  bytes, escrow shares as armored age files and bech32 recipients, and no TEE
  identity in a record (the harness node has none). Duplicate keys are refused.
- **Raw-key scan** over every JSON key and every string outside those exact
  fields: nothing that decodes (hex, base64, base64url, base32, padded or
  not, whitespace and prefixes like `0x`, any short `label:`, data URLs
  removed) to 32 bytes or more, no array of 32 byte values, no two fields of
  16 bytes each (escrow holder names, which the schema checks exactly and
  which can be 16-byte-looking, are left out of that split check).
- **Content.** The same identity, fingerprint and marker scans as blocks,
  over the name and the text.
- **Authentic key material.** The check reads the node's Static root
  (`secrets/node-static-secret`, never printed) and re-derives the hierarchy
  from S1's spec: every sealed ARK opens under W, each older generation's
  chain opens under the next, every wrapped DEK opens under KEK_g with its
  AAD, its tag mapped to a space the harness signed in to (`spaces.log`). An
  escrow bundle's canary and EFP and a record's MAC are recomputed. A raw key
  padded to 60 bytes fails here. ARK generations are unbounded in the node
  (`rotate_ark` makes g+1; the 1..=9 in INTERFACES is the TCE *format*
  generation, not this). The harness applies its own sanity cap of 1,000 so
  an absurd name like `ark-4294967295-…` fails RED at once, and a gap is one
  finding: a name never sets a loop bound.
- **No derived secret anywhere.** No string of any mirror (exempt fields,
  escrow commitments, holder names alone, joined in every order with or
  without `-`/`_` separators and shifted by up to 7 characters, the armored
  share text and its decoded payload as bytes and as text, the data of a
  bech32 recipient, record fields) may carry, in any of the encodings above,
  a secret the harness derived or unwrapped: the root, W, each ARK_g, KEK_g,
  chain, canary and record-MAC key, NK, the DEK mirror tag key, or any DEK.
  The same goes for every block, in every mode:
  - its raw bytes, searched whole;
  - its name (the whole name, every `/` segment) and its bytes read as text:
    hex in any case and base64/base64url at any alignment (padded or not),
    and decoded as hex, base64, base64url (padded or not), base32 and bech32
    data after removing whitespace and a `0x`, `\x`, short `label:` or
    `data:…;base64,` prefix, shifted by 0 to 7 characters. This decoding
    is applied to the whole text and to every run of 32 or more characters
    from those alphabets (so a key encoded inside ciphertext or other text
    is found).
- **No piece of a secret in a TCE1 salt.** The salt (header bytes 20..52) is
  the only free field of a sealed block. No block's salt may hold any 16-byte
  window of any of those secrets: a truncated key (31 bytes and one other
  byte) and a key split across two blocks' salts (one half in each) are both
  RED. A random salt matches with probability about 2^-120 per secret.
- **Escrow-none.** If `up` started the node with `TC887_AT_REST_ESCROW_NONE=true`,
  any escrow bundle or record object is RED.
- **Mirrors required, blocks tied to them (encrypt/strict mode).** An ARK
  mirror must exist. Every block must be named
  `v1/<22-char space tag>/<43-char object>`; its space tag (from the
  re-derived NK) must belong to a harness space with an authenticated DEK
  mirror; it must parse as TCE1 with a header `dek_id` that is one of those
  DEKs; its name must be the sealed name of a put the harness logged
  (`puts.log`: space and content hash); and it must open under that DEK, with
  AAD (space, content hash), to bytes whose blake3 is that content hash.
  (The TCE1 header carries no ARK generation; the DEK mirror does.)

Out of scope for a regression harness, one line each:
- Escrow share commitments and age-encrypted shares can't be opened without
  the holders' keys, so key material the harness didn't derive can hide there.
- A key split across two commitments, or XOR'd with anything, isn't found.
- A piece of a secret (fewer than 32 bytes) is only looked for in TCE1 salts;
  everywhere else only whole secrets are matched.
- Separators other than `-`/`_` inside holder names, shifts of more than 7
  characters, and splits across fields other than holder names aren't
  rejoined.
- Secrets in encodings other than hex, base64, base64url, base32 and bech32
  data (e.g. base58, decimal, a custom alphabet) aren't decoded.
- A secret encrypted or hashed under something the harness doesn't know is
  indistinguishable from random bytes.

`selftest_key_hierarchy_reference_vectors` (RFC 5869 vectors, seal/open
round trips, every one-bit flip and wrong binding rejected),
`selftest_key_mirror_accepts_s1_shaped_mirrors`,
`selftest_key_mirror_flags_every_bypass` (one case per rule and per known
bypass), `selftest_key_mirror_refuses_escrow_contents_and_derived_keys`,
`selftest_key_mirror_bounds_absurd_generations`,
`selftest_key_mirror_requires_mirrors_in_encrypt_mode`,
`selftest_blocks_open_under_their_mirrored_dek`,
`selftest_blocks_carry_no_derived_secret` and
`selftest_salts_hold_no_piece_of_a_secret` run in plain `cargo test`.

## Not covered

- The dstack simulator (`DSTACK_SIMULATOR_ENDPOINT`). No native simulator is
  installed here, so the node runs with a per-run Static root; S1 adds a
  Dstack-root variant.
- DuckDB artifacts (`service=duckdb`, an opt-in feature): S4 follow-up.

# Renewal scheduler HTTP harness

This opt-in harness runs the real node binary, HTTP routes, scheduler, migrations,
and stamp verifier. It creates temporary file-backed SQLite storage and, when
configured, an isolated schema on PostgreSQL **16**. Synthetic keys are test data.
It neither inserts renewal rows nor calls an issuance helper.

From the repository root:

```sh
export CARGO_TARGET_DIR="$PWD/target/renewal-scheduler"
cargo test --locked -p tinycloud-node --features renewal-test-clock \
  --test renewal_scheduler_e2e -- --nocapture
```

To include an isolated local PostgreSQL 16 instance:

```sh
docker run --rm -d --name renewal-test-pg16 \
  -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:25432:5432 postgres:16-alpine
export TINYCLOUD_TEST_POSTGRES_URL=postgres://postgres@127.0.0.1:25432/postgres
export TINYCLOUD_ALLOW_LOCAL_PG=1
cargo test --locked -p tinycloud-node --features renewal-test-clock \
  --test renewal_scheduler_e2e -- --nocapture
docker stop renewal-test-pg16
```

The test registers an owner-signed original and proofless exact-CID lease over
`POST /delegate`. At original half-life, the running scheduler signs and admits
an extension. After the original signed expiry, `POST /delegation/status` must
report active authority, the extended effective expiry, and signed history. At
the next due threshold the lease expiry caps the stamp. After the lease expires,
status must be expired and no additional stamp may appear. STOP is not covered
until its separate public control contract lands.

## Using the node from the SDK

Build the same test binary with `cargo build -p tinycloud-node --features
renewal-test-clock`. Start it with a private data directory, a synthetic static
node key, and a loopback-only address/unused port in your normal node config.
Set `TINYCLOUD_CONFIG_FILE` to that configuration and
`TINYCLOUD_RENEWAL_TEST_CLOCK` to an absolute filename containing Unix seconds.
The integration test shows the exact config and signed wire profile. Never use
this feature build or synthetic identity for a deployed node.

The optional file clock controls renewal selection, registration, stamp
admission and status evaluation. It also polls the real scheduler every 25 ms;
there is no HTTP clock/issuance endpoint. Both changes require the explicit
`renewal-test-clock` Cargo feature **and** clock environment variable. Without
that variable, cadence is 300 seconds and the clock is wall time, including in
a feature build. The feature requires debug assertions; release builds fail at
compile time, and container builds reject it in the feature arguments.

Advance monotonically by atomically renaming a new file over the clock file:

```sh
printf '%s\n' "$NEXT_UNIX_SECONDS" > "$CLOCK_FILE.next"
mv "$CLOCK_FILE.next" "$CLOCK_FILE"
```

Register while the original is live, advance to half-life and poll normal
holder-authorized status until a signed stamp appears, then advance past original
expiry while staying before its admitted end. Scheduler admission refuses a
lapsed original: jumping straight past expiry cannot revive it. Keep ordinary
HTTP authentication envelopes valid under wall time too; this narrow seam does
not replace all node authentication clocks. Use a separate private home, port,
and data directory for each SDK scenario. Stop only your own node process.

The runtime baseline is main `7684febe62242b603d09c662692954423c2235c0`,
including proofless owner-lease registration (#554), consistent status snapshots
(#556), holder-visible original-bound history (#559), and fractional SIWE expiry
comparisons (#561). No SDK restore/read claim follows from this status test; the
SDK scenario must independently verify admitted authority and perform its ordinary
read.

Status reads use the original holder's proofless signature. CI exports only
public synthetic stamp fixtures as `renewal-scheduler-history-sdk` for the SDK
verifier, at a captured time after the original signed expiry.

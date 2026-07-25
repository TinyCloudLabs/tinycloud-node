# TC-268 Baseline

Reproducible local smoke baseline:

1. Start the signer:

   ```bash
   cargo run --manifest-path test/load/signer/Cargo.toml
   ```

2. Run the row through the TC-268 wrapper, pointing it at the live control manifest:

   ```bash
   TC268_SMOKE=1 \
   TC268_ROW_INDEX=0 \
   TC268_RATE=10 \
   TC268_WARMUP_SECONDS=20 \
   TC268_MEASURE_SECONDS=60 \
   TC268_MIN_SAMPLES=250 \
   TC268_CONTROL_JSON=/path/to/runtime/control.json \
   node test/load/k6/tc268-runner.mjs test/load/k6/json_put.js
   ```

   ```bash
   TC268_SMOKE=1 \
   TC268_ROW_INDEX=0 \
   TC268_RATE=10 \
   TC268_WARMUP_SECONDS=20 \
   TC268_MEASURE_SECONDS=60 \
   TC268_MIN_SAMPLES=250 \
   TC268_CONTROL_JSON=/path/to/runtime/control.json \
   node test/load/k6/tc268-runner.mjs test/load/k6/json_get.js
   ```

Row-specific node config overlay:

```bash
TC268_ROW_INDEX=0 \
TC268_STORAGE_DATADIR=/tmp/tc268-row-0 \
node test/load/k6/tc268-node-config.mjs --row-index 0 > /tmp/tc268-row-0.toml
cargo run --manifest-path tinycloud-node-server/Cargo.toml -- serve --config /tmp/tc268-row-0.toml &
TC268_CONTROL_JSON=/path/to/runtime/control.json \
TC268_ROW_INDEX=0 \
TC268_RATE=10 \
TC268_WARMUP_SECONDS=20 \
TC268_MEASURE_SECONDS=60 \
TC268_MIN_SAMPLES=250 \
node test/load/k6/tc268-runner.mjs test/load/k6/json_put.js
```

For a postgres/S3 row, add the row-matching backend inputs before generating the overlay:

```bash
TC268_ROW_INDEX=7 \
TC268_STORAGE_DATADIR=/tmp/tc268-row-7 \
TC268_POSTGRES_DATABASE_URL='postgres://user:password@db.example/share?sslmode=verify-full' \
TC268_S3_BUCKET='tinycloud-blocks' \
TC268_S3_ENDPOINT='http://localhost:4566' \
node test/load/k6/tc268-node-config.mjs --row-index 7 > /tmp/tc268-row-7.toml
cargo run --manifest-path tinycloud-node-server/Cargo.toml -- serve --config /tmp/tc268-row-7.toml &
TC268_CONTROL_JSON=/path/to/runtime/control.json \
TC268_ROW_INDEX=7 \
TC268_RATE=10 \
TC268_WARMUP_SECONDS=20 \
TC268_MEASURE_SECONDS=60 \
TC268_MIN_SAMPLES=250 \
node test/load/k6/tc268-runner.mjs test/load/k6/json_put.js
```

Full matrix example:

```bash
TC268_POSTGRES_DATABASE_URL='postgres://user:password@db.example/share?sslmode=verify-full' \
TC268_S3_BUCKET='tinycloud-blocks' \
TC268_S3_ENDPOINT='http://localhost:4566' \
node test/load/k6/tc268-matrix-runner.mjs test/load/k6/json_put.js

TC268_POSTGRES_DATABASE_URL='postgres://user:password@db.example/share?sslmode=verify-full' \
TC268_S3_BUCKET='tinycloud-blocks' \
TC268_S3_ENDPOINT='http://localhost:4566' \
node test/load/k6/tc268-matrix-runner.mjs test/load/k6/json_get.js
```

`tc268-matrix-runner.mjs` starts a row-matching TinyCloud node for each matrix
row, waits for `dataPath/runtime/control.json`, validates the live `/v1/config`
snapshot against the selected row, and only then invokes `tc268-runner.mjs`.
`selectTc268MatrixRow()` fails closed on out-of-range indexes, so a misindexed
row cannot silently fall back to row 0.

Separate unrelated failure:

- `cargo test -p tinycloud-core share_email::authority -- --nocapture` still fails in this workspace because the `share/feat/email-claim-e1-e2e/test/vectors/email-claim-v1/positive.json` fixture is missing. That failure is unrelated to TC-268 and is intentionally left intact.

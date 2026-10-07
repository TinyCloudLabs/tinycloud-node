# TC-780 SQL/DuckDB identity cutover

Production uses `deploy-phala` and `docker-compose.dstack-postgres.yaml`: the
metadata and durable SQL/DuckDB artifacts are in external Postgres. There is
no data volume. The `FROM scratch` image has no shell, Cargo, SQLite CLI, or
migration CLI. Build `tinycloud-sql-identity` from the reviewed N3 commit on
a trusted operator host with
`cargo build --locked -p tinycloud-node --features duckdb --bin tinycloud-sql-identity`.
Give that host TLS/network access to Postgres and obtain the same database
URL as `PROD_TINYCLOUD_DATABASE_URL` from the secret manager. Export it as
`TC780_DATABASE_URL` without printing it or putting it in shell history.
The examples use `TC780_CLI=target/debug/tinycloud-sql-identity` and
`TC780_DATADIR=$(mktemp -d)`; production has no local cache directory.

## 1. Prevent an unfenced deploy

Keep repository variable `TC780_CUTOVER_READY` unset. Do not merge a version
bump or push a `v*` tag before step 6: `release-plz.yml` can tag a main
push, and `docker.yml` builds on `v*`. The N3 workflow gates image
publishing (including `latest`) on that variable and permits Phala deploy
only through manual `workflow_dispatch` with `deploy_phala=true`. Keep this
gate closed until aliases are installed. Self-hosters on `latest` are
automatically fenced while unmigrated legacy artifacts exist and must run
their own cutover.

## 2. Fence

The old binary cannot honor the N3 fence. From an authorized workstation,
run `phala ssh tinycloud-node`. On the CVM host, identify and stop only the
tinycloud compose service:

```sh
docker ps --filter label=com.docker.compose.service=tinycloud --format '{{.ID}}'
docker ps --filter label=com.docker.compose.service=tinycloud --quiet | xargs -r docker stop
```

Confirm exactly one production node was selected and public `/invoke` is
unavailable. There is no ingress 503 rule in this topology. A manually
stopped `restart: unless-stopped` container stays stopped until redeploy.
Never restart the old binary after the N3 migration ledger entry is written.

## 3. Drain and checkpoint

Wait for in-flight requests to finish and confirm the node and its database
actors are stopped. Postgres commits durable artifacts on every write.
Production has no SQLite/DuckDB cache volume to checkpoint. For a self-hosted
file-backed node, stop it and checkpoint its SQLite metadata database with
`sqlite3 /path/to/data/caps.db 'PRAGMA wal_checkpoint(TRUNCATE);'`. Keep SQL
and DuckDB cache files and their `.db-wal`, `.db-shm`, and `.duckdb.wal`
files together. After the pre-migration backup in step 4, run `fence on`
and the N3 CLI `checkpoint` command while the server remains stopped.

## 4. Back up

Before **any** N3 metadata mutation, back up the full Postgres database,
including migration ledger, artifacts, grants, and invocation history:

```sh
pg_dump --dbname="$TC780_DATABASE_URL" --format=custom --no-owner \
  --file="tc780-pre-cutover-$(date -u +%Y%m%dT%H%M%SZ).dump"
```

Record the filename and SHA-256 checksum. A self-hoster backs up the entire
stopped data directory, including WAL and checkpoint files. Rollback to the
old binary requires this **full pre-migration** backup.

## 5. Inventory and dry-run

Restore the backup to a separate scratch Postgres database and set
`TC780_SNAPSHOT_URL` to that database URL. Dry-run is read-only and must
target the copy:

```sh
"$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_SNAPSHOT_URL" \
  dry-run > tc780-inventory.json
```

For file-backed installations, copy `caps.db`, `sql/`, and `duckdb/`
together and use that directory without `--database`. The JSON report
includes service, space, physical name, candidate paths, classification,
collision, table names, schema hashes, and row counts. Dry-run exits nonzero
for exactly the identity validation that apply performs, including a unique
SQL legacy name containing `..` or `\`. Resolve collisions and cache-only
artifacts before proceeding. Keep the report immutable for offline verify.

## 6. Alias transaction

Keep the old node stopped. On the operator host run:

```sh
"$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" fence on
"$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" apply > tc780-applied.json
"$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" report > tc780-aliases.json
```

`fence on` creates the N3 tables and persists the fence in metadata. Every
mutating CLI command checks it. `apply` inventories and writes quarantine
and unique alias rows in one transaction, refuses digest collisions, and
never renames artifact files or modifies checkpoint/WAL columns. It can be
retried. Ambiguous and unattributed artifacts remain quarantined; every
candidate path rejects `/invoke`, including writes, until an authorized
mapping exists. Keep owner approval, then run
`set <sql|duckdb> <space> <physical> --path <logical-path> --authorized`
(or `--pathless`). `clear <service> <space> --path <logical-path>` removes
an alias only while fenced.

## 7. Deploy N3 while fenced

Merge the reviewed stack only after step 6. Set `TC780_CUTOVER_READY=true`.
Manually dispatch `docker.yml` at the reviewed ref with
`deploy_phala=true`, `sql_identity_fence=true`, and
`include_duckdb=true` if DuckDB is used. The workflow passes
`SQL_IDENTITY_FENCE=true` into the Phala compose file, so
`TINYCLOUD_DATABASE__WRITE_FENCE=true` is set before `/tinycloud` starts.
Confirm `/version` converges. Do not use a `v*` auto-deploy.

## 8. Restart verification

Confirm the restarted node's SQL/DuckDB `/invoke` returns 503. Offline,
compare **every** aliased artifact with the immutable pre-cutover report:

```sh
"$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" \
  verify --baseline tc780-inventory.json > tc780-verified.json
```

`verify` loads durable artifacts into temporary local database files and
compares table lists, schema hashes, and row counts. It needs no end-user
signing keys. Verify an authorized web `/invoke` smoke case on a staging
clone, then run the production smoke case immediately after step 9.

## 9. Unfence

Run `fence off` against production Postgres while the deployed binary
still has `TINYCLOUD_DATABASE__WRITE_FENCE=true`. Manually dispatch
`docker.yml` again at the same reviewed ref with `deploy_phala=true`
and `sql_identity_fence=false`. This redeploy restarts the container with
the fence disabled. Confirm existing web data loads by `/invoke` at its
original full logical path with an authorized test client; unresolved paths
return 409; writes work. Monitor errors and new digest artifacts.

After the observation window, restore normal release behavior in a separate
reviewed PR: remove the temporary `TC780_CUTOVER_READY` publishing gate
and restore the `v*` `deploy-phala` trigger in `docker.yml`. Merge it
only after Phala and self-hosted migrations are verified and communicated.

## Rollback

Stop the N3 container as in step 2, or redeploy with
`sql_identity_fence=true` and confirm 503 before restore. Back up the N3
state for investigation. Restore the **entire** pre-cutover metadata backup
while stopped:

```sh
pg_restore --dbname="$TC780_DATABASE_URL" --clean --if-exists --no-owner \
  tc780-pre-cutover-YYYYMMDDTHHMMSSZ.dump
```

Then redeploy the old pinned image. Clearing aliases is **not** a rollback:
the old binary does not recognize the N3 migration ledger entry and fails at
boot. For file-backed nodes restore the complete metadata and cache backup
together. After N2 digest identities accept writes, the old binary cannot
read or merge them; restoring the backup discards those writes. Reconcile
them separately before rollback.

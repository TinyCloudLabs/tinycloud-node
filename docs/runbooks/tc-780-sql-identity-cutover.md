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

## Preflight: production snapshot dry-run (no outage)

Complete this final N3 acceptance check before scheduling the outage. A
normal `pg_dump` takes a consistent snapshot of the live external Postgres
database without stopping the node. Restore it into an **empty local
Postgres database**; never run the CLI's dry-run against production:

```sh
export TC780_SNAPSHOT_DUMP=tc780-production-snapshot.dump
export TC780_SNAPSHOT_DATADIR="$(mktemp -d)"
export TC780_SNAPSHOT_DB="tc780_cutover_$(date -u +%Y%m%dT%H%M%SZ)"
createdb "$TC780_SNAPSHOT_DB"  # using the operator host's local Postgres credentials
export TC780_SNAPSHOT_URL="postgresql://localhost/$TC780_SNAPSHOT_DB"
pg_dump --dbname="$TC780_DATABASE_URL" --format=custom --no-owner \
  --file="$TC780_SNAPSHOT_DUMP"
pg_restore --dbname="$TC780_SNAPSHOT_URL" --no-owner "$TC780_SNAPSHOT_DUMP"
"$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" \
  --database "$TC780_SNAPSHOT_URL" dry-run > tc780-inventory.json
"$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" \
  --database "$TC780_SNAPSHOT_URL" report > tc780-preflight-report.json
```

Production stores artifact bytes in Postgres and has no separate node data
volume. If an installation has a separate `sql/` or `duckdb/` artifact
store, take a consistent filesystem snapshot and copy it under
`$TC780_SNAPSHOT_DATADIR` with `rsync -a "$TC780_ARTIFACT_STORE"/
"$TC780_SNAPSHOT_DATADIR"/` before the CLI commands. The local snapshot
database must include `database_artifact`, grants and invocation history.
Inspect and retain both JSON reports; resolve collisions and invalid names.
Time the dump, restore and dry-run. Use those measured durations to size the
maintenance window; do not run a first full inventory during the outage.

## 1. Prevent an unfenced deploy and stage the image (no outage)

Merge the reviewed N3 stack and wait for CI and the version tag **before**
stopping the old node. `release-plz.yml` can tag a main push; `docker.yml`
builds on `v*`, but the N3 `deploy-phala` job runs only on manual dispatch.
The temporary repository variable gates image publishing, including
`latest`. Set it for the build after confirming the manual-only deploy gate.
Self-hosters who pull N3 `latest` automatically fence SQL/DuckDB while
unmigrated legacy artifacts exist.

Use a **new** release-plz `vX.Y.Z` tag containing the final approved N3
commit. The existing `v1.16.1` tag predates this cutover and must not be
used. The example below assumes the DuckDB-enabled production image; use
`include_duckdb=false` and omit `-duckdb` from the image tag only if
production has no DuckDB artifacts.

```sh
export TC780_REF="vX.Y.Z"  # replace with the new reviewed release-plz tag
export TC780_APPROVED_SHA="<final-reviewed-N3-commit>"
export TC780_VERSION="${TC780_REF#v}"
git fetch origin --tags
git merge-base --is-ancestor "$TC780_APPROVED_SHA" "$TC780_REF"
test "$(git show "${TC780_REF}:tinycloud-node-server/Cargo.toml" |
  sed -n -E 's/^version = "([^"]+)"/\1/p' | head -1)" = "$TC780_VERSION"
gh variable set TC780_CUTOVER_READY --body true
gh workflow run docker.yml --ref "$TC780_REF" \
  -f deploy_phala=false -f sql_identity_fence=true \
  -f include_duckdb=true -f image_version="$TC780_VERSION"
gh run list --workflow docker.yml --limit 5
export TC780_BUILD_RUN_ID="<build-run-id-from-list>"
gh run watch "$TC780_BUILD_RUN_ID" --exit-status
export TC780_IMAGE="ghcr.io/tinycloudlabs/tinycloud-node:${TC780_VERSION}-dstack-duckdb"
export TC780_DIGEST="$(docker buildx imagetools inspect "$TC780_IMAGE" |
  awk '$1 == "Digest:" { print $2; exit }')"
case "$TC780_DIGEST" in sha256:????????????????????????????????????????????????????????????????) ;; *) exit 1 ;; esac
docker pull "ghcr.io/tinycloudlabs/tinycloud-node@$TC780_DIGEST"
test "$(docker image inspect "ghcr.io/tinycloudlabs/tinycloud-node@$TC780_DIGEST" \
  --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')" = \
  "$(git rev-list -n 1 "$TC780_REF")"
```

Record the digest and verify the pulled image's
`org.opencontainers.image.revision` label equals the commit at
`$TC780_REF`. Keep that ref and digest unchanged through steps 7 and 9.
The deploy workflow accepts `prebuilt_dstack_digest`, skips its Docker
builds, and still checks the digest's revision against the selected ref.

**Outage budget:** the **entire node, including KV**, is unavailable from
step 2 until the fenced N3 node starts in step 7. If merge and CI build
happened after step 2, they would extend that outage; they are completed
here. These are planning allowances, not measured production timings;
replace the data-size-dependent ranges with the preflight rehearsal results.

| Step | Estimated time | Whole-node outage? |
| --- | --- | --- |
| Preflight snapshot, restore, dry-run | 15–60 minutes, measure the data-sized work | No |
| 1. Merge, CI, tag, build/push image | 20–60 minutes | No |
| 2. Stop old node | 1–2 minutes | Starts here |
| 3. Drain/checkpoint | 1–3 minutes | Yes |
| 4. Full backup | 5–20 minutes, replace with measured dump time | Yes |
| 5. Review inventory | 1–2 minutes | Yes |
| 6. Alias transaction | 5–20 minutes, replace with measured dry-run time | Yes |
| 7. Deploy staged image | 5–10 minutes | Ends when healthy |
| 8. Offline verify | 5–20 minutes | No; SQL/DuckDB fenced |
| 9. Unfence redeploy | 5–10 minutes | No; SQL/DuckDB fenced until complete |

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

## 5. Confirm the reviewed inventory

Confirm the backup succeeded and the preflight `tc780-inventory.json` and
`tc780-preflight-report.json` were approved. Their classifications, table
lists, schema hashes, row counts, and collision checks came from the copied
production snapshot. Do not repeat the full dry-run while the node is down.
If material legacy data appeared since the snapshot, stop and repeat the
preflight procedure before applying aliases. For a file-backed installation,
back up `caps.db`, `sql/`, and `duckdb/` together, including WAL files.

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

## 7. Deploy the prebuilt N3 image while fenced

The reviewed image was built and pushed in step 1. Deploy its immutable
digest without another Docker build:

```sh
gh workflow run docker.yml --ref "$TC780_REF" \
  -f deploy_phala=true -f sql_identity_fence=true \
  -f include_duckdb=true -f image_version="$TC780_VERSION" \
  -f prebuilt_dstack_digest="$TC780_DIGEST"
```

Watch the deployment run to completion. The workflow passes
`SQL_IDENTITY_FENCE=true` into the Phala compose file, so
`TINYCLOUD_DATABASE__WRITE_FENCE=true` is set before `/tinycloud` starts.
Confirm `/version` converges. Do not use a `v*` auto-deploy.
The whole-node/KV outage ends when this fenced N3 node is healthy.

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
still has `TINYCLOUD_DATABASE__WRITE_FENCE=true`. Redeploy the same
prebuilt digest with the fence input off:

```sh
"$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" fence off
gh workflow run docker.yml --ref "$TC780_REF" \
  -f deploy_phala=true -f sql_identity_fence=false \
  -f include_duckdb=true -f image_version="$TC780_VERSION" \
  -f prebuilt_dstack_digest="$TC780_DIGEST"
```

Watch the deployment run to completion. This redeploy restarts the container with
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
  --single-transaction --exit-on-error \
  tc780-pre-cutover-YYYYMMDDTHHMMSSZ.dump
psql "$TC780_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c 'DROP TABLE IF EXISTS database_identity_fence, database_alias, database_legacy_artifact;'
test "$(psql "$TC780_DATABASE_URL" -At -c \
  "SELECT count(*) FROM seaql_migrations WHERE version IN ('m20261007_000000_database_alias', 'm20261007_010000_database_identity_fence')")" = 0
```

Postgres `pg_restore --clean` only cleans objects present in its archive;
it leaves the newer N3 tables, including a stale enabled fence row, behind.
Drop those tables as shown and verify the restored migration ledger has no
N3 entries. If restore, cleanup, or ledger verification fails, keep the node
stopped and fenced. Then redeploy the old pinned image. Clearing aliases is **not** a rollback:
the old binary does not recognize the N3 migration ledger entry and fails at
boot. For file-backed nodes restore the complete metadata and cache backup
together. After N2 digest identities accept writes, the old binary cannot
read or merge them; restoring the backup discards those writes. Reconcile
them separately before rollback.

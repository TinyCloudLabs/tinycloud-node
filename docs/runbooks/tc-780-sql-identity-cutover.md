# TC-780 production SQL identity cutover

Production runs 1.17.4 with external PostgreSQL metadata and durable SQL artifacts. It has no DuckDB feature or local database cache. Use `include_duckdb=false` throughout this run. Never push a `v*` tag; its push triggers `docker.yml`.

Use a trusted operator host with PostgreSQL 16 tools, Docker, the N3 `tinycloud-sql-identity` and `tinycloud` binaries, and TLS access to production Postgres. Obtain `TC780_DATABASE_URL` from the secret manager without echoing it or putting it in shell history. Set `TC780_CLI=target/debug/tinycloud-sql-identity`, `TC780_NODE=target/debug/tinycloud`, and `TC780_DATADIR` to a private empty directory. Every pasteable block is a subshell: a failed check stops the block without killing the operator shell.

## Preflight on a production snapshot

Arrange a no-deploy/no-DDL window with the database owner. **Do not run `pg_dump` concurrently with any deployment or DDL.** Record the running image from `phala cvms get tinycloud-node --json`; require exactly one pinned `ghcr.io/tinycloudlabs/tinycloud-node@sha256:…` image. The OCI revision and digest, not a tag, are the rollback target.

```sh
(
  set -euo pipefail
  umask 077
  phala cvms get tinycloud-node --json > tc780-running-cvm.json
  TC780_RUNNING_IMAGE="$(python3 - <<'PY'
import json, re
from pathlib import Path
value = json.loads(Path('tc780-running-cvm.json').read_text())
compose_file = value.get('compose_file', {}) if isinstance(value, dict) else {}
compose = value if isinstance(value, str) else (compose_file.get('docker_compose_file', '') if isinstance(compose_file, dict) else '')
if not compose and isinstance(value, dict):
    compose = value.get('docker_compose_file', '')
images = re.findall(r"(?m)^\s*image:\s*['\"]?(ghcr\.io/tinycloudlabs/tinycloud-node@sha256:[0-9a-f]{64})", compose)
if len(images) != 1:
    raise SystemExit('expected exactly one pinned running node image')
print(images[0])
PY
)"
  docker pull --platform linux/amd64 "$TC780_RUNNING_IMAGE"
  TC780_RUNNING_DIGEST="${TC780_RUNNING_IMAGE##*@}"
  TC780_RUNNING_REVISION="$(docker image inspect "$TC780_RUNNING_IMAGE" --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')"
  TC780_RUNNING_VERSION="$(docker image inspect "$TC780_RUNNING_IMAGE" --format '{{ index .Config.Labels "org.opencontainers.image.version" }}')"
  test "$TC780_RUNNING_VERSION" = '1.17.4-dstack'
  printf 'image=%s\ndigest=%s\nrevision=%s\nversion=%s\n' "$TC780_RUNNING_IMAGE" "$TC780_RUNNING_DIGEST" "$TC780_RUNNING_REVISION" "$TC780_RUNNING_VERSION" > tc780-running-image.txt
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" check-migrations
)
```

`check-migrations` reads production's applied `seaql_migrations` rows and fails if any migration file is absent from the N3 binary. Save its output. The dump and restored DB contain private user data: use an encrypted volume and `umask 077`. Remove the dump immediately after restore. Set `TC780_SNAPSHOT_URL` to a fresh empty local PostgreSQL database URL, `TC780_SNAPSHOT_DATADIR` to a private directory, and `TC780_REHEARSAL_KEY` to a throwaway static node key.

```sh
(
  set -euo pipefail
  umask 077
  TC780_DUMP="$(mktemp ./tc780-snapshot.XXXXXXXX.dump)"
  trap 'rm -f "$TC780_DUMP"' EXIT
  /usr/bin/time -p pg_dump --dbname="$TC780_DATABASE_URL" --format=custom --no-owner --no-privileges --file="$TC780_DUMP"
  /usr/bin/time -p pg_restore --dbname="$TC780_SNAPSHOT_URL" --clean --if-exists --no-owner --no-privileges --single-transaction --exit-on-error "$TC780_DUMP"
  rm -f "$TC780_DUMP"
  "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" check-migrations
  "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" dry-run > tc780-preflight-inventory.json
  if ! psql "$TC780_SNAPSHOT_URL" -At -c "SELECT 1 FROM pg_indexes WHERE indexname='idx_current_kv_space_order'" | grep -qx 1; then
    /usr/bin/time -p psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 -c 'CREATE INDEX idx_current_kv_space_order ON current_kv (space, seq, epoch, epoch_seq, key)'
    psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 -c 'DROP INDEX idx_current_kv_space_order'
  else
    echo 'current_kv_sync_order index already present; no build needed'
  fi
  /usr/bin/time -p "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" fence on
  "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" apply > tc780-preflight-applied.json
  "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" verify --baseline tc780-preflight-applied.json > tc780-preflight-verified.json
  ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=18080 TINYCLOUD_STORAGE__DATABASE="$TC780_SNAPSHOT_URL" TINYCLOUD_STORAGE__DATADIR="$TC780_SNAPSHOT_DATADIR" TINYCLOUD_DATABASE__WRITE_FENCE=false TINYCLOUD_KEYS_SECRET="$TC780_REHEARSAL_KEY" "$TC780_NODE" > tc780-preflight-node.log 2>&1 &
  TC780_PID=$!
  trap 'kill "$TC780_PID" 2>/dev/null || true; rm -f "$TC780_DUMP"' EXIT
  for attempt in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:18080/healthz >/dev/null; then break; fi
    sleep 1
  done
  curl -fsS http://127.0.0.1:18080/healthz >/dev/null
  kill "$TC780_PID"
  wait "$TC780_PID" || true
)
```

Check the boot log for missing-migration errors and confirm the node reached `/healthz`. On the restored DB, use a signed test client to confirm an authorized exact-path web SQL read returns the expected row and short legacy paths cannot read it. Keep private inventory and verification reports for drift checks. Drop the snapshot DB and delete its directory after approval. Record the measured `pg_restore`, index-build and `fence on` times. If an installation has filesystem artifacts, copy their caches and WAL files into `TC780_SNAPSHOT_DATADIR` before `dry-run`.

## 1. Stage the release-line image

After review and merge into `Codex/roman/rollback-meeting-node-20260915`, build 1.20.0 with `docker.yml` `workflow_dispatch`: `deploy_phala=false`, `include_duckdb=false`, `image_version=1.20.0`. The temporary `TC780_CUTOVER_READY=true` repository variable permits image publishing; it does not authorize deployment. Record the immutable `1.20.0-dstack` digest, pull it with `docker pull --platform linux/amd64`, and require its OCI revision to equal the merged release-line SHA. Do not push a tag. Production 1.17.4 stays running.

| Phase | Budget | Service state |
| --- | --- | --- |
| Preflight dump, restore, index timing, apply/verify, boot | Measured before outage | 1.17.4 serving |
| 1. Review, merge, build, pin digest | Before outage | 1.17.4 serving |
| 2–6. Stop, drain, backup, drift check, apply | Measured backup and `fence on` times | Whole node down, including KV |
| 7. Promote pinned N3 digest | 5–10 minutes | Whole-node outage ends when healthy; SQL fenced |
| 8. Offline verify | Measured rehearsal time | KV serving; SQL fenced |
| 9. SQL smoke and `fence off` | A few minutes | SQL resumes without redeploy |

## 2–5. Stop, drain, back up, check drift

On the CVM, `phala ssh tinycloud-node` and stop exactly the `tinycloud` compose service. Wait for active requests to finish. There is no local cache volume in production. Never restart 1.17.4 after the N3 migration ledger is written.

```sh
(
  set -euo pipefail
  TC780_NODE_ID="$(docker ps --filter label=com.docker.compose.service=tinycloud --quiet)"
  test "$(printf '%s\n' "$TC780_NODE_ID" | grep -c .)" -eq 1
  docker stop "$TC780_NODE_ID"
)
```

With the node stopped, take a protected full Postgres backup. Record its filename and checksum. It includes `seaql_migrations`, SQL artifacts, KV, delegations, invocations and shares. Keep it untouched. Recheck migration coverage and compare a fresh inventory to preflight for new artifacts, changed classifications, collisions and row counts. If drift is material, repeat the rehearsal on a new snapshot.

```sh
(
  set -euo pipefail
  umask 077
  TC780_BACKUP="tc780-pre-cutover-$(date -u +%Y%m%dT%H%M%SZ).dump"
  /usr/bin/time -p pg_dump --dbname="$TC780_DATABASE_URL" --format=custom --no-owner --no-privileges --file="$TC780_BACKUP"
  shasum -a 256 "$TC780_BACKUP" > "$TC780_BACKUP.sha256"
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" check-migrations
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" dry-run > tc780-outage-inventory.json
)
```

Persist the backup filename, digest and running-image record outside the subshell for the rollback operator. Keep the dump on encrypted storage.

## 6. Durable fence and alias transaction

Keep 1.17.4 stopped. `fence on` applies the N3 migrations. `apply` fingerprints artifacts inside its alias transaction and writes `tc780-applied.json`; this is the verification baseline. Ambiguous and unattributed names stay quarantined. Document owner-approved `set` resolutions before step 7.

```sh
(
  set -euo pipefail
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" fence on
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" apply > tc780-applied.json
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" report > tc780-aliases.json
)
```

## 7. Promote the pinned N3 image while SQL is fenced

The **config fence is off** at deployment. The durable metadata fence from step 6 holds SQL fenced and is checked on every request. KV can resume. The TC-767 ancestry guard stays enabled; `deploy_image_digest` skips rebuilding.

```sh
(
  set -euo pipefail
  gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref Codex/roman/rollback-meeting-node-20260915 -f image_version=1.20.0 -f deploy_phala=true -f include_duckdb=false -f sql_identity_fence=false -f deploy_image_digest="$TC780_N3_DIGEST"
)
```

Watch the workflow, `/healthz` and `/version` until 1.20.0 is healthy. Require SQL `/invoke` to return 503 under the durable fence and confirm KV works. The whole-node outage ends here.

## 8. Verify before SQL resumes

Compare aliased artifacts to the **transaction-time** baseline. The preflight inventory is for drift detection only.

```sh
(
  set -euo pipefail
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" verify --baseline tc780-applied.json > tc780-verified.json
)
```

## 9. SQL smoke gate and unfence

Require the signed exact-path SQL smoke on the rehearsed snapshot to have passed: an authorized web read returned the preflight row, a short legacy path could not read it, and an unresolved name was rejected. In production, require SQL `/invoke` to return 503 while fenced, verify the expected alias in `report`, and confirm KV health. A version check alone does not pass this gate. Prepare three different fresh signed invocation bodies and their private header files: `TC780_SQL_FENCED_BODY`/`TC780_SQL_FENCED_HEADERS`, `TC780_SQL_OPEN_BODY`/`TC780_SQL_OPEN_HEADERS`, and `TC780_SQL_SHORT_BODY`/`TC780_SQL_SHORT_HEADERS`. The first two read the original full web path; the last attempts the short legacy path. Set `TC780_SQL_EXPECTED_MARKER` to a known nonsecret row value from preflight. Run **only** `fence off`; the running node observes the durable flag on every request and serves SQL without restart or redeploy. Monitor errors and digest artifacts.

```sh
(
  set -euo pipefail
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" report > tc780-before-unfence.json
  test -n "$TC780_SQL_EXPECTED_MARKER"
  for file in "$TC780_SQL_FENCED_BODY" "$TC780_SQL_FENCED_HEADERS" "$TC780_SQL_OPEN_BODY" "$TC780_SQL_OPEN_HEADERS" "$TC780_SQL_SHORT_BODY" "$TC780_SQL_SHORT_HEADERS"; do test -s "$file"; done
  status="$(curl -sS -o tc780-fenced-response.json -w '%{http_code}' -H @"$TC780_SQL_FENCED_HEADERS" --data-binary @"$TC780_SQL_FENCED_BODY" https://tee.node.tinycloud.xyz/invoke)"
  test "$status" = 503
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" fence off
  status="$(curl -sS -o tc780-open-response.json -w '%{http_code}' -H @"$TC780_SQL_OPEN_HEADERS" --data-binary @"$TC780_SQL_OPEN_BODY" https://tee.node.tinycloud.xyz/invoke)"
  test "$status" = 200
  jq -e --arg marker "$TC780_SQL_EXPECTED_MARKER" '.. | strings | select(contains($marker))' tc780-open-response.json >/dev/null
  status="$(curl -sS -o tc780-short-response.json -w '%{http_code}' -H @"$TC780_SQL_SHORT_HEADERS" --data-binary @"$TC780_SQL_SHORT_BODY" https://tee.node.tinycloud.xyz/invoke)"
  case "$status" in 403|409) ;; *) echo "short legacy SQL path returned $status" >&2; exit 1 ;; esac
)
```

## Rollback criteria and exact path

Roll back if N3 cannot boot, KV remains unavailable after step 7, verification mismatches transaction-time fingerprints, or the authorized SQL smoke fails and cannot be corrected while fenced. Before step 9, keep the durable fence on while investigating. After step 9, stop N3 and fence traffic before restoring. Preserve a separate N3-state backup for analysis.

**`pg_restore --clean` loses every write since step 7: KV, delegations, invocations and shares, plus SQL writes after step 9.** Notify owners and choose the rollback deliberately. Restore the entire pre-cutover backup. `--clean` can leave N3-only tables, so drop them and confirm no N3 ledger rows remain. If any check fails, keep the node stopped.

```sh
(
  set -euo pipefail
  pg_restore --dbname="$TC780_DATABASE_URL" --clean --if-exists --no-owner --no-privileges --single-transaction --exit-on-error "$TC780_BACKUP"
  psql "$TC780_DATABASE_URL" -v ON_ERROR_STOP=1 -c 'DROP TABLE IF EXISTS database_identity_fence, database_alias, database_legacy_artifact;'
  test "$(psql "$TC780_DATABASE_URL" -At -c "SELECT count(*) FROM seaql_migrations WHERE version IN ('m20261007_000000_database_alias','m20261007_010000_database_identity_fence')")" = 0
)
```

Use the **recorded** running 1.17.4 digest and OCI revision from preflight after independently rechecking its labels. Load the two values from the protected record into `TC780_RUNNING_DIGEST` and `TC780_RUNNING_REVISION` in the operator shell. TC-767's ancestry guard is roll-forward only. `allow_non_descendant=true` is its sanctioned emergency override; the rollback version/revision inputs require that override and make the workflow validate the digest's recorded labels. The N3 image-only `--validate-config` preflight is skipped for the legacy rollback image; Compose configuration validation still runs. Use the current release-line ref, whose Cargo version remains 1.20.0:

```sh
(
  set -euo pipefail
  gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref Codex/roman/rollback-meeting-node-20260915 -f image_version=1.20.0 -f deploy_phala=true -f include_duckdb=false -f sql_identity_fence=false -f allow_non_descendant=true -f deploy_image_digest="$TC780_RUNNING_DIGEST" -f rollback_image_version=1.17.4 -f rollback_image_revision="$TC780_RUNNING_REVISION"
)
```

Verify `/healthz`, `/version` reporting 1.17.4, and the approved signed SQL read. Keep the protected backup until the observation window closes. Restore normal automatic release behavior only in a separately reviewed change after the cutover.

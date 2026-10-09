# TC-780 production SQL identity cutover

Production may run **1.19.1 or 1.19.2** when this cutover starts. Preflight records the actual running version, revision and digest; those exact values are the rollback target. Production uses external PlanetScale PostgreSQL metadata, durable SQL artifacts, no DuckDB feature and no local artifact cache. Set `include_duckdb=false`. A production artifact is about **79 MB**; reading its whole payload has crash-restarted this PostgreSQL instance. Every production inventory, backup and drift check below reads artifact **metadata only**. Never select `payload` or `delta_payload` from production, run the offline fingerprint command against production, or take a production dump containing `database_artifact` rows. Never push a `v*` tag.

Use a private encrypted volume on a trusted Linux/amd64 operator host with PostgreSQL 16 tools, Docker, `jq`, the N3 `tinycloud-sql-identity` CLI and a signed SQL test client. Obtain `TC780_DATABASE_URL` and the sealed trust bundle through the secret manager without echoing them or putting them in shell history. Export `TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_BASE64` from that bundle before the image preflight; require it to be nonempty. Set `TC780_SNAPSHOT_URL` to a fresh empty **local** PostgreSQL database, and provide a throwaway `TC780_REHEARSAL_KEY`. Set `TC780_SMOKE_SPACE` to a space controlled by the operator, with a small SQL database and a known nonsecret marker. If needed, create this fixture through normal signed SQL requests **before** the snapshot; never choose another user's database. All blocks are `set -euo pipefail` subshells; a failed check stops that block without exiting the operator shell. They use `./tc780-private/record.json` to carry values across blocks and to the rollback operator. Protect this directory and delete the dump immediately after restore.

## Preflight: record image and check migration coverage

Arrange a no-deploy/no-DDL window with the database owner. `pg_dump` must never overlap a deployment or DDL. Record the exact running digest, revision and version. `check-migrations` reads only `seaql_migrations` and must pass **before** the outage; it catches any production migration absent from the N3 binary.

```sh
(
  set -euo pipefail
  umask 077
  mkdir -p ./tc780-private
  phala cvms get tinycloud-node --json > ./tc780-private/running-cvm.json
  image="$(python3 - <<'PY'
import json, re
from pathlib import Path
value = json.loads(Path('tc780-private/running-cvm.json').read_text())
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
  docker pull --platform linux/amd64 "$image"
  revision="$(docker image inspect "$image" --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')"
  version="$(docker image inspect "$image" --format '{{ index .Config.Labels "org.opencontainers.image.version" }}')"
  case "$version" in 1.19.1-dstack|1.19.2-dstack) ;; *) echo "unexpected production version: $version" >&2; exit 1;; esac
  [[ "$revision" =~ ^[0-9a-f]{40}$ ]]
  jq -n --arg image "$image" --arg digest "${image##*@}" --arg revision "$revision" --arg version "$version" \
    '{running_image:$image,running_digest:$digest,running_revision:$revision,running_version:$version}' > ./tc780-private/record.json
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" check-migrations
)
```

## Preflight: protected metadata-only snapshot and full rehearsal

The snapshot deliberately lacks real artifact bytes. N3 writes aliases and fence metadata; it never writes `database_artifact`. Take a protected custom dump with `--exclude-table-data=public.database_artifact`, then export a CSV manifest with `service`, `space`, `name` and the six fingerprint fields (`revision`, `size_bytes`, `checkpoint_content_hash`, `checkpoint_size_bytes`, `delta_content_hash`, `delta_size_bytes`). This uses stored lengths; if an actual byte length is ever needed, use `octet_length()`, never `md5()` or a payload value. A PlanetScale-managed backup is a recommended additional safety step for an operator with PlanetScale access.

```sh
(
  set -euo pipefail
  umask 077
  dump="$(mktemp ./tc780-private/snapshot.XXXXXXXX.dump)"
  trap 'rm -f "$dump"' EXIT
  /usr/bin/time -p pg_dump --dbname="$TC780_DATABASE_URL" --format=custom --no-owner --no-privileges \
    --exclude-table-data=public.database_artifact --file="$dump"
  psql "$TC780_DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "COPY (SELECT service,space,name,revision,size_bytes,checkpoint_content_hash,checkpoint_size_bytes,delta_content_hash,delta_size_bytes FROM public.database_artifact ORDER BY service,space,name) TO STDOUT WITH CSV HEADER" \
    > ./tc780-private/artifact-metadata.csv
  test "$TC780_SNAPSHOT_URL" != "$TC780_DATABASE_URL"
  python3 - "$TC780_SNAPSHOT_URL" <<'PY'
import ipaddress
import sys
from urllib.parse import urlsplit
url = urlsplit(sys.argv[1])
host = url.hostname
if url.scheme not in ('postgres', 'postgresql') or not host or not (host == 'localhost' or ipaddress.ip_address(host).is_loopback):
    raise SystemExit('snapshot URL must name a loopback PostgreSQL host')
PY
  psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 <<'SQL'
DO $$ BEGIN
  IF NOT (inet_server_addr() <<= inet '127.0.0.0/8' OR inet_server_addr() = inet '::1') THEN
    RAISE EXCEPTION 'snapshot connection is not loopback';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%')
     OR EXISTS (SELECT 1 FROM pg_namespace
                WHERE nspname NOT IN ('public', 'pg_catalog', 'information_schema') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp_%') THEN
    RAISE EXCEPTION 'snapshot target database is not empty';
  END IF;
END $$;
SQL
  /usr/bin/time -p pg_restore --dbname="$TC780_SNAPSHOT_URL" --no-owner --no-privileges \
    --single-transaction --exit-on-error "$dump"
  rm -f "$dump"
  trap - EXIT
  psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 -c \
    'CREATE TABLE tc780_artifact_manifest (service text, space text, name text, revision bigint, size_bytes bigint, checkpoint_content_hash text, checkpoint_size_bytes bigint, delta_content_hash text, delta_size_bytes bigint)'
  psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 -c \
    '\copy tc780_artifact_manifest FROM ./tc780-private/artifact-metadata.csv WITH CSV HEADER'
  psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
INSERT INTO database_artifact (service,space,name,revision,content_hash,payload,size_bytes,backend,storage_mode,created_at,updated_at,checkpoint_size_bytes,checkpoint_content_hash,delta_payload,delta_content_hash,delta_size_bytes)
SELECT service,space,name,revision,checkpoint_content_hash,'\x'::bytea,size_bytes,
       CASE WHEN service='duckdb' THEN 'duckdb' ELSE 'sqlite' END,'database-blob',
       '2026-10-07T00:00:00Z','2026-10-07T00:00:00Z',checkpoint_size_bytes,checkpoint_content_hash,
       NULL,delta_content_hash,delta_size_bytes FROM tc780_artifact_manifest;
DROP TABLE tc780_artifact_manifest;
COMMIT;
SQL
  "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" check-migrations
  "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" dry-run > ./tc780-private/preflight-inventory.json
  jq -e --arg smoke_space "$TC780_SMOKE_SPACE" '[.[] | select(.service == "sql" and .space == $smoke_space and .durable and .classification == "unique" and
    (.paths | length) == 1 and (.paths[0] | type) == "string" and
    (.paths[0] | startswith("web/")) and .metadata != null and
    (.metadata.size_bytes + .metadata.delta_size_bytes) < 1048576)] |
    sort_by(.metadata.size_bytes + .metadata.delta_size_bytes) | first |
    {space, physical_name, path: .paths[0], size_bytes: .metadata.size_bytes,
     delta_size_bytes: .metadata.delta_size_bytes} | select(.space != null)' \
    ./tc780-private/preflight-inventory.json > ./tc780-private/smoke-choice.json
  jq --slurpfile smoke ./tc780-private/smoke-choice.json '. + {smoke:$smoke[0]}' \
    ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 -c 'DROP INDEX IF EXISTS idx_current_kv_space_order'
  /usr/bin/time -p psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 -c \
    'CREATE INDEX idx_current_kv_space_order ON current_kv (space, seq, epoch, epoch_seq, key)'
  /usr/bin/time -p "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" fence on
  "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" apply > ./tc780-private/preflight-applied.json
  "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" verify \
    --baseline ./tc780-private/preflight-applied.json > ./tc780-private/preflight-verified.json
)
```

The placeholder payloads above are **only** for migration and metadata rehearsal. Never serve them to users. `smoke-choice.json` selects the smallest attributed web SQL artifact under 1 MiB **in `TC780_SMOKE_SPACE`**, by metadata, and records its exact path. If none is suitable, create a small authorized SQL fixture in that operator-controlled space while the old node still serves, then retake the metadata snapshot and repeat preflight. Build its rehearsal payload locally as a small SQLite database and replace **only its snapshot placeholder** with synthetic bytes. Do not copy any production artifact payload. Provide `TC780_SYNTHETIC_ARTIFACT_CSV`, a locally generated one-row CSV with columns `payload_hex,content_hash`; its hash must be the node's content CID for the synthetic SQLite bytes. The signed test client must have matching snapshot authorization and a known nonsecret row marker. Provide fresh `TC780_SQL_REHEARSAL_FENCED_BODY`/`TC780_SQL_REHEARSAL_FENCED_HEADERS`, `TC780_SQL_REHEARSAL_OPEN_BODY`/`TC780_SQL_REHEARSAL_OPEN_HEADERS`, and `TC780_SQL_REHEARSAL_SHORT_BODY`/`TC780_SQL_REHEARSAL_SHORT_HEADERS`. Preflight fails unless the fenced read is unavailable, the exact-path read succeeds after CLI `fence off`, and the short-path read fails. The same client supplies three fresh signed request bodies and header files for step 9. Do not use a version response as the SQL smoke gate.

The optional `offline-fingerprint --local-snapshot` command reads full artifact bytes for schema and row counts. It refuses remote database URLs and must be used only on a local copy whose artifacts are all synthetic or small. It is not part of the production inventory, apply, report or verify path.

Merge into `Codex/roman/rollback-meeting-node-20260915` with a **merge commit** that retains the running production revision as an ancestor. Do not squash, rebase or force-update this release line: `docker.yml` checks `git merge-base --is-ancestor` before deployment.

After the reviewed release-line merge and `docker.yml` `workflow_dispatch` build (`deploy_phala=false`, `include_duckdb=false`, `image_version=1.20.0`), export `TC780_N3_DIGEST=sha256:<full build digest>` and `TC780_MERGED_REVISION=<full merged commit SHA>` from the completed build, then pin both in the record below. The repository variable `TC780_CUTOVER_READY=true` permits the dispatch; keep it true through the rollback window. Before step 2, a repository administrator must apply a temporary GitHub ruleset to `refs/heads/Codex/roman/rollback-meeting-node-20260915` that restricts updates and force pushes; the release owner must hold the merge queue and reserve `docker.yml` dispatches for this cutover. Record the ruleset ID and remove it only after the cutover or rollback observation window. Check the remote HEAD against the pinned N3 revision immediately before stopping the old node and again before step 7. A changed ref aborts the cutover. Do not deploy yet.

```sh
(
  set -euo pipefail
  umask 077
  test -f ./tc780-private/record.json
  test "$TC780_N3_DIGEST" != ''
  test -n "$TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_BASE64"
  image="ghcr.io/tinycloudlabs/tinycloud-node@$TC780_N3_DIGEST"
  docker pull --platform linux/amd64 "$image"
  test "$(docker image inspect "$image" --format '{{ index .Config.Labels "org.opencontainers.image.version" }}')" = '1.20.0-dstack'
  test "$(docker image inspect "$image" --format '{{ index .Config.Labels "org.opencontainers.image.revision" }}')" = "$TC780_MERGED_REVISION"
  jq --arg digest "$TC780_N3_DIGEST" --arg revision "$TC780_MERGED_REVISION" \
    '. + {n3_digest:$digest,n3_revision:$revision}' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  cid="$(docker create --platform linux/amd64 "$image")"
  trap 'docker rm "$cid" >/dev/null 2>&1 || true' EXIT
  docker cp "$cid:/tinycloud" ./tc780-private/tinycloud-n3
  docker rm "$cid" >/dev/null
  trap - EXIT
  chmod 700 ./tc780-private/tinycloud-n3
  docker run --rm --platform linux/amd64 --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges \
    -e TINYCLOUD_STORAGE__DATABASE='postgresql://preflight:unused@db.invalid/tinycloud?sslmode=verify-full' \
    -e TINYCLOUD_DATABASE__WRITE_FENCE=false \
    -e TINYCLOUD_SHARE_EMAIL__ENABLED=true \
    -e TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_BASE64 \
    -e TINYCLOUD_SHARE_EMAIL__POSTGRES_TLS__SSLMODE=verify-full \
    -e TINYCLOUD_KEYS__TYPE=Dstack "$image" --validate-config
  test -s "$TC780_SYNTHETIC_ARTIFACT_CSV"
  test "$(wc -c < "$TC780_SYNTHETIC_ARTIFACT_CSV")" -lt 2097152
  cp "$TC780_SYNTHETIC_ARTIFACT_CSV" ./tc780-private/synthetic-artifact.csv
  psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 -c \
    'CREATE TABLE tc780_synthetic_fixture (payload_hex text, content_hash text)'
  psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 -c \
    '\copy tc780_synthetic_fixture FROM ./tc780-private/synthetic-artifact.csv WITH CSV HEADER'
  smoke_space="$(jq -er '.smoke.space' ./tc780-private/record.json)"
  smoke_name="$(jq -er '.smoke.physical_name' ./tc780-private/record.json)"
  psql "$TC780_SNAPSHOT_URL" -v ON_ERROR_STOP=1 -v smoke_space="$smoke_space" -v smoke_name="$smoke_name" <<'SQL'
DO $$ BEGIN
  IF (SELECT count(*) FROM tc780_synthetic_fixture) != 1 OR
     EXISTS (SELECT 1 FROM tc780_synthetic_fixture WHERE payload_hex !~ '^[0-9a-f]+$' OR length(payload_hex) > 2097152 OR content_hash = '') THEN
    RAISE EXCEPTION 'invalid local synthetic fixture';
  END IF;
END $$;
UPDATE database_artifact AS a SET
  payload = decode(f.payload_hex, 'hex'), content_hash = f.content_hash,
  size_bytes = length(f.payload_hex) / 2, checkpoint_size_bytes = length(f.payload_hex) / 2,
  checkpoint_content_hash = f.content_hash, delta_payload = NULL,
  delta_content_hash = NULL, delta_size_bytes = 0
FROM tc780_synthetic_fixture AS f
WHERE a.service = 'sql' AND a.space = :'smoke_space' AND a.name = :'smoke_name';
SELECT (count(*) = 1) AS fixture_applied FROM database_artifact
WHERE service = 'sql' AND space = :'smoke_space' AND name = :'smoke_name' AND octet_length(payload) > 0
\gset
\if :fixture_applied
\else
DO $$ BEGIN RAISE EXCEPTION 'synthetic fixture was not applied exactly once'; END $$;
\endif
DROP TABLE tc780_synthetic_fixture;
SQL
  ROCKET_ADDRESS=127.0.0.1 ROCKET_PORT=18080 \
    TINYCLOUD_STORAGE__DATABASE="$TC780_SNAPSHOT_URL" \
    TINYCLOUD_STORAGE__DATADIR="$TC780_SNAPSHOT_DATADIR" \
    TINYCLOUD_DATABASE__WRITE_FENCE=false TINYCLOUD_KEYS_TYPE=Static TINYCLOUD_KEYS_SECRET="$TC780_REHEARSAL_KEY" \
    ./tc780-private/tinycloud-n3 > ./tc780-private/preflight-node.log 2>&1 &
  pid=$!
  trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
  for attempt in $(seq 1 30); do
    if curl -fsS http://127.0.0.1:18080/healthz >/dev/null; then break; fi
    sleep 1
  done
  curl -fsS http://127.0.0.1:18080/healthz >/dev/null
  status="$(curl -sS -o ./tc780-private/rehearsal-fenced.json -w '%{http_code}' -H @"$TC780_SQL_REHEARSAL_FENCED_HEADERS" --data-binary @"$TC780_SQL_REHEARSAL_FENCED_BODY" http://127.0.0.1:18080/invoke)"
  test "$status" = 503
  "$TC780_CLI" --datadir "$TC780_SNAPSHOT_DATADIR" --database "$TC780_SNAPSHOT_URL" fence off
  status="$(curl -sS -o ./tc780-private/rehearsal-open.json -w '%{http_code}' -H @"$TC780_SQL_REHEARSAL_OPEN_HEADERS" --data-binary @"$TC780_SQL_REHEARSAL_OPEN_BODY" http://127.0.0.1:18080/invoke)"
  test "$status" = 200
  jq -e --arg marker "$TC780_SQL_EXPECTED_MARKER" '.. | strings | select(contains($marker))' ./tc780-private/rehearsal-open.json >/dev/null
  status="$(curl -sS -o ./tc780-private/rehearsal-short.json -w '%{http_code}' -H @"$TC780_SQL_REHEARSAL_SHORT_HEADERS" --data-binary @"$TC780_SQL_REHEARSAL_SHORT_BODY" http://127.0.0.1:18080/invoke)"
  case "$status" in 403|409) ;; *) echo "short path returned $status" >&2; exit 1;; esac
)
```

Record measured `pg_restore` and index-build times, migration results, boot log and signed smoke outputs. Retain private inventory reports for drift comparison. Destroy the local snapshot after approval. The artifact metadata CSV is sensitive; protect and delete it after cutover. The local `--network none` image check uses a dummy PostgreSQL URL with the same TLS shape; `--validate-config` does no database I/O. The deployment workflow validates its own configured secret.

Before step 2, confirm the dispatch gate and frozen release ref. These checks must pass again immediately before step 7:

```sh
(
  set -euo pipefail
  test "$(gh api repos/TinyCloudLabs/tinycloud-node/actions/variables/TC780_CUTOVER_READY --jq .value)" = true
  revision="$(jq -er '.n3_revision' ./tc780-private/record.json)"
  test "$(git ls-remote origin refs/heads/Codex/roman/rollback-meeting-node-20260915 | cut -f1)" = "$revision"
)
```

## Outage and user impact

| Phase | Budget | Service state |
| --- | --- | --- |
| Snapshot, metadata rehearsal, image extraction, config preflight and signed smoke | Measured before outage | Recorded old version serving |
| Stop, drain, backup, drift check and alias transaction | Measured backup and migration time | Whole node down, including KV |
| Step 7, promote pinned N3 digest | 5–10 minutes | Whole-node outage ends when healthy; SQL fenced |
| Step 8, verify transaction-time metadata | Measured rehearsal time | KV serving; SQL fenced |
| Step 9, signed SQL smoke and CLI unfence | A few minutes | SQL resumes without redeploy |

The maximum whole-node outage is **20 minutes from the stop in step 2**. The recorded `outage_deadline_epoch` is the abort-at-T trigger: before any next action, and while watching a deployment, stop forward progress when it is reached and take the abort path below. An operator should also watch the clock during long `pg_dump` and `apply` commands. N3 changes SQL/DuckDB identity scoping. Hook subscriptions on table-suffixed SQL/DuckDB paths stop firing; TC-541 already deactivated older hook subscriptions, so this affects subscriptions registered since 1.17.4. TC-730 also rotates hook tickets to v3 and changes subscription prefix matching to literal path segments. Communicate these changes before the cutover.

## Steps 2–6: stop, protected backup, drift check, durable fence

Stop exactly the `tinycloud` compose service on the CVM and drain active requests. There is no local artifact cache volume. Keep the recorded old node stopped after N3 migrations enter the ledger. The new backup excludes artifact data; its metadata manifest is separate. A PlanetScale-managed backup is recommended for full disaster recovery. Do not overlap this dump with a deploy or DDL.

```sh
(
  set -euo pipefail
  test "$(gh api repos/TinyCloudLabs/tinycloud-node/actions/variables/TC780_CUTOVER_READY --jq .value)" = true
  test "$(git ls-remote origin refs/heads/Codex/roman/rollback-meeting-node-20260915 | cut -f1)" = "$(jq -er '.n3_revision' ./tc780-private/record.json)"
  jq --argjson deadline "$(($(date +%s) + 1200))" '. + {outage_deadline_epoch:$deadline,phase:"stopping"}' \
    ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
)
```

On the CVM:

```sh
(
  set -euo pipefail
  node_id="$(docker ps --filter label=com.docker.compose.service=tinycloud --quiet)"
  test "$(printf '%s\n' "$node_id" | grep -c .)" -eq 1
  docker stop "$node_id"
)
```

```sh
(
  set -euo pipefail
  umask 077
  deadline="$(jq -er '.outage_deadline_epoch' ./tc780-private/record.json)"
  budget() {
    remaining="$((deadline - $(date +%s)))"
    test "$remaining" -gt 0
    timeout "$remaining" "$@"
  }
  test "$(date +%s)" -lt "$deadline"
  jq '.phase="stopped_before_step6"' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  backup="./tc780-private/pre-cutover-$(date -u +%Y%m%dT%H%M%SZ).dump"
  budget /usr/bin/time -p pg_dump --dbname="$TC780_DATABASE_URL" --format=custom --no-owner --no-privileges \
    --exclude-table-data=public.database_artifact --file="$backup"
  budget psql "$TC780_DATABASE_URL" -v ON_ERROR_STOP=1 -c \
    "COPY (SELECT service,space,name,revision,size_bytes,checkpoint_content_hash,checkpoint_size_bytes,delta_content_hash,delta_size_bytes FROM public.database_artifact ORDER BY service,space,name) TO STDOUT WITH CSV HEADER" \
    > ./tc780-private/outage-artifact-metadata.csv
  shasum -a 256 "$backup" > "$backup.sha256"
  jq --arg backup "$backup" '. + {backup:$backup}' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  budget "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" check-migrations
  budget "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" dry-run > ./tc780-private/outage-inventory.json
  python3 - <<'PY'
import csv
from pathlib import Path
def identities(path):
    with Path(path).open(newline='') as file:
        return {(row['service'], row['space'], row['name']) for row in csv.DictReader(file)}
assert identities('tc780-private/artifact-metadata.csv') == identities('tc780-private/outage-artifact-metadata.csv'), 'artifact identity drift'
PY
  for phase in preflight outage; do
    jq -S '[.[] | {service,space,physical_name,paths,classification,collision}] | sort_by(.service,.space,.physical_name)' \
      "./tc780-private/$phase-inventory.json" > "./tc780-private/$phase-identities.json"
  done
  cmp ./tc780-private/preflight-identities.json ./tc780-private/outage-identities.json
  test "$(date +%s)" -lt "$deadline"
  jq '.phase="step6_started"' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  budget "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" fence on
  budget "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" apply > ./tc780-private/tc780-applied.json
  budget "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" report > ./tc780-private/aliases.json
  jq '.phase="step6_applied"' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
)
```

`apply` fingerprints the six stored metadata fields inside its transaction. `tc780-applied.json` is the verification baseline; preflight inventory is only for drift checks. Ambiguous and unattributed names stay quarantined. Record owner-approved `set` resolutions before step 7.

## Step 7: promote pinned N3 image

Deploy with the **config fence off**. The step-6 durable metadata fence holds SQL fenced and is checked on every request. KV can resume. TC-767's ancestry guard remains enabled; digest promotion skips rebuilding.

```sh
(
  set -euo pipefail
  digest="$(jq -er '.n3_digest' ./tc780-private/record.json)"
  revision="$(jq -er '.n3_revision' ./tc780-private/record.json)"
  deadline="$(jq -er '.outage_deadline_epoch' ./tc780-private/record.json)"
  test "$(date +%s)" -lt "$deadline"
  test "$(gh api repos/TinyCloudLabs/tinycloud-node/actions/variables/TC780_CUTOVER_READY --jq .value)" = true
  test "$(git ls-remote origin refs/heads/Codex/roman/rollback-meeting-node-20260915 | cut -f1)" = "$revision"
  before="$(gh run list -R TinyCloudLabs/tinycloud-node --workflow docker.yml --branch Codex/roman/rollback-meeting-node-20260915 --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // 0')"
  jq --argjson before "$before" '. + {n3_previous_run_id:$before,phase:"step7_dispatching",n3_dispatch_exit_status:null} | del(.n3_deploy_run_id)' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  if gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref Codex/roman/rollback-meeting-node-20260915 \
    -f image_version=1.20.0 -f deploy_phala=true -f include_duckdb=false \
    -f sql_identity_fence=false -f deploy_image_digest="$digest"; then
    dispatch_status=0
  else
    dispatch_status=$?
  fi
  jq --argjson status "$dispatch_status" '.n3_dispatch_exit_status=$status' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  test "$dispatch_status" -eq 0 || { echo 'N3 dispatch command failed; take the abort path' >&2; exit 1; }
  run_id=''
  for attempt in $(seq 1 30); do
    run_id="$(gh run list -R TinyCloudLabs/tinycloud-node --workflow docker.yml --branch Codex/roman/rollback-meeting-node-20260915 --event workflow_dispatch --limit 1 --json databaseId,headSha \
      --jq ".[0] | select(.databaseId != $before and .headSha == \"$revision\") | .databaseId")"
    test -n "$run_id" && break
    sleep 2
  done
  test -n "$run_id"
  jq --argjson run_id "$run_id" '. + {n3_deploy_run_id:$run_id,phase:"step7_running"}' \
    ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  remaining="$((deadline - $(date +%s)))"
  test "$remaining" -gt 0
  timeout "$remaining" gh run watch "$run_id" -R TinyCloudLabs/tinycloud-node --exit-status
  jq '.phase="step7_deployed"' \
    ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
)
```

Require `/healthz` and `/version` to report healthy 1.20.0. A signed SQL `/invoke` must return 503 while fenced; confirm KV works. The whole-node outage ends here.

## Step 8: verify while SQL is fenced

```sh
(
  set -euo pipefail
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" verify \
    --baseline ./tc780-private/tc780-applied.json > ./tc780-private/verified.json
)
```

## Step 9: signed SQL smoke gate and CLI unfence

Use only the recorded smoke database in the operator-controlled `TC780_SMOKE_SPACE`: an attributed SQL row with `size_bytes + delta_size_bytes < 1048576`, known exact full path and known nonsecret marker. Never select its payload in the selection query. The rehearsal signed smoke must already have passed. Prepare fresh signed invocation bodies and private header files: `TC780_SQL_FENCED_BODY`/`TC780_SQL_FENCED_HEADERS`, `TC780_SQL_OPEN_BODY`/`TC780_SQL_OPEN_HEADERS`, `TC780_SQL_SHORT_BODY`/`TC780_SQL_SHORT_HEADERS`. The first two read the approved full path; the last tries its short legacy path. The same record and selected path must be used throughout. If no safe small artifact exists, keep SQL fenced.

```sh
(
  set -euo pipefail
  test -n "$TC780_SQL_EXPECTED_MARKER"
  for file in "$TC780_SQL_FENCED_BODY" "$TC780_SQL_FENCED_HEADERS" "$TC780_SQL_OPEN_BODY" "$TC780_SQL_OPEN_HEADERS" "$TC780_SQL_SHORT_BODY" "$TC780_SQL_SHORT_HEADERS"; do test -s "$file"; done
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" report > ./tc780-private/before-unfence.json
  status="$(curl -sS -o ./tc780-private/fenced.json -w '%{http_code}' -H @"$TC780_SQL_FENCED_HEADERS" --data-binary @"$TC780_SQL_FENCED_BODY" https://tee.node.tinycloud.xyz/invoke)"
  test "$status" = 503
  "$TC780_CLI" --datadir "$TC780_DATADIR" --database "$TC780_DATABASE_URL" fence off
  status="$(curl -sS -o ./tc780-private/open.json -w '%{http_code}' -H @"$TC780_SQL_OPEN_HEADERS" --data-binary @"$TC780_SQL_OPEN_BODY" https://tee.node.tinycloud.xyz/invoke)"
  test "$status" = 200
  jq -e --arg marker "$TC780_SQL_EXPECTED_MARKER" '.. | strings | select(contains($marker))' ./tc780-private/open.json >/dev/null
  status="$(curl -sS -o ./tc780-private/short.json -w '%{http_code}' -H @"$TC780_SQL_SHORT_HEADERS" --data-binary @"$TC780_SQL_SHORT_BODY" https://tee.node.tinycloud.xyz/invoke)"
  case "$status" in 403|409) ;; *) echo "short path returned $status" >&2; exit 1;; esac
)
```

No redeploy is required after `fence off`. Monitor SQL errors, KV health and new digest artifacts.

## Rollback criteria and exact non-destructive path

Abort forward progress immediately at the recorded **20-minute deadline**, or if the frozen ref changes, step 7's workflow fails, N3 cannot boot, KV remains unavailable, verification differs from `tc780-applied.json`, or the signed SQL smoke fails and cannot be corrected while fenced. The abort ladder is based on `record.json`:

- **Before `phase=step6_started`:** no N3 ledger change was attempted. On the CVM, keep the old `tinycloud` container running, or `docker start` it if stopped, and verify health. If it cannot be started, use the old-digest promotion block below **without** the ledger transaction.
- **At or after `phase=step6_started`:** first cancel and settle any step-7 run (or establish that it was never dispatched), then inspect Phala's desired image and the CVM's actual running image. Stop any running node, run the ledger rollback transaction, then dispatch and watch promotion of the recorded old digest. This includes a failed `apply`, a step-7 workflow failure, and a case where N3 never started. Complete this rollback even if the 20-minute forward budget has expired.

Before step 9, keep the durable fence on during investigation. After step 9, stop N3 and block traffic before changing metadata. Preserve a separate N3-state backup for analysis if needed; exclude artifact table data from any operator `pg_dump`.

If step 7 was dispatched, cancel its recorded run **before** touching the CVM or ledger. `timeout gh run watch` only stops the local watcher; it does not cancel the workflow, and a terminal GitHub run does not prove that Phala stopped updating the CVM. If `phase=step7_dispatching` but the run ID is absent, the block searches for a newer run. It declares **never dispatched** only after three minutes with no newer `docker.yml` dispatch run than `n3_previous_run_id` **and** Phala's desired Compose image still equal to `running_image`. The saved `n3_dispatch_exit_status` records whether `gh workflow run` failed; even a zero exit status alone does not prove a run exists. A newer run with a different revision or an unreadable/changed Phala image halts for investigation. The cancellation loops can sleep for **20 minutes total** (120 × 5 seconds before and after force-cancel), plus up to 242 GitHub status requests and the cancel requests; those requests have no fixed timeout, so the actual worst case is unbounded. Escalate after the first 120 polls with force-cancel; if the second wait still does not reach `completed`, leave the CVM and ledger untouched.

```sh
(
  set -euo pipefail
  umask 077
  phase="$(jq -er '.phase' ./tc780-private/record.json)"
  case "$phase" in
    step7_dispatching|step7_running|step7_deployed)
      run_id="$(jq -r '.n3_deploy_run_id // empty' ./tc780-private/record.json)"
      if test -z "$run_id"; then
        before="$(jq -er '.n3_previous_run_id' ./tc780-private/record.json)"
        revision="$(jq -er '.n3_revision' ./tc780-private/record.json)"
        for attempt in $(seq 1 36); do
          run_id="$(gh run list -R TinyCloudLabs/tinycloud-node --workflow docker.yml --branch Codex/roman/rollback-meeting-node-20260915 --event workflow_dispatch --limit 30 --json databaseId,headSha \
            --jq "[.[] | select(.databaseId > $before and .headSha == \"$revision\") | .databaseId] | first // empty")"
          test -z "$run_id" || break
          sleep 5
        done
      fi
      if test -z "$run_id"; then
        newest="$(gh run list -R TinyCloudLabs/tinycloud-node --workflow docker.yml --branch Codex/roman/rollback-meeting-node-20260915 --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // 0')"
        test "$newest" -le "$before" || { echo 'newer docker.yml run is unaccounted for; halt rollback' >&2; exit 1; }
        phala cvms get tinycloud-node --json > ./tc780-private/abort-cvm.json
        desired="$(python3 - <<'PY'
import json, re
from pathlib import Path
value = json.loads(Path('tc780-private/abort-cvm.json').read_text())
compose_file = value.get('compose_file', {}) if isinstance(value, dict) else {}
compose = value if isinstance(value, str) else (compose_file.get('docker_compose_file', '') if isinstance(compose_file, dict) else '')
if not compose and isinstance(value, dict):
    compose = value.get('docker_compose_file', '')
images = re.findall(r"(?m)^\s*image:\s*['\"]?(ghcr\.io/tinycloudlabs/tinycloud-node@sha256:[0-9a-f]{64})", compose)
if len(images) != 1:
    raise SystemExit('cannot identify one pinned desired node image; halt rollback')
print(images[0])
PY
)"
        old="$(jq -er '.running_image' ./tc780-private/record.json)"
        test "$desired" = "$old" || { echo 'Phala desired image changed; halt rollback' >&2; exit 1; }
        jq '.phase="step7_never_dispatched"' ./tc780-private/record.json > ./tc780-private/record.next.json
        mv ./tc780-private/record.next.json ./tc780-private/record.json
        echo 'No newer docker.yml run after three minutes; Phala still desires the old image'
        exit 0
      fi
      jq --argjson run_id "$run_id" '.n3_deploy_run_id=$run_id' ./tc780-private/record.json > ./tc780-private/record.next.json
      mv ./tc780-private/record.next.json ./tc780-private/record.json
      status="$(gh run view "$run_id" -R TinyCloudLabs/tinycloud-node --json status --jq .status)"
      if test "$status" != completed; then gh run cancel "$run_id" -R TinyCloudLabs/tinycloud-node || true; fi
      for attempt in $(seq 1 120); do
        status="$(gh run view "$run_id" -R TinyCloudLabs/tinycloud-node --json status --jq .status)"
        test "$status" = completed && break
        sleep 5
      done
      if test "$status" != completed; then
        gh api -X POST "repos/TinyCloudLabs/tinycloud-node/actions/runs/$run_id/force-cancel"
        for attempt in $(seq 1 120); do
          status="$(gh run view "$run_id" -R TinyCloudLabs/tinycloud-node --json status --jq .status)"
          test "$status" = completed && break
          sleep 5
        done
      fi
      test "$(gh run view "$run_id" -R TinyCloudLabs/tinycloud-node --json status --jq .status)" = completed
      ;;
  esac
)
```

Before the CVM stop and ledger transaction, run the following on the operator host. `phala cvms get --json` exposes the desired Compose image in `compose_file.docker_compose_file` (or top-level `docker_compose_file`), as used by `docker.yml`; the workflow does **not** establish a reliable JSON field for an in-progress update. If Phala still desires N3, the CVM check below requires an **already running N3 container** before stopping it. If N3 is not running yet, halt with the ledger intact and repeat this gate after it starts. If Phala still desires the old image after a recorded N3 run, separately confirm in the Phala control plane that no update is in progress, then set `TC780_PHALA_UPDATE_SETTLED=confirmed`; without that confirmation, halt. An unreadable or unexpected desired image also halts. A completed GitHub run, or no currently running container, never supplies this confirmation.

```sh
(
  set -euo pipefail
  umask 077
  phala cvms get tinycloud-node --json > ./tc780-private/abort-cvm.json
  desired="$(python3 - <<'PY'
import json, re
from pathlib import Path
value = json.loads(Path('tc780-private/abort-cvm.json').read_text())
compose_file = value.get('compose_file', {}) if isinstance(value, dict) else {}
compose = value if isinstance(value, str) else (compose_file.get('docker_compose_file', '') if isinstance(compose_file, dict) else '')
if not compose and isinstance(value, dict):
    compose = value.get('docker_compose_file', '')
images = re.findall(r"(?m)^\s*image:\s*['\"]?(ghcr\.io/tinycloudlabs/tinycloud-node@sha256:[0-9a-f]{64})", compose)
if len(images) != 1:
    raise SystemExit('cannot identify one pinned desired node image; halt rollback')
print(images[0])
PY
)"
  old="$(jq -er '.running_image' ./tc780-private/record.json)"
  n3="ghcr.io/tinycloudlabs/tinycloud-node@$(jq -er '.n3_digest' ./tc780-private/record.json)"
  case "$desired" in "$old"|"$n3") ;; *) echo 'unexpected Phala desired image; halt rollback' >&2; exit 1;; esac
  run_id="$(jq -r '.n3_deploy_run_id // empty' ./tc780-private/record.json)"
  if test "$desired" = "$old" && test -n "$run_id"; then
    test "${TC780_PHALA_UPDATE_SETTLED:-}" = confirmed || { echo 'confirm no Phala update is in progress before rollback' >&2; exit 1; }
  fi
  jq --arg desired "$desired" '.abort_desired_image=$desired' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  printf 'Phala desired node image: %s\n' "$desired"
)
```

On the CVM set `TC780_OLD_IMAGE`, `TC780_N3_IMAGE`, and `TC780_PHALA_DESIRED_IMAGE` to `running_image`, `ghcr.io/tinycloudlabs/tinycloud-node@<n3_digest>`, and `abort_desired_image` from the operator's `record.json`. Inspect the **running container** as well. An unknown running image or multiple running node containers halts rollback for investigation. Keep these values for the stop and failed-promotion checks below.

```sh
(
  set -euo pipefail
  test -n "$TC780_OLD_IMAGE" && test -n "$TC780_N3_IMAGE" && test -n "$TC780_PHALA_DESIRED_IMAGE"
  case "$TC780_PHALA_DESIRED_IMAGE" in "$TC780_OLD_IMAGE"|"$TC780_N3_IMAGE") ;; *) echo 'unexpected Phala desired image; halt rollback' >&2; exit 1;; esac
  node_id="$(docker ps --filter label=com.docker.compose.service=tinycloud --quiet)"
  test "$(printf '%s\n' "$node_id" | grep -c . || true)" -le 1
  if test -n "$node_id"; then
    image="$(docker inspect "$node_id" --format '{{.Config.Image}}')"
    printf 'Running node image: %s\n' "$image"
    case "$image" in "$TC780_OLD_IMAGE"|"$TC780_N3_IMAGE") ;; *) echo 'unknown running node image; halt rollback' >&2; exit 1;; esac
  else
    echo 'No running tinycloud container on CVM'
  fi
  if test "$TC780_PHALA_DESIRED_IMAGE" = "$TC780_N3_IMAGE"; then
    test -n "$node_id" && test "$image" = "$TC780_N3_IMAGE" || { echo 'Phala desires N3 but N3 is not running yet; halt before ledger rollback' >&2; exit 1; }
  fi
)
```

Before step 6, ensure the old container is running on the CVM:

```sh
(
  set -euo pipefail
  old_id="$(docker ps -a --filter label=com.docker.compose.service=tinycloud --quiet)"
  test "$(printf '%s\n' "$old_id" | grep -c .)" -eq 1
  if test "$(docker inspect "$old_id" --format '{{.State.Running}}')" = false; then
    docker start "$old_id"
  fi
  test "$(docker inspect "$old_id" --format '{{.State.Running}}')" = true
)
```

For ordinary rollback after step 6 begins, stop the node, then remove N3's two migrations **in one PostgreSQL transaction**. This keeps KV, delegations, invocations, shares and existing SQL writes. Databases first created under N3 after unfencing use digest names and become unreachable from the recorded old version; identify and notify their owners before rollback. If that loss is unacceptable, remain on N3 while fixing forward. Do not use `pg_restore` for ordinary rollback.

On the CVM, stop the N3 service and confirm it is stopped before touching the ledger:

```sh
(
  set -euo pipefail
  node_id="$(docker ps --filter label=com.docker.compose.service=tinycloud --quiet)"
  test "$(printf '%s\n' "$node_id" | grep -c .)" -le 1
  if test -n "$node_id"; then docker stop "$node_id"; fi
  test "$(docker ps --filter label=com.docker.compose.service=tinycloud --quiet | grep -c . || true)" -eq 0
)
```

Only for aborts at or after `phase=step6_started`, on the operator host remove the N3 metadata and migration rows in one transaction. Do this after the CVM image check and stop above:

```sh
(
  set -euo pipefail
  psql "$TC780_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DROP TABLE IF EXISTS database_identity_fence, database_alias, database_legacy_artifact;
DELETE FROM seaql_migrations WHERE version IN ('m20261007_000000_database_alias','m20261007_010000_database_identity_fence');
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM seaql_migrations WHERE version IN ('m20261007_000000_database_alias','m20261007_010000_database_identity_fence')) THEN
    RAISE EXCEPTION 'N3 migration ledger remains';
  END IF;
END $$;
COMMIT;
SQL
)
```

For either path that needs image promotion, run this separate sanctioned TC-767 rollback dispatch on the operator host. A pre-step-6 fallback starts here and does not run the ledger transaction. If this dispatch command fails before a new run appears, wait three minutes and verify that no newer `docker.yml` run exists, then repeat the Phala desired-image and CVM checks above before retrying this block. It clears the previous rollback run ID at each attempt. If either check is uncertain, halt before touching the CVM or ledger:

```sh
(
  set -euo pipefail
  version="$(jq -er '.running_version' ./tc780-private/record.json)"
  case "$version" in 1.19.1-dstack|1.19.2-dstack) ;; *) exit 1;; esac
  digest="$(jq -er '.running_digest' ./tc780-private/record.json)"
  revision="$(jq -er '.running_revision' ./tc780-private/record.json)"
  before="$(gh run list -R TinyCloudLabs/tinycloud-node --workflow docker.yml --branch Codex/roman/rollback-meeting-node-20260915 --event workflow_dispatch --limit 1 --json databaseId --jq '.[0].databaseId // 0')"
  jq --argjson before "$before" '. + {rollback_previous_run_id:$before,phase:"rollback_dispatching"} | del(.rollback_deploy_run_id)' \
    ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref Codex/roman/rollback-meeting-node-20260915 \
    -f image_version=1.20.0 -f deploy_phala=true -f include_duckdb=false -f sql_identity_fence=false \
    -f allow_non_descendant=true -f deploy_image_digest="$digest" \
    -f rollback_image_version="${version%-dstack}" -f rollback_image_revision="$revision"
  n3_revision="$(jq -er '.n3_revision' ./tc780-private/record.json)"
  run_id=''
  for attempt in $(seq 1 30); do
    run_id="$(gh run list -R TinyCloudLabs/tinycloud-node --workflow docker.yml --branch Codex/roman/rollback-meeting-node-20260915 --event workflow_dispatch --limit 1 --json databaseId,headSha \
      --jq ".[0] | select(.databaseId != $before and .headSha == \"$n3_revision\") | .databaseId")"
    test -n "$run_id" && break
    sleep 2
  done
  test -n "$run_id"
  jq --argjson run_id "$run_id" '. + {rollback_deploy_run_id:$run_id,phase:"rollback_running"}' \
    ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  if ! gh run watch "$run_id" -R TinyCloudLabs/tinycloud-node --exit-status; then
    jq '.phase="rollback_failed"' ./tc780-private/record.json > ./tc780-private/record.next.json
    mv ./tc780-private/record.next.json ./tc780-private/record.json
    echo 'rollback deploy failed; follow failed-promotion step below' >&2
    exit 1
  fi
  psql "$TC780_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM seaql_migrations WHERE version IN ('m20261007_000000_database_alias','m20261007_010000_database_identity_fence')) THEN
    RAISE EXCEPTION 'N3 migration ledger reappeared after rollback deploy';
  END IF;
END $$;
SQL
  jq '.phase="rollback_deployed"' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
)
```

If the rollback deploy or its local watcher fails, **do not restart N3** after the ledger transaction. First settle the recorded rollback run: a failed local watch does not prove the workflow stopped. Cancel it if still active, wait for `completed`, and inspect its conclusion and logs. This has the same worst case as the N3 cancel block: 20 minutes of sleeps plus up to 242 status requests and two cancel requests, with no finite wall-clock bound on those requests. Force-cancel after the first 120 polls; if the second 120 polls do not reach `completed`, escalate and leave the CVM untouched.

```sh
(
  set -euo pipefail
  run_id="$(jq -r '.rollback_deploy_run_id // empty' ./tc780-private/record.json)"
  if test -z "$run_id"; then
    before="$(jq -er '.rollback_previous_run_id' ./tc780-private/record.json)"
    revision="$(jq -er '.n3_revision' ./tc780-private/record.json)"
    run_id="$(gh run list -R TinyCloudLabs/tinycloud-node --workflow docker.yml --branch Codex/roman/rollback-meeting-node-20260915 --event workflow_dispatch --limit 30 --json databaseId,headSha \
      --jq "[.[] | select(.databaseId > $before and .headSha == \"$revision\") | .databaseId] | first // empty")"
  fi
  test -n "$run_id" || { echo 'rollback dispatch not accounted for; halt' >&2; exit 1; }
  jq --argjson run_id "$run_id" '.rollback_deploy_run_id=$run_id' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  status="$(gh run view "$run_id" -R TinyCloudLabs/tinycloud-node --json status --jq .status)"
  if test "$status" != completed; then gh run cancel "$run_id" -R TinyCloudLabs/tinycloud-node || true; fi
  for attempt in $(seq 1 120); do
    status="$(gh run view "$run_id" -R TinyCloudLabs/tinycloud-node --json status --jq .status)"
    test "$status" = completed && break
    sleep 5
  done
  if test "$status" != completed; then
    gh api -X POST "repos/TinyCloudLabs/tinycloud-node/actions/runs/$run_id/force-cancel"
    for attempt in $(seq 1 120); do
      status="$(gh run view "$run_id" -R TinyCloudLabs/tinycloud-node --json status --jq .status)"
      test "$status" = completed && break
      sleep 5
    done
  fi
  test "$(gh run view "$run_id" -R TinyCloudLabs/tinycloud-node --json status --jq .status)" = completed
  gh run view "$run_id" -R TinyCloudLabs/tinycloud-node --json status,conclusion
)
```

Before any `docker start` after a failed promotion, repeat the Phala desired-image gate above. If Phala desires N3 and N3 is not yet running, halt and wait with the ledger unchanged. On the operator host, check the N3 ledger rows **before** attempting to start the old container. A positive count means a late N3 start re-applied its migrations. Keep the result with the private record:

```sh
(
  set -euo pipefail
  rows="$(psql "$TC780_DATABASE_URL" -v ON_ERROR_STOP=1 -Atc "SELECT count(*) FROM seaql_migrations WHERE version IN ('m20261007_000000_database_alias','m20261007_010000_database_identity_fence')")"
  jq --argjson rows "$rows" '.failed_promotion_n3_ledger_rows=$rows' ./tc780-private/record.json > ./tc780-private/record.next.json
  mv ./tc780-private/record.next.json ./tc780-private/record.json
  printf 'N3 ledger rows before old-container recovery: %s\n' "$rows"
)
```

On the CVM, stop **every running node container**, including an old one, before repairing the ledger. Halt on an unknown image or duplicate old containers. Use the recorded `TC780_OLD_IMAGE` and `TC780_N3_IMAGE`:

```sh
(
  set -euo pipefail
  test -n "$TC780_OLD_IMAGE" && test -n "$TC780_N3_IMAGE"
  old_id=''
  while IFS= read -r node_id; do
    test -n "$node_id" || continue
    if test "$(docker inspect "$node_id" --format '{{.Config.Image}}')" = "$TC780_OLD_IMAGE"; then
      test -z "$old_id" || { echo 'multiple old containers; halt' >&2; exit 1; }
      old_id="$node_id"
    fi
  done <<< "$(docker ps -a --filter label=com.docker.compose.service=tinycloud --quiet)"
  while IFS= read -r running_id; do
    test -n "$running_id" || continue
    image="$(docker inspect "$running_id" --format '{{.Config.Image}}')"
    case "$image" in "$TC780_OLD_IMAGE"|"$TC780_N3_IMAGE") ;; *) echo 'unknown running image; halt' >&2; exit 1;; esac
    docker stop "$running_id"
  done <<< "$(docker ps --filter label=com.docker.compose.service=tinycloud --quiet)"
  test "$(docker ps --filter label=com.docker.compose.service=tinycloud --quiet | grep -c . || true)" -eq 0
  test -n "$old_id" || { echo 'old container absent; keep node stopped and escalate' >&2; exit 1; }
  printf 'Stopped all node containers; old container ID: %s\n' "$old_id"
)
```

On the operator host, re-run the **idempotent ledger transaction**, even if the count was zero. This repairs N3 rows that reappeared and ensures the next block has a clean ledger. Run it only after every node container is stopped:

```sh
(
  set -euo pipefail
  psql "$TC780_DATABASE_URL" -v ON_ERROR_STOP=1 <<'SQL'
BEGIN;
DROP TABLE IF EXISTS database_identity_fence, database_alias, database_legacy_artifact;
DELETE FROM seaql_migrations WHERE version IN ('m20261007_000000_database_alias','m20261007_010000_database_identity_fence');
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM seaql_migrations WHERE version IN ('m20261007_000000_database_alias','m20261007_010000_database_identity_fence')) THEN
    RAISE EXCEPTION 'N3 migration ledger remains';
  END IF;
END $$;
COMMIT;
SQL
)
```

Only after that transaction commits, on the CVM start the existing old container:

```sh
(
  set -euo pipefail
  test -n "$TC780_OLD_IMAGE"
  old_id=''
  while IFS= read -r node_id; do
    test -n "$node_id" || continue
    if test "$(docker inspect "$node_id" --format '{{.Config.Image}}')" = "$TC780_OLD_IMAGE"; then
      test -z "$old_id" || { echo 'multiple old containers; halt' >&2; exit 1; }
      old_id="$node_id"
    fi
  done <<< "$(docker ps -a --filter label=com.docker.compose.service=tinycloud --quiet)"
  test -n "$old_id" || { echo 'old container absent; keep node stopped and escalate' >&2; exit 1; }
  test "$(docker ps --filter label=com.docker.compose.service=tinycloud --quiet | grep -c . || true)" -eq 0
  if test "$(docker inspect "$old_id" --format '{{.State.Running}}')" = false; then docker start "$old_id"; fi
  test "$(docker inspect "$old_id" --format '{{.State.Running}}')" = true
)
```

Check `/healthz`, `/version` against the recorded old version and the approved signed SQL read. Recheck that the N3 ledger rows are absent before admitting traffic. If the post-deploy ledger assertion fails, block traffic and repair the ledger with every node container stopped before attempting to boot the old image. If the old container is absent or cannot pass these checks, keep the node stopped and escalate the outage. On a promotion retry, clear the stale rollback run ID via the dispatch block, settle that new run, then repeat the Phala gate, ledger check, container stop and idempotent ledger transaction before starting the old container. Retry of the promotion block alone is insufficient when N3 rows have reappeared.

TC-767's ancestry guard is roll-forward only. `allow_non_descendant=true` plus the recorded digest/version/revision is its sanctioned emergency override; the workflow validates those labels. The N3 image-only config preflight is skipped for the old rollback image, while Compose validation still runs. Verify `/healthz`, `/version` matches `running_version` in the record and the approved signed SQL read.

**Never run `pg_restore --clean` with this operator dump on production.** The dump contains `database_artifact` schema but no artifact rows: a clean restore drops the production table and recreates it empty, wiping every artifact. It also loses every write since step 7: KV, delegations, invocations and shares, plus SQL writes after step 9. For disaster recovery, prefer a complete PlanetScale-managed backup. If recovering selected metadata from the operator dump, build a TOC list and exclude every artifact entry, then restore **to a fresh recovery database**, never directly to production:

```sh
(
  set -euo pipefail
  dump="$(jq -er '.backup' ./tc780-private/record.json)"
  pg_restore -l "$dump" > ./tc780-private/recovery.toc
  awk '/database_artifact/ && $0 !~ /^;/ {print ";" $0; next} {print}' \
    ./tc780-private/recovery.toc > ./tc780-private/recovery-without-artifacts.toc
  ! grep -E '^[0-9]+;.*database_artifact' ./tc780-private/recovery-without-artifacts.toc
  pg_restore --use-list=./tc780-private/recovery-without-artifacts.toc \
    --no-owner --no-privileges --single-transaction --exit-on-error \
    --dbname="$TC780_FRESH_RECOVERY_URL" "$dump"
)
```

Review recovered metadata and a complete artifact backup together before any separate disaster-recovery decision. Keep private records until the observation window closes, then securely delete them.

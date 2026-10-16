#!/usr/bin/env bash
# CI-only smoke of the published dstack compose's local data mount, using
# explicit Static keys instead of requiring a real dstack socket on the runner.
set -euo pipefail
umask 077
here="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
owner="$work/owner.key"
openssl rand -hex 32 > "$owner"
export TC1282_TEST_KEY="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')"
export COMPOSE_PROJECT_NAME=tc1282-dstack
compose() { docker compose -f "$here/docker-compose.dstack.yaml" -f "$here/deploy/personal-node/dstack-smoke.yaml" "$@"; }
trap 'compose down -v >/dev/null 2>&1 || true' EXIT

ready() {
  for _ in {1..40}; do
    if curl -fsS http://127.0.0.1:8000/healthz -o /dev/null; then return; fi
    sleep 2
  done
  printf '%s\n' 'Dstack-profile health check failed' >&2
  exit 1
}

compose up -d tinycloud
ready
curl -fsS http://127.0.0.1:8000/version |
  jq -e '.version == "1.20.6" and (.features | index("tee") != null) and .inTEE == false' >/dev/null ||
  { printf '%s\n' 'Dstack profile did not run the pinned dstack build' >&2; exit 1; }
"$here/test/probe/node_modules/.bin/tsx" "$here/test/probe/personal-node-check.ts" seed http://127.0.0.1:8000 "$owner"
compose down
compose up -d tinycloud
ready
"$here/test/probe/node_modules/.bin/tsx" "$here/test/probe/personal-node-check.ts" verify http://127.0.0.1:8000 "$owner"
printf '%s\n' 'Dstack compose local SQLite and blocks survived container recreation'

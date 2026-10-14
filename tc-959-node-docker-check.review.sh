#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(git rev-parse --show-toplevel)
BASE_COMPOSE="$ROOT/docker-compose.dstack-postgres.yaml"
VECTOR_BIN=${TC_VECTOR_BIN:-/tmp/tc959-vector-0.59.0/vector-x86_64-unknown-linux-musl/bin/vector}
DRY_RUN=${TC_DRY_RUN:-0}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tc959-gelf-check.XXXXXX")
CONTROL="$WORK/control"
mkdir -p "$CONTROL"
PROJECT="tc959-gelf-$$"
OVERRIDE="$WORK/compose.override.yaml"
VECTOR_TEST_CONFIG="$WORK/vector.acceptance.yaml"
NATIVE_VECTOR_CONFIG="$WORK/vector.native.yaml"
NATIVE_SECRET_DIR="$WORK/native-secrets"
NATIVE_DATA_DIR="$WORK/native-data"
SENDER="$WORK/send-gelf.mjs"
ENV_FILE="$WORK/acceptance.env"
REPORT=${TC_REPORT:-"/tmp/tc959-node-gelf-check-$$.txt"}
COMPOSE=(docker compose --env-file "$ENV_FILE" --project-directory "$ROOT" -p "$PROJECT" -f "$BASE_COMPOSE" -f "$OVERRIDE")
VECTOR_ID=""
NODE_ID=""
PG_ID=""
STARTED=0
SAMPLER_PID=""
SAMPLER_STOP="$WORK/sample-memory"

record() { printf '%s\n' "$*" | tee -a "$REPORT"; }
docker_cmd() {
  if [[ "$DRY_RUN" == 1 ]]; then
    record "DRY-RUN docker $*"
    return 0
  fi
  command docker "$@"
}
compose_cmd() {
  if [[ "$DRY_RUN" == 1 ]]; then
    record "DRY-RUN compose $*"
    return 0
  fi
  "${COMPOSE[@]}" "$@"
}
memory_sampler() {
  local peak=0 container running current
  while [[ -f "$SAMPLER_STOP" ]]; do
    container=$("${COMPOSE[@]}" ps -q vector 2>/dev/null || true)
    if [[ -n "$container" ]]; then
      running=$(command docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null || true)
      if [[ "$running" == true ]]; then
        current=$(command docker stats --no-stream --format '{{.MemUsage}}' "$container" 2>/dev/null | awk '{value=$1; amount=value; sub(/[A-Za-z].*$/, "", amount); unit=substr(value, length(amount)+1); multiplier=unit=="GiB"?1073741824:unit=="MiB"?1048576:unit=="KiB"?1024:1; printf "%.0f", amount*multiplier}' || true)
        [[ "$current" =~ ^[0-9]+$ ]] || current=0
        (( current > peak )) && peak=$current
      fi
    fi
    printf '%s\n' "$peak" >"$WORK/vector-peak-bytes"
    sleep 0.2
  done
}

cleanup() {
  local status=$?
  if [[ -n "$SAMPLER_PID" ]]; then
    rm -f "$SAMPLER_STOP"
    wait "$SAMPLER_PID" || true
  fi
  if [[ "$DRY_RUN" != 1 && "$STARTED" == 1 ]]; then
    compose_cmd down --remove-orphans --volumes >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT

fail() { record "FAIL: $*"; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }

record "TC-959 GELF/UDP acceptance; project=$PROJECT; report=$REPORT"
record "This script is review-only. Run only after the lead authorizes Docker."

require node
[[ -x "$VECTOR_BIN" ]] || fail "native Vector binary not executable: $VECTOR_BIN"
mkdir -p "$NATIVE_SECRET_DIR" "$NATIVE_DATA_DIR"
printf '%s\n' 'tc959-dummy-token-only' >"$NATIVE_SECRET_DIR/bs_token"
chmod 0644 "$NATIVE_SECRET_DIR/bs_token"
node - "$ROOT/log-shipper/vector.yaml" "$NATIVE_VECTOR_CONFIG" "$NATIVE_SECRET_DIR" "$NATIVE_DATA_DIR" <<'NODE'
const fs = require('node:fs');
const [sourcePath, targetPath, secretDir, dataDir] = process.argv.slice(2);
let config = fs.readFileSync(sourcePath, 'utf8');
for (const [from, to] of [['/var/lib/vector/secrets', secretDir], ['/var/lib/vector', dataDir]]) {
  if (!config.includes(from)) throw new Error(`canonical Vector config is missing ${from}`);
  config = config.replaceAll(from, to);
}
fs.writeFileSync(targetPath, config, { mode: 0o600 });
NODE
node "$ROOT/scripts/node-vector-schema.mjs" --check || fail "generated schema check failed"
node "$ROOT/scripts/node-vector-schema.mjs" --check-compose || fail "embedded Compose parity failed"
node --test "$ROOT/scripts/node-vector-schema.test.mjs" || fail "schema/packaging tests failed"
"$VECTOR_BIN" validate --no-environment "$NATIVE_VECTOR_CONFIG" || fail "native Vector validation failed"
"$VECTOR_BIN" test "$NATIVE_VECTOR_CONFIG" "$ROOT/log-shipper/vector.tests.yaml" || fail "native Vector tests failed"
record "PASS: native checks used only a disposable dummy token fixture before any Docker operation"

cat >"$ENV_FILE" <<'EOF'
DATABASE_URL=postgres://postgres@postgres:5432/postgres?sslmode=disable
S3_BUCKET=acceptance-unused
S3_ENDPOINT=http://127.0.0.1:9
AWS_KEY=acceptance-unused
AWS_SECRET=acceptance-unused
AWS_REGION=us-east-1
SQL_IDENTITY_FENCE=true
SHARE_TRUST_BUNDLE_BASE64=e30=
TINYCLOUD_QUOTA_URL=http://127.0.0.1:9
TINYCLOUD_ADMIN_SECRET=
CLOUDFLARE_API_TOKEN=acceptance-unused
DSTACK_GATEWAY_DOMAIN=invalid.test
CERTBOT_EMAIL=acceptance@example.invalid
EOF

node - "$ROOT/log-shipper/vector.yaml" "$VECTOR_TEST_CONFIG" <<'NODE'
const fs = require('node:fs');
const [sourcePath, targetPath] = process.argv.slice(2);
let config = fs.readFileSync(sourcePath, 'utf8');
const sinkAt = config.lastIndexOf('\nsinks:\n');
if (sinkAt < 0) throw new Error('canonical sink block not found');
const metricSource = '  internal_metrics:\n    type: internal_metrics\n';
if (!config.includes('\ntransforms:\n')) throw new Error('canonical transforms block not found');
config = config.replace('\ntransforms:\n', `\n${metricSource}transforms:\n`);
const updatedSinkAt = config.lastIndexOf('\nsinks:\n');
config = config.slice(0, updatedSinkAt) + `\nsinks:\n  local_console:\n    type: console\n    inputs: [budget_size_guard]\n    encoding: { codec: json }\n  metrics_exporter:\n    type: prometheus_exporter\n    inputs: [internal_metrics]\n    address: 0.0.0.0:9598\n`;
fs.writeFileSync(targetPath, config, { mode: 0o644 });
fs.chmodSync(targetPath, 0o644);
NODE
"$VECTOR_BIN" validate --no-environment "$VECTOR_TEST_CONFIG" || fail "acceptance Vector config validation failed"

cat >"$SENDER" <<'NODE'
import { createSocket } from 'node:dgram';
const [host, portText, payload] = process.argv.slice(2);
if (!host || !portText || !payload) throw new Error('usage: send-gelf HOST PORT JSON');
const socket = createSocket('udp4');
socket.send(Buffer.from(payload), Number(portText), host, (error) => {
  socket.close();
  if (error) {
    console.error(`GELF UDP send failed to ${host}:${portText}: ${error.code ?? error.message}`);
    process.exitCode = 1;
  }
});
NODE
chmod 0644 "$SENDER"

cat >"$OVERRIDE" <<EOF
services:
  tinycloud:
    volumes: !override []
    depends_on:
      postgres:
        condition: service_healthy
    ports: !override
      - "127.0.0.1:18000:8000"
    environment: !override
      TINYCLOUD_KEYS_TYPE: Static
      TINYCLOUD_KEYS_SECRET: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
      TINYCLOUD_TEE__MODE: Off
      TINYCLOUD_STORAGE_DATABASE: postgres://postgres@postgres:5432/postgres?sslmode=disable
      TINYCLOUD_STORAGE_BLOCKS_TYPE: Local
      TINYCLOUD_LOG__FORMAT: Json
      TINYCLOUD_DATABASE__WRITE_FENCE: "true"
      TINYCLOUD_SHARE_EMAIL__ENABLED: "false"
      TINYCLOUD_ADMIN_SECRET: ""
      TINYCLOUD_QUOTA_URL: http://127.0.0.1:9
      ROCKET_ADDRESS: 0.0.0.0
    extra_hosts:
      - "host.docker.internal:host-gateway"
  dstack-ingress:
    image: alpine:3.21
    entrypoint: ["/bin/sh", "-ec"]
    command: |
      emit() { printf '%s\n' '{"time":"2026-10-14T10:00:00+00:00","method":"GET","route":"/info","protocol":"HTTP/1.1","status":200,"bytes":32,"request_time":1.25,"upstream_status":"200"}; }
      while :; do
        if [ -f /control/burst ]; then
          count=\$\$(cat /control/burst)
          rm -f /control/burst
          i=0
          while [ "\$\$i" -lt "\$\$count" ]; do emit; i=\$\$((i + 1)); done
          touch /control/burst-done
        elif [ -f /control/pulse ]; then
          rm -f /control/pulse
          emit
        fi
        sleep 0.05
      done
    volumes: !override
      - "$CONTROL:/control"
    ports: !override []
  vector:
    entrypoint: ["/bin/sh", "-ec"]
    command: "mkdir -p /var/lib/vector/secrets && printf '%s\\n' tc959-dummy-token-only > /var/lib/vector/secrets/bs_token && chmod 0644 /var/lib/vector/secrets/bs_token && exec vector --config /etc/vector/acceptance.yaml"
    volumes:
      - "$VECTOR_TEST_CONFIG:/etc/vector/acceptance.yaml:ro"
    ports:
      - "127.0.0.1:9598:9598/tcp"
  postgres:
    image: postgres:16.6-alpine
    restart: unless-stopped
    environment:
      POSTGRES_HOST_AUTH_METHOD: trust
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 2s
      timeout: 2s
      retries: 30
    extra_hosts:
      - "host.docker.internal:host-gateway"
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
  app-net-probe:
    image: alpine:3.21
    network_mode: "service:tinycloud"
    depends_on:
      - tinycloud
    command: ["/bin/sh", "-ec", "while :; do sleep 3600; done"]
    extra_hosts:
      - "host.docker.internal:host-gateway"
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
EOF
node - "$OVERRIDE" <<'NODE'
const fs = require('node:fs');
const override = fs.readFileSync(process.argv[2], 'utf8');
for (const fragment of [
  'count=$$(cat /control/burst)',
  'while [ "$$i" -lt "$$count" ]',
  'i=$$((i + 1))',
]) {
  if (!override.includes(fragment)) throw new Error(`rendered producer command lost Compose escaping: ${fragment}`);
}
NODE

if [[ "$DRY_RUN" == 1 ]]; then
  record "DRY-RUN: no Docker command invoked"
  record "DRY-RUN: start local Postgres, test-only Static-key/TEE-Off node, labelled ingress producer, isolated Vector and network probes"
  record "DRY-RUN: 5x restart, 5x SIGKILL/restart-policy recovery, 5x Vector recreate; each next labelled line <=20s and no duplicate output"
  record "DRY-RUN: 3x Vector-down 500-line bursts; recover and verify next labelled line <=20s"
  record "DRY-RUN: app restart count unchanged; /version responds 10/10 while Vector is stopped"
  record "DRY-RUN: positive host-loopback and logship-control-container probes require source +1 and shipped +1"
  record "DRY-RUN: node/ingress/Postgres sibling and host external-interface probes require source +0 and shipped +0, using parsed Prometheus values"
  record "DRY-RUN: sample Vector peak RSS; 5,000-line delivery-loss percentage is informational"
  record "DRY-RUN: actual Docker, network and memory checks NOT run"
  exit 0
fi

require docker
require curl
require ip
docker compose version >/dev/null || fail "Docker Compose v2 is required"
record "Preflight: no DockerRootDir assumption; this GELF topology has no host Docker-directory access."

# Continue below only on an explicitly Docker-authorized acceptance host.
STARTED=1
compose_cmd up -d --wait postgres tinycloud dstack-ingress vector app-net-probe
touch "$SAMPLER_STOP"
memory_sampler &
SAMPLER_PID=$!

wait_vector() {
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    VECTOR_ID=$(compose_cmd ps -q vector)
    if [[ -n "$VECTOR_ID" ]] && [[ "$(docker_cmd inspect -f '{{.State.Running}}' "$VECTOR_ID")" == true ]] && curl --fail --silent --max-time 1 http://127.0.0.1:9598/metrics >/dev/null; then return 0; fi
    sleep 0.2
  done
  fail "Vector did not become running within 20 seconds"
}
wait_node() {
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if curl --fail --silent --max-time 2 http://127.0.0.1:18000/version >/dev/null; then return 0; fi
    sleep 0.5
  done
  fail "node did not serve /version within 30 seconds"
}
read_metric() {
  curl --fail --silent http://127.0.0.1:9598/metrics | node "$ROOT/scripts/tc-959-vector-metrics.mjs" received-counter
}
wait_metric() {
  local deadline=$((SECONDS + 20)) value
  while (( SECONDS < deadline )); do
    value=$(read_metric)
    if [[ "$value" =~ ^[0-9]+$ ]] && (( value >= ${1:-1} )); then printf '%s\n' "$value"; return 0; fi
    sleep 0.25
  done
  fail "Vector GELF receive metric did not reach ${1:-1}"
}
vector_shipped_count() {
  [[ "$(docker_cmd inspect -f '{{.State.Running}}' "$VECTOR_ID")" == true ]] || fail "refusing to read events from a stopped Vector container"
  docker_cmd logs "$VECTOR_ID" 2>&1 | node "$ROOT/scripts/tc-959-vector-metrics.mjs" shipped-count
}
vector_event_count() {
  [[ "$(docker_cmd inspect -f '{{.State.Running}}' "$VECTOR_ID")" == true ]] || fail "refusing to read events from a stopped Vector container"
  docker_cmd logs "$VECTOR_ID" 2>&1 | node "$ROOT/scripts/tc-959-vector-metrics.mjs" event-count ingress_request_slow
}
wait_next_line() {
  local previous=${1:-0} deadline=$((SECONDS + 20)) current
  touch "$CONTROL/pulse"
  while (( SECONDS < deadline )); do
    wait_vector
    current=$(vector_event_count)
    if (( current > previous )); then
      sleep 0.4
      current=$(vector_event_count)
      (( current == previous + 1 )) || fail "duplicate/flood output after Vector recovery: expected one line, saw $((current - previous))"
      return 0
    fi
    sleep 0.2
  done
  fail "next labelled line not observed within 20 seconds"
}

compose_cmd ps -q tinycloud >/dev/null
NODE_ID=$(compose_cmd ps -q tinycloud)
PG_ID=$(compose_cmd ps -q postgres)
[[ -n "$NODE_ID" && -n "$PG_ID" ]] || fail "node or Postgres container missing"
node_restarts=$(docker_cmd inspect -f '{{.RestartCount}}' "$NODE_ID")
wait_vector
wait_node
curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18000/version >/dev/null || fail "node did not serve /version without dstack"
wait_next_line 0
wait_metric 1 >/dev/null
record "PASS: node serves /version with test-only Static key, TEE Off, local Postgres, and no dstack mount"

for mode in restart crash recreate; do
  for iteration in 1 2 3 4 5; do
    case "$mode" in
      restart)
        before=$(vector_event_count)
        compose_cmd restart vector >/dev/null
        wait_vector
        wait_next_line "$before"
        ;;
      crash)
        before=$(vector_event_count)
        docker_cmd kill --signal KILL "$VECTOR_ID" >/dev/null
        deadline=$((SECONDS + 20))
        while (( SECONDS < deadline )); do
          if [[ "$(docker_cmd inspect -f '{{.State.Running}}' "$VECTOR_ID" 2>/dev/null || true)" == true ]]; then break; fi
          sleep 0.2
        done
        wait_vector
        wait_next_line "$before"
        ;;
      recreate)
        compose_cmd up -d --force-recreate --no-deps vector >/dev/null
        wait_vector
        wait_next_line 0
        ;;
    esac
    record "PASS: $mode recovery $iteration/5; next labelled line <=20s; one output; app remains up"
  done
done

for iteration in 1 2 3; do
  before=$(vector_event_count)
  compose_cmd stop vector >/dev/null
  printf '%s\n' 500 >"$CONTROL/burst"
  deadline=$((SECONDS + 20))
  while [[ ! -f "$CONTROL/burst-done" ]] && (( SECONDS < deadline )); do sleep 0.1; done
  [[ -f "$CONTROL/burst-done" ]] || fail "ingress 500-line outage burst did not complete"
  rm -f "$CONTROL/burst-done"
  compose_cmd start vector >/dev/null
  wait_vector
  wait_next_line "$before"
  record "PASS: Vector-down 500-line burst $iteration/3; next labelled line <=20s"
done

node_restarts_after=$(docker_cmd inspect -f '{{.RestartCount}}' "$NODE_ID")
[[ "$node_restarts" == "$node_restarts_after" ]] || fail "node restarted during Vector recovery matrix"
record "PASS: app restart count unchanged across all Vector recovery tests"

before_metric=$(wait_metric 0)
printf '%s\n' 5000 >"$CONTROL/burst"
deadline=$((SECONDS + 30))
while [[ ! -f "$CONTROL/burst-done" ]] && (( SECONDS < deadline )); do sleep 0.1; done
[[ -f "$CONTROL/burst-done" ]] || fail "5,000-line producer burst did not complete"
rm -f "$CONTROL/burst-done"
deadline=$((SECONDS + 20))
after_metric=$before_metric
while (( SECONDS < deadline )); do
  after_metric=$(read_metric)
  [[ "$after_metric" =~ ^[0-9]+$ ]] || after_metric=$before_metric
  (( after_metric >= before_metric + 5000 )) && break
  sleep 0.5
done
loss=100
if (( after_metric >= before_metric )); then loss=$(( (5000 - (after_metric - before_metric)) * 100 / 5000 )); (( loss < 0 )) && loss=0; fi
record "INFO: 5,000-line receive count delta=$((after_metric - before_metric)); estimated transport loss=${loss}% (informational)"

# Keep the idle synthetic ingress up so its network namespace is available for sibling probes.
sleep 1
payload='{"version":"1.1","host":"tc959-isolation-probe","short_message":"{\"timestamp\":\"2026-10-14T10:00:00.000Z\",\"level\":\"WARN\",\"fields\":{\"message\":\"invocation replay insert failed\"}}","timestamp":1760436000,"level":4,"_tc.logship":"tinycloud-node"}'
vector_ip=10.255.253.2
app_gateway=$(docker_cmd inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$NODE_ID")
INGRESS_ID=$(compose_cmd ps -q dstack-ingress)
[[ -n "$INGRESS_ID" ]] || fail "ingress control container missing"

send_from_container() {
  local network=$1 target=$2
  docker_cmd run --rm --network "$network" --mount "type=bind,src=$SENDER,dst=/sender.mjs,readonly" node:20-alpine node /sender.mjs "$target" 12201 "$payload"
}
assert_positive_delivery() {
  local source_before=$1 shipped_before=$2 description=$3 deadline=$((SECONDS + 20)) source_after shipped_after source_delta shipped_delta
  while (( SECONDS < deadline )); do
    source_after=$(read_metric)
    shipped_after=$(vector_shipped_count)
    [[ "$source_after" =~ ^[0-9]+$ && "$shipped_after" =~ ^[0-9]+$ ]] || fail "invalid Vector counters during $description"
    source_delta=$((source_after - source_before))
    shipped_delta=$((shipped_after - shipped_before))
    if (( source_delta == 1 && shipped_delta == 1 )); then
      record "PASS: $description positive control; source +1 and shipped +1"
      return 0
    fi
    (( source_delta <= 1 && shipped_delta <= 1 )) || fail "$description produced duplicate source/shipped events: source +$source_delta, shipped +$shipped_delta"
    sleep 0.2
  done
  fail "$description positive control failed: source +$source_delta, shipped +$shipped_delta"
}

# Positive controls prove both paths before attempting forbidden sibling/external sources.
source_before=$(wait_metric 0)
shipped_before=$(vector_shipped_count)
node "$SENDER" 127.0.0.1 12201 "$payload"
assert_positive_delivery "$source_before" "$shipped_before" "host loopback"

source_before=$(wait_metric 0)
shipped_before=$(vector_shipped_count)
send_from_container "${PROJECT}_logship" "$vector_ip"
assert_positive_delivery "$source_before" "$shipped_before" "logship-network control container"

assert_isolated_probe() {
  local description=$1 network=$2 target=$3 source_before shipped_before send_status=0 source_after shipped_after
  source_before=$(wait_metric 0)
  shipped_before=$(vector_shipped_count)
  if send_from_container "$network" "$target"; then
    record "INFO: $description sender completed"
  else
    send_status=$?
    record "INFO: $description sender reported transport error exit=$send_status"
  fi
  sleep 0.5
  source_after=$(read_metric)
  shipped_after=$(vector_shipped_count)
  [[ "$source_after" =~ ^[0-9]+$ && "$shipped_after" =~ ^[0-9]+$ ]] || fail "invalid Vector counters during $description"
  [[ "$source_after" == "$source_before" ]] || fail "$description isolation leak: source counter changed $source_before -> $source_after"
  [[ "$shipped_after" == "$shipped_before" ]] || fail "$description isolation leak: shipped count changed $shipped_before -> $shipped_after"
  record "PASS: $description isolation; source +0 and shipped +0"
}

probe_targets=("$vector_ip" "$app_gateway" vector host.docker.internal 127.0.0.1)
for target in "${probe_targets[@]}"; do
  assert_isolated_probe "node->$target" "container:$NODE_ID" "$target"
  assert_isolated_probe "ingress->$target" "container:$INGRESS_ID" "$target"
  assert_isolated_probe "postgres->$target" "container:$PG_ID" "$target"
done

host_ips=$(ip -o -4 addr show scope global | awk '{split($4,a,"/"); print a[1]}')
[[ -n "$host_ips" ]] || fail "no non-loopback IPv4 interface available for external-interface isolation probes"
while read -r host_ip; do
  [[ -n "$host_ip" ]] || continue
  source_before=$(wait_metric 0)
  shipped_before=$(vector_shipped_count)
  if node "$SENDER" "$host_ip" 12201 "$payload"; then
    record "INFO: host external-interface sender completed to $host_ip"
  else
    send_status=$?
    record "INFO: host external-interface sender reported transport error exit=$send_status for $host_ip"
  fi
  sleep 0.5
  source_after=$(read_metric)
  shipped_after=$(vector_shipped_count)
  [[ "$source_after" =~ ^[0-9]+$ && "$shipped_after" =~ ^[0-9]+$ ]] || fail "invalid Vector counters during host interface $host_ip probe"
  [[ "$source_after" == "$source_before" ]] || fail "host interface $host_ip isolation leak: source $source_before -> $source_after"
  [[ "$shipped_after" == "$shipped_before" ]] || fail "host interface $host_ip isolation leak: shipped $shipped_before -> $shipped_after"
  record "PASS: host external interface $host_ip isolation; source +0 and shipped +0"
done <<<"$host_ips"

compose_cmd stop vector >/dev/null
max_ms=0
for _ in 1 2 3 4 5 6 7 8 9 10; do
  start_ms=$(date +%s%3N)
  curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18000/version >/dev/null || fail "node stopped serving while Vector was down"
  end_ms=$(date +%s%3N)
  elapsed=$((end_ms - start_ms))
  (( elapsed > max_ms )) && max_ms=$elapsed
 done
node_restarts_after=$(docker_cmd inspect -f '{{.RestartCount}}' "$NODE_ID")
[[ "$node_restarts" == "$node_restarts_after" ]] || fail "node restarted with Vector stopped"
record "PASS: node served /version 10/10 with Vector down; max sampled latency=${max_ms}ms"
compose_cmd start vector >/dev/null
wait_vector
rm -f "$SAMPLER_STOP"
wait "$SAMPLER_PID"
SAMPLER_PID=""
peak_bytes=$(cat "$WORK/vector-peak-bytes")
record "INFO: sampled Vector peak RSS=$peak_bytes bytes (64 MiB configured limit)"
(( peak_bytes <= 64 * 1024 * 1024 )) || fail "Vector sampled RSS exceeded its 64 MiB memory cap"
record "PASS: complete Docker acceptance matrix"

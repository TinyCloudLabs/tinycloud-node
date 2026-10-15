#!/usr/bin/env bash
umask 077
set -Eeuo pipefail

ROOT=$(git rev-parse --show-toplevel)
BASE_COMPOSE="$ROOT/docker-compose.dstack-postgres.yaml"
VECTOR_BIN=${TC_VECTOR_BIN:-/tmp/tc959-vector-0.59.0/vector-x86_64-unknown-linux-musl/bin/vector}
DRY_RUN=${TC_DRY_RUN:-0}
WORK=$(mktemp -d "${TMPDIR:-/tmp}/tc959-gelf-check.XXXXXX")
CPU_OVERRIDE="$WORK/compose.cpu-override.yaml"
CONTROL="$WORK/control"
mkdir -p "$CONTROL"
PROJECT="tc959-gelf-$$"
OVERRIDE="$WORK/compose.override.yaml"
VECTOR_REPLAY_CONFIG="$WORK/vector.acceptance.native.yaml"
VECTOR_TEST_CONFIG="$WORK/vector.acceptance.yaml"
NATIVE_VECTOR_CONFIG="$WORK/vector.native.yaml"
NATIVE_SECRET_DIR="$WORK/native-secrets"
NATIVE_DATA_DIR="$WORK/native-data"
SENDER="$WORK/send-gelf.mjs"
ENV_FILE="$WORK/acceptance.env"
REPORT=${TC_REPORT:-"/tmp/tc959-node-gelf-check-$$.txt"}
touch "$REPORT"
chmod 0600 "$REPORT"
COMPOSE=(docker compose --env-file "$ENV_FILE" --project-directory "$ROOT" -p "$PROJECT" -f "$BASE_COMPOSE" -f "$OVERRIDE")
VECTOR_ID=""
NODE_ID=""
PG_ID=""
STARTED=0
SAMPLER_PID=""
METRICS_SCRAPE_INTERVAL_SECONDS=1
ISOLATION_SETTLE_SECONDS=2
SAMPLER_STOP="$WORK/sample-memory"

record() { printf '%s\n' "$*" | tee -a "$REPORT"; }
docker_cmd() {
  if [[ "$DRY_RUN" == 1 ]]; then
    record "DRY-RUN docker $*"
    return 0
  fi
  if [[ "${1:-}" == timeout ]]; then
    local seconds=$2
    shift 2
    timeout "$seconds" docker "$@"
    return
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
compose_half_cpu_cmd() {
  if [[ "$DRY_RUN" == 1 ]]; then
    record "DRY-RUN compose -f $OVERRIDE -f $CPU_OVERRIDE $*"
    return 0
  fi
  "${COMPOSE[@]}" -f "$CPU_OVERRIDE" "$@"
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
        if (( current > peak )); then peak=$current; fi
      fi
    fi
    printf '%s\n' "$peak" >"$WORK/vector-peak-bytes"
    sleep 0.2
  done
}

cleanup() {
  local status=$? probe_id
  local -a probe_ids=()
  if [[ -n "$SAMPLER_PID" ]]; then
    rm -f "$SAMPLER_STOP"
    wait "$SAMPLER_PID" || true
  fi
  if [[ "$DRY_RUN" != 1 && "$STARTED" == 1 ]]; then
    mapfile -t probe_ids < <(docker_cmd ps -aq --filter "label=com.docker.compose.project=$PROJECT" --filter "label=tc959.probe=true" 2>/dev/null || true)
    for probe_id in "${probe_ids[@]}"; do
      [[ -n "$probe_id" ]] && docker_cmd rm -f "$probe_id" >/dev/null 2>&1 || true
    done
    compose_cmd down --remove-orphans --volumes >/dev/null 2>&1 || true
  fi
  rm -rf "$WORK"
  exit "$status"
}
trap cleanup EXIT

fail() { record "FAIL: $*"; exit 1; }
require() { command -v "$1" >/dev/null 2>&1 || fail "missing command: $1"; }
source "$ROOT/scripts/tc-959-isolation.sh"

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
node --test "$ROOT/scripts/node-vector-schema.test.mjs" "$ROOT/scripts/tc-959-vector-metrics.test.mjs" "$ROOT/scripts/tc-959-compose-env.test.mjs" || fail "schema, packaging, metrics, and compose environment tests failed"
bash "$ROOT/scripts/test-tc-959-isolation.sh" || fail "freshness and isolation helper tests failed"
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

node - "$ROOT/log-shipper/vector.yaml" "$VECTOR_TEST_CONFIG" "$VECTOR_REPLAY_CONFIG" "$NATIVE_SECRET_DIR" "$NATIVE_DATA_DIR" <<'NODE'
const fs = require('node:fs');
const [sourcePath, targetPath, replayPath, secretDir, dataDir] = process.argv.slice(2);
let config = fs.readFileSync(sourcePath, 'utf8');
const sinkAt = config.lastIndexOf('\nsinks:\n');
if (sinkAt < 0) throw new Error('canonical sink block not found');
const metricSource = '  internal_metrics:\n    type: internal_metrics\n    scrape_interval_secs: 1\n';
if (!config.includes('\ntransforms:\n')) throw new Error('canonical transforms block not found');
config = config.replace('\ntransforms:\n', `\n${metricSource}transforms:\n`);
const updatedSinkAt = config.lastIndexOf('\nsinks:\n');
config = config.slice(0, updatedSinkAt) + `\nsinks:\n  local_console:\n    type: console\n    inputs: [budget_size_guard]\n    encoding: { codec: json }\n  metrics_exporter:\n    type: prometheus_exporter\n    inputs: [internal_metrics]\n    address: 0.0.0.0:9598\n`;
fs.writeFileSync(targetPath, config, { mode: 0o644 });
fs.chmodSync(targetPath, 0o644);
const replayConfig = config.replaceAll('/var/lib/vector/secrets', secretDir).replaceAll('/var/lib/vector', dataDir);
fs.writeFileSync(replayPath, replayConfig, { mode: 0o644 });
fs.chmodSync(replayPath, 0o644);
NODE
"$VECTOR_BIN" validate --no-environment "$VECTOR_TEST_CONFIG" || fail "acceptance Vector config validation failed"
"$VECTOR_BIN" validate --no-environment "$VECTOR_REPLAY_CONFIG" || fail "native acceptance replay config validation failed"
node "$ROOT/scripts/tc-959-vector-env-replay.mjs" "$VECTOR_BIN" "$VECTOR_REPLAY_CONFIG" "$ROOT/log-shipper/vector.yaml" || fail "native Vector environment replay failed"

cat >"$SENDER" <<'NODE'
import { createSocket } from 'node:dgram';
const [host, portText, payload] = process.argv.slice(2);
if (!host || !portText || !payload) throw new Error('usage: send-gelf HOST PORT JSON');
const recognizedCodes = new Set(['ENOTFOUND', 'EAI_AGAIN', 'ENETUNREACH', 'EHOSTUNREACH', 'ECONNREFUSED']);
const socket = createSocket('udp4');
socket.send(Buffer.from(payload), Number(portText), host, (error) => {
  socket.close();
  if (error) {
    const code = recognizedCodes.has(error.code) ? error.code : 'other';
    console.error(`GELF_SEND_ERROR code=${code}`);
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
    image: alpine:3.21@sha256:ce64758a109eb420d874a118f87920e625e12d3634e03b4a5573fd9f6e5d3507
    environment: !override {}
    command:
      - /bin/sh
      - -ec
      - |
        emit() { printf '%s\n' '{"time":"2026-10-14T10:00:00+00:00","method":"GET","route":"/info","protocol":"HTTP/1.1","status":200,"bytes":32,"request_time":1.25,"upstream_status":"200"}'; }
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
    init: true
    entrypoint: !override ["/bin/sh", "-ec"]
    environment: !override {}
    command:
      - mkdir -p /var/lib/vector/secrets && printf '%s\\n' tc959-dummy-token-only > /var/lib/vector/secrets/bs_token && chmod 0644 /var/lib/vector/secrets/bs_token && exec env -u VECTOR_CONFIG_YAML -u BETTERSTACK_SOURCE_TOKEN -u BETTERSTACK_SOURCE_HOST vector --config /etc/vector/acceptance.yaml
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
EOF
cat >"$CPU_OVERRIDE" <<'EOF'
services:
  vector:
    cpus: 0.25
EOF
node - "$OVERRIDE" "$CPU_OVERRIDE" "$ROOT" "$ROOT/tc-959-node-docker-check.review.sh" "$VECTOR_TEST_CONFIG" <<'NODE'
const fs = require('node:fs');
const { spawnSync } = require('node:child_process');
const { createRequire } = require('node:module');
const requireFromRoot = createRequire(`${process.argv[4]}/package.json`);
const { parse } = requireFromRoot('yaml');
const [overridePath, cpuOverridePath, root, harnessPath, vectorConfigPath] = process.argv.slice(2);
const composeText = fs.readFileSync(overridePath, 'utf8');
const cpuOverride = parse(fs.readFileSync(cpuOverridePath, 'utf8'));
const compose = parse(composeText.replaceAll('!override', ''));
if (cpuOverride.services?.vector?.cpus !== 0.25) throw new Error('half-CPU override must set only Vector cpus: 0.25');
const baseCompose = parse(fs.readFileSync(`${root}/docker-compose.dstack-postgres.yaml`, 'utf8'));
const baseVectorEnv = baseCompose.services.vector.environment ?? {};
if (!Object.hasOwn(baseVectorEnv, 'VECTOR_CONFIG_YAML') || !Object.hasOwn(baseVectorEnv, 'BETTERSTACK_SOURCE_TOKEN')) {
  throw new Error('base Vector environment regression fixture is missing');
}
if (baseCompose.services?.vector?.init !== true) {
  throw new Error('production Vector service must set init: true for restart supervision');
}
if (baseCompose.services?.vector?.cpus !== 0.5) throw new Error('production Vector CPU setting changed unexpectedly');
const vectorEnv = compose.services?.vector?.environment;
if (!vectorEnv || Object.keys(vectorEnv).length !== 0) throw new Error('acceptance Vector environment must be explicitly empty');
const ingressEnv = compose.services?.['dstack-ingress']?.environment;
if (!ingressEnv || Object.keys(ingressEnv).length !== 0) throw new Error('acceptance ingress environment must be explicitly empty');
const postgresEnv = compose.services?.postgres?.environment ?? {};
if (Object.keys(postgresEnv).some((name) => name.startsWith('TINYCLOUD_'))) {
  throw new Error('acceptance Postgres environment must not inherit TINYCLOUD_* variables');
}
const nodeEnv = compose.services?.tinycloud?.environment ?? {};
if (nodeEnv.TINYCLOUD_KEYS_TYPE !== 'Static' || nodeEnv.TINYCLOUD_TEE__MODE !== 'Off') {
  throw new Error('acceptance node lost its test-only environment override');
}
const envCheck = spawnSync(process.execPath, [`${root}/scripts/tc-959-compose-env.mjs`], {
  input: JSON.stringify({ services: {
    tinycloud: { environment: nodeEnv },
    'dstack-ingress': { environment: ingressEnv },
    postgres: { environment: postgresEnv },
    vector: { init: true, environment: vectorEnv },
  } }),
  encoding: 'utf8',
});
if (envCheck.status !== 0) throw new Error(`acceptance service environments failed: ${envCheck.stderr}`);
const ingressCommand = compose.services?.['dstack-ingress']?.command;
if (!Array.isArray(ingressCommand) || ingressCommand.length !== 3 ||
    ingressCommand[0] !== '/bin/sh' || ingressCommand[1] !== '-ec' || typeof ingressCommand[2] !== 'string') {
  throw new Error('dstack-ingress effective Compose argv must be [/bin/sh, -ec, script]');
}
const vector = compose.services?.vector;
if (vector?.init !== true) throw new Error('acceptance Vector service must set init: true');
if (JSON.stringify(vector?.entrypoint) !== JSON.stringify(['/bin/sh', '-ec']) ||
    !Array.isArray(vector.command) || vector.command.length !== 1 || typeof vector.command[0] !== 'string') {
  throw new Error('vector must override the production entrypoint and use a one-script command');
}
const effectiveArgv = [...vector.entrypoint, ...vector.command].map((argument) => argument.replaceAll('$$', '$'));
const expectedVectorScript = String.raw`mkdir -p /var/lib/vector/secrets && printf '%s\n' tc959-dummy-token-only > /var/lib/vector/secrets/bs_token && chmod 0644 /var/lib/vector/secrets/bs_token && exec env -u VECTOR_CONFIG_YAML -u BETTERSTACK_SOURCE_TOKEN -u BETTERSTACK_SOURCE_HOST vector --config /etc/vector/acceptance.yaml`;
const expectedVectorArgv = ['/bin/sh', '-ec', expectedVectorScript];
if (JSON.stringify(effectiveArgv) !== JSON.stringify(expectedVectorArgv)) {
  throw new Error(`vector effective argv mismatch: ${JSON.stringify(effectiveArgv)}`);
}
const vectorConfig = fs.readFileSync(vectorConfigPath, 'utf8');
for (const fragment of ['allowlist:', 'budget_size_guard:', 'local_console:', 'metrics_exporter:']) {
  if (!vectorConfig.includes(fragment)) throw new Error(`acceptance Vector config is missing ${fragment}`);
}
for (const [name, argv] of [['dstack-ingress', ingressCommand.map((argument) => argument.replaceAll('$$', '$'))], ['vector', effectiveArgv]]) {
  const syntax = spawnSync('sh', ['-n'], { input: argv[2], encoding: 'utf8' });
  if (syntax.status !== 0) throw new Error(`${name} generated shell is invalid: ${syntax.stderr}`);
}
const ingress = ingressCommand[2];
for (const fragment of ['count=$$(cat /control/burst)', 'while [ "$$i" -lt "$$count" ]', 'i=$$((i + 1))']) {
  if (!ingress.includes(fragment)) throw new Error(`rendered producer command lost Compose escaping: ${fragment}`);
}
const libraryPath = `${root}/scripts/tc-959-isolation.sh`;
const harnessSource = fs.readFileSync(harnessPath, 'utf8');
if (!harnessSource.split(/\r?\n/).slice(1, 3).includes('set -Eeuo pipefail')) {
  throw new Error('harness must keep set -Eeuo pipefail on line 2 or 3');
}
const shellSources = [harnessSource, fs.readFileSync(libraryPath, 'utf8')];
const declared = new Set(shellSources.flatMap((source) =>
  [...source.matchAll(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(\)\s*\{/gm)].map((match) => match[1])));
const calledHelpers = [
  'record', 'docker_cmd', 'compose_cmd', 'memory_sampler', 'cleanup', 'fail', 'require',
  'check_host_ports_free', 'crash_vector',
  'wait_fresh_stable_metric', 'fresh_sample', 'wait_metric', 'vector_shipped_count',
  'vector_shipped_name_counts', 'report_shipped_event_delta', 'vector_event_count',
  'assert_no_console_marker', 'wait_next_line', 'send_from_container', 'send_probe',
  'send_positive_probe', 'run_probe_sender', 'sender_error_code', 'probe_routing_error_matches_target',
  'probe_target_is_name', 'name_network_names_from_json', 'name_network_container_ids_from_json',
  'name_peer_matches_target', 'hosts_file_has_name', 'name_resolver_positive_control',
  'read_target_hosts_file', 'prove_name_target_structure',
  'compose_half_cpu_cmd', 'measure_burst', 'run_isolation_leak_self_test',
];
const missing = calledHelpers.filter((name) => !declared.has(name));
if (missing.length) throw new Error(`harness calls undefined shell functions: ${missing.join(', ')}`);
for (const shellFile of [harnessPath, libraryPath, `${root}/scripts/test-tc-959-isolation.sh`]) {
  const syntax = spawnSync('bash', ['-n', shellFile], { encoding: 'utf8' });
  if (syntax.status !== 0) throw new Error(`${shellFile} has invalid Bash syntax: ${syntax.stderr}`);
}
NODE
if [[ "$DRY_RUN" == 1 ]]; then
  record "DRY-RUN: no Docker command invoked"
  docker_cmd version
  compose_cmd config
  record "DRY-RUN: acceptance self-test expects an allowed host-loopback packet to make the negative check fail"
  record "DRY-RUN: positive controls require source +1 and exact event=node_warning/event_code=invocation_replay_insert_failed shipped +1"
  record "DRY-RUN: negative probes require source +0 and exact probe shipped +0; unrelated event deltas print event/event_code enums"
  record "DRY-RUN: 5,000-line bursts measured with fresh source samples at production cpus=0.5 and temporary cpus=0.25"
  record "DRY-RUN: half-CPU Vector is recreated only for the second burst and production cpus=0.5 restored before isolation"
  record "DRY-RUN: actual Docker, network and memory checks NOT run"
  exit 0
fi

require docker
require timeout
require curl
require ip
require ss
check_host_ports_free
docker compose version >/dev/null || fail "Docker Compose v2 is required"
if ! "${COMPOSE[@]}" config --format json | node "$ROOT/scripts/tc-959-compose-env.mjs"; then
  fail "rendered Compose environment isolation failed"
fi
record "Preflight: no DockerRootDir assumption; no host Docker-directory access."
record "Metrics freshness: internal_metrics scrape interval=${METRICS_SCRAPE_INTERVAL_SECONDS}s; isolation settle=${ISOLATION_SETTLE_SECONDS}s; require two strictly newer timestamps with stable source value."

# Continue below only on an explicitly Docker-authorized acceptance host.
STARTED=1
compose_cmd up -d --wait postgres tinycloud dstack-ingress vector
touch "$SAMPLER_STOP"
memory_sampler &
SAMPLER_PID=$!

read_metric() {
  curl --fail --silent http://127.0.0.1:9598/metrics | node "$ROOT/scripts/tc-959-vector-metrics.mjs" received-counter
}
read_metric_sample() {
  curl --fail --silent http://127.0.0.1:9598/metrics | node "$ROOT/scripts/tc-959-vector-metrics.mjs" received-sample
}
metric_now_ms() { node -p 'Date.now()'; }
report_shipped_event_delta() {
  printf '%s\n%s\n' "$1" "$2" | node "$ROOT/scripts/tc-959-vector-metrics.mjs" event-name-delta |
    while IFS= read -r event; do record "INFO: newly shipped console $event"; done
}
measure_burst() {
  local cpus=$1 before sent_at after received deadline loss
  before=$(fresh_sample)
  sent_at=$(metric_now_ms)
  rm -f "$CONTROL/burst-done"
  printf '%s\n' 5000 >"$CONTROL/burst"
  deadline=$((SECONDS + 30))
  while [[ ! -f "$CONTROL/burst-done" ]] && (( SECONDS < deadline )); do sleep 0.1; done
  [[ -f "$CONTROL/burst-done" ]] || fail "5,000-line producer burst did not complete at cpus=$cpus"
  rm -f "$CONTROL/burst-done"
  after=$(wait_fresh_stable_metric "$sent_at")
  received=$((after - before))
  (( received >= 0 )) || fail "GELF receive counter regressed during cpus=$cpus burst"
  loss=$(( (5000 - received) * 100 / 5000 ))
  (( loss >= 0 )) || loss=0
  record "INFO: 5,000-line burst cpus=$cpus received=$received loss=${loss}%"
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
        crash_vector "$before"
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

measure_burst 0.5
compose_half_cpu_cmd up -d --force-recreate --no-deps vector >/dev/null
wait_vector
wait_next_line 0
measure_burst 0.25
compose_cmd up -d --force-recreate --no-deps vector >/dev/null
wait_vector
wait_next_line 0
restored_nano_cpus=$(docker_cmd inspect -f '{{.HostConfig.NanoCpus}}' "$VECTOR_ID")
[[ "$restored_nano_cpus" == 500000000 ]] || fail "Vector CPU limit after restore is $restored_nano_cpus, expected 500000000"
record "PASS: restored production Vector NanoCpus=500000000 before isolation, node-latency, and memory checks"

# Keep the idle synthetic ingress up so its network namespace is available for sibling probes.
PROBE_CANARY=TC959_FORGED_PROBE_CANARY_UNEXPECTED_FIELD
payload='{"version":"1.1","host":"tc959-isolation-probe","short_message":"{\"timestamp\":\"2026-10-14T10:00:00.000Z\",\"level\":\"WARN\",\"fields\":{\"message\":\"invocation replay insert failed\"}}","timestamp":1760436000,"level":4,"_forged_probe_canary":"'"$PROBE_CANARY"'","_tc.logship":"tinycloud-node"}'
vector_ip=10.255.253.2
app_gateway=$(docker_cmd inspect -f '{{range .NetworkSettings.Networks}}{{.Gateway}}{{end}}' "$NODE_ID")
INGRESS_ID=$(compose_cmd ps -q dstack-ingress)
[[ -n "$INGRESS_ID" ]] || fail "ingress control container missing"

send_from_container() {
  local network=$1 target=$2
  docker_cmd timeout 60 run --rm --label "com.docker.compose.project=$PROJECT" --label "tc959.probe=true" --network "$network" --mount "type=bind,src=$SENDER,dst=/sender.mjs,readonly" node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 node /sender.mjs "$target" 12201 "$payload"
}
send_probe() {
  local sender=$1 network=$2 target=$3
  if [[ "$sender" == host ]]; then
    node "$SENDER" "$target" 12201 "$payload"
  else
    send_from_container "$network" "$target"
  fi
}

# Positive controls precede the leak self-test and every forbidden-source assertion.
source_before=$(fresh_sample)
shipped_before=$(vector_shipped_count)
shipped_names_before=$(vector_shipped_name_counts)
sent_at=$(metric_now_ms)
send_positive_probe "host loopback" host host 127.0.0.1
assert_positive_delivery "$source_before" "$shipped_before" "$sent_at" "host loopback" "$shipped_names_before"

source_before=$(fresh_sample)
shipped_before=$(vector_shipped_count)
shipped_names_before=$(vector_shipped_name_counts)
sent_at=$(metric_now_ms)
send_positive_probe "logship-network control container" container "${PROJECT}_logship" "$vector_ip"
assert_positive_delivery "$source_before" "$shipped_before" "$sent_at" "logship-network control container" "$shipped_names_before"


run_isolation_leak_self_test host host 127.0.0.1

probe_targets=("$vector_ip" "$app_gateway" vector host.docker.internal 127.0.0.1)
for target in "${probe_targets[@]}"; do
  assert_isolated_probe "node->$target" container "container:$NODE_ID" "$target" "$NODE_ID"
  assert_isolated_probe "ingress->$target" container "container:$INGRESS_ID" "$target" "$INGRESS_ID"
  assert_isolated_probe "postgres->$target" container "container:$PG_ID" "$target" "$PG_ID"
done

host_ips=$(ip -o -4 addr show scope global | awk '{split($4,a,"/"); print a[1]}')
[[ -n "$host_ips" ]] || fail "no non-loopback IPv4 interface available for external-interface isolation probes"
while read -r host_ip; do
  [[ -n "$host_ip" ]] || continue
  assert_isolated_probe "host external interface $host_ip" host host "$host_ip"
done <<<"$host_ips"
assert_no_console_marker "$PROBE_CANARY" || fail "forged probe canary appeared anywhere in Vector console output"
record "PASS: raw Vector console output contains no forged-probe canary after the isolation matrix"

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

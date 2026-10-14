#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/tc-959-isolation.sh"

METRICS_SCRAPE_INTERVAL_SECONDS=1
ISOLATION_SETTLE_SECONDS=2
TEST_NOW_MS=3000
METRIC_SAMPLES=()
SHIPPED_NAME_SAMPLES=()
SEND_COUNT=0

read_metric_sample() {
  local sample
  IFS= read -r sample <&3 || { printf 'no captured metric sample\n' >&2; return 1; }
  printf '%s\n' "$sample"
}
metric_now_ms() { printf '%s\n' "$TEST_NOW_MS"; }
vector_shipped_count() {
  local sample
  IFS= read -r sample <&4 || { printf 'no captured shipped count\n' >&2; return 1; }
  printf '%s\n' "$sample"
}
vector_shipped_name_counts() {
  local sample
  IFS= read -r sample <&6 || { printf 'no captured event names\n' >&2; return 1; }
  printf '%s\n' "$sample"
}
report_shipped_event_delta() { :; }
compose_cmd() { printf '%s\n' test-vector; }
LOGS_SHOULD_FAIL=0
docker_cmd() {
  if [[ "$1" == logs ]]; then
    if (( LOGS_SHOULD_FAIL )); then printf '%s\n' 'stub docker logs failure' >&2; return 1; fi
    printf '%s\n' "$RAW_CONSOLE_OUTPUT"
    return 0
  fi
  [[ "$1" == inspect ]] && printf '%s\n' true
}
curl() { return 0; }
read_metric() { printf '%s\n' 3; }
vector_event_count() {
  local sample
  IFS= read -r sample <&5 || return 1
  printf '%s\n' "$sample"
}
SENDER_EXIT=0
SENDER_OUTPUT=""
SEND_COUNT_FILE=""
RECORD_LINES=()
sleep() { :; }
CONTROL=$(mktemp -d)
trap 'rm -rf "$CONTROL"' EXIT

send_probe() {
  SEND_COUNT=$((SEND_COUNT + 1))
  [[ -n "$SEND_COUNT_FILE" ]] && printf x >>"$SEND_COUNT_FILE"
  printf '%s' "$SENDER_OUTPUT"
  return "$SENDER_EXIT"
}
record() { RECORD_LINES+=("$*"); }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "expected '$2', got '$1'"; }
expect_probe_failure() {
  local expected=$1 target=$2 status=$3 output_text=$4 actual
  SENDER_EXIT=$status
  SENDER_OUTPUT=$output_text
  if actual=$(assert_isolated_probe "stub failure" container test-network "$target" 2>&1); then
    fail "probe failure was accepted: $expected"
  fi
  [[ "$actual" == *"$expected"* ]] || fail "probe failure did not explain $expected: $actual"
}

prepare_sender_error_probe() {
  TEST_NOW_MS=50000
  METRIC_SAMPLES=('10 51000' '10 52000')
  SHIPPED_SAMPLES=(5)
  SHIPPED_NAME_SAMPLES=('[]')
  reset_fixtures
}
reset_fixtures() {
  SEND_COUNT=0
  exec 3< <(printf '%s\n' "${METRIC_SAMPLES[@]}")
  exec 4< <(printf '%s\n' "${SHIPPED_SAMPLES[@]}")
  exec 6< <(printf '%s\n' "${SHIPPED_NAME_SAMPLES[@]}")
}
wait_vector
wait_node
assert_eq "$(wait_metric 3)" 3
exec 5< <(printf '%s\n' 1 1)
wait_next_line 0

# Fresh samples must be newer than the send and stable, after the 2s settle.
reset_fixtures
METRIC_SAMPLES=('10 2000' '10 3000')
reset_fixtures
assert_eq "$(wait_fresh_stable_metric 1000)" 10

# Positive controls accept exactly one source and one shipped event.
reset_fixtures
TEST_NOW_MS=6000
ISOLATION_SETTLE_SECONDS=0
METRIC_SAMPLES=('6 5000' '6 6000')
SHIPPED_SAMPLES=(5)
SHIPPED_NAME_SAMPLES=('[]')
reset_fixtures
assert_positive_delivery 5 4 4000 'captured positive control' '[]'

# A negative probe remains isolated when fresh source and sink counts do not move.
reset_fixtures
TEST_NOW_MS=7000
METRIC_SAMPLES=('10 8000' '10 9000' '10 10000' '10 11000')
SHIPPED_SAMPLES=(5 5)
SHIPPED_NAME_SAMPLES=('[]' '[]')
reset_fixtures
assert_isolated_probe 'captured isolated probe' container test-network 127.0.0.1
assert_eq "$SEND_COUNT" 1

# The same negative check must reject an allowed host-loopback delivery.
reset_fixtures
TEST_NOW_MS=12000
METRIC_SAMPLES=('10 13000' '10 14000' '11 15000' '11 16000')
SHIPPED_SAMPLES=(5 6)
SHIPPED_NAME_SAMPLES=('[]' '[{"event":"node_warning","event_code":"invocation_replay_insert_failed","count":1}]')
reset_fixtures
run_isolation_leak_self_test host host 127.0.0.1
assert_eq "$SEND_COUNT" 1
# Not-routable sender errors pass only after fresh +0/+0 samples for a matching target type.
TEST_NOW_MS=20000
METRIC_SAMPLES=('10 21000' '10 22000' '10 23000' '10 24000')
SHIPPED_SAMPLES=(5 5)
SHIPPED_NAME_SAMPLES=('[]' '[]')
SENDER_EXIT=1
SENDER_OUTPUT='GELF_SEND_ERROR code=ENOTFOUND'
reset_fixtures
RECORD_LINES=()
assert_isolated_probe 'name target' container test-network vector
[[ "${RECORD_LINES[*]}" == *"name target not routable (ENOTFOUND)"* ]] || fail "name target ENOTFOUND was not reported as not routable"
[[ "${RECORD_LINES[*]}" == *"source=0 shipped_probe=0"* ]] || fail "name target did not require zero deltas"

# ENOTFOUND is only valid for names; reachability errors are only valid for IP literals.
prepare_sender_error_probe
expect_probe_failure 'isolation check failed' 10.255.253.2 1 'GELF_SEND_ERROR code=ENOTFOUND'

TEST_NOW_MS=30000
METRIC_SAMPLES=('10 31000' '10 32000' '10 33000' '10 34000')
SHIPPED_SAMPLES=(5 5)
SHIPPED_NAME_SAMPLES=('[]' '[]')
SENDER_OUTPUT='GELF_SEND_ERROR code=EHOSTUNREACH'
reset_fixtures
RECORD_LINES=()
assert_isolated_probe 'IP target' container test-network 10.255.253.2
[[ "${RECORD_LINES[*]}" == *"IP target not routable (EHOSTUNREACH)"* ]] || fail "IP EHOSTUNREACH was not reported as not routable"

TEST_NOW_MS=35000
METRIC_SAMPLES=('10 36000' '10 37000' '10 38000' '10 39000')
SHIPPED_SAMPLES=(5 5)
SHIPPED_NAME_SAMPLES=('[]' '[]')
SENDER_OUTPUT='GELF_SEND_ERROR code=ENETUNREACH'
reset_fixtures
RECORD_LINES=()
assert_isolated_probe 'unreachable IP target' container test-network 10.255.253.2
[[ "${RECORD_LINES[*]}" == *"unreachable IP target not routable (ENETUNREACH)"* ]] || fail "IP ENETUNREACH was not reported as not routable"
SENDER_OUTPUT='GELF_SEND_ERROR code=EHOSTUNREACH'
prepare_sender_error_probe
expect_probe_failure 'status=2' vector 1 "$SENDER_OUTPUT"

# Transient DNS failures retry exactly three times, then fail closed.
SENDER_OUTPUT='GELF_SEND_ERROR code=EAI_AGAIN'
SEND_COUNT=0
RECORD_LINES=()
SEND_COUNT_FILE="$CONTROL/sender-attempts"
: >"$SEND_COUNT_FILE"
prepare_sender_error_probe
if check_isolated_probe 'EAI_AGAIN target' container test-network vector; then
  fail "EAI_AGAIN passed after retries"
else
  assert_eq "$?" 2
fi
assert_eq "$SEND_COUNT" 3
assert_eq "$(wc -c <"$SEND_COUNT_FILE")" 3
[[ "${RECORD_LINES[*]}" == *"EAI_AGAIN remained after 3 attempts"* ]] || fail "EAI_AGAIN retry exhaustion was not reported"
SEND_COUNT_FILE=""

prepare_sender_error_probe
expect_probe_failure 'status=2' vector 1 'GELF_SEND_ERROR code=ETIMEDOUT'
prepare_sender_error_probe
expect_probe_failure 'status=2' vector 124 'GELF_SEND_ERROR code=ETIMEDOUT'
prepare_sender_error_probe
expect_probe_failure 'status=2' vector 125 'docker run failed'
prepare_sender_error_probe
expect_probe_failure 'status=2' vector 126 'docker run failed'
prepare_sender_error_probe
expect_probe_failure 'status=2' vector 1 'usage: send-gelf HOST PORT JSON'

# A not-routable error contradicts a received probe and therefore cannot pass.
TEST_NOW_MS=40000
METRIC_SAMPLES=('10 41000' '10 42000' '11 43000' '11 44000')
SHIPPED_SAMPLES=(5 6)
SHIPPED_NAME_SAMPLES=('[]' '[{"event":"node_warning","event_code":"invocation_replay_insert_failed","count":1}]')
SENDER_OUTPUT='GELF_SEND_ERROR code=ENOTFOUND'
reset_fixtures
expect_probe_failure 'isolation check failed' vector 1 "$SENDER_OUTPUT"

# Positive controls and the isolation leak self-test never accept sender errors.
SENDER_OUTPUT='GELF_SEND_ERROR code=ENOTFOUND'
if output=$(send_positive_probe 'host loopback' host host 127.0.0.1 2>&1); then
  fail "positive-control sender error passed"
fi
[[ "$output" == *"positive control sender failed"* ]] || fail "positive-control sender error was not fatal: $output"
SENDER_OUTPUT='GELF_SEND_ERROR code=EHOSTUNREACH'
prepare_sender_error_probe
if output=$(run_isolation_leak_self_test host host 127.0.0.1 2>&1); then
  fail "leak self-test accepted a sender error"
fi
[[ "$output" == *"could not deliver its allowed packet"* ]] || fail "leak self-test sender error was not fatal: $output"
SENDER_EXIT=0
SENDER_OUTPUT=""
printf '%s\n' 'PASS: sender failures are classified by exact code, target type, and context'
printf '%s\n' 'PASS: isolation freshness, positive controls, and leak self-test'

# The raw console scan catches a marker hidden in an unexpected field even when the probe filter returns zero.
VECTOR_ID=test-vector
RAW_CONSOLE_OUTPUT='{"event":"node_warning","event_code":"other_warning","unexpected_field":"TC959_FORGED_PROBE_CANARY_UNEXPECTED_FIELD"}'
filtered_probe_count=$(printf '%s\n' "$RAW_CONSOLE_OUTPUT" | node "$ROOT/scripts/tc-959-vector-metrics.mjs" probe-count)
assert_eq "$filtered_probe_count" 0
if assert_no_console_marker TC959_FORGED_PROBE_CANARY_UNEXPECTED_FIELD; then
  fail "raw console scan missed a marker in an unexpected field"
else
  assert_eq "$?" 1
fi
RAW_CONSOLE_OUTPUT='{"event":"node_warning","event_code":"other_warning"}'
assert_no_console_marker TC959_FORGED_PROBE_CANARY_UNEXPECTED_FIELD || fail "raw console scan falsely matched absent marker"
unset -f vector_shipped_count vector_shipped_name_counts vector_event_count assert_no_console_marker
source "$ROOT/scripts/tc-959-isolation.sh"
LOGS_SHOULD_FAIL=1
for reader in vector_shipped_count vector_shipped_name_counts vector_event_count assert_no_console_marker; do
  if output=$("$reader" TC959_FORGED_PROBE_CANARY_UNEXPECTED_FIELD 2>&1); then
    fail "$reader passed after docker logs failed"
  fi
  [[ "$output" == *"docker logs failed"* ]] || fail "$reader did not fail closed: $output"
done
LOGS_SHOULD_FAIL=0

# Host-port preflight reports the owning Compose service before startup.
PORT_HOLDER_MODE=container
ss() {
  if [[ "$3" == "sport = :18000" && "$PORT_HOLDER_MODE" == container ]]; then
    printf '%s\n' 'LISTEN 0 4096 127.0.0.1:18000 0.0.0.0:* users:(("docker-proxy",pid=123,fd=4))'
  elif [[ "$3" == "sport = :12201" && "$PORT_HOLDER_MODE" == udp ]]; then
    printf '%s\n' 'UNCONN 0 0 0.0.0.0:12201 0.0.0.0:* users:(("docker-proxy",pid=456,fd=7))'
  fi
}
docker_cmd() {
  if [[ "$1" == ps && "$3" == publish=18000 ]]; then
    printf '%s\n' 'tc959-existing-compose'
    return 0
  fi
  if [[ "$1" == ps && "$3" == publish=12201/udp ]]; then
    printf '%s\n' 'tc959-udp-owner'
    return 0
  fi
  return 1
}
port_error=$(check_host_ports_free 2>&1) && fail "busy host port passed preflight"
[[ "$port_error" == *"127.0.0.1:18000"* && "$port_error" == *"tc959-existing-compose"* ]] || fail "port preflight omitted listener owner: $port_error"
PORT_HOLDER_MODE=udp
port_error=$(check_host_ports_free 2>&1) && fail "busy host UDP port passed preflight"
[[ "$port_error" == *"127.0.0.1:12201/udp"* && "$port_error" == *"tc959-udp-owner"* ]] || fail "UDP port preflight omitted listener owner: $port_error"

# Container-scoped crash proofs use an exact container ID and never host PIDs.
VECTOR_ID=0123456789abcdef-vector
SNAPSHOT_ID=$VECTOR_ID
SNAPSHOT_RESTARTS=4
SNAPSHOT_STARTED=2026-10-14T10:00:00.000000000Z
CURRENT_ID=$VECTOR_ID
CURRENT_RESTARTS=5
CURRENT_STARTED=2026-10-14T10:01:00.000000000Z
CURRENT_RUNNING=true
VECTOR_PIDS=42
VECTOR_COMM=vector
SIGNALS=0
RECOVERED_LINE_COUNT=""
docker_cmd() {
  if [[ "$1" == inspect ]]; then
    case "$3" in
      '{{.Id}}|{{.RestartCount}}|{{.State.StartedAt}}')
        printf '%s|%s|%s\n' "$SNAPSHOT_ID" "$SNAPSHOT_RESTARTS" "$SNAPSHOT_STARTED"
        ;;
      '{{.Id}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.Running}}')
        printf '%s|%s|%s|%s\n' "$CURRENT_ID" "$CURRENT_RESTARTS" "$CURRENT_STARTED" "$CURRENT_RUNNING"
        ;;
      *) return 1 ;;
    esac
    return 0
  fi
  if [[ "$1" == exec && "$2" == --user && "$3" == 10001:10001 && "$4" == "$VECTOR_ID" ]]; then
    case "$5" in
      busybox)
        case "$6" in
          pidof)
            [[ "$7" == vector && -n "$VECTOR_PIDS" ]] || return 1
            printf '%s\n' "$VECTOR_PIDS"
            ;;
          kill)
            [[ "$7" == -KILL && "$8" == "${VECTOR_PIDS%% *}" ]] || return 1
            SIGNALS=$((SIGNALS + 1))
            printf '%s\n' SIGNAL_SENT >&2
            ;;
          *) return 1 ;;
        esac
        ;;
      cat)
        [[ "$6" == "/proc/${VECTOR_PIDS%% *}/comm" ]] || return 1
        printf '%s\n' "$VECTOR_COMM"
        ;;
      *) return 1 ;;
    esac
    return 0
  fi
  return 1
}
wait_vector() { :; }
wait_next_line() { RECOVERED_LINE_COUNT=$1; }
sleep() { SECONDS=$((SECONDS + 20)); }
record() { :; }
expect_crash_failure() {
  local expected=$1 signal_expected=${2:-no} output
  SECONDS=0
  output=$(crash_vector 17 2>&1) && fail "crash helper accepted $expected"
  [[ "$output" == *"$expected"* ]] || fail "crash helper failure did not explain $expected: $output"
  if [[ "$signal_expected" == no ]]; then
    [[ "$output" != *SIGNAL_SENT* ]] || fail "crash helper signalled before rejecting $expected"
  else
    [[ "$output" == *SIGNAL_SENT* ]] || fail "crash helper did not signal before checking $expected"
  fi
}
crash_vector 17
assert_eq "$SIGNALS" 1
assert_eq "$RECOVERED_LINE_COUNT" 17

VECTOR_PIDS=""
expect_crash_failure "exactly one Vector PID"
VECTOR_PIDS="42 43"
expect_crash_failure "exactly one Vector PID"
VECTOR_PIDS=1
expect_crash_failure "PID must be greater than 1"
VECTOR_PIDS=42
VECTOR_COMM=nginx
expect_crash_failure "comm is not vector"
VECTOR_COMM=vector
SNAPSHOT_ID=another-container-id
expect_crash_failure "container ID changed before crash"
SNAPSHOT_ID=$VECTOR_ID
CURRENT_ID=another-container-id
expect_crash_failure "container ID changed" after-signal
CURRENT_ID=$VECTOR_ID
CURRENT_RESTARTS=4
expect_crash_failure "RestartCount did not increase by exactly one" after-signal
CURRENT_RESTARTS=6
expect_crash_failure "RestartCount advanced past expected +1" after-signal
CURRENT_RESTARTS=5
CURRENT_STARTED=$SNAPSHOT_STARTED
expect_crash_failure "StartedAt did not advance" after-signal
SNAPSHOT_STARTED=2026-10-14T10:00:00.11Z
CURRENT_STARTED=2026-10-14T10:00:00.1Z
expect_crash_failure "StartedAt did not advance" after-signal

assert_crash_recovered() {
  SECONDS=0
  SIGNALS=0
  RECOVERED_LINE_COUNT=""
  crash_vector 17
  assert_eq "$SIGNALS" 1
  assert_eq "$RECOVERED_LINE_COUNT" 17
}
SNAPSHOT_STARTED=2026-10-14T10:00:00.1Z
CURRENT_STARTED=2026-10-14T10:00:00.11Z
assert_crash_recovered
SNAPSHOT_STARTED=2026-10-14T10:00:00Z
CURRENT_STARTED=2026-10-14T10:00:00Z
expect_crash_failure "StartedAt did not advance" after-signal
SNAPSHOT_STARTED=2026-10-14T10:00:00Z
CURRENT_STARTED=2026-10-14T10:00:00.000000001Z
assert_crash_recovered
SNAPSHOT_STARTED=2026-10-14T10:00:00.123456788Z
CURRENT_STARTED=2026-10-14T10:00:00.123456789Z
assert_crash_recovered
SNAPSHOT_STARTED=2026-10-14T10:00:00Z
CURRENT_STARTED=0001-01-01T00:00:00Z
expect_crash_failure "StartedAt did not advance" after-signal
SNAPSHOT_STARTED=2026-10-14T10:00:00.999999999+01:30
CURRENT_STARTED=2026-10-14T08:30:01Z
assert_crash_recovered
printf '%s\n' 'PASS: exact-container crash identity and restart proofs'

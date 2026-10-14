#!/usr/bin/env bash
set -Eeuo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
source "$ROOT/scripts/tc-959-isolation.sh"

METRICS_SCRAPE_INTERVAL_SECONDS=1
ISOLATION_SETTLE_SECONDS=2
TEST_NOW_MS=3000
METRIC_SAMPLES=()
SHIPPED_SAMPLES=()
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
compose_cmd() { printf '%s\n' test-vector; }
docker_cmd() { [[ "$1" == inspect ]] && printf '%s\n' true; }
curl() { return 0; }
read_metric() { printf '%s\n' 3; }
vector_event_count() {
  local sample
  IFS= read -r sample <&5 || return 1
  printf '%s\n' "$sample"
}
sleep() { :; }
CONTROL=$(mktemp -d)
trap 'rm -rf "$CONTROL"' EXIT

send_probe() { SEND_COUNT=$((SEND_COUNT + 1)); }
record() { :; }
fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
assert_eq() { [[ "$1" == "$2" ]] || fail "expected '$2', got '$1'"; }
reset_fixtures() {
  SEND_COUNT=0
  exec 3< <(printf '%s\n' "${METRIC_SAMPLES[@]}")
  exec 4< <(printf '%s\n' "${SHIPPED_SAMPLES[@]}")
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
reset_fixtures
assert_positive_delivery 5 4 4000 'captured positive control'

# A negative probe remains isolated when fresh source and sink counts do not move.
reset_fixtures
TEST_NOW_MS=7000
METRIC_SAMPLES=('10 8000' '10 9000' '10 10000' '10 11000')
SHIPPED_SAMPLES=(5 5)
reset_fixtures
assert_isolated_probe 'captured isolated probe' container test-network 127.0.0.1
assert_eq "$SEND_COUNT" 1

# The same negative check must reject an allowed host-loopback delivery.
reset_fixtures
TEST_NOW_MS=12000
METRIC_SAMPLES=('10 13000' '10 14000' '11 15000' '11 16000')
SHIPPED_SAMPLES=(5 6)
reset_fixtures
run_isolation_leak_self_test host host 127.0.0.1
assert_eq "$SEND_COUNT" 1
printf '%s\n' 'PASS: isolation freshness, positive controls, and leak self-test'

# Host-port preflight reports the owning Compose service before startup.
PORT_HOLDER_MODE=container
ss() {
  if [[ "$3" == "sport = :18000" && "$PORT_HOLDER_MODE" == container ]]; then
    printf '%s\n' 'LISTEN 0 4096 127.0.0.1:18000 0.0.0.0:* users:(("docker-proxy",pid=123,fd=4))'
  fi
}
docker_cmd() {
  if [[ "$1" == ps && "$3" == publish=18000 ]]; then
    printf '%s\n' 'tc959-existing-compose'
    return 0
  fi
  return 1
}
port_error=$(check_host_ports_free 2>&1) && fail "busy host port passed preflight"
[[ "$port_error" == *"127.0.0.1:18000"* && "$port_error" == *"tc959-existing-compose"* ]] || fail "port preflight omitted listener owner: $port_error"

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
printf '%s\n' 'PASS: exact-container crash identity and restart proofs'

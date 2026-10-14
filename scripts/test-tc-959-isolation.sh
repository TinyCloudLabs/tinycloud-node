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

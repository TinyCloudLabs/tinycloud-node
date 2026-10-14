check_host_ports_free() {
  local port listeners containers owner
  for port in 18000 9598; do
    listeners=$(ss -H -ltnp "sport = :$port") || fail "could not inspect host port 127.0.0.1:$port"
    [[ -n "$listeners" ]] || continue
    containers=$(docker_cmd ps --filter "publish=$port" --format '{{.Names}}' 2>/dev/null || true)
    owner=$listeners
    [[ -z "$containers" ]] || owner="$containers; $listeners"
    fail "host port 127.0.0.1:$port is already in use: $owner"
  done

  listeners=$(ss -H -lunp 'sport = :12201') || fail "could not inspect host UDP port 127.0.0.1:12201"
  if [[ -n "$listeners" ]]; then
    containers=$(docker_cmd ps --filter "publish=12201/udp" --format '{{.Names}}' 2>/dev/null || true)
    owner=$listeners
    [[ -z "$containers" ]] || owner="$containers; $listeners"
    fail "host port 127.0.0.1:12201/udp is already in use: $owner"
  fi
}

started_at_is_newer() {
  node -e '
const parseNanoseconds = (value) => {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  if (!match) throw new Error("invalid RFC3339Nano timestamp");
  const [, year, month, day, hour, minute, second, fraction = "", zone] = match;
  if (Number(hour) > 23 || Number(minute) > 59 || Number(second) > 59) throw new Error("invalid timestamp time");
  const offsetHour = zone === "Z" ? 0 : Number(zone.slice(1, 3));
  const offsetMinute = zone === "Z" ? 0 : Number(zone.slice(4, 6));
  if (offsetHour > 23 || offsetMinute > 59) throw new Error("invalid timestamp offset");
  const instant = Date.parse(`${year}-${month}-${day}T${hour}:${minute}:${second}${zone}`);
  if (!Number.isSafeInteger(instant)) throw new Error("timestamp is out of range");
  const offsetSign = zone === "Z" ? 0 : (zone[0] === "+" ? 1 : -1);
  const wallTime = new Date(instant + offsetSign * (offsetHour * 60 + offsetMinute) * 60000).toISOString().slice(0, 19);
  if (wallTime !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) throw new Error("invalid timestamp date");
  const nanoseconds = BigInt(instant / 1000) * 1000000000n + BigInt(fraction.padEnd(9, "0") || "0");
  if (nanoseconds === -62135596800000000000n) throw new Error("Docker StartedAt is the zero time");
  return nanoseconds;
};
try {
  const [current, previous] = process.argv.slice(1);
  process.exit(parseNanoseconds(current) > parseNanoseconds(previous) ? 0 : 1);
} catch {
  process.exit(1);
}
' "$1" "$2"
}


crash_vector() {
  local previous_line_count=$1 snapshot snapshot_id restart_before started_before
  local pids vector_pid comm target_restart current current_id current_restart current_started current_running
  local deadline
  local -a vector_pids=()

  snapshot=$(docker_cmd inspect -f '{{.Id}}|{{.RestartCount}}|{{.State.StartedAt}}' "$VECTOR_ID") ||
    fail "could not snapshot Vector container before crash"
  IFS='|' read -r snapshot_id restart_before started_before <<<"$snapshot"
  [[ "$snapshot_id" == "$VECTOR_ID" ]] || fail "Vector container ID changed before crash"
  [[ "$restart_before" =~ ^[0-9]+$ && -n "$started_before" ]] || fail "Vector crash snapshot is invalid"

  pids=$(docker_cmd exec --user 10001:10001 "$VECTOR_ID" busybox pidof vector 2>/dev/null || true)
  read -r -a vector_pids <<<"$pids"
  (( ${#vector_pids[@]} == 1 )) || fail "expected exactly one Vector PID in container, found ${#vector_pids[@]}"
  vector_pid=${vector_pids[0]}
  [[ "$vector_pid" =~ ^[0-9]+$ ]] || fail "Vector PID is not numeric: $vector_pid"
  (( vector_pid > 1 )) || fail "Vector PID must be greater than 1"
  comm=$(docker_cmd exec --user 10001:10001 "$VECTOR_ID" cat "/proc/$vector_pid/comm" 2>/dev/null) ||
    fail "could not read Vector process comm"
  [[ "$comm" == vector ]] || fail "container process PID $vector_pid comm is not vector"

  target_restart=$((restart_before + 1))
  docker_cmd exec --user 10001:10001 "$VECTOR_ID" busybox kill -KILL "$vector_pid" >/dev/null ||
    fail "container-scoped SIGKILL failed; crash signal was not retried"

  deadline=$((SECONDS + 20))
  current=""
  while (( SECONDS < deadline )); do
    current=$(docker_cmd inspect -f '{{.Id}}|{{.RestartCount}}|{{.State.StartedAt}}|{{.State.Running}}' "$VECTOR_ID" 2>/dev/null || true)
    IFS='|' read -r current_id current_restart current_started current_running <<<"$current"
    [[ -n "$current_id" ]] || { sleep 0.2; continue; }
    [[ "$current_id" == "$snapshot_id" ]] || fail "Vector container ID changed during crash recovery"
    [[ "$current_restart" =~ ^[0-9]+$ ]] || { sleep 0.2; continue; }
    if (( current_restart > target_restart )); then
      fail "Vector RestartCount advanced past expected +1: before=$restart_before after=$current_restart"
    fi
    if (( current_restart == target_restart )) &&
       [[ "$current_running" == true ]] &&
       started_at_is_newer "$current_started" "$started_before"; then
      break
    fi
    sleep 0.2
  done

  [[ "$current_id" == "$snapshot_id" ]] || fail "Vector container ID changed during crash recovery"
  [[ "$current_restart" =~ ^[0-9]+$ ]] && (( current_restart == target_restart )) ||
    fail "Vector RestartCount did not increase by exactly one: before=$restart_before after=${current_restart:-unavailable}"
  started_at_is_newer "$current_started" "$started_before" || fail "Vector StartedAt did not advance after crash"
  [[ "$current_running" == true ]] || fail "Vector was not running after crash recovery"
  wait_vector
  [[ "$VECTOR_ID" == "$snapshot_id" ]] || fail "Vector container ID changed while waiting for output"
  wait_next_line "$previous_line_count"
}

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

wait_metric() {
  local deadline=$((SECONDS + 20)) value
  while (( SECONDS < deadline )); do
    value=$(read_metric)
    if [[ "$value" =~ ^[0-9]+$ ]] && (( value >= ${1:-1} )); then printf '%s\n' "$value"; return 0; fi
    sleep 0.25
  done
  fail "Vector GELF receive metric did not reach ${1:-1}"
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

wait_fresh_stable_metric() {
  local after_ms=$1
  local deadline=$((SECONDS + 20))
  local settle_until
  settle_until=$((after_ms + ISOLATION_SETTLE_SECONDS * 1000))
  local sample value timestamp previous_timestamp=-1 previous_value=-1 now
  while (( SECONDS < deadline )); do
    sample=$(read_metric_sample)
    if [[ "$sample" =~ ^([0-9]+)[[:space:]]([0-9]+)$ ]]; then
      value=${BASH_REMATCH[1]}
      timestamp=${BASH_REMATCH[2]}
      if (( timestamp > after_ms && timestamp > previous_timestamp )); then
        now=$(metric_now_ms)
        if (( value == previous_value && now >= settle_until )); then
          printf '%s\n' "$value"
          return 0
        fi
        previous_value=$value
        previous_timestamp=$timestamp
      fi
    fi
    sleep 0.2
  done
  fail "Vector source metric did not produce two fresh, stable samples after timestamp $after_ms"
}

fresh_sample() {
  local started
  started=$(metric_now_ms)
  wait_fresh_stable_metric "$started"
}

assert_positive_delivery() {
  local source_before=$1 shipped_before=$2 sent_at=$3 description=$4 shipped_names_before=$5
  local source_after source_delta deadline=$((SECONDS + 20)) shipped_after shipped_delta shipped_names_after
  source_after=$(wait_fresh_stable_metric "$sent_at")
  source_delta=$((source_after - source_before))
  (( source_delta == 1 )) || fail "$description positive control source delta was $source_delta, expected +1"
  while (( SECONDS < deadline )); do
    shipped_after=$(vector_shipped_count)
    shipped_delta=$((shipped_after - shipped_before))
    if (( shipped_delta != 0 )); then
      shipped_names_after=$(vector_shipped_name_counts)
      report_shipped_event_delta "$shipped_names_before" "$shipped_names_after"
    fi
    if (( shipped_delta == 1 )); then
      record "PASS: $description positive control; fresh source +1 and shipped probe +1"
      return 0
    fi
    (( shipped_delta <= 1 )) || fail "$description produced duplicate probe events: +$shipped_delta"
    sleep 0.2
  done
  fail "$description positive control shipped probe delta was $shipped_delta, expected +1"
}

check_isolated_probe() {
  local description=$1 sender=$2 network=$3 target=$4
  local source_before shipped_before shipped_names_before sent_at source_after shipped_after shipped_names_after source_delta shipped_delta send_status=0
  source_before=$(fresh_sample)
  shipped_before=$(vector_shipped_count)
  shipped_names_before=$(vector_shipped_name_counts)
  sent_at=$(metric_now_ms)
  if send_probe "$sender" "$network" "$target"; then
    record "INFO: $description sender completed"
  else
    send_status=$?
    record "INFO: $description sender reported transport error exit=$send_status"
  fi
  source_after=$(wait_fresh_stable_metric "$sent_at")
  shipped_after=$(vector_shipped_count)
  shipped_names_after=$(vector_shipped_name_counts)
  source_delta=$((source_after - source_before))
  shipped_delta=$((shipped_after - shipped_before))
  if (( shipped_delta != 0 )); then report_shipped_event_delta "$shipped_names_before" "$shipped_names_after"; fi
  record "INFO: $description fresh deltas source=$source_delta shipped_probe=$shipped_delta"
  (( send_status == 0 )) || return 2
  if (( source_delta == 0 && shipped_delta == 0 )); then return 0; fi
  return 1
}


vector_shipped_count() {
  [[ "$(docker_cmd inspect -f '{{.State.Running}}' "$VECTOR_ID")" == true ]] || fail "refusing to read events from a stopped Vector container"
  local logs
  logs=$(docker_cmd logs "$VECTOR_ID" 2>&1) || fail "docker logs failed"
  printf '%s\n' "$logs" | node "$ROOT/scripts/tc-959-vector-metrics.mjs" probe-count
}

vector_shipped_name_counts() {
  [[ "$(docker_cmd inspect -f '{{.State.Running}}' "$VECTOR_ID")" == true ]] || fail "refusing to read events from a stopped Vector container"
  local logs
  logs=$(docker_cmd logs "$VECTOR_ID" 2>&1) || fail "docker logs failed"
  printf '%s\n' "$logs" | node "$ROOT/scripts/tc-959-vector-metrics.mjs" event-name-counts
}

vector_event_count() {
  [[ "$(docker_cmd inspect -f '{{.State.Running}}' "$VECTOR_ID")" == true ]] || fail "refusing to read events from a stopped Vector container"
  local logs
  logs=$(docker_cmd logs "$VECTOR_ID" 2>&1) || fail "docker logs failed"
  printf '%s\n' "$logs" | node "$ROOT/scripts/tc-959-vector-metrics.mjs" event-count ingress_request_slow
}

assert_no_console_marker() {
  local marker=$1 logs match_count
  logs=$(docker_cmd logs "$VECTOR_ID" 2>&1) || fail "docker logs failed"
  match_count=$(printf '%s\n' "$logs" | grep -cF -- "$marker" || true)
  [[ "$match_count" == 0 ]]
}
assert_isolated_probe() {
  local description=$1 sender=$2 network=$3 target=$4 status
  if check_isolated_probe "$description" "$sender" "$network" "$target"; then
    record "PASS: $description isolation; fresh source +0 and shipped +0"
    return 0
  else
    status=$?
    fail "$description isolation check failed (status=$status)"
  fi
}

run_isolation_leak_self_test() {
  local sender=$1 network=$2 target=$3 status
  if check_isolated_probe "intentional host-loopback leak self-test" "$sender" "$network" "$target"; then
    fail "isolation leak self-test passed unexpectedly"
  else
    status=$?
    (( status == 1 )) || fail "isolation leak self-test could not deliver its allowed packet (status=$status)"
    record "PASS: negative isolation check rejected a deliberately allowed host-loopback packet"
  fi
}

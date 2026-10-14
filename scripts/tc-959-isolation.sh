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
}

crash_vector() {
  local previous_line_count=$1 restart_before container_pid target_restart
  local restart_count="" running="" deadline
  restart_before=$(docker_cmd inspect -f '{{.RestartCount}}' "$VECTOR_ID")
  container_pid=$(docker_cmd inspect -f '{{.State.Pid}}' "$VECTOR_ID")
  [[ "$restart_before" =~ ^[0-9]+$ ]] || fail "Vector RestartCount is invalid before SIGKILL: $restart_before"
  [[ "$container_pid" =~ ^[1-9][0-9]*$ ]] || fail "Vector host PID is invalid before SIGKILL: $container_pid"
  target_restart=$((restart_before + 1))
  kill -KILL "$container_pid" || fail "could not SIGKILL Vector host PID $container_pid"

  deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    restart_count=$(docker_cmd inspect -f '{{.RestartCount}}' "$VECTOR_ID" 2>/dev/null || true)
    [[ "$restart_count" =~ ^[0-9]+$ ]] || { sleep 0.2; continue; }
    if (( restart_count > target_restart )); then
      fail "Vector RestartCount advanced past expected +1 after SIGKILL: before=$restart_before after=$restart_count"
    fi
    if (( restart_count == target_restart )); then
      running=$(docker_cmd inspect -f '{{.State.Running}}' "$VECTOR_ID" 2>/dev/null || true)
      [[ "$running" == true ]] && break
    fi
    sleep 0.2
  done
  [[ "$restart_count" == "$target_restart" ]] ||
    fail "Vector RestartCount did not increase by exactly one after SIGKILL: before=$restart_before after=${restart_count:-unavailable}"
  [[ "$running" == true ]] || fail "Vector RestartCount increased but Vector is not running after SIGKILL"
  wait_vector
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
  local source_before=$1 shipped_before=$2 sent_at=$3 description=$4
  local source_after source_delta deadline=$((SECONDS + 20)) shipped_after shipped_delta
  source_after=$(wait_fresh_stable_metric "$sent_at")
  source_delta=$((source_after - source_before))
  (( source_delta == 1 )) || fail "$description positive control source delta was $source_delta, expected +1"
  while (( SECONDS < deadline )); do
    shipped_after=$(vector_shipped_count)
    shipped_delta=$((shipped_after - shipped_before))
    if (( shipped_delta == 1 )); then
      record "PASS: $description positive control; fresh source +1 and shipped +1"
      return 0
    fi
    (( shipped_delta <= 1 )) || fail "$description produced duplicate shipped events: +$shipped_delta"
    sleep 0.2
  done
  fail "$description positive control shipped delta was $shipped_delta, expected +1"
}

check_isolated_probe() {
  local description=$1 sender=$2 network=$3 target=$4
  local source_before shipped_before sent_at source_after shipped_after source_delta shipped_delta send_status=0
  source_before=$(fresh_sample)
  shipped_before=$(vector_shipped_count)
  sent_at=$(metric_now_ms)
  if send_probe "$sender" "$network" "$target"; then
    record "INFO: $description sender completed"
  else
    send_status=$?
    record "INFO: $description sender reported transport error exit=$send_status"
  fi
  source_after=$(wait_fresh_stable_metric "$sent_at")
  shipped_after=$(vector_shipped_count)
  source_delta=$((source_after - source_before))
  shipped_delta=$((shipped_after - shipped_before))
  record "INFO: $description fresh deltas source=$source_delta shipped=$shipped_delta"
  (( send_status == 0 )) || return 2
  if (( source_delta == 0 && shipped_delta == 0 )); then return 0; fi
  return 1
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

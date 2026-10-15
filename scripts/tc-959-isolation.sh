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

run_probe_sender() {
  local sender=$1 network=$2 target=$3
  if send_probe "$sender" "$network" "$target" >"$CONTROL/probe-sender.out" 2>&1; then
    LAST_PROBE_SEND_STATUS=0
  else
    LAST_PROBE_SEND_STATUS=$?
  fi
  LAST_PROBE_SEND_OUTPUT=$(<"$CONTROL/probe-sender.out")
  (( LAST_PROBE_SEND_STATUS == 0 ))
}

send_positive_probe() {
  local description=$1 sender=$2 network=$3 target=$4 error_code
  if run_probe_sender "$sender" "$network" "$target"; then
    return 0
  fi
  if error_code=$(sender_error_code "$LAST_PROBE_SEND_STATUS" "$LAST_PROBE_SEND_OUTPUT"); then
    record "INFO: $description sender error code=$error_code exit=$LAST_PROBE_SEND_STATUS"
  fi
  fail "$description positive control sender failed (exit=$LAST_PROBE_SEND_STATUS)"
}

sender_error_code() {
  local exit_status=$1 output=$2
  (( exit_status == 1 )) || return 1
  [[ "$output" =~ ^GELF_SEND_ERROR\ code=(ENOTFOUND|EAI_AGAIN|ENETUNREACH|EHOSTUNREACH|ECONNREFUSED|other)$ ]] || return 1
  printf '%s\n' "${BASH_REMATCH[1]}"
}

probe_routing_error_matches_target() {
  local code=$1 target=$2
  case "$code" in
    ENOTFOUND) [[ "$target" == vector || "$target" == host.docker.internal ]] ;;
    ENETUNREACH|EHOSTUNREACH) [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] ;;
    *) return 1 ;;
  esac
}
probe_target_is_name() {
  [[ "$1" == vector || "$1" == host.docker.internal ]]
}

name_network_names_from_json() {
  node -e '
    const fs = require("node:fs");
    let networks;
    try { networks = JSON.parse(fs.readFileSync(0, "utf8")); } catch { process.exit(2); }
    if (!networks || typeof networks !== "object" || Array.isArray(networks)) process.exit(2);
    const names = Object.keys(networks);
    if (names.length === 0) process.exit(3);
    if (names.some((name) => !/^[A-Za-z0-9_.-]+$/.test(name))) process.exit(2);
    process.stdout.write(`${names.sort().join(",")}\n`);
  '
}

name_network_container_ids_from_json() {
  node -e '
    const fs = require("node:fs");
    let containers;
    try { containers = JSON.parse(fs.readFileSync(0, "utf8")); } catch { process.exit(2); }
    if (containers === null) containers = {};
    if (typeof containers !== "object" || Array.isArray(containers)) process.exit(2);
    const ids = Object.keys(containers);
    if (ids.some((id) => !/^[A-Za-z0-9_.-]+$/.test(id))) process.exit(2);
    if (ids.length) process.stdout.write(`${ids.join("\n")}\n`);
  '
}

name_peer_matches_target() {
  local network=$1 target=$2 peer_json=$3
  printf '%s\n' "$peer_json" | node -e '
    const fs = require("node:fs");
    const [network, target] = process.argv.slice(1);
    let peer;
    try { peer = JSON.parse(fs.readFileSync(0, "utf8")); } catch { process.exit(2); }
    if (!peer || typeof peer !== "object" || Array.isArray(peer) ||
        typeof peer.name !== "string" || typeof peer.hostname !== "string" ||
        (peer.service !== null && typeof peer.service !== "string") ||
        !peer.networks || typeof peer.networks !== "object" || !Object.hasOwn(peer.networks, network)) {
      process.exit(2);
    }
    const endpoint = peer.networks[network];
    if (!endpoint || typeof endpoint !== "object" || Array.isArray(endpoint)) process.exit(2);
    const aliases = endpoint.Aliases ?? [];
    const dnsNames = endpoint.DNSNames ?? [];
    if (!Array.isArray(aliases) || !Array.isArray(dnsNames) ||
        aliases.some((name) => typeof name !== "string") ||
        dnsNames.some((name) => typeof name !== "string")) process.exit(2);
    const names = [peer.name.replace(/^\/+/, ""), peer.hostname, peer.service, ...aliases, ...dnsNames];
    process.exit(names.includes(target) ? 0 : 1);
  ' "$network" "$target"
}

hosts_file_has_name() {
  local hosts_file=$1 target=$2
  awk -v target="$target" '
    /^[[:space:]]*#/ { next }
    {
      for (i = 2; i <= NF; i++) {
        if ($i ~ /^#/) break;
        if ($i == target) found = 1;
      }
    }
    END { exit !found }
  ' <<<"$hosts_file"
}

name_resolver_positive_control() {
  local target_container=$1 result project=${PROJECT:-tc959-isolation-test}
  result=$(docker_cmd timeout 60 run --rm \
    --label "com.docker.compose.project=$project" \
    --label "tc959.probe=true" \
    --network "container:$target_container" \
    node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 \
    node -e 'require("node:dns").lookup("tinycloud", (error) => {
      if (error) {
        process.stderr.write(`GELF_RESOLVER_ERROR code=${error.code === "EAI_AGAIN" ? "EAI_AGAIN" : "other"}\n`);
        process.exitCode = 1;
      } else process.stdout.write("GELF_RESOLVER_OK\n");
    })' 2>&1) || return 1
  [[ "$result" == GELF_RESOLVER_OK ]]
}

prove_name_target_structure() {
  local description=$1 target_container=$2 target=$3 error_code=$4
  local hosts_file sender_networks_json vector_networks_json sender_networks vector_networks
  local sender_parse_status vector_parse_status shared_networks=0 alias_matches=0
  local network containers_json peer_ids peer_id peer_metadata peer_match_status
  local sender_member_found peer_format
  local -a sender_network_names=() vector_network_names=()
  if [[ -z "$target_container" ]]; then
    record "INFO: $description name proof failed; sender_networks=unavailable vector_networks=unavailable shared_networks=unknown alias_matches=unknown hosts_entry=unknown resolver_control=not-run error_code=$error_code reason=missing_container_id"
    return 2
  fi
  if ! hosts_file=$(docker_cmd exec "$target_container" cat /etc/hosts 2>/dev/null); then
    record "INFO: $description name proof failed; sender_networks=unavailable vector_networks=unavailable shared_networks=unknown alias_matches=unknown hosts_entry=unreadable resolver_control=not-run error_code=$error_code"
    return 2
  fi
  if hosts_file_has_name "$hosts_file" "$target"; then
    record "INFO: $description name target is in hosts file; sender_networks=not-checked vector_networks=not-checked shared_networks=not-applicable alias_matches=not-applicable hosts_entry=1 resolver_control=not-needed error_code=$error_code"
    return 2
  fi
  if ! sender_networks_json=$(docker_cmd inspect -f '{{json .NetworkSettings.Networks}}' "$target_container" 2>/dev/null); then
    record "INFO: $description name proof failed; sender_networks=unavailable vector_networks=unavailable shared_networks=unknown alias_matches=unknown hosts_entry=0 resolver_control=not-run error_code=$error_code inspect_error=1"
    return 2
  fi
  if ! vector_networks_json=$(docker_cmd inspect -f '{{json .NetworkSettings.Networks}}' "$VECTOR_ID" 2>/dev/null); then
    record "INFO: $description name proof failed; sender_networks=read vector_networks=unavailable shared_networks=unknown alias_matches=unknown hosts_entry=0 resolver_control=not-run error_code=$error_code inspect_error=1"
    return 2
  fi
  if sender_networks=$(name_network_names_from_json <<<"$sender_networks_json"); then
    :
  else
    sender_parse_status=$?
    if (( sender_parse_status == 3 )); then sender_networks=empty; else sender_networks=invalid; fi
    record "INFO: $description name proof failed; sender_networks=$sender_networks vector_networks=read shared_networks=unknown alias_matches=unknown hosts_entry=0 resolver_control=not-run error_code=$error_code inspect_error=1"
    return 2
  fi
  if vector_networks=$(name_network_names_from_json <<<"$vector_networks_json"); then
    :
  else
    vector_parse_status=$?
    if (( vector_parse_status == 3 )); then vector_networks=empty; else vector_networks=invalid; fi
    record "INFO: $description name proof failed; sender_networks=$sender_networks vector_networks=$vector_networks shared_networks=unknown alias_matches=unknown hosts_entry=0 resolver_control=not-run error_code=$error_code inspect_error=1"
    return 2
  fi
  IFS=, read -r -a sender_network_names <<<"$sender_networks"
  IFS=, read -r -a vector_network_names <<<"$vector_networks"
  for network in "${sender_network_names[@]}"; do
    for peer_id in "${vector_network_names[@]}"; do
      if [[ "$network" == "$peer_id" ]]; then shared_networks=$((shared_networks + 1)); fi
    done
  done
  peer_format='{{printf "{\"name\":%s,\"hostname\":%s,\"service\":%s,\"networks\":%s}" (json .Name) (json .Config.Hostname) (json (index .Config.Labels "com.docker.compose.service")) (json .NetworkSettings.Networks)}}'
  for network in "${sender_network_names[@]}"; do
    if ! containers_json=$(docker_cmd network inspect -f '{{json .Containers}}' "$network" 2>/dev/null); then
      record "INFO: $description name proof failed; sender_networks=$sender_networks vector_networks=$vector_networks shared_networks=$shared_networks alias_matches=$alias_matches hosts_entry=0 resolver_control=not-run error_code=$error_code network_inspect_error=1"
      return 2
    fi
    if ! peer_ids=$(name_network_container_ids_from_json <<<"$containers_json"); then
      record "INFO: $description name proof failed; sender_networks=$sender_networks vector_networks=$vector_networks shared_networks=$shared_networks alias_matches=$alias_matches hosts_entry=0 resolver_control=not-run error_code=$error_code network_inspect_error=1"
      return 2
    fi
    sender_member_found=0
    while IFS= read -r peer_id; do
      [[ -n "$peer_id" ]] || continue
      [[ "$peer_id" == "$target_container" ]] && sender_member_found=1
      if ! peer_metadata=$(docker_cmd inspect -f "$peer_format" "$peer_id" 2>/dev/null); then
        record "INFO: $description name proof failed; sender_networks=$sender_networks vector_networks=$vector_networks shared_networks=$shared_networks alias_matches=$alias_matches hosts_entry=0 resolver_control=not-run error_code=$error_code inspect_error=1"
        return 2
      fi
      if name_peer_matches_target "$network" "$target" "$peer_metadata"; then
        alias_matches=1
      else
        peer_match_status=$?
        if (( peer_match_status != 1 )); then
          record "INFO: $description name proof failed; sender_networks=$sender_networks vector_networks=$vector_networks shared_networks=$shared_networks alias_matches=unknown hosts_entry=0 resolver_control=not-run error_code=$error_code inspect_error=1"
          return 2
        fi
      fi
    done <<<"$peer_ids"
    if (( sender_member_found == 0 )); then
      record "INFO: $description name proof failed; sender_networks=$sender_networks vector_networks=$vector_networks shared_networks=$shared_networks alias_matches=$alias_matches hosts_entry=0 resolver_control=not-run error_code=$error_code network_sender_match=0"
      return 2
    fi
  done
  if (( shared_networks != 0 || alias_matches != 0 )); then
    record "INFO: $description name proof failed; sender_networks=$sender_networks vector_networks=$vector_networks shared_networks=$shared_networks alias_matches=$alias_matches hosts_entry=0 resolver_control=not-run error_code=$error_code"
    return 2
  fi
  if ! name_resolver_positive_control "$target_container"; then
    record "INFO: $description name proof failed; sender_networks=$sender_networks vector_networks=$vector_networks shared_networks=0 alias_matches=0 hosts_entry=0 resolver_control=failed error_code=$error_code"
    return 2
  fi
  PROBE_NAME_EVIDENCE="sender_networks=$sender_networks vector_networks=$vector_networks shared_networks=0 alias_matches=0 hosts_entry=0 resolver_control=ok error_code=$error_code"
  record "INFO: $description name unresolvable ($error_code); structural: $PROBE_NAME_EVIDENCE"
}

check_isolated_probe() {
  local description=$1 sender=$2 network=$3 target=$4
  local target_container=${5:-} sender_errors=${6:-allow-routing-errors}
  local source_before shipped_before shipped_names_before sent_at source_after shipped_after shipped_names_after
  local source_delta shipped_delta send_status=0 sender_code="" routing_code="" eai_attempts=0
  source_before=$(fresh_sample)
  shipped_before=$(vector_shipped_count)
  shipped_names_before=$(vector_shipped_name_counts)
  sent_at=$(metric_now_ms)
  while true; do
    if run_probe_sender "$sender" "$network" "$target"; then
      record "INFO: $description sender completed"
      break
    fi
    send_status=$LAST_PROBE_SEND_STATUS
    if ! sender_code=$(sender_error_code "$send_status" "$LAST_PROBE_SEND_OUTPUT"); then
      record "INFO: $description sender error is unclassified (exit=$send_status)"
      return 2
    fi
    record "INFO: $description sender error code=$sender_code exit=$send_status"
    if [[ "$sender_code" == EAI_AGAIN ]]; then
      probe_target_is_name "$target" && [[ "$sender_errors" == allow-routing-errors ]] || {
        record "INFO: $description EAI_AGAIN is not acceptable for this target/context"
        return 2
      }
      eai_attempts=$((eai_attempts + 1))
      if (( eai_attempts >= 3 )); then
        if ! prove_name_target_structure "$description" "$target_container" "$target" "$sender_code"; then
          return 2
        fi
        routing_code=$sender_code
        break
      fi
      record "INFO: $description retrying EAI_AGAIN attempt $((eai_attempts + 1))/3"
      continue
    fi
    if [[ "$sender_errors" == allow-routing-errors ]] && probe_routing_error_matches_target "$sender_code" "$target"; then
      if [[ "$sender_code" == ENOTFOUND ]]; then
        if ! prove_name_target_structure "$description" "$target_container" "$target" "$sender_code"; then
          return 2
        fi
      fi
      routing_code=$sender_code
      if [[ "$sender_code" != ENOTFOUND ]]; then record "INFO: $description not routable ($routing_code)"; fi
      break
    fi
    record "INFO: $description sender error code=$sender_code is not acceptable for this target/context"
    return 2
  done
  source_after=$(wait_fresh_stable_metric "$sent_at")
  shipped_after=$(vector_shipped_count)
  shipped_names_after=$(vector_shipped_name_counts)
  source_delta=$((source_after - source_before))
  shipped_delta=$((shipped_after - shipped_before))
  if (( shipped_delta != 0 )); then report_shipped_event_delta "$shipped_names_before" "$shipped_names_after"; fi
  record "INFO: $description fresh deltas source=$source_delta shipped_probe=$shipped_delta"
  if (( source_delta == 0 && shipped_delta == 0 )); then
    if [[ -n "$routing_code" ]]; then
      if [[ "$routing_code" == ENOTFOUND || "$routing_code" == EAI_AGAIN ]]; then
        record "PASS: $description isolated: name unresolvable ($routing_code); fresh source +0 and shipped +0"
      else
        record "PASS: $description isolated: not routable ($routing_code); fresh source +0 and shipped +0"
      fi
      return 3
    fi
    return 0
  fi
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
  local description=$1 sender=$2 network=$3 target=$4
  local target_container=${5:-} status
  if check_isolated_probe "$description" "$sender" "$network" "$target" "$target_container"; then
    record "PASS: $description isolation; fresh source +0 and shipped +0"
    return 0
  else
    status=$?
  fi
  if (( status == 3 )); then return 0; fi
  fail "$description isolation check failed (status=$status)"
}

run_isolation_leak_self_test() {
  local sender=$1 network=$2 target=$3 status
  if check_isolated_probe "intentional host-loopback leak self-test" "$sender" "$network" "$target" "" must-deliver; then
    fail "isolation leak self-test passed unexpectedly"
  else
    status=$?
    (( status == 1 )) || fail "isolation leak self-test could not deliver its allowed packet (status=$status)"
    record "PASS: negative isolation check rejected a deliberately allowed host-loopback packet"
  fi
}

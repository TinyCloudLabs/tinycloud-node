#!/usr/bin/env bash
# TC-3284: tests how `harness.sh down --purge` treats a recorded process: the
# pid-reuse guard (start time) and a process that vanishes while being stopped.
# Self-contained: real `sleep` processes, a mktemp scratch dir, no network,
# no PostgreSQL or MinIO. Usage: test-stop.sh   (from anywhere)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
harness="${here}/harness.sh"

scratch="$(mktemp -d)"
scratch="$(cd "$scratch" && pwd -P)"
spawned=()
# shellcheck disable=SC2329 # runs from the EXIT trap
cleanup() {
  local p
  for p in ${spawned[@]+"${spawned[@]}"}; do
    kill -KILL -- "-$p" 2>/dev/null || kill -KILL "$p" 2>/dev/null || true
  done
  rm -rf -- "$scratch"
}
trap cleanup EXIT

failed=0
pass() { printf 'ok %s\n' "$*"; }
fail() { printf 'FAIL %s\n' "$*"; failed=1; }

# Start a session/group leader that stays up; its pid is $SPAWNED_PID.
spawn() {
  setsid sleep 300 </dev/null >/dev/null 2>&1 &
  SPAWNED_PID=$!
  disown "$SPAWNED_PID" # no job-control notice when it is killed
  spawned+=("$SPAWNED_PID")
  local i
  for ((i = 0; i < 50; i++)); do
    [[ -n "$(start_of "$SPAWNED_PID")" ]] && return 0
    sleep 0.1
  done
  echo "could not start a sleep process" >&2
  exit 1
}

# Kernel start time of a pid, read with harness.sh's own proc_start.
start_of() { bash -c 'source "$1"; proc_start "$2"' _ "$harness" "$1" 2>/dev/null || true; }

alive() { kill -0 "$1" 2>/dev/null; }

# A harness-run-* dir with a state.json recording one postgres pid and start
# time (empty start = nothing recorded). Prints the state path.
mkstate() {
  local pid=$2 start=$3 run="${scratch}/harness-run-$1"
  mkdir -p "$run"
  python3 - "$run" "$pid" "$start" <<'PY'
import json, sys
run, pid, start = sys.argv[1], int(sys.argv[2]), sys.argv[3]
state = {
    "schema": "tc887-at-rest-harness/v4",
    "status": "up",
    "run_dir": run,
    "node": {},
    "minio": {},
    "postgres": {"pid": pid, "pid_start": int(start) if start else None},
}
with open(run + "/state.json", "w") as f:
    json.dump(state, f)
PY
  printf '%s\n' "$run/state.json"
}

# Run the real `down --purge` on a state file in a fresh shell, optionally
# with proc_start stubbed to fail (what a vanished /proc/<pid>/stat does).
# Sets RC and OUT (the combined output).
run_down() {
  local state=$1 stub=$2 out="${scratch}/out.$$.$RANDOM"
  RC=0
  if [[ "$stub" == unreadable ]]; then
    bash -c 'source "$1"; proc_start() { return 1; }; cmd_down --purge "$2"' _ "$harness" "$state" >"$out" 2>&1 || RC=$?
  else
    bash -c 'source "$1"; cmd_down --purge "$2"' _ "$harness" "$state" >"$out" 2>&1 || RC=$?
  fi
  OUT=$(<"$out")
}

# check LABEL EXPECTED_RC EXPECT_ALIVE(yes|no) EXPECT_DIR(kept|removed) PID RUN_DIR OUT_PATTERN
check() {
  local label=$1 want_rc=$2 want_alive=$3 want_dir=$4 pid=$5 run=$6 pattern=$7
  local got_alive=no got_dir=removed problems=""
  alive "$pid" && got_alive=yes
  [[ -d "$run" ]] && got_dir=kept
  [[ "$RC" == "$want_rc" ]] || problems+=" exit=$RC (want $want_rc);"
  [[ "$got_alive" == "$want_alive" ]] || problems+=" process alive=$got_alive (want $want_alive);"
  [[ "$got_dir" == "$want_dir" ]] || problems+=" run dir $got_dir (want $want_dir);"
  [[ "$OUT" == *"$pattern"* ]] || problems+=" output lacks '$pattern';"
  if [[ -z "$problems" ]]; then
    pass "$label: exit $RC, process alive=$got_alive, run dir $got_dir"
  else
    fail "$label:$problems"
    printf '%s\n' "$OUT" | sed 's/^/    | /'
  fi
}

# (a) A live process whose readable start time differs from the recorded one
# is another process that reused the pid: never signalled, never purged.
spawn; pid=$SPAWNED_PID
state=$(mkstate a "$pid" 1)
run_down "$state" readable
check "(a) live, readable start != recorded: refused" 2 yes kept "$pid" "$(dirname "$state")" "is not the recorded postgres (start time $(start_of "$pid") != 1); leaving it alone"

# (b) The recorded process is exiting: its start time cannot be read now.
# Not pid reuse: the group is stopped and the run purged.
spawn; pid=$SPAWNED_PID
state=$(mkstate b "$pid" "$(start_of "$pid")")
run_down "$state" unreadable
check "(b) recorded start, unreadable now: stopped and purged" 0 no removed "$pid" "$(dirname "$state")" "postgres (process group $pid) stopped"

# (b') The recorded process has already exited (no stub: /proc/<pid> is gone).
spawn; pid=$SPAWNED_PID
start=$(start_of "$pid")
kill -KILL "$pid"
for ((i = 0; i < 100; i++)); do alive "$pid" || break; sleep 0.1; done
alive "$pid" && { echo "sleep $pid did not exit" >&2; exit 1; }
state=$(mkstate bx "$pid" "$start")
run_down "$state" readable
check "(b') process already exited: not running, purged" 0 no removed "$pid" "$(dirname "$state")" "postgres (pid $pid) is not running"

# (c) A live pid with no recorded start time is never signalled or purged,
# even when its start time cannot be read now.
spawn; pid=$SPAWNED_PID
state=$(mkstate c "$pid" "")
run_down "$state" unreadable
check "(c) live, nothing recorded, start unreadable: refused" 2 yes kept "$pid" "$(dirname "$state")" "is not the recorded postgres (start time ? != unrecorded); leaving it alone"

# (c') Same, with a readable start time.
spawn; pid=$SPAWNED_PID
state=$(mkstate cx "$pid" "")
run_down "$state" readable
check "(c') live, nothing recorded, start readable: refused" 2 yes kept "$pid" "$(dirname "$state")" "is not the recorded postgres (start time $(start_of "$pid") != unrecorded); leaving it alone"

exit "$failed"

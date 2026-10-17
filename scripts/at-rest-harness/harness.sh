#!/usr/bin/env bash
# TC-887 S0: native at-rest harness. A real tinycloud-node binary on native
# PostgreSQL (capability DB + SQL artifacts) and native MinIO (S3 block store).
# No containers. Everything binds 127.0.0.1 on free ports; all state lives in
# one per-run directory; `down` stops only the PIDs this harness recorded.
#
#   harness.sh bins                 fetch + sha256-verify the pinned MinIO/mc binaries
#   harness.sh up [--no-build]      start PG, MinIO, the node; print the state file path
#   harness.sh test green|red       run the harness checks against the running harness
#   harness.sh status               print the state file
#   harness.sh logs                 tail the harness logs (no secrets are written to them)
#   harness.sh down [--purge]       stop recorded PIDs; --purge also removes the run dir
#
# See README.md next to this script.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRATCH_ROOT=${TC887_SCRATCH_ROOT:-$HOME/scratch/tc887}
LATEST_LINK=$SCRATCH_ROOT/harness-latest
BIN_DIR=${TC887_BIN_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/tc887-harness/bin}

# Pinned MinIO community releases. dl.min.io no longer serves community
# binaries (HTTP 410), so these come from the archived GitHub releases. The
# sha256 values are pinned here, not trusted from the download.
MINIO_RELEASE=RELEASE.2025-09-07T16-13-09Z
MINIO_SHA256=7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f
MC_RELEASE=RELEASE.2025-08-13T08-35-41Z
MC_SHA256=01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891
MINIO_URL=https://github.com/minio/minio/releases/download/$MINIO_RELEASE/minio.linux-amd64.$MINIO_RELEASE
MC_URL=https://github.com/minio/mc/releases/download/$MC_RELEASE/mc.linux-amd64.$MC_RELEASE

BUCKET=tinycloud-blocks
REGION=us-east-1
PG_USER=tc887
PG_DB=tinycloud

die() { printf 'at-rest-harness: %s\n' "$*" >&2; exit 2; }
log() { printf 'at-rest-harness: %s\n' "$*" >&2; }

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

random_hex() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }

# Write stdin to a new 0600 file.
secret_file() { (umask 077 && cat >"$1"); }

# ---------------------------------------------------------------- binaries --

fetch_one() {
  local name=$1 url=$2 want=$3 dest=$BIN_DIR/$1
  if [[ -x "$dest" && "$(sha256_of "$dest")" == "$want" ]]; then
    return 0
  fi
  mkdir -p "$BIN_DIR"
  local tmp
  tmp=$(mktemp "$BIN_DIR/.$name.XXXXXX")
  log "downloading $name from $url"
  curl -fsSL --retry 3 --max-time 600 -o "$tmp" "$url"
  local got
  got=$(sha256_of "$tmp")
  if [[ "$got" != "$want" ]]; then
    rm -f "$tmp"
    die "$name sha256 mismatch: got $got, pinned $want"
  fi
  chmod 0755 "$tmp"
  mv -f "$tmp" "$dest"
}

cmd_bins() {
  fetch_one minio "$MINIO_URL" "$MINIO_SHA256"
  fetch_one mc "$MC_URL" "$MC_SHA256"
  log "minio: $("$BIN_DIR/minio" --version | head -1)"
  log "mc:    $("$BIN_DIR/mc" --version | head -1)"
}

detect_pg_bin() {
  if [[ -n "${PG_BIN:-}" ]]; then
    [[ -x "$PG_BIN/initdb" ]] || die "PG_BIN=$PG_BIN has no initdb"
    printf '%s\n' "$PG_BIN"
    return
  fi
  local best
  best=$(find /usr/lib/postgresql -mindepth 3 -maxdepth 3 -path '*/bin/initdb' 2>/dev/null | sort -V | tail -1)
  if [[ -n "$best" ]]; then
    dirname "$best"
    return
  fi
  if command -v pg_config >/dev/null && [[ -x "$(pg_config --bindir)/initdb" ]]; then
    pg_config --bindir
    return
  fi
  die "no native PostgreSQL found; set PG_BIN to a directory with initdb/pg_ctl/postgres"
}

node_target_dir() {
  cargo metadata --format-version 1 --no-deps --manifest-path "$ROOT/Cargo.toml" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])'
}

# --------------------------------------------------------------------- up ---

wait_http() {
  local url=$1 pid=$2 what=$3 seconds=$4 i
  for ((i = 0; i < seconds * 5; i++)); do
    kill -0 "$pid" 2>/dev/null || die "$what (pid $pid) exited during startup"
    if curl -fsS --max-time 2 -o /dev/null "$url" 2>/dev/null; then
      return 0
    fi
    sleep 0.2
  done
  die "$what did not become ready at $url within ${seconds}s"
}

cmd_up() {
  local build=1
  for arg in "$@"; do
    case $arg in
      --no-build) build=0 ;;
      *) die "up: unknown argument $arg" ;;
    esac
  done
  command -v python3 >/dev/null || die "python3 is required"
  command -v curl >/dev/null || die "curl is required"
  cmd_bins

  local pg_bin
  pg_bin=$(detect_pg_bin)

  local node_bin=${TC887_NODE_BIN:-}
  if [[ -z "$node_bin" ]]; then
    if ((build)); then
      log "building tinycloud-node (nice -n 10, -j ${TC887_CARGO_JOBS:-8})"
      (cd "$ROOT" && nice -n 10 cargo build -p tinycloud-node --bin tinycloud -j "${TC887_CARGO_JOBS:-8}")
    fi
    node_bin=$(node_target_dir)/debug/tinycloud
  fi
  [[ -x "$node_bin" ]] || die "node binary $node_bin is missing (build it or set TC887_NODE_BIN)"
  node_bin=$(readlink -f "$node_bin")

  mkdir -p "$SCRATCH_ROOT"
  local run
  run=${TC887_RUN_DIR:-$SCRATCH_ROOT/harness-run-$(date -u +%Y%m%dT%H%M%SZ)-$$}
  [[ ! -e "$run/state.json" ]] || die "$run already holds a harness"
  mkdir -p "$run"
  chmod 0700 "$run"
  run=$(cd "$run" && pwd)
  mkdir -p "$run"/{bin,secrets,logs,home,tmp,node-data,minio-data,mc}
  chmod 0700 "$run/secrets"
  # Run a private copy, so a rebuild of target/ neither swaps the binary under
  # the node nor breaks `down`'s /proc/<pid>/exe check.
  log "node binary: $node_bin"
  install -m 0755 "$node_bin" "$run/bin/tinycloud"
  node_bin=$run/bin/tinycloud

  local pg_port=${TC887_PG_PORT:-$(free_port)}
  local minio_port=${TC887_MINIO_PORT:-$(free_port)}
  local console_port=${TC887_MINIO_CONSOLE_PORT:-$(free_port)}
  local node_port=${TC887_NODE_PORT:-$(free_port)}
  # Every write_state call (including the partial ones `down` may need after a
  # failed `up`) records the binaries `down` verifies PIDs against.
  export STATE_PG_BIN=$pg_bin STATE_NODE_BIN=$node_bin STATE_PG_PORT=$pg_port \
    STATE_MINIO_PORT=$minio_port STATE_CONSOLE_PORT=$console_port STATE_NODE_PORT=$node_port

  # Per-run secrets: generated here, kept in 0600 files, never on argv.
  random_hex | secret_file "$run/secrets/pg-password"
  printf 'tc887%s\n' "$(python3 -c 'import secrets; print(secrets.token_hex(8))')" | secret_file "$run/secrets/minio-user"
  random_hex | secret_file "$run/secrets/minio-password"
  python3 -c 'import secrets; print(secrets.token_urlsafe(32))' | secret_file "$run/secrets/node-static-secret"
  local pg_password minio_user minio_password node_secret
  pg_password=$(<"$run/secrets/pg-password")
  minio_user=$(<"$run/secrets/minio-user")
  minio_password=$(<"$run/secrets/minio-password")
  node_secret=$(<"$run/secrets/node-static-secret")
  printf '127.0.0.1:%s:*:%s:%s\n' "$pg_port" "$PG_USER" "$pg_password" | secret_file "$run/secrets/pgpass"

  local pg_url="postgres://$PG_USER:$pg_password@127.0.0.1:$pg_port/$PG_DB"
  local s3_endpoint="http://127.0.0.1:$minio_port"
  local node_url="http://127.0.0.1:$node_port"

  # Test-side credentials (read by the Rust harness checks).
  secret_file "$run/harness.env" <<EOF
TC887_NODE_URL=$node_url
TC887_PG_URL=$pg_url
TC887_S3_ENDPOINT=$s3_endpoint
TC887_S3_BUCKET=$BUCKET
TC887_S3_REGION=$REGION
TC887_S3_ACCESS_KEY_ID=$minio_user
TC887_S3_SECRET_ACCESS_KEY=$minio_password
EOF
  # The node's whole environment; sourced inside the child, never on argv.
  secret_file "$run/node.env" <<EOF
HOME=$run/home
TMPDIR=$run/tmp
PATH=/usr/local/bin:/usr/bin:/bin
TINYCLOUD_CONFIG_FILE=$run/tinycloud.toml
TINYCLOUD_ADDRESS=127.0.0.1
TINYCLOUD_PORT=$node_port
TINYCLOUD_LOG_LEVEL=normal
TINYCLOUD_STORAGE__DATADIR=$run/node-data
TINYCLOUD_STORAGE__STAGING=FileSystem
TINYCLOUD_STORAGE__DATABASE=$pg_url
TINYCLOUD_STORAGE__BLOCKS__TYPE=S3
TINYCLOUD_STORAGE__BLOCKS__BUCKET=$BUCKET
TINYCLOUD_STORAGE__BLOCKS__ENDPOINT=$s3_endpoint
TINYCLOUD_KEYS__TYPE=Static
TINYCLOUD_KEYS__SECRET=$node_secret
AWS_ACCESS_KEY_ID=$minio_user
AWS_SECRET_ACCESS_KEY=$minio_password
AWS_REGION=$REGION
AWS_DEFAULT_REGION=$REGION
AWS_EC2_METADATA_DISABLED=true
EOF
  printf '[global]\nlog_level = "normal"\n' >"$run/tinycloud.toml"

  # Partial state first, so `down` can clean up a failed `up`.
  write_state "$run" "starting" "" "" ""
  ln -sfn "$run" "$LATEST_LINK"
  trap 'log "up failed; run: $0 down --purge $run"' ERR

  # ---- PostgreSQL
  log "PostgreSQL: $("$pg_bin/postgres" --version) on 127.0.0.1:$pg_port"
  "$pg_bin/initdb" -D "$run/pgdata" -U "$PG_USER" --auth=scram-sha-256 \
    --pwfile="$run/secrets/pg-password" -E UTF8 --locale=C >"$run/logs/initdb.log" 2>&1
  cat >>"$run/pgdata/postgresql.conf" <<EOF
# TC-887 harness
listen_addresses = '127.0.0.1'
port = $pg_port
unix_socket_directories = ''
EOF
  "$pg_bin/pg_ctl" -D "$run/pgdata" -l "$run/logs/postgres.log" -w -t 60 start >/dev/null
  local pg_pid
  pg_pid=$(head -1 "$run/pgdata/postmaster.pid")
  write_state "$run" "starting" "$pg_pid" "" ""
  PGPASSFILE=$run/secrets/pgpass "$pg_bin/psql" -X -q -h 127.0.0.1 -p "$pg_port" -U "$PG_USER" \
    -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE $PG_DB"

  # ---- MinIO
  log "MinIO: $MINIO_RELEASE on $s3_endpoint"
  (
    cd "$run"
    export MINIO_ROOT_USER=$minio_user MINIO_ROOT_PASSWORD=$minio_password
    export MINIO_BROWSER=off MINIO_UPDATE=off HOME=$run/home
    exec setsid "$BIN_DIR/minio" server "$run/minio-data" --quiet \
      --address "127.0.0.1:$minio_port" --console-address "127.0.0.1:$console_port" \
      </dev/null >"$run/logs/minio.log" 2>&1
  ) &
  local minio_pid=$!
  write_state "$run" "starting" "$pg_pid" "$minio_pid" ""
  wait_http "$s3_endpoint/minio/health/live" "$minio_pid" MinIO 60
  # mc reads the alias (with credentials) from the environment, not argv.
  MC_CONFIG_DIR=$run/mc MC_HOST_tc887="http://$minio_user:$minio_password@127.0.0.1:$minio_port" \
    "$BIN_DIR/mc" --quiet mb "tc887/$BUCKET" >"$run/logs/mc.log" 2>&1

  # ---- tinycloud-node
  log "tinycloud-node: $node_bin on $node_url"
  (
    cd "$run"
    exec env -i NODE_ENV_FILE="$run/node.env" setsid bash -c \
      'set -a; . "$NODE_ENV_FILE"; set +a; unset NODE_ENV_FILE; exec "$0"' "$node_bin" \
      </dev/null >"$run/logs/node.log" 2>&1
  ) &
  local node_pid=$!
  write_state "$run" "starting" "$pg_pid" "$minio_pid" "$node_pid"
  wait_http "$node_url/healthz" "$node_pid" tinycloud-node 180

  # ---- state file
  write_state "$run" "up" "$pg_pid" "$minio_pid" "$node_pid"
  trap - ERR
  log "up: state file $run/state.json"
  printf '%s\n' "$run/state.json"
}

# write_state RUN STATUS PG_PID MINIO_PID NODE_PID; extra fields via STATE_* env.
write_state() {
  local run=$1
  RUN=$run STATUS=$2 PG_PID=$3 MINIO_PID=$4 NODE_PID=$5 \
    BIN_DIR=$BIN_DIR MINIO_RELEASE=$MINIO_RELEASE MC_RELEASE=$MC_RELEASE \
    BUCKET=$BUCKET REGION=$REGION PG_USER=$PG_USER PG_DB=$PG_DB python3 - <<'PY'
import json, os, datetime
e = os.environ
run = e["RUN"]
def pid(name):
    v = e.get(name, "")
    return int(v) if v else None
def port(name):
    v = e.get(name, "")
    return int(v) if v else None
pg_bin = e.get("STATE_PG_BIN")
state = {
    "schema": "tc887-at-rest-harness/v1",
    "status": e["STATUS"],
    "run_dir": run,
    "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "env_file": os.path.join(run, "harness.env"),
    "node": {
        "pid": pid("NODE_PID"),
        "port": port("STATE_NODE_PORT"),
        "url": f"http://127.0.0.1:{e['STATE_NODE_PORT']}" if e.get("STATE_NODE_PORT") else None,
        "bin": e.get("STATE_NODE_BIN"),
        "data_dir": os.path.join(run, "node-data"),
        "log": os.path.join(run, "logs", "node.log"),
        "keys": "Static (per-run, secrets/node-static-secret)",
    },
    "postgres": {
        "pid": pid("PG_PID"),
        "port": port("STATE_PG_PORT"),
        "bin_dir": pg_bin,
        "exe": os.path.join(pg_bin, "postgres") if pg_bin else None,
        "data_dir": os.path.join(run, "pgdata"),
        "user": e["PG_USER"],
        "database": e["PG_DB"],
        "log": os.path.join(run, "logs", "postgres.log"),
    },
    "minio": {
        "pid": pid("MINIO_PID"),
        "port": port("STATE_MINIO_PORT"),
        "console_port": port("STATE_CONSOLE_PORT"),
        "endpoint": f"http://127.0.0.1:{e['STATE_MINIO_PORT']}" if e.get("STATE_MINIO_PORT") else None,
        "bin": os.path.join(e["BIN_DIR"], "minio"),
        "release": e["MINIO_RELEASE"],
        "mc_release": e["MC_RELEASE"],
        "bucket": e["BUCKET"],
        "region": e["REGION"],
        "data_dir": os.path.join(run, "minio-data"),
        "log": os.path.join(run, "logs", "minio.log"),
    },
}
path = os.path.join(run, "state.json")
with open(path + ".tmp", "w") as f:
    json.dump(state, f, indent=2)
    f.write("\n")
os.replace(path + ".tmp", path)
PY
}

# ------------------------------------------------------------------- down ---

resolve_state() {
  local target=${1:-${TC887_HARNESS_STATE:-$LATEST_LINK}}
  [[ -d "$target" ]] && target=$target/state.json
  [[ -f "$target" ]] || die "no harness state at $target"
  readlink -f "$target"
}

state_get() {
  python3 - "$1" "$2" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
for key in sys.argv[2].split("."):
    value = value.get(key) if isinstance(value, dict) else None
print("" if value is None else value)
PY
}

# Signal PID only if it is still the process we started (exe matches).
# Returns 1 if a live PID was left alone.
stop_recorded() {
  local what=$1 pid=$2 exe=$3
  [[ -n "$pid" ]] || return 0
  if ! kill -0 "$pid" 2>/dev/null; then
    log "$what (pid $pid) is not running"
    return 0
  fi
  local actual
  actual=$(readlink "/proc/$pid/exe" 2>/dev/null || true)
  actual=${actual% (deleted)}
  if [[ -z "$exe" || "$actual" != "$(readlink -f "$exe")" ]]; then
    log "pid $pid is '$actual', not the recorded $what ($exe); leaving it alone"
    return 1
  fi
  kill -TERM "$pid" 2>/dev/null || true
  local i
  for ((i = 0; i < 100; i++)); do
    kill -0 "$pid" 2>/dev/null || { log "$what (pid $pid) stopped"; return 0; }
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  log "$what (pid $pid) killed"
}

cmd_down() {
  local purge=0 target=""
  for arg in "$@"; do
    case $arg in
      --purge) purge=1 ;;
      *) target=$arg ;;
    esac
  done
  local state run
  state=$(resolve_state "$target")
  run=$(state_get "$state" run_dir)
  local survivors=0
  stop_recorded tinycloud-node "$(state_get "$state" node.pid)" "$(state_get "$state" node.bin)" || survivors=1
  stop_recorded minio "$(state_get "$state" minio.pid)" "$(state_get "$state" minio.bin)" || survivors=1
  local pg_pid pg_bin pg_exe
  pg_pid=$(state_get "$state" postgres.pid)
  pg_bin=$(state_get "$state" postgres.bin_dir)
  pg_exe=$(state_get "$state" postgres.exe)
  if [[ -n "$pg_pid" && -n "$pg_exe" ]] && kill -0 "$pg_pid" 2>/dev/null \
    && [[ "$(readlink "/proc/$pg_pid/exe" 2>/dev/null)" == "$(readlink -f "$pg_exe")" ]] \
    && "$pg_bin/pg_ctl" -D "$run/pgdata" -m fast -w -t 60 stop >/dev/null; then
    log "postgres (pid $pg_pid) stopped"
  else
    stop_recorded postgres "$pg_pid" "$pg_exe" || survivors=1
  fi
  if ((purge)); then
    ((survivors == 0)) || die "not purging $run: a recorded PID is still running"
    case $run in
      "$SCRATCH_ROOT"/harness-run-*|"${TC887_RUN_DIR:-/nonexistent}") rm -rf -- "$run"; log "removed $run" ;;
      *) log "not purging $run: outside $SCRATCH_ROOT/harness-run-*" ;;
    esac
    [[ "$(readlink -f "$LATEST_LINK" 2>/dev/null)" != "$run" ]] || rm -f "$LATEST_LINK"
  fi
  return "$survivors"
}

# ------------------------------------------------------------------- test ---

cmd_test() {
  local kind=${1:-} expected
  case $kind in
    green) expected=2 ;;
    red) expected=2 ;;
    *) die "usage: harness.sh test green|red" ;;
  esac
  local state
  state=$(resolve_state "${2:-}")
  [[ "$(state_get "$state" status)" == up ]] || die "harness at $state is not up"
  local out status=0
  out=$(mktemp)
  (cd "$ROOT" && TC887_HARNESS_STATE=$state nice -n 10 cargo test -p tinycloud-node \
    -j "${TC887_CARGO_JOBS:-8}" --test at_rest_harness -- --ignored --nocapture --test-threads=1 "${kind}_") \
    2>&1 | tee "$out" || status=$?
  # libtest exits 0 when a filter matches nothing; never let that pass (TC-381).
  local ran
  ran=$(grep -Eo 'test result: [A-Za-z]+\. [0-9]+ passed; [0-9]+ failed' "$out" \
    | awk '{s += $4 + $6} END {print s + 0}')
  rm -f "$out"
  if [[ "$ran" -ne "$expected" ]]; then
    die "$kind: expected $expected harness checks to run, $ran ran"
  fi
  return "$status"
}

cmd_status() { cat "$(resolve_state "${1:-}")"; }

cmd_logs() {
  local state run f
  state=$(resolve_state "${1:-}")
  run=$(state_get "$state" run_dir)
  for f in "$run"/logs/*.log; do
    printf '==> %s <==\n' "$f"
    tail -n "${TC887_LOG_LINES:-40}" "$f"
  done
}

case ${1:-} in
  bins) shift; cmd_bins "$@" ;;
  up) shift; cmd_up "$@" ;;
  down) shift; cmd_down "$@" ;;
  test) shift; cmd_test "$@" ;;
  status) shift; cmd_status "$@" ;;
  logs) shift; cmd_logs "$@" ;;
  *) die "usage: harness.sh bins|up [--no-build]|test green|red|status|logs|down [--purge] [STATE]" ;;
esac

#!/usr/bin/env bash
# TC-887 S0: native at-rest harness. A real tinycloud-node binary on native
# PostgreSQL (capability DB + SQL artifacts) and native MinIO (S3 block store).
# No containers. Everything binds 127.0.0.1 on free ports; all state lives in
# one per-run directory; `down` stops only the process groups this run started.
#
#   harness.sh bins                              fetch + sha256-verify the pinned MinIO/mc binaries
#   harness.sh up [--no-build]                   start PG, MinIO, the node; prints the STATE path last
#   harness.sh test green|red [--expect EXPECT] STATE
#                                                run the checks; exit 0 only if each check (kv, sql)
#                                                matches EXPECT: green|red (both) or kv=green|red,sql=green|red
#   harness.sh status STATE                      print the state file
#   harness.sh logs STATE                        tail the harness logs (no secrets are written to them)
#   harness.sh down [--purge] STATE              stop the recorded processes; --purge removes the run dir
#
# STATE is the state.json path `up` printed (or its run directory). Commands
# never guess it. See README.md next to this script.
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SCRATCH_ROOT=${TC887_SCRATCH_ROOT:-$HOME/scratch/tc887}
BIN_DIR=${TC887_BIN_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/tc887-harness/bin}
STATE_SCHEMA=tc887-at-rest-harness/v4

# Pinned MinIO community releases (linux-amd64). dl.min.io no longer serves
# community binaries (HTTP 410), so these come from the archived GitHub
# releases. The sha256 values are pinned here, not trusted from the download.
MINIO_RELEASE=RELEASE.2025-09-07T16-13-09Z
MINIO_SHA256=7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f
MC_RELEASE=RELEASE.2025-08-13T08-35-41Z
MC_SHA256=01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891
MINIO_URL=https://github.com/minio/minio/releases/download/$MINIO_RELEASE/minio.linux-amd64.$MINIO_RELEASE
MC_URL=https://github.com/minio/mc/releases/download/$MC_RELEASE/mc.linux-amd64.$MC_RELEASE

# ---------------------------------------------------------------------------
# TC-887 at-rest node config, as defined by the S1 key-continuity slice. This
# block is the only place the harness names them (README "At-rest mode"
# documents the same mapping).
#   TC887_AT_REST_MODE        -> TINYCLOUD_AT_REST__MODE         (off|encrypt|strict)
#   TC887_AT_REST_ESCROW_NONE -> TINYCLOUD_AT_REST__ESCROW_NONE  (true|false: the Static
#                                self-host acknowledgement that no escrow exists, plan §5)
# Unset: the harness sets nothing and the node runs its default (today: no
# encryption at rest). Simplest encrypting node: Static root (always, here) +
# TC887_AT_REST_MODE=encrypt + TC887_AT_REST_ESCROW_NONE=true. With mode
# encrypt/strict, `test red` defaults to expecting kv=green,sql=red: S3 seals
# KV before S4 seals SQL. When S4 lands, flip the SQL default to green
# (default_expect below).
AT_REST_MODE_VAR=TINYCLOUD_AT_REST__MODE
AT_REST_ESCROW_NONE_VAR=TINYCLOUD_AT_REST__ESCROW_NONE
# ---------------------------------------------------------------------------

BUCKET=tinycloud-blocks
REGION=us-east-1
PG_USER=tc887
PG_DB=tinycloud

die() { printf 'at-rest-harness: %s\n' "$*" >&2; exit 2; }
log() { printf 'at-rest-harness: %s\n' "$*" >&2; }

sha256_of() { sha256sum "$1" | awk '{print $1}'; }

# Bind-and-release; another process can take the port before we use it.
free_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

random_hex() { python3 -c 'import secrets; print(secrets.token_hex(24))'; }

# Write stdin to a new 0600 file.
secret_file() { (umask 077 && cat >"$1"); }

# Kernel start time (clock ticks since boot) of PID: with the PID, it names
# one process for its whole life, across exec and binary rebuilds.
proc_start() {
  local stat
  stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  stat=${stat##*) }
  # shellcheck disable=SC2086
  set -- $stat
  printf '%s\n' "${20}"
}

# ---------------------------------------------------------------- binaries --

fetch_one() {
  local name=$1 url=$2 want=$3 dest=$BIN_DIR/$1
  if [[ -x "$dest" && "$(sha256_of "$dest")" == "$want" ]]; then
    return 0
  fi
  mkdir -p "$BIN_DIR"
  local tmp got
  tmp=$(mktemp "$BIN_DIR/.$name.XXXXXX")
  log "downloading $name from $url"
  if ! curl -fsSL --retry 3 --max-time 600 -o "$tmp" "$url"; then
    rm -f "$tmp"
    die "downloading $name failed"
  fi
  got=$(sha256_of "$tmp")
  if [[ "$got" != "$want" ]]; then
    rm -f "$tmp"
    die "$name sha256 mismatch: got $got, pinned $want"
  fi
  chmod 0755 "$tmp"
  mv -f "$tmp" "$dest"
}

cmd_bins() {
  local os arch
  os=$(uname -s) arch=$(uname -m)
  [[ "$os" == Linux && "$arch" == x86_64 ]] \
    || die "the pinned MinIO/mc binaries are linux-amd64 only; this host is $os $arch"
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

# ------------------------------------------------------------ processes ---

# Is the process group led by PID (or PID itself) still alive?
group_alive() { kill -0 -- "-$1" 2>/dev/null || kill -0 "$1" 2>/dev/null; }

signal_group() { kill "-$1" -- "-$2" 2>/dev/null || kill "-$1" "$2" 2>/dev/null || true; }

# Stop the process group led by a recorded PID. Each harness process is a
# session/group leader (setsid; pg_ctl's postmaster calls setsid), so the
# group holds it and the children it forks. (PostgreSQL moves its backends
# into their own groups; the postmaster stops them on SIGTERM, and they exit
# by themselves if it dies.) The leader is signalled only if its kernel start
# time still matches the recorded one. A group whose leader is gone still
# holds our leftovers: Linux never reuses a PID while it names a live process
# group. Returns 1 if a live PID was left alone.
stop_recorded() {
  local what=$1 pid=$2 start=$3
  [[ -n "$pid" ]] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    local actual
    actual=$(proc_start "$pid" || true)
    if [[ -z "$start" || "$actual" != "$start" ]]; then
      log "pid $pid is not the recorded $what (start time ${actual:-?} != ${start:-unrecorded}); leaving it alone"
      return 1
    fi
  elif ! group_alive "$pid"; then
    log "$what (pid $pid) is not running"
    return 0
  fi
  signal_group TERM "$pid"
  local i
  for ((i = 0; i < 100; i++)); do
    group_alive "$pid" || { log "$what (process group $pid) stopped"; return 0; }
    sleep 0.1
  done
  signal_group KILL "$pid"
  for ((i = 0; i < 50; i++)); do
    group_alive "$pid" || { log "$what (process group $pid) killed"; return 0; }
    sleep 0.1
  done
  log "$what (process group $pid) survived SIGKILL"
  return 1
}

# pg_ctl stop (a clean shutdown of our data dir), then the group fallback.
stop_postgres() {
  local run=$1 pid=$2 start=$3 pg_bin=$4
  if [[ -n "$pid" && -n "$pg_bin" && -f "$run/pgdata/postmaster.pid" ]] \
    && kill -0 "$pid" 2>/dev/null && [[ "$(proc_start "$pid" || true)" == "$start" ]]; then
    if "$pg_bin/pg_ctl" -D "$run/pgdata" -m fast -w -t 30 stop >/dev/null 2>&1 && ! group_alive "$pid"; then
      log "postgres (process group $pid) stopped by pg_ctl"
      return 0
    fi
  fi
  stop_recorded postgres "$pid" "$start"
}

# --------------------------------------------------------------------- up ---

UP_RUN="" UP_PG_PID="" UP_PG_START="" UP_MINIO_PID="" UP_MINIO_START="" UP_NODE_PID="" UP_NODE_START=""

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

# EXIT trap of `up`: a failed, interrupted or timed-out `up` stops every
# process group it started and keeps the run dir (logs) for inspection.
up_abort() {
  local status=$?
  trap '' INT TERM
  trap - EXIT
  set +e
  if [[ -n "$UP_RUN" && -d "$UP_RUN" ]]; then
    log "up failed (exit $status); stopping every process this run started"
    if [[ -z "$UP_PG_PID" && -f "$UP_RUN/pgdata/postmaster.pid" ]]; then
      UP_PG_PID=$(head -1 "$UP_RUN/pgdata/postmaster.pid")
      UP_PG_START=$(proc_start "$UP_PG_PID")
    fi
    write_state "$UP_RUN" failed
    stop_recorded tinycloud-node "$UP_NODE_PID" "$UP_NODE_START"
    stop_recorded minio "$UP_MINIO_PID" "$UP_MINIO_START"
    stop_postgres "$UP_RUN" "$UP_PG_PID" "$UP_PG_START" "${STATE_PG_BIN:-}"
    log "logs kept in $UP_RUN/logs; remove the run with: $0 down --purge $UP_RUN/state.json"
  fi
  exit "$status"
}

valid_mode() { [[ "$1" =~ ^(off|encrypt|strict)$ ]]; }
valid_bool() { [[ "$1" =~ ^(true|false)$ ]]; }

cmd_up() {
  local build=1
  for arg in "$@"; do
    case $arg in
      --no-build) build=0 ;;
      *) die "up: unknown argument $arg" ;;
    esac
  done
  trap up_abort EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  command -v python3 >/dev/null || die "python3 is required"
  command -v curl >/dev/null || die "curl is required"
  local at_rest_mode=${TC887_AT_REST_MODE:-} at_rest_escrow_none=${TC887_AT_REST_ESCROW_NONE:-}
  [[ -z "$at_rest_mode" ]] || valid_mode "$at_rest_mode" \
    || die "TC887_AT_REST_MODE must be off, encrypt or strict"
  [[ -z "$at_rest_escrow_none" ]] || valid_bool "$at_rest_escrow_none" \
    || die "TC887_AT_REST_ESCROW_NONE must be true or false"
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
  [[ "$(basename "$run")" == harness-run-* ]] || die "run dir must be named harness-run-*: $run"
  [[ ! -e "$run/state.json" ]] || die "$run already holds a harness"
  mkdir -p "$run"
  chmod 0700 "$run"
  run=$(cd "$run" && pwd)
  UP_RUN=$run
  mkdir -p "$run"/{bin,secrets,logs,home,tmp,node-data,minio-data,mc}
  chmod 0700 "$run/secrets"
  # Run a private copy, so a rebuild of target/ can't swap the binary under
  # the node.
  log "node binary: $node_bin"
  install -m 0755 "$node_bin" "$run/bin/tinycloud"
  node_bin=$run/bin/tinycloud

  local pg_port=${TC887_PG_PORT:-$(free_port)}
  local minio_port=${TC887_MINIO_PORT:-$(free_port)}
  local console_port=${TC887_MINIO_CONSOLE_PORT:-$(free_port)}
  local node_port=${TC887_NODE_PORT:-$(free_port)}
  # Recorded by every write_state call, including a failed up's.
  export STATE_PG_BIN=$pg_bin STATE_NODE_BIN=$node_bin STATE_PG_PORT=$pg_port \
    STATE_MINIO_PORT=$minio_port STATE_CONSOLE_PORT=$console_port STATE_NODE_PORT=$node_port \
    STATE_AT_REST_MODE=$at_rest_mode STATE_AT_REST_ESCROW_NONE=$at_rest_escrow_none

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
TC887_NODE_ROOT_FILE=$run/secrets/node-static-secret
TC887_SPACES_LOG=$run/spaces.log
TC887_PUTS_LOG=$run/puts.log
TC887_BOOT_SNAPSHOT=$run/boot-snapshot
EOF
  # The node's whole environment; sourced inside the child, never on argv.
  # memory_threshold=0 keeps SQL databases file-backed, so writes after the
  # first checkpoint are saved as WAL deltas (database_artifact.delta_payload).
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
TINYCLOUD_STORAGE__SQL__MEMORY_THRESHOLD=0
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
  if [[ -n "$at_rest_mode" ]]; then
    printf '%s=%s\n' "$AT_REST_MODE_VAR" "$at_rest_mode" >>"$run/node.env"
    log "at-rest: $AT_REST_MODE_VAR=$at_rest_mode"
  fi
  if [[ -n "$at_rest_escrow_none" ]]; then
    printf '%s=%s\n' "$AT_REST_ESCROW_NONE_VAR" "$at_rest_escrow_none" >>"$run/node.env"
    log "at-rest: $AT_REST_ESCROW_NONE_VAR=$at_rest_escrow_none"
  fi
  printf '[global]\nlog_level = "normal"\n' >"$run/tinycloud.toml"
  write_state "$run" starting

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
  UP_PG_PID=$(head -1 "$run/pgdata/postmaster.pid")
  UP_PG_START=$(proc_start "$UP_PG_PID")
  write_state "$run" starting
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
  UP_MINIO_PID=$!
  UP_MINIO_START=$(proc_start "$UP_MINIO_PID" || true)
  write_state "$run" starting
  wait_http "$s3_endpoint/minio/health/live" "$UP_MINIO_PID" MinIO 60
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
  UP_NODE_PID=$!
  UP_NODE_START=$(proc_start "$UP_NODE_PID" || true)
  write_state "$run" starting
  wait_http "$node_url/healthz" "$UP_NODE_PID" tinycloud-node "${TC887_NODE_READY_SECS:-180}"

  # ---- boot snapshot: every object as the node left it at boot, before any
  # test write (the at-rest key mirror writes ARK/escrow objects here).
  MC_HOST_tc887="http://$minio_user:$minio_password@127.0.0.1:$minio_port" \
    snapshot_bucket "$run"

  write_state "$run" up
  trap - EXIT INT TERM
  log "up: state file $run/state.json"
  printf '%s\n' "$run/state.json"
}

# Copy every object of the harness bucket into $1/boot-snapshot as N.bin, with
# index.json mapping each object key to its file. Keys never become paths.
# Needs MC_HOST_tc887 (credentials) in the environment.
snapshot_bucket() {
  local run=$1 dir=$1/boot-snapshot i=0 key count
  mkdir -p "$dir"
  MC_CONFIG_DIR=$run/mc "$BIN_DIR/mc" --quiet ls --recursive --json "tc887/$BUCKET" \
    >"$dir/listing.jsonl" 2>>"$run/logs/mc.log"
  while IFS= read -r -d '' key; do
    MC_CONFIG_DIR=$run/mc "$BIN_DIR/mc" --quiet cat "tc887/$BUCKET/$key" \
      >"$dir/$i.bin" 2>>"$run/logs/mc.log"
    i=$((i + 1))
  done < <(python3 - "$dir" <<'PY'
import json, os, sys
out = sys.argv[1]
keys = []
with open(os.path.join(out, "listing.jsonl")) as f:
    for line in f:
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("status") != "success":
            sys.exit("mc ls reported an error")
        if entry.get("type") == "file":
            keys.append(entry["key"])
index = [{"key": k, "file": f"{i}.bin"} for i, k in enumerate(keys)]
with open(os.path.join(out, "index.json"), "w") as f:
    json.dump(index, f, indent=1)
for k in keys:
    sys.stdout.write(k + "\0")
PY
)
  count=$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$dir/index.json")
  [[ "$count" == "$i" ]] || die "boot snapshot: listed $count objects, copied $i"
  log "boot snapshot: $i object(s) in $dir"
}

# write_state RUN STATUS; PIDs come from UP_*, the rest from STATE_* env.
write_state() {
  RUN=$1 STATUS=$2 SCHEMA=$STATE_SCHEMA \
    PG_PID=$UP_PG_PID PG_START=$UP_PG_START MINIO_PID=$UP_MINIO_PID MINIO_START=$UP_MINIO_START \
    NODE_PID=$UP_NODE_PID NODE_START=$UP_NODE_START \
    BIN_DIR=$BIN_DIR MINIO_RELEASE=$MINIO_RELEASE MC_RELEASE=$MC_RELEASE \
    BUCKET=$BUCKET REGION=$REGION PG_USER=$PG_USER PG_DB=$PG_DB \
    AT_REST_MODE_VAR=$AT_REST_MODE_VAR AT_REST_ESCROW_NONE_VAR=$AT_REST_ESCROW_NONE_VAR python3 - <<'PY'
import json, os, datetime
e = os.environ
run = e["RUN"]
def num(name):
    v = e.get(name, "")
    return int(v) if v else None
def text(name):
    return e.get(name) or None
pg_bin = text("STATE_PG_BIN")
node_port = num("STATE_NODE_PORT")
minio_port = num("STATE_MINIO_PORT")
state = {
    "schema": e["SCHEMA"],
    "status": e["STATUS"],
    "run_dir": run,
    "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "env_file": os.path.join(run, "harness.env"),
    "at_rest": {
        "mode": text("STATE_AT_REST_MODE"),
        "escrow_none": {"true": True, "false": False}.get(e.get("STATE_AT_REST_ESCROW_NONE", "")),
        "mode_var": e["AT_REST_MODE_VAR"],
        "escrow_none_var": e["AT_REST_ESCROW_NONE_VAR"],
    },
    "node": {
        "pid": num("NODE_PID"),
        "pid_start": num("NODE_START"),
        "port": node_port,
        "url": f"http://127.0.0.1:{node_port}" if node_port else None,
        "bin": text("STATE_NODE_BIN"),
        "data_dir": os.path.join(run, "node-data"),
        "log": os.path.join(run, "logs", "node.log"),
        "keys": "Static (per-run, secrets/node-static-secret)",
        "sql_memory_threshold": 0,
    },
    "postgres": {
        "pid": num("PG_PID"),
        "pid_start": num("PG_START"),
        "port": num("STATE_PG_PORT"),
        "bin_dir": pg_bin,
        "data_dir": os.path.join(run, "pgdata"),
        "user": e["PG_USER"],
        "database": e["PG_DB"],
        "log": os.path.join(run, "logs", "postgres.log"),
    },
    "minio": {
        "pid": num("MINIO_PID"),
        "pid_start": num("MINIO_START"),
        "port": minio_port,
        "console_port": num("STATE_CONSOLE_PORT"),
        "endpoint": f"http://127.0.0.1:{minio_port}" if minio_port else None,
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

# ------------------------------------------------------------ state file ---

# The explicit STATE argument (state.json or its run dir), checked.
resolve_state() {
  local target=${1:-}
  [[ -n "$target" ]] || die "STATE is required: pass the state.json path \`up\` printed (no default; refusing to guess)"
  [[ -d "$target" ]] && target=$target/state.json
  [[ -f "$target" ]] || die "no harness state at $target"
  target=$(readlink -f "$target")
  [[ "$(state_get "$target" schema)" == "$STATE_SCHEMA" ]] || die "$target is not a $STATE_SCHEMA state file"
  [[ "$(state_get "$target" run_dir)" == "$(dirname "$target")" ]] || die "$target does not live in its recorded run dir"
  printf '%s\n' "$target"
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

# ------------------------------------------------------------------- down ---

cmd_down() {
  local purge=0 target=""
  for arg in "$@"; do
    case $arg in
      --purge) purge=1 ;;
      -*) die "down: unknown option $arg" ;;
      *) [[ -z "$target" ]] || die "down: one STATE only"; target=$arg ;;
    esac
  done
  local state run survivors=0
  state=$(resolve_state "$target")
  run=$(state_get "$state" run_dir)
  stop_recorded tinycloud-node "$(state_get "$state" node.pid)" "$(state_get "$state" node.pid_start)" || survivors=1
  stop_recorded minio "$(state_get "$state" minio.pid)" "$(state_get "$state" minio.pid_start)" || survivors=1
  stop_postgres "$run" "$(state_get "$state" postgres.pid)" "$(state_get "$state" postgres.pid_start)" \
    "$(state_get "$state" postgres.bin_dir)" || survivors=1
  if ((purge)); then
    ((survivors == 0)) || die "not purging $run: a recorded process is still running"
    [[ "$(basename "$run")" == harness-run-* ]] || die "not purging $run: not a harness-run-* dir"
    rm -rf -- "$run"
    log "removed $run"
  elif ((survivors == 0)); then
    python3 - "$state" <<'PY'
import json, os, sys
path = sys.argv[1]
state = json.load(open(path))
state["status"] = "down"
with open(path + ".tmp", "w") as f:
    json.dump(state, f, indent=2)
    f.write("\n")
os.replace(path + ".tmp", path)
PY
  fi
  return "$survivors"
}

# ------------------------------------------------------------------- test ---

annotate() {
  local level=$1
  shift
  if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
    printf '::%s::%s\n' "$level" "$*"
  fi
  log "$*"
}

# The harness test for each check, per kind, and the finding its RED test
# prints when the stored bytes are plaintext.
test_name() {
  case $1-$2 in
    green-kv) echo green_kv_put_reaches_minio ;;
    green-sql) echo green_sql_write_reaches_postgres ;;
    red-kv) echo red_kv_blocks_are_sealed_in_minio ;;
    red-sql) echo red_sql_artifacts_are_sealed_in_postgres ;;
  esac
}
red_finding() {
  case $1 in
    kv) echo 'TC-887 RED: KV data is not sealed at rest' ;;
    sql) echo 'TC-887 RED: SQL artifacts are not sealed at rest' ;;
  esac
}

# Default expectation of CHECK for KIND on the harness at STATE.
default_expect() {
  local kind=$1 check=$2 state=$3
  [[ "$kind" == green ]] && { echo green; return; }
  case $(state_get "$state" at_rest.mode) in
    # S3 seals KV before S4 seals SQL; flip sql to green when S4 lands.
    encrypt|strict) [[ "$check" == kv ]] && echo green || echo red ;;
    *) echo red ;;
  esac
}

# Run one check alone; sets CHECK_OUTCOME (green|red|errored) and CHECK_DETAIL.
run_check() {
  local kind=$1 check=$2 state=$3 name out status=0 passed failed
  name=$(test_name "$kind" "$check")
  out=$(mktemp)
  (cd "$ROOT" && TC887_HARNESS_STATE=$state nice -n 10 cargo test -p tinycloud-node \
    -j "${TC887_CARGO_JOBS:-8}" --test at_rest_harness -- --ignored --nocapture --exact "$name") \
    2>&1 | tee "$out" || status=$?
  read -r passed failed < <(grep -Eo 'test result: [A-Za-z]+\. [0-9]+ passed; [0-9]+ failed' "$out" \
    | awk '{p += $4; f += $6} END {print p + 0, f + 0}')
  CHECK_DETAIL="cargo exit $status"
  # libtest exits 0 when a filter matches nothing; never let that pass (TC-381).
  if ((passed + failed != 1)); then
    CHECK_OUTCOME=errored
    CHECK_DETAIL="expected 1 test ($name) to run, $((passed + failed)) ran; $CHECK_DETAIL (compile or harness failure)"
  elif ((passed == 1 && status == 0)); then
    CHECK_OUTCOME=green
  elif [[ "$kind" == red ]] && grep -qF "$(red_finding "$check")" "$out"; then
    CHECK_OUTCOME=red
  else
    CHECK_OUTCOME=errored
    CHECK_DETAIL="$name failed without a TC-887 RED finding (harness, precondition or node error; see output above)"
  fi
  rm -f "$out"
}

cmd_test() {
  local kind="" expect="" target=""
  while (($#)); do
    case $1 in
      green|red) [[ -z "$kind" ]] || die "test: one kind only"; kind=$1 ;;
      --expect) (($# >= 2)) || die "--expect needs a value"; shift; expect=$1 ;;
      --expect=*) expect=${1#--expect=} ;;
      -*) die "test: unknown option $1" ;;
      *) [[ -z "$target" ]] || die "test: one STATE only"; target=$1 ;;
    esac
    shift
  done
  [[ -n "$kind" ]] || die "usage: harness.sh test green|red [--expect EXPECT] STATE"
  local state
  state=$(resolve_state "$target")
  [[ "$(state_get "$state" status)" == up ]] || die "harness at $state is not up"

  local -A want=([kv]=$(default_expect "$kind" kv "$state") [sql]=$(default_expect "$kind" sql "$state"))
  local item key value items=()
  case $expect in
    "") ;;
    green|red) want[kv]=$expect want[sql]=$expect ;;
    *)
      IFS=, read -ra items <<<"$expect"
      for item in "${items[@]}"; do
        key=${item%%=*} value=${item#*=}
        [[ "$item" == *=* && ( "$key" == kv || "$key" == sql ) && ( "$value" == green || "$value" == red ) ]] \
          || die "--expect must be green, red, or kv=green|red,sql=green|red (got '$item')"
        want[$key]=$value
      done
      ;;
  esac

  local check rc=0 CHECK_OUTCOME CHECK_DETAIL label
  for check in kv sql; do
    run_check "$kind" "$check" "$state"
    label=$(tr '[:lower:]' '[:upper:]' <<<"$check")
    if [[ "$CHECK_OUTCOME" == errored ]]; then
      annotate error "$label $kind check ERRORED: $CHECK_DETAIL"
      rc=4
    elif [[ "$CHECK_OUTCOME" == "${want[$check]}" ]]; then
      if [[ "$CHECK_OUTCOME" == red ]]; then
        annotate notice "$label RED as expected: $label data is plaintext at rest"
      else
        annotate notice "$label $kind check GREEN as expected"
      fi
    elif [[ "$CHECK_OUTCOME" == green ]]; then
      annotate error "$label $kind check UNEXPECTEDLY PASSED under expect $check=red: the at-rest property holds for $label; expect $check=green and update CI"
      ((rc == 4)) || rc=3
    else
      annotate error "$label $kind check still RED ($label data is plaintext at rest) but expected $check=green"
      ((rc == 4)) || rc=3
    fi
  done
  if ((rc == 0)); then
    if [[ "$kind" == red && "${want[kv]}" == red && "${want[sql]}" == red ]]; then
      annotate notice "RED as expected: both TC-887 RED checks report plaintext at rest (KV and SQL)"
    else
      annotate notice "$kind checks as expected (kv=${want[kv]}, sql=${want[sql]})"
    fi
  fi
  return "$rc"
}

cmd_status() {
  local state
  state=$(resolve_state "${1:-}")
  cat "$state"
}

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
  *) die "usage: harness.sh bins | up [--no-build] | test green|red [--expect EXPECT] STATE | status STATE | logs STATE | down [--purge] STATE" ;;
esac

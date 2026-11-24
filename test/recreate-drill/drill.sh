#!/usr/bin/env bash
# TC-1491 P4.2b part 1: the container-recreate drill (design doc section 12).
#
#   drill.sh today    the production layout as it is: SQL datadir in the
#                     container's writable layer, Postgres the master copy
#   drill.sh volume   the same with /data/sql on a named volume
#   drill.sh all      both, in that order
#
# Each layout: write acknowledged rows, then (1) recreate the container,
# (2) SIGKILL it and start the same container again, (3) SIGKILL it and
# recreate it, and after every step read back every acknowledged row.
# Needs Docker with compose v2, the node image in DRILL_NODE_IMAGE, node 20+
# with `npm ci` already run in this directory. See README.md.
#
# Run only on an isolated CI runner, not a shared Docker host: it creates and
# removes containers and volumes under its own project name.
set -euo pipefail
umask 077

here="$(cd "$(dirname "$0")" && pwd)"
if [[ "${CI:-}" != true && "${DRILL_ALLOW_LOCAL:-}" != 1 ]]; then
  printf '%s\n' 'Refusing to run: set CI=true on an isolated runner, or DRILL_ALLOW_LOCAL=1 on a Docker host you own.' >&2
  exit 1
fi
: "${DRILL_NODE_IMAGE:?build the node image and set DRILL_NODE_IMAGE}"
layouts="${1:-all}"
case "$layouts" in today | volume | all) ;; *) printf 'usage: %s today|volume|all\n' "$0" >&2; exit 1 ;; esac

port="${DRILL_PORT:-18000}"
export DRILL_PORT="$port"
export DRILL_HOST="http://127.0.0.1:$port"
work="$(mktemp -d)"
export DRILL_KEY_FILE="$work/drill.key"
openssl rand -hex 32 >"$DRILL_KEY_FILE"
# Per-run throwaway secrets for the node's static key and the drill's Postgres.
# The node reads the static secret as URL-safe base64 without padding.
DRILL_KEYS_SECRET="$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')"
DRILL_PG_PASSWORD="$(openssl rand -hex 16)"
export DRILL_KEYS_SECRET DRILL_PG_PASSWORD
summary="${DRILL_SUMMARY:-$work/summary.txt}"
: >"$summary"
project="tcdrill$$"
export DRILL_SQL_VOLUME="${project}-sql-data"
volume_made=0
writer_pid=""
failures=0

dc() {
  if [[ "$layout" == volume ]]; then
    docker compose -p "$project" -f "$here/compose.yaml" -f "$here/compose.volume.yaml" "$@"
  else
    docker compose -p "$project" -f "$here/compose.yaml" "$@"
  fi
}
drill() { (cd "$here" && npx --no-install tsx drill.ts "$@"); }
say() { printf '%s\n' "$*" | tee -a "$summary"; }
fail() { say "FAIL: $*"; failures=$((failures + 1)); }

cleanup() {
  [[ -n "$writer_pid" ]] && kill "$writer_pid" 2>/dev/null || true
  layout=today dc down -v --remove-orphans >/dev/null 2>&1 || true
  layout=volume dc down -v --remove-orphans >/dev/null 2>&1 || true
  if [[ "$volume_made" == 1 ]]; then docker volume rm -f "$DRILL_SQL_VOLUME" >/dev/null 2>&1 || true; fi
  # The summary is the artifact; keep it, drop the key and ledgers.
  rm -f "$DRILL_KEY_FILE" "$work"/ledger-*
}
trap cleanup EXIT

wait_ready() {
  local i
  for ((i = 0; i < 120; i++)); do
    if curl -fsS "$DRILL_HOST/healthz" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  dc logs --no-color --tail 40 tinycloud >&2 || true
  fail "the node did not become healthy in 120 s"
  return 1
}

# Files under /data/sql in the node container, counted from the host with
# `docker cp` (the image is FROM scratch: no shell to exec). 0 when the path
# does not exist.
sql_files() {
  local id
  id="$(dc ps -aq tinycloud)"
  docker cp "$id:/data/sql" - 2>/dev/null | tar -t 2>/dev/null | grep -vc '/$' || true
}

acked() { grep -c '"state":"ack"' "$1" || true; }

# verify <label>: every acknowledged row is read back.
verify() {
  local out
  if out="$(drill verify "$ledger" 2>&1)"; then
    say "ok   [$layout] $1: $out"
  else
    fail "[$layout] $1: $out"
  fi
}

# expect_files <label> <survives: yes|no>: checked after the node is back but
# BEFORE any SQL request, so a surviving file cannot be a re-hydrated one.
expect_files() {
  local n
  n="$(sql_files)"
  say "info [$layout] $1: $n file(s) under /data/sql before the first request"
  if [[ "$2" == yes && "$n" -lt 1 ]]; then
    fail "[$layout] $1: the SQL working copy did not survive"
  elif [[ "$2" == no && "$n" -gt 0 ]]; then
    fail "[$layout] $1: the working copy survived a recreate on the layout that has no volume (the claim in section 14 is wrong; re-read it)"
  fi
}

# kill_during_writes <label>: a writer runs until the node stops answering.
kill_during_writes() {
  local before want i
  before="$(acked "$ledger")"
  want=$((before + 15))
  drill write "$ledger" 5000 --until-failure >"$work/writer.log" 2>&1 &
  writer_pid=$!
  for ((i = 0; i < 120; i++)); do
    [[ "$(acked "$ledger")" -ge "$want" ]] && break
    sleep 0.5
  done
  if [[ "$(acked "$ledger")" -lt "$want" ]]; then
    fail "[$layout] $1: the writer made no progress before the kill"
  fi
  dc kill -s SIGKILL tinycloud >/dev/null
  local code=0
  wait "$writer_pid" || code=$?
  writer_pid=""
  # 0: the writer saw the node fail (expected). 2: it never did. 1: it broke.
  [[ "$code" == 0 ]] || fail "[$layout] $1: the writer exited $code ($(tail -n 1 "$work/writer.log"))"
  say "info [$layout] $1: killed with SIGKILL after $(($(acked "$ledger") - before)) more acknowledged rows"
}

run_layout() {
  layout="$1"
  ledger="$work/ledger-$layout"
  local survives=no
  say "== layout: $layout"
  if [[ "$layout" == volume ]]; then
    survives=yes
    docker volume create "$DRILL_SQL_VOLUME" >/dev/null
    volume_made=1
    # What the image's own mkdir+chown will do (see compose.volume.yaml).
    docker run --rm -v "$DRILL_SQL_VOLUME:/d" busybox:1.36 chown 1000:1000 /d
  fi
  dc up -d
  wait_ready || return 0

  drill write "$ledger" 30 || fail "[$layout] initial writes failed"
  expect_files "before any restart" yes
  verify "baseline"

  # 1. Graceful recreate: the deploy.
  dc up -d --force-recreate --no-deps tinycloud
  wait_ready || return 0
  expect_files "after a recreate" "$survives"
  verify "after a recreate"
  drill write "$ledger" 10 || fail "[$layout] writes after the recreate failed"

  # 2. SIGKILL, same container started again (OOM kill, crash: the writable
  # layer survives a restart).
  kill_during_writes "kill, restart"
  dc start tinycloud
  wait_ready || return 0
  expect_files "after a kill and restart" yes
  verify "after a kill and restart"

  # 3. SIGKILL, then a recreate (a crash during a deploy).
  kill_during_writes "kill, recreate"
  dc up -d --force-recreate --no-deps tinycloud
  wait_ready || return 0
  expect_files "after a kill and recreate" "$survives"
  verify "after a kill and recreate"
  drill write "$ledger" 5 || fail "[$layout] writes after the last recreate failed"
  verify "final"

  dc down -v --remove-orphans >/dev/null
  if [[ "$volume_made" == 1 ]]; then
    docker volume rm -f "$DRILL_SQL_VOLUME" >/dev/null
    volume_made=0
  fi
}

layout=today
if [[ "$layouts" == today || "$layouts" == all ]]; then run_layout today; fi
if [[ "$layouts" == volume || "$layouts" == all ]]; then run_layout volume; fi

if [[ "$failures" -gt 0 ]]; then
  say "DRILL FAILED: $failures check(s)"
  exit 1
fi
say 'DRILL PASSED'

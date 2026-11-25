#!/usr/bin/env bash
# TC-1491 P4.2b: tests drill.sh's own logic with a fake `docker`, `curl` and
# `npx` on PATH. No Docker, no network, no node. It proves the script runs its
# steps in order, passes on a healthy run, and FAILS when the data is lost, when
# the volume does not keep the working copy, and when the no-volume layout keeps
# it (the claim in design doc section 14). It does not test Docker or the node:
# the real drill does.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bin="$tmp/bin"
mkdir -p "$bin"

# Fake world, kept in files: FAKE/db holds the "Postgres" rows (they survive
# everything), FAKE/cache is the container's /data/sql (wiped by a recreate on
# the layout without a volume), FAKE/killed is set by `compose kill`.
cat >"$bin/docker" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: "${FAKE:?}"
log() { printf '%s\n' "$*" >>"$FAKE/calls"; }
case "$1" in
  volume | run) log "$1 $2"; exit 0 ;;
  cp)
    [[ -d "$FAKE/cache" && -n "$(ls -A "$FAKE/cache")" ]] || exit 1
    tar -C "$FAKE" -cf - --transform 's#^cache#sql#' cache
    exit 0 ;;
  compose)
    volume=0; args=()
    for a in "$@"; do
      [[ "$a" == *compose.volume.yaml ]] && volume=1
      args+=("$a")
    done
    # Which layout is this? `drill.sh` adds compose.files.yaml for the layouts
    # whose database is a file.
    if printf '%s\n' "${args[@]}" | grep -q 'compose\.files\.yaml$'; then : >"$FAKE/filebacked"; else rm -f "$FAKE/filebacked"; fi
    for i in "${!args[@]}"; do
      case "${args[$i]}" in
        up)
          if printf '%s\n' "${args[@]}" | grep -qx -- '--force-recreate'; then
            log "recreate volume=$volume"
            if [[ "$volume" == 0 && "${FAKE_PERSIST_TODAY:-}" != 1 ]] || [[ "$volume" == 1 && "${FAKE_VOLUME_WIPES:-}" == 1 ]]; then
              rm -rf "$FAKE/cache"; mkdir -p "$FAKE/cache"
            fi
          else
            log "up"
          fi
          rm -f "$FAKE/killed"; exit 0 ;;
        kill) log "kill"; : >"$FAKE/killed"; exit 0 ;;
        start) log "start"; rm -f "$FAKE/killed"; exit 0 ;;
        ps) echo fakecontainer; exit 0 ;;
        down | logs) log "${args[$i]}"; exit 0 ;;
      esac
    done
    exit 0 ;;
esac
exit 0
EOF
cat >"$bin/curl" <<'EOF'
#!/usr/bin/env bash
[[ ! -e "${FAKE:?}/killed" ]]
EOF
# npx --no-install tsx drill.ts <mode> <ledger> ...
cat >"$bin/npx" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
: "${FAKE:?}"
shift 3 # --no-install tsx drill.ts
mode="$1" ledger="$2"
db="$FAKE/db"; touch "$db"
case "$mode" in
  write)
    count="$3"; until_failure="${4:-}"
    [[ -f "$ledger" ]] || printf '{"run":"fake"}\n' >"$ledger"
    # The node's database is a file only on the file-backed layouts (default
    # config: in memory, no file). FAKE_FILE_LATE: the actor promotes it a moment
    # after the write returns.
    if [[ ( -e "$FAKE/filebacked" || "${FAKE_TODAY_FILE:-}" == 1 ) && "${FAKE_NO_FILES:-}" != 1 ]]; then
      if [[ "${FAKE_FILE_LATE:-}" == 1 && ! -e "$FAKE/cache/main.db" ]]; then
        (sleep 1; mkdir -p "$FAKE/cache"; echo data >"$FAKE/cache/main.db") >/dev/null 2>&1 &
      else
        mkdir -p "$FAKE/cache"; echo data >"$FAKE/cache/main.db"
        # FAKE_DID_NAMES: the node's real file names start with the space's DID
        # (`<did>:<space name>/v2<hash>.db`); the drill must never print it.
        if [[ "${FAKE_DID_NAMES:-}" == 1 ]]; then
          rm -f "$FAKE/cache/main.db"
          d="$FAKE/cache/tinycloud:pkh:eip155:1:0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:account"
          mkdir -p "$d"; echo data >"$d/v2abc.db"; echo data >"$d/v2abc.db-wal"
        fi
      fi
    fi
    id="$(grep -o '"id":[0-9]*' "$ledger" | cut -d: -f2 | sort -n | tail -n 1 || true)"
    id=$(( ${id:-0} + 1 ))
    for ((n = 0; n < count; n++, id++)); do
      if [[ -e "$FAKE/killed" ]]; then
        printf '{"id":%d,"value":"fake-%d","state":"intent"}\n' "$id" "$id" >>"$ledger"
        [[ -n "$until_failure" ]] && exit 0 || exit 1
      fi
      printf '{"id":%d,"value":"fake-%d","state":"intent"}\n' "$id" "$id" >>"$ledger"
      echo "$id" >>"$db"
      printf '{"id":%d,"value":"fake-%d","state":"ack"}\n' "$id" "$id" >>"$ledger"
      [[ -n "$until_failure" ]] && sleep 0.05
    done
    [[ -n "$until_failure" ]] && exit 2 || exit 0 ;;
  verify)
    [[ "${FAKE_LOSE:-}" == 1 ]] && sed -i '$ d' "$db"
    missing=0
    while read -r id; do grep -qx "$id" "$db" || missing=$((missing + 1)); done \
      < <(grep '"state":"ack"' "$ledger" | grep -o '"id":[0-9]*' | cut -d: -f2)
    echo "verify missing=$missing"
    [[ "$missing" == 0 ]] ;;
esac
EOF
chmod +x "$bin"/*

# run_case <name> <expected exit: 0|1> <expected text in summary> [VAR=1 ...]
run_case() {
  local name="$1" want="$2" text="$3" got=0
  shift 3
  export FAKE="$tmp/$name"
  mkdir -p "$FAKE/cache"
  : >"$FAKE/calls"
  env DRILL_FILE_WAIT=0 "$@" PATH="$bin:$PATH" CI=true DRILL_NODE_IMAGE=fake DRILL_SUMMARY="$FAKE/summary" \
    bash "$here/drill.sh" all >"$FAKE/out" 2>&1 || got=$?
  if [[ "$got" != "$want" ]]; then
    printf 'case %s: exit %s, wanted %s\n' "$name" "$got" "$want" >&2
    cat "$FAKE/out" >&2
    exit 1
  fi
  if ! grep -q -- "$text" "$FAKE/summary"; then
    printf 'case %s: summary lacks "%s"\n' "$name" "$text" >&2
    cat "$FAKE/summary" >&2
    exit 1
  fi
  printf 'ok  %s\n' "$name"
  if [[ -n "${SHOW_SUMMARY:-}" ]]; then sed 's/^/      /' "$FAKE/summary"; fi
}

run_case healthy 0 'DRILL PASSED'
# The steps ran in the documented order, three recreates and two kills per layout.
test "$(grep -c '^recreate volume=0' "$tmp/healthy/calls")" == 4 ||
  { echo 'expected 4 recreates on the two layouts without a volume' >&2; exit 1; }
test "$(grep -c '^recreate volume=1' "$tmp/healthy/calls")" == 2 ||
  { echo 'expected 2 recreates on the volume layout' >&2; exit 1; }
test "$(grep -c '^kill' "$tmp/healthy/calls")" == 6 ||
  { echo 'expected 6 kills' >&2; exit 1; }
# today: a small database is in memory, no file until a restart re-hydrates it.
grep -q 'info \[today\] before any restart: 0 file' "$tmp/healthy/summary"
grep -q 'info \[files\] before any restart: 1 file' "$tmp/healthy/summary"
grep -q 'info \[files\] after a recreate: 0 file' "$tmp/healthy/summary"
grep -q 'info \[volume\] after a recreate: 1 file' "$tmp/healthy/summary"
# The names are printed next to the count (relative to /data/sql), and an empty
# directory prints none: the count can then be explained from the log itself.
grep -q 'info \[files\] before any restart: files: main\.db *$' "$tmp/healthy/summary"
grep -q 'info \[volume\] after a recreate: files: main\.db *$' "$tmp/healthy/summary"
grep -q 'info \[today\] before any restart: files: *$' "$tmp/healthy/summary"
grep -q 'info \[files\] after a recreate: files: *$' "$tmp/healthy/summary"
grep -q 'ok   \[volume\] final' "$tmp/healthy/summary"

run_case acknowledged-write-lost 1 'DRILL FAILED' FAKE_LOSE=1
run_case volume-loses-the-working-copy 1 'the SQL working copy did not survive' FAKE_VOLUME_WIPES=1
run_case no-volume-keeps-the-working-copy 1 'the claim in section 14 is wrong' FAKE_PERSIST_TODAY=1
# The first real run (45501421888) found that a small database has no file at
# all under the default memory_threshold: these two cases pin both sides.
run_case small-database-gets-a-file 1 'a small database has a local file' FAKE_TODAY_FILE=1
run_case file-backed-layout-never-gets-a-file 1 'no SQL working copy was created' FAKE_NO_FILES=1
run_case file-appearing-a-moment-late-is-waited-for 0 'DRILL PASSED' FAKE_FILE_LATE=1 DRILL_FILE_WAIT=5
# A file name that starts with a DID (as the node's real ones do) is printed
# without it: neither the summary nor the output carries a did:pkh or an 0x
# address, and the logical name and its -wal sidecar are still listed.
run_case did-prefixed-names-are-printed-without-the-did 0 'DRILL PASSED' FAKE_DID_NAMES=1
grep -q 'info \[files\] before any restart: files: account/v2abc\.db account/v2abc\.db-wal *$' "$tmp/did-prefixed-names-are-printed-without-the-did/summary"
if grep -q 'pkh\|0x[0-9A-Fa-f]\|eip155' "$tmp/did-prefixed-names-are-printed-without-the-did/summary" "$tmp/did-prefixed-names-are-printed-without-the-did/out"; then
  echo 'a DID-shaped name was echoed' >&2
  exit 1
fi
printf 'ok  a DID in a file name is never echoed\n'

# The guards.
if CI='' bash "$here/drill.sh" today >/dev/null 2>&1; then
  echo 'drill.sh ran without CI=true or DRILL_ALLOW_LOCAL=1' >&2
  exit 1
fi
printf 'ok  refuses to run outside CI\n'

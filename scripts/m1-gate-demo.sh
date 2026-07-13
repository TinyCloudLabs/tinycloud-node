#!/usr/bin/env bash
set -Eeuo pipefail

# This runner is intentionally an evidence recorder, never an evidence author.
# Every secret/random input and every production phase command comes from the PM.

die() { printf 'm1-gate-demo: %s\n' "$*" >&2; exit 2; }
need() { [[ -n "${!1:-}" ]] || die "required environment variable $1 is unset"; }
sha256() { shasum -a 256 "$1" | awk '{print $1}'; }
now() { python3 -c 'from datetime import datetime, timezone; print(datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"))'; }
json_string() { python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "$1"; }
run_capture() {
  local phase=$1 command=$2 output=$3
  mkdir -p "$(dirname "$output")"
  printf '%s\n' "$command" >"$output.command"
  ( export M1_PHASE="$phase"; bash -o pipefail -c "$command" ) \
    > >(tee "$output.stdout") 2> >(tee "$output.stderr" >&2)
}
start_capture() {
  local phase=$1 command=$2 prefix=$3
  mkdir -p "$(dirname "$prefix")"
  printf '%s\n' "$command" >"$prefix.command"
  ( export M1_PHASE="$phase"; exec bash -c "$command" ) \
    > >(tee "$prefix.stdout") 2> >(tee "$prefix.stderr" >&2) &
  LAST_PID=$!
  printf '%s\n' "$LAST_PID" >"$prefix.pid"
}
stop_pid() {
  local pid=${1:-}
  [[ -n "$pid" ]] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in {1..50}; do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}

for name in \
  M1_RUN_NONCE_FILE M1_RENEWAL_NONCE_FILE M1_REVOKED_NONCE_FILE \
  M1_SQL_SEED_FILE M1_OWNER_PRIVATE_KEY_FILE \
  M1_HOLDER_PRIVATE_KEY_FILE M1_NODE_REPO M1_POLICY_ENGINE_REPO M1_SDK_REPO \
  M1_LISTEN_REPO M1_OPEN_CREDENTIALS_REPO M1_NODE_DB \
  M1_PINNED_ARTIFACTS_FILE \
  M1_NODE_CMD M1_NODE_READY_CMD M1_SEED_CMD M1_DRIVER_PUBLISH_CMD \
  M1_SIDECAR_CMD M1_SIDECAR_READY_CMD M1_REQUEST_INITIAL_CMD \
  M1_REQUEST_RENEW_CMD M1_DRIVER_REVOKE_CMD M1_REQUEST_DENIED_CMD \
  M1_WAIT_EXPIRY_CMD M1_POST_EXPIRY_READ_CMD; do need "$name"; done

for file in "$M1_RUN_NONCE_FILE" "$M1_RENEWAL_NONCE_FILE" "$M1_REVOKED_NONCE_FILE" \
  "$M1_SQL_SEED_FILE" "$M1_OWNER_PRIVATE_KEY_FILE" \
  "$M1_HOLDER_PRIVATE_KEY_FILE"; do [[ -s "$file" ]] || die "input file is missing/empty: $file"; done
[[ -s "$M1_PINNED_ARTIFACTS_FILE" ]] || die "pinned artifact list is missing/empty"

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
BUNDLE=${1:-}
[[ -n "$BUNDLE" ]] || die "usage: scripts/m1-gate-demo.sh RAW_BUNDLE_DIRECTORY"
[[ ! -e "$BUNDLE" ]] || die "bundle path already exists: $BUNDLE"
mkdir -p "$BUNDLE"/{meta,node,driver,sidecar,requester,node-db}
BUNDLE=$(cd "$BUNDLE" && pwd)
RUN_ID=${M1_RUN_ID:-$(basename "$BUNDLE")}
[[ -n "$RUN_ID" ]] || die "run id is empty"

export M1_BUNDLE="$BUNDLE" M1_RUN_ID="$RUN_ID"
printf '%s\n' "$$" >"$BUNDLE/meta/runner.pid"
ps -p "$$" -o command= >"$BUNDLE/meta/runner.actual-command"
export M1_RUN_NONCE_FILE M1_RENEWAL_NONCE_FILE M1_REVOKED_NONCE_FILE
export M1_SQL_SEED_FILE M1_OWNER_PRIVATE_KEY_FILE M1_HOLDER_PRIVATE_KEY_FILE

NODE_PID= SIDECAR_PID=
NODE_STARTED_PID= SIDECAR_INITIAL_PID= SIDECAR_REDEPLOYED_PID=
cleanup() {
  local rc=$?
  stop_pid "$SIDECAR_PID"
  stop_pid "$NODE_PID"
  { printf '{"runId":%s,"observedAt":%s,"runnerExit":%s,"nodeAlive":false,"sidecarAlive":false}\n' \
      "$(json_string "$RUN_ID")" "$(json_string "$(now)")" "$rc"; } >"$BUNDLE/meta/teardown.json"
}
trap cleanup EXIT INT TERM

repo_meta() {
  local label=$1 repo=$2
  git -C "$repo" rev-parse HEAD >"$BUNDLE/meta/$label.sha"
  git -C "$repo" status --porcelain=v1 >"$BUNDLE/meta/$label.dirty"
}
repo_meta tinycloud-node "$M1_NODE_REPO"
repo_meta policy-engine "$M1_POLICY_ENGINE_REPO"
repo_meta js-sdk "$M1_SDK_REPO"
repo_meta listen "$M1_LISTEN_REPO"
repo_meta open-credentials "$M1_OPEN_CREDENTIALS_REPO"
while IFS= read -r artifact; do
  [[ -n "$artifact" ]] || continue
  [[ -f "$artifact" ]] || die "pinned artifact is not a file: $artifact"
  shasum -a 256 "$artifact"
done <"$M1_PINNED_ARTIFACTS_FILE" >"$BUNDLE/meta/artifacts.sha256"
[[ -s "$BUNDLE/meta/artifacts.sha256" ]] || die "no pinned artifact hashes captured"

NODE_SHA=$(<"$BUNDLE/meta/tinycloud-node.sha")
POLICY_SHA=$(<"$BUNDLE/meta/policy-engine.sha")
SDK_SHA=$(<"$BUNDLE/meta/js-sdk.sha")
LISTEN_SHA=$(<"$BUNDLE/meta/listen.sha")
OC_SHA=$(<"$BUNDLE/meta/open-credentials.sha")
need M1_EXPECTED_NODE_SHA
# The node pin is env-supplied: the gate script lives in this repo, so a
# hardcoded self-SHA would be stale the moment the script itself merges.
[[ $NODE_SHA == "$M1_EXPECTED_NODE_SHA"* && $POLICY_SHA == d72812a* && $SDK_SHA == 2949408* && \
   $LISTEN_SHA == 7bbd99a* && $OC_SHA == a1633710* ]] || die "candidate SHA mismatch"
for dirty in "$BUNDLE"/meta/*.dirty; do [[ ! -s "$dirty" ]] || die "candidate checkout is dirty: $dirty"; done

cat >"$BUNDLE/manifest.json" <<JSON
{"schema":"xyz.tinycloud.m1/live-gate-raw-bundle/v1","runId":$(json_string "$RUN_ID"),"createdAt":$(json_string "$(now)"),"inputs":{"nonceSha256":"$(sha256 "$M1_RUN_NONCE_FILE")","renewalNonceSha256":"$(sha256 "$M1_RENEWAL_NONCE_FILE")","revokedNonceSha256":"$(sha256 "$M1_REVOKED_NONCE_FILE")","sqlSeedSha256":"$(sha256 "$M1_SQL_SEED_FILE")"},"candidates":{"tinycloudNode":"$NODE_SHA","policyEngine":"$POLICY_SHA","jsSdk":"$SDK_SHA","listen":"$LISTEN_SHA","openCredentials":"$OC_SHA"}}
JSON

# B: real node, dynamic-port command supplied by PM, real owner seed.
start_capture B "$M1_NODE_CMD" "$BUNDLE/node/process"
NODE_PID=$LAST_PID; export M1_NODE_PID=$NODE_PID
NODE_STARTED_PID=$NODE_PID
run_capture B-ready "$M1_NODE_READY_CMD" "$BUNDLE/node/ready"
[[ -s "$BUNDLE/node/port" ]] || die "node command did not write dynamic port to M1_BUNDLE/node/port"
ps -p "$NODE_PID" -o command= >"$BUNDLE/node/process.actual-command"
run_capture B-seed "$M1_SEED_CMD" "$BUNDLE/node/seed"

# C: production Listen publisher and delegation-path origin pre/post snapshots.
run_capture C-pre-import "$ROOT/test/m1-realdata-e2e/scripts/snapshot-node-db.sh '$M1_NODE_DB' '$RUN_ID' '$BUNDLE/node-db/pre-import.json'" "$BUNDLE/node-db/pre-import-capture"
run_capture C "$M1_DRIVER_PUBLISH_CMD" "$BUNDLE/driver/publish"

# D/E: startup-only authority load, real requester, exact resolve -> /delegate bytes.
start_capture D "$M1_SIDECAR_CMD" "$BUNDLE/sidecar/initial-process"
SIDECAR_PID=$LAST_PID; export M1_SIDECAR_PID=$SIDECAR_PID
SIDECAR_INITIAL_PID=$SIDECAR_PID
run_capture D-ready "$M1_SIDECAR_READY_CMD" "$BUNDLE/sidecar/initial-ready"
[[ -s "$BUNDLE/sidecar/port" ]] || die "sidecar command did not write dynamic port to M1_BUNDLE/sidecar/port"
cp "$BUNDLE/sidecar/port" "$BUNDLE/sidecar/initial-port"
ps -p "$SIDECAR_PID" -o command= >"$BUNDLE/sidecar/initial-process.actual-command"
run_capture E "$M1_REQUEST_INITIAL_CMD" "$BUNDLE/requester/initial"
run_capture E-post-import "$ROOT/test/m1-realdata-e2e/scripts/snapshot-node-db.sh '$M1_NODE_DB' '$RUN_ID' '$BUNDLE/node-db/post-import.json'" "$BUNDLE/node-db/post-import-capture"

# F: access-triggered renewal with the PM's second nonce.
run_capture F "$M1_REQUEST_RENEW_CMD" "$BUNDLE/requester/renewal"

# G: publish monotonic revoked status, replace (never refresh) the sidecar.
run_capture G-revoke "$M1_DRIVER_REVOKE_CMD" "$BUNDLE/driver/revoke"
stop_pid "$SIDECAR_PID"; SIDECAR_PID=
start_capture G-redeploy "$M1_SIDECAR_CMD" "$BUNDLE/sidecar/redeployed-process"
SIDECAR_PID=$LAST_PID; export M1_SIDECAR_PID=$SIDECAR_PID
SIDECAR_REDEPLOYED_PID=$SIDECAR_PID
run_capture G-ready "$M1_SIDECAR_READY_CMD" "$BUNDLE/sidecar/redeployed-ready"
[[ -s "$BUNDLE/sidecar/port" ]] || die "replacement sidecar did not write its dynamic port"
cp "$BUNDLE/sidecar/port" "$BUNDLE/sidecar/redeployed-port"
ps -p "$SIDECAR_PID" -o command= >"$BUNDLE/sidecar/redeployed-process.actual-command"
now >"$BUNDLE/sidecar/redeployed-ready.timestamp"

# H/I: wire denial from replacement sidecar, then native refusal after expiry.
run_capture H "$M1_REQUEST_DENIED_CMD" "$BUNDLE/requester/renewal-denied"
run_capture I-wait "$M1_WAIT_EXPIRY_CMD" "$BUNDLE/requester/expiry-wait"
run_capture I "$M1_POST_EXPIRY_READ_CMD" "$BUNDLE/requester/post-expiry-read"

# J: verifier is independent and consumes only the now-closed raw bundle.
stop_pid "$SIDECAR_PID"; SIDECAR_PID=
stop_pid "$NODE_PID"; NODE_PID=
for pid in "$NODE_STARTED_PID" "$SIDECAR_INITIAL_PID" "$SIDECAR_REDEPLOYED_PID"; do
  kill -0 "$pid" 2>/dev/null && die "owned process survived teardown: $pid"
done
for port_file in "$BUNDLE/node/port" "$BUNDLE/sidecar/initial-port" "$BUNDLE/sidecar/redeployed-port"; do
  python3 - "$(<"$port_file")" <<'PY'
import socket, sys
port = int(sys.argv[1])
sock = socket.socket()
sock.settimeout(0.2)
try:
    connected = sock.connect_ex(("127.0.0.1", port)) == 0
finally:
    sock.close()
raise SystemExit(1 if connected else 0)
PY
done
trap - EXIT INT TERM
printf '{"runId":%s,"observedAt":%s,"runnerExit":0,"allOwnedProcessesDead":true,"allDynamicPortsClosed":true}\n' \
  "$(json_string "$RUN_ID")" "$(json_string "$(now)")" >"$BUNDLE/meta/teardown.json"
cargo run --quiet --manifest-path "$ROOT/test/m1-realdata-e2e/Cargo.toml" \
  --bin m1-gate-verify -- "$BUNDLE" --self-test | tee "$BUNDLE/verifier-report.json"

#!/usr/bin/env bash
# TC-887 end-to-end check of a ledger-backup image on a disposable CI runner:
# MinIO stands in for R2, a Docker volume for `deletion-ledger`, and the image
# runs with the production compose service's flags. Then the restore drill
# decrypts what it uploaded into a scratch directory and checks it.
#
#   MINIO_BIN=<path to minio> ci-e2e.sh <image>
#
# Needs docker, age, age-keygen, jq and curl >= 8 on the runner. Every value
# here is synthetic; no deployment credential is read.
set -euo pipefail
umask 077

image=${1:?usage: ci-e2e.sh <image>}
: "${MINIO_BIN:?set MINIO_BIN to the minio binary}"
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
scratch=$(mktemp -d -p "${RUNNER_TEMP:-/var/tmp}")
run_id="ledger-e2e-$$-$RANDOM"
volume="$run_id"
minio_pid=
cleanup() {
  docker rm -f "$run_id-writer" "$run_id-backup" >/dev/null 2>&1 || true
  docker volume rm -f "$volume" >/dev/null 2>&1 || true
  [ -z "$minio_pid" ] || kill "$minio_pid" 2>/dev/null || true
  rm -rf "$scratch"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$*"; }
fail() { echo "ci-e2e: $*" >&2; exit 1; }

step "MinIO (region auto, as R2 signs) with a bucket named like production's"
export MINIO_ROOT_USER="e2e$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')"
export MINIO_ROOT_PASSWORD="$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')"
export MINIO_SITE_REGION=auto
port=$(( 20000 + RANDOM % 20000 ))
mkdir "$scratch/minio"
"$MINIO_BIN" server "$scratch/minio" --address "127.0.0.1:$port" --console-address "127.0.0.1:0" >"$scratch/minio.log" 2>&1 &
minio_pid=$!
endpoint="http://127.0.0.1:$port"
for _ in $(seq 100); do curl --silent --output /dev/null "$endpoint/minio/health/live" && break; sleep 0.2; done
curl --silent --fail --output /dev/null "$endpoint/minio/health/live" || fail "MinIO did not start"
export NODE_BACKUP_R2_ENDPOINT=$endpoint
export NODE_BACKUP_R2_BUCKET=tinycloud-node-backups
export NODE_BACKUP_R2_ACCESS_KEY_ID=$MINIO_ROOT_USER
export NODE_BACKUP_R2_SECRET_ACCESS_KEY=$MINIO_ROOT_PASSWORD
printf 'user = "%s:%s"\n' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" \
  | curl --config - --fail --silent --show-error --aws-sigv4 "aws:amz:auto:s3" -X PUT "$endpoint/$NODE_BACKUP_R2_BUCKET"

step "Operator identity (off-CVM in production) and its public recipient"
age-keygen -o "$scratch/identity.txt" 2>/dev/null
export NODE_BACKUP_AGE_RECIPIENT
NODE_BACKUP_AGE_RECIPIENT=$(age-keygen -y "$scratch/identity.txt")
export AGE_IDENTITY_FILE=$scratch/identity.txt

as_node() { # as_node <docker run args...> -- <sh script>; uid 1000 shell in the image on the ledger volume
  docker run --rm --user 1000:1000 --entrypoint sh -v "$volume:/var/lib/tinycloud/ledger" "$@"
}
backup_args=(--network host --init --user 1000:1000 --read-only --cap-drop ALL
  --security-opt no-new-privileges:true --memory 96m --memory-swap 96m --cpus 0.25
  --tmpfs /tmp:rw,noexec,nosuid,size=32m,uid=1000,gid=1000,mode=0700
  -v "$volume:/var/lib/tinycloud/ledger:ro"
  -e NODE_BACKUP_R2_ENDPOINT -e NODE_BACKUP_R2_BUCKET -e NODE_BACKUP_R2_ACCESS_KEY_ID
  -e NODE_BACKUP_R2_SECRET_ACCESS_KEY -e NODE_BACKUP_AGE_RECIPIENT -e BACKUP_ONCE=1 -e BACKUP_SETTLE_SECONDS=1)

step "A fresh deletion-ledger volume first mounted by the sidecar image stays writable by the node (uid 1000, 0700)"
docker volume create "$volume" >/dev/null
mode=$(as_node "$image" -c 'stat -c "%u:%g %a" /var/lib/tinycloud/ledger')
[ "$mode" = "1000:1000 700" ] || fail "fresh volume is $mode, not 1000:1000 700"
echo "volume: $mode"

step "A ledger in the node's format, mode 0600, ending in a torn line"
line() { printf '{"op":"bafyop%d","networkId":"urn:tinycloud:encryption:did:key:z6MkE2eSample:mainnet","keys":[{"keyPath":"apps/e2e/k%d","keyVersion":1}],"deletedAt":"2026-11-01T00:00:00Z"}\n{"committed":"bafyop%d"}\n' "$1" "$1" "$1"; }
for i in 1 2 3; do line "$i"; done > "$scratch/sample.jsonl"
{ cat "$scratch/sample.jsonl"; printf '{"op":"bafyop4","netw'; } \
  | as_node -i "$image" -c 'cat > /var/lib/tinycloud/ledger/deletions.jsonl && chmod 600 /var/lib/tinycloud/ledger/deletions.jsonl'

step "The sidecar refuses a private key as its recipient"
private_key=$(grep '^AGE-SECRET-KEY-' "$scratch/identity.txt")
if NODE_BACKUP_AGE_RECIPIENT=$private_key docker run --rm "${backup_args[@]}" "$image" >"$scratch/refused.out" 2>&1; then
  fail "a private key was accepted as the recipient"
fi
grep -q 'PRIVATE key; refusing to start' "$scratch/refused.out" || fail "unexpected refusal: $(cat "$scratch/refused.out")"
if grep -q 'AGE-SECRET-KEY-' "$scratch/refused.out"; then fail "the refusal echoed the private key"; fi
unset private_key
echo "refused: $(cat "$scratch/refused.out")"

step "Backup once, exactly as the compose service runs; nothing is written to the container's own filesystem"
docker run --name "$run_id-backup" "${backup_args[@]}" "$image"
changes=$(docker diff "$run_id-backup")
[ -z "$changes" ] || fail "the container filesystem changed: $changes"
docker rm "$run_id-backup" >/dev/null
echo "docker diff: (no changes)"

step "Restore drill: newest object -> scratch dir, schema, counts, last entry, byte-for-byte sample"
sh "$here/ledger-restore-drill.sh" --expect "$scratch/sample.jsonl"

step "Backups taken while the node appends (each record in two writes) are whole-line prefixes of the final ledger"
docker run -d --name "$run_id-writer" --user 1000:1000 --entrypoint sh -v "$volume:/var/lib/tinycloud/ledger" "$image" -c '
  ledger=/var/lib/tinycloud/ledger/deletions.jsonl
  # Finish the torn line first: the next node start would otherwise drop it.
  printf "orkId\":\"urn:tinycloud:encryption:did:key:z6MkE2eSample:mainnet\",\"keys\":[{\"keyPath\":\"apps/e2e/k4\",\"keyVersion\":1}],\"deletedAt\":\"2026-11-01T00:00:00Z\"}\n" >> "$ledger"
  i=100
  while :; do
    printf "{\"op\":\"bafyop%d\",\"networkId\":\"urn:tinycloud:encryption:did:key:z6MkE2eSample:mainnet\"," "$i" >> "$ledger"
    sleep 0.003
    printf "\"keys\":[{\"keyPath\":\"apps/e2e/k%d\",\"keyVersion\":1}],\"deletedAt\":\"2026-11-01T00:00:00Z\"}\n" "$i" >> "$ledger"
    i=$((i + 1))
  done' >/dev/null
sleep 1
for round in 1 2 3; do
  sleep 1.1  # object keys have one-second resolution
  docker run --rm "${backup_args[@]}" "$image"
done
docker rm -f "$run_id-writer" >/dev/null
as_node "$image" -c 'cat /var/lib/tinycloud/ledger/deletions.jsonl' > "$scratch/final.jsonl"
listing=$(printf 'user = "%s:%s"\n' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" \
  | curl --config - --fail --silent --show-error --aws-sigv4 "aws:amz:auto:s3" -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
    "$endpoint/$NODE_BACKUP_R2_BUCKET/?list-type=2&prefix=ledger/")
mapfile -t keys < <(grep -o '<Key>[^<]*</Key>' <<<"$listing" | sed 's/<[^>]*>//g' | sort)
[ "${#keys[@]}" -eq 4 ] || fail "expected 4 backup objects, found ${#keys[@]}"
previous=0
for key in "${keys[@]:1}"; do
  printf 'user = "%s:%s"\n' "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" \
    | curl --config - --fail --silent --show-error --aws-sigv4 "aws:amz:auto:s3" -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
      -o "$scratch/object.age" "$endpoint/$NODE_BACKUP_R2_BUCKET/$key"
  age -d -i "$AGE_IDENTITY_FILE" -o "$scratch/restored.jsonl" "$scratch/object.age"
  size=$(wc -c < "$scratch/restored.jsonl")
  [ "$(tail -c 1 "$scratch/restored.jsonl" | od -An -c | tr -d ' ')" = '\n' ] || fail "$key does not end with a whole line"
  head -c "$size" "$scratch/final.jsonl" | cmp -s - "$scratch/restored.jsonl" || fail "$key is not a prefix of the final ledger"
  [ "$size" -gt "$previous" ] || fail "$key holds no more than the backup before it"
  echo "$key: $(tr -cd '\n' < "$scratch/restored.jsonl" | wc -c) whole lines, a prefix of the final ledger"
  previous=$size
  rm -f "$scratch/restored.jsonl" "$scratch/object.age"
done
sh "$here/ledger-restore-drill.sh" --expect-prefix "$scratch/sample.jsonl"
echo
echo "ci-e2e: OK"

#!/bin/sh
# Encrypted backup loop for the node's named-keys deletion ledger (TC-887).
#
# Entrypoint of the `ledger-backup` sidecar image (deploy/ledger-backup/Dockerfile).
# The compose service mounts the `deletion-ledger` volume READ-ONLY, runs as the
# node's uid 1000 with a read-only root filesystem, and gives this script a
# RAM-backed tmpfs /tmp. Nothing else in the container is writable, so the
# plaintext copy never reaches the overlay disk.
#
# snapshot -> age -r <public recipient> -> S3 PUT to Cloudflare R2.
# The CVM holds only the age PUBLIC recipient; the identity (private key) is
# held by operators off the CVM (deploy/ledger-backup/README.md, "Key custody").
#
# Consistency: the node holds an exclusive flock on `<ledger>.lock` for as long
# as it runs, so the copy is lock-free. The ledger is append-only, but an
# append whose write or fsync fails is cut back to the length before it. A
# snapshot therefore (1) copies the file's current length, (2) keeps only whole
# lines, (3) waits BACKUP_SETTLE_SECONDS and (4) accepts the copy only if the
# live file still starts with exactly those bytes; otherwise it starts again.
#
# Env (sealed): NODE_BACKUP_R2_ENDPOINT, NODE_BACKUP_R2_ACCESS_KEY_ID,
#   NODE_BACKUP_R2_SECRET_ACCESS_KEY, NODE_BACKUP_AGE_RECIPIENT (age1... only).
# Env (plain): NODE_BACKUP_R2_BUCKET,
#   NODE_BACKUP_LEDGER_PATH (default /var/lib/tinycloud/ledger/deletions.jsonl),
#   BACKUP_INTERVAL_SECONDS (default 300: how often the ledger is checked),
#   BACKUP_UNCHANGED_UPLOAD_SECONDS (default 86400: upload at least this often
#     even if the ledger did not change, so a dead sidecar shows as a gap),
#   BACKUP_RETRY_SECONDS (default 60), BACKUP_SETTLE_SECONDS (default 5),
#   BACKUP_SNAPSHOT_TRIES (default 10),
#   BACKUP_ONCE=1 (one snapshot and upload; the exit status reflects it; CI).
set -eu
umask 077

die() { echo "backup: $*" >&2; exit 1; }

for name in NODE_BACKUP_R2_ENDPOINT NODE_BACKUP_R2_BUCKET NODE_BACKUP_R2_ACCESS_KEY_ID NODE_BACKUP_R2_SECRET_ACCESS_KEY NODE_BACKUP_AGE_RECIPIENT; do
  eval "value=\${$name:-}"
  [ -n "$value" ] || die "$name is required"
done
unset value
case "$NODE_BACKUP_AGE_RECIPIENT" in
  AGE-SECRET-KEY-*) die "NODE_BACKUP_AGE_RECIPIENT is a PRIVATE key; refusing to start" ;;
  age1*) ;;
  *) die "NODE_BACKUP_AGE_RECIPIENT must be an age1... public recipient" ;;
esac
# The credentials reach curl through its stdin config, never argv, inside one
# double-quoted value: refuse anything that would need escaping there.
for name in NODE_BACKUP_R2_ACCESS_KEY_ID NODE_BACKUP_R2_SECRET_ACCESS_KEY; do
  eval "value=\$$name"
  case "$value" in
    *'"'* | *'\'* | *'
'* | *"$(printf '\r')"*) die "$name contains a character that is not allowed" ;;
  esac
done
unset value

ledger=${NODE_BACKUP_LEDGER_PATH:-/var/lib/tinycloud/ledger/deletions.jsonl}
interval=${BACKUP_INTERVAL_SECONDS:-300}
unchanged_every=${BACKUP_UNCHANGED_UPLOAD_SECONDS:-86400}
retry=${BACKUP_RETRY_SECONDS:-60}
settle=${BACKUP_SETTLE_SECONDS:-5}
tries=${BACKUP_SNAPSHOT_TRIES:-10}
for value in "$interval" "$unchanged_every" "$retry" "$settle" "$tries"; do
  case "$value" in '' | *[!0-9]*) die "BACKUP_* intervals and counts must be whole numbers" ;; esac
done
[ "$tries" -ge 1 ] || die "BACKUP_SNAPSHOT_TRIES must be at least 1"

# Fail at start, not at the first upload, if age cannot use the recipient.
printf '' | age -r "$NODE_BACKUP_AGE_RECIPIENT" > /dev/null 2>&1 \
  || die "NODE_BACKUP_AGE_RECIPIENT is not a valid age recipient"

# mktemp honours TMPDIR and falls back to /tmp, the compose service's tmpfs.
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
# Exit promptly on `docker stop`; EXIT then removes $work.
trap 'exit 143' TERM INT

# Interruptible sleep: a trap only runs between commands.
nap() { sleep "$1" & wait $!; }

bytes() { n=$(wc -c < "$1") && echo $((n)); }
lines() { n=$(tr -cd '\n' < "$1" | wc -c) && echo $((n)); }

# Writes a consistent whole-line copy of the ledger to $work/snap.
snapshot() {
  attempt=0
  while [ "$attempt" -lt "$tries" ]; do
    attempt=$((attempt + 1))
    rm -f "$work/raw" "$work/snap"
    [ -f "$ledger" ] || { echo "backup: the ledger file does not exist" >&2; return 1; }
    size=$(bytes "$ledger") || return 1
    head -c "$size" "$ledger" > "$work/raw" || return 1
    if [ "$(bytes "$work/raw")" -eq "$size" ]; then
      whole=$(lines "$work/raw")
      if [ "$whole" -gt 0 ]; then
        head -n "$whole" "$work/raw" > "$work/snap" || return 1
      else
        : > "$work/snap"
      fi
      rm -f "$work/raw"
      length=$(bytes "$work/snap")
      nap "$settle"
      # The live file must still begin with exactly the bytes copied.
      if head -c "$length" "$ledger" | cmp -s - "$work/snap"; then
        return 0
      fi
    fi
    echo "backup: the ledger changed under the copy (attempt $attempt of $tries); copying again" >&2
  done
  rm -f "$work/raw" "$work/snap"
  return 1
}

put() { # put <file> <key>
  printf 'user = "%s:%s"\n' "$NODE_BACKUP_R2_ACCESS_KEY_ID" "$NODE_BACKUP_R2_SECRET_ACCESS_KEY" \
    | curl --config - --fail --silent --show-error --max-time 120 \
      --aws-sigv4 "aws:amz:auto:s3" \
      -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
      -H "If-None-Match: *" \
      -T "$1" \
      "${NODE_BACKUP_R2_ENDPOINT%/}/${NODE_BACKUP_R2_BUCKET}/$2"
}

last_hash=
last_upload=0

# `|| return 1`: set -e is ignored inside `if backup_once`, so fail each step explicitly.
backup_once() {
  snapshot || return 1
  hash=$(sha256sum "$work/snap" | cut -d ' ' -f 1) || return 1
  now=$(date +%s)
  if [ "$hash" = "$last_hash" ] && [ $((now - last_upload)) -lt "$unchanged_every" ]; then
    rm -f "$work/snap"
    return 0
  fi
  count=$(lines "$work/snap")
  stamp=$(date -u +%Y%m%dT%H%M%SZ)
  key="ledger/deletions-${stamp}.jsonl.age"
  age -r "$NODE_BACKUP_AGE_RECIPIENT" -o "$work/snap.age" "$work/snap" || return 1
  rm -f "$work/snap"
  put "$work/snap.age" "$key" || return 1
  size=$(bytes "$work/snap.age")
  rm -f "$work/snap.age"
  last_hash=$hash
  last_upload=$now
  echo "backup: uploaded ${key} (${count} lines, ${size} bytes encrypted)"
}

if [ "${BACKUP_ONCE:-}" = 1 ]; then
  backup_once || die "FAILED"
  exit 0
fi

while true; do
  if backup_once; then
    nap "$interval"
  else
    echo "backup: FAILED; retrying in ${retry}s" >&2
    rm -f "$work/raw" "$work/snap" "$work/snap.age"
    nap "$retry"
  fi
done

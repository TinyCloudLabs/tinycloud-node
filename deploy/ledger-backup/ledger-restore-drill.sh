#!/bin/sh
# Restore drill for the node's deletion-ledger backups (TC-887).
# Run by an operator, never on the CVM: it needs the age PRIVATE key.
#
#   ledger-restore-drill.sh [--file <backup.jsonl.age>] [--expect <ledger>] [--expect-prefix <ledger>]
#
# 1. Without --file, find the newest ledger backup in the bucket and download it.
# 2. Decrypt it with the identity in AGE_IDENTITY_FILE into a fresh scratch
#    directory (mktemp -d; TMPDIR decides where; use a private one).
# 3. Check it: every line is a whole ledger record of exactly the node's schema
#    (`{op, networkId, keys:[{keyPath, keyVersion}], deletedAt}`, `{committed}`
#    or `{aborted}`), print the line count, the record counts and the last entry.
# 4. --expect: the restored ledger must equal that file byte for byte.
#    --expect-prefix: the restored ledger must start with exactly that file.
# The scratch directory is removed on exit unless RESTORE_KEEP=1, which prints
# its path (the decrypted ledger is `deletions.jsonl` in it).
#
# Env:
#   AGE_IDENTITY_FILE                       age identity (private key) file. Required.
#   NODE_BACKUP_R2_ENDPOINT / _BUCKET / _ACCESS_KEY_ID / _SECRET_ACCESS_KEY
#                                           Read credentials. Not needed with --file.
# Needs: age, jq, and curl >= 8 without --file.
set -eu
umask 077

die() { echo "restore-drill: $*" >&2; exit 1; }

file=
expect=
expect_prefix=
while [ $# -gt 0 ]; do
  case "$1" in
    --file) [ $# -ge 2 ] || die "--file needs a path"; file=$2; shift 2 ;;
    --expect) [ $# -ge 2 ] || die "--expect needs a path"; expect=$2; shift 2 ;;
    --expect-prefix) [ $# -ge 2 ] || die "--expect-prefix needs a path"; expect_prefix=$2; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -n "${AGE_IDENTITY_FILE:-}" ] && [ -r "$AGE_IDENTITY_FILE" ] || die "AGE_IDENTITY_FILE must point to a readable age identity file"
for tool in age jq; do command -v "$tool" >/dev/null 2>&1 || die "$tool is required"; done
[ -z "$expect" ] || [ -r "$expect" ] || die "cannot read $expect"
[ -z "$expect_prefix" ] || [ -r "$expect_prefix" ] || die "cannot read $expect_prefix"

work=$(mktemp -d)
cleanup() {
  if [ "${RESTORE_KEEP:-}" = 1 ]; then
    echo "restore-drill: kept scratch directory $work"
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT
trap 'exit 143' TERM INT

if [ -z "$file" ]; then
  for name in NODE_BACKUP_R2_ENDPOINT NODE_BACKUP_R2_BUCKET NODE_BACKUP_R2_ACCESS_KEY_ID NODE_BACKUP_R2_SECRET_ACCESS_KEY; do
    eval "value=\${$name:-}"
    [ -n "$value" ] || die "$name is required (or pass --file)"
  done
  command -v curl >/dev/null 2>&1 || die "curl is required"
  # curl 7.x does not sign x-amz-content-sha256 with --aws-sigv4, so R2 rejects it.
  curl_major=$(curl --version | sed -n '1s/^curl \([0-9][0-9]*\)\..*/\1/p')
  case "$curl_major" in '' | *[!0-9]*) die "cannot parse the curl version" ;; esac
  [ "$curl_major" -ge 8 ] || die "curl $curl_major is too old; version 8 or newer is required"
  s3() { # s3 <path-and-query> [curl args...]; credentials on stdin, never argv
    path=$1; shift
    printf 'user = "%s:%s"\n' "$NODE_BACKUP_R2_ACCESS_KEY_ID" "$NODE_BACKUP_R2_SECRET_ACCESS_KEY" \
      | curl --config - --fail --silent --show-error --max-time 120 --aws-sigv4 "aws:amz:auto:s3" \
        -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" "$@" \
        "${NODE_BACKUP_R2_ENDPOINT%/}/${NODE_BACKUP_R2_BUCKET}${path}"
  }
  # Keys embed a UTC timestamp, so lexical order is chronological. Page through
  # ListObjectsV2 (1000 keys a page) and keep the greatest key.
  latest=
  token=
  while :; do
    if [ -n "$token" ]; then
      s3 "/?list-type=2&prefix=ledger/" -G --data-urlencode "continuation-token=$token" > "$work/list.xml"
    else
      s3 "/?list-type=2&prefix=ledger/" > "$work/list.xml"
    fi
    page=$(grep -o '<Key>[^<]*</Key>' "$work/list.xml" | sed 's/<[^>]*>//g' | grep '^ledger/deletions-[0-9TZ]*\.jsonl\.age$' | sort | tail -n 1 || true)
    if [ -n "$page" ] && { [ -z "$latest" ] || [ "$page" \> "$latest" ]; }; then latest=$page; fi
    grep -q '<IsTruncated>true</IsTruncated>' "$work/list.xml" || break
    token=$(sed -n 's/.*<NextContinuationToken>\([^<]*\)<\/NextContinuationToken>.*/\1/p' "$work/list.xml")
    [ -n "$token" ] || die "truncated listing without a continuation token"
  done
  rm -f "$work/list.xml"
  [ -n "$latest" ] || die "no ledger backups found in the bucket"
  echo "restore-drill: latest backup is ${latest}"
  s3 "/${latest}" -o "$work/backup.age"
  file=$work/backup.age
fi
[ -r "$file" ] || die "cannot read $file"

ledger=$work/deletions.jsonl
age -d -i "$AGE_IDENTITY_FILE" -o "$ledger" "$file" || die "decryption failed (wrong identity?)"
size=$(wc -c < "$ledger")
size=$((size))
count=$(tr -cd '\n' < "$ledger" | wc -c)
count=$((count))
echo "restore-drill: decrypted ${size} bytes, ${count} lines"

if [ "$size" -gt 0 ] && [ "$(tail -c 1 "$ledger" | od -An -c | tr -d ' ')" != '\n' ]; then
  die "the last line is not terminated: not a whole-line snapshot"
fi

# Exactly the node's serde shapes (deny_unknown_fields): an intent, or a
# committed / aborted marker naming an operation.
summary=$(jq -R -n -r '
  def str: type == "string";
  def intent: type == "object" and (keys == ["deletedAt", "keys", "networkId", "op"])
    and (.op | str) and (.networkId | str) and (.deletedAt | str)
    and (.keys | type == "array" and all(.[]; type == "object" and keys == ["keyPath", "keyVersion"]
      and (.keyPath | str) and (.keyVersion | type == "number" and . == floor)));
  def marker($k): type == "object" and keys == [$k] and (.[$k] | str);
  [inputs | (try fromjson catch {invalid: true})] as $rows
  | ($rows | map(intent or marker("committed") or marker("aborted"))) as $valid
  | if ($valid | all | not) then
      "INVALID line \(1 + ($valid | index(false)))"
    else
      ($rows | map(select(intent))) as $intents
      | ($rows | map(select(marker("committed")) | .committed)) as $committed
      | ($rows | map(select(marker("aborted")) | .aborted)) as $aborted
      | ($intents | map(.op) - $committed - $aborted) as $open
      | "OK intents=\($intents | length) committed=\($committed | length) aborted=\($aborted | length) open=\($open | length) keys=\($intents | map(.keys | length) | add // 0)"
      + "\nLAST " + (if ($rows | length) == 0 then "(empty ledger)"
          else ($rows[-1] | if intent then "intent op=\(.op) deletedAt=\(.deletedAt) keys=\(.keys | length)"
            elif has("committed") then "committed op=\(.committed)" else "aborted op=\(.aborted)" end) end)
    end' < "$ledger") || die "jq could not read the ledger"
case "$summary" in
  OK*) ;;
  *) die "schema check failed: ${summary}" ;;
esac
echo "restore-drill: records $(printf '%s\n' "$summary" | sed -n 's/^OK //p')"
echo "restore-drill: last entry $(printf '%s\n' "$summary" | sed -n 's/^LAST //p')"

if [ -n "$expect" ]; then
  cmp -s "$expect" "$ledger" || die "the restored ledger differs from $expect"
  echo "restore-drill: matches the expected ledger byte for byte"
fi
if [ -n "$expect_prefix" ]; then
  plen=$(wc -c < "$expect_prefix")
  plen=$((plen))
  [ "$size" -ge "$plen" ] && head -c "$plen" "$ledger" | cmp -s - "$expect_prefix" \
    || die "the restored ledger does not start with $expect_prefix"
  echo "restore-drill: starts with the expected ${plen} bytes"
fi
echo "restore-drill: OK"

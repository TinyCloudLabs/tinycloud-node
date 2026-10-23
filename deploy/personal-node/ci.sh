#!/usr/bin/env bash
# Run only on an isolated GitHub Actions runner, not a shared Docker host.
set -euo pipefail
umask 077
here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
owner="$work/owner.key"
passphrase="$work/backup-passphrase"
openssl rand -hex 32 > "$owner"
openssl rand -base64 48 > "$passphrase"

cleanup() {
  for name in tc1282-a tc1282-b tc1282-c tc1282-d tc1282-e; do
    if [[ -f "$work/$name/tls-mode" ]]; then
      NODE_HOME="$work/$name" "$here/node.sh" destroy-test || true
    fi
  done
}
trap cleanup EXIT

export NODE_HOME="$work/tc1282-e"
"$here/node.sh" init localhost test
"$here/node.sh" check-missing-key
saved_image="$(<"$NODE_HOME/image")"
printf '%s\n' 'not a valid image reference' > "$NODE_HOME/image"
unrelated_status=0
"$here/node.sh" compose-check >/dev/null 2>&1 || unrelated_status=$?
[[ "$unrelated_status" == 1 ]] ||
  { printf '%s\n' 'Negative control did not produce an unrelated exit 1' >&2; exit 1; }
if "$here/node.sh" check-missing-key; then
  printf '%s\n' 'Missing-key guard accepted an unrelated exit 1' >&2
  exit 1
fi
printf '%s\n' "$saved_image" > "$NODE_HOME/image"
"$here/node.sh" start
"$here/node.sh" check-version 1.22.0
"$here/node.sh" seed "$owner"
"$here/node.sh" restart
"$here/node.sh" verify "$owner"
"$here/node.sh" stop

export NODE_HOME="$work/tc1282-a"
"$here/node.sh" init localhost test 1.20.6
"$here/node.sh" check-missing-key
"$here/node.sh" start
"$here/node.sh" check-version 1.20.6
"$here/node.sh" seed "$owner"
"$here/node.sh" restart
"$here/node.sh" verify "$owner"
"$here/node.sh" backup "$work/pre-upgrade" "$passphrase"
"$here/node.sh" stop

export NODE_HOME="$work/tc1282-b"
"$here/node.sh" restore "$work/pre-upgrade" "$passphrase"
"$here/node.sh" start
"$here/node.sh" check-version 1.20.6
"$here/node.sh" verify "$owner"
"$here/node.sh" upgrade
"$here/node.sh" check-version 1.22.0
"$here/node.sh" verify "$owner"
"$here/node.sh" backup "$work/post-upgrade" "$passphrase"
"$here/node.sh" stop

export NODE_HOME="$work/tc1282-c"
"$here/node.sh" restore "$work/post-upgrade" "$passphrase"
"$here/node.sh" start
"$here/node.sh" check-version 1.22.0
"$here/node.sh" verify "$owner"
"$here/node.sh" stop

# Rollback is a restore from the pre-upgrade snapshot, not an in-place
# downgrade of a migrated database: the upgrade applies database migrations
# that 1.20.6 does not know.
export NODE_HOME="$work/tc1282-d"
"$here/node.sh" restore "$work/pre-upgrade" "$passphrase"
"$here/node.sh" start
"$here/node.sh" check-version 1.20.6
"$here/node.sh" verify "$owner"
"$here/node.sh" stop
printf '%s\n' 'Personal-node lifecycle passed: TLS, signed KV/SQL, restart, fresh restore, upgrade, rollback restore'

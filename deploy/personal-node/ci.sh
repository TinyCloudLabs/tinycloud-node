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
  for name in tc1282-a tc1282-b tc1282-c tc1282-d; do
    if [[ -f "$work/$name/tls-mode" ]]; then
      NODE_HOME="$work/$name" "$here/node.sh" destroy-test || true
    fi
  done
}
trap cleanup EXIT

export NODE_HOME="$work/tc1282-a"
"$here/node.sh" init localhost test 1.20.5
"$here/node.sh" check-missing-key
"$here/node.sh" start
"$here/node.sh" check-version 1.20.5
"$here/node.sh" seed "$owner"
"$here/node.sh" restart
"$here/node.sh" verify "$owner"
"$here/node.sh" backup "$work/pre-upgrade" "$passphrase"
"$here/node.sh" stop

export NODE_HOME="$work/tc1282-b"
"$here/node.sh" restore "$work/pre-upgrade" "$passphrase"
"$here/node.sh" start
"$here/node.sh" check-version 1.20.5
"$here/node.sh" verify "$owner"
"$here/node.sh" upgrade
"$here/node.sh" check-version 1.20.6
"$here/node.sh" verify "$owner"
"$here/node.sh" backup "$work/post-upgrade" "$passphrase"
"$here/node.sh" stop

export NODE_HOME="$work/tc1282-c"
"$here/node.sh" restore "$work/post-upgrade" "$passphrase"
"$here/node.sh" start
"$here/node.sh" check-version 1.20.6
"$here/node.sh" verify "$owner"
"$here/node.sh" stop

# Rollback is a restore from the pre-upgrade snapshot, not an in-place
# downgrade of a migrated database.
export NODE_HOME="$work/tc1282-d"
"$here/node.sh" restore "$work/pre-upgrade" "$passphrase"
"$here/node.sh" start
"$here/node.sh" check-version 1.20.5
"$here/node.sh" verify "$owner"
"$here/node.sh" stop
printf '%s\n' 'Personal-node lifecycle passed: TLS, signed KV/SQL, restart, fresh restore, upgrade, rollback restore'

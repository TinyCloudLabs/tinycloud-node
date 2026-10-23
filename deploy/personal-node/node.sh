#!/usr/bin/env bash
set -euo pipefail
umask 077

here="$(cd "$(dirname "$0")" && pwd)"
home="$(realpath -m "${NODE_HOME:-./personal-node}")"
image_1220='ghcr.io/tinycloudlabs/tinycloud-node@sha256:2f3c65d85aa94610456bf09cd54713bab5260097bb3d56858025bc6eadb5a4a0'
# The previous published image, used only to rehearse the upgrade.
image_1206='ghcr.io/tinycloudlabs/tinycloud-node@sha256:41667d3d133aaa12290a2f3a744afacd838988327552d159c60f04466e66f86f'

fail() { printf '%s\n' "$*" >&2; exit 1; }
require_home() { [[ -f "$home/node.env" && -f "$home/image" && -f "$home/domain" ]] || fail 'Initialize or restore the node first'; }

compose() {
  require_home
  local domain tls_mode
  domain="$(<"$home/domain")"
  tls_mode="$(<"$home/tls-mode")"
  export NODE_IMAGE="$(<"$home/image")"
  export NODE_KEY_ENV_FILE="${NODE_KEY_ENV_FILE:-$home/node.env}"
  export NODE_DATA_DIR="$home/data" NODE_DOMAIN="$domain"
  export COMPOSE_PROJECT_NAME="$(basename "$home")"
  export NODE_CADDYFILE="$here/Caddyfile"
  if [[ "$tls_mode" == test ]]; then
    export NODE_CADDYFILE="$here/Caddyfile.test"
    export NODE_HTTP_BIND='127.0.0.1:8080:80' NODE_HTTPS_BIND='127.0.0.1:8443:443'
  fi
  docker compose -f "$here/compose.yaml" "$@"
}

url() {
  if [[ "$(<"$home/tls-mode")" == test ]]; then
    printf 'https://localhost:8443'
  else
    printf 'https://%s' "$(<"$home/domain")"
  fi
}

ca_args=()
prepare_tls() {
  ca_args=()
  if [[ "$(<"$home/tls-mode")" == test ]]; then
    for _ in {1..40}; do
      if compose cp https:/data/caddy/pki/authorities/local/root.crt "$home/test-root.crt" >/dev/null 2>&1; then break; fi
      sleep 2
    done
    [[ -s "$home/test-root.crt" ]] || fail 'Test TLS certificate was not issued'
    ca_args=(--cacert "$home/test-root.crt")
    export NODE_EXTRA_CA_CERTS="$home/test-root.crt"
  fi
}

health() {
  prepare_tls
  for _ in {1..40}; do
    if curl -fsS "${ca_args[@]}" "$(url)/healthz" -o /dev/null; then return; fi
    sleep 2
  done
  fail 'HTTPS health check failed'
}

identity() {
  health
  curl -fsS "${ca_args[@]}" "$(url)/.well-known/tinycloud/node-keys" | jq -er '.nodeDid' > "$home/current-identity"
  [[ -s "$home/current-identity" ]] || fail 'Node identity is unavailable'
}

case "${1:-}" in
  init)
    [[ $# -ge 2 ]] || fail 'Usage: node.sh init DOMAIN [test] [1.20.6]'
    [[ ! -e "$home" ]] || fail 'Choose a fresh NODE_HOME'
    [[ "$2" =~ ^[a-zA-Z0-9.-]+$ ]] || fail 'Invalid domain'
    [[ "${3:-}" == '' || "${3:-}" == test ]] || fail 'TLS mode must be test or omitted'
    [[ "${4:-}" == '' || "${4:-}" == 1.20.6 ]] || fail 'Only 1.20.6 is supported as the previous image'
    mkdir -p "$home/data"
    printf '%s\n' "$2" > "$home/domain"
    printf '%s\n' "${3:-production}" > "$home/tls-mode"
    printf '%s\n' "$image_1220" > "$home/image"
    if [[ "${4:-}" == 1.20.6 ]]; then printf '%s\n' "$image_1206" > "$home/image"; fi
    printf 'TINYCLOUD_KEYS__TYPE=Static\nTINYCLOUD_KEYS__SECRET=%s\n' \
      "$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')" > "$home/node.env"
    sudo chown -R 1000:1000 "$home/data"
    ;;
  check-missing-key)
    require_home
    blank="$(mktemp)"
    diagnostic="$(mktemp)"
    trap 'rm -f "$blank" "$diagnostic"' EXIT
    printf 'TINYCLOUD_KEYS__TYPE=Static\n' > "$blank"
    status=0
    NODE_KEY_ENV_FILE="$blank" timeout 30 "$0" compose-check >"$diagnostic" 2>&1 || status=$?
    missing=0
    while IFS= read -r line; do
      if [[ "$line" == '  Missing secret' ]]; then missing=1; fi
    done < "$diagnostic"
    [[ "$status" == 1 && "$missing" == 1 ]] ||
      fail 'Missing-key check did not report the exact missing-secret error'
    printf '%s\n' 'Missing-key startup failed as required'
    ;;
  compose-check)
    compose run --rm --no-deps node
    ;;
  start)
    compose up -d
    health
    ;;
  restart)
    compose restart node
    health
    ;;
  stop)
    compose stop
    ;;
  check-version)
    [[ $# == 2 ]] || fail 'Usage: node.sh check-version 1.20.6|1.22.0'
    health
    curl -fsS "${ca_args[@]}" "$(url)/version" |
      jq -e --arg version "$2" '.version == $version and .quota_url == null and .inTEE == false and ((.features | index("encryption-named-keys-v1")) == null) and ((.features | index("sql-delegated-caveats-v1")) == null)' >/dev/null ||
      fail 'Unexpected node version, hosted quota, TEE mode, or enabled named-key/delegated-SQL feature'
    ;;
  verify|seed)
    [[ $# == 2 && -f "$2" ]] || fail "Usage: node.sh $1 OWNER_KEY_FILE"
    identity
    if [[ -f "$home/identity" ]]; then
      cmp -s "$home/identity" "$home/current-identity" || fail 'Node identity changed'
    else
      [[ "$1" == seed ]] || fail 'Expected restored identity record'
      cp "$home/current-identity" "$home/identity"
    fi
    [[ -x "$here/../../test/probe/node_modules/.bin/tsx" ]] || fail 'Run npm ci --prefix test/probe first'
    "$here/../../test/probe/node_modules/.bin/tsx" "$here/../../test/probe/personal-node-check.ts" "$1" "$(url)" "$2"
    ;;
  backup)
    [[ $# == 3 && -f "$3" ]] || fail 'Usage: node.sh backup BACKUP_DIR PASSPHRASE_FILE'
    [[ ! -e "$2" ]] || fail 'Choose a fresh backup directory'
    identity
    [[ -f "$home/identity" ]] && cmp -s "$home/identity" "$home/current-identity" ||
      fail 'Back up only after verifying the original node identity'
    mkdir -m 700 "$2"
    compose stop node
    sudo tar -C "$home/data" -czf - . > "$2/data.tar.gz"
    openssl enc -aes-256-cbc -pbkdf2 -salt -in "$home/node.env" -out "$2/identity.enc" -pass "file:$3"
    cp "$home/identity" "$home/image" "$home/domain" "$home/tls-mode" "$2/"
    compose up -d node
    health
    ;;
  restore)
    [[ $# == 3 && -f "$3" ]] || fail 'Usage: node.sh restore BACKUP_DIR PASSPHRASE_FILE'
    [[ ! -e "$home" ]] || fail 'Restore only into a fresh NODE_HOME'
    for file in identity.enc data.tar.gz identity image domain tls-mode; do
      [[ -f "$2/$file" ]] || fail "Backup lacks $file"
    done
    mkdir -p "$home/data"
    openssl enc -d -aes-256-cbc -pbkdf2 -in "$2/identity.enc" -out "$home/node.env" -pass "file:$3" || fail 'Identity decryption failed'
    tar -C "$home/data" -xzf "$2/data.tar.gz"
    cp "$2/identity" "$2/image" "$2/domain" "$2/tls-mode" "$home/"
    sudo chown -R 1000:1000 "$home/data"
    ;;
  upgrade)
    require_home
    [[ "$(<"$home/image")" == "$image_1206" ]] || fail 'Upgrade expects the previous published image'
    compose stop node
    printf '%s\n' "$image_1220" > "$home/image"
    compose up -d node
    health
    ;;
  destroy-test)
    [[ "$(<"$home/tls-mode")" == test && "$(basename "$home")" == tc1282-* ]] || fail 'Only tc1282 test instances may be removed'
    compose down -v
    ;;
  *) fail 'Usage: node.sh {init|check-missing-key|start|check-version|seed|verify|restart|stop|backup|restore|upgrade|destroy-test}' ;;
esac

#!/usr/bin/env bash
# TC-970: run the ingress wrapper with the server block its own entrypoint
# generates (TLS, proxy headers, CLIENT_MAX_BODY_SIZE), send requests carrying
# credentials and identifiers from a separate client container, and check that
# none of them, nor the client address, reaches the ingress container's
# stdout/stderr or any file under /var/log/nginx. Also re-checks the TC-910
# 32 KB header buffers and the #261 200 MB body limit.
#
# Usage: deploy/ingress/test-redacted-logging.sh
#   IMAGE=<ref>   test an existing image instead of building deploy/ingress
#   DOCKER=...    docker command (default: docker)
set -euo pipefail

DOCKER=${DOCKER:-docker}
HERE=$(cd "$(dirname "$0")" && pwd)
RUN_ID="tc970-ingress-logtest-$$-$RANDOM"
NETWORK="$RUN_ID"
INGRESS="$RUN_ID-ingress"
CLIENT="$RUN_ID-client"
BUILT_IMAGE=""

cleanup() {
    $DOCKER rm -f "$INGRESS" "$CLIENT" >/dev/null 2>&1 || true
    $DOCKER network rm "$NETWORK" >/dev/null 2>&1 || true
    if [ -n "$BUILT_IMAGE" ]; then
        $DOCKER image rm "$BUILT_IMAGE" >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

if [ -z "${IMAGE:-}" ]; then
    IMAGE="$RUN_ID:test"
    BUILT_IMAGE="$IMAGE"
    $DOCKER build -q -t "$IMAGE" "$HERE" >/dev/null
fi
echo "testing $IMAGE"

hex() { od -An -N"$1" -tx1 /dev/urandom | tr -d ' \n'; }
TICKET="tc970ticket$(hex 12)"
HOOK_TICKET="tc970hookticket$(hex 12)"
WALLET="$(hex 20)"
SPACE="tinycloud:pkh:eip155:1:0x${WALLET}:default"
KEY="tc970key$(hex 12)"
BEARER="tc970bearer$(hex 12)"
FORWARDED_IP="198.51.100.$((RANDOM % 200 + 20))"
USER_AGENT="tc970agent$(hex 12)"
REFERER_MARKER="tc970referer$(hex 12)"
# nginx accepts only A-Z, `_` and `-` in a method.
METHOD="TCMETHOD$(hex 8 | tr '0-9a-f' 'GHIJKLMNOPQRSTUV')"
DOMAIN="ingress-logtest.local"

# Inside the ingress container: a self-signed certificate where the entrypoint
# expects the Let's Encrypt one, then the entrypoint's own setup_nginx_conf,
# with the production compose's settings, and a fake node on 127.0.0.1:8000.
# /public/ is routed to a closed port so nginx's upstream-error path runs; that
# path writes the request line and the client address to the error log.
INGRESS_SETUP='
set -eo pipefail
source /scripts/functions.sh
mkdir -p "/etc/letsencrypt/live/$DOMAIN"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=$DOMAIN" \
    -keyout "/etc/letsencrypt/live/$DOMAIN/privkey.pem" \
    -out "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" 2>/dev/null
PROXY_CMD=proxy
# setup_nginx_conf runs up to the next function; its heredoc has a column-0 "}".
eval "$(sed -n "/^setup_nginx_conf() {/,/^set_alias_record() {/p" /scripts/entrypoint.sh | sed "\$d")"
setup_nginx_conf
sed -i "s#^    location / {#    location /public/ {\n        proxy_pass http://127.0.0.1:9;\n    }\n\n    location / {#" \
    /etc/nginx/conf.d/default.conf
cat >/etc/nginx/conf.d/zz-fake-node.conf <<EOF
server {
    listen 127.0.0.1:8000;
    access_log off;
    client_max_body_size 0;
    location /signed/kv/ { return 401; }
    location / { return 200 "ok\n"; }
}
EOF
exec nginx -g "daemon off;"
'

$DOCKER network create "$NETWORK" >/dev/null
$DOCKER run -d --name "$INGRESS" --network "$NETWORK" \
    -e DOMAIN="$DOMAIN" -e PORT=443 -e TARGET_ENDPOINT=http://127.0.0.1:8000 \
    -e CLIENT_MAX_BODY_SIZE=200m -e PROXY_READ_TIMEOUT=600s -e PROXY_SEND_TIMEOUT=600s \
    --entrypoint /bin/bash "$IMAGE" -c "$INGRESS_SETUP" >/dev/null
$DOCKER run -d --name "$CLIENT" --network "$NETWORK" --entrypoint sleep "$IMAGE" infinity >/dev/null

ip_of() {
    $DOCKER inspect -f "{{(index .NetworkSettings.Networks \"$NETWORK\").IPAddress}}" "$1"
}
INGRESS_IP=$(ip_of "$INGRESS")
CLIENT_IP=$(ip_of "$CLIENT")
[ -n "$INGRESS_IP" ] && [ -n "$CLIENT_IP" ] || fail "no container addresses"

# Prints the HTTP status of one request sent from the client container.
request() {
    $DOCKER exec "$CLIENT" curl -sk -o /dev/null -w '%{http_code}' --connect-timeout 2 --max-time 120 \
        --resolve "$DOMAIN:443:$INGRESS_IP" \
        -H "Authorization: Bearer $BEARER" \
        -H "X-Forwarded-For: $FORWARDED_IP" \
        -H "User-Agent: $USER_AGENT" \
        -H "Referer: https://app.example/signed/kv/$REFERER_MARKER" \
        "$@"
}

ready=""
for _ in $(seq 1 50); do
    if [ "$(request "https://$DOMAIN/healthz" || true)" = "200" ]; then
        ready=1
        break
    fi
    sleep 0.2
done
[ -n "$ready" ] || { $DOCKER logs "$INGRESS" >&2 || true; fail "ingress did not become ready"; }

expect_status() {
    local want=$1 got
    shift
    got=$(request "$@")
    [ "$got" = "$want" ] || fail "expected $want, got $got for: ${*: -1}"
}

expect_status 401 "https://$DOMAIN/signed/kv/$TICKET"
expect_status 200 "https://$DOMAIN/hooks/events?ticket=$HOOK_TICKET"
expect_status 502 "https://$DOMAIN/public/$SPACE/kv/$KEY"
expect_status 401 "https://$DOMAIN/signed/kv/$TICKET/unmatched"
# HTTP/1.1, a client-chosen method, and a 400 raised before routing (a header
# line over the 32 KB buffers) with the ticket in the request line.
expect_status 401 --http1.1 "https://$DOMAIN/signed/kv/$TICKET"
expect_status 401 --http1.1 -X "$METHOD" "https://$DOMAIN/signed/kv/$TICKET"
expect_status 400 --http1.1 -H "X-Large: $(head -c 40000 /dev/zero | tr '\0' a)" \
    "https://$DOMAIN/signed/kv/$TICKET"

# TC-910: a single header line of about 30 KB fits the 32 KB buffers.
LARGE_HEADER="X-Large: $(head -c 30000 /dev/zero | tr '\0' a)"
expect_status 200 -H "$LARGE_HEADER" "https://$DOMAIN/delegate"

# #261: CLIENT_MAX_BODY_SIZE=200m admits 150 MB and refuses more than 200 MiB.
$DOCKER exec "$CLIENT" sh -c 'head -c 150000000 /dev/zero >/tmp/under && head -c 210000000 /dev/zero >/tmp/over'
expect_status 200 -X POST --data-binary @/tmp/under "https://$DOMAIN/invoke"
expect_status 413 -X POST --data-binary @/tmp/over "https://$DOMAIN/invoke"

sleep 1
LOGS=$($DOCKER logs "$INGRESS" 2>&1)
FILES=$($DOCKER exec "$INGRESS" sh -c 'find /var/log/nginx -type f -exec cat {} +' 2>&1)

for pair in \
    "signed-KV ticket=$TICKET" \
    "hook ticket=$HOOK_TICKET" \
    "space id=$SPACE" \
    "wallet address=$WALLET" \
    "KV key=$KEY" \
    "bearer token=$BEARER" \
    "client address=$CLIENT_IP" \
    "X-Forwarded-For address=$FORWARDED_IP" \
    "User-Agent=$USER_AGENT" \
    "Referer=$REFERER_MARKER" \
    "request method=$METHOD"; do
    what=${pair%%=*}
    needle=${pair#*=}
    if grep -F -- "$needle" <<<"$LOGS" >&2; then
        fail "the $what reached the ingress container's stdout/stderr (lines above)"
    fi
    if grep -F -- "$needle" <<<"$FILES" >&2; then
        fail "the $what reached a file under /var/log/nginx (lines above)"
    fi
done

LOG_FILES=$($DOCKER exec "$INGRESS" find /var/log/nginx -type f -size +0c)
[ -z "$LOG_FILES" ] || { $DOCKER exec "$INGRESS" sh -c "head -c 2000 $LOG_FILES" >&2; fail "nginx wrote to unrotated log files: $LOG_FILES"; }

# Every access line is valid JSON with the expected fields, and each request
# is logged by method, route class and status.
ACCESS=$(python3 -c '
import json, sys
for line in sys.stdin:
    if not line.startswith("{"):
        continue
    record = json.loads(line)
    for key in ("status", "bytes"):
        assert isinstance(record[key], int), line
    assert isinstance(record["request_time"], (int, float)), line
    for key in ("time", "method", "route", "protocol", "upstream_status",
                "upstream_connect_time", "upstream_response_time"):
        assert isinstance(record[key], str), line
    print(record["method"], record["route"], record["status"])
' <<<"$LOGS") || { echo "$LOGS" >&2; fail "an access log line is not the expected JSON"; }
expect_line() {
    grep -qxF "$*" <<<"$ACCESS" \
        || { echo "$ACCESS" >&2; fail "no access log line: $*"; }
}
expect_line GET "/signed/kv/<ticket_id>" 401
expect_line GET "/hooks/events" 200
expect_line GET "/public/<space_id>/kv/<key..>" 502
expect_line GET "<other>" 401
expect_line "<other>" "/signed/kv/<ticket_id>" 401
expect_line GET "/signed/kv/<ticket_id>" 400
expect_line GET "/delegate" 200
expect_line POST "/invoke" 200
expect_line POST "/invoke" 413

echo "ingress container output:"
sed 's/^/  /' <<<"$LOGS"
echo "PASS: no ticket, identifier or client address in the ingress logs; 32 KB headers and 200 MB bodies still accepted"

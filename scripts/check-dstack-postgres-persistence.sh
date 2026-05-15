#!/bin/sh

# Validate that the production dstack Postgres+S3 compose keeps embedded
# TinyCloud SQL and DuckDB data on a persistent Docker volume.

set -eu

COMPOSE_FILE="${1:-docker-compose.dstack-postgres.yaml}"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required to render compose config" >&2
    exit 1
fi

if ! command -v node >/dev/null 2>&1; then
    echo "node is required to inspect rendered compose JSON" >&2
    exit 1
fi

CONFIG_JSON="$(
    DATABASE_URL=postgres://tinycloud:tinycloud@example.invalid:5432/tinycloud \
    S3_BUCKET=tinycloud-blocks \
    S3_ENDPOINT=https://s3.example.invalid \
    AWS_KEY=placeholder \
    AWS_SECRET=placeholder \
    AWS_REGION=us-east-1 \
    CLOUDFLARE_API_TOKEN=placeholder \
    DSTACK_GATEWAY_DOMAIN=example.invalid \
    CERTBOT_EMAIL=ops@example.invalid \
        docker compose -f "$COMPOSE_FILE" config --format json
)"

CONFIG_FILE="$(mktemp)"
trap 'rm -f "$CONFIG_FILE"' EXIT
printf '%s' "$CONFIG_JSON" > "$CONFIG_FILE"

node - "$CONFIG_FILE" <<'NODE'
const fs = require("fs");

const config = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const service = config.services && config.services.tinycloud;

function assert(condition, message) {
  if (!condition) {
    console.error(message);
    process.exit(1);
  }
}

assert(service, "tinycloud service is missing");

const env = service.environment || {};
assert(
  env.TINYCLOUD_STORAGE_DATABASE === "postgres://tinycloud:tinycloud@example.invalid:5432/tinycloud",
  "metadata database must remain externalized to Postgres"
);
assert(env.TINYCLOUD_STORAGE_BLOCKS_TYPE === "S3", "blocks must remain externalized to S3");
assert(env.TINYCLOUD_STORAGE_DATADIR === "/data", "TinyCloud datadir must be /data");

const volumes = service.volumes || [];
const hasDataVolume = volumes.some(
  (volume) => volume.type === "volume" && volume.source === "tinycloud-data" && volume.target === "/data"
);

assert(hasDataVolume, "tinycloud-data volume must be mounted at /data");
assert(config.volumes && config.volumes["tinycloud-data"], "tinycloud-data volume must be declared");

console.log("dstack Postgres compose persistence check passed");
NODE

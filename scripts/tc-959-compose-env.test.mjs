import assert from "node:assert/strict";
import test from "node:test";
import { assertAcceptanceEnvironment } from "./tc-959-compose-env.mjs";

const nodeEnvironment = {
  TINYCLOUD_KEYS_TYPE: "Static",
  TINYCLOUD_KEYS_SECRET: "test-only",
  TINYCLOUD_TEE__MODE: "Off",
  TINYCLOUD_STORAGE_DATABASE: "postgres://postgres@postgres:5432/postgres?sslmode=disable",
  TINYCLOUD_STORAGE_BLOCKS_TYPE: "Local",
  TINYCLOUD_LOG__FORMAT: "Json",
  TINYCLOUD_DATABASE__WRITE_FENCE: "true",
  TINYCLOUD_SHARE_EMAIL__ENABLED: "false",
  TINYCLOUD_ADMIN_SECRET: "",
  TINYCLOUD_QUOTA_URL: "http://127.0.0.1:9",
  ROCKET_ADDRESS: "0.0.0.0",
};
const safe = {
  services: {
    tinycloud: { environment: nodeEnvironment },
    "dstack-ingress": { environment: {} },
    postgres: { environment: { POSTGRES_HOST_AUTH_METHOD: "trust" } },
    vector: { environment: {} },
  },
};

test("accepts only the test node environment and isolated helper environments", () => {
  assert.doesNotThrow(() => assertAcceptanceEnvironment(safe));
});

test("rejects inherited Vector config and source-token variables", () => {
  for (const key of ["VECTOR_CONFIG_YAML", "BETTERSTACK_SOURCE_TOKEN"]) {
    const compose = structuredClone(safe);
    compose.services.vector.environment[key] = "must-not-be-exposed";
    assert.throws(() => assertAcceptanceEnvironment(compose), /vector environment/);
  }
});

test("rejects production credentials inherited by ingress", () => {
  const compose = structuredClone(safe);
  compose.services["dstack-ingress"].environment.CLOUDFLARE_API_TOKEN = "must-not-be-exposed";
  assert.throws(() => assertAcceptanceEnvironment(compose), /ingress environment/);
});

test("rejects node production settings and TINYCLOUD variables on Postgres", () => {
  const compose = structuredClone(safe);
  compose.services.tinycloud.environment.TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_BASE64 = "must-not-be-exposed";
  assert.throws(() => assertAcceptanceEnvironment(compose), /node environment/);
  const postgres = structuredClone(safe);
  postgres.services.postgres.environment.TINYCLOUD_ADMIN_SECRET = "must-not-be-exposed";
  assert.throws(() => assertAcceptanceEnvironment(postgres), /Postgres environment/);
});

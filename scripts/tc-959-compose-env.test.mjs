import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { assertAcceptanceEnvironment } from "./tc-959-compose-env.mjs";

const rendered = JSON.parse(readFileSync(new URL("./tc-959-compose-env.rendered.json", import.meta.url), "utf8"));

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
    vector: { init: true, environment: {} },
  },
};

test("accepts the sanitized real Compose rendering with omitted cleared environments", () => {
  assert.equal(Object.hasOwn(rendered.services["dstack-ingress"], "environment"), false);
  assert.equal(Object.hasOwn(rendered.services.vector, "environment"), false);
  assert.equal(rendered.services.vector.init, true);
  assert.doesNotThrow(() => assertAcceptanceEnvironment(rendered));
});

test("requires init on the rendered Vector service", () => {
  const missing = structuredClone(safe);
  delete missing.services.vector.init;
  assert.throws(() => assertAcceptanceEnvironment(missing), /Vector service must set init: true/);
  const disabled = structuredClone(safe);
  disabled.services.vector.init = false;
  assert.throws(() => assertAcceptanceEnvironment(disabled), /Vector service must set init: true/);
  assert.doesNotThrow(() => assertAcceptanceEnvironment(safe));
});

test("rejects forbidden environment entries added to the rendered Compose snapshot", () => {
  const contaminated = structuredClone(rendered);
  contaminated.services.vector.environment = { VECTOR_CONFIG_YAML: "must-not-be-exposed" };
  assert.throws(() => assertAcceptanceEnvironment(contaminated), /vector environment/);
});

test("rejects missing services and malformed present environments", () => {
  const missingService = structuredClone(rendered);
  delete missingService.services.vector;
  assert.throws(() => assertAcceptanceEnvironment(missingService), /vector service/);

  for (const environment of [null, "bad", [], { VECTOR_CONFIG_YAML: 4 }, { VECTOR_CONFIG_YAML: {} }]) {
    const malformed = structuredClone(rendered);
    malformed.services.vector.environment = environment;
    assert.throws(() => assertAcceptanceEnvironment(malformed), /vector environment/);
  }
});

test("accepts null Compose environment values", () => {
  const compose = structuredClone(safe);
  compose.services.tinycloud.environment.ROCKET_ADDRESS = null;
  assert.doesNotThrow(() => assertAcceptanceEnvironment(compose));
});

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

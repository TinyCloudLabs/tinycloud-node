import { fileURLToPath } from "node:url";

const expectedNodeKeys = [
  "ROCKET_ADDRESS",
  "TINYCLOUD_ADMIN_SECRET",
  "TINYCLOUD_DATABASE__WRITE_FENCE",
  "TINYCLOUD_KEYS_SECRET",
  "TINYCLOUD_KEYS_TYPE",
  "TINYCLOUD_LOG__FORMAT",
  "TINYCLOUD_QUOTA_URL",
  "TINYCLOUD_SHARE_EMAIL__ENABLED",
  "TINYCLOUD_STORAGE_BLOCKS_TYPE",
  "TINYCLOUD_STORAGE_DATABASE",
  "TINYCLOUD_TEE__MODE",
].sort();

function serviceEnvironment(compose, serviceName) {
  const service = compose?.services?.[serviceName];
  if (!service || typeof service !== "object" || Array.isArray(service)) {
    throw new Error(`${serviceName} service must be an object`);
  }
  const environment = service.environment;
  if (environment === undefined) return {};
  if (environment === null || typeof environment !== "object" || Array.isArray(environment)) {
    throw new Error(`${serviceName} environment must be an object`);
  }
  for (const value of Object.values(environment)) {
    if (value !== null && typeof value !== "string") {
      throw new Error(`${serviceName} environment values must be strings or null`);
    }
  }
  return environment;
}

export function assertAcceptanceEnvironment(compose) {
  const node = serviceEnvironment(compose, "tinycloud");
  const nodeKeys = Object.keys(node).sort();
  if (JSON.stringify(nodeKeys) !== JSON.stringify(expectedNodeKeys) ||
      node.TINYCLOUD_KEYS_TYPE !== "Static" || node.TINYCLOUD_TEE__MODE !== "Off") {
    throw new Error("node environment differs from the test-only override");
  }

  const ingress = serviceEnvironment(compose, "dstack-ingress");
  if (Object.keys(ingress).length !== 0) throw new Error("ingress environment contains inherited production variables");

  const postgres = serviceEnvironment(compose, "postgres");
  const postgresKeys = Object.keys(postgres);
  if (postgresKeys.length !== 1 || postgresKeys[0] !== "POSTGRES_HOST_AUTH_METHOD" || postgres.POSTGRES_HOST_AUTH_METHOD !== "trust") {
    throw new Error("Postgres environment differs from the test-only override");
  }


  const vector = serviceEnvironment(compose, "vector");
  const vectorService = compose.services.vector;
  if (vectorService.init !== true) throw new Error("Compose Vector service must set init: true");
  const forbiddenVectorKeys = Object.keys(vector).filter((name) => name.startsWith("VECTOR_") || name.includes("TOKEN"));
  if (forbiddenVectorKeys.length || Object.keys(vector).length) {
    throw new Error(`vector environment contains inherited keys${forbiddenVectorKeys.length ? `: ${forbiddenVectorKeys.join(", ")}` : ""}`);
  }
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  const compose = JSON.parse(input);
  assertAcceptanceEnvironment(compose);
  process.stdout.write("PASS: effective Compose environments are isolated\n");
}

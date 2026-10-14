import { readFileSync } from "node:fs";
import {
  createClient,
  getCvmInfo,
  getCvmComposeFile,
  updateCvmEnvs,
  encryptEnvVars,
} from "@phala/cloud";

const apiKey = process.env.PHALA_CLOUD_API_KEY;
const cvmId = process.env.PHALA_CVM_ID;
const envFile = process.env.ENV_FILE;
if (!apiKey || !cvmId || !envFile) {
  console.error("PHALA_CLOUD_API_KEY, PHALA_CVM_ID and ENV_FILE are required");
  process.exit(1);
}

const envs = [];
for (const line of readFileSync(envFile, "utf8").split("\n")) {
  if (!line.trim() || line.startsWith("#")) continue;
  const i = line.indexOf("=");
  if (i <= 0) continue;
  envs.push({ key: line.slice(0, i), value: line.slice(i + 1) });
}
const envKeys = envs.map((e) => e.key);
if (envKeys.length === 0) {
  console.error(`No env vars parsed from ${envFile}`);
  process.exit(1);
}

const client = createClient({ apiKey });
const cvmRef = { id: cvmId };
const compose = await getCvmComposeFile(client, cvmRef, { schema: false });
const allowed = new Set(compose?.allowed_envs ?? []);
const nextAllowed = [...new Set([...allowed, ...envKeys])];
const missing = envKeys.filter((k) => !allowed.has(k));
if (missing.length === 0) {
  console.log(`allowed_envs already contains all ${envKeys.length} deploy env keys — nothing to do.`);
  process.exit(0);
}
console.log(`allowed_envs is missing ${missing.length} deploy env key(s): ${missing.join(", ")}`);

const info = await getCvmInfo(client, cvmRef, { schema: false });
const pubkey = info?.encrypted_env_pubkey ?? info?.kms_info?.encrypted_env_pubkey;
if (!pubkey) {
  console.error("Could not resolve encrypted_env_pubkey from CVM info");
  process.exit(1);
}

const encryptedEnv = await encryptEnvVars(envs, pubkey);
let result = await updateCvmEnvs(
  client,
  { ...cvmRef, encrypted_env: encryptedEnv, env_keys: nextAllowed },
  { schema: false },
);
console.log("phase 1 response:", JSON.stringify(result));

if (result?.status === "precondition_required") {
  result = await updateCvmEnvs(
    client,
    {
      ...cvmRef,
      encrypted_env: encryptedEnv,
      env_keys: nextAllowed,
      compose_hash: result.compose_hash,
    },
    { schema: false },
  );
  console.log("phase 2 response:", JSON.stringify(result));
}

if (result?.status !== "in_progress") {
  console.error(`Unexpected env update result: ${JSON.stringify(result)}`);
  process.exit(1);
}
console.log(
  `Env update started (correlation ${result.correlation_id}, allowed_envs_changed=${result.allowed_envs_changed}). Waiting for CVM to settle...`,
);

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let started = false;
for (let i = 0; i < 120; i++) {
  await sleep(5000);
  const cur = await getCvmInfo(client, cvmRef, { schema: false });
  const status = cur?.status ?? "unknown";
  if (!started) {
    if (status !== "running") started = true;
    else if (i >= 12) started = true;
    console.log(`[${(i + 1) * 5}s] status=${status} (waiting for update to ${started ? "finish" : "start"})`);
    continue;
  }
  console.log(`[${(i + 1) * 5}s] status=${status}`);
  if (status === "running") break;
  if (status === "failed" || status === "error") {
    console.error(`CVM entered status '${status}' after env update`);
    process.exit(1);
  }
}

const after = await getCvmComposeFile(client, cvmRef, { schema: false });
const afterAllowed = new Set(after?.allowed_envs ?? []);
const stillMissing = nextAllowed.filter((k) => !afterAllowed.has(k));
if (stillMissing.length > 0) {
  console.error(`allowed_envs still missing after update: ${stillMissing.join(", ")}`);
  process.exit(1);
}
console.log(`allowed_envs now contains all ${envKeys.length} deploy env keys.`);

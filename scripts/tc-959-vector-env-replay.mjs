import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";

const [vectorBinary, acceptanceConfig, embeddedConfigPath] = process.argv.slice(2);
if (!vectorBinary || !acceptanceConfig || !embeddedConfigPath) {
  throw new Error("usage: tc-959-vector-env-replay.mjs VECTOR ACCEPTANCE_CONFIG EMBEDDED_CONFIG");
}
const baseEnv = { PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", HOME: "/tmp", TMPDIR: "/tmp" };
const contaminated = spawnSync(vectorBinary, ["--config", acceptanceConfig], {
  env: { ...baseEnv, VECTOR_CONFIG_YAML: readFileSync(embeddedConfigPath, "utf8") },
  encoding: "utf8",
  timeout: 10000,
});
if (contaminated.status === 0 || !contaminated.stderr?.includes("Config file not found in path")) {
  throw new Error("native Vector did not reproduce the VECTOR_CONFIG_YAML-as-path failure");
}

const cleaned = spawnSync(vectorBinary, ["--config", acceptanceConfig], {
  env: baseEnv,
  encoding: "utf8",
  timeout: 2000,
});
if (cleaned.error?.code !== "ETIMEDOUT" && cleaned.status !== 0) {
  throw new Error("native Vector failed to start the acceptance config with VECTOR_CONFIG_YAML removed");
}
process.stdout.write("PASS: native Vector reproduced the environment-as-path failure and started after config env removal\n");

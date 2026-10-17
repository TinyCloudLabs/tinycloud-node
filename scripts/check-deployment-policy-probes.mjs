import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";

const workflow = readFileSync(".github/workflows/docker.yml", "utf8");
const expectedRoutes = [
  "/policy/v3/enforcer-bindings",
  "/policy/v3/policies",
  "/policy/v3/challenges",
  "/policy/v3/delegations",
  "/policy/v3/deliveries/authorize",
];

function shellForStep(name) {
  const lines = workflow.split("\n");
  const start = lines.indexOf(`      - name: ${name}`);
  assert(start >= 0, `missing deployment check: ${name}`);
  const run = lines.indexOf("        run: |", start);
  assert(run > start, `missing deployment script: ${name}`);
  const body = [];
  for (const line of lines.slice(run + 1)) {
    if (line && !line.startsWith("          ")) break;
    body.push(line.slice(10));
  }
  return body.join("\n");
}

const directory = mkdtempSync(join(tmpdir(), "tinycloud-deploy-probes-"));
const logPath = join(directory, "requests.jsonl");
const mockCurl = `#!${process.execPath}
const fs = require("node:fs");
const args = process.argv.slice(2);
const url = new URL(args.at(-1));
if (url.origin !== "https://tee.node.tinycloud.xyz") process.exit(90);
const valueAfter = flag => args[args.indexOf(flag) + 1];
const post = args.includes("-X") && valueAfter("-X") === "POST";
const headers = args.flatMap((arg, index) => arg === "-H" ? [args[index + 1].toLowerCase()] : []);
const safeProbe = post && valueAfter("--data") === "{}" &&
  headers.includes("accept: application/json") && headers.includes("content-type: application/json") &&
  !headers.some(header => header.startsWith("authorization:"));
fs.appendFileSync(process.env.PROBE_LOG, JSON.stringify({path:url.pathname, safeProbe}) + "\\n");
if (url.pathname === "/version") {
  if (process.env.TLS_UNREADY === "true") process.exit(22);
  console.log(JSON.stringify({version:process.env.READY_VERSION}));
} else {
  if (!safeProbe) process.exit(91);
  const statuses = JSON.parse(process.env.PROBE_STATUSES);
  const status = statuses[url.pathname] ?? 404;
  if (args.includes("-o")) fs.writeFileSync(valueAfter("-o"), "{}");
  process.stdout.write(String(status));
}
`;
const mockJq = `#!${process.execPath}
let input = "";
process.stdin.on("data", chunk => input += chunk);
process.stdin.on("end", () => {
  try { console.log(JSON.parse(input).version); } catch { process.exitCode = 1; }
});
`;
let cases = 0;

function run(name, statuses, success, options = {}) {
  writeFileSync(logPath, "");
  const result = spawnSync("bash", ["-e", "-o", "pipefail", "-c", shellForStep(name)], {
    env: {
      PATH: `${directory}:${process.env.PATH}`,
      EXPECTED: "1.20.6",
      PROBE_LOG: logPath,
      PROBE_STATUSES: JSON.stringify(statuses),
      READY_VERSION: options.version ?? "1.20.6",
      TLS_UNREADY: options.tlsUnready ? "true" : "false",
    },
    encoding: "utf8",
    timeout: 15000,
  });
  // Do not forward captured output: workflow errors may contain server data.
  assert.equal(result.error, undefined, "synthetic probe execution failed");
  assert.equal(result.status === 0, success, "deployment probe accepted/rejected the wrong response");
  cases++;
  return readFileSync(logPath, "utf8").trim().split("\n").filter(Boolean).map(line => JSON.parse(line));
}

try {
  writeFileSync(join(directory, "curl"), mockCurl, { mode: 0o700 });
  writeFileSync(join(directory, "jq"), mockJq, { mode: 0o700 });
  writeFileSync(join(directory, "sleep"), "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  const defaults = Object.fromEntries(expectedRoutes.map(route => [route, route.endsWith("/authorize") ? 401 : 400]));
  for (const general of [400, 422]) {
    const statuses = Object.fromEntries(expectedRoutes.map(route => [route, route.endsWith("/authorize") ? 401 : general]));
    const requests = run("Verify deployed Policy/v3 routes", statuses, true);
    assert.deepEqual(new Set(requests.map(request => request.path)), new Set(expectedRoutes));
    assert.equal(requests.length, expectedRoutes.length, "each required route must be probed exactly once");
    assert(requests.every(request => request.safeProbe), "probe must be unsigned POST with intentionally empty JSON");
  }
  for (const bad of [200, 400, 422, 500]) {
    run("Verify deployed Policy/v3 routes", { ...defaults, [expectedRoutes.at(-1)]: bad }, false);
  }
  for (const bad of [200, 401, 404, 500]) {
    run("Verify deployed Policy/v3 routes", { ...defaults, [expectedRoutes[0]]: bad }, false);
  }
  run("Verify deployed ingress health", {}, true);
  run("Verify deployed ingress health", {}, false, { version: "1.20.5" });
  run("Verify deployed ingress health", {}, false, { tlsUnready: true });
  console.log(`Deployment probes: ${cases} synthetic response scenarios passed; no network requests.`);
} finally {
  rmSync(directory, { recursive: true, force: true });
}

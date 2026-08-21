import { readFileSync } from "node:fs";

const expectedRoutes = [
  "/policy/v3/enforcer-bindings",
  "/policy/v3/policies",
  "/policy/v3/challenges",
  "/policy/v3/delegations",
];
const workflow = readFileSync(".github/workflows/docker.yml", "utf8");
const source = readFileSync("tinycloud-node-server/src/policy_v3.rs", "utf8");
const probeStart = workflow.indexOf("- name: Verify deployed Policy/v3 routes");
const probeEnd = workflow.indexOf("\n      - name:", probeStart + 1);

if (probeStart === -1) {
  throw new Error("Policy/v3 deployment probe step is missing or malformed");
}

const probe = workflow.slice(probeStart, probeEnd === -1 ? undefined : probeEnd);
const routesBlock = probe.match(/ROUTES=\(\n([\s\S]*?)\n          \)/)?.[1];
const routes = routesBlock?.match(/^\s+(\/\S+)$/gm)?.map((route) => route.trim());

if (JSON.stringify(routes) !== JSON.stringify(expectedRoutes)) {
  throw new Error(`unexpected Policy/v3 deployment probe routes: ${JSON.stringify(routes)}`);
}
for (const route of expectedRoutes) {
  if (!source.includes(`#[post("${route}"`)) {
    throw new Error(`deployment probe route is not a Node-owned POST route: ${route}`);
  }
}
if (probe.includes("/share/")) {
  throw new Error("deployment probe must not use a retired /share/* route");
}
for (const invariant of [
  'NODE_ORIGIN="https://tee.node.tinycloud.xyz"',
  '"${NODE_ORIGIN}/version"',
  "--data '{}'",
  '"${STATUS}" != "400"',
  '"${STATUS}" != "422"',
]) {
  if (!probe.includes(invariant)) {
    throw new Error(`Policy/v3 deployment probe lost required invariant: ${invariant}`);
  }
}

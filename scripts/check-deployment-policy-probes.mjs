import { readFileSync } from "node:fs";

const expectedRoutes = [
  "/policy/v3/enforcer-bindings",
  "/policy/v3/policies",
  "/policy/v3/challenges",
  "/policy/v3/delegations",
  "/policy/v3/deliveries/authorize",
];
const workflow = readFileSync(".github/workflows/docker.yml", "utf8");
const source = readFileSync("tinycloud-node-server/src/policy_v3.rs", "utf8");
const main = readFileSync("tinycloud-node-server/src/main.rs", "utf8");
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
  'if [ "${route}" = "/policy/v3/deliveries/authorize" ]',
  'EXPECTED="401"',
  'EXPECTED="400 or 422"',
  'case "${STATUS}" in 401)',
  'case "${STATUS}" in 400|422)',
]) {
  if (!probe.includes(invariant)) {
    throw new Error(`Policy/v3 deployment probe lost required invariant: ${invariant}`);
  }
}
if (probe.includes("400|401|422")) {
  throw new Error("unsigned delivery probe must require exactly HTTP 401");
}

const imagePinStart = workflow.indexOf("- name: Validate and pin deployment image");
const preflightStart = workflow.indexOf("- name: Preflight sealed runtime configuration");
const deployStart = workflow.indexOf("- name: Deploy to Phala Cloud");
const preflightEnd = workflow.indexOf("\n      - name:", preflightStart + 1);
if (
  imagePinStart === -1 ||
  preflightStart === -1 ||
  deployStart === -1 ||
  imagePinStart > preflightStart ||
  preflightStart > deployStart
) {
  throw new Error("immutable image pin and runtime preflight must precede the Phala deploy");
}
const imagePinEnd = workflow.indexOf("\n      - name:", imagePinStart + 1);
const imagePin = workflow.slice(imagePinStart, imagePinEnd === -1 ? undefined : imagePinEnd);
for (const invariant of [
  "outputs:\n      digest: ${{ steps.build.outputs.digest }}",
  "id: build",
  "BUILD_DIGEST: ${{ needs.build-dstack.outputs.digest }}",
  'RESOLVED_IMAGE="${REGISTRY}/${IMAGE_NAME}@${DIGEST}"',
  'docker pull "${RESOLVED_IMAGE}"',
  '"${REVISION}" != "${GITHUB_SHA}"',
  'os.environ["RESOLVED_IMAGE"]',
]) {
  if (!workflow.includes(invariant)) {
    throw new Error(`immutable candidate deployment invariant is missing: ${invariant}`);
  }
}
if (workflow.includes("- name: Update compose with release tag")) {
  throw new Error("deployment must not select a mutable release tag");
}
if (!imagePin.includes("@${DIGEST}")) {
  throw new Error("compose image replacement must use the immutable build digest");
}
const preflight = workflow.slice(preflightStart, preflightEnd === -1 ? undefined : preflightEnd);
for (const invariant of [
  "TINYCLOUD_STORAGE__DATABASE",
  "TINYCLOUD_SHARE_EMAIL__TRUST_BUNDLE_BASE64",
  "TINYCLOUD_SHARE_EMAIL__POSTGRES_TLS__SSLMODE: verify-full",
  "TINYCLOUD_KEYS__TYPE: Dstack",
  "--network none",
  "--read-only",
  "--cap-drop ALL",
  "--security-opt no-new-privileges",
  "-e TINYCLOUD_STORAGE__DATABASE",
  "TINYCLOUD_SHARE_EMAIL__ENABLED=true",
  "-e TINYCLOUD_SHARE_EMAIL__POSTGRES_TLS__SSLMODE",
  "-e TINYCLOUD_KEYS__TYPE",
  "--validate-config",
]) {
  if (!preflight.includes(invariant)) {
    throw new Error(`runtime configuration preflight lost required invariant: ${invariant}`);
  }
}
for (const invariant of ["resolve_runtime_config", 'arg == "--validate-config"']) {
  if (!main.includes(invariant)) {
    throw new Error(`runtime configuration preflight binary support is missing: ${invariant}`);
  }
}

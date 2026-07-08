#!/usr/bin/env node
// TC-112 capability registry codegen.
//
// Reads capabilities.json (the SSOT) and emits:
//   * tinycloud-core/src/policy_capability/generated.rs — Rust constants,
//     accepted-actions lookup, alias resolution, implication expansion.
//   * generated/capabilities.ts — TypeScript mirror destined for js-sdk.
//
// Run `node scripts/gen-capabilities.mjs` to regenerate, or with `--check` to
// fail if the checked-in artifacts are stale (used by CI).
//
// TC-121: both artifacts also embed REGISTRY_SOURCE_GIT_SHA / REGISTRY_SOURCE_REPO
// so js-sdk's capabilities-sync CI can fetch the matching capabilities.json from
// raw.githubusercontent.com (a content sha256 is not fetchable). The sha is
// GITHUB_SHA when set (CI is authoritative); otherwise `git rev-parse HEAD` at
// gen time, which is approximate: it names the parent of the commit that will
// eventually contain the regenerated artifact (the artifact cannot know its own
// commit). Because the environment's sha differs from the committed artifact's
// sha on every new commit, --check normalizes the REGISTRY_SOURCE_GIT_SHA value
// out of both sides before comparing — everything else must match byte-exact.
// Full regeneration (no --check) always writes the real current sha.

import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const REGISTRY_PATH = join(ROOT, "capabilities.json");
const RUST_OUT = join(ROOT, "tinycloud-core/src/policy_capability/generated.rs");
// The TS mirror is destined for js-sdk; keep it out of the Rust crate's src
// tree so cargo never sees a stray .ts file.
const TS_OUT = join(ROOT, "generated/capabilities.ts");

const raw = readFileSync(REGISTRY_PATH, "utf8");
const registry = JSON.parse(raw);
const sourceHash = createHash("sha256").update(raw).digest("hex");

// TC-121: git rev the artifacts were generated from (see header for semantics).
const SOURCE_REPO = "TinyCloudLabs/tinycloud-node";
function resolveSourceGitSha() {
  const env = process.env.GITHUB_SHA;
  if (env) {
    if (!/^[0-9a-f]{40}$/.test(env)) {
      throw new Error(`GITHUB_SHA is not a 40-char hex sha: ${env}`);
    }
    return env;
  }
  const res = spawnSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" });
  if (res.error || res.status !== 0) {
    const detail = res.error ? res.error.message : res.stderr;
    throw new Error(`git rev-parse HEAD failed: ${detail}`);
  }
  const sha = res.stdout.trim();
  if (!/^[0-9a-f]{40}$/.test(sha)) {
    throw new Error(`unexpected git rev-parse HEAD output: ${sha}`);
  }
  return sha;
}
const sourceGitSha = resolveSourceGitSha();

const caps = registry.capabilities;

// --- Validation (fail loud; the registry is security-critical) ---
const URN_PATTERN = /^[a-z0-9.]+\/[A-Za-z0-9._*]+$/;
const byUrn = new Map();
for (const c of caps) {
  if (byUrn.has(c.urn)) throw new Error(`duplicate URN in registry: ${c.urn}`);
  byUrn.set(c.urn, c);
  if (!URN_PATTERN.test(c.urn)) {
    throw new Error(`URN ${c.urn} does not match ${URN_PATTERN} (see capabilities.schema.json)`);
  }
  if (!c.urn.startsWith(c.service + "/")) {
    throw new Error(`URN ${c.urn} does not match its service ${c.service}`);
  }
  if (c.status === "deprecated-alias" && !c.aliasOf) {
    throw new Error(`deprecated-alias ${c.urn} is missing aliasOf`);
  }
  if (c.status !== "deprecated-alias" && c.aliasOf) {
    throw new Error(`non-alias ${c.urn} has aliasOf`);
  }
}
for (const c of caps) {
  if (c.aliasOf) {
    const target = byUrn.get(c.aliasOf);
    if (!target) throw new Error(`alias ${c.urn} points at unknown URN ${c.aliasOf}`);
    if (target.status === "deprecated-alias") {
      throw new Error(`alias ${c.urn} points at another alias ${c.aliasOf} (aliases must resolve in one hop)`);
    }
    if (target.service !== c.service) {
      throw new Error(`alias ${c.urn} points across services at ${c.aliasOf}`);
    }
  }
  for (const imp of c.implies ?? []) {
    const target = byUrn.get(imp);
    if (!target) throw new Error(`${c.urn} implies unknown URN ${imp}`);
    if (target.service !== c.service) {
      throw new Error(`${c.urn} implies across services: ${imp}`);
    }
  }
}
// Wildcard entries must imply exactly the active concrete actions of their
// service — otherwise a later-added action would be silently missing from
// the wildcard grant (deny-by-default, but a broken SSOT promise).
for (const c of caps) {
  if (!c.urn.endsWith("/*")) continue;
  const want = caps
    .filter((x) => x.service === c.service && x.status === "active" && !x.urn.endsWith("/*"))
    .map((x) => x.urn)
    .sort();
  const got = [...(c.implies ?? [])].sort();
  if (JSON.stringify(got) !== JSON.stringify(want)) {
    throw new Error(
      `wildcard ${c.urn} implies [${got.join(", ")}] but the active actions of ${c.service} are [${want.join(", ")}]`,
    );
  }
}

// --- Derived tables ---
// accepted[service] = sorted list of every URN accepted for that service
// (active + deprecated-alias + reserved). This is the policy-boundary set.
const accepted = new Map();
for (const c of caps) {
  if (!accepted.has(c.service)) accepted.set(c.service, []);
  accepted.get(c.service).push(c.urn);
}
for (const list of accepted.values()) list.sort();
const services = [...accepted.keys()].sort();

// aliases: (aliasUrn -> canonicalUrn), sorted by aliasUrn.
const aliases = caps
  .filter((c) => c.status === "deprecated-alias")
  .map((c) => [c.urn, c.aliasOf])
  .sort((a, b) => (a[0] < b[0] ? -1 : 1));

// implications: (urn -> [implied]), only entries with a non-empty implies.
const implications = caps
  .filter((c) => (c.implies ?? []).length > 0)
  .map((c) => [c.urn, [...c.implies].sort()])
  .sort((a, b) => (a[0] < b[0] ? -1 : 1));

// --- Rust emitter ---
function rustStr(s) {
  return `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

function emitRust() {
  const lines = [];
  lines.push("// @generated by scripts/gen-capabilities.mjs — DO NOT EDIT.");
  lines.push(`// Source: capabilities.json (registry version ${registry.version}, sha256 ${sourceHash}).`);
  lines.push("//");
  lines.push("// Canonical single source of truth for TinyCloud capability action URNs (TC-112).");
  lines.push("// Regenerate with: node scripts/gen-capabilities.mjs");
  lines.push("");
  lines.push(`pub const REGISTRY_VERSION: u32 = ${registry.version};`);
  lines.push(`pub const REGISTRY_SOURCE_SHA256: &str = ${rustStr(sourceHash)};`);
  lines.push("");
  lines.push("/// GitHub repository the registry lives in (TC-121; js-sdk sync anchor).");
  lines.push(`pub const REGISTRY_SOURCE_REPO: &str = ${rustStr(SOURCE_REPO)};`);
  lines.push("/// Git commit the artifact was generated from. Authoritative when generated");
  lines.push("/// in CI (GITHUB_SHA); approximate when generated locally, where it names");
  lines.push("/// the parent of the commit that will contain this artifact.");
  lines.push(`pub const REGISTRY_SOURCE_GIT_SHA: &str = ${rustStr(sourceGitSha)};`);
  lines.push("");
  lines.push("/// Every action URN accepted at the policy boundary for `service`");
  lines.push("/// (active, deprecated-alias, and reserved), sorted. `None` if the");
  lines.push("/// service is unknown to the registry.");
  lines.push("pub fn accepted_actions(service: &str) -> Option<&'static [&'static str]> {");
  lines.push("    match service {");
  for (const service of services) {
    const urns = accepted.get(service).map(rustStr);
    lines.push(`        ${rustStr(service)} => Some(&[`);
    for (const u of urns) lines.push(`            ${u},`);
    lines.push("        ]),");
  }
  lines.push("        _ => None,");
  lines.push("    }");
  lines.push("}");
  lines.push("");
  lines.push("/// Resolve a deprecated alias URN to its canonical URN. Returns the input");
  lines.push("/// unchanged when it is not an alias. Aliases resolve in a single hop.");
  lines.push("pub fn resolve_alias(action: &str) -> &str {");
  lines.push("    match action {");
  for (const [alias, canonical] of aliases) {
    lines.push(`        ${rustStr(alias)} => ${rustStr(canonical)},`);
  }
  lines.push("        other => other,");
  lines.push("    }");
  lines.push("}");
  lines.push("");
  lines.push("/// URNs directly implied by holding `action` (e.g. `sql/admin` implies");
  lines.push("/// `sql/schema`). Empty slice when there are no implications.");
  lines.push("pub fn implied_actions(action: &str) -> &'static [&'static str] {");
  lines.push("    match action {");
  for (const [urn, implied] of implications) {
    lines.push(`        ${rustStr(urn)} => &[${implied.map(rustStr).join(", ")}],`);
  }
  lines.push("        _ => &[],");
  lines.push("    }");
  lines.push("}");
  lines.push("");
  return lines.join("\n");
}

// --- TypeScript emitter ---
function emitTs() {
  const lines = [];
  lines.push("// @generated by scripts/gen-capabilities.mjs — DO NOT EDIT.");
  lines.push(`// Source: capabilities.json (registry version ${registry.version}, sha256 ${sourceHash}).`);
  lines.push("//");
  lines.push("// Canonical single source of truth for TinyCloud capability action URNs (TC-112).");
  lines.push("// Regenerate with: node scripts/gen-capabilities.mjs");
  lines.push("");
  lines.push(`export const REGISTRY_VERSION = ${registry.version} as const;`);
  lines.push(`export const REGISTRY_SOURCE_SHA256 = ${JSON.stringify(sourceHash)} as const;`);
  lines.push("");
  lines.push("/** GitHub repository the registry lives in (TC-121; js-sdk sync anchor). */");
  lines.push(`export const REGISTRY_SOURCE_REPO = ${JSON.stringify(SOURCE_REPO)} as const;`);
  lines.push("/**");
  lines.push(" * Git commit the artifact was generated from. Authoritative when generated");
  lines.push(" * in CI (GITHUB_SHA); approximate when generated locally, where it names");
  lines.push(" * the parent of the commit that will contain this artifact.");
  lines.push(" */");
  lines.push(`export const REGISTRY_SOURCE_GIT_SHA = ${JSON.stringify(sourceGitSha)} as const;`);
  lines.push("");
  lines.push("export type CapabilityStatus = \"active\" | \"deprecated-alias\" | \"reserved\";");
  lines.push("");
  lines.push("export interface CapabilityEntry {");
  lines.push("  urn: string;");
  lines.push("  service: string;");
  lines.push("  status: CapabilityStatus;");
  lines.push("  aliasOf?: string;");
  lines.push("  implies?: readonly string[];");
  lines.push("}");
  lines.push("");
  lines.push("export const CAPABILITIES: readonly CapabilityEntry[] = [");
  for (const c of caps) {
    const parts = [`urn: ${JSON.stringify(c.urn)}`, `service: ${JSON.stringify(c.service)}`, `status: ${JSON.stringify(c.status)}`];
    if (c.aliasOf) parts.push(`aliasOf: ${JSON.stringify(c.aliasOf)}`);
    if ((c.implies ?? []).length > 0) parts.push(`implies: [${c.implies.map((i) => JSON.stringify(i)).join(", ")}]`);
    lines.push(`  { ${parts.join(", ")} },`);
  }
  lines.push("] as const;");
  lines.push("");
  lines.push("/// Every action URN accepted at the policy boundary for a service");
  lines.push("/// (active, deprecated-alias, and reserved), sorted.");
  lines.push("export const ACCEPTED_ACTIONS: Readonly<Record<string, readonly string[]>> = {");
  for (const service of services) {
    const urns = accepted.get(service).map((u) => JSON.stringify(u));
    lines.push(`  ${JSON.stringify(service)}: [${urns.join(", ")}],`);
  }
  lines.push("};");
  lines.push("");
  lines.push("/// aliasUrn -> canonical URN.");
  lines.push("export const ALIASES: Readonly<Record<string, string>> = {");
  for (const [alias, canonical] of aliases) {
    lines.push(`  ${JSON.stringify(alias)}: ${JSON.stringify(canonical)},`);
  }
  lines.push("};");
  lines.push("");
  lines.push("/// urn -> directly implied URNs.");
  lines.push("export const IMPLICATIONS: Readonly<Record<string, readonly string[]>> = {");
  for (const [urn, implied] of implications) {
    lines.push(`  ${JSON.stringify(urn)}: [${implied.map((i) => JSON.stringify(i)).join(", ")}],`);
  }
  lines.push("};");
  lines.push("");
  lines.push("/// Resolve a deprecated alias to its canonical URN (single hop).");
  lines.push("export function resolveAlias(action: string): string {");
  lines.push("  return ALIASES[action] ?? action;");
  lines.push("}");
  lines.push("");
  lines.push("/// URNs directly implied by holding `action`.");
  lines.push("export function impliedActions(action: string): readonly string[] {");
  lines.push("  return IMPLICATIONS[action] ?? [];");
  lines.push("}");
  lines.push("");
  return lines.join("\n");
}

// Run the emitted Rust through rustfmt so the checked-in artifact matches
// `cargo fmt` exactly (otherwise CI's fmt job and this --check disagree).
// rustfmt is part of the standard Rust toolchain and is required here.
function rustfmt(src) {
  const res = spawnSync("rustfmt", ["--edition", "2021", "--emit", "stdout"], {
    input: src,
    encoding: "utf8",
  });
  if (res.error || res.status !== 0) {
    const detail = res.error ? res.error.message : res.stderr;
    throw new Error(
      `rustfmt failed (is the Rust toolchain installed?): ${detail}`,
    );
  }
  return res.stdout;
}

const rust = rustfmt(emitRust());
const ts = emitTs();

// --check must not fail merely because the current environment's git sha
// differs from the one embedded in the committed artifact (every CI run on a
// new commit would otherwise report the artifacts stale). Normalize the
// REGISTRY_SOURCE_GIT_SHA value out of both sides before comparing; every
// other byte must still match exactly. A malformed committed sha does not
// match the regex, so it is not normalized and --check fails as it should.
function normalizeGitSha(s) {
  return s.replace(
    /(REGISTRY_SOURCE_GIT_SHA[^=\n]*= ")[0-9a-f]{40}(")/g,
    "$1<git-sha>$2",
  );
}

const check = process.argv.includes("--check");
if (check) {
  let stale = false;
  for (const [path, want] of [[RUST_OUT, rust], [TS_OUT, ts]]) {
    let got = "";
    try {
      got = readFileSync(path, "utf8");
    } catch {
      got = "";
    }
    if (normalizeGitSha(got) !== normalizeGitSha(want)) {
      console.error(`stale generated artifact: ${path}`);
      stale = true;
    }
  }
  if (stale) {
    console.error("Run `node scripts/gen-capabilities.mjs` and commit the result.");
    process.exit(1);
  }
  console.log("capability artifacts are up to date.");
} else {
  writeFileSync(RUST_OUT, rust);
  writeFileSync(TS_OUT, ts);
  console.log(`wrote ${RUST_OUT}`);
  console.log(`wrote ${TS_OUT}`);
}

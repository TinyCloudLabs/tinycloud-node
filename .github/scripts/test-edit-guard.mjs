#!/usr/bin/env node
// Test-edit guard (TC-1933). Fails a pull request that removes or changes any
// line in a test file that already exists at the merge base, unless the PR body
// has a ruling line:
//
//   test-ruling: TC-123
//
// (key is case-insensitive; the line must start with it, matching
// /^test-ruling: TC-[0-9]+/im). New test files and pure additions to existing
// test files always pass. Every removed line counts, whitespace-only changes
// included. Deleting an existing test file counts as an edit. A renamed test
// file is a delete plus an add, so it counts too (diffs run with --no-renames).
//
// Test files in this repo (CONFIG.testPatterns below; the only part of this
// script that differs between repos):
//   *.test.* / *.spec.* for js, jsx, ts, tsx, mjs, cjs
//   anything under a tests/, test/ or __tests__/ directory
//   tests.rs (the file behind `#[cfg(test)] mod tests;`)
//   *_test.rs / *_tests.rs
//
// Rust: a file that is not a test file but contains a `#[cfg(test)]` (or
// `#![cfg(test)]`) line is only counted for removed lines at or after the FIRST
// such line in the merge-base version of the file. This is deliberately cheap
// (no brace matching): code after a `#[cfg(test)]` that is not the test module
// is over-counted, and edits before the first `#[cfg(test)]` are never counted.
// Usage (CI): BASE_REF=main HEAD_SHA=<sha> PR_BODY="$body" node test-edit-guard.mjs
//   HEAD_SHA defaults to HEAD. Needs a full-history checkout with origin/$BASE_REF.
// Self-test: node test-edit-guard.mjs --self-test   (fixture diffs, no git, no files)
// No dependencies, no network, no secrets. Every git call has a timeout.

import { execFileSync } from "node:child_process";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const CONFIG = {
  testPatterns: [
    /\.(test|spec)\.[cm]?[jt]sx?$/,
    /(^|\/)(__tests__|tests?)\//,
    /(^|\/)tests\.rs$/,
    /_tests?\.rs$/,
  ],
  rustCfgTest: true,
  // Self-test only: paths that must / must not be classified as test files.
  examples: {
    test: [
      "tinycloud-node-server/tests/startup_identity.rs",
      "tinycloud-core/tests/fixtures/x.json",
      "test/probe/run.mjs",
      "scripts/tc959-docker.test.mjs",
      "tinycloud-node-server/src/policy_v3/tests.rs"
    ],
    notTest: [
      "tinycloud-core/src/lib.rs",
      "scripts/tc959-docker.mjs",
      ".github/scripts/test-edit-guard.mjs",
      "tinycloud-core/src/latest.rs"
    ],
  },
};

const RULING_RE = /^test-ruling: TC-[0-9]+/im;
const RULING_LINE = "test-ruling: TC-<N>";
const GIT_TIMEOUT_MS = 60_000;

export function hasRuling(body) {
  return RULING_RE.test(body ?? "");
}

// Parse `git diff -U0` output into [{ path, deleted, binary, removed: [oldLineNo] }].
export function parseDiff(text) {
  const files = [];
  let cur = null;
  let oldNo = 0;
  let oldLeft = 0;
  let newLeft = 0;
  for (const line of text.split("\n")) {
    if (oldLeft > 0 || newLeft > 0) {
      const c = line[0];
      if (c === "-") { cur.removed.push(oldNo++); oldLeft--; continue; }
      if (c === "+") { newLeft--; continue; }
      if (c === " ") { oldNo++; oldLeft--; newLeft--; continue; }
      if (c === "\\") continue;
      oldLeft = newLeft = 0; // malformed hunk: resync on headers
    }
    if (line.startsWith("diff --git ")) {
      // Both sides share one path because renames are disabled: "a/P b/P".
      const rest = line.slice("diff --git a/".length);
      cur = { path: rest.slice(0, (rest.length - 3) / 2), deleted: false, binary: false, removed: [] };
      files.push(cur);
    } else if (!cur) {
      continue;
    } else if (line.startsWith("deleted file mode")) {
      cur.deleted = true;
    } else if (line.startsWith("Binary files ")) {
      cur.binary = true;
    } else {
      const m = /^@@ -(\d+)(?:,(\d+))? \+\d+(?:,(\d+))? @@/.exec(line);
      if (m) {
        oldNo = Number(m[1]);
        oldLeft = m[2] === undefined ? 1 : Number(m[2]);
        newLeft = m[3] === undefined ? 1 : Number(m[3]);
      }
    }
  }
  return files;
}

function firstCfgTestLine(source) {
  const idx = source.split("\n").findIndex((l) => /^\s*#!?\[cfg\(test\)\]/.test(l));
  return idx < 0 ? 0 : idx + 1;
}

// Returns [{ path, removed, deleted }] for edited existing test files.
export function findEdits(files, config, readBase) {
  const isTest = (p) => config.testPatterns.some((re) => re.test(p));
  const hits = [];
  for (const f of files) {
    if (isTest(f.path)) {
      const removed = f.removed.length + (f.binary ? 1 : 0);
      if (removed > 0 || f.deleted) hits.push({ path: f.path, removed, deleted: f.deleted });
    } else if (config.rustCfgTest && f.path.endsWith(".rs") && f.removed.length > 0) {
      const first = firstCfgTestLine(readBase(f.path));
      const removed = first ? f.removed.filter((n) => n >= first).length : 0;
      if (removed > 0) hits.push({ path: f.path, removed, deleted: false });
    }
  }
  return hits;
}

export function check({ diffText, body, config, readBase }) {
  const hits = findEdits(parseDiff(diffText), config, readBase);
  if (hits.length === 0) return { pass: true, hits, report: "test-edit-guard: no existing test lines removed or changed." };
  const list = hits
    .map((h) => `  ${h.path}: ${h.removed} removed line(s)${h.deleted ? " (file deleted)" : ""}`)
    .join("\n");
  if (hasRuling(body)) {
    return { pass: true, hits, report: `test-edit-guard: existing tests edited, PR body names a ruling.\n${list}` };
  }
  const report = [
    "test-edit-guard: this PR removes or changes lines in existing test files:",
    list,
    "",
    "An edit to an existing test needs a ruling. Add this line to the PR body",
    "(replace N with the Linear issue that records the ruling):",
    "",
    `  ${RULING_LINE}`,
    "",
    "The check re-runs when the PR body is edited.",
  ].join("\n");
  return { pass: false, hits, report };
}

function git(args) {
  return execFileSync("git", args, {
    encoding: "utf8",
    timeout: GIT_TIMEOUT_MS,
    maxBuffer: 512 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function main() {
  const baseRef = process.env.BASE_REF;
  if (!baseRef) throw new Error("BASE_REF is required (the PR base branch name)");
  const head = process.env.HEAD_SHA || "HEAD";
  const mergeBase = git(["merge-base", `origin/${baseRef}`, head]).trim();
  const diffText = git([
    "-c", "core.quotepath=false",
    "diff", "--no-renames", "--no-color", "--no-ext-diff", "--no-textconv", "-U0",
    "--diff-filter=MDT", "--src-prefix=a/", "--dst-prefix=b/",
    mergeBase, head,
  ]);
  const { pass, report } = check({
    diffText,
    body: process.env.PR_BODY,
    config: CONFIG,
    readBase: (p) => git(["show", `${mergeBase}:${p}`]),
  });
  console.log(report);
  if (!pass) console.log("::error title=test-edit-guard::Existing tests edited without a test-ruling line in the PR body");
  process.exit(pass ? 0 : 1);
}

// ---- self-test -------------------------------------------------------------

function selfTest() {
  const cfg = { testPatterns: [/\.test\.ts$/, /(^|\/)tests\//], rustCfgTest: true };
  const hdr = (p) => `diff --git a/${p} b/${p}\nindex 111..222 100644\n--- a/${p}\n+++ b/${p}\n`;
  const T = "src/a.test.ts";
  const diffs = {
    pureAddition: `${hdr(T)}@@ -10,0 +11,2 @@ describe\n+  it("x", () => {});\n+\n`,
    newFile: `diff --git a/src/new.test.ts b/src/new.test.ts\nnew file mode 100644\nindex 000..222\n--- /dev/null\n+++ b/src/new.test.ts\n@@ -0,0 +1,2 @@\n+a\n+b\n`,
    removedLine: `${hdr(T)}@@ -3 +2,0 @@\n-  expect(a).toBe(1);\n`,
    changedLine: `${hdr(T)}@@ -3 +3 @@\n-  expect(a).toBe(1);\n+  expect(a).toBe(2);\n`,
    whitespaceOnly: `${hdr(T)}@@ -3 +3 @@\n-  expect(a).toBe(1);\n+expect(a).toBe(1);\n`,
    deletedFile: `diff --git a/${T} b/${T}\ndeleted file mode 100644\nindex 111..000\n--- a/${T}\n+++ /dev/null\n@@ -1,2 +0,0 @@\n-a\n-b\n`,
    deletedEmptyFile: `diff --git a/tests/empty.ts b/tests/empty.ts\ndeleted file mode 100644\nindex e69de29..000\n`,
    nonTestEdit: `${hdr("src/a.ts")}@@ -3 +3 @@\n-a\n+b\n`,
    dashDashLine: `${hdr(T)}@@ -5 +4,0 @@\n--- not a header\n`,
    twoFiles: `${hdr(T)}@@ -3,2 +3,0 @@\n-x\n-y\n${hdr("tests/b.ts")}@@ -1 +1 @@\n-p\n+q\n`,
    rustInCfgTest: `${hdr("src/lib.rs")}@@ -12 +12 @@\n-    assert_eq!(a, 1);\n+    assert_eq!(a, 2);\n`,
    rustBeforeCfgTest: `${hdr("src/lib.rs")}@@ -2 +2 @@\n-fn a() {}\n+fn b() {}\n`,
    rustNoCfgTest: `${hdr("src/other.rs")}@@ -12 +12 @@\n-x\n+y\n`,
  };
  const rustSrc = "fn a() {}\n\n".concat("x\n".repeat(7), "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(a, 1);\n    }\n}\n");
  const readBase = (p) => (p === "src/lib.rs" ? rustSrc : "fn x() {}\n");
  const run = (diffText, body) => check({ diffText, body, config: cfg, readBase });
  const RULED = "Fixes things.\ntest-ruling: TC-123\n";
  let n = 0;
  const t = (name, fn) => { fn(); n++; console.log(`ok - ${name}`); };

  t("pure addition passes", () => assert.equal(run(diffs.pureAddition, "").pass, true));
  t("new file passes", () => assert.equal(run(diffs.newFile, "").pass, true));
  t("non-test file edit passes", () => assert.equal(run(diffs.nonTestEdit, "").pass, true));
  t("removed line fails", () => {
    const r = run(diffs.removedLine, "");
    assert.equal(r.pass, false);
    assert.deepEqual(r.hits, [{ path: T, removed: 1, deleted: false }]);
    assert.match(r.report, /src\/a\.test\.ts: 1 removed/);
    assert.match(r.report, /test-ruling: TC-<N>/);
  });
  t("changed line fails", () => assert.equal(run(diffs.changedLine, "").pass, false));
  t("whitespace-only change fails", () => assert.equal(run(diffs.whitespaceOnly, "").pass, false));
  t("deleted test file fails", () => {
    const r = run(diffs.deletedFile, "");
    assert.equal(r.pass, false);
    assert.deepEqual(r.hits, [{ path: T, removed: 2, deleted: true }]);
  });
  t("deleted empty test file fails", () => assert.equal(run(diffs.deletedEmptyFile, "").pass, false));
  t("removed line starting with dashes is counted once", () => {
    assert.deepEqual(run(diffs.dashDashLine, "").hits, [{ path: T, removed: 1, deleted: false }]);
  });
  t("every edited file is listed with its count", () => {
    assert.deepEqual(run(diffs.twoFiles, "").hits.map((h) => [h.path, h.removed]), [[T, 2], ["tests/b.ts", 1]]);
  });
  t("removed line + test-ruling: TC-123 passes", () => {
    const r = run(diffs.removedLine, RULED);
    assert.equal(r.pass, true);
    assert.equal(r.hits.length, 1);
  });
  t("ruling key is case-insensitive", () => assert.equal(run(diffs.removedLine, "Test-Ruling: TC-9").pass, true));
  for (const bad of [
    "test-ruling: TC-",
    "test-ruling: TC-abc",
    "test-ruling TC-123",
    "test-ruling: 123",
    "test-ruling:TC-123",
    " test-ruling: TC-123",
    "see test-ruling: TC-123",
    "ruling: TC-123",
    "",
    null,
    undefined,
  ]) {
    t(`malformed ruling fails: ${JSON.stringify(bad)}`, () => assert.equal(run(diffs.removedLine, bad).pass, false));
  }
  t("CRLF body ruling passes", () => assert.equal(run(diffs.removedLine, "x\r\ntest-ruling: TC-5\r\n").pass, true));
  t("rust: removed line inside #[cfg(test)] fails", () => {
    const r = run(diffs.rustInCfgTest, "");
    assert.equal(r.pass, false);
    assert.deepEqual(r.hits, [{ path: "src/lib.rs", removed: 1, deleted: false }]);
  });
  t("rust: removed line before #[cfg(test)] passes", () => assert.equal(run(diffs.rustBeforeCfgTest, "").pass, true));
  t("rust: file without #[cfg(test)] passes", () => assert.equal(run(diffs.rustNoCfgTest, "").pass, true));
  t("rust: rustCfgTest=false ignores cfg(test)", () => {
    const r = check({ diffText: diffs.rustInCfgTest, body: "", config: { ...cfg, rustCfgTest: false }, readBase });
    assert.equal(r.pass, true);
  });
  for (const p of CONFIG.examples.test) {
    t(`repo pattern: ${p} is a test file`, () => assert.ok(CONFIG.testPatterns.some((re) => re.test(p))));
  }
  for (const p of CONFIG.examples.notTest) {
    t(`repo pattern: ${p} is not a test file`, () => assert.ok(!CONFIG.testPatterns.some((re) => re.test(p))));
  }
  console.log(`test-edit-guard self-test: ${n} passed`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  if (process.argv.includes("--self-test")) selfTest();
  else main();
}

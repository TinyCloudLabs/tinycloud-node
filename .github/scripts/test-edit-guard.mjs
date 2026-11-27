#!/usr/bin/env node
// Test changes are reviewed with their implementation in the same PR. This
// advisory lists changed or removed coverage and changes to its own files; it
// does not require a separate ticket or claim to prove assertion equivalence.
// Formatting, imports and fixtures follow ordinary review. Explain intended
// behavior changes and replacement coverage in the PR. No approval marker can
// substitute for the tests running or for a review of weakened assertions.
//
// Known limitation: git quotes paths containing a tab, quote or backslash in the
// `diff --git` header and this script does not unquote them, so such a file may
// not be classified correctly. No such paths exist in this repo today.
//
// Test files in this repo (CONFIG.testPatterns below; the only part of this
// script that differs between repos):
//   *.test.* / *.spec.* for js, jsx, ts, tsx, mjs, cjs
//   anything under a tests/, test/ or __tests__/ directory (helpers, scripts and fixtures included)
//   fixture and test-data directories: test-fixtures/, fixtures/, __fixtures__/, testdata/, test-support/
//   test helper scripts: test-*.sh, test_*.py (and test-*.py, test_*.sh)
//   *_test.sh / *_test.py
//   tests.rs (the file behind `#[cfg(test)] mod tests;`)
//   *_test.rs / *_tests.rs
//   test_*.rs helpers (test_support.rs, test_harness.rs)
//
// Rust: a file that is not a test file but contains a `#[cfg(test)]` (or
// `#![cfg(test)]`) line is only counted for removed lines at or after the FIRST
// such line in the merge-base version of the file. This is deliberately cheap
// (no brace matching): code after a `#[cfg(test)]` that is not the test module
// is over-counted, and edits before the first `#[cfg(test)]` are never counted.
//
// Usage (CI): BASE_REF=main HEAD_SHA=<sha> node test-edit-guard.mjs
//   HEAD_SHA defaults to HEAD. Needs a full-history checkout with origin/$BASE_REF.
// Self-test: node test-edit-guard.mjs --self-test   (fixture diffs, no git, no files)
// No dependencies, no network, no secrets. Every git call has a timeout.

import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";

const CONFIG = {
  testPatterns: [
    /\.(test|spec)\.[cm]?[jt]sx?$/,
    /(^|\/)(__tests__|tests?)\//,
    /(^|\/)(test-fixtures|fixtures|__fixtures__|testdata|test-support)\//,
    /(^|\/)test[-_][^/]*\.(sh|py)$/,
    /_test\.(sh|py)$/,
    /(^|\/)tests\.rs$/,
    /_tests?\.rs$/,
    /(^|\/)test_[^/]*\.rs$/,
  ],
  rustCfgTest: true,
  // Self-test only: paths that must / must not be classified as test files.
  examples: {
    test: [
      "tinycloud-node-server/tests/startup_identity.rs",
      "tinycloud-core/tests/fixtures/x.json",
      "test/probe/run.mjs",
      "scripts/tc959-docker.test.mjs",
      "tinycloud-node-server/src/policy_v3/tests.rs",
      "tinycloud-core/src/test_harness.rs",
      "x/test-fixtures/golden.json",
      "pkg/fixtures/a.ts",
      "pkg/__fixtures__/b.json",
      "pkg/testdata/c.txt",
      "scripts/ci/test-redact.sh",
      "mobile/scripts/test_fixtures.py"
    ],
    notTest: [
      "tinycloud-core/src/lib.rs",
      "scripts/tc959-docker.mjs",
      "tinycloud-core/src/latest.rs",
      ".github/scripts/test-edit-guard.mjs",
      "docs/testing.md"
    ],
  },
};

const GIT_TIMEOUT_MS = 60_000;
const GUARD_FILES = [".github/scripts/test-edit-guard.mjs", ".github/workflows/test-edit-guard.yml"];

// Parse `git diff -U0` output into [{ path, deleted, binary, added, removed: [oldLineNo] }].
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
      if (c === "+") { cur.added++; newLeft--; continue; }
      if (c === " ") { oldNo++; oldLeft--; newLeft--; continue; }
      if (c === "\\") continue;
      oldLeft = newLeft = 0; // malformed hunk: resync on headers
    }
    if (line.startsWith("diff --git ")) {
      // Both sides share one path because renames are disabled: "a/P b/P".
      const rest = line.slice("diff --git a/".length);
      cur = { path: rest.slice(0, (rest.length - 3) / 2), deleted: false, created: false, binary: false, added: 0, removed: [] };
      files.push(cur);
    } else if (!cur) {
      continue;
    } else if (line.startsWith("new file mode")) {
      cur.created = true;
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

// Returns [{ path, removed, deleted }] for edited existing test files, plus
// [{ path, removed, deleted, guard: true }] for any changed guard file.
export function findEdits(files, config, readBase) {
  const isTest = (p) => config.testPatterns.some((re) => re.test(p));
  const hits = [];
  for (const f of files) {
    if (GUARD_FILES.includes(f.path)) {
      if (!f.created && (f.removed.length > 0 || f.added > 0 || f.deleted || f.binary)) {
        hits.push({ path: f.path, removed: f.removed.length, deleted: f.deleted, guard: true });
      }
    } else if (isTest(f.path)) {
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

export function check({ diffText, config, readBase }) {
  const hits = findEdits(parseDiff(diffText), config, readBase);
  if (hits.length === 0) return { pass: true, hits, report: "test-edit-guard: no existing test lines removed or changed." };
  const list = hits.map(h => `  ${h.path}: ${h.removed} removed line(s)${h.deleted ? " (file deleted)" : ""}${h.guard ? " (review tooling changed)" : ""}`).join("\n");
  return {
    pass: true, hits,
    report: [
      "Test changes for review (advisory):", list, "",
      "Review removed assertions and replacement coverage with the implementation.",
      "Explain changed behavior and validation in this PR; no separate ruling is required.",
      "This line-based report does not establish whether coverage was weakened.",
    ].join("\n"),
  };
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
  const { report } = check({
    diffText,
    config: CONFIG,
    readBase: (p) => git(["show", `${mergeBase}:${p}`]),
  });
  console.log(report);
  if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, report + "\n");
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
    guardScriptEdit: `${hdr(GUARD_FILES[0])}@@ -40 +40 @@\n-const GIT_TIMEOUT_MS = 60_000;\n+const GIT_TIMEOUT_MS = 600_000;\n`,
    guardScriptAddition: `${hdr(GUARD_FILES[0])}@@ -10,0 +11 @@\n+process.exit(0);\n`,
    guardWorkflowEdit: `${hdr(GUARD_FILES[1])}@@ -5 +5 @@\n-    timeout-minutes: 10\n+    timeout-minutes: 99\n`,
    guardScriptDeleted: `diff --git a/${GUARD_FILES[0]} b/${GUARD_FILES[0]}\ndeleted file mode 100644\nindex 111..000\n--- a/${GUARD_FILES[0]}\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n`,
    guardFileNew: `diff --git a/${GUARD_FILES[0]} b/${GUARD_FILES[0]}\nnew file mode 100644\nindex 000..222\n--- /dev/null\n+++ b/${GUARD_FILES[0]}\n@@ -0,0 +1 @@\n+x\n`,
  };
  const rustSrc = "fn a() {}\n\n".concat("x\n".repeat(7), "#[cfg(test)]\nmod tests {\n    #[test]\n    fn t() {\n        assert_eq!(a, 1);\n    }\n}\n");
  const readBase = (p) => (p === "src/lib.rs" ? rustSrc : "fn x() {}\n");
  const run = (diffText, body) => check({ diffText, body, config: cfg, readBase });
  let n = 0;
  const t = (name, fn) => { fn(); n++; console.log(`ok - ${name}`); };
  for (const name of ["pureAddition", "newFile", "nonTestEdit", "rustBeforeCfgTest", "rustNoCfgTest", "guardFileNew"]) {
    t(`${name}: no removed coverage`, () => {
      const r = run(diffs[name]);
      assert.equal(r.pass, true);
      assert.deepEqual(r.hits, []);
    });
  }
  for (const name of ["removedLine", "changedLine", "whitespaceOnly", "deletedFile", "deletedEmptyFile", "dashDashLine", "twoFiles", "rustInCfgTest", "guardScriptEdit", "guardScriptAddition", "guardWorkflowEdit", "guardScriptDeleted"]) {
    t(`${name}: visible to review without a separate ruling`, () => {
      const r = run(diffs[name]);
      assert.equal(r.pass, true);
      assert.ok(r.hits.length > 0);
      assert.match(r.report, /Review removed assertions and replacement coverage/);
    });
  }
  t("removed assertion names its file and count", () => {
    assert.deepEqual(run(diffs.removedLine).hits, [{ path: T, removed: 1, deleted: false }]);
    assert.match(run(diffs.removedLine).report, /src\/a\.test\.ts: 1 removed/);
  });
  t("Rust inline test changes remain visible", () => {
    assert.deepEqual(run(diffs.rustInCfgTest).hits, [{ path: "src/lib.rs", removed: 1, deleted: false }]);
  });
  t("a ruling marker does not hide removed coverage", () => {
    assert.deepEqual(run(diffs.removedLine, "test-ruling: TC-123"), run(diffs.removedLine, ""));
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

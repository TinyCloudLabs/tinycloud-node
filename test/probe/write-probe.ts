/**
 * TC-313 + TC-1176: synthetic end-to-end probe for the TinyCloud prod node.
 *
 * WHY THIS EXISTS
 * ---------------
 * 2026-07-27/28 (TC-313): `/healthz` returned 200 in ~300ms while `kv.put`
 * took 46s and `/delegate` blew past Cloudflare's 100s ceiling.
 * 2026-10-14 (TC-1176): signed-in KV reads and SQL hung ~62s (504) for every
 * account while `/healthz`, `/version`, 401s and writes stayed green. This
 * probe failed twice during that window and nobody was paged.
 *
 * WHAT IT DOES (normal mode, every scheduled run)
 * -----------------------------------------------
 * Read half — the alerting signal. Each stage has a hard 20s client deadline:
 *   signin  SIWE sign-in + delegation activation
 *   space   ensure the probe's own space exists (idempotent)
 *   kv      signed-in read of a fixed key (written once, on first run)
 *   sql     signed-in `SELECT` of a fixed row (created once, on first run)
 * A good read pings the Better Stack heartbeat. A failed read is counted in a
 * state file; from the 2nd failure in a row the probe POSTs the heartbeat's
 * `/fail` URL with one line naming the stage, outcome, duration, node build
 * and UTC time (see probe-core.ts `failBody`).
 *
 * Write half — TC-313's original round-trip (put -> get -> delete), each with
 * its latency threshold and the same 20s deadline. A breach fails the job
 * (GitHub e-mail) but does not touch the heartbeat.
 *
 * DENSE MODE (`PROBE_MODE=dense`, the post-promote watch)
 * --------------------------------------------------------
 * Reads every 30s for 5 min, then every 5 min for 60 min; a read over 5s or
 * any failure counts, 2 in a row POST `/fail`. See probe-core.ts `denseWatch`.
 *
 * IDENTITY / SECRETS
 * ------------------
 * PROBE_PRIVATE_KEY (GitHub secret) is a THROWAWAY key operating only in its
 * own probe space (PREFIX). BETTERSTACK_HEARTBEAT_URL (GitHub secret) is the
 * heartbeat's secret URL. Neither is ever printed: errors are reduced to a
 * classified outcome and raw details are redacted.
 */

import { mkdir, readFile, writeFile, appendFile } from "node:fs/promises";
import { dirname } from "node:path";
import { TinyCloudNode } from "@tinycloud/node-sdk";
import {
  STAGE_DEADLINE_MS,
  decide,
  denseWatch,
  detail,
  failBody,
  heartbeatUrl,
  measure,
  nodeBuild,
  parseState,
  readCheck,
  report,
  summaryTable,
  type ReadClient,
  type Reporter,
  type StageResult,
} from "./probe-core";

// ---- configuration (env-overridable) ---------------------------------------

// The workflow wires optional overrides straight from secrets/vars, which
// arrive as EMPTY STRINGS when unset — and `??` only falls back on
// null/undefined. Treat blank values as absent, otherwise HOST/PREFIX go empty
// and Number("") coerces every threshold to 0 (instant breach).
function envStr(name: string, fallback: string): string {
  const v = process.env[name];
  return v !== undefined && v.trim() !== "" ? v : fallback;
}
function envMs(name: string, fallback: number): number {
  const v = process.env[name];
  if (v === undefined || v.trim() === "") return fallback;
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) {
    throw new Error(`[probe] ${name} must be a positive number, got "${v}"`);
  }
  return n;
}

const MODE = envStr("PROBE_MODE", "normal");
// `force_failure` dispatch input: a host under the reserved .invalid TLD, so
// the run fails at DNS and exercises the alert path end to end.
const FORCED_FAILURE_HOST = "https://read-probe-forced-failure.invalid";
const HOST = envStr("PROBE_FORCE_FAILURE", "") === "true" ? FORCED_FAILURE_HOST : envStr("PROBE_HOST", "https://node.tinycloud.xyz");
// Dedicated, isolated space prefix for the probe identity.
const PREFIX = envStr("PROBE_PREFIX", "tc313-write-probe");
const STATE_FILE = envStr("PROBE_STATE_FILE", ".state/probe-state.json");

const WRITE_THRESHOLDS_MS = {
  put: envMs("PROBE_THRESHOLD_PUT_MS", 5_000),
  get: envMs("PROBE_THRESHOLD_GET_MS", 5_000),
  delete: envMs("PROBE_THRESHOLD_DELETE_MS", 5_000),
} as const;

// The fixed read targets. Written once by the probe itself, then only read.
const FIXED_KEY = "read-probe/fixed";
const FIXED_VALUE = "tc1176-read-probe-v1";
const SQL_SELECT = "SELECT v FROM read_probe WHERE id = 1";

class ReadBackMismatch extends Error {
  constructor(what: string) {
    super(`${what} read-back did not match the fixed value`);
    this.name = "ReadBackMismatch";
  }
}

type Result<T> = { ok: true; data: T } | { ok: false; error: unknown };

// A failed SDK call surfaces as its ServiceError (code, meta.status, cause),
// which classify() turns into "HTTP 504", "connection refused", "DNS", ...
function unwrap<T>(result: Result<T>): T {
  if (!result.ok) throw result.error;
  return result.data;
}

function errorCode(result: Result<unknown>): string | undefined {
  if (result.ok || !result.error || typeof result.error !== "object" || !("code" in result.error)) return undefined;
  return typeof result.error.code === "string" ? result.error.code : undefined;
}

function sdkClient(node: TinyCloudNode): ReadClient {
  let kvProvisioned = false;
  let sqlProvisioned = false;
  return {
    signIn: () => node.signIn(),
    ensureSpace: async () => {
      await node.hostOwnedSpace(PREFIX);
    },
    async kvRead() {
      let got = await node.kv.get(FIXED_KEY);
      if (errorCode(got) === "KV_NOT_FOUND" && !kvProvisioned) {
        kvProvisioned = true;
        unwrap(await node.kv.put(FIXED_KEY, FIXED_VALUE));
        got = await node.kv.get(FIXED_KEY);
      }
      if (unwrap<{ data: unknown }>(got).data !== FIXED_VALUE) throw new ReadBackMismatch("kv");
    },
    async sqlRead() {
      // Rows are arrays of cell values ({ columns, rows: unknown[][], rowCount }).
      let rows = await node.sql.query<unknown>(SQL_SELECT);
      const missing = ["SQL_ERROR", "SQL_DATABASE_NOT_FOUND"].includes(errorCode(rows) ?? "") || (rows.ok && rows.data.rowCount === 0);
      if (missing && !sqlProvisioned) {
        sqlProvisioned = true;
        unwrap(await node.sql.execute("CREATE TABLE IF NOT EXISTS read_probe (id INTEGER PRIMARY KEY, v TEXT NOT NULL)"));
        unwrap(await node.sql.execute("INSERT OR REPLACE INTO read_probe (id, v) VALUES (1, ?)", [FIXED_VALUE]));
        rows = await node.sql.query<unknown>(SQL_SELECT);
      }
      if (unwrap(rows).rows[0]?.[0] !== FIXED_VALUE) throw new ReadBackMismatch("sql");
    },
  };
}

async function writeSummary(markdown: string): Promise<void> {
  const path = process.env.GITHUB_STEP_SUMMARY;
  if (path) await appendFile(path, `${markdown}\n`);
}

// ---- normal (scheduled) run ----------------------------------------------------

async function normalRun(node: TinyCloudNode, client: ReadClient, reporter: Reporter, secrets: string[]): Promise<boolean> {
  const log = (line: string) => console.log(line);
  const { results, failure } = await readCheck(client, { log, secrets });

  const prev = parseState(await readFile(STATE_FILE, "utf8").catch(() => undefined));
  const decision = decide(prev, !failure, Date.now());
  console.log(
    `[probe] read verdict=${failure ? "fail" : "ok"} consecutive_failures=${decision.state.consecutiveFailures} heartbeat_action=${decision.action}`,
  );
  if (decision.action !== "none") await reporter(decision.action, failure, decision.state.consecutiveFailures);
  await mkdir(dirname(STATE_FILE), { recursive: true });
  await writeFile(STATE_FILE, `${JSON.stringify(decision.state)}\n`);

  // Write half (TC-313). Needs a signed-in session in an existing space.
  const writes: StageResult[] = [];
  if (!failure || (failure.stage !== "signin" && failure.stage !== "space")) {
    const key = `probe/${Date.now()}`;
    const value = `tc313-${Date.now()}`;
    const stages: [keyof typeof WRITE_THRESHOLDS_MS, () => Promise<unknown>][] = [
      ["put", async () => unwrap(await node.kv.put(key, value))],
      [
        "get",
        async () => {
          if (unwrap<{ data: unknown }>(await node.kv.get(key)).data !== value) throw new ReadBackMismatch("write round-trip");
        },
      ],
      ["delete", async () => unwrap(await node.kv.delete(key))],
    ];
    for (const [stage, fn] of stages) {
      const threshold = WRITE_THRESHOLDS_MS[stage];
      const r = await measure(`write.${stage}`, fn, {
        slowMs: threshold,
        onError: (e) => console.log(`[probe] mode=normal sample=1 stage=write.${stage} error: ${detail(e, secrets)}`),
      });
      console.log(
        `[probe] mode=normal sample=1 stage=${r.stage} ms=${r.ms} threshold_ms=${threshold} result=${r.ok ? "ok" : "fail"} outcome="${r.outcome}"`,
      );
      writes.push(r);
      if (!r.ok) break;
    }
  }

  const all = [...results, ...writes];
  await writeSummary(summaryTable("Write Probe (normal)", [{ sample: 1, at: new Date().toISOString(), results: all, ok: all.every((r) => r.ok) }]));
  const breaches = all.filter((r) => !r.ok);
  if (breaches.length > 0) {
    console.error(`[probe] FAIL: ${breaches.map((b) => `${b.stage} ${b.outcome} (${b.ms}ms)`).join(", ")}`);
    return false;
  }
  console.log("[probe] PASS: reads and writes within thresholds");
  return true;
}

// ---- main ----------------------------------------------------------------------

async function main(): Promise<number> {
  const privateKey = process.env.PROBE_PRIVATE_KEY;
  if (!privateKey) {
    console.error("[probe] PROBE_PRIVATE_KEY is not set (a throwaway key in its own probe space). See test/probe/README.md.");
    return 1;
  }
  const mode = MODE === "normal" || MODE === "dense" ? MODE : undefined;
  if (!mode) {
    console.error(`[probe] PROBE_MODE must be "normal" or "dense"`);
    return 1;
  }
  const rawHeartbeat = process.env.BETTERSTACK_HEARTBEAT_URL;
  const secrets = [privateKey, privateKey.replace(/^0x/, ""), rawHeartbeat ?? ""];
  let hbUrl: URL | undefined;
  let configOk = true;
  try {
    hbUrl = heartbeatUrl(rawHeartbeat);
  } catch (error) {
    // The message names the problem, never the value.
    console.error(`[probe] ${error instanceof Error ? error.message : "invalid BETTERSTACK_HEARTBEAT_URL"}; heartbeat reporting disabled for this run`);
    configOk = false;
  }
  if (hbUrl) secrets.push(hbUrl.pathname.split("/").filter(Boolean).pop() ?? "");

  console.log(`[probe] mode=${MODE} host=${HOST} space_prefix=${PREFIX} stage_deadline_ms=${STAGE_DEADLINE_MS} heartbeat=${hbUrl ? "configured" : "not configured"}`);

  const reporter: Reporter = async (action, failure, consecutive) => {
    const body =
      action === "fail" && failure
        ? failBody({ mode, consecutive, failure, build: await nodeBuild(HOST, fetch), host: new URL(HOST).host, at: new Date() })
        : undefined;
    if (body) console.log(`[probe] fail report body: ${body}`);
    console.log(`[probe] ${await report(action, hbUrl, body, fetch)}`);
  };

  const node = new TinyCloudNode({ privateKey, host: HOST, prefix: PREFIX });
  const client = sdkClient(node);

  if (MODE === "dense") {
    const samples = await denseWatch(client, { log: (line) => console.log(line), secrets, report: reporter });
    await writeSummary(summaryTable("Write Probe promote watch (dense)", samples));
    const failed = samples.filter((s) => !s.ok).length;
    console.log(`[probe] dense watch done: ${samples.length} samples, ${failed} failed`);
    return failed === 0 && configOk ? 0 : 1;
  }
  return (await normalRun(node, client, reporter, secrets)) && configOk ? 0 : 1;
}

// Deadlines leave SDK requests running in the background; exit explicitly so a
// hung request can't keep the process (and the job) alive.
main().then(
  (code) => process.exit(code),
  (err: unknown) => {
    console.error(`[probe] crashed: ${detail(err, [process.env.PROBE_PRIVATE_KEY ?? "", process.env.BETTERSTACK_HEARTBEAT_URL ?? ""])}`);
    process.exit(1);
  },
);

/**
 * TC-313: Synthetic end-to-end WRITE probe for the TinyCloud prod node.
 *
 * WHY THIS EXISTS
 * ---------------
 * During the 2026-07-27/28 write-degradation incident, `/healthz` kept
 * returning 200 in ~300ms while `kv.put` took 46s and `/delegate` blew past
 * Cloudflare's 100s ceiling. Monitoring was blind because `/healthz` and
 * `/version` never touch the database or the write path. This probe closes
 * that gap: it drives a REAL signed, end-to-end write against the live node
 * and fails (which is the alert) when any stage crosses a latency threshold.
 *
 * WHAT IT MEASURES (each stage timed independently)
 * -------------------------------------------------
 *   1. signIn    - SIWE sign-in + delegation activation (the /delegate path
 *                  that was worst-hit in the incident).
 *   2. kv.put    - write a small value.
 *   3. kv.get    - read it back and verify the bytes round-trip.
 *   4. kv.delete - clean up so the probe space never accumulates data.
 *
 * THRESHOLDS (see THRESHOLDS_MS below; override via env)
 * ------------------------------------------------------
 *   signIn    > 15s -> fail. The incident showed /delegate as the first thing
 *                      to blow the CF ceiling; 15s is well under the 100s wall
 *                      but far above a healthy (~1-3s) activation.
 *   kv.put    >  5s -> fail. Healthy puts are sub-second; 5s means the write
 *                      path is degrading before users hit a hard failure.
 *   kv.get    >  5s -> fail. Same rationale on the read path.
 *   kv.delete >  5s -> fail. Delete also exercises the write path.
 *
 * A non-zero exit fails the GitHub Actions job; a failed scheduled job IS the
 * alert (GitHub emails the configured recipients). No always-on infra added.
 *
 * IDENTITY / SECRETS
 * ------------------
 * The private key comes from the PROBE_PRIVATE_KEY env var (a GH secret) and
 * is NEVER hardcoded. It must be a THROWAWAY key operating in its own probe
 * space (the PREFIX below) so the probe never reads or writes user data.
 */

import { TinyCloudNode } from "@tinycloud/node-sdk";

// ---- configuration (env-overridable) ---------------------------------------

// The workflow wires optional overrides straight from secrets/vars, which
// arrive as EMPTY STRINGS when unset — and `??` only falls back on
// null/undefined, so `"" ?? default` keeps the empty string. Treat blank
// (whitespace-only) env values as absent, otherwise HOST/PREFIX go empty
// (sign-in fails: "Space name cannot be empty") and Number("") coerces every
// threshold to 0 (instant breach).
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

const HOST = envStr("PROBE_HOST", "https://node.tinycloud.xyz");
// Dedicated, isolated space prefix for the probe identity. Never shared with
// any user-facing app prefix.
const PREFIX = envStr("PROBE_PREFIX", "tc313-write-probe");

const THRESHOLDS_MS = {
  signIn: envMs("PROBE_THRESHOLD_SIGNIN_MS", 15_000),
  put: envMs("PROBE_THRESHOLD_PUT_MS", 5_000),
  get: envMs("PROBE_THRESHOLD_GET_MS", 5_000),
  delete: envMs("PROBE_THRESHOLD_DELETE_MS", 5_000),
} as const;

type Stage = keyof typeof THRESHOLDS_MS;

// ---- helpers ---------------------------------------------------------------

interface StageResult {
  stage: Stage;
  ms: number;
  threshold: number;
  breached: boolean;
}

async function timed<T>(
  stage: Stage,
  fn: () => Promise<T>,
): Promise<{ value: T; result: StageResult }> {
  const start = performance.now();
  const value = await fn();
  const ms = Math.round(performance.now() - start);
  const threshold = THRESHOLDS_MS[stage];
  const breached = ms > threshold;
  const flag = breached ? "SLOW" : "ok";
  console.log(
    `[probe] ${stage.padEnd(8)} ${String(ms).padStart(6)}ms (threshold ${threshold}ms) ${flag}`,
  );
  return { value, result: { stage, ms, threshold, breached } };
}

type Result<T> = { ok: true; data: T } | { ok: false; error: unknown };

/**
 * Unwrap a Result-typed SDK response. We do NOT swallow errors or add a
 * graceful fallback: a failed KV op must surface loudly and fail the probe,
 * exactly like a threshold breach would.
 */
function unwrap<T>(label: string, result: Result<T>): T {
  if (!result.ok) {
    throw new Error(`[probe] ${label} failed: ${JSON.stringify(result.error)}`);
  }
  return result.data;
}

// ---- probe -----------------------------------------------------------------

async function main(): Promise<void> {
  const privateKey = process.env.PROBE_PRIVATE_KEY;
  if (!privateKey) {
    throw new Error(
      "PROBE_PRIVATE_KEY is not set. Set it as a GitHub Actions secret " +
        "(a throwaway key in its own probe space). See test/probe/README.md.",
    );
  }

  console.log(`[probe] target host: ${HOST}`);
  console.log(`[probe] space prefix: ${PREFIX}`);

  const node = new TinyCloudNode({ privateKey, host: HOST, prefix: PREFIX });

  const key = `probe/${Date.now()}`;
  const value = `tc313-${Date.now()}`;
  const results: StageResult[] = [];

  // 1. Sign-in + delegation activation (worst-hit path in the incident).
  results.push((await timed("signIn", () => node.signIn())).result);

  // 1b. Ensure the probe's own space exists. A brand-new probe identity has no
  // space yet, so the first write 404s "space not found"; hostOwnedSpace is
  // idempotent (fast no-op once the space exists) and returns the space id.
  // This is provisioning, not the steady-state write we alert on, so we time
  // and log it but do NOT threshold-gate it — a genuine failure throws and
  // still fails the probe. (Do not branch on the return value: it is the space
  // id string on success and throws on failure, never a falsy sentinel.)
  const ensureStart = performance.now();
  const spaceId = await node.hostOwnedSpace(PREFIX);
  console.log(
    `[probe] ${"ensure".padEnd(8)} ${String(Math.round(performance.now() - ensureStart)).padStart(6)}ms -> ${spaceId}`,
  );

  // 2. Write a small value.
  results.push(
    (await timed("put", async () => unwrap("kv.put", await node.kv.put(key, value))))
      .result,
  );

  // 3. Read it back and verify the round-trip.
  const { value: readBack, result: getResult } = await timed("get", async () =>
    unwrap<{ data: unknown }>("kv.get", await node.kv.get(key)),
  );
  results.push(getResult);
  if (readBack?.data !== value) {
    throw new Error(
      `[probe] readback mismatch: wrote ${JSON.stringify(value)} but read ${JSON.stringify(
        readBack?.data,
      )}`,
    );
  }

  // 4. Clean up.
  results.push(
    (await timed("delete", async () => unwrap("kv.delete", await node.kv.delete(key))))
      .result,
  );

  // ---- verdict -------------------------------------------------------------
  const breaches = results.filter((r) => r.breached);
  if (breaches.length > 0) {
    console.error(
      `[probe] FAIL: ${breaches.length} stage(s) exceeded threshold: ` +
        breaches.map((b) => `${b.stage}=${b.ms}ms>${b.threshold}ms`).join(", "),
    );
    process.exit(1);
  }
  console.log("[probe] PASS: all stages within thresholds");
}

main().catch((err) => {
  // No graceful fallback: any error (network, auth, mismatch) fails the probe
  // so the scheduled job goes red and GitHub sends the failure notification.
  console.error(err instanceof Error ? (err.stack ?? err.message) : String(err));
  process.exit(1);
});

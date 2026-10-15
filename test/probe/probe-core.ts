/**
 * TC-1176: SDK-free core of the Write Probe — deadlines, failure
 * classification, the consecutive-failure rule, Better Stack heartbeat
 * reporting and the dense "promote watch" loop. `write-probe.ts` wires these
 * to the real `@tinycloud/node-sdk`; `probe-core.test.ts` drives them with a
 * stub client, so every timeout and failure path is tested without a node.
 *
 * Nothing in here may print a secret. Errors are reduced to a classified
 * outcome ("timeout >=20s", "HTTP 504", "connection refused", "DNS", ...);
 * raw messages only reach the log through `redact`, and the heartbeat URL is
 * never logged at all.
 */

/** Hard client deadline for every stage (the TC-1176 spec: >20 s is a failure). */
export const STAGE_DEADLINE_MS = 20_000;
/** Dense (post-promote) mode: a read slower than this counts as a failure. */
export const DENSE_SLOW_MS = 5_000;
/** Failures in a row before the heartbeat gets a `/fail` report. */
export const FAILURES_TO_ALERT = 2;
/** At most one `/fail` per this interval while a failure streak lasts. */
export const FAIL_REPORT_MIN_INTERVAL_MS = 240_000;
/** Deadline for the heartbeat ping/fail and the /version lookup. */
export const REPORT_TIMEOUT_MS = 10_000;

/** Dense watch: every 30 s for 5 min, then every 5 min for 60 min. */
export const DENSE_SCHEDULE: readonly Phase[] = [
  { intervalMs: 30_000, count: 10 },
  { intervalMs: 300_000, count: 12 },
];

export type ReadStage = "signin" | "space" | "kv" | "sql";
export type Phase = { intervalMs: number; count: number };

export class DeadlineError extends Error {
  constructor(
    readonly stage: string,
    readonly deadlineMs: number,
  ) {
    super(`${stage} did not finish within ${deadlineMs}ms`);
    this.name = "DeadlineError";
  }
}

/** Runs `fn`, rejecting with DeadlineError if it hasn't settled within `ms`. */
export async function withDeadline<T>(stage: string, ms: number, fn: () => Promise<T>): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new DeadlineError(stage, ms)), ms);
  });
  try {
    return await Promise.race([fn(), deadline]);
  } finally {
    clearTimeout(timer);
  }
}

const NET_CODES: Record<string, string> = {
  ECONNREFUSED: "connection refused",
  ENOTFOUND: "DNS",
  EAI_AGAIN: "DNS",
  ECONNRESET: "connection reset",
  ETIMEDOUT: "connect timeout",
  UND_ERR_CONNECT_TIMEOUT: "connect timeout",
  UND_ERR_SOCKET: "connection reset",
};

function field(value: unknown, key: string): unknown {
  return value !== null && typeof value === "object" ? Reflect.get(value, key) : undefined;
}

/** The value and its `cause` chain (SDK ServiceError -> TypeError -> undici error). */
function causes(error: unknown): unknown[] {
  const chain: unknown[] = [];
  for (let e = error; e !== undefined && e !== null && chain.length < 6; e = field(e, "cause")) chain.push(e);
  return chain;
}

/**
 * One short outcome for an operator, never a raw message:
 * "timeout >=20s" | "HTTP 504" | "connection refused" | "DNS" | ... | "error KV_NOT_FOUND".
 */
export function classify(error: unknown): string {
  const chain = causes(error);
  for (const e of chain) {
    if (e instanceof DeadlineError) return `timeout >=${Number((e.deadlineMs / 1000).toFixed(2))}s`;
  }
  for (const e of chain) {
    const status = field(field(e, "meta"), "status") ?? field(e, "status");
    if (typeof status === "number" && status >= 100 && status <= 599) return `HTTP ${status}`;
  }
  for (const e of chain) {
    const code = field(e, "code");
    if (typeof code === "string" && NET_CODES[code]) return NET_CODES[code];
  }
  for (const e of chain) {
    if (field(e, "name") === "TimeoutError") return "timeout (client)";
  }
  // The SDK's sign-in pre-check: a non-2xx /info carries no status or cause.
  if (field(error, "name") === "VersionCheckError") return "node /info not OK";
  const code = field(error, "code");
  if (typeof code === "string" && /^[A-Z][A-Z0-9_]{1,40}$/.test(code)) return `error ${code}`;
  if (error instanceof Error && /^[A-Za-z]{1,40}$/.test(error.name)) return `error ${error.name}`;
  return "error";
}

/** Replaces every secret occurrence, strips control characters and caps the length. */
export function redact(text: string, secrets: readonly string[], max = 300): string {
  let out = text;
  for (const s of secrets) if (s && s.length >= 8) out = out.split(s).join("[redacted]");
  out = out.replace(/[\u0000-\u001f\u007f]+/g, " ");
  return out.length > max ? `${out.slice(0, max)}…` : out;
}

/** Short, redacted detail for the job log (the outcome alone is what alerts). */
export function detail(error: unknown, secrets: readonly string[]): string {
  const message = field(error, "message");
  return redact(typeof message === "string" ? message : String(error), secrets, 200);
}

export type StageResult = {
  stage: string;
  ms: number;
  ok: boolean;
  /** "ok", "slow 6.2s >5s", or a classify() outcome. */
  outcome: string;
};

/**
 * Times one stage under the hard deadline. `slowMs` turns a completed but slow
 * call into a failure (dense mode: 5 s); in normal mode it equals the deadline.
 */
export async function measure(
  stage: string,
  fn: () => Promise<unknown>,
  opts: { deadlineMs?: number; slowMs?: number; now?: () => number; onError?: (e: unknown) => void } = {},
): Promise<StageResult> {
  const deadlineMs = opts.deadlineMs ?? STAGE_DEADLINE_MS;
  const slowMs = opts.slowMs ?? deadlineMs;
  const now = opts.now ?? (() => performance.now());
  const start = now();
  try {
    await withDeadline(stage, deadlineMs, fn);
  } catch (error) {
    opts.onError?.(error);
    return { stage, ms: Math.round(now() - start), ok: false, outcome: classify(error) };
  }
  const ms = Math.round(now() - start);
  if (ms > slowMs) return { stage, ms, ok: false, outcome: `slow ${(ms / 1000).toFixed(1)}s >${slowMs / 1000}s` };
  return { stage, ms, ok: true, outcome: "ok" };
}

// ---- consecutive-failure rule ------------------------------------------------

/**
 * KV and SQL are tracked separately: a sample may read only one of them (dense
 * 30 s phase), and a healthy SQL read must not hide a broken KV read.
 */
export const READ_TARGETS = ["kv", "sql"] as const;
export type ReadTarget = (typeof READ_TARGETS)[number];

/** Persisted between runs and shared by normal and dense mode. */
export type ProbeState = {
  /** Failed observations in a row, per read target. */
  failures: Record<ReadTarget, number>;
  /** The latest failure per target, for the `/fail` body. */
  lastFailure: Partial<Record<ReadTarget, StageResult>>;
  /** ISO time of the last ACCEPTED `/fail` in the current streak. */
  lastFailReportAt?: string;
};

export const INITIAL_STATE: ProbeState = { failures: { kv: 0, sql: 0 }, lastFailure: {} };

export type Decision = {
  action: "ping" | "fail" | "none";
  /** State to keep if the action's delivery succeeds (see settle()). */
  state: ProbeState;
  /** The failure named in the `/fail` body: the worst target's latest failure. */
  failure?: StageResult;
  consecutive: number;
};

/**
 * Folds one sample into the state and decides what the heartbeat should hear.
 * A kv/sql result updates its own target; a failed signin/space means neither
 * could be read, so it counts against both. Targets the sample didn't observe
 * keep their count.
 * - every target at 0 failures -> ping (resolves an open heartbeat incident);
 * - any target at FAILURES_TO_ALERT+ -> `/fail`, at most once per
 *   FAIL_REPORT_MIN_INTERVAL_MS;
 * - otherwise nothing (one failure alone never pages).
 */
export function decide(prev: ProbeState, results: readonly StageResult[], nowMs: number): Decision {
  const failures = { ...prev.failures };
  const lastFailure = { ...prev.lastFailure };
  for (const r of results) {
    const targets: readonly ReadTarget[] = r.stage === "kv" || r.stage === "sql" ? [r.stage] : r.ok ? [] : READ_TARGETS;
    for (const t of targets) {
      failures[t] = r.ok ? 0 : failures[t] + 1;
      if (r.ok) delete lastFailure[t];
      else lastFailure[t] = r;
    }
  }
  const worst = READ_TARGETS.reduce((a, b) => (failures[b] > failures[a] ? b : a));
  const consecutive = failures[worst];
  if (consecutive === 0) return { action: "ping", state: { failures, lastFailure: {} }, consecutive };
  const state: ProbeState = { failures, lastFailure, ...(prev.lastFailReportAt ? { lastFailReportAt: prev.lastFailReportAt } : {}) };
  const last = prev.lastFailReportAt ? Date.parse(prev.lastFailReportAt) : Number.NaN;
  const due = consecutive >= FAILURES_TO_ALERT && !(nowMs - last < FAIL_REPORT_MIN_INTERVAL_MS);
  return { action: due ? "fail" : "none", state, failure: lastFailure[worst], consecutive };
}

function count(value: unknown): number {
  return typeof value === "number" && Number.isInteger(value) && value >= 0 ? value : 0;
}

/** Tolerates a missing or corrupt state file: start from zero failures. */
export function parseState(text: string | undefined): ProbeState {
  if (!text) return INITIAL_STATE;
  try {
    const raw: unknown = JSON.parse(text);
    const failures = field(raw, "failures");
    const lastFailure = field(raw, "lastFailure");
    const at = field(raw, "lastFailReportAt");
    const restored: Partial<Record<ReadTarget, StageResult>> = {};
    for (const t of READ_TARGETS) {
      const r = field(lastFailure, t);
      const stage = field(r, "stage");
      const ms = field(r, "ms");
      const outcome = field(r, "outcome");
      if (typeof stage === "string" && typeof ms === "number" && typeof outcome === "string") {
        restored[t] = { stage: redact(stage, [], 20), ms, ok: false, outcome: redact(outcome, [], 60) };
      }
    }
    return {
      failures: { kv: count(field(failures, "kv")), sql: count(field(failures, "sql")) },
      lastFailure: restored,
      ...(typeof at === "string" && !Number.isNaN(Date.parse(at)) ? { lastFailReportAt: at } : {}),
    };
  } catch {
    return INITIAL_STATE;
  }
}

// ---- heartbeat reporting -------------------------------------------------------

/** The one-line `/fail` body: stage, outcome, duration, node build, UTC time. No secrets. */
export function failBody(f: {
  mode: "normal" | "dense";
  consecutive: number;
  failure: StageResult;
  build: string;
  host: string;
  at: Date;
}): string {
  const line =
    `TC-1176 node read probe FAIL (${f.consecutive} in a row, ${f.mode}): ` +
    `stage=${f.failure.stage} outcome="${f.failure.outcome}" duration_ms=${f.failure.ms} ` +
    `build=${f.build} host=${f.host} at=${f.at.toISOString().replace(/\.\d{3}Z$/, "Z")}`;
  return redact(line, [], 400);
}

/** Accepts only a Better Stack heartbeat URL, so a mis-set secret can't send reports elsewhere. */
export function heartbeatUrl(raw: string | undefined): URL | undefined {
  if (!raw || raw.trim() === "") return undefined;
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error("BETTERSTACK_HEARTBEAT_URL is not a URL");
  }
  const okHost = url.hostname === "uptime.betterstack.com" || url.hostname === "betteruptime.com" || url.hostname === "incidents.betterstack.com";
  if (url.protocol !== "https:" || !okHost || !/^\/api\/v1\/heartbeat\/[A-Za-z0-9_-]+\/?$/.test(url.pathname) || url.search) {
    throw new Error("BETTERSTACK_HEARTBEAT_URL is not a Better Stack heartbeat URL");
  }
  return url;
}

export type Fetch = (input: string, init?: RequestInit) => Promise<Response>;

/** Outcome of a heartbeat call; `line` is safe to log (never the URL). */
export type Delivery = { ok: boolean; line: string };

/** Sends the ping or `/fail`. Only a 2xx counts as delivered. */
export async function report(action: "ping" | "fail", url: URL | undefined, body: string | undefined, fetchFn: Fetch): Promise<Delivery> {
  if (!url) return { ok: true, line: `heartbeat ${action} skipped: BETTERSTACK_HEARTBEAT_URL not set` };
  const target = action === "fail" ? `${url.toString().replace(/\/$/, "")}/fail` : url.toString();
  try {
    const res = await fetchFn(target, {
      method: action === "fail" ? "POST" : "GET",
      ...(action === "fail" ? { body, headers: { "content-type": "text/plain" } } : {}),
      signal: AbortSignal.timeout(REPORT_TIMEOUT_MS),
    });
    return res.ok
      ? { ok: true, line: `heartbeat ${action} sent: HTTP ${res.status}` }
      : { ok: false, line: `heartbeat ${action} NOT accepted: HTTP ${res.status}` };
  } catch (error) {
    return { ok: false, line: `heartbeat ${action} NOT delivered: ${classify(error)}` };
  }
}

/** Node build from public /version, or a short reason it's unknown. */
export async function nodeBuild(host: string, fetchFn: Fetch): Promise<string> {
  try {
    const res = await fetchFn(`${host.replace(/\/$/, "")}/version`, { signal: AbortSignal.timeout(5_000) });
    if (!res.ok) return `unknown(HTTP ${res.status})`;
    const version = field(await res.json(), "version");
    return typeof version === "string" && /^[0-9A-Za-z.+-]{1,40}$/.test(version) ? version : "unknown";
  } catch (error) {
    return `unknown(${classify(error)})`;
  }
}

// ---- the read check --------------------------------------------------------------

/** What the probe needs from a TinyCloud client; the real one wraps TinyCloudNode. */
export interface ReadClient {
  signIn(): Promise<void>;
  ensureSpace(): Promise<void>;
  /** Signed-in read of the fixed KV key (provisions it once if absent). */
  kvRead(): Promise<void>;
  /** Signed-in tiny SQL select of the fixed row (provisions it once if absent). */
  sqlRead(): Promise<void>;
}

export type Logger = (line: string) => void;

/** Delivers the decided ping or `/fail`; `failure` is the stage named in the `/fail` body. */
export type Deliver = (action: "ping" | "fail", failure: StageResult | undefined, consecutive: number) => Promise<Delivery>;

export type Settled = { state: ProbeState; action: Decision["action"]; delivered: boolean };

/**
 * decide() + delivery. A `/fail` only starts its rate-limit window once
 * Better Stack accepted it, so a rejected report is retried on the next sample.
 */
export async function settle(prev: ProbeState, results: readonly StageResult[], nowMs: number, deliver: Deliver): Promise<Settled> {
  const d = decide(prev, results, nowMs);
  if (d.action === "none") return { state: d.state, action: d.action, delivered: true };
  const { ok } = await deliver(d.action, d.failure, d.consecutive);
  const state = d.action === "fail" && ok ? { ...d.state, lastFailReportAt: new Date(nowMs).toISOString() } : d.state;
  return { state, action: d.action, delivered: ok };
}

export type ReadCheckResult = { results: StageResult[]; failure?: StageResult };

/**
 * Normal (scheduled) mode, read half: sign in, ensure the space, KV read, SQL
 * read — each under the 20 s deadline. Stops at the first failure, which is
 * the one named in the `/fail` body.
 */
export async function readCheck(
  client: ReadClient,
  opts: {
    log: Logger;
    secrets: readonly string[];
    mode?: string;
    sample?: number;
    slowMs?: number;
    deadlineMs?: number;
    stages?: readonly ReadStage[];
    /** Clock for stage durations (tests drive it; default performance.now). */
    now?: () => number;
  },
): Promise<ReadCheckResult> {
  const deadlineMs = opts.deadlineMs ?? STAGE_DEADLINE_MS;
  const slowMs = opts.slowMs ?? deadlineMs;
  const mode = opts.mode ?? "normal";
  const sample = opts.sample ?? 1;
  const all: [ReadStage, () => Promise<void>, number][] = [
    ["signin", () => client.signIn(), deadlineMs],
    ["space", () => client.ensureSpace(), deadlineMs],
    ["kv", () => client.kvRead(), slowMs],
    ["sql", () => client.sqlRead(), slowMs],
  ];
  const wanted = opts.stages ?? ["signin", "space", "kv", "sql"];
  const results: StageResult[] = [];
  for (const [stage, fn, stageSlow] of all) {
    if (!wanted.includes(stage)) continue;
    const r = await measure(stage, fn, {
      deadlineMs,
      now: opts.now,
      slowMs: stageSlow,
      onError: (e) => opts.log(`[probe] mode=${mode} sample=${sample} stage=${stage} error: ${detail(e, opts.secrets)}`),
    });
    opts.log(
      `[probe] mode=${mode} sample=${sample} stage=${r.stage} ms=${r.ms} threshold_ms=${stageSlow} result=${r.ok ? "ok" : "fail"} outcome="${r.outcome}"`,
    );
    results.push(r);
    if (!r.ok) return { results, failure: r };
  }
  return { results };
}

export type DenseSample = { sample: number; at: string; results: StageResult[]; ok: boolean };
export type DenseResult = { samples: DenseSample[]; state: ProbeState; undelivered: number };

/**
 * Dense promote watch. One sign-in (retried on the next sample if it fails),
 * then reads on DENSE_SCHEDULE. Under a 60 s interval each sample reads ONE of
 * KV/SQL alternately, so each sees at most one request per 30 s; otherwise both.
 * A read over DENSE_SLOW_MS or failing counts. Starts from, and hands back
 * through `onState`, the same per-target state as normal mode.
 */
export async function denseWatch(
  client: ReadClient,
  opts: {
    log: Logger;
    secrets: readonly string[];
    deliver: Deliver;
    initialState?: ProbeState;
    onState?: (state: ProbeState) => Promise<void>;
    schedule?: readonly Phase[];
    slowMs?: number;
    deadlineMs?: number;
    sleep?: (ms: number) => Promise<void>;
    clock?: () => number;
  },
): Promise<DenseResult> {
  const schedule = opts.schedule ?? DENSE_SCHEDULE;
  const slowMs = opts.slowMs ?? DENSE_SLOW_MS;
  const sleep = opts.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const clock = opts.clock ?? (() => Date.now());
  const samples: DenseSample[] = [];
  let state = opts.initialState ?? INITIAL_STATE;
  let undelivered = 0;
  let signedIn = false;
  let next = clock();
  let n = 0;
  for (const phase of schedule) {
    for (let i = 0; i < phase.count; i++) {
      const wait = next - clock();
      if (wait > 0) await sleep(wait);
      n += 1;
      const reads: ReadStage[] = phase.intervalMs < 60_000 ? [n % 2 === 1 ? "kv" : "sql"] : ["kv", "sql"];
      const stages: ReadStage[] = signedIn ? reads : ["signin", "space", ...reads];
      const at = new Date(clock()).toISOString();
      const { results, failure } = await readCheck(client, {
        log: opts.log,
        secrets: opts.secrets,
        mode: "dense",
        sample: n,
        slowMs,
        deadlineMs: opts.deadlineMs,
        now: opts.clock,
        stages,
      });
      if (!signedIn && results.some((r) => r.stage === "space" && r.ok)) signedIn = true;
      const settled = await settle(state, results, clock(), opts.deliver);
      state = settled.state;
      if (!settled.delivered) undelivered += 1;
      opts.log(`[probe] mode=dense sample=${n} failures_kv=${state.failures.kv} failures_sql=${state.failures.sql} heartbeat_action=${settled.action}`);
      await opts.onState?.(state);
      samples.push({ sample: n, at, results, ok: !failure });
      next += phase.intervalMs;
    }
  }
  return { samples, state, undelivered };
}

/** Markdown for $GITHUB_STEP_SUMMARY: every sample's latency. */
export function summaryTable(title: string, samples: readonly DenseSample[]): string {
  const rows = samples.flatMap((s) =>
    s.results.map((r) => `| ${s.sample} | ${s.at.replace(/\.\d{3}Z$/, "Z")} | ${r.stage} | ${r.ms} | ${r.ok ? "ok" : "FAIL"} | ${r.outcome} |`),
  );
  const failed = samples.filter((s) => !s.ok).length;
  return [
    `### ${title}`,
    "",
    `${samples.length} sample(s), ${failed} failed.`,
    "",
    "| sample | time (UTC) | stage | ms | result | outcome |",
    "|---:|---|---|---:|---|---|",
    ...rows,
    "",
  ].join("\n");
}

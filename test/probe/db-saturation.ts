/**
 * TC-1601: sustained DB saturation check for a PlanetScale branch.
 *
 * Pure logic only. The PlanetScale fetch and the heartbeat call live in
 * db-saturation-run.ts. Logs numeric metric values only, never query text.
 *
 * RULES
 * -----
 * Points are one-minute samples. The window is the `window_min` minutes that
 * end LAG_SEC seconds ago, so ingestion lag never counts.
 * - CPU: breach when at least `min_breach_points` window points are above
 *   `cpu_pct` (13 of 15 by default, so one or two dips do not reset it).
 * - Pool: the same counting, using the target's `pool` comparator.
 * - Fewer than `min_points` valid points in a series, or no series at all, is
 *   UNKNOWN: the heartbeat gets no ping, so the missed-heartbeat alert fires.
 * - A breach on any rule wins over UNKNOWN on another rule.
 * - A target with no `pool` rule is a CONFIG fault and fails the heartbeat.
 */

export class ConfigFault extends Error {}

export const CPU_METRIC = "planetscale_primary_pods_cpu_util_percentages";
/** Points newer than this are dropped for ingestion lag. */
export const LAG_SEC = 90;

export type PoolRule = {
  metric: string;
  /** Every key must equal the series label; {} matches every series of the metric. */
  series_labels: Record<string, string>;
  op: "gt" | "gte";
  threshold: number;
};

export type Target = {
  label: string;
  org: string;
  database: string;
  branch: string;
  /** Name of the env var holding the PlanetScale token (ID:TOKEN). */
  token_secret: string;
  /** Name of the env var holding the Better Stack heartbeat URL. */
  heartbeat_secret: string;
  cpu_pct: number;
  window_min: number;
  min_points: number;
  min_breach_points: number;
  /** null until the connection path is confirmed; null fails the target as CONFIG. */
  pool: PoolRule | null;
};

/** [unix seconds, value or null when PlanetScale has no sample for that minute]. */
export type Point = [number, number | null];
export type Series = { metric: string; labels: Record<string, string>; points: Point[] };

export type Status = "ok" | "breach" | "unknown" | "config";
export type Verdict = { status: Status; detail: string };

type Obj = Record<string, unknown>;
const isObj = (x: unknown): x is Obj => typeof x === "object" && x !== null && !Array.isArray(x);

function str(o: Obj, key: string, at: string): string {
  const v = o[key];
  if (typeof v !== "string" || v.trim() === "") throw new ConfigFault(`${at}: ${key} must be a non-empty string`);
  return v;
}

function num(o: Obj, key: string, at: string): number {
  const v = o[key];
  if (typeof v !== "number" || !Number.isFinite(v)) throw new ConfigFault(`${at}: ${key} must be a finite number`);
  return v;
}

function parsePool(v: unknown, at: string): PoolRule {
  if (!isObj(v)) throw new ConfigFault(`${at}: pool must be an object or null`);
  const labels = v.series_labels;
  if (!isObj(labels) || Object.values(labels).some((x) => typeof x !== "string")) {
    throw new ConfigFault(`${at}: pool.series_labels must map strings to strings`);
  }
  if (v.op !== "gt" && v.op !== "gte") throw new ConfigFault(`${at}: pool.op must be "gt" or "gte"`);
  return {
    metric: str(v, "metric", `${at}.pool`),
    series_labels: labels as Record<string, string>,
    op: v.op,
    threshold: num(v, "threshold", `${at}.pool`),
  };
}

/** Validates the targets file. Throws ConfigFault on any malformed entry. */
export function loadTargets(raw: unknown): Target[] {
  if (!Array.isArray(raw) || raw.length === 0) throw new ConfigFault("targets file must be a non-empty array");
  const labels = new Set<string>();
  return raw.map((entry, i) => {
    const at = `target ${i}`;
    if (!isObj(entry)) throw new ConfigFault(`${at} must be an object`);
    const label = str(entry, "label", at);
    if (labels.has(label)) throw new ConfigFault(`${at}: duplicate label ${label}`);
    labels.add(label);
    const target: Target = {
      label,
      org: str(entry, "org", at),
      database: str(entry, "database", at),
      branch: str(entry, "branch", at),
      token_secret: str(entry, "token_secret", at),
      heartbeat_secret: str(entry, "heartbeat_secret", at),
      cpu_pct: num(entry, "cpu_pct", at),
      window_min: num(entry, "window_min", at),
      min_points: num(entry, "min_points", at),
      min_breach_points: num(entry, "min_breach_points", at),
      pool: entry.pool === null ? null : parsePool(entry.pool, at),
    };
    if (target.cpu_pct < 0 || target.cpu_pct > 100) throw new ConfigFault(`${at}: cpu_pct out of range`);
    if (!Number.isInteger(target.window_min) || target.window_min < 1) throw new ConfigFault(`${at}: window_min must be a positive integer`);
    if (target.min_breach_points > target.window_min || target.min_points > target.window_min) {
      throw new ConfigFault(`${at}: min_points and min_breach_points must not exceed window_min`);
    }
    return target;
  });
}

/** Metrics endpoint for one branch. Only this endpoint is ever called. */
export function metricsUrl(t: Target): string {
  const metrics = [CPU_METRIC, ...(t.pool ? [t.pool.metric] : [])];
  const period = Math.ceil((t.window_min * 60 + LAG_SEC) / 60);
  const enc = encodeURIComponent;
  return (
    `https://api.planetscale.com/v1/organizations/${enc(t.org)}/databases/${enc(t.database)}` +
    `/branches/${enc(t.branch)}/metrics?metrics=${metrics.join(",")}&period=${period}m`
  );
}

/** Parses a PlanetScale MetricSeries body. Shape changes throw ConfigFault. */
export function parseSeries(body: unknown): Series[] {
  if (!isObj(body) || !Array.isArray(body.series)) throw new ConfigFault("metrics response has no series array");
  return body.series.map((s: unknown, i: number): Series => {
    const at = `series ${i}`;
    if (!isObj(s) || typeof s.metric !== "string" || !isObj(s.labels) || !Array.isArray(s.points)) {
      throw new ConfigFault(`${at} is malformed`);
    }
    const points = s.points.map((p: unknown): Point => {
      if (!Array.isArray(p) || p.length !== 2 || typeof p[0] !== "number") throw new ConfigFault(`${at} has a malformed point`);
      const value = p[1];
      return [p[0], typeof value === "number" && Number.isFinite(value) ? value : null];
    });
    const labels = Object.fromEntries(Object.entries(s.labels).map(([k, v]) => [k, String(v)]));
    return { metric: s.metric, labels, points };
  });
}

type RuleResult = { status: "ok" | "breach" | "unknown"; detail: string };

function labelText(s: Series): string {
  const entries = Object.entries(s.labels);
  return entries.length === 0 ? "all" : entries.map(([k, v]) => `${k}=${v}`).join(",");
}

function evaluateRule(args: {
  name: string;
  series: Series[];
  above: (v: number) => boolean;
  t: Target;
  nowSec: number;
}): RuleResult {
  const { name, series, above, t, nowSec } = args;
  if (series.length === 0) return { status: "unknown", detail: `${name}: no series` };
  const hi = nowSec - LAG_SEC;
  const lo = hi - t.window_min * 60;
  let breach = false;
  let unknown = false;
  const parts: string[] = [];
  for (const s of series) {
    const values = s.points
      .filter(([ts, v]) => ts > lo && ts <= hi && v !== null)
      .map(([, v]) => v as number);
    const count = values.filter(above).length;
    parts.push(`[${labelText(s)}] ${count}/${values.length}`);
    if (values.length < t.min_points) unknown = true;
    else if (count >= t.min_breach_points) breach = true;
  }
  const detail = `${name} ${parts.join(" ")} (need ${t.min_breach_points} of ${t.window_min} for breach, ${t.min_points} valid to judge)`;
  if (breach) return { status: "breach", detail };
  if (unknown) return { status: "unknown", detail };
  return { status: "ok", detail };
}

/** Judges one target from its metric series. Pure: `nowSec` is passed in. */
export function evaluateTarget(t: Target, series: Series[], nowSec: number): Verdict {
  if (!t.pool) return { status: "config", detail: "pool rule not set in targets file" };
  const pool = t.pool;
  const cpu = evaluateRule({
    name: `cpu>${t.cpu_pct}%`,
    series: series.filter((s) => s.metric === CPU_METRIC),
    above: (v) => v > t.cpu_pct,
    t,
    nowSec,
  });
  const comparator = pool.op === "gt" ? ">" : ">=";
  const poolRes = evaluateRule({
    name: `pool${comparator}${pool.threshold}`,
    series: series.filter(
      (s) => s.metric === pool.metric && Object.entries(pool.series_labels).every(([k, v]) => s.labels[k] === v),
    ),
    above: (v) => (pool.op === "gt" ? v > pool.threshold : v >= pool.threshold),
    t,
    nowSec,
  });
  const detail = `${cpu.detail} | ${poolRes.detail}`;
  if (cpu.status === "breach" || poolRes.status === "breach") return { status: "breach", detail };
  if (cpu.status === "unknown" || poolRes.status === "unknown") return { status: "unknown", detail };
  return { status: "ok", detail };
}

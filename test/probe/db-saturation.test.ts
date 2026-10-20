import assert from "node:assert/strict";
import { test } from "node:test";
import {
  CPU_METRIC,
  ConfigFault,
  LAG_SEC,
  evaluateTarget,
  loadTargets,
  metricsUrl,
  parseSeries,
  type Point,
  type Series,
  type Target,
} from "./db-saturation";

const NOW = 1_800_000_000;
const POOL_METRIC = "planetscale_pgbouncer_pools_client";

const base: Target = {
  label: "node-db",
  org: "tinycloudlabs",
  database: "tinycloud-node-production",
  branch: "main",
  token_secret: "PLANETSCALE_METRICS_TOKEN_NODE_DB",
  heartbeat_secret: "BETTERSTACK_HEARTBEAT_URL_NODE_DB",
  cpu_pct: 85,
  window_min: 15,
  min_points: 12,
  min_breach_points: 13,
  pool: { metric: POOL_METRIC, series_labels: {}, op: "gt", threshold: 0 },
};

/** values[0] is the newest counted point (NOW - LAG_SEC); each older value is one minute earlier. */
function points(values: (number | null)[]): Point[] {
  return values.map((v, k): Point => [NOW - LAG_SEC - 60 * k, v]);
}

function cpu(values: (number | null)[]): Series {
  return { metric: CPU_METRIC, labels: {}, points: points(values) };
}

function pool(values: number[], labels: Record<string, string> = {}): Series {
  return { metric: POOL_METRIC, labels, points: points(values) };
}

const idlePool = pool(Array(15).fill(0));
const idleCpu = cpu(Array(15).fill(50));

test("CPU breaches when 13 of the 15 window points exceed the threshold", () => {
  const verdict = evaluateTarget(base, [cpu([...Array(13).fill(90), 10, 10]), idlePool], NOW);
  assert.equal(verdict.status, "breach");
});

test("CPU does not breach at 12 of 15 points, so two dips are tolerated", () => {
  const verdict = evaluateTarget(base, [cpu([...Array(12).fill(90), 10, 10, 10]), idlePool], NOW);
  assert.equal(verdict.status, "ok");
});

test("points inside the lag window are ignored", () => {
  const lagSpike: Point = [NOW - 30, 99];
  const series: Series = { metric: CPU_METRIC, labels: {}, points: [lagSpike, ...points([...Array(12).fill(90), 10, 10, 10])] };
  assert.equal(evaluateTarget(base, [series, idlePool], NOW).status, "ok");
});

test("a point older than the window is ignored", () => {
  const boundary: Point = [NOW - LAG_SEC - 15 * 60, 99];
  const series: Series = { metric: CPU_METRIC, labels: {}, points: [...points([...Array(12).fill(90), 10, 10, 10]), boundary] };
  assert.equal(evaluateTarget(base, [series, idlePool], NOW).status, "ok");
});

test("fewer than min_points valid points is unknown even when every point breaches", () => {
  const verdict = evaluateTarget(base, [cpu(Array(11).fill(99)), idlePool], NOW);
  assert.equal(verdict.status, "unknown");
});

test("null samples do not count as valid points", () => {
  const verdict = evaluateTarget(base, [cpu([...Array(11).fill(99), null, null, null, null]), idlePool], NOW);
  assert.equal(verdict.status, "unknown");
});

test("no CPU series is unknown, not ok", () => {
  assert.equal(evaluateTarget(base, [idlePool], NOW).status, "unknown");
});

test("a breach on one rule wins over unknown on the other", () => {
  const verdict = evaluateTarget(base, [cpu(Array(13).fill(99).concat(Array(2).fill(10))), pool([1, 1, 1])], NOW);
  assert.equal(verdict.status, "breach");
});

test("pool rule breaches when waiting clients persist in 13 of 15 points", () => {
  const verdict = evaluateTarget(base, [idleCpu, pool([...Array(13).fill(2), 0, 0])], NOW);
  assert.equal(verdict.status, "breach");
});

test("pool rule only reads series whose labels match the rule", () => {
  const rule = { ...base, pool: { metric: POOL_METRIC, series_labels: { state: "waiting" }, op: "gt" as const, threshold: 0 } };
  const verdict = evaluateTarget(rule, [idleCpu, pool(Array(15).fill(9), { state: "active" }), pool(Array(15).fill(0), { state: "waiting" })], NOW);
  assert.equal(verdict.status, "ok");
});

test("gte compares inclusively and gt does not", () => {
  const at = pool(Array(15).fill(15));
  const gte = { ...base, pool: { metric: POOL_METRIC, series_labels: {}, op: "gte" as const, threshold: 15 } };
  const gt = { ...base, pool: { metric: POOL_METRIC, series_labels: {}, op: "gt" as const, threshold: 15 } };
  assert.equal(evaluateTarget(gte, [idleCpu, at], NOW).status, "breach");
  assert.equal(evaluateTarget(gt, [idleCpu, at], NOW).status, "ok");
});

test("a target without a pool rule is a config fault", () => {
  assert.equal(evaluateTarget({ ...base, pool: null }, [idleCpu, idlePool], NOW).status, "config");
});

test("a manual CPU threshold of 1% breaches on normal load", () => {
  assert.equal(evaluateTarget({ ...base, cpu_pct: 1 }, [idleCpu, idlePool], NOW).status, "breach");
});

test("loadTargets rejects a target missing a required field", () => {
  const { label: _label, ...missing } = base;
  assert.throws(() => loadTargets([missing]), ConfigFault);
});

test("loadTargets rejects a window smaller than the breach count", () => {
  assert.throws(() => loadTargets([{ ...base, window_min: 10 }]), ConfigFault);
});

test("loadTargets accepts a null pool and rejects duplicate labels", () => {
  assert.equal(loadTargets([{ ...base, pool: null }])[0].pool, null);
  assert.throws(() => loadTargets([base, base]), ConfigFault);
});

test("metrics requests go only to the branch metrics endpoint", () => {
  const url = new URL(metricsUrl(base));
  assert.equal(url.hostname, "api.planetscale.com");
  assert.ok(url.pathname.endsWith("/branches/main/metrics"));
  assert.ok(url.searchParams.get("metrics")?.split(",").includes(CPU_METRIC));
});

test("parseSeries rejects a body without a series array", () => {
  assert.throws(() => parseSeries({ type: "MetricSeries" }), ConfigFault);
});

test("parseSeries keeps numeric samples and turns non-numeric ones into null", () => {
  const [series] = parseSeries({
    series: [{ metric: CPU_METRIC, labels: {}, points: [[NOW, 42], [NOW - 60, "x"]] }],
  });
  assert.deepEqual(series.points, [
    [NOW, 42],
    [NOW - 60, null],
  ]);
});

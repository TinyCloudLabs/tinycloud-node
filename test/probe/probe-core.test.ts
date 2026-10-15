import assert from "node:assert/strict";
import { mock, test } from "node:test";
import {
  DeadlineError,
  INITIAL_STATE,
  classify,
  decide,
  denseWatch,
  failBody,
  heartbeatUrl,
  parseState,
  readCheck,
  report,
  settle,
  type Deliver,
  type Fetch,
  type ReadClient,
  type StageResult,
} from "./probe-core";

const KEY = "0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318";
const HB = "https://uptime.betterstack.com/api/v1/heartbeat/CANARYtokenAbc123XYZ";

const never = () => new Promise<void>(() => {});

// Errors in the shapes the SDK actually produces (sdk-services ServiceError).
const http504 = { code: "NETWORK_ERROR", message: `Failed to get key "read-probe/fixed": 504 - <html>gateway</html>`, service: "kv", meta: { status: 504 } };
const undiciCause = (code: string) => Object.assign(new TypeError("fetch failed"), { cause: Object.assign(new Error(`connect ${code}`), { code }) });
const network = (code: string) => ({ code: "NETWORK_ERROR", message: "fetch failed", service: "kv", cause: undiciCause(code) });

/** A stub client whose stages behave as scripted and record what was called. */
function stub(behavior: Partial<Record<keyof ReadClient, () => Promise<void>>>): ReadClient & { calls: string[] } {
  const calls: string[] = [];
  const stage = (name: keyof ReadClient) => () => {
    calls.push(name);
    return (behavior[name] ?? (async () => {}))();
  };
  return { calls, signIn: stage("signIn"), ensureSpace: stage("ensureSpace"), kvRead: stage("kvRead"), sqlRead: stage("sqlRead") };
}

test("outcomes name what failed: deadline, HTTP status, refused, DNS", () => {
  assert.equal(classify(new DeadlineError("kv", 20_000)), "timeout >=20s");
  assert.equal(classify(http504), "HTTP 504");
  assert.equal(classify(network("ECONNREFUSED")), "connection refused");
  assert.equal(classify(network("ENOTFOUND")), "DNS");
  assert.equal(classify(network("EAI_AGAIN")), "DNS");
  assert.equal(classify({ code: "KV_NOT_FOUND", message: "Key not found", service: "kv" }), "error KV_NOT_FOUND");
});

test("a hung read fails at its deadline and the check stops there", async () => {
  mock.timers.enable({ apis: ["setTimeout"] });
  try {
    let kvStarted!: () => void;
    const started = new Promise<void>((r) => (kvStarted = r));
    const client = stub({
      kvRead: () => {
        kvStarted();
        return never();
      },
    });
    const lines: string[] = [];
    const check = readCheck(client, { log: (l) => lines.push(l), secrets: [KEY] });
    await started;
    mock.timers.tick(20_000);
    const { results, failure } = await check;
    assert.equal(failure?.stage, "kv");
    assert.equal(failure?.outcome, "timeout >=20s");
    assert.deepEqual(client.calls, ["signIn", "ensureSpace", "kvRead"], "sql is not attempted after kv failed");
    assert.deepEqual(results.map((r) => r.ok), [true, true, false]);
    assert.ok(lines.some((l) => l.includes("stage=kv") && l.includes("result=fail")));
  } finally {
    mock.timers.reset();
  }
});

test("a failed sign-in is reported as the signin stage, with the HTTP status", async () => {
  const client = stub({ signIn: async () => { throw http504; } });
  const { failure } = await readCheck(client, { log: () => {}, secrets: [KEY] });
  assert.deepEqual([failure?.stage, failure?.outcome], ["signin", "HTTP 504"]);
  assert.deepEqual(client.calls, ["signIn"]);
});

test("a read that completes but exceeds the slow threshold is a failure", async () => {
  let now = 0;
  const client = stub({ sqlRead: async () => void (now += 5_200) });
  const { failure } = await readCheck(client, { log: () => {}, secrets: [KEY], slowMs: 5_000, stages: ["sql"], now: () => now });
  assert.deepEqual([failure?.stage, failure?.ms, failure?.outcome], ["sql", 5_200, "slow 5.2s >5s"]);
});

test("logged error details never contain the key or the heartbeat URL", async () => {
  const leaky = { code: "NETWORK_ERROR", message: `bad sig from ${KEY} posting ${HB}`, service: "kv" };
  const client = stub({ kvRead: async () => { throw leaky; } });
  const lines: string[] = [];
  await readCheck(client, { log: (l) => lines.push(l), secrets: [KEY, HB] });
  const all = lines.join("\n");
  assert.ok(all.includes("[redacted]"));
  assert.ok(!all.includes(KEY) && !all.includes(HB));
});

const fail = (stage: string, outcome = "timeout >=20s", ms = 20_000): StageResult => ({ stage, ms, ok: false, outcome });
const ok = (stage: string): StageResult => ({ stage, ms: 300, ok: true, outcome: "ok" });

test("two failures in a row report /fail; a good read of everything pings and resets", () => {
  const t0 = Date.parse("2026-10-15T01:00:00Z");
  const first = decide(INITIAL_STATE, [ok("signin"), ok("space"), fail("kv")], t0);
  assert.equal(first.action, "none", "one failure (e.g. a ~60 s node restart) does not alert");
  const second = decide(first.state, [ok("signin"), ok("space"), fail("kv", "HTTP 504", 61_700)], t0 + 300_000);
  assert.deepEqual([second.action, second.consecutive, second.failure?.outcome], ["fail", 2, "HTTP 504"]);
  const reported = { ...second.state, lastFailReportAt: new Date(t0 + 300_000).toISOString() };
  // Dense samples 30 s apart don't re-post inside the minimum interval...
  assert.equal(decide(reported, [fail("kv")], t0 + 330_000).action, "none");
  // ...but a streak that lasts keeps re-reporting.
  assert.equal(decide(reported, [fail("kv")], t0 + 600_000).action, "fail");
  const healed = decide(reported, [ok("signin"), ok("space"), ok("kv"), ok("sql")], t0 + 900_000);
  assert.deepEqual(healed, { action: "ping", state: INITIAL_STATE, consecutive: 0 });
});

test("a failed sign-in counts against both reads; a healthy SQL read never hides a broken KV read", () => {
  const t0 = 0;
  const s1 = decide(INITIAL_STATE, [fail("signin", "HTTP 502")], t0);
  assert.deepEqual(s1.state.failures, { kv: 1, sql: 1 });
  const s2 = decide(s1.state, [ok("signin"), ok("space"), ok("kv"), ok("sql")], t0 + 1);
  assert.equal(s2.action, "ping");
  // KV keeps failing while SQL is fine (dense alternation): no ping, and KV still alerts.
  const k1 = decide(INITIAL_STATE, [fail("kv")], t0);
  const q1 = decide(k1.state, [ok("sql")], t0 + 30_000);
  assert.equal(q1.action, "none");
  const k2 = decide(q1.state, [fail("kv")], t0 + 60_000);
  assert.deepEqual([k2.action, k2.failure?.stage, k2.consecutive], ["fail", "kv", 2]);
});

test("a rejected /fail is retried on the next failure instead of starting the quiet window", async () => {
  const t0 = Date.parse("2026-10-15T01:00:00Z");
  const streak = decide(INITIAL_STATE, [fail("kv")], t0).state;
  const attempts: string[] = [];
  const rejecting: Deliver = async (action) => (attempts.push(action), { ok: false, line: "heartbeat fail NOT accepted: HTTP 503" });
  const first = await settle(streak, [fail("kv")], t0 + 30_000, rejecting);
  assert.deepEqual([first.action, first.delivered, first.state.lastFailReportAt], ["fail", false, undefined]);
  const accepting: Deliver = async (action) => (attempts.push(action), { ok: true, line: "heartbeat fail sent: HTTP 200" });
  const second = await settle(first.state, [fail("kv")], t0 + 60_000, accepting);
  assert.deepEqual([second.action, second.delivered], ["fail", true]);
  assert.equal(second.state.lastFailReportAt, new Date(t0 + 60_000).toISOString());
  assert.deepEqual(attempts, ["fail", "fail"]);
});

test("the state file round-trips; a missing or corrupt one starts from zero failures", () => {
  const state = decide(decide(INITIAL_STATE, [fail("sql", "HTTP 504", 61_712)], 0).state, [fail("sql")], 1).state;
  assert.deepEqual(parseState(JSON.stringify(state)), state);
  assert.deepEqual(parseState(undefined), INITIAL_STATE);
  assert.deepEqual(parseState("{not json"), INITIAL_STATE);
  assert.deepEqual(parseState('{"failures":{"kv":-3,"sql":"x"}}'), INITIAL_STATE);
});

test("the /fail body names stage, outcome, duration, build and UTC time on one line", () => {
  const failure: StageResult = { stage: "kv", ms: 20_004, ok: false, outcome: "timeout >=20s" };
  const body = failBody({ mode: "normal", consecutive: 2, failure, build: "1.20.6", host: "node.tinycloud.xyz", at: new Date("2026-10-15T01:05:07.123Z") });
  assert.equal(
    body,
    'TC-1176 node read probe FAIL (2 in a row, normal): stage=kv outcome="timeout >=20s" duration_ms=20004 build=1.20.6 host=node.tinycloud.xyz at=2026-10-15T01:05:07Z',
  );
  assert.ok(!body.includes("\n"));
});

test("ping GETs the heartbeat URL, /fail POSTs the body; only 2xx counts; lines never have the URL", async () => {
  const sent: { url: string; method?: string; body?: unknown }[] = [];
  let status = 200;
  const fetchFn: Fetch = async (url, init) => {
    sent.push({ url, method: init?.method, body: init?.body });
    return new Response("", { status });
  };
  const url = heartbeatUrl(HB);
  assert.deepEqual(await report("ping", url, undefined, fetchFn), { ok: true, line: "heartbeat ping sent: HTTP 200" });
  assert.deepEqual(await report("fail", url, "the body", fetchFn), { ok: true, line: "heartbeat fail sent: HTTP 200" });
  assert.deepEqual(sent, [
    { url: HB, method: "GET", body: undefined },
    { url: `${HB}/fail`, method: "POST", body: "the body" },
  ]);
  status = 503;
  assert.deepEqual(await report("ping", url, undefined, fetchFn), { ok: false, line: "heartbeat ping NOT accepted: HTTP 503" });

  const fetchDown: Fetch = async () => {
    throw undiciCause("ENOTFOUND");
  };
  assert.deepEqual(await report("fail", url, "x", fetchDown), { ok: false, line: "heartbeat fail NOT delivered: DNS" });
  assert.equal((await report("ping", undefined, undefined, fetchFn)).line, "heartbeat ping skipped: BETTERSTACK_HEARTBEAT_URL not set");
});

test("only a Better Stack heartbeat URL is accepted, and errors don't echo it", () => {
  assert.equal(heartbeatUrl(""), undefined);
  for (const bad of ["http://uptime.betterstack.com/api/v1/heartbeat/abc", "https://evil.example/api/v1/heartbeat/abc", "https://uptime.betterstack.com/api/v2/monitors", "nope"]) {
    assert.throws(() => heartbeatUrl(bad), (e: Error) => !e.message.includes(bad));
  }
});

const delivered: Deliver = async (action) => ({ ok: true, line: `heartbeat ${action} sent: HTTP 200` });

test("dense watch: alternating reads on the 30 s phase, both on the 5 min phase, one sign-in", async () => {
  const client = stub({});
  const sleeps: number[] = [];
  let now = 0;
  const { samples } = await denseWatch(client, {
    log: () => {},
    secrets: [KEY],
    deliver: delivered,
    schedule: [{ intervalMs: 30_000, count: 4 }, { intervalMs: 300_000, count: 2 }],
    clock: () => now,
    sleep: async (ms) => {
      sleeps.push(ms);
      now += ms;
    },
  });
  assert.equal(samples.length, 6);
  assert.deepEqual(samples.map((s) => s.results.map((r) => r.stage).join("+")), ["signin+space+kv", "sql", "kv", "sql", "kv+sql", "kv+sql"]);
  assert.deepEqual(sleeps, [30_000, 30_000, 30_000, 30_000, 300_000]);
  assert.equal(client.calls.filter((c) => c === "signIn").length, 1);
});

test("dense watch: KV reads over 5 s alert even while SQL is healthy, and only full recovery pings", async () => {
  let now = 0;
  let kvSlow = 3;
  const client = stub({
    kvRead: async () => {
      if (kvSlow > 0) {
        kvSlow -= 1;
        now += 6_000;
      }
    },
  });
  const reports: string[] = [];
  const { samples } = await denseWatch(client, {
    log: () => {},
    secrets: [KEY],
    deliver: async (action, failure, consecutive) => (reports.push(`${action}:${failure?.stage ?? "-"}:${consecutive}`), { ok: true, line: "" }),
    schedule: [{ intervalMs: 30_000, count: 8 }],
    clock: () => now,
    sleep: async (ms) => void (now += ms),
  });
  // kv on odd samples: slow at 1, 3, 5, healthy at 7. sql on even samples, always healthy.
  assert.deepEqual(samples.map((s) => s.ok), [false, true, false, true, false, true, true, true]);
  // 2nd slow KV (sample 3) reports; sample 5 is inside the 4 min minimum; sample 7 heals KV -> ping.
  assert.deepEqual(reports, ["fail:kv:2", "ping:-:0", "ping:-:0"]);
});

test("failure history carries across normal and dense runs", async () => {
  // A normal run failed KV once just before the promote: the dense watch's first slow KV is the 2nd in a row.
  const handedOver = decide(INITIAL_STATE, [ok("signin"), ok("space"), fail("kv")], 0).state;
  let now = 0;
  const reports: string[] = [];
  const saved: number[] = [];
  const dense = await denseWatch(stub({ kvRead: async () => void (now += 6_000) }), {
    log: () => {},
    secrets: [KEY],
    initialState: handedOver,
    onState: async (s) => void saved.push(s.failures.kv),
    deliver: async (action) => (reports.push(action), { ok: true, line: "" }),
    schedule: [{ intervalMs: 30_000, count: 1 }],
    clock: () => now,
    sleep: async () => {},
  });
  assert.deepEqual(reports, ["fail"]);
  assert.deepEqual(saved, [2]);

  // A healthy dense watch clears the streak, so the next normal failure is the 1st, not the 2nd.
  const cleared = await denseWatch(stub({}), {
    log: () => {},
    secrets: [KEY],
    initialState: dense.state,
    deliver: delivered,
    schedule: [{ intervalMs: 300_000, count: 1 }],
    sleep: async () => {},
  });
  assert.equal(decide(cleared.state, [ok("signin"), ok("space"), fail("kv")], 1).action, "none");
});

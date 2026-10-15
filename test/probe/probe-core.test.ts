import assert from "node:assert/strict";
import { mock, test } from "node:test";
import {
  DeadlineError,
  classify,
  decide,
  denseWatch,
  failBody,
  heartbeatUrl,
  parseState,
  readCheck,
  report,
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

test("two failures in a row report /fail; a good read pings and resets", () => {
  const t0 = Date.parse("2026-10-15T01:00:00Z");
  const first = decide({ consecutiveFailures: 0 }, false, t0);
  assert.equal(first.action, "none", "one failure (e.g. a ~60 s node restart) does not alert");
  const second = decide(first.state, false, t0 + 300_000);
  assert.equal(second.action, "fail");
  assert.equal(second.state.consecutiveFailures, 2);
  // Dense samples 30 s apart don't re-post inside the minimum interval...
  assert.equal(decide(second.state, false, t0 + 330_000).action, "none");
  // ...but a streak that lasts keeps re-reporting.
  assert.equal(decide(second.state, false, t0 + 600_000).action, "fail");
  const ok = decide(second.state, true, t0 + 900_000);
  assert.deepEqual(ok, { action: "ping", state: { consecutiveFailures: 0 } });
});

test("a missing or corrupt state file starts from zero failures", () => {
  assert.deepEqual(parseState(undefined), { consecutiveFailures: 0 });
  assert.deepEqual(parseState("{not json"), { consecutiveFailures: 0 });
  assert.deepEqual(parseState('{"consecutiveFailures":-3}'), { consecutiveFailures: 0 });
  assert.deepEqual(parseState('{"consecutiveFailures":1}'), { consecutiveFailures: 1 });
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

test("ping GETs the heartbeat URL, /fail POSTs the body; the result line never has the URL", async () => {
  const sent: { url: string; method?: string; body?: unknown }[] = [];
  const fetchOk: Fetch = async (url, init) => {
    sent.push({ url, method: init?.method, body: init?.body });
    return new Response("", { status: 200 });
  };
  const url = heartbeatUrl(HB);
  const ping = await report("ping", url, undefined, fetchOk);
  const fail = await report("fail", url, "the body", fetchOk);
  assert.deepEqual(sent, [
    { url: HB, method: "GET", body: undefined },
    { url: `${HB}/fail`, method: "POST", body: "the body" },
  ]);
  assert.equal(ping, "heartbeat ping sent: HTTP 200");
  assert.equal(fail, "heartbeat fail sent: HTTP 200");

  const fetchDown: Fetch = async () => {
    throw undiciCause("ENOTFOUND");
  };
  const down = await report("fail", url, "x", fetchDown);
  assert.equal(down, "heartbeat fail failed: DNS");
  assert.equal(await report("ping", undefined, undefined, fetchOk), "heartbeat ping skipped: BETTERSTACK_HEARTBEAT_URL not set");
});

test("only a Better Stack heartbeat URL is accepted, and errors don't echo it", () => {
  assert.equal(heartbeatUrl(""), undefined);
  for (const bad of ["http://uptime.betterstack.com/api/v1/heartbeat/abc", "https://evil.example/api/v1/heartbeat/abc", "https://uptime.betterstack.com/api/v2/monitors", "nope"]) {
    assert.throws(() => heartbeatUrl(bad), (e: Error) => !e.message.includes(bad));
  }
});

test("dense watch: alternating reads on the 30 s phase, both on the 5 min phase, one sign-in", async () => {
  const client = stub({});
  const sleeps: number[] = [];
  let now = 0;
  const samples = await denseWatch(client, {
    log: () => {},
    secrets: [KEY],
    report: async () => {},
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

test("dense watch: two reads over 5 s in a row report /fail, then a good read pings", async () => {
  let now = 0;
  let slowReads = 2;
  const read = async () => {
    if (slowReads > 0) {
      slowReads -= 1;
      now += 6_000;
    }
  };
  const client = stub({ kvRead: read, sqlRead: read });
  const reports: string[] = [];
  const samples = await denseWatch(client, {
    log: () => {},
    secrets: [KEY],
    report: async (action, failure, consecutive) => void reports.push(`${action}:${failure?.stage ?? "-"}:${consecutive}`),
    schedule: [{ intervalMs: 30_000, count: 3 }],
    clock: () => now,
    sleep: async (ms) => void (now += ms),
  });
  assert.deepEqual(samples.map((s) => s.ok), [false, false, true]);
  // Sample 1 (kv) alone doesn't alert; sample 2 (sql) is the 2nd in a row; sample 3 resolves.
  assert.deepEqual(reports, ["fail:sql:2", "ping:-:0"]);
});

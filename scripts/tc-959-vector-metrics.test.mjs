import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import test from "node:test";
import { parseGelfReceivedSample, shippedEventNameCounts, shippedEventNameDelta } from "./tc-959-vector-metrics.mjs";

test("parses the counter value and exporter sample timestamp separately", () => {
  const sample = parseGelfReceivedSample(`# HELP vector_component_received_events_total Events received\nvector_component_received_events_total{component_id="gelf_in",component_kind="source",component_type="socket",host="vector",mode="udp"} 1 1791992950070\n`);
  assert.deepEqual(sample, { value: 1, timestamp: 1791992950070 });
});

test("requires a timestamp for freshness-sensitive source samples", () => {
  assert.equal(parseGelfReceivedSample(`vector_component_received_events_total{component_id="gelf_in",component_kind="source",component_type="socket",host="vector",mode="udp"} 1\n`), null);
});
test("received-sample CLI prints value and timestamp for a captured exporter sample", () => {
  const input = `vector_component_received_events_total{component_id="gelf_in",component_kind="source",component_type="socket",host="vector",mode="udp"} 1 1791992950070\n`;
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("./tc-959-vector-metrics.mjs", import.meta.url)), "received-sample"], {
    input,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "1 1791992950070");
});
test("probe-count CLI counts only the exact probe event and code pair", () => {
  const input = [
    JSON.stringify({ event: "node_warning", event_code: "invocation_replay_insert_failed" }),
    JSON.stringify({ event: "node_warning", event_code: "different_warning" }),
    JSON.stringify({ event: "logship_gate_summary_total", event_code: "logship_gate_summary_total" }),
    JSON.stringify({ event: "ingress_request_slow", event_code: "ingress_request_slow" }),
    JSON.stringify({ event: "different_event", event_code: "invocation_replay_insert_failed" }),
  ].join("\n");
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("./tc-959-vector-metrics.mjs", import.meta.url)), "probe-count"], {
    input,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "1");
});

test("event-name delta exposes new fixed enums without console content", () => {
  const before = shippedEventNameCounts([
    JSON.stringify({ event: "node_warning", event_code: "invocation_replay_insert_failed", message: "before" }),
    JSON.stringify({ event: "logship_gate_summary_total", event_code: "logship_gate_summary_total" }),
  ].join("\n"));
  const after = shippedEventNameCounts([
    JSON.stringify({ event: "node_warning", event_code: "invocation_replay_insert_failed", message: "before" }),
    JSON.stringify({ event: "logship_gate_summary_total", event_code: "logship_gate_summary_total" }),
    JSON.stringify({ event: "ingress_request_slow", event_code: "ingress_request_slow" }),
    JSON.stringify({ event: "node_error", event_code: "safe_fixed_code", message: "secret-like content" }),
  ].join("\n"));
  assert.deepEqual(shippedEventNameDelta(before, after), [
    { event: "ingress_request_slow", event_code: "ingress_request_slow", count: 1 },
    { event: "node_error", event_code: "safe_fixed_code", count: 1 },
  ]);
});

test("event-name-delta CLI reports only newly observed enum pairs", () => {
  const before = [{ event: "logship_gate_summary_total", event_code: "logship_gate_summary_total", count: 1 }];
  const after = [
    ...before,
    { event: "node_warning", event_code: "invocation_replay_insert_failed", count: 1 },
  ];
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("./tc-959-vector-metrics.mjs", import.meta.url)), "event-name-delta"], {
    input: `${JSON.stringify(before)}\n${JSON.stringify(after)}\n`,
    encoding: "utf8",
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "event=node_warning event_code=invocation_replay_insert_failed count=1\n");
});

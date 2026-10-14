import assert from "node:assert/strict";
import test from "node:test";
import { parseGelfReceivedSample } from "./tc-959-vector-metrics.mjs";

test("parses the counter value and exporter sample timestamp separately", () => {
  const sample = parseGelfReceivedSample(`# HELP vector_component_received_events_total Events received\nvector_component_received_events_total{component_id="gelf_in",component_kind="source",component_type="socket",host="vector",mode="udp"} 1 1791992950070\n`);
  assert.deepEqual(sample, { value: 1, timestamp: 1791992950070 });
});

test("requires a timestamp for freshness-sensitive source samples", () => {
  assert.equal(parseGelfReceivedSample(`vector_component_received_events_total{component_id="gelf_in",component_kind="source",component_type="socket",host="vector",mode="udp"} 1\n`), null);
});

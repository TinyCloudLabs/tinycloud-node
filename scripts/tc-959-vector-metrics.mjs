import { fileURLToPath } from "node:url";

const expectedLabels = ["component_id", "component_kind", "component_type", "host", "mode"];

function parseLabels(serialized) {
  const labels = Object.create(null);
  let remaining = serialized;
  while (remaining.length > 0) {
    const match = remaining.match(/^([a-zA-Z_][a-zA-Z0-9_]*)="((?:\\.|[^"\\])*)"/);
    if (!match || Object.hasOwn(labels, match[1])) return null;
    labels[match[1]] = match[2];
    remaining = remaining.slice(match[0].length);
    if (remaining.length === 0) break;
    if (remaining[0] !== ",") return null;
    remaining = remaining.slice(1);
  }
  return labels;
}

export function parseGelfReceivedSample(metrics) {
  for (const line of metrics.split(/\r?\n/)) {
    const sample = line.match(/^vector_component_received_events_total\{([^}]*)\}\s+(\d+)\s+(\d+)\s*$/);
    if (!sample) continue;
    const labels = parseLabels(sample[1]);
    if (!labels) continue;
    const names = Object.keys(labels).sort();
    if (names.length !== expectedLabels.length || names.some((name, index) => name !== expectedLabels[index])) continue;
    if (labels.component_id !== "gelf_in" || labels.component_kind !== "source" || labels.component_type !== "socket" || labels.mode !== "udp" || labels.host.length === 0) continue;
    const value = Number(sample[2]);
    const timestamp = Number(sample[3]);
    if (Number.isSafeInteger(value) && Number.isSafeInteger(timestamp)) return { value, timestamp };
  }
  return null;
}

export function parseGelfReceivedCounter(metrics) {
  return parseGelfReceivedSample(metrics)?.value ?? null;
}

function parsedEvents(logs) {
  const records = [];
  for (const line of logs.split(/\r?\n/)) {
    try {
      const record = JSON.parse(line);
      if (record && typeof record.event === "string") records.push(record);
    } catch {
      // Vector's own text logs are not console-sink events.
    }
  }
  return records;
}

export function countShippedEvents(logs) {
  return parsedEvents(logs).length;
}

export function countShippedEvent(logs, event) {
  return parsedEvents(logs).filter((record) => record.event === event).length;
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  const [operation, event] = process.argv.slice(2);
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  if (operation === "received-counter") {
    const value = parseGelfReceivedCounter(input);
    process.stdout.write(value === null ? "missing" : String(value));
  } else if (operation === "received-sample") {
    process.stdout.write(sample === null ? "missing" : `${sample.value} ${sample.timestamp}`);
  } else if (operation === "shipped-count") {
    process.stdout.write(String(countShippedEvents(input)));
  } else if (operation === "event-count" && event) {
    process.stdout.write(String(countShippedEvent(input, event)));
  } else {
    throw new Error("usage: tc-959-vector-metrics.mjs received-counter|received-sample|shipped-count|event-count EVENT");
  }
}

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
export function countShippedProbeEvents(logs) {
  return parsedEvents(logs).filter((record) => record.event === "node_warning" && record.event_code === "invocation_replay_insert_failed").length;
}

export function shippedEventNameCounts(logs) {
  const counts = new Map();
  for (const record of parsedEvents(logs)) {
    if (typeof record.event !== "string" || typeof record.event_code !== "string") continue;
    if (!/^[a-z][a-z0-9_]*$/.test(record.event) || !/^[a-z][a-z0-9_]*$/.test(record.event_code)) continue;
    const key = `${record.event}\t${record.event_code}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return [...counts].map(([key, count]) => {
    const [event, event_code] = key.split("\t");
    return { event, event_code, count };
  });
}

export function shippedEventNameDelta(before, after) {
  const prior = new Map(before.map(({ event, event_code, count }) => [`${event}\t${event_code}`, count]));
  return after.flatMap(({ event, event_code, count }) => {
    const delta = count - (prior.get(`${event}\t${event_code}`) ?? 0);
    return delta > 0 ? [{ event, event_code, count: delta }] : [];
  });
}

if (fileURLToPath(import.meta.url) === process.argv[1]) {
  const [operation, event] = process.argv.slice(2);
  let input = "";
  for await (const chunk of process.stdin) input += chunk;
  if (operation === "received-counter") {
    const value = parseGelfReceivedCounter(input);
    process.stdout.write(value === null ? "missing" : String(value));
  } else if (operation === "received-sample") {
    const sample = parseGelfReceivedSample(input);
    process.stdout.write(sample === null ? "missing" : `${sample.value} ${sample.timestamp}`);
  } else if (operation === "shipped-count") {
    process.stdout.write(String(countShippedEvents(input)));
  } else if (operation === "event-count" && event) {
    process.stdout.write(String(countShippedEvent(input, event)));
  } else if (operation === "probe-count") {
    process.stdout.write(String(countShippedProbeEvents(input)));
  } else if (operation === "event-name-counts") {
    process.stdout.write(JSON.stringify(shippedEventNameCounts(input)));
  } else if (operation === "event-name-delta") {
    const [before, after] = input.trimEnd().split(/\r?\n/).map((line) => JSON.parse(line));
    for (const { event, event_code, count } of shippedEventNameDelta(before, after)) {
      process.stdout.write(`event=${event} event_code=${event_code} count=${count}\n`);
    }
  } else {
    throw new Error("usage: tc-959-vector-metrics.mjs received-counter|received-sample|shipped-count|event-count EVENT|probe-count|event-name-counts|event-name-delta");
  }
}

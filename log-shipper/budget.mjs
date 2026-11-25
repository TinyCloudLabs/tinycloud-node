import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const schema = JSON.parse(readFileSync(new URL('./fields.json', import.meta.url), 'utf8')).services['tinycloud-node'];
const longest = values => values.reduce((chosen, value) => Buffer.byteLength(value) > Buffer.byteLength(chosen) ? value : chosen, '');
/** Event codes that ship as individual events, outside the count reducer (TC-1840). */
export const INDIVIDUAL_EVENT_CODES = Object.freeze(['db_failure_5xx']);
/** Event codes the shipper emits itself; no node log line maps to them (TC-1843). */
export const SHIPPER_EVENT_CODES = Object.freeze(['errors_dropped']);
const aggregatedCodes = schema.fields.event_code.values.filter(code => !INDIVIDUAL_EVENT_CODES.includes(code) && !SHIPPER_EVENT_CODES.includes(code));

/** Thirty days, not a calendar-month or billing-period guarantee. */
export const MINUTES_30_DAYS = 30 * 24 * 60;
/** Decimal 0.48 GB allocated to requests only; diagnostic reserve is additional. */
export const REQUEST_ALLOCATION_BYTES = 480_000_000;
/** Seconds in one cap window; the shipper caps and counts per window and reports it as `window_s`. */
export const CAP_WINDOW_SECONDS = 60;
/**
 * Decimal 0.6 GB (20% of the shared 3 GB) reserved, worst case, for the capped classes and their dropped-count
 * events; additional to the request allocation and the diagnostic reserve. With the caps below the worst case is
 * sum(capPerMinute x worst-valid bytes) x 43,200 minutes, plus one dropped-count event per class per minute.
 */
export const CAPPED_ALLOCATION_BYTES = 600_000_000;
/**
 * Per-minute caps (TC-1843): db_failure_5xx is the node's 5xx diagnostic event; node_request_5xx and
 * ingress_request_5xx are the node and ingress request events with status >= 500; node_request_4xx and
 * ingress_request_4xx are the node and ingress request events with status 400 to 499. `representative` names the
 * worst-valid event in representativeEvents used for the size arithmetic (its status is three digits, as in 4xx).
 * The 4xx cap is the largest whole number that keeps the worst case, including one dropped-count event per class
 * per minute, within CAPPED_ALLOCATION_BYTES: 3. A node 5xx line also carries its `error_code` (TC-3834), at most
 * MAX_ERROR_CODE_LEN bytes, and the three DB accounting fields (TC-4308, +112 bytes). With the DB accounting the
 * node_request_5xx cap is 8 (TC-4308; it was 10): the worst case is 596,203,200 bytes NDJSON and 597,888,000 bytes
 * json-array (a node_request_5xx cap of 9 gives 622,987,200 bytes json-array, and the former 10 gives 648,086,400).
 */
export const CAPPED_CLASSES = Object.freeze({
  db_failure_5xx: Object.freeze({ capPerMinute: 10, representative: 'dbFailure' }),
  node_request_5xx: Object.freeze({ capPerMinute: 8, representative: 'nodeCapped5xx' }),
  ingress_request_5xx: Object.freeze({ capPerMinute: 10, representative: 'ingress' }),
  node_request_4xx: Object.freeze({ capPerMinute: 3, representative: 'nodeCapped' }),
  ingress_request_4xx: Object.freeze({ capPerMinute: 3, representative: 'ingress' }),
});

/**
 * The longest `error_code` a node 5xx line may carry (TC-3834), in bytes. It is the node's own bound (tinycloud-core
 * `MAX_ERROR_CODE_LEN`), not derived here, and a FLOOR under the budget, not its exact maximum: the capped reserve above
 * has room for a longest code of up to 19 bytes under json-array framing and 23 under NDJSON (TC-4308 cap of 8). A longer
 * code is a node change, not a budget one.
 */
export const MAX_ERROR_CODE_LEN = 13;

const common = { level: 'info', ts: '9999-12-31T23:59:59.999Z' };
// Worst-valid N2 correlation fields on a node request: longest request id, both full-width pseudonyms.
const correlation = {
  request_id: 'ffffffff-ffff-8fff-bfff-ffffffffffff', request_id_replaced: true,
  account_hash: 'f'.repeat(64), space_hash: 'f'.repeat(64),
};
// Worst-valid per-request DB accounting (TC-3739): two long round-trippable fractional timings and the widest
// attempt count. The shipper copies them onto node_request lines with status below 400 (the request allocation) and
// from 500 (the capped 5xx class, TC-4308); 4xx lines never carry them.
const dbAccounting = {
  pool_wait_ms: 0.0000010000000000000002, query_time_ms: 0.0000010000000000000002,
  query_count: schema.fields.query_count.max,
};
const request = {
  method: longest(schema.fields.method.values), route: longest(schema.fields.route.values),
  status: schema.fields.status.max,
};

/**
 * Representative worst-valid N0 wire records: longest schema strings, maximum
 * integer widths, and a long round-trippable fractional ingress duration.
 * Only node_request carries N2 correlation fields (request_id, request_id_replaced, account_hash,
 * space_hash); the ingress log carries none. db_hash is emitted by the F6 typed events only. The node's 5xx
 * diagnostic (dbFailure) ships individually, one event per failing request: it is not an aggregated code. The
 * shipper's dropped-count event (errorsDropped) is emitted by the shipper itself, one per capped class per window. The
 * disk headroom event (storageHeadroom, TC-2917) ships once per local store every 5 minutes. `node` is the request
 * allocation's node line (status below 400, so it also carries the TC-3739 DB accounting); `nodeCapped` is the
 * capped 4xx node line, which the shipper never gives DB accounting; `nodeCapped5xx` is the same line for a 5xx,
 * which also carries the longest declared `error_code` (TC-3834) and, since TC-4308, the DB accounting.
 * Bytes below are exact for these records, not a proven Vector float-serializer
 * upper bound or a fixed event-size guard. Actual ingestion/billing can differ.
 */
export const representativeEvents = Object.freeze({
  node: Object.freeze({ ...common, event: 'node_request', svc: 'api', ...request, status: 399, latency_us: schema.fields.latency_us.max, ...correlation, ...dbAccounting }),
  nodeCapped: Object.freeze({ ...common, event: 'node_request', svc: 'api', ...request, latency_us: schema.fields.latency_us.max, ...correlation }),
  nodeCapped5xx: Object.freeze({ ...common, event: 'node_request', svc: 'api', ...request, latency_us: schema.fields.latency_us.max, ...correlation, ...dbAccounting, error_code: longest(schema.fields.error_code.values) }),
  ingress: Object.freeze({ ...common, event: 'ingress_request', svc: 'ingress', ...request, request_time_seconds: 0.0000010000000000000002 }),
  diagnostic: Object.freeze({ level: 'warn', ts: common.ts, event: 'node_warning', svc: 'api', event_code: longest(aggregatedCodes), event_count: schema.fields.event_count.max }),
  dbFailure: Object.freeze({
    level: 'warn', ts: common.ts, event: 'node_warning', svc: 'api', event_code: INDIVIDUAL_EVENT_CODES[0], status: 599,
    code: longest(schema.fields.code.values), service: longest(schema.fields.service.values), route: request.route,
    elapsed_ms: schema.fields.elapsed_ms.max, failure_kind: longest(schema.fields.failure_kind.values), write_may_have_applied: false, db_hash: 'f'.repeat(64),
  }),
  errorsDropped: Object.freeze({
    level: 'warn', ts: common.ts, event: 'node_warning', svc: 'api', event_code: SHIPPER_EVENT_CODES[0],
    class: longest(schema.fields.class.values), dropped: schema.fields.dropped.max, window_s: schema.fields.window_s.max,
  }),
  storageHeadroom: Object.freeze({
    level: 'info', ts: common.ts, event: 'node_storage_headroom', svc: 'api',
    store: longest(schema.fields.store.values), free_bytes: schema.fields.free_bytes.max,
  }),
  gate: Object.freeze({ level: 'warn', ts: common.ts, event: 'logship_gate_summary_total', svc: 'logship', reason: longest(schema.fields.reason.values), count: schema.fields.count.max }),
});

/**
 * NDJSON charges one newline per event. json-array conservatively charges a
 * singleton [event] per event (two brackets). A real N-event JSON array costs
 * sum(object bytes) + N + 1 (commas and brackets), so batching saves N - 1 bytes
 * versus this conservative singleton estimate. No HTTP/TLS headers, gzip savings,
 * provider enrichment, retries, or billing-specific overhead are assumed.
 */
export function serializedEventBytes(event, framing = 'ndjson') {
  if (framing !== 'ndjson' && framing !== 'json-array') throw new RangeError('unsupported framing');
  return Buffer.byteLength(JSON.stringify(event)) + (framing === 'ndjson' ? 1 : 2);
}

/**
 * Full individual-request retention: each request costs one node plus one ingress
 * event. This is arithmetic only: no sampling, aggregation or sink cap applies to the
 * requests counted here (status below 400). The classes in CAPPED_CLASSES (request events with status 400 and
 * above and the 5xx diagnostic) are capped per window and are reserved separately below.
 * Diagnostic and gate group-rate assumptions reserve additional bytes separately;
 * defaults are conservative planning rates, NOT guaranteed emission ceilings.
 * The shared Better Stack 3 GB free tier is shared with other sources and is NOT
 * guaranteed. Traffic above the sustainable rate needs more allocation or spend,
 * not hidden request dropping. UDP and bounded queues can still lose transport.
 */
export function calculateBudget({
  requestsPerMinute = 1,
  diagnosticEventsPerMinute = aggregatedCodes.length * 2,
  gateEventsPerMinute = schema.fields.reason.values.length,
  allocationBytes = REQUEST_ALLOCATION_BYTES,
  framing = 'ndjson',
} = {}) {
  for (const [name, value] of Object.entries({ requestsPerMinute, diagnosticEventsPerMinute, gateEventsPerMinute, allocationBytes })) {
    if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) throw new RangeError(`${name} must be finite non-negative`);
  }
  const eventBytes = Object.fromEntries(Object.entries(representativeEvents).map(([name, event]) => [name, serializedEventBytes(event, framing)]));
  const requestPairBytes = eventBytes.node + eventBytes.ingress;
  const requestBytes30Days = requestsPerMinute * requestPairBytes * MINUTES_30_DAYS;
  const diagnosticReserveBytes30Days = (diagnosticEventsPerMinute * eventBytes.diagnostic + gateEventsPerMinute * eventBytes.gate) * MINUTES_30_DAYS;
  // TC-2917: a fixed rate, one event per store every 5 minutes, whatever the traffic; reported on its own.
  const headroomEventsPerMinute = schema.fields.store.values.length / 5;
  const headroomBytes30Days = headroomEventsPerMinute * eventBytes.storageHeadroom * MINUTES_30_DAYS;
  const sustainableRequestsPerMinute = allocationBytes / (requestPairBytes * MINUTES_30_DAYS);
  const cappedClasses = Object.fromEntries(Object.entries(CAPPED_CLASSES).map(([name, { capPerMinute, representative }]) => [name, {
    capPerMinute, eventBytes: eventBytes[representative], bytes30Days: capPerMinute * eventBytes[representative] * MINUTES_30_DAYS,
  }]));
  // Worst case: every window ships its full cap and one dropped-count event per class.
  const cappedEventBytes30Days = Object.values(cappedClasses).reduce((sum, { bytes30Days }) => sum + bytes30Days, 0);
  const droppedCountBytes30Days = Object.keys(CAPPED_CLASSES).length * eventBytes.errorsDropped * MINUTES_30_DAYS;
  const cappedReserveBytes30Days = cappedEventBytes30Days + droppedCountBytes30Days;
  const totalBytes30Days = requestBytes30Days + diagnosticReserveBytes30Days;
  return {
    sizeBasis: 'exact JSON bytes of representative worst-valid N0 events; not a hard serialized-size ceiling',
    framing, eventBytes, requestPairBytes, requestsPerMinute, allocationBytes,
    requestBytes30Days, diagnosticReserveBytes30Days,
    totalBytes30Days,
    sustainableRequestsPerMinute,
    sustainableWholeRequestsPerMinute: Math.floor(sustainableRequestsPerMinute),
    withinRequestAllocation: requestBytes30Days <= allocationBytes,
    diagnosticEventsPerMinute, gateEventsPerMinute, headroomEventsPerMinute, headroomBytes30Days,
    cappedWindowSeconds: CAP_WINDOW_SECONDS, cappedClasses,
    cappedEventBytes30Days, droppedCountBytes30Days, cappedReserveBytes30Days,
    cappedAllocationBytes: CAPPED_ALLOCATION_BYTES,
    withinCappedAllocation: cappedReserveBytes30Days <= CAPPED_ALLOCATION_BYTES,
    totalWithCappedBytes30Days: totalBytes30Days + cappedReserveBytes30Days,
    freeTierGuaranteed: false,
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const requestsPerMinute = process.argv[2] === undefined ? 1 : Number(process.argv[2]);
  console.log(JSON.stringify({
    ndjson: calculateBudget({ requestsPerMinute }),
    jsonArray: calculateBudget({ requestsPerMinute, framing: 'json-array' }),
  }, null, 2));
}

import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

const schema = JSON.parse(readFileSync(new URL('./fields.json', import.meta.url), 'utf8')).services['tinycloud-node'];
const longest = values => values.reduce((chosen, value) => Buffer.byteLength(value) > Buffer.byteLength(chosen) ? value : chosen, '');

/** Thirty days, not a calendar-month or billing-period guarantee. */
export const MINUTES_30_DAYS = 30 * 24 * 60;
/** Decimal 0.48 GB allocated to requests only; diagnostic reserve is additional. */
export const REQUEST_ALLOCATION_BYTES = 480_000_000;

const common = { level: 'info', ts: '9999-12-31T23:59:59.999Z' };
// Worst-valid N2 correlation fields on a node request: longest request id, both full-width pseudonyms.
const correlation = {
  request_id: 'ffffffff-ffff-8fff-bfff-ffffffffffff', request_id_replaced: true,
  account_hash: 'f'.repeat(64), space_hash: 'f'.repeat(64),
};
const request = {
  method: longest(schema.fields.method.values), route: longest(schema.fields.route.values),
  status: schema.fields.status.max,
};

/**
 * Representative worst-valid N0 wire records: longest schema strings, maximum
 * integer widths, and a long round-trippable fractional ingress duration.
 * Only node_request carries N2 correlation fields (request_id, request_id_replaced, account_hash,
 * space_hash); the ingress log carries none. db_hash is emitted by the F6 typed events only.
 * Bytes below are exact for these records, not a proven Vector float-serializer
 * upper bound or a fixed event-size guard. Actual ingestion/billing can differ.
 */
export const representativeEvents = Object.freeze({
  node: Object.freeze({ ...common, event: 'node_request', svc: 'api', ...request, latency_us: schema.fields.latency_us.max, ...correlation }),
  ingress: Object.freeze({ ...common, event: 'ingress_request', svc: 'ingress', ...request, request_time_seconds: 0.0000010000000000000002 }),
  diagnostic: Object.freeze({ level: 'warn', ts: common.ts, event: 'node_warning', svc: 'api', event_code: longest(schema.fields.event_code.values), event_count: schema.fields.event_count.max }),
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
 * event. This is arithmetic only: no sampling, aggregation, throttle, or sink cap.
 * Diagnostic and gate group-rate assumptions reserve additional bytes separately;
 * defaults are conservative planning rates, NOT guaranteed emission ceilings.
 * The shared Better Stack 3 GB free tier is shared with other sources and is NOT
 * guaranteed. Traffic above the sustainable rate needs more allocation or spend,
 * not hidden request dropping. UDP and bounded queues can still lose transport.
 */
export function calculateBudget({
  requestsPerMinute = 1,
  diagnosticEventsPerMinute = schema.fields.event_code.values.length * 2,
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
  const sustainableRequestsPerMinute = allocationBytes / (requestPairBytes * MINUTES_30_DAYS);
  return {
    sizeBasis: 'exact JSON bytes of representative worst-valid N0 events; not a hard serialized-size ceiling',
    framing, eventBytes, requestPairBytes, requestsPerMinute, allocationBytes,
    requestBytes30Days, diagnosticReserveBytes30Days,
    totalBytes30Days: requestBytes30Days + diagnosticReserveBytes30Days,
    sustainableRequestsPerMinute,
    sustainableWholeRequestsPerMinute: Math.floor(sustainableRequestsPerMinute),
    withinRequestAllocation: requestBytes30Days <= allocationBytes,
    diagnosticEventsPerMinute, gateEventsPerMinute,
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

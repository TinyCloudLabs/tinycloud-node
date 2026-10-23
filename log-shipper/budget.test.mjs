import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { calculateBudget, representativeEvents, serializedEventBytes, INDIVIDUAL_EVENT_CODES, SHIPPER_EVENT_CODES, CAPPED_CLASSES, CAPPED_ALLOCATION_BYTES, CAP_WINDOW_SECONDS, MINUTES_30_DAYS, REQUEST_ALLOCATION_BYTES } from './budget.mjs';

const fields = JSON.parse(await readFile(new URL('./fields.json', import.meta.url), 'utf8'));
const nodeSchema = fields.services['tinycloud-node'];

test('request representatives use the schema longest route and method; only node requests carry correlation fields', () => {
  const routes = nodeSchema.fields.route.values;
  const methods = nodeSchema.fields.method.values;
  for (const row of [representativeEvents.node, representativeEvents.ingress]) {
    assert.equal(row.route.length, Math.max(...routes.map(value => value.length)));
    assert.equal(row.method.length, Math.max(...methods.map(value => value.length)));
    assert.ok(routes.includes(row.route));
    assert.ok(methods.includes(row.method));
    assert.equal(row.ts.length, 24);
    for (const key of ['request_id', 'request_id_replaced', 'account_hash', 'space_hash']) {
      assert.equal(Object.hasOwn(row, key), row === representativeEvents.node);
    }
    if (row === representativeEvents.node) for (const key of ['request_id', 'account_hash', 'space_hash']) assert.match(row[key], new RegExp(nodeSchema.fields[key].regex));
    assert.equal(Object.hasOwn(row, 'db_hash'), false);
  }
  assert.equal(representativeEvents.node.event, 'node_request');
  assert.equal(representativeEvents.node.latency_us, Number.MAX_SAFE_INTEGER);
  assert.equal(representativeEvents.ingress.event, 'ingress_request');
  assert.ok(representativeEvents.ingress.request_time_seconds >= 0 && representativeEvents.ingress.request_time_seconds <= 86400);
});

test('exact serialized bytes account for newlines or singleton JSON array overhead', () => {
  for (const row of Object.values(representativeEvents)) {
    assert.equal(serializedEventBytes(row, 'ndjson'), Buffer.byteLength(`${JSON.stringify(row)}\n`));
    assert.equal(serializedEventBytes(row, 'json-array'), Buffer.byteLength(JSON.stringify([row])));
  }
  assert.equal(MINUTES_30_DAYS, 43200);
  assert.equal(REQUEST_ALLOCATION_BYTES, 480_000_000);
  assert.throws(() => serializedEventBytes({}, 'raw'), /framing/);
});

test('every request costs both full events; increasing traffic is linear without a sampler', () => {
  const one = calculateBudget({ requestsPerMinute: 1, diagnosticEventsPerMinute: 0, gateEventsPerMinute: 0 });
  const many = calculateBudget({ requestsPerMinute: 10000, diagnosticEventsPerMinute: 0, gateEventsPerMinute: 0 });
  const pair = serializedEventBytes(representativeEvents.node, 'ndjson') + serializedEventBytes(representativeEvents.ingress, 'ndjson');
  assert.equal(one.requestPairBytes, pair);
  assert.equal(one.requestBytes30Days, pair * 43200);
  assert.equal(many.requestBytes30Days, one.requestBytes30Days * 10000);
  assert.equal(many.totalBytes30Days, many.requestBytes30Days);
  assert.equal(many.withinRequestAllocation, false);
  assert.equal(one.freeTierGuaranteed, false);
});

test('allocation boundary is sustainable requests per minute, not a throttle', () => {
  for (const framing of ['ndjson', 'json-array']) {
    const base = calculateBudget({ requestsPerMinute: 0, framing, diagnosticEventsPerMinute: 0, gateEventsPerMinute: 0 });
    const rate = REQUEST_ALLOCATION_BYTES / (base.requestPairBytes * MINUTES_30_DAYS);
    assert.equal(base.sustainableRequestsPerMinute, rate);
    assert.equal(base.sustainableWholeRequestsPerMinute, Math.floor(rate));
    const fits = calculateBudget({ requestsPerMinute: Math.floor(rate), framing, diagnosticEventsPerMinute: 0, gateEventsPerMinute: 0 });
    const exceeds = calculateBudget({ requestsPerMinute: Math.floor(rate) + 1, framing, diagnosticEventsPerMinute: 0, gateEventsPerMinute: 0 });
    assert.equal(fits.withinRequestAllocation, true);
    assert.equal(exceeds.withinRequestAllocation, false);
  }
});

test('fixed diagnostic reserve is separate from the request allocation', () => {
  const budget = calculateBudget({ requestsPerMinute: 1, diagnosticEventsPerMinute: 53, gateEventsPerMinute: 9 });
  assert.equal(budget.diagnosticReserveBytes30Days,
    43200 * (53 * serializedEventBytes(representativeEvents.diagnostic, 'ndjson') + 9 * serializedEventBytes(representativeEvents.gate, 'ndjson')));
  assert.equal(budget.totalBytes30Days, budget.requestBytes30Days + budget.diagnosticReserveBytes30Days);
  assert.equal(budget.sustainableRequestsPerMinute, REQUEST_ALLOCATION_BYTES / (budget.requestPairBytes * 43200));
  const noTraffic = calculateBudget({ requestsPerMinute: 0 });
  assert.equal(noTraffic.requestBytes30Days, 0);
  assert.ok(noTraffic.diagnosticReserveBytes30Days > 0);
  assert.equal(noTraffic.totalBytes30Days, noTraffic.diagnosticReserveBytes30Days);
});

test('diagnostic storm reserve covers every code at both severity levels', () => {
  const budget = calculateBudget({ requestsPerMinute: 0 });
  const maximumGroups = nodeSchema.fields.event_code.values.filter(code => !INDIVIDUAL_EVENT_CODES.includes(code) && !SHIPPER_EVENT_CODES.includes(code)).length * 2;
  assert.ok(budget.diagnosticEventsPerMinute >= maximumGroups);
  assert.ok(budget.diagnosticReserveBytes30Days >= maximumGroups * serializedEventBytes(representativeEvents.diagnostic) * MINUTES_30_DAYS);
});

test('the 5xx diagnostic is an individual event: not an aggregated code, and its representative is worst-valid (TC-1840)', () => {
  assert.deepEqual(INDIVIDUAL_EVENT_CODES, ['db_failure_5xx']);
  assert.ok(nodeSchema.fields.event_code.values.includes('db_failure_5xx'));
  assert.equal(calculateBudget({ requestsPerMinute: 0 }).diagnosticEventsPerMinute, (nodeSchema.fields.event_code.values.length - INDIVIDUAL_EVENT_CODES.length - SHIPPER_EVENT_CODES.length) * 2);
  assert.notEqual(representativeEvents.diagnostic.event_code, 'db_failure_5xx');
  const row = representativeEvents.dbFailure;
  assert.equal(row.event_code, 'db_failure_5xx');
  assert.deepEqual(Object.keys(row).sort(), ['code', 'db_hash', 'elapsed_ms', 'event', 'event_code', 'failure_kind', 'level', 'route', 'service', 'status', 'svc', 'ts', 'write_may_have_applied']);
  for (const key of ['code', 'service', 'failure_kind', 'route']) assert.ok(nodeSchema.fields[key].values.includes(row[key]), key);
  assert.equal(row.route.length, Math.max(...nodeSchema.fields.route.values.map(value => value.length)));
  assert.match(row.db_hash, new RegExp(nodeSchema.fields.db_hash.regex));
  assert.equal(row.elapsed_ms, nodeSchema.fields.elapsed_ms.max);
  assert.equal(calculateBudget({ requestsPerMinute: 0 }).eventBytes.dbFailure, serializedEventBytes(row, 'ndjson'));
});

test('the dropped-count event is emitted by the shipper: not an aggregated code, worst-valid, and no node log line maps to it (TC-1840)', async () => {
  assert.deepEqual(SHIPPER_EVENT_CODES, ['errors_dropped']);
  assert.ok(nodeSchema.fields.event_code.values.includes('errors_dropped'));
  assert.notEqual(representativeEvents.diagnostic.event_code, 'errors_dropped');
  const row = representativeEvents.errorsDropped;
  assert.deepEqual(Object.keys(row).sort(), ['class', 'dropped', 'event', 'event_code', 'level', 'svc', 'ts', 'window_s']);
  assert.equal(row.event_code, 'errors_dropped');
  assert.equal(row.class, 'ingress_request_5xx');
  assert.ok(nodeSchema.fields.class.values.includes(row.class));
  assert.equal(row.dropped, nodeSchema.fields.dropped.max);
  assert.equal(row.window_s, 60);
  assert.equal(calculateBudget({ requestsPerMinute: 0 }).eventBytes.errorsDropped, serializedEventBytes(row, 'ndjson'));
  const diagnostics = JSON.parse(await readFile(new URL('./diagnostics.json', import.meta.url), 'utf8'));
  assert.equal([...Object.values(diagnostics.exact), ...Object.values(diagnostics.prefix)].includes('errors_dropped'), false);
});

test('capped 5xx classes: worst case is cap x worst-valid bytes x 43,200 minutes plus one dropped-count event per class per minute, within 600 MB (TC-1840)', () => {
  assert.equal(CAP_WINDOW_SECONDS, 60);
  assert.equal(CAPPED_ALLOCATION_BYTES, 600_000_000);
  assert.ok(CAPPED_ALLOCATION_BYTES <= 0.2 * 3_000_000_000);
  assert.deepEqual(Object.keys(CAPPED_CLASSES).sort(), [...nodeSchema.fields.class.values].sort());
  for (const { capPerMinute } of Object.values(CAPPED_CLASSES)) assert.ok(Number.isSafeInteger(capPerMinute) && capPerMinute >= 1);
  for (const framing of ['ndjson', 'json-array']) {
    const budget = calculateBudget({ requestsPerMinute: 0, framing });
    const bytes = name => serializedEventBytes(representativeEvents[name], framing);
    assert.equal(budget.cappedClasses.db_failure_5xx.bytes30Days, CAPPED_CLASSES.db_failure_5xx.capPerMinute * bytes('dbFailure') * 43200);
    assert.equal(budget.cappedClasses.node_request_5xx.bytes30Days, CAPPED_CLASSES.node_request_5xx.capPerMinute * bytes('node') * 43200);
    assert.equal(budget.cappedClasses.ingress_request_5xx.bytes30Days, CAPPED_CLASSES.ingress_request_5xx.capPerMinute * bytes('ingress') * 43200);
    assert.equal(budget.droppedCountBytes30Days, 3 * bytes('errorsDropped') * 43200);
    assert.equal(budget.cappedReserveBytes30Days, budget.cappedEventBytes30Days + budget.droppedCountBytes30Days);
    assert.equal(budget.cappedEventBytes30Days, Object.values(budget.cappedClasses).reduce((sum, row) => sum + row.bytes30Days, 0));
    assert.equal(budget.cappedAllocationBytes, CAPPED_ALLOCATION_BYTES);
    assert.equal(budget.withinCappedAllocation, true);
    assert.ok(budget.cappedReserveBytes30Days <= CAPPED_ALLOCATION_BYTES);
    // The reserve is additional: the request and diagnostic totals do not change, and the combined worst case adds it.
    assert.equal(budget.totalBytes30Days, budget.requestBytes30Days + budget.diagnosticReserveBytes30Days);
    assert.equal(budget.totalWithCappedBytes30Days, budget.totalBytes30Days + budget.cappedReserveBytes30Days);
  }
  // The figures quoted in the runbook: 10 per minute per class.
  assert.deepEqual(Object.values(CAPPED_CLASSES).map(row => row.capPerMinute), [10, 10, 10]);
  const ndjson = calculateBudget({ requestsPerMinute: 0 });
  assert.equal(ndjson.cappedEventBytes30Days, 10 * (402 + 439 + 223) * 43200);
  assert.equal(ndjson.cappedEventBytes30Days, 459_648_000);
  assert.equal(ndjson.droppedCountBytes30Days, 23_976_000);
  assert.equal(ndjson.cappedReserveBytes30Days, 483_624_000);
});

test('invalid numeric budgets fail rather than hiding impossible volume', () => {
  for (const field of ['requestsPerMinute', 'diagnosticEventsPerMinute', 'gateEventsPerMinute', 'allocationBytes']) {
    for (const value of [-1, NaN, Infinity, '1']) assert.throws(() => calculateBudget({ [field]: value }), /finite non-negative/);
  }
  assert.throws(() => calculateBudget({ framing: 'raw' }), /framing/);
  const zero = calculateBudget({ requestsPerMinute: 0, allocationBytes: 0 });
  assert.equal(zero.sustainableRequestsPerMinute, 0);
  assert.equal(zero.withinRequestAllocation, true);
});

test('diagnostic mapping uses only closed schema codes and cannot assert a panic', async () => {
  const diagnostics = JSON.parse(await readFile(new URL('./diagnostics.json', import.meta.url), 'utf8'));
  const codes = nodeSchema.fields.event_code.values;
  assert.equal(diagnostics.fallback, 'unclassified');
  for (const code of [...Object.values(diagnostics.exact), ...Object.values(diagnostics.prefix), diagnostics.fallback]) {
    assert.ok(codes.includes(code));
    assert.equal(code.includes('panic'), false);
    assert.notEqual(code, 'errors_dropped');
  }
  assert.equal(Object.hasOwn(diagnostics.exact, 'node fatal panic'), false);
  assert.equal(diagnostics.exact['invalid link bind address; LAN listener not started'], 'link_bind_invalid');
  assert.ok(diagnostics.exact['network DID resolution enabled: did:web/did:tz fetches use the unhardened ssi client (TC-1080)']);
  assert.ok(diagnostics.exact['link auto-renew succeeded but no state.json found; skipping cert hot-reload']);
});

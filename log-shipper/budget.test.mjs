import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { calculateBudget, representativeEvents, serializedEventBytes, MINUTES_30_DAYS, REQUEST_ALLOCATION_BYTES } from './budget.mjs';
import { assertCapture } from '../scripts/tc959-docker.mjs';

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
  const one = calculateBudget({ requestsPerMinute: 1, diagnosticEventsPerMinute: 0, gateEventsPerMinute: 0, typedEventsPerMinute: 0 });
  const many = calculateBudget({ requestsPerMinute: 10000, diagnosticEventsPerMinute: 0, gateEventsPerMinute: 0, typedEventsPerMinute: 0 });
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
  const budget = calculateBudget({ requestsPerMinute: 1, diagnosticEventsPerMinute: 53, gateEventsPerMinute: 9, typedEventsPerMinute: 0 });
  assert.equal(budget.diagnosticReserveBytes30Days,
    43200 * (53 * serializedEventBytes(representativeEvents.diagnostic, 'ndjson') + 9 * serializedEventBytes(representativeEvents.gate, 'ndjson')));
  assert.equal(budget.totalBytes30Days, budget.requestBytes30Days + budget.diagnosticReserveBytes30Days);
  assert.equal(budget.sustainableRequestsPerMinute, REQUEST_ALLOCATION_BYTES / (budget.requestPairBytes * 43200));
  const noTraffic = calculateBudget({ requestsPerMinute: 0 });
  assert.equal(noTraffic.requestBytes30Days, 0);
  assert.ok(noTraffic.diagnosticReserveBytes30Days > 0);
  assert.equal(noTraffic.totalBytes30Days, noTraffic.diagnosticReserveBytes30Days + noTraffic.typedReserveBytes30Days);
});

test('typed per-occurrence diagnostics are reserved at the shipper cap with each code\'s widest valid record', async () => {
  const diagnostics = JSON.parse(await readFile(new URL('./diagnostics.json', import.meta.url), 'utf8'));
  const codes = Object.keys(diagnostics.typed);
  const { records, window_secs } = diagnostics.typed_limit;
  // Sam's decision (tc-959-f6-log-cap): 10 records per typed code per minute, each code counted separately.
  assert.deepEqual(diagnostics.typed_limit, { records: 10, window_secs: 60 });
  // Every code's widest record is valid on the wire and no wider than the budgeted representative.
  for (const code of codes) {
    const { level, fields } = diagnostics.typed[code];
    const widest = { ts: '9999-12-31T23:59:59.999Z', level, event: level === 'warn' ? 'node_warning' : 'node_error', svc: 'api', event_code: code, event_count: 1 };
    for (const name of fields) {
      const spec = nodeSchema.fields[name];
      widest[name] = spec.type === 'integer' ? spec.max : spec.type === 'enum' ? spec.values.reduce((a, b) => (b.length > a.length ? b : a)) : 'f'.repeat(spec.max_len);
    }
    assert.doesNotThrow(() => assertCapture([widest], nodeSchema.fields));
    assert.ok(serializedEventBytes(widest) <= serializedEventBytes(representativeEvents.typed), code);
  }
  const budget = calculateBudget({ requestsPerMinute: 0, diagnosticEventsPerMinute: 0, gateEventsPerMinute: 0 });
  assert.equal(budget.typedEventsPerMinute, codes.length * records * 60 / window_secs);
  assert.equal(budget.typedEventsPerMinute, 70);
  assert.equal(budget.typedReserveBytes30Days, budget.typedEventsPerMinute * serializedEventBytes(representativeEvents.typed) * MINUTES_30_DAYS);
  assert.equal(budget.totalBytes30Days, budget.typedReserveBytes30Days);
  assert.equal(calculateBudget({ requestsPerMinute: 0, typedEventsPerMinute: 0 }).typedReserveBytes30Days, 0);
});

test('diagnostic storm reserve covers every code at both severity levels', () => {
  const budget = calculateBudget({ requestsPerMinute: 0 });
  const maximumGroups = nodeSchema.fields.event_code.values.length * 2;
  assert.ok(budget.diagnosticEventsPerMinute >= maximumGroups);
  assert.ok(budget.diagnosticReserveBytes30Days >= maximumGroups * serializedEventBytes(representativeEvents.diagnostic) * MINUTES_30_DAYS);
});

test('invalid numeric budgets fail rather than hiding impossible volume', () => {
  for (const field of ['requestsPerMinute', 'diagnosticEventsPerMinute', 'gateEventsPerMinute', 'typedEventsPerMinute', 'allocationBytes']) {
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
  }
  assert.equal(Object.hasOwn(diagnostics.exact, 'node fatal panic'), false);
  assert.equal(diagnostics.exact['invalid link bind address; LAN listener not started'], 'link_bind_invalid');
  assert.ok(diagnostics.exact['network DID resolution enabled: did:web/did:tz fetches use the unhardened ssi client (TC-1080)']);
  assert.ok(diagnostics.exact['link auto-renew succeeded but no state.json found; skipping cert hot-reload']);
});

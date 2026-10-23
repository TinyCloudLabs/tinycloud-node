import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { calculateBudget, representativeEvents, serializedEventBytes, INDIVIDUAL_EVENT_CODES, MINUTES_30_DAYS, REQUEST_ALLOCATION_BYTES } from './budget.mjs';

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
  const maximumGroups = nodeSchema.fields.event_code.values.filter(code => !INDIVIDUAL_EVENT_CODES.includes(code)).length * 2;
  assert.ok(budget.diagnosticEventsPerMinute >= maximumGroups);
  assert.ok(budget.diagnosticReserveBytes30Days >= maximumGroups * serializedEventBytes(representativeEvents.diagnostic) * MINUTES_30_DAYS);
});

test('the 5xx diagnostic is an individual event: not an aggregated code, and its representative is worst-valid (TC-1840)', () => {
  assert.deepEqual(INDIVIDUAL_EVENT_CODES, ['db_failure_5xx']);
  assert.ok(nodeSchema.fields.event_code.values.includes('db_failure_5xx'));
  assert.equal(calculateBudget({ requestsPerMinute: 0 }).diagnosticEventsPerMinute, (nodeSchema.fields.event_code.values.length - 1) * 2);
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
  }
  assert.equal(Object.hasOwn(diagnostics.exact, 'node fatal panic'), false);
  assert.equal(diagnostics.exact['invalid link bind address; LAN listener not started'], 'link_bind_invalid');
  assert.ok(diagnostics.exact['network DID resolution enabled: did:web/did:tz fetches use the unhardened ssi client (TC-1080)']);
  assert.ok(diagnostics.exact['link auto-renew succeeded but no state.json found; skipping cert hot-reload']);
});

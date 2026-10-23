import test from 'node:test';
import assert from 'node:assert/strict';
import { buildConfig } from '../scripts/tc959-logship.mjs';
import { CAPPED_CLASSES, CAP_WINDOW_SECONDS } from './budget.mjs';

test('invalid profile selections fail startup rather than silently logging another set', () => {
  for (const profile of [null, '', 'error_slow', 'WARN', true, 42, {}]) {
    assert.throws(() => buildConfig({ profile }));
  }
});

test('slow threshold requires a nonnegative safe integer in microseconds', () => {
  for (const slowThresholdUs of ['1000000', null, -1, 0.5, Infinity, NaN, Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => buildConfig({ slowThresholdUs }));
  }
});

test('runtime profile interpolation is an explicit boolean compiler choice', () => {
  for (const runtimeProfile of [null, 'true', 1, {}]) {
    assert.throws(() => buildConfig({ runtimeProfile }));
  }
});

test('the real sink receives the uncapped requests, the three cap transforms, the count reducers and the gate counts; the reducer only the counted diagnostics (TC-1840, TC-1843)', () => {
  for (const profile of ['errors_slow', 'all_requests']) {
    const { sinks, transforms } = buildConfig({ profile });
    assert.deepEqual(sinks.betterstack.inputs, ['event_route.request', 'cap_db_failure_5xx', 'cap_node_request_5xx', 'cap_ingress_request_5xx', 'diagnostic_output', 'gate_output']);
    assert.deepEqual(transforms.diagnostic_reduce.inputs, ['event_route.diagnostic']);
    assert.deepEqual(Object.keys(transforms.event_route.route), ['request', 'node_request_5xx', 'ingress_request_5xx', 'db_failure_5xx', 'diagnostic']);
    assert.match(transforms.event_route.route.diagnostic, /event_code != "db_failure_5xx"/);
  }
});

test('each capped class reaches the sink only through its own cap transform, with the stated cap and window (TC-1843)', () => {
  for (const profile of ['errors_slow', 'all_requests']) {
    const { sinks, transforms } = buildConfig({ profile });
    assert.deepEqual(Object.keys(CAPPED_CLASSES), ['db_failure_5xx', 'node_request_5xx', 'ingress_request_5xx']);
    assert.equal(CAP_WINDOW_SECONDS, 60);
    for (const [name, { capPerMinute }] of Object.entries(CAPPED_CLASSES)) {
      const cap = transforms[`cap_${name}`];
      assert.equal(cap.type, 'lua');
      assert.equal(cap.version, '2');
      assert.deepEqual(cap.inputs, [`event_route.${name}`]);
      assert.deepEqual(cap.hooks, { process: 'process' });
      assert.deepEqual(cap.timers, [{ interval_seconds: 60, handler: 'flush' }]);
      assert.match(cap.source, new RegExp(`^local class = "${name}"$`, 'm'));
      assert.match(cap.source, new RegExp(`^local cap = ${capPerMinute}$`, 'm'));
      // The uncapped route must not also feed the sink, and nothing else may consume the route or the cap.
      assert.equal(sinks.betterstack.inputs.includes(`event_route.${name}`), false);
      const nodes = { ...transforms, ...sinks };
      assert.deepEqual(Object.keys(nodes).filter(id => nodes[id].inputs?.includes(`event_route.${name}`)), [`cap_${name}`]);
      assert.deepEqual(Object.keys(nodes).filter(id => nodes[id].inputs?.includes(`cap_${name}`)), ['betterstack']);
    }
  }
});

test('the uncapped request route feeds only the sink, and the only caps are the three Lua cap transforms (TC-1843)', () => {
  const { sinks, transforms } = buildConfig();
  const types = Object.values(transforms).map(node => node.type);
  assert.equal(types.filter(type => type === 'lua').length, 3);
  for (const type of ['throttle', 'sample', 'dedupe']) assert.equal(types.includes(type), false);
  const nodes = { ...transforms, ...sinks };
  assert.deepEqual(Object.keys(nodes).filter(id => nodes[id].inputs?.includes('event_route.request')), ['betterstack']);
});

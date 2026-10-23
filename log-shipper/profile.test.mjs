import test from 'node:test';
import assert from 'node:assert/strict';
import { buildConfig } from '../scripts/tc959-logship.mjs';

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

test('the real sink receives the individual events, including the 5xx diagnostic, and the reducer only the counted ones (TC-1840)', () => {
  for (const profile of ['errors_slow', 'all_requests']) {
    const { sinks, transforms } = buildConfig({ profile });
    assert.deepEqual(sinks.betterstack.inputs, ['event_route.request', 'event_route.db_failure', 'diagnostic_output', 'gate_output']);
    assert.deepEqual(transforms.diagnostic_reduce.inputs, ['event_route.diagnostic']);
    assert.deepEqual(Object.keys(transforms.event_route.route), ['request', 'db_failure', 'diagnostic']);
    assert.match(transforms.event_route.route.diagnostic, /event_code != "db_failure_5xx"/);
  }
});

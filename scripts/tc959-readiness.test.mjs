import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import test from 'node:test';
import { awaitReadiness, classifyProbeError, classifyStartupOutput, hasUdpListener, componentCounters } from './tc959-readiness.mjs';

async function fixture(t, handler) {
  const server = createServer(handler);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => server.close());
  return `http://127.0.0.1:${server.address().port}/healthz`;
}

test('readiness distinguishes an available node from an ingress 502 without logging payload', async t => {
  const node = await fixture(t, (_req, res) => res.end('ok'));
  const ingress = await fixture(t, (_req, res) => { res.statusCode = 502; res.end('Bearer TC959_SYNTHETIC private header'); });
  const probe = async () => {
    const read = async url => { const response = await fetch(url); await response.arrayBuffer(); return response.status; };
    return { node_healthz: await read(node), ingress_healthz: await read(ingress) };
  };
  await assert.rejects(awaitReadiness(probe, { attempts: 2, intervalMs: 0 }), error => {
    assert.deepEqual(error.diagnostics, { node_healthz: { state: 'http', status: 200 }, ingress_healthz: { state: 'http', status: 502 } });
    assert.equal(JSON.stringify(error.diagnostics).includes('TC959_SYNTHETIC'), false);
    assert.equal(error.message, 'readiness_timeout');
    return true;
  });
});

test('readiness observes each probe transition instead of treating one pass as permanent', async () => {
  const results = [ { node_healthz: 200, ingress_healthz: 503 }, { node_healthz: 503, ingress_healthz: 200 }, { node_healthz: 200, ingress_healthz: 200 } ];
  let attempts = 0;
  const diagnostics = await awaitReadiness(async () => results[attempts++], { attempts: 3, intervalMs: 0 });
  assert.equal(attempts, 3);
  assert.deepEqual(diagnostics, { node_healthz: { state: 'http', status: 200 }, ingress_healthz: { state: 'http', status: 200 } });
});

test('network exceptions expose only fixed classes, not the message, URL, or nested cause', () => {
  for (const [code, expected] of [['ECONNREFUSED', 'connection_refused'], ['ECONNRESET', 'connection_reset'], ['ETIMEDOUT', 'timeout'], ['ENOTFOUND', 'dns'], ['PRIVATE_SECRET', 'network']]) {
    const error = new Error('Bearer TC959_SYNTHETIC https://private.invalid/secret');
    error.cause = { code, secret: 'TC959_SYNTHETIC' };
    assert.equal(classifyProbeError(error), expected);
  }
  assert.equal(classifyProbeError({ name: 'TimeoutError' }), 'timeout');
});

test('a failed connection remains distinguishable from an HTTP failure', async () => {
  await assert.rejects(awaitReadiness(async () => ({ node_healthz: { state: 'connection_refused' }, ingress_healthz: 503 }), { attempts: 1, intervalMs: 0 }), error => {
    assert.deepEqual(error.diagnostics, { node_healthz: { state: 'connection_refused' }, ingress_healthz: { state: 'http', status: 503 } });
    return true;
  });
});

test('startup output is classified without forwarding text or fixture credentials', () => {
  const raw = 'TC959_SYNTHETIC Bearer private\nFailed to start tinycloud-node:\ninvalid value unknown variant\npermission denied\nnginx: [emerg] configuration file test failed';
  assert.deepEqual(classifyStartupOutput(raw), ['application_startup_failed', 'invalid_configuration', 'permission_denied', 'nginx_startup_failed']);
  assert.deepEqual(classifyStartupOutput('TC959_SYNTHETIC unrelated private text'), []);
  assert.equal(JSON.stringify(classifyStartupOutput(raw)).includes('TC959_SYNTHETIC'), false);
});

test('process running is not UDP readiness and a remote port does not count as a listener', async () => {
  const header = 'sl local_address rem_address st tx_queue rx_queue';
  const wrong = `${header}\n0: 00000000:0035 0100007F:2FA9 07 0:0 00:0 0 0 0`;
  const right = `${header}\n0: 00000000:2FA9 00000000:0000 07 0:0 00:0 0 0 0`;
  assert.equal(hasUdpListener(wrong, 12201), false);
  assert.equal(hasUdpListener(right, 12201), true);
  let attempt = 0;
  await awaitReadiness(async () => ({ node_healthz: 200, vector_running: true, vector_udp_listener: hasUdpListener(attempt++ === 0 ? wrong : right, 12201) }), { attempts: 2, intervalMs: 0 });
  assert.equal(attempt, 2);
});

test('component metrics preserve numeric hop counts without returning labels or text', () => {
  const metrics = `# private TC959_SYNTHETIC
vector_component_received_events_total{component_id=\"gelf_in\",host=\"TC959_SYNTHETIC\"} 3
component_received_events_total{component_id=\"gelf_in\",output=\"x\"} 2
vector_component_sent_events_total{component_id=\"gelf_in\"} 5
vector_component_errors_total{component_id=\"gelf_in\"} 1
vector_component_discarded_events_total{component_id=\"gelf_in\"} 0
vector_component_received_events_total{component_id=\"gelf_in_other\"} 999
vector_component_received_events_total{component_id=\"other\"} 999`;
  assert.deepEqual(componentCounters(metrics, 'gelf_in'), { received_events: 5, sent_events: 5, errors: 1, discarded_events: 0 });
  assert.equal(JSON.stringify(componentCounters(metrics, 'gelf_in')).includes('TC959_SYNTHETIC'), false);
});

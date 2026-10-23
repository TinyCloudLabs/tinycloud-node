import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs, assertCapture, resourceNames } from './tc959-docker.mjs';
import { assertHostedRunner, cleanupOwnedResources, burstEvidence, assertHealthyBurst, progressEvidence, assertServiceParity, assertLogshipNetwork, composeRuntimeValues, socketEvidence, numericMetrics, diagnosticCounts } from './tc959-compose-proof.mjs';

const request = { ts: '2026-10-16T12:00:00.000Z', level: 'info', event: 'node_request', svc: 'api', method: 'GET', route: '/healthz', status: 200, latency_us: 12 };
const ingress = { ...request, event: 'ingress_request', svc: 'ingress', request_time_seconds: 0.001 };
delete ingress.latency_us;

test('Docker requires an explicit disposable hosted CI opt in', () => {
  assert.throws(() => parseArgs([]));
  assert.throws(() => parseArgs(['--go', '--unknown']));
  assert.throws(() => parseArgs(['--go']));
  assert.equal(parseArgs(['--go', '--ci']).ci, true);
});

test('the executable CI entry point refuses local execution without invoking Docker or leaking environment', () => {
  const child = spawnSync(process.execPath, [fileURLToPath(new URL('./tc959-docker.mjs', import.meta.url)), '--go', '--ci'], { encoding: 'utf8', timeout: 5000, env: { PATH: '/nonexistent', BETTERSTACK_SOURCE_TOKEN: 'TC959_SYNTHETIC_NOT_TO_PRINT' } });
  assert.equal(child.status, 1);
  assert.deepEqual(JSON.parse(child.stdout), { status: 'failed', phase: 'preflight', code: 'disposable_hosted_runner_required' });
  assert.equal(child.stderr, '');
  assert.equal(child.stdout.includes('TC959_SYNTHETIC'), false);
});

test('all resource names carry the owner and unique run', () => {
  const names = resourceNames('abc123');
  assert.equal(new Set(Object.values(names)).size, Object.keys(names).length);
  assert.ok(Object.values(names).every(name => name.startsWith('tc959-n0-abc123-')));
});

test('capture rejects unsafe values even when all request positive controls are present', () => {
  const baseline = [request, { ...request, route: '/version' }, { ...request, method: 'POST', route: '/invoke', status: 401 }, ingress];
  assert.doesNotThrow(() => assertCapture(baseline));
  assert.doesNotThrow(() => assertCapture([request])); // errors_slow intentionally excludes fast healthy controls.
  for (const poison of [{ authorization: 'synthetic-bearer' }, { route: '/raw-secret' }, { latency_us: -1 }, { status: 999 }, { extra: 'TC959_SYNTHETIC' }]) {
    assert.throws(() => assertCapture([{ ...request, ...poison }, ...baseline.slice(1)]));
  }
});

const goodId = 'a8098c1a-f86e-4b1f-92a7-4b50b53ec932';
test('capture accepts well-formed N2 correlation fields on node_request only', () => {
  const correlated = { ...request, request_id: goodId, request_id_replaced: false, account_hash: 'a'.repeat(64), space_hash: '0123456789abcdef'.repeat(4) };
  assert.doesNotThrow(() => assertCapture([correlated]));
  assert.doesNotThrow(() => assertCapture([{ ...request, request_id: goodId }])); // each key is optional
  for (const bad of [
    { request_id: 'anything' }, { request_id: goodId.toUpperCase() }, { request_id: `${goodId}0` }, { request_id: `x${goodId}` },
    { request_id_replaced: 'true' }, { account_hash: 'A'.repeat(64) }, { space_hash: 'a'.repeat(63) }, { space_hash: `${'a'.repeat(64)}f` },
    { account_hash: 'did:pkh:eip155:1:0xabc' }, { request_id: 7 },
  ]) {
    assert.throws(() => assertCapture([{ ...request, ...bad }]), JSON.stringify(bad));
  }
  // Never anywhere else: ingress rows, diagnostics and gate counters.
  const warning = { ts: request.ts, level: 'warn', event: 'node_warning', svc: 'api', event_code: 'unclassified', event_count: 1 };
  for (const key of ['request_id', 'request_id_replaced', 'account_hash', 'space_hash']) {
    const value = key === 'request_id' ? goodId : key === 'request_id_replaced' ? true : 'a'.repeat(64);
    assert.throws(() => assertCapture([{ ...ingress, [key]: value }]), `ingress ${key}`);
    assert.throws(() => assertCapture([{ ...warning, [key]: value }], { event_code: { values: ['unclassified'] } }), `warning ${key}`);
  }
});

test('capture accepts the individual 5xx diagnostic with exactly its eight typed fields (TC-1840)', () => {
  const fields = JSON.parse(readFileSync(new URL('../log-shipper/fields.json', import.meta.url), 'utf8')).services['tinycloud-node'].fields;
  const dbFailure = { ts: request.ts, level: 'warn', event: 'node_warning', svc: 'api', event_code: 'db_failure_5xx', status: 503, code: 'sql_busy', service: 'sql', route: '/invoke', elapsed_ms: 30001, failure_kind: 'lock_wait', write_may_have_applied: false, db_hash: 'a'.repeat(64) };
  assert.doesNotThrow(() => assertCapture([dbFailure], fields));
  const { db_hash, ...withoutDatabase } = dbFailure;
  assert.doesNotThrow(() => assertCapture([withoutDatabase], fields)); // db_hash is optional
  for (const bad of [
    { event_count: 1 }, { message: 'TC959_SYNTHETIC' }, { sql: 'select 1' }, { status: 200 }, { status: 503.5 }, { code: 'sql_busy ' }, { service: 'postgres' },
    { route: '/raw-secret' }, { elapsed_ms: -1 }, { elapsed_ms: '1' }, { failure_kind: 'timeout' }, { write_may_have_applied: 'false' },
    { db_hash: 'A'.repeat(64) }, { db_hash: 'a'.repeat(63) }, { db_hash: `${'a'.repeat(64)}\n` }, { db_hash: 'notes.db' }, { db_hash: null },
  ]) {
    assert.throws(() => assertCapture([{ ...dbFailure, ...bad }], fields), JSON.stringify(bad));
  }
  assert.throws(() => assertCapture([{ ...withoutDatabase, level: 'error' }], fields));
  assert.throws(() => assertCapture([{ ...ingress, event_code: 'db_failure_5xx' }], fields));
});

const hosted = { GITHUB_ACTIONS: 'true', RUNNER_ENVIRONMENT: 'github-hosted', RUNNER_OS: 'Linux', GITHUB_RUN_ID: '12345', GITHUB_RUN_ATTEMPT: '1', RUNNER_TEMP: '/home/runner/work/_temp' };
test('CI guard rejects local and self-hosted Docker before any daemon operation', () => {
  assert.doesNotThrow(() => assertHostedRunner(hosted));
  for (const patch of [{ GITHUB_ACTIONS: undefined }, { RUNNER_ENVIRONMENT: 'self-hosted' }, { RUNNER_OS: 'macOS' }, { GITHUB_RUN_ID: '' }, { GITHUB_RUN_ATTEMPT: '' }, { RUNNER_TEMP: '/tmp/local' }]) {
    assert.throws(() => assertHostedRunner({ ...hosted, ...patch }));
  }
});

test('cleanup validates the entire ownership boundary before deleting anything', () => {
  const owned = (kind, name) => ({ kind, name, labels: { 'tc959.owner': 'tc959-n0', 'tc959-n0': 'run1' } });
  const resources = [owned('container', 'tc959-n0-run1-node'), owned('network', 'tc959-n0-run1-logship'), owned('volume', 'tc959-n0-run1-data')];
  const removed = [];
  assert.deepEqual(cleanupOwnedResources(resources, value => removed.push(value.name), 'run1'), { containers: 1, networks: 1, volumes: 1 });
  assert.equal(removed.length, 3);
  for (const poison of [
    { ...resources[0], labels: { 'tc959.owner': 'someone-else', 'tc959-n0': 'run1' } },
    { ...resources[0], labels: { 'tc959.owner': 'tc959-n0', 'tc959-n0': 'other-run' } },
    { ...resources[0], name: 'production-node' },
    { ...resources[0], kind: 'image' },
  ]) {
    let calls = 0;
    assert.throws(() => cleanupOwnedResources([...resources, poison], () => calls++, 'run1'));
    assert.equal(calls, 0, 'foreign resources must never be deleted, even after an owned item');
  }
});

test('healthy burst requires its exact distinct set, not a compensating duplicate or a fast success', () => {
  const events = Array.from({ length: 500 }, (_, index) => ({ ...request, status: 503, latency_us: 9000000 + index }));
  assert.deepEqual(burstEvidence(events, 9000000, 500), { expected: 500, received: 500, unique: 500, missing: [], duplicates: [] });
  assert.doesNotThrow(() => assertHealthyBurst(events, 9000000, 500, 500));
  assert.throws(() => assertHealthyBurst(events, 9000000, 500, 499));
  const compensated = [...events.slice(1), events[1], { ...request, latency_us: 8000000 }];
  const evidence = burstEvidence(compensated, 9000000, 500);
  assert.equal(evidence.received, 500);
  assert.deepEqual(evidence.missing, [9000000]);
  assert.deepEqual(evidence.duplicates, [{ marker: 9000001, count: 2 }]);
  assert.throws(() => assertHealthyBurst(compensated, 9000000, 500, 500));
  assert.throws(() => assertHealthyBurst(events.slice(1), 9000000, 500, 500));
  assert.equal(burstEvidence([{ ...request, latency_us: 8000000 }], 9000000, 500).received, 0);
});

test('timed per-hop evidence distinguishes continued drainage from an observed plateau', () => {
  const sample = (elapsed_ms, source, gate, admitted, sink, capture) => ({ elapsed_ms, source, gate, admitted, sink, capture });
  const first = sample(0, 500, 500, 500, 200, 200);
  const later = sample(1000, 500, 500, 500, 300, 300);
  const evidence = progressEvidence([first, later, sample(2000, 500, 500, 500, 300, 300)]);
  assert.equal(evidence.plateau, false);
  assert.equal(evidence.deltas.capture, 100);
  assert.equal(evidence.latest.admitted, 500);
  assert.equal(evidence.plateaus.source, true);
  assert.equal(evidence.plateaus.capture, false);
  const burstStatic = [first, later, sample(2000, 500, 500, 500, 400, 400)].map(point => ({ ...point, burst_capture: 200 }));
  assert.equal(progressEvidence(burstStatic).burst_plateau, true, 'other captured controls must not hide a static burst subset');
  assert.equal(progressEvidence([later, sample(2000, 500, 500, 500, 300, 300), sample(3000, 500, 500, 500, 300, 300)]).plateau, true);
  assert.equal(progressEvidence([first]).plateau, false);
  assert.equal(progressEvidence([first, { ...later, sink: null }]).deltas.sink, null);
});

test('canonical Compose dollar escaping becomes runtime variables rather than shell PID expansion', () => {
  const runtime = composeRuntimeValues({
    environment: { TC959_VALUE: 'TC959_SYNTHETIC_$$literal' },
    entrypoint: ['/bin/sh', '-ec', 'printf "%s" "$$TC959_VALUE"'],
    config: JSON.stringify({ condition: '"$${TINYCLOUD_LOGSHIP_PROFILE}" == "all_requests"' }),
  });
  const child = spawnSync(runtime.entrypoint[0], runtime.entrypoint.slice(1), { env: runtime.environment, encoding: 'utf8' });
  assert.equal(child.status, 0);
  assert.equal(child.stdout, 'TC959_SYNTHETIC_$literal');
  assert.equal(JSON.parse(runtime.config).condition, '"${TINYCLOUD_LOGSHIP_PROFILE}" == "all_requests"');
});

test('normal bridge defaults cannot hide external, routed or host-changing network options', () => {
  assertLogshipNetwork({ name: 'synthetic_logship', driver: 'bridge' });
  assertLogshipNetwork({ name: 'synthetic_logship', driver: 'bridge', internal: false, external: false, attachable: false, enable_ipv4: true, enable_ipv6: false, driver_opts: {}, labels: {}, ipam: { driver: 'default', config: [], options: {} } });
  for (const poison of [{ driver: 'host' }, { internal: true }, { external: true }, { enable_ipv4: false }, { enable_ipv6: true }, { driver_opts: { 'com.docker.network.bridge.name': 'foreign' } }, { ipam: { config: [{ subnet: '10.0.0.0/8' }] } }, { unknown_option: true }]) {
    assert.throws(() => assertLogshipNetwork({ driver: 'bridge', ...poison }));
  }
});

test('actual container parity catches image, GELF option, isolation and resource drift', () => {
  const service = { image: 'example@sha256:abc', user: '10001:10001', read_only: true, init: true, cap_drop: ['ALL'], security_opt: ['no-new-privileges:true'], mem_limit: '67108864', memswap_limit: '67108864', cpus: 0.5, tmpfs: ['/var/lib/vector:rw,noexec,nosuid,size=8m,uid=10001,gid=10001,mode=0700'], labels: { 'tc.logship': 'tinycloud-node' }, logging: { driver: 'gelf', options: { 'gelf-address': 'udp://127.0.0.1:12201', mode: 'non-blocking', 'max-buffer-size': '4m', 'cache-disabled': 'true' } } };
  const inspect = { Config: { Image: service.image, User: service.user, Labels: service.labels }, HostConfig: { ReadonlyRootfs: true, Init: true, Privileged: false, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges:true'], Memory: 67108864, MemorySwap: 67108864, NanoCpus: 500000000, Tmpfs: { '/var/lib/vector': service.tmpfs[0].split(':')[1] }, LogConfig: { Type: 'gelf', Config: service.logging.options }, PortBindings: { '12201/udp': [{ HostIp: '127.0.0.1', HostPort: '12201' }] } }, NetworkSettings: { Networks: { 'tc959-n0-run1-logship': {} }, Ports: { '12201/udp': [{ HostIp: '127.0.0.1', HostPort: '12201' }] } } };
  const boundary = { networks: ['tc959-n0-run1-logship'], portBindings: inspect.HostConfig.PortBindings };
  assert.doesNotThrow(() => assertServiceParity(service, inspect, boundary));
  for (const poison of [
    { ...inspect, Config: { ...inspect.Config, Image: 'mutable:latest' } },
    { ...inspect, HostConfig: { ...inspect.HostConfig, LogConfig: { Type: 'json-file', Config: {} } } },
    { ...inspect, HostConfig: { ...inspect.HostConfig, Memory: 134217728 } },
    { ...inspect, HostConfig: { ...inspect.HostConfig, SecurityOpt: [] } },
    { ...inspect, NetworkSettings: { ...inspect.NetworkSettings, Networks: { bridge: {} } } },
    { ...inspect, HostConfig: { ...inspect.HostConfig, Tmpfs: {} } },
    { ...inspect, Mounts: [{ Type: 'bind', Source: '/var/run/docker.sock', Destination: '/var/run/docker.sock', RW: true }] },
    { ...inspect, Config: { ...inspect.Config, User: 'root' } },
    ...[{}, { '12201/udp': null }, { '12201/udp': [] }, { '12201/udp': [{ HostIp: '0.0.0.0', HostPort: '12201' }] }, { '12201/udp': [{ HostIp: '127.0.0.1', HostPort: '12202' }] }].map(Ports => ({ ...inspect, NetworkSettings: { ...inspect.NetworkSettings, Ports } })),
  ]) assert.throws(() => assertServiceParity(service, poison, boundary));
});

test('socket evidence measures effective receive buffer and drops rather than assuming requested bytes', () => {
  const observed = socketEvidence('UNCONN 0 0 0.0.0.0:12201 0.0.0.0:*\n skmem:(r0,rb425984,t0,tb212992,f0,w0,o0,bl0,d7)', '212992');
  assert.deepEqual(observed, { requested_receive_buffer_bytes: 8388608, rmem_max: 212992, effective_so_rcvbuf: 425984, socket_drops: 7 });
  assert.equal(socketEvidence('UNCONN 0 0 0.0.0.0:12201', 'private').effective_so_rcvbuf, null);
  assert.equal(socketEvidence('', '212992').socket_drops, null);
});

test('buffer and error diagnostics never expose raw metric labels or invent absent counters', () => {
  const observed = numericMetrics('vector_buffer_events{component_id="betterstack",secret="TC959_SYNTHETIC"} 17\nvector_component_errors_total{component_id="betterstack"} 2\nvector_component_discarded_events_total{component_id="betterstack"} 3\nvector_component_received_events_total{component_id="betterstack"} 500\nvector_buffer_byte_size{component_id="betterstack"} 1024');
  assert.equal(observed.buffer_events, 17);
  assert.equal(observed.component_errors_total, 2);
  assert.equal(observed.component_discarded_events_total, 3);
  assert.equal(observed.buffer_byte_size, 1024);
  assert.equal(JSON.stringify(observed).includes('TC959_SYNTHETIC'), false);
  assert.equal(numericMetrics('').buffer_events, null);
});

test('diagnostic acceptance sums aggregated occurrences instead of counting output rows', () => {
  const observed = diagnosticCounts([
    { event: 'node_warning', event_code: 'link_bind_invalid', event_count: 2 },
    { event: 'node_warning', event_code: 'unclassified', event_count: 1 },
    { event: 'node_error', event_code: 'share_native_kv_put_failed', event_count: 1 },
    { event: 'node_error', event_code: 'unclassified', event_count: 3 },
    { event: 'node_error', event_code: 'link_bind_invalid', event_count: 100 },
    { event: 'node_warning', event_code: 'unclassified', event_count: 'TC959_SYNTHETIC' },
    null,
  ]);
  assert.deepEqual(observed, { warn: 2, unclassified: 1, error: 1, dependency_error: 3, total: 107 });
  assert.equal(JSON.stringify(observed).includes('TC959_SYNTHETIC'), false);
});

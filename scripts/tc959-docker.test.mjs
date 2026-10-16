import test from 'node:test';
import assert from 'node:assert/strict';
import { parseArgs, assertLocalDocker, assertCapture, assertShipperIsolation, resourceNames } from './tc959-docker.mjs';

const request = { ts: '2026-10-16T12:00:00.000Z', level: 'info', event: 'node_request', svc: 'api', method: 'GET', route: '/healthz', status: 200, latency_us: 12 };
const ingress = { ...request, event: 'ingress_request', svc: 'ingress', request_time_seconds: 0.001 };
delete ingress.latency_us;

test('Docker is an explicit local-only opt in', () => {
  assert.throws(() => parseArgs([]));
  assert.throws(() => parseArgs(['--go', '--unknown']));
  assert.equal(parseArgs(['--go']).go, true);
  assert.doesNotThrow(() => assertLocalDocker({ host: 'unix:///var/run/docker.sock', endpoint: 'unix:///var/run/docker.sock' }));
  for (const host of ['ssh://remote', 'tcp://127.0.0.1:2375', 'tcp://remote:2376']) {
    assert.throws(() => assertLocalDocker({ host, endpoint: 'unix:///var/run/docker.sock' }));
    assert.throws(() => assertLocalDocker({ endpoint: host }));
  }
});

test('all resource names carry the claim and unique run', () => {
  const names = resourceNames('abc123');
  assert.equal(new Set(Object.values(names)).size, Object.keys(names).length);
  assert.ok(Object.values(names).every(name => name.startsWith('tc959-n0-abc123-')));
});

test('capture rejects unsafe values even when all request positive controls are present', () => {
  const baseline = [request, { ...request, route: '/version' }, { ...request, method: 'POST', route: '/invoke', status: 401 }, ingress];
  assert.doesNotThrow(() => assertCapture(baseline));
  assert.throws(() => assertCapture([request]));
  for (const poison of [{ authorization: 'synthetic-bearer' }, { route: '/raw-secret' }, { request_id: 'anything' }, { request_id_replaced: true }, { latency_us: -1 }, { status: 999 }, { extra: 'TC959_SYNTHETIC' }]) {
    assert.throws(() => assertCapture([{ ...request, ...poison }, ...baseline.slice(1)]));
  }
});

test('shipper isolation requires an actual loopback UDP binding, not just requested ports', () => {
  const inspect = { Config: { User: '10001:10001' }, HostConfig: { ReadonlyRootfs: true, Privileged: false, CapDrop: ['ALL'], SecurityOpt: ['no-new-privileges:true'], Memory: 67108864, NanoCpus: 500000000, Tmpfs: { '/tmp': 'rw,noexec,nosuid,size=8388608,mode=1777' }, PortBindings: { '12201/udp': [{ HostIp: '127.0.0.1', HostPort: '42000' }] } }, Mounts: [{ Destination: '/etc/vector/vector.json', RW: false }], NetworkSettings: { Networks: { 'tc959-n0-test-logship': {} }, Ports: { '12201/udp': [{ HostIp: '127.0.0.1', HostPort: '42000' }] } } };
  assert.doesNotThrow(() => assertShipperIsolation(inspect, 'tc959-n0-test-logship', 42000));
  assert.throws(() => assertShipperIsolation({ ...inspect, Config: { User: 'root' } }, 'tc959-n0-test-logship', 42000));
  assert.throws(() => assertShipperIsolation({ ...inspect, Mounts: [{ Destination: '/var/run/docker.sock', RW: false }] }, 'tc959-n0-test-logship', 42000));
  assert.throws(() => assertShipperIsolation({ ...inspect, NetworkSettings: { Networks: { bridge: {} } } }, 'tc959-n0-test-logship', 42000));
  for (const Ports of [{}, { '12201/udp': null }, { '12201/udp': [] }, { '12201/udp': [{ HostIp: '0.0.0.0', HostPort: '42000' }] }, { '12201/udp': [{ HostIp: '127.0.0.1', HostPort: '42001' }] }, { '12201/udp': [{ HostIp: '127.0.0.1', HostPort: '42000' }, { HostIp: '0.0.0.0', HostPort: '42000' }] }]) {
    assert.throws(() => assertShipperIsolation({ ...inspect, NetworkSettings: { ...inspect.NetworkSettings, Ports } }, 'tc959-n0-test-logship', 42000));
  }
});

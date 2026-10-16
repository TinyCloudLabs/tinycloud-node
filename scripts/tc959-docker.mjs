#!/usr/bin/env node
// Synthetic, local-only acceptance. No production credentials or env files are read.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import dgram from 'node:dgram';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildConfig, nodeImage, ingressImage, vectorImage } from './tc959-logship.mjs';
import { canary, nodeRequest } from '../log-shipper/cases.mjs';
import { awaitReadiness, classifyProbeError, classifyStartupOutput, hasUdpListener, componentCounters } from './tc959-readiness.mjs';

const owner = 'tc959-n0';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const token = 'TC959_SYNTHETIC_LOCAL_SINK_BEARER';
const methods = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', '<other>']);
const routes = new Set(['/healthz', '/version', '/invoke', '<unmatched>']);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let phase = 'preflight';

export function parseArgs(args) {
  const result = { go: false, deadline: undefined };
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--go') result.go = true;
    else if (args[index] === '--deadline' && args[index + 1]) result.deadline = args[++index];
    else throw new Error('invalid_arguments');
  }
  if (!result.go) throw new Error('explicit_go_required');
  if (result.deadline !== undefined && !Number.isFinite(Date.parse(result.deadline))) throw new Error('invalid_deadline');
  return result;
}

export function assertLocalDocker({ host, endpoint }) {
  if ((host && !host.startsWith('unix:///')) || !endpoint?.startsWith('unix:///')) throw new Error('local_unix_docker_required');
}

export function resourceNames(id) {
  return Object.fromEntries(['logship', 'sink', 'vector', 'node', 'ingress', 'emitter'].map(role => [role, `${owner}-${id}-${role}`]));
}

export function assertShipperIsolation(value, network, gelfPort) {
  const host = value.HostConfig;
  assert.equal(value.Config.User, '10001:10001');
  assert.equal(host.ReadonlyRootfs, true);
  assert.equal(host.Privileged, false);
  assert.deepEqual(host.CapDrop, ['ALL']);
  assert.ok(host.SecurityOpt.includes('no-new-privileges:true'));
  assert.equal(host.Memory, 64 * 1024 * 1024);
  assert.equal(host.NanoCpus, 500000000);
  assert.match(host.Tmpfs['/tmp'], /size=(8388608|8m)(,|$)/i);
  assert.deepEqual(Object.keys(value.NetworkSettings.Networks), [network]);
  assert.deepEqual(value.NetworkSettings.Ports['12201/udp'], [{ HostIp: '127.0.0.1', HostPort: String(gelfPort) }]);
  for (const mount of value.Mounts) {
    if (mount.Type === 'tmpfs' && mount.Destination === '/tmp') continue;
    assert.equal(mount.RW, false);
    assert.ok(!/sock|dstack|docker/i.test(`${mount.Source ?? ''} ${mount.Destination}`));
  }
}

export function assertCapture(events, fields) {
  assert.ok(events.length > 0);
  for (const event of events) {
    const encoded = JSON.stringify(event);
    for (const forbidden of [canary, 'TC959_SYNTHETIC', token, 'did:pkh:', 'email@example.test', 'Bearer ', 'eyJhbGci']) assert.ok(!encoded.includes(forbidden));
    assert.match(event.ts, /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/);
    const base = ['ts', 'level', 'event', 'svc'];
    let allowed;
    if (event.event === 'node_request' || event.event === 'ingress_request') {
      assert.equal(event.level, 'info');
      assert.equal(event.svc, event.event === 'node_request' ? 'api' : 'ingress');
      assert.ok(methods.has(event.method));
      assert.ok((fields?.route?.values ?? [...routes]).includes(event.route));
      assert.ok(Number.isInteger(event.status) && event.status >= 100 && event.status <= 599);
      const timing = event.event === 'node_request' ? 'latency_us' : 'request_time_seconds';
      if (timing === 'latency_us') assert.ok(Number.isSafeInteger(event[timing]) && event[timing] >= 0);
      else assert.ok(Number.isFinite(event[timing]) && event[timing] >= 0 && event[timing] <= 86400);
      allowed = [...base, 'method', 'route', 'status', timing];
    } else if (event.event === 'node_warning' || event.event === 'node_error') {
      assert.equal(event.svc, 'api');
      assert.equal(event.level, event.event === 'node_warning' ? 'warn' : 'error');
      assert.ok(fields?.event_code?.values.includes(event.event_code));
      assert.ok(Number.isSafeInteger(event.event_count) && event.event_count > 0);
      allowed = [...base, 'event_code', 'event_count'];
    } else {
      assert.equal(event.event, 'logship_gate_summary_total');
      assert.equal(event.svc, 'logship');
      assert.equal(event.level, 'warn');
      assert.ok(fields?.reason?.values.includes(event.reason));
      assert.ok(Number.isSafeInteger(event.count) && event.count > 0);
      allowed = [...base, 'reason', 'count'];
    }
    assert.deepEqual(Object.keys(event).sort(), allowed.sort());
  }
  for (const route of ['/healthz', '/version', '/invoke']) assert.ok(events.some(e => e.event === 'node_request' && e.route === route && e.method === (route === '/invoke' ? 'POST' : 'GET') && (route === '/invoke' ? e.status >= 400 : e.status === 200)));
  assert.ok(events.some(e => e.event === 'ingress_request' && e.route === '/healthz' && e.status === 200));
}

async function freePort(udp = false) {
  if (udp) {
    const socket = dgram.createSocket('udp4');
    await new Promise((resolve, reject) => { socket.once('error', reject); socket.bind(0, '127.0.0.1', resolve); });
    const port = socket.address().port;
    await new Promise(resolve => socket.close(resolve));
    return port;
  }
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

export async function main(args = process.argv.slice(2)) {
  const options = parseArgs(args);
  // No fixed calendar date in the reusable tool: the invocation must name its authorization window.
  if (!options.deadline) throw new Error('deadline_required');
  const deadline = Date.parse(options.deadline);
  const checkTime = () => { if (Date.now() >= deadline - 120000) throw new Error('deadline_cleanup_margin'); };
  checkTime();
  const command = (binary, args, { cleanup = false, optional = false } = {}) => {
    if (!cleanup) checkTime();
    const child = spawnSync(binary === 'docker' ? 'sudo' : binary, binary === 'docker' ? ['-n', 'docker', '--host', 'unix:///var/run/docker.sock', ...args] : args, { encoding: 'utf8', timeout: cleanup ? 10000 : 15000, maxBuffer: 16 * 1024 * 1024, stdio: ['ignore', 'pipe', 'pipe'] });
    if (!optional && (child.error || child.status !== 0)) {
      const detail = child.stderr ?? '';
      const reason = child.error?.code === 'ETIMEDOUT' ? 'timeout'
        : /permission denied|not permitted/i.test(detail) ? 'permission_denied'
        : /cannot connect|connection refused|daemon.*running/i.test(detail) ? 'daemon_unavailable'
        : /no such image|not found/i.test(detail) ? 'resource_missing'
        : /already in use|already exists|conflict/i.test(detail) ? 'resource_conflict'
        : /invalid|unknown|unsupported/i.test(detail) ? 'invalid_configuration'
        : child.status === 3 && binary === 'host-slot' ? 'claim_unavailable' : 'nonzero_exit';
      throw Object.assign(new Error(`${binary === 'docker' ? 'docker' : 'host_slot'}_command_failed`), { reason, operation: ['create', 'start', 'inspect', 'exec', 'network', 'pause', 'unpause', 'rm', 'image', 'context'].includes(args[0]) ? args[0] : 'check' });
    }
    return child;
  };
  const docker = (...args) => command('docker', args).stdout.trim();
  const json = (...args) => JSON.parse(docker(...args));
  const slot = cleanup => command('host-slot', ['check', '--owner', owner], { cleanup });
  // Every daemon operation is pinned to the local socket; no env values are inspected.
  const context = docker('context', 'show');
  const contextInfo = json('context', 'inspect', context)[0];
  assertLocalDocker({ endpoint: contextInfo.Endpoints?.docker?.Host });
  for (const image of [nodeImage, ingressImage, vectorImage]) docker('image', 'inspect', '--format', '{{.Id}}', image); // Never pull or guess another test image.
  const id = `${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`;
  const names = resourceNames(id);
  const scratch = await mkdtemp(join(tmpdir(), `${owner}-`));
  const containers = [];
  let networkCreated = false;
  let paused = false;
  let report;
  const starters = new Map();
  const start = (name, role) => {
    checkTime();
    const child = spawn('sudo', ['-n', 'docker', '--host', 'unix:///var/run/docker.sock', 'start', '--attach', name], { stdio: ['ignore', 'pipe', 'pipe'] });
    const state = { child, text: '' };
    const collect = chunk => { state.text = (state.text + chunk.toString()).slice(-65536); };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    child.on('error', () => { state.text = 'configuration error'; });
    starters.set(role, state);
  };
  const labels = ['--label', `${owner}=${id}`, '--label', `tc959.owner=${owner}`];
  const create = (name, args) => {
    slot(false);
    docker('create', '--name', name, ...labels, ...args);
    containers.push(name);
  };
  const inspectFormat = '{"Config":{"User":{{json .Config.User}},"Labels":{{json .Config.Labels}}},"HostConfig":{{json .HostConfig}},"Mounts":{{json .Mounts}},"NetworkSettings":{{json .NetworkSettings}},"State":{{json .State}}}';
  const inspect = name => JSON.parse(docker('inspect', '--format', inspectFormat, name));
  const capture = () => {
    const result = command('docker', ['exec', names.sink, 'cat', '/tmp/capture.ndjson'], { optional: true });
    if (result.status !== 0) return [];
    const complete = result.stdout.slice(0, result.stdout.lastIndexOf('\n') + 1);
    return complete.split('\n').filter(Boolean).map(line => JSON.parse(line));
  };
  const request = async (port, path, method = 'GET') => {
    checkTime();
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { authorization: `Bearer ${canary}`, 'x-request-id': canary, 'user-agent': canary }, signal: AbortSignal.timeout(3000), redirect: 'manual' });
    await response.arrayBuffer();
    return response.status;
  };
  const waitFor = async (predicate, attempts = 90) => {
    for (let index = 0; index < attempts; index++) {
      checkTime();
      if (await predicate()) return;
      await sleep(500);
    }
    throw new Error('readiness_timeout');
  };
  try {
    const [nodePort, ingressPort, gelfPort] = await Promise.all([freePort(), freePort(), freePort(true)]);
    phase = 'create';
    const shipperConfig = buildConfig({ sinkUri: `http://${names.sink}:8080/`, dataDir: '/tmp/vector-data', sourceAddress: '0.0.0.0:12201', token });
    // Local acceptance instrumentation only; production has no metrics listener.
    shipperConfig.sources.acceptance_metrics = { type: 'internal_metrics', scrape_interval_secs: 1 };
    shipperConfig.sinks.acceptance_metrics_out = { type: 'prometheus_exporter', inputs: ['acceptance_metrics'], address: '127.0.0.1:9598' };
    await writeFile(join(scratch, 'vector.json'), JSON.stringify(shipperConfig));
    slot(false);
    // Match compose: an internal-only bridge suppresses the daemon's published UDP port.
    docker('network', 'create', '--driver', 'bridge', ...labels, names.logship);
    networkCreated = true;
    const hardened = ['--network', names.logship, '--user', '10001:10001', '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '64m', '--memory-swap', '64m', '--cpus', '0.5', '--tmpfs', '/tmp:rw,noexec,nosuid,size=8388608,mode=1777', '--log-driver', 'none'];
    const vectorCommand = ['--entrypoint', '/bin/sh', vectorImage, '-ec', 'mkdir -p /tmp/vector-data; exec vector --config /etc/vector/vector.json'];
    create(names.sink, [...hardened, '--mount', `type=bind,src=${join(root, 'log-shipper/fixtures/capture.json')},dst=/etc/vector/vector.json,readonly`, ...vectorCommand]);
    create(names.vector, [...hardened, '--publish', `127.0.0.1:${gelfPort}:12201/udp`, '--mount', `type=bind,src=${join(scratch, 'vector.json')},dst=/etc/vector/vector.json,readonly`, ...vectorCommand]);
    const logging = label => ['--label', `tc.logship=${label}`, '--log-driver', 'gelf', '--log-opt', `gelf-address=udp://127.0.0.1:${gelfPort}`, '--log-opt', 'gelf-compression-type=none', '--log-opt', 'labels=tc.logship', '--log-opt', 'mode=non-blocking', '--log-opt', 'max-buffer-size=4m', '--log-opt', 'cache-disabled=true'];
    create(names.node, ['--network', 'bridge', '--publish', `127.0.0.1:${nodePort}:8000`, ...logging('tinycloud-node'), '--tmpfs', '/data:rw,nosuid,size=134217728,uid=1000,gid=1000,mode=0700', '--env', 'TINYCLOUD_LOG__FORMAT=Json', '--env', 'TINYCLOUD_LOG_LEVEL=normal', '--env', 'TINYCLOUD_KEYS__TYPE=Static', '--env', `TINYCLOUD_KEYS__SECRET=${Buffer.alloc(32, 9).toString('base64url')}`, '--env', 'TINYCLOUD_TEE__MODE=Off', '--env', 'TINYCLOUD_TEE_MODE=off', '--env', 'TINYCLOUD_STORAGE__DATADIR=/data', '--env', 'TINYCLOUD_STORAGE__DATABASE=sqlite:/data/caps.db?mode=rwc', '--env', 'TINYCLOUD_STORAGE__BLOCKS__TYPE=Local', '--env', 'TINYCLOUD_STORAGE__BLOCKS__PATH=/data/blocks', '--env', 'ROCKET_ADDRESS=0.0.0.0', '--env', 'TINYCLOUD_PORT=8000', nodeImage]);
    const nginxConfig = upstream => `worker_processes 1;\nerror_log /dev/stderr notice;\npid /tmp/nginx.pid;\nevents { worker_connections 1024; }\nhttp {\ninclude /etc/nginx/tc959-redacted.conf;\nserver { listen 80; location / { proxy_pass http://${upstream}; } }\n}\n`;
    await writeFile(join(scratch, 'nginx.conf'), nginxConfig('127.0.0.1:1'));
    create(names.ingress, ['--network', 'bridge', '--publish', `127.0.0.1:${ingressPort}:80`, ...logging('tinycloud-ingress'), '--mount', `type=bind,src=${join(scratch, 'nginx.conf')},dst=/etc/nginx/nginx.conf,readonly`, '--mount', `type=bind,src=${join(root, 'deploy/ingress/redacted-logging.conf')},dst=/etc/nginx/tc959-redacted.conf,readonly`, '--entrypoint', 'nginx', ingressImage, '-g', 'daemon off;']);
    create(names.emitter, ['--network', 'bridge', ...logging('tinycloud-node'), '--entrypoint', '/bin/sh', vectorImage, '-c', 'exec sleep 3600']);
    // The entire resource batch exists before the first start; no recreation.
    phase = 'start';
    start(names.sink, 'sink');
    start(names.vector, 'vector');
    start(names.node, 'node');
    start(names.emitter, 'emitter');
    await waitFor(() => inspect(names.node).State.Running);
    const nodeIP = inspect(names.node).NetworkSettings.Networks.bridge.IPAddress;
    assert.ok(net.isIPv4(nodeIP));
    // writeFile truncates the existing inode, preserving the already-bound mount.
    await writeFile(join(scratch, 'nginx.conf'), nginxConfig(`${nodeIP}:8000`));
    start(names.ingress, 'ingress');
    phase = 'listener_readiness';
    await awaitReadiness(async () => {
      const sockets = command('docker', ['exec', names.vector, 'cat', '/proc/net/udp'], { optional: true });
      const http = command('docker', ['exec', names.sink, 'nc', '-z', '-w', '1', '127.0.0.1', '8080'], { optional: true });
      return {
        vector_udp_listener: sockets.status === 0 && hasUdpListener(sockets.stdout, 12201),
        capture_tcp_listener: http.status === 0,
      };
    });
    phase = 'published_binding';
    const shipper = inspect(names.vector);
    assertShipperIsolation(shipper, names.logship, gelfPort);
    const logshipNetwork = json('network', 'inspect', names.logship)[0];
    assert.equal(logshipNetwork.Internal, false);
    assert.equal(logshipNetwork.Driver, 'bridge');
    phase = 'real_requests';
    await awaitReadiness(async () => {
      checkTime();
      const probe = async port => {
        try { return await request(port, '/healthz'); }
        catch (error) { return { state: classifyProbeError(error) }; }
      };
      return {
        node_healthz: await probe(nodePort),
        ingress_healthz: await probe(ingressPort),
        vector_running: inspect(names.vector).State.Running,
        sink_running: inspect(names.sink).State.Running,
      };
    });
    assert.equal(await request(nodePort, '/version'), 200);
    assert.ok(await request(nodePort, '/invoke', 'POST') >= 400);
    assert.equal(await request(ingressPort, '/version'), 200);
    await request(ingressPort, `/TC959_SYNTHETIC_PATH?ticket=${encodeURIComponent(canary)}`);
    phase = 'sink_real_requests';
    await awaitReadiness(async () => {
      const values = capture();
      return {
        node_request_sink: values.some(e => e.event === 'node_request' && e.route === '/invoke'),
        ingress_request_sink: values.some(e => e.event === 'ingress_request'),
      };
    });
    phase = 'isolation';
    const ingressIP = inspect(names.ingress).NetworkSettings.Networks.bridge.IPAddress;
    const gateway = logshipNetwork.IPAM.Config[0].Gateway;
    docker('exec', names.vector, '/bin/sh', '-c', 'command -v nc');
    // A failed/unsupported probe binary must not masquerade as network isolation.
    docker('exec', names.vector, 'nc', '-z', '-w', '2', names.sink, '8080');
    let reverseReachable = 0;
    for (const [address, port] of [[nodeIP, 8000], [ingressIP, 80], [gateway, nodePort], [gateway, ingressPort]]) {
      const probe = command('docker', ['exec', names.vector, 'nc', '-z', '-w', '2', address, String(port)], { optional: true });
      assert.equal(probe.error, undefined);
      if (probe.status === 0) reverseReachable++;
      assert.equal(inspect(names.vector).State.Running, true);
    }
    // Prove the intended HOST-loopback ingress before probing the app bridge.
    const gelf = latency_us => JSON.stringify({ version: '1.1', host: 'synthetic', short_message: JSON.stringify(nodeRequest({ method: 'GET', route: '/healthz', latency_us })), '_tc.logship': 'tinycloud-node', timestamp: Date.now() / 1000 });
    const hostControl = 7654322;
    const injected = 7654321;
    const udp = dgram.createSocket('udp4');
    await new Promise((resolve, reject) => udp.send(Buffer.from(gelf(hostControl)), gelfPort, '127.0.0.1', error => error ? reject(error) : resolve()));
    await new Promise(resolve => udp.close(resolve));
    await waitFor(() => capture().some(event => event.latency_us === hostControl));
    const shipperIP = shipper.NetworkSettings.Networks[names.logship].IPAddress;
    const peerControl = 7654323;
    docker('exec', names.sink, '/bin/sh', '-c', 'printf "%s" "$1" | nc -u -w 1 "$2" "$3"', 'probe', gelf(peerControl), shipperIP, '12201');
    await waitFor(() => capture().some(event => event.latency_us === peerControl));
    const appGateway = inspect(names.emitter).NetworkSettings.Networks.bridge.Gateway;
    docker('exec', names.emitter, '/bin/sh', '-c', 'command -v nc');
    assert.equal(capture().filter(event => event.latency_us === injected).length, 0);
    for (const [address, port] of [[shipperIP, 12201], [appGateway, gelfPort]]) {
      const sent = command('docker', ['exec', names.emitter, '/bin/sh', '-c', 'printf "%s" "$1" | nc -u -w 1 "$2" "$3"', 'probe', gelf(injected), address, String(port)], { optional: true });
      assert.equal(sent.error, undefined);
      if (sent.status !== 0 && !/unreachable|refused|timed out/i.test(sent.stderr)) throw new Error('isolation_sender_failed');
    }
    await sleep(3000);
    assert.equal(capture().filter(event => event.latency_us === injected).length, 0);
    phase = 'burst';
    // Untrusted labels are input selection, not authentication. An owned emitter exercises the real GELF driver.
    const emit = payload => docker('exec', names.emitter, '/bin/sh', '-c', 'printf "%s\\n" "$1" > /proc/1/fd/1', 'emit', payload);
    const synthetic = JSON.stringify(nodeRequest({ route: '/healthz', authorization: canary, uri: canary, nested: { did: canary } }));
    emit(synthetic);
    emit(JSON.stringify(nodeRequest({ route: `/signed/kv/${canary}` })));
    emit(`raw panic ${canary}`);
    // Single exec emits 500 individually framed lines; there is no fixed-volume request throttle.
    const burstLatency = 9000000001;
    const burstPayload = JSON.stringify(nodeRequest({ route: '/healthz', latency_us: burstLatency, authorization: canary, uri: canary }));
    docker('exec', names.emitter, '/bin/sh', '-c', 'i=0; while [ "$i" -lt 500 ]; do printf "%s\\n" "$1"; i=$((i+1)); done > /proc/1/fd/1', 'burst', burstPayload);
    await waitFor(() => capture().filter(e => e.event === 'node_request' && e.latency_us === burstLatency).length >= 500);
    // No lossless claim: paused UDP receivers and bounded nonblocking queues may lose events.
    phase = 'continuity';
    docker('pause', names.vector);
    paused = true;
    const continuityStart = Date.now();
    for (let index = 0; index < 30; index++) assert.equal(await request(nodePort, '/healthz'), 200);
    assert.ok(Date.now() - continuityStart < 15000);
    docker('unpause', names.vector);
    paused = false;
    const afterResume = capture().filter(e => e.event === 'node_request' && e.latency_us === 1234).length;
    emit(synthetic);
    await waitFor(() => capture().filter(e => e.event === 'node_request' && e.latency_us === 1234).length > afterResume);
    phase = 'diagnostic_counts';
    const diagnostic = (level, message) => JSON.stringify({ timestamp: new Date().toISOString(), level, target: 'tinycloud::runtime', fields: { message, error: canary } });
    emit(diagnostic('WARN', 'invalid link bind address; LAN listener not started'));
    emit(diagnostic('WARN', 'invalid link bind address; LAN listener not started'));
    emit(diagnostic('WARN', `raw tunnel close ${canary}`));
    emit(diagnostic('ERROR', 'native share KV put failed'));
    const total = (values, predicate, field) => values.filter(predicate).reduce((sum, value) => sum + value[field], 0);
    await waitFor(() => {
      const values = capture();
      return total(values, e => e.event === 'node_warning' && e.event_code === 'link_bind_invalid', 'event_count') >= 2
        && total(values, e => e.event === 'node_warning' && e.event_code === 'unclassified', 'event_count') >= 1
        && total(values, e => e.event === 'node_error' && e.event_code === 'share_native_kv_put_failed', 'event_count') >= 1
        && total(values, e => e.event === 'logship_gate_summary_total' && e.reason === 'invalid_fields', 'count') >= 1
        && total(values, e => e.event === 'logship_gate_summary_total' && e.reason === 'non_json', 'count') >= 1;
    }, 180);
    const events = capture();
    phase = 'capture_validation';
    const schema = JSON.parse(await readFile(join(root, 'log-shipper/fields.json'), 'utf8'));
    assertCapture(events, schema.services['tinycloud-node'].fields);
    const burstReceived = events.filter(e => e.event === 'node_request' && e.latency_us === burstLatency).length;
    assert.equal(burstReceived, 500, 'controlled healthy burst must not silently lose or duplicate events');
    report = { status: 'passed', events: events.length, node_requests: events.filter(e => e.event === 'node_request').length, ingress_requests: events.filter(e => e.event === 'ingress_request').length, burst_sent: 500, burst_received: burstReceived, burst_missing: Math.max(0, 500 - burstReceived), burst_loss_percent: Math.max(0, 500 - burstReceived) / 5, burst_duplicates: Math.max(0, burstReceived - 500), continuity_requests: 30, blocked_injection_probes: 2, reverse_tcp_probes: 4, reverse_tcp_reachable: reverseReachable, udp_lossless: false };
    Object.assign(report, {
      synthetic_warning_occurrences: total(events, e => e.event === 'node_warning' && e.event_code === 'link_bind_invalid', 'event_count'),
      unclassified_warning_occurrences: total(events, e => e.event === 'node_warning' && e.event_code === 'unclassified', 'event_count'),
      synthetic_error_occurrences: total(events, e => e.event === 'node_error' && e.event_code === 'share_native_kv_put_failed', 'event_count'),
      invalid_fields_rejections: total(events, e => e.event === 'logship_gate_summary_total' && e.reason === 'invalid_fields', 'count'),
      non_json_rejections: total(events, e => e.event === 'logship_gate_summary_total' && e.reason === 'non_json', 'count'),
      forbidden_canary_hits: 0,
      sender_positive_controls: 2,
    });
  } catch (error) {
    error.containers = Object.fromEntries(containers.map(name => {
      const role = Object.keys(names).find(key => names[key] === name);
      try {
        const state = inspect(name).State;
        return [role, { running: state.Running, exit_code: state.ExitCode, oom_killed: state.OOMKilled }];
      } catch { return [role, { state: 'inspect_unavailable' }]; }
    }));
    error.startup = Object.fromEntries([...starters].map(([role, state]) => [role, classifyStartupOutput(state.text)]));
    try {
      const metrics = command('docker', ['exec', names.vector, 'wget', '-q', '-O', '-', 'http://127.0.0.1:9598/metrics'], { optional: true });
      error.counters = metrics.status === 0
        ? Object.fromEntries(['gelf_in', 'logship_gate', 'allowlist', 'betterstack'].map(id => [id, componentCounters(metrics.stdout, id)]))
        : { state: 'unavailable' };
      error.captured_events = capture().length;
    } catch { error.counters = { state: 'unavailable' }; }
    throw error;
  } finally {
    // Cleanup exactly our once-created resources, never discover-and-delete or global prune.
    if (paused) command('docker', ['unpause', names.vector], { cleanup: true, optional: true });
    let cleanupFailed = false;
    for (const name of containers.reverse()) {
      try {
        const state = JSON.parse(command('docker', ['inspect', '--format', inspectFormat, name], { cleanup: true }).stdout);
        assert.equal(state.Config.Labels[owner], id);
        assert.equal(state.Config.Labels['tc959.owner'], owner);
        slot(true);
        command('docker', ['rm', '--force', name], { cleanup: true });
      } catch { cleanupFailed = true; }
    }
    if (networkCreated) {
      try {
        const network = JSON.parse(command('docker', ['network', 'inspect', names.logship], { cleanup: true }).stdout)[0];
        assert.equal(network.Labels[owner], id);
        slot(true);
        command('docker', ['network', 'rm', names.logship], { cleanup: true });
      } catch { cleanupFailed = true; }
    }
    for (const { child } of starters.values()) child.kill('SIGTERM');
    await rm(scratch, { recursive: true, force: true });
    if (cleanupFailed) throw new Error('owned_cleanup_incomplete');
  }
  process.stdout.write(`${JSON.stringify(report)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    const known = new Set(['invalid_arguments', 'explicit_go_required', 'invalid_deadline', 'deadline_required', 'deadline_cleanup_margin', 'local_unix_docker_required', 'docker_command_failed', 'host_slot_command_failed', 'readiness_timeout', 'owned_cleanup_incomplete']);
    const code = known.has(error.message) ? error.message : error.code === 'ERR_ASSERTION' ? 'assertion_failed' : 'unexpected_failure';
    process.stdout.write(`${JSON.stringify({ status: 'failed', phase, code, ...(error.reason ? { reason: error.reason, operation: error.operation } : {}), ...(error.diagnostics ? { probes: error.diagnostics } : {}), ...(error.containers ? { containers: error.containers, startup: error.startup, counters: error.counters, captured_events: error.captured_events } : {}) })}\n`);
    process.exitCode = 1;
  });
}

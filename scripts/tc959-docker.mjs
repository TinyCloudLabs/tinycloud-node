#!/usr/bin/env node
// Disposable hosted-runner proof. Never reads deployment credentials, .env files or GH secrets.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import dgram from 'node:dgram';
import { writeFileSync } from 'node:fs';
import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import net from 'node:net';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { buildConfig, nodeImage, ingressImage, vectorImage } from './tc959-logship.mjs';
import { canary, nodeRequest } from '../log-shipper/cases.mjs';
import { awaitReadiness, classifyProbeError, classifyStartupOutput, hasUdpListener, componentCounters } from './tc959-readiness.mjs';
import { owner, assertHostedRunner, cleanupOwnedResources, burstEvidence, assertHealthyBurst, progressEvidence, assertServiceParity, socketEvidence, numericMetrics, diagnosticCounts } from './tc959-compose-proof.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const token = 'TC959_SYNTHETIC_HOSTED_SINK_BEARER';
const burstFirst = 100000; // Fast errors: all 500 markers remain below the slow threshold.
const burstSize = 500;
const fastMarker = 800000;
const methods = new Set(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', '<other>']);
const routes = new Set(['/healthz', '/version', '/invoke', '<unmatched>']);
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let phase = 'preflight';

export function parseArgs(args) {
  const result = { go: false, ci: false, cleanupOnly: false, deadline: undefined };
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--go') result.go = true;
    else if (args[index] === '--ci') result.ci = true;
    else if (args[index] === '--cleanup-only') result.cleanupOnly = true;
    else if (args[index] === '--deadline' && args[index + 1]) result.deadline = args[++index];
    else throw new Error('invalid_arguments');
  }
  if (!result.go) throw new Error('explicit_go_required');
  if (!result.ci) throw new Error('disposable_hosted_runner_required');
  if (result.deadline !== undefined && !Number.isFinite(Date.parse(result.deadline))) throw new Error('invalid_deadline');
  return result;
}

export function resourceNames(id) {
  return Object.fromEntries(['logship', 'sink', 'vector', 'node', 'ingress', 'emitter'].map(role => [role, `${owner}-${id}-${role}`]));
}

/** Strict validation applies to every captured record, including a failing proof's partial capture. */
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
}

async function freePort() {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  const port = server.address().port;
  await new Promise(resolve => server.close(resolve));
  return port;
}

const substitutions = [
  'node_static_keys_sqlite_local_blocks_tee_off_share_email_off',
  'node_dstack_socket_replaced_with_ephemeral_data_tmpfs',
  'ingress_local_nginx_bootstrap_no_dns_no_certbot_no_dstack_no_tls',
  'app_dynamic_loopback_http_ports_default_docker_bridge',
  'vector_synthetic_sink_uri_and_bearer_internal_metrics_only',
  'restart_policy_disabled_for_all_once_created_containers',
];

/** The only executable Docker entry point: guarded, bounded, no deployment inputs. */
export async function main(args = process.argv.slice(2)) {
  const options = parseArgs(args);
  assertHostedRunner(process.env);
  const id = `${process.env.GITHUB_RUN_ID}-${process.env.GITHUB_RUN_ATTEMPT}`;
  const names = resourceNames(id);
  const scratch = join(process.env.RUNNER_TEMP, `${owner}-${id}`);
  const deadline = options.deadline ? Date.parse(options.deadline) : Date.now() + 420000;
  const checkTime = () => { if (Date.now() >= deadline - 45000) throw new Error('deadline_cleanup_margin'); };
  const env = {
    PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', HOME: scratch, LANG: 'C.UTF-8', DOCKER_CONFIG: join(scratch, 'docker-config'), COMPOSE_DISABLE_ENV_FILE: 'true',
    DATABASE_URL: 'sqlite:/data/caps.db?mode=rwc', S3_BUCKET: 'tc959-synthetic', S3_ENDPOINT: 'http://127.0.0.1:9', AWS_KEY: 'TC959_SYNTHETIC_KEY', AWS_SECRET: 'TC959_SYNTHETIC_SECRET', AWS_REGION: 'us-east-1',
    SQL_IDENTITY_FENCE: 'false', SHARE_TRUST_BUNDLE_BASE64: Buffer.from('{}').toString('base64'), TINYCLOUD_QUOTA_URL: '', TINYCLOUD_ADMIN_SECRET: 'TC959_SYNTHETIC_ADMIN',
    CLOUDFLARE_API_TOKEN: 'TC959_SYNTHETIC_DNS', DSTACK_GATEWAY_DOMAIN: 'invalid.test', CERTBOT_EMAIL: 'email@example.test', BETTERSTACK_SOURCE_TOKEN: token, TINYCLOUD_LOGSHIP_PROFILE: 'errors_slow',
  };
  const command = (binary, args, { final = false, optional = false, timeout = 15000 } = {}) => {
    if (!final) checkTime();
    const docker = binary === 'docker';
    const child = spawnSync(docker ? 'sudo' : binary, docker ? ['-n', 'env', '-i', ...Object.entries(env).map(([key, value]) => `${key}=${value}`), 'docker', '--host', 'unix:///var/run/docker.sock', ...args] : args,
      { encoding: 'utf8', timeout, maxBuffer: 16 * 1024 * 1024, env, cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
    if (!optional && (child.error || child.status !== 0)) throw Object.assign(new Error('proof_command_failed'), { operation: docker ? args[0] : 'diagnostic', timed_out: child.error?.code === 'ETIMEDOUT' });
    return child;
  };
  const docker = (...args) => command('docker', args).stdout.trim();
  const inspect = (name, final = false) => {
    // Actual environments are wholly synthetic. Never print this inspect result.
    const result = command('docker', ['inspect', name], { final, optional: final });
    return result.status === 0 ? JSON.parse(result.stdout)[0] : null;
  };
  const inventory = () => {
    const resources = [];
    for (const [kind, args] of [['container', ['ps', '--all', '--quiet']], ['network', ['network', 'ls', '--quiet']], ['volume', ['volume', 'ls', '--quiet']]]) {
      const listed = command('docker', [...args, '--filter', `label=tc959.owner=${owner}`, '--filter', `label=${owner}=${id}`], { final: true });
      for (const resource of listed.stdout.trim().split(/\s+/).filter(Boolean)) {
        const args = kind === 'container' ? ['inspect', resource] : [kind, 'inspect', resource];
        const value = JSON.parse(command('docker', args, { final: true }).stdout)[0];
        resources.push({ kind, name: (value.Name ?? resource).replace(/^\//, ''), labels: kind === 'container' ? value.Config.Labels : value.Labels });
      }
    }
    return resources;
  };
  const capture = () => {
    const result = command('docker', ['exec', names.sink, 'cat', '/tmp/capture.ndjson'], { final: true, optional: true });
    if (result.status !== 0) return { events: [], invalid: 0, incomplete: 0, canary_hits: 0, available: false };
    const lines = result.stdout.split('\n');
    const trailing = lines.pop();
    let invalid = 0;
    const events = [];
    let hits = 0;
    // Scan even malformed/partial lines; never echo their contents or parser messages.
    for (const line of [...lines, trailing].filter(Boolean)) {
      if ([canary, 'TC959_SYNTHETIC', token, 'did:pkh:', 'email@example.test', 'Bearer ', 'eyJhbGci'].some(value => line.includes(value))) hits++;
      try { events.push(JSON.parse(line)); } catch { invalid++; }
    }
    return { events, invalid, incomplete: trailing ? 1 : 0, canary_hits: hits, available: true };
  };
  const readMetrics = () => {
    const result = command('docker', ['exec', names.vector, 'wget', '-q', '-O', '-', 'http://127.0.0.1:9598/metrics'], { final: true, optional: true });
    return result.status === 0 ? result.stdout : '';
  };
  const sockets = () => {
    const state = inspect(names.vector, true);
    let text = '';
    let rmem = '';
    if (state?.State.Running && state.State.Pid > 0) {
      const prefix = ['-n', 'nsenter', '--target', String(state.State.Pid), '--net'];
      text = command('sudo', [...prefix, 'ss', '-u', '-a', '-n', '-m', 'sport', '=', ':12201'], { final: true, optional: true }).stdout ?? '';
      rmem = command('sudo', [...prefix, 'cat', '/proc/sys/net/core/rmem_max'], { final: true, optional: true }).stdout ?? '';
    }
    return socketEvidence(text, rmem);
  };
  const cpu = () => {
    const result = command('docker', ['exec', names.vector, 'cat', '/sys/fs/cgroup/cpu.stat'], { final: true, optional: true });
    const allowed = new Set(['usage_usec', 'user_usec', 'system_usec', 'nr_periods', 'nr_throttled', 'throttled_usec']);
    return Object.fromEntries((result.stdout ?? '').split('\n').map(line => line.trim().split(/\s+/)).filter(([key, value]) => allowed.has(key) && /^\d+$/.test(value ?? '')).map(([key, value]) => [key, Number(value)]));
  };
  const samples = [];
  let startedAt = Date.now();
  let schema;
  let burstSent = null;
  let socketBefore = null;
  let cpuBefore = null;
  let socketAfterBurst = null;
  let cpuAfterBurst = null;
  let diagnosticBaseline = null;
  let diagnosticInjected = null;
  let schemaChecked = 0;
  let schemaInvalid = 0;
  const validateCapture = values => {
    let bad = 0;
    for (const event of values.events) {
      try { assertCapture([event], schema.services['tinycloud-node'].fields); } catch { bad++; }
    }
    schemaChecked = values.events.length;
    schemaInvalid = bad + values.invalid;
    return { checked: schemaChecked, invalid: schemaInvalid, incomplete: values.incomplete, canary_hits: values.canary_hits, available: values.available };
  };
  const sample = () => {
    const metrics = readMetrics();
    const hops = Object.fromEntries(['gelf_in', 'logship_gate', 'allowlist', 'request_profile', 'event_route', 'betterstack'].map(key => [key, componentCounters(metrics, key)]));
    const values = capture();
    const point = { elapsed_ms: Date.now() - startedAt, source: hops.gelf_in.sent_events, gate: hops.logship_gate.sent_events, admitted: hops.request_profile.sent_events, sink: hops.betterstack.sent_events, capture: values.events.length,
      burst_capture: burstEvidence(values.events, burstFirst, burstSize).received };
    samples.push(point);
    // Only synthetic numeric evidence is persisted for an outer step timeout's always() diagnostic.
    try { writeFileSync(join(scratch, 'evidence-state.json'), JSON.stringify({ startedAt, burstSent, socketBefore, cpuBefore, socketAfterBurst, cpuAfterBurst, diagnosticBaseline, diagnosticInjected, samples })); } catch { /* Live-resource diagnostics remain available if the snapshot write fails. */ }
    return { point, hops, metrics: numericMetrics(metrics), values };
  };
  const diagnostics = async () => {
    const last = sample();
    const emitted = command('docker', ['exec', names.emitter, 'cat', '/tmp/tc959-emitted-count'], { final: true, optional: true });
    const count = emitted.status === 0 && /^\d+\s*$/.test(emitted.stdout) ? Number(emitted.stdout.trim()) : burstSent;
    const states = {};
    const startup = {};
    for (const role of ['sink', 'vector', 'node', 'ingress', 'emitter']) {
      const value = inspect(names[role], true);
      states[role] = value ? { running: value.State.Running, exit_code: value.State.ExitCode, oom_killed: value.State.OOMKilled, restart_count: value.RestartCount } : { state: 'not_created' };
      const output = command('docker', ['logs', '--tail', '80', names[role]], { final: true, optional: true });
      startup[role] = classifyStartupOutput(`${output.stdout ?? ''}\n${output.stderr ?? ''}`);
    }
    const burst = burstEvidence(last.values.events, burstFirst, burstSize);
    const socketAfter = sockets();
    const cpuAfter = cpu();
    const delta = (before, after) => Number.isFinite(before) && Number.isFinite(after) ? after - before : null;
    return { emitted_burst: count, burst: { ...burst, received_markers: Array.from({ length: burstSize }, (_, index) => burstFirst + index).filter(marker => !burst.missing.includes(marker)) }, capture: validateCapture(last.values), hops: last.hops,
      diagnostic_controls: { baseline: diagnosticBaseline, injected: diagnosticInjected, observed: diagnosticCounts(last.values.events) },
      progress: progressEvidence(samples), socket_before: socketBefore, socket_after_healthy_burst: socketAfterBurst, socket_after_all_controls: socketAfter,
      healthy_burst_socket_drops_delta: delta(socketBefore?.socket_drops, socketAfterBurst?.socket_drops), overall_socket_drops_delta: delta(socketBefore?.socket_drops, socketAfter.socket_drops),
      cpu_before: cpuBefore, cpu_after_healthy_burst: cpuAfterBurst, cpu_after_all_controls: cpuAfter,
      healthy_burst_cpu_throttled_periods_delta: delta(cpuBefore?.nr_throttled, cpuAfterBurst?.nr_throttled), overall_cpu_throttled_periods_delta: delta(cpuBefore?.nr_throttled, cpuAfter.nr_throttled), buffer_backpressure_errors: last.metrics, states, startup };
  };
  const cleanup = () => {
    const owned = inventory();
    const counts = cleanupOwnedResources(owned, resource => {
      if (resource.kind === 'container') {
        const value = inspect(resource.name, true);
        if (value?.State.Paused) command('docker', ['unpause', resource.name], { final: true });
        command('docker', ['rm', '--force', resource.name], { final: true });
      } else command('docker', [resource.kind, 'rm', resource.name], { final: true });
    }, id);
    const remaining = inventory();
    assert.equal(remaining.length, 0, 'owned_cleanup_incomplete');
    const labelled = {};
    for (const [kind, args] of [['containers', ['ps', '--all', '--quiet']], ['networks', ['network', 'ls', '--quiet']], ['volumes', ['volume', 'ls', '--quiet']]]) {
      const output = command('docker', [...args, '--filter', `label=tc959.owner=${owner}`], { final: true }).stdout.trim();
      labelled[kind] = output ? output.split(/\s+/).length : 0;
    }
    assert.equal(Object.values(labelled).reduce((sum, count) => sum + count, 0), 0, 'owned_cleanup_incomplete');
    return { removed: counts, remaining_labelled: labelled };
  };
  schema = JSON.parse(await readFile(join(root, 'log-shipper/fields.json'), 'utf8'));
  if (options.cleanupOnly) {
    // Workflow always() calls this even after the proof step's outer timeout.
    let evidence;
    let failure;
    try {
      const owned = inventory();
      if (owned.length) {
        try {
          const state = JSON.parse(await readFile(join(scratch, 'evidence-state.json'), 'utf8'));
          const numeric = value => Number.isFinite(value) && value >= 0 ? value : null;
          const pick = (value, keys) => Object.fromEntries(keys.map(key => [key, numeric(value?.[key])]));
          startedAt = numeric(state.startedAt) ?? Date.now();
          burstSent = numeric(state.burstSent);
          socketBefore = pick(state.socketBefore, ['requested_receive_buffer_bytes', 'rmem_max', 'effective_so_rcvbuf', 'socket_drops']);
          cpuBefore = pick(state.cpuBefore, ['usage_usec', 'user_usec', 'system_usec', 'nr_periods', 'nr_throttled', 'throttled_usec']);
          socketAfterBurst = pick(state.socketAfterBurst, ['requested_receive_buffer_bytes', 'rmem_max', 'effective_so_rcvbuf', 'socket_drops']);
          cpuAfterBurst = pick(state.cpuAfterBurst, ['usage_usec', 'user_usec', 'system_usec', 'nr_periods', 'nr_throttled', 'throttled_usec']);
          if (state.diagnosticBaseline) diagnosticBaseline = pick(state.diagnosticBaseline, ['warn', 'unclassified', 'error', 'dependency_error', 'total']);
          if (state.diagnosticInjected) diagnosticInjected = pick(state.diagnosticInjected, ['warn', 'unclassified', 'error', 'dependency_error', 'total']);
          if (Array.isArray(state.samples)) for (const point of state.samples.slice(-32)) samples.push(pick(point, ['elapsed_ms', 'source', 'gate', 'admitted', 'sink', 'capture', 'burst_capture']));
        } catch { /* An early timeout can precede the first synthetic numeric snapshot. */ }
        for (const resource of owned.filter(value => value.kind === 'container')) {
          const state = inspect(resource.name, true);
          if (state?.State.Paused) command('docker', ['unpause', resource.name], { final: true, optional: true });
        }
        if (!samples.length) startedAt = Date.now();
        sample(); await sleep(1000); sample(); await sleep(1000);
        evidence = await diagnostics();
        if (evidence.capture.invalid || evidence.capture.canary_hits || evidence.capture.incomplete) failure = 'capture_boundary_failed';
      }
    } finally {
      const result = cleanup();
      await rm(scratch, { recursive: true, force: true });
      process.stdout.write(`${JSON.stringify({ status: failure ? 'failed' : 'cleaned', phase: 'always_cleanup', ...(evidence ? { evidence } : {}), cleanup: result })}\n`);
    }
    if (failure) throw new Error(failure);
    return;
  }
  checkTime();
  await mkdir(scratch, { recursive: false });
  await mkdir(env.DOCKER_CONFIG);
  let report = { status: 'failed', compose_proof: false, substitutions, dstack_tls_proof: false, udp_lossless: false };
  let failure;
  const waitFor = async (predicate, attempts = 90) => {
    for (let index = 0; index < attempts; index++) { checkTime(); if (await predicate()) return; await sleep(500); }
    throw new Error('readiness_timeout');
  };
  const request = async (port, path, method = 'GET') => {
    checkTime();
    const response = await fetch(`http://127.0.0.1:${port}${path}`, { method, headers: { authorization: `Bearer ${canary}`, 'x-request-id': canary, 'user-agent': canary }, signal: AbortSignal.timeout(3000), redirect: 'manual' });
    await response.arrayBuffer();
    return response.status;
  };
  const labels = ['--label', `${owner}=${id}`, '--label', `tc959.owner=${owner}`];
  const create = (name, args) => docker('create', '--name', name, ...labels, ...args);
  const loggingArgs = service => ['--log-driver', service.logging.driver, ...Object.entries(service.logging.options ?? {}).flatMap(([key, value]) => ['--log-opt', `${key}=${value}`])];
  const serviceArgs = (service, network) => {
    const args = ['--network', network, '--restart', 'no', ...loggingArgs(service)];
    if (service.init) args.push('--init');
    if (service.user) args.push('--user', service.user);
    if (service.read_only) args.push('--read-only');
    assert.equal(service.privileged ?? false, false);
    for (const cap of service.cap_drop ?? []) args.push('--cap-drop', cap);
    for (const option of service.security_opt ?? []) args.push('--security-opt', option);
    if (service.mem_limit) args.push('--memory', String(service.mem_limit));
    if (service.memswap_limit) args.push('--memory-swap', String(service.memswap_limit));
    if (service.cpus) args.push('--cpus', String(service.cpus));
    for (const value of service.tmpfs ?? []) args.push('--tmpfs', value);
    for (const [key, value] of Object.entries(service.labels ?? {})) args.push('--label', `${key}=${value}`);
    for (const [key, value] of Object.entries(service.environment ?? {})) args.push('--env', `${key}=${value}`);
    return args;
  };
  const declaredVolumes = new Map();
  const disposableVolumeArgs = image => (declaredVolumes.get(image) ?? []).flatMap(path => ['--tmpfs', `${path}:rw,noexec,nosuid,size=8388608,mode=1777`]);
  try {
    phase = 'immutable_images';
    for (const image of [nodeImage, ingressImage, vectorImage]) {
      assert.match(image, /@sha256:[a-f0-9]{64}$/);
      command('docker', ['pull', image], { timeout: 150000 });
      const metadata = JSON.parse(docker('image', 'inspect', image))[0];
      assert.ok(metadata.RepoDigests.includes(image.replace(/:[^/:@]+@/, '@')));
      const volumes = Object.keys(metadata.Config.Volumes ?? {});
      assert.ok(volumes.every(path => ['/var/lib/vector', '/data', '/etc/letsencrypt'].includes(path)), 'unexpected_image_volume');
      declaredVolumes.set(image, volumes);
    }
    phase = 'compose_render';
    const composeArgs = ['compose', '--env-file', '/dev/null', '-f', join(root, 'docker-compose.dstack-postgres.yaml'), 'config'];
    const unresolved = JSON.parse(docker(...composeArgs, '--no-interpolate', '--no-env-resolution', '--format', 'json'));
    assert.equal(unresolved.secrets, undefined, 'deployment_secret_files_forbidden');
    assert.equal(unresolved.configs, undefined, 'deployment_config_files_forbidden');
    for (const service of Object.values(unresolved.services)) assert.equal(service.env_file, undefined, 'deployment_env_files_forbidden');
    const rendered = JSON.parse(docker(...composeArgs, '--format', 'json'));
    const production = rendered.services;
    phase = 'compose_images';
    assert.equal(production.tinycloud.image, nodeImage);
    assert.equal(production['dstack-ingress'].image, ingressImage);
    assert.equal(production.vector.image, vectorImage);
    phase = 'compose_fields';
    // Refuse silently ignored compose fields: this is a projection with explicit substitutions, not a mirror.
    const supported = new Set(['image', 'restart', 'labels', 'logging', 'ports', 'volumes', 'environment', 'networks', 'depends_on', 'entrypoint', 'command', 'init', 'user', 'read_only', 'cap_drop', 'security_opt', 'mem_limit', 'memswap_limit', 'cpus', 'tmpfs', 'privileged']);
    for (const service of [production.tinycloud, production['dstack-ingress'], production.vector]) for (const key of Object.keys(service)) assert.ok(supported.has(key), 'unsupported_rendered_compose_field');
    phase = 'compose_ports';
    assert.equal(production.vector.volumes, undefined);
    assert.equal(production.tinycloud.ports.length, 1);
    assert.equal(production.tinycloud.ports[0].target, 8000);
    assert.equal(production['dstack-ingress'].ports.length, 1);
    assert.equal(production['dstack-ingress'].ports[0].target, 443);
    for (const [service, port] of [[production.tinycloud, 8000], [production['dstack-ingress'], 443]]) {
      assert.equal(service.ports[0].published, String(port));
      assert.equal(service.ports[0].protocol, 'tcp');
      assert.equal(service.ports[0].host_ip ?? '0.0.0.0', '0.0.0.0');
    }
    phase = 'compose_mounts';
    assert.deepEqual(production.tinycloud.volumes.map(value => [value.type, value.source, value.target]), [['bind', '/var/run/dstack.sock', '/var/run/dstack.sock']]);
    assert.deepEqual(production['dstack-ingress'].volumes.map(value => [value.type, value.source, value.target]).sort((a, b) => a[2].localeCompare(b[2])), [['volume', 'cert-data', '/etc/letsencrypt'], ['bind', '/var/run/dstack.sock', '/var/run/dstack.sock']]);
    phase = 'compose_networks';
    assert.deepEqual(Object.keys(production.tinycloud.networks), ['default']);
    assert.deepEqual(Object.keys(production['dstack-ingress'].networks), ['default']);
    assert.deepEqual(Object.keys(production.vector.networks), ['logship']);
    assert.equal(rendered.networks.logship.driver, 'bridge');
    assert.equal(rendered.networks.logship.internal ?? false, false);
    assert.equal(rendered.networks.logship.external ?? false, false);
    assert.ok(Object.keys(rendered.networks.logship).every(key => ['name', 'driver', 'internal', 'external'].includes(key)), 'unsupported_compose_network_options');
    phase = 'compose_compiler';
    const compiled = buildConfig({ runtimeProfile: true });
    assert.deepEqual(JSON.parse(production.vector.environment.VECTOR_CONFIG_JSON), compiled, 'rendered_compose_compiler_mismatch');
    assert.equal(compiled.sources.gelf_in.receive_buffer_bytes, 8388608);
    const [nodePort, ingressPort] = await Promise.all([freePort(), freePort()]);
    const vectorService = structuredClone(production.vector);
    vectorService.restart = 'no';
    const config = JSON.parse(vectorService.environment.VECTOR_CONFIG_JSON);
    config.sinks.betterstack.uri = `http://${names.sink}:8080/`;
    config.sources.acceptance_metrics = { type: 'internal_metrics', scrape_interval_secs: 1 };
    config.sinks.acceptance_metrics_out = { type: 'prometheus_exporter', inputs: ['acceptance_metrics'], address: '127.0.0.1:9598' };
    vectorService.environment = { ...vectorService.environment, BETTERSTACK_SOURCE_TOKEN: token, TINYCLOUD_LOGSHIP_PROFILE: 'errors_slow', VECTOR_CONFIG_JSON: JSON.stringify(config) };
    const nodeService = structuredClone(production.tinycloud);
    nodeService.restart = 'no';
    nodeService.environment = {
      TINYCLOUD_LOG__FORMAT: production.tinycloud.environment.TINYCLOUD_LOG__FORMAT, TINYCLOUD_LOG_LEVEL: 'normal', TINYCLOUD_KEYS__TYPE: 'Static', TINYCLOUD_KEYS__SECRET: Buffer.alloc(32, 9).toString('base64url'),
      TINYCLOUD_TEE__MODE: 'Off', TINYCLOUD_TEE_MODE: 'off', TINYCLOUD_STORAGE__DATADIR: '/data', TINYCLOUD_STORAGE__DATABASE: 'sqlite:/data/caps.db?mode=rwc', TINYCLOUD_STORAGE__BLOCKS__TYPE: 'Local', TINYCLOUD_STORAGE__BLOCKS__PATH: '/data/blocks', ROCKET_ADDRESS: '0.0.0.0', TINYCLOUD_PORT: '8000', TINYCLOUD_SHARE_EMAIL__ENABLED: 'false',
    };
    nodeService.tmpfs = ['/data:rw,nosuid,size=134217728,uid=1000,gid=1000,mode=0700'];
    const ingressService = structuredClone(production['dstack-ingress']);
    ingressService.restart = 'no';
    ingressService.environment = {};
    ingressService.entrypoint = ['nginx'];
    ingressService.command = ['-g', 'daemon off;'];
    if (declaredVolumes.get(ingressImage).length) ingressService.tmpfs = declaredVolumes.get(ingressImage).map(path => `${path}:rw,noexec,nosuid,size=8388608,mode=1777`);
    for (const service of [vectorService, nodeService, ingressService]) for (const path of declaredVolumes.get(service.image)) assert.ok((service.tmpfs ?? []).some(value => value.startsWith(`${path}:`)), 'anonymous_image_volume_forbidden');
    // Logging options remain EXACTLY as rendered, including the real published UDP port 12201.
    for (const service of [nodeService, ingressService]) assert.deepEqual(service.logging, production[service === nodeService ? 'tinycloud' : 'dstack-ingress'].logging);
    const portMap = (target, published, protocol = 'tcp') => ({ [`${target}/${protocol}`]: [{ HostIp: '127.0.0.1', HostPort: String(published) }] });
    const vectorPorts = Object.fromEntries(production.vector.ports.map(port => [`${port.target}/${port.protocol}`, [{ HostIp: port.host_ip, HostPort: port.published }]]));
    assert.deepEqual(vectorPorts, portMap(12201, 12201, 'udp'));
    const vectorPublish = production.vector.ports.flatMap(port => ['--publish', `${port.host_ip}:${port.published}:${port.target}/${port.protocol}`]);
    const nginxConfig = upstream => `worker_processes 1;\nerror_log /dev/stderr notice;\npid /tmp/nginx.pid;\nevents { worker_connections 1024; }\nhttp {\ninclude /etc/nginx/tc959-redacted.conf;\nserver { listen 80; location / { proxy_pass http://${upstream}; } }\n}\n`;
    await writeFile(join(scratch, 'nginx.conf'), nginxConfig('127.0.0.1:1'));
    phase = 'create_batch';
    docker('network', 'create', '--driver', rendered.networks.logship.driver, ...labels, names.logship);
    const sinkArgs = ['--network', names.logship, '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '64m', '--memory-swap', '64m', '--cpus', '0.5', '--tmpfs', '/tmp:rw,noexec,nosuid,size=8388608,mode=1777', '--log-driver', 'none'];
    create(names.sink, [...sinkArgs, ...disposableVolumeArgs(vectorImage), '--user', '10001:10001', '--mount', `type=bind,src=${join(root, 'log-shipper/fixtures/capture.json')},dst=/etc/vector/vector.json,readonly`, '--entrypoint', '/bin/sh', vectorImage, '-ec', 'mkdir -p /tmp/vector-data; exec vector --config /etc/vector/vector.json']);
    create(names.vector, [...serviceArgs(vectorService, names.logship), ...vectorPublish, '--entrypoint', vectorService.entrypoint[0], vectorService.image, ...vectorService.entrypoint.slice(1)]);
    create(names.node, [...serviceArgs(nodeService, 'bridge'), '--publish', `127.0.0.1:${nodePort}:8000`, nodeService.image]);
    create(names.ingress, [...serviceArgs(ingressService, 'bridge'), '--publish', `127.0.0.1:${ingressPort}:80`, '--mount', `type=bind,src=${join(scratch, 'nginx.conf')},dst=/etc/nginx/nginx.conf,readonly`, '--mount', `type=bind,src=${join(root, 'deploy/ingress/redacted-logging.conf')},dst=/etc/nginx/tc959-redacted.conf,readonly`, '--entrypoint', ingressService.entrypoint[0], ingressService.image, ...ingressService.command]);
    create(names.emitter, ['--network', 'bridge', '--label', 'tc.logship=tinycloud-node', ...loggingArgs(nodeService), ...disposableVolumeArgs(vectorImage), '--tmpfs', '/tmp:rw,noexec,nosuid,size=1048576,mode=1777', '--entrypoint', '/bin/sh', vectorImage, '-c', 'exec sleep 3600']);
    // One batch is fully created before any start; no restart/recreate is allowed.
    phase = 'start_batch';
    docker('start', names.sink, names.vector, names.node, names.emitter);
    await waitFor(() => inspect(names.node).State.Running);
    const nodeIP = inspect(names.node).NetworkSettings.Networks.bridge.IPAddress;
    assert.ok(net.isIPv4(nodeIP));
    await writeFile(join(scratch, 'nginx.conf'), nginxConfig(`${nodeIP}:8000`));
    docker('start', names.ingress);
    phase = 'listener_readiness';
    await awaitReadiness(async () => ({
      vector_udp_listener: hasUdpListener(command('docker', ['exec', names.vector, 'cat', '/proc/net/udp'], { optional: true }).stdout ?? '', 12201),
      capture_tcp_listener: command('docker', ['exec', names.sink, 'nc', '-z', '-w', '1', '127.0.0.1', '8080'], { optional: true }).status === 0,
    }));
    phase = 'actual_compose_parity';
    const ingressMounts = [
      { type: 'bind', source: join(scratch, 'nginx.conf'), target: '/etc/nginx/nginx.conf', read_only: true },
      { type: 'bind', source: join(root, 'deploy/ingress/redacted-logging.conf'), target: '/etc/nginx/tc959-redacted.conf', read_only: true },
    ];
    for (const [service, name, networks, ports, mounts] of [[vectorService, names.vector, [names.logship], vectorPorts, []], [nodeService, names.node, ['bridge'], portMap(8000, nodePort), []], [ingressService, names.ingress, ['bridge'], portMap(80, ingressPort), ingressMounts]]) {
      const actual = inspect(name);
      assertServiceParity(service, actual, { networks, portBindings: ports, mounts });
      assert.equal(actual.Image, JSON.parse(docker('image', 'inspect', service.image))[0].Id);
      assert.equal(actual.RestartCount, 0);
      assert.equal(actual.Mounts.filter(mount => mount.Type === 'volume').length, 0, 'unlabelled_volume_forbidden');
    }
    const actualVector = inspect(names.vector);
    assert.equal(actualVector.Mounts.filter(mount => mount.Type !== 'tmpfs').length, 0);
    const runtime = docker('exec', names.vector, 'cat', '/var/lib/vector/runtime.json');
    assert.deepEqual(JSON.parse(runtime), config, 'actual_runtime_config_mismatch');
    const network = JSON.parse(docker('network', 'inspect', names.logship))[0];
    assert.equal(network.Internal, false);
    assert.equal(network.Driver, rendered.networks.logship.driver);
    assert.deepEqual(network.Options, {});
    assert.equal(network.Attachable, false);
    assert.equal(network.EnableIPv6, false);
    assert.deepEqual(Object.values(network.Containers).map(value => value.Name).sort(), [names.sink, names.vector].sort());
    report.compose_proof = true;
    phase = 'real_requests';
    await awaitReadiness(async () => {
      const probe = async port => { try { return await request(port, '/healthz'); } catch (error) { return { state: classifyProbeError(error) }; } };
      return { node_healthz: await probe(nodePort), ingress_healthz: await probe(ingressPort), vector_running: inspect(names.vector).State.Running, sink_running: inspect(names.sink).State.Running };
    });
    const appReadyAt = Date.now();
    assert.equal(await request(nodePort, '/version'), 200);
    assert.ok(await request(nodePort, '/invoke', 'POST') >= 400);
    assert.equal(await request(ingressPort, '/version'), 200);
    assert.ok(await request(ingressPort, '/invoke', 'POST') >= 400);
    await request(ingressPort, `/TC959_SYNTHETIC_PATH?ticket=${encodeURIComponent(canary)}`);
    await waitFor(() => { const events = capture().events; return events.some(e => e.event === 'node_request' && e.route === '/invoke' && e.status >= 400) && events.some(e => e.event === 'ingress_request' && e.status >= 400); });
    report.real_request_flow = true;
    phase = 'isolation';
    const ingressIP = inspect(names.ingress).NetworkSettings.Networks.bridge.IPAddress;
    const gateway = network.IPAM.Config[0].Gateway;
    docker('exec', names.vector, '/bin/sh', '-c', 'command -v nc');
    docker('exec', names.vector, 'nc', '-z', '-w', '2', names.sink, '8080');
    let reverseReachable = 0;
    for (const [address, port] of [[nodeIP, 8000], [ingressIP, 80], [gateway, nodePort], [gateway, ingressPort]]) {
      const probe = command('docker', ['exec', names.vector, 'nc', '-z', '-w', '2', address, String(port)], { optional: true });
      assert.equal(probe.error, undefined);
      if (probe.status === 0) reverseReachable++;
      assert.equal(inspect(names.vector).State.Running, true);
    }
    const gelf = latency_us => JSON.stringify({ version: '1.1', host: 'synthetic', short_message: JSON.stringify(nodeRequest({ method: 'GET', route: '/healthz', status: 503, latency_us })), '_tc.logship': 'tinycloud-node', timestamp: Date.now() / 1000 });
    const hostControl = 7654322;
    const peerControl = 7654323;
    const injected = 7654321;
    const udp = dgram.createSocket('udp4');
    try {
      await new Promise((resolve, reject) => udp.send(Buffer.from(gelf(hostControl)), 12201, '127.0.0.1', error => error ? reject(error) : resolve()));
    } finally { await new Promise(resolve => udp.close(resolve)); }
    await waitFor(() => capture().events.some(event => event.latency_us === hostControl));
    const shipperIP = actualVector.NetworkSettings.Networks[names.logship].IPAddress;
    docker('exec', names.sink, '/bin/sh', '-c', 'printf "%s" "$1" | nc -u -w 1 "$2" "$3"', 'probe', gelf(peerControl), shipperIP, '12201');
    await waitFor(() => capture().events.some(event => event.latency_us === peerControl));
    const appGateway = inspect(names.emitter).NetworkSettings.Networks.bridge.Gateway;
    docker('exec', names.emitter, '/bin/sh', '-c', 'command -v nc');
    for (const [address, port] of [[shipperIP, 12201], [appGateway, 12201]]) {
      const sent = command('docker', ['exec', names.emitter, '/bin/sh', '-c', 'printf "%s" "$1" | nc -u -w 1 "$2" "$3"', 'probe', gelf(injected), address, String(port)], { optional: true });
      assert.equal(sent.error, undefined);
      if (sent.status !== 0 && !/unreachable|refused|timed out/i.test(sent.stderr)) throw new Error('isolation_sender_failed');
    }
    await sleep(3000);
    assert.equal(capture().events.filter(event => event.latency_us === injected).length, 0);
    Object.assign(report, { blocked_injection_probes: 2, sender_positive_controls: 2, reverse_tcp_probes: 4, reverse_tcp_reachable: reverseReachable });
    const emit = payload => docker('exec', names.emitter, '/bin/sh', '-ec', 'printf "%s\\n" "$1" > /proc/1/fd/1', 'emit', payload);
    phase = 'profile_controls';
    const beforeFast = componentCounters(readMetrics(), 'request_profile').received_events;
    emit(JSON.stringify(nodeRequest({ route: '/healthz', status: 200, latency_us: fastMarker, authorization: canary, uri: canary, nested: { did: canary } })));
    // A subsequent eligible control confirms that the unpaced fast-success control traversed the driver.
    const slowMarker = 1000001;
    emit(JSON.stringify(nodeRequest({ route: '/healthz', status: 200, latency_us: slowMarker, authorization: canary })));
    await waitFor(() => capture().events.some(event => event.latency_us === slowMarker));
    await sleep(1500);
    assert.equal(capture().events.filter(event => event.latency_us === fastMarker).length, 0);
    const afterFast = componentCounters(readMetrics(), 'request_profile').received_events;
    assert.ok(Number.isFinite(beforeFast) && Number.isFinite(afterFast) && afterFast >= beforeFast + 2);
    report.fast_success_filtered = true;
    phase = 'healthy_burst';
    socketBefore = sockets();
    cpuBefore = cpu();
    startedAt = Date.now();
    sample();
    const payload = JSON.stringify(nodeRequest({ route: '/healthz', status: 503, latency_us: '__MARKER__', authorization: canary, uri: canary }));
    const [prefix, suffix] = payload.split('"__MARKER__"');
    // One exec; 500 distinct 503 lines, no sleeps, no pacing, no emission reduction.
    const emitted = docker('exec', names.emitter, '/bin/sh', '-ec', 'i=0; while [ "$i" -lt 500 ]; do printf "%s%s%s\\n" "$1" "$(($3+i))" "$2" || exit 71; i=$((i+1)); done > /proc/1/fd/1; printf "%s\\n" "$i" > /tmp/tc959-emitted-count; printf "%s\\n" "$i"', 'burst', prefix, suffix, String(burstFirst));
    assert.match(emitted, /^500$/);
    burstSent = Number(emitted);
    // Fixed bounded sampling persists the exact subset even if loss is static; never retry the burst.
    for (const offset of [0, 1000, 3000, 6000, 10000, 15000]) {
      const delay = offset - (Date.now() - startedAt);
      if (delay > 0) await sleep(delay);
      sample();
    }
    // Scope kernel/cgroup deltas to the healthy burst, before accepted outage-loss controls.
    socketAfterBurst = sockets();
    cpuAfterBurst = cpu();
    sample();
    report.healthy_burst_progress = progressEvidence(samples.slice());
    phase = 'continuity';
    docker('pause', names.vector);
    const continuityStart = Date.now();
    for (let index = 0; index < 30; index++) assert.equal(await request(nodePort, '/healthz'), 200);
    assert.ok(Date.now() - continuityStart < 15000);
    docker('unpause', names.vector);
    const resumeMarker = 7654324;
    emit(JSON.stringify(nodeRequest({ route: '/healthz', status: 503, latency_us: resumeMarker })));
    await waitFor(() => capture().events.some(event => event.latency_us === resumeMarker));
    report.continuity_requests = 30;
    report.resumed_delivery = true;
    phase = 'diagnostic_counts';
    const diagnostic = (level, message, target = 'tinycloud::runtime') => JSON.stringify({ timestamp: new Date().toISOString(), level, target, fields: { message, error: canary } });
    const total = (values, predicate, field) => values.filter(predicate).reduce((sum, value) => sum + value[field], 0);
    // Baselines account for real app startup diagnostics: count occurrences, never aggregate rows.
    // Drain startup's 60s/75s diagnostic reductions before measuring synthetic increments.
    const startupDrain = 80000 - (Date.now() - appReadyAt);
    if (startupDrain > 0) await sleep(startupDrain);
    const baseline = diagnosticCounts(capture().events);
    diagnosticBaseline = baseline;
    diagnosticInjected = { warn: 0, unclassified: 0, error: 0, dependency_error: 0, total: 0 };
    const emitDiagnostic = (control, level, message, target) => {
      emit(diagnostic(level, message, target));
      diagnosticInjected[control]++;
      diagnosticInjected.total++;
    };
    emitDiagnostic('warn', 'WARN', 'invalid link bind address; LAN listener not started');
    emitDiagnostic('warn', 'WARN', 'invalid link bind address; LAN listener not started');
    emitDiagnostic('unclassified', 'WARN', `raw tunnel close ${canary}`);
    emitDiagnostic('error', 'ERROR', 'native share KV put failed');
    emitDiagnostic('unclassified', 'WARN', undefined, 'hyper::proto');
    emitDiagnostic('dependency_error', 'ERROR', undefined, 'sqlx::pool');
    emit(JSON.stringify(nodeRequest({ route: `/signed/kv/${canary}`, status: 503 })));
    emit(`raw panic ${canary}`);
    sample();
    await waitFor(() => {
      const values = capture().events;
      const observed = diagnosticCounts(values);
      return Object.keys(diagnosticInjected).every(key => observed[key] >= baseline[key] + diagnosticInjected[key])
        && total(values, e => e.event === 'logship_gate_summary_total' && e.reason === 'invalid_fields', 'count') >= 1 && total(values, e => e.event === 'logship_gate_summary_total' && e.reason === 'non_json', 'count') >= 1;
    }, 180);
    const events = capture().events;
    const observed = diagnosticCounts(events);
    for (const key of Object.keys(diagnosticInjected)) assert.equal(observed[key] - baseline[key], diagnosticInjected[key]);
    Object.assign(report, { synthetic_warning_occurrences: diagnosticInjected.warn, unclassified_warning_occurrences: diagnosticInjected.unclassified, synthetic_error_occurrences: diagnosticInjected.error, dependency_error_occurrences: diagnosticInjected.dependency_error, synthetic_diagnostic_occurrences: diagnosticInjected.total });
    // Final gate is exact set equality. A duplicate cannot compensate for a missing marker.
    assertHealthyBurst(events, burstFirst, burstSize, burstSent);
    phase = 'completed';
    report.status = 'passed';
  } catch (error) {
    failure = error;
    report.failed_phase = phase;
    report.code = error.code === 'ERR_ASSERTION' ? 'assertion_failed' : ['deadline_cleanup_margin', 'readiness_timeout', 'proof_command_failed', 'isolation_sender_failed'].includes(error.message) ? error.message : 'unexpected_failure';
    if (error.diagnostics) report.probes = error.diagnostics;
  } finally {
    // Bounded diagnostics ALWAYS precede cleanup, including failed assertions and readiness failures.
    try {
      const vector = inspect(names.vector, true);
      if (vector?.State.Paused) command('docker', ['unpause', names.vector], { final: true, optional: true });
      if (samples.length < 3) { sample(); await sleep(1000); sample(); await sleep(1000); }
      report.evidence = await diagnostics();
      const evidence = report.evidence;
      if (evidence.capture.invalid || evidence.capture.canary_hits || evidence.capture.incomplete || (report.status === 'passed' && !evidence.capture.available)) {
        report.status = 'failed'; report.code = 'capture_boundary_failed'; failure ??= new Error('capture_boundary_failed');
      }
      if (report.status === 'passed') {
        for (const field of ['rmem_max', 'effective_so_rcvbuf', 'socket_drops']) assert.ok(Number.isSafeInteger(evidence.socket_before?.[field]));
        assert.ok(Object.hasOwn(evidence.cpu_before ?? {}, 'nr_throttled'));
        for (const measurement of [evidence.socket_after_healthy_burst, evidence.socket_after_all_controls]) for (const field of ['rmem_max', 'effective_so_rcvbuf', 'socket_drops']) assert.ok(Number.isSafeInteger(measurement?.[field]));
        assert.ok(Object.hasOwn(evidence.cpu_after_healthy_burst ?? {}, 'nr_throttled'));
        assert.ok(Object.hasOwn(evidence.cpu_after_all_controls, 'nr_throttled'));
        for (const key of ['source', 'gate', 'admitted', 'sink', 'capture']) assert.ok(Number.isFinite(evidence.progress.latest[key]));
        for (const value of Object.values(evidence.states)) {
          assert.equal(value.restart_count, 0);
          assert.equal(value.running, true);
          assert.equal(value.oom_killed, false);
        }
      }
    } catch {
      report.status = 'failed'; report.code = 'diagnostics_incomplete'; failure ??= new Error('diagnostics_incomplete');
    } finally {
      try { report.cleanup = cleanup(); } catch { report.status = 'failed'; report.code = 'owned_cleanup_incomplete'; failure ??= new Error('owned_cleanup_incomplete'); }
      await rm(scratch, { recursive: true, force: true });
    }
    process.stdout.write(`${JSON.stringify(report)}\n`);
  }
  if (failure) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(error => {
    const known = new Set(['invalid_arguments', 'explicit_go_required', 'invalid_deadline', 'disposable_hosted_runner_required', 'deadline_cleanup_margin', 'owned_cleanup_incomplete']);
    process.stdout.write(`${JSON.stringify({ status: 'failed', phase, code: known.has(error.message) ? error.message : 'proof_failed' })}\n`);
    process.exitCode = 1;
  });
}

import assert from 'node:assert/strict';

export const owner = 'tc959-n0';

/** Canonical `compose config` escapes dollars for reuse as Compose input. */
export function composeRuntimeValues(value) {
  if (typeof value === 'string') return value.replaceAll('$$', '$');
  if (Array.isArray(value)) return value.map(composeRuntimeValues);
  if (value !== null && typeof value === 'object') return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, composeRuntimeValues(item)]));
  return value;
}

/** Refuse local/self-hosted execution before touching the Docker daemon. */
export function assertHostedRunner(env) {
  if (env.GITHUB_ACTIONS !== 'true' || env.RUNNER_ENVIRONMENT !== 'github-hosted' || env.RUNNER_OS !== 'Linux'
    || !/^\d+$/.test(env.GITHUB_RUN_ID ?? '') || !/^\d+$/.test(env.GITHUB_RUN_ATTEMPT ?? '')
    || !/^\/home\/runner\/work\/_temp(?:\/|$)/.test(env.RUNNER_TEMP ?? '')) throw new Error('disposable_hosted_runner_required');
}

/** Validate the whole deletion set before the first mutation. Never accept images or foreign names. */
export function cleanupOwnedResources(resources, remove, runId) {
  assert.match(runId, /^[a-zA-Z0-9-]+$/);
  for (const value of resources) {
    assert.ok(['container', 'network', 'volume'].includes(value.kind));
    assert.ok(value.name.startsWith(`${owner}-${runId}-`));
    assert.equal(value.labels?.['tc959.owner'], owner);
    assert.equal(value.labels?.[owner], runId);
  }
  const result = { containers: 0, networks: 0, volumes: 0 };
  for (const kind of ['container', 'network', 'volume']) for (const value of resources.filter(value => value.kind === kind)) {
    remove(value);
    result[`${kind}s`]++;
  }
  return result;
}

/** Distinct existing safe timing values identify the complete controlled burst without new wire fields. */
export function burstEvidence(events, first, count) {
  const seen = new Map();
  for (const event of events) if (event?.event === 'node_request' && event.status === 429
    && Number.isSafeInteger(event.latency_us) && event.latency_us >= first && event.latency_us < first + count) {
    seen.set(event.latency_us, (seen.get(event.latency_us) ?? 0) + 1);
  }
  return { expected: count, received: [...seen.values()].reduce((sum, value) => sum + value, 0), unique: seen.size,
    missing: Array.from({ length: count }, (_, index) => first + index).filter(marker => !seen.has(marker)),
    duplicates: [...seen].filter(([, total]) => total > 1).sort(([a], [b]) => a - b).map(([marker, total]) => ({ marker, count: total })) };
}

/** Healthy controlled bursts have no observed loss, compensating duplicate, or unconfirmed emission. */
export function assertHealthyBurst(events, first, count, emitted) {
  const evidence = burstEvidence(events, first, count);
  assert.equal(emitted, count, 'burst_emission_unconfirmed');
  assert.equal(evidence.received, count, 'healthy_burst_loss_or_duplicate');
  assert.equal(evidence.unique, count, 'healthy_burst_missing');
  assert.equal(evidence.missing.length, 0);
  assert.equal(evidence.duplicates.length, 0);
  return evidence;
}

/** An observed plateau requires three timed, fully known, identical hop samples. It is not a root cause. */
export function progressEvidence(samples) {
  const keys = ['source', 'gate', 'admitted', 'sink', 'capture'];
  const first = samples[0];
  const latest = samples.at(-1);
  const deltas = Object.fromEntries(keys.map(key => [key, Number.isFinite(first?.[key]) && Number.isFinite(latest?.[key]) ? latest[key] - first[key] : null]));
  const isStatic = key => samples.length >= 3 && latest.elapsed_ms > samples.at(-3).elapsed_ms
    && samples.slice(-3).every(sample => Number.isFinite(sample[key]) && sample[key] === latest[key]);
  const plateaus = Object.fromEntries(keys.map(key => [key, isStatic(key)]));
  return { samples, latest, deltas, plateau: keys.every(key => plateaus[key]), plateaus, burst_plateau: isStatic('burst_capture') };
}

const bytes = value => {
  if (value === undefined) return 0;
  const match = /^(\d+)([kmg])?b?$/i.exec(String(value));
  assert.ok(match, 'unsupported_compose_memory_unit');
  return Number(match[1]) * 1024 ** ({ k: 1, m: 2, g: 3 }[match[2]?.toLowerCase()] ?? 0);
};

/** Compare actual Docker settings to the rendered service, not to a second handwritten deployment. */
export function assertServiceParity(service, value, { networks, portBindings, mounts = [] }) {
  const host = value.HostConfig;
  assert.equal(value.Config.Image, service.image);
  if (service.user !== undefined) assert.equal(value.Config.User, service.user);
  for (const [key, label] of Object.entries(service.labels ?? {})) assert.equal(value.Config.Labels[key], label);
  assert.equal(host.ReadonlyRootfs, service.read_only ?? false);
  assert.equal(host.Privileged, service.privileged ?? false);
  assert.equal(Boolean(host.Init), service.init ?? false);
  assert.deepEqual(host.CapDrop ?? [], service.cap_drop ?? []);
  assert.deepEqual(host.SecurityOpt ?? [], service.security_opt ?? []);
  assert.equal(host.Memory, bytes(service.mem_limit));
  assert.equal(host.MemorySwap, bytes(service.memswap_limit));
  assert.equal(host.NanoCpus, Math.round(Number(service.cpus ?? 0) * 1e9));
  assert.deepEqual(host.LogConfig, { Type: service.logging.driver, Config: service.logging.options ?? {} });
  assert.deepEqual(host.Tmpfs ?? {}, Object.fromEntries((service.tmpfs ?? []).map(item => {
    const separator = item.indexOf(':');
    return [item.slice(0, separator), item.slice(separator + 1)];
  })));
  assert.deepEqual(Object.keys(value.NetworkSettings.Networks).sort(), [...networks].sort());
  assert.deepEqual(host.PortBindings ?? {}, portBindings);
  assert.deepEqual(Object.fromEntries(Object.entries(value.NetworkSettings.Ports ?? {}).filter(([, bindings]) => bindings !== null)), portBindings);
  assert.deepEqual((value.Mounts ?? []).filter(mount => mount.Type !== 'tmpfs').map(mount => ({ type: mount.Type, source: mount.Source, target: mount.Destination, read_only: !mount.RW })).sort((a, b) => a.target.localeCompare(b.target)), [...mounts].sort((a, b) => a.target.localeCompare(b.target)));
  if (service.entrypoint) assert.deepEqual([...(value.Config.Entrypoint ?? []), ...(value.Config.Cmd ?? [])], [...service.entrypoint, ...(service.command ?? [])]);
  else if (service.command) assert.deepEqual(value.Config.Cmd, service.command);
  if (service.restart) assert.equal(host.RestartPolicy.Name, service.restart);
  if (service.environment) for (const [key, expected] of Object.entries(service.environment)) assert.ok(value.Config.Env.includes(`${key}=${expected}`), 'rendered_environment_mismatch');
}

/** Validate network semantics, including explicit defaults emitted by Compose. */
export function assertLogshipNetwork(value) {
  assert.equal(value.driver, 'bridge');
  assert.equal(value.internal ?? false, false);
  assert.equal(value.external ?? false, false);
  assert.equal(value.attachable ?? false, false);
  assert.equal(value.enable_ipv4 ?? true, true);
  assert.equal(value.enable_ipv6 ?? false, false);
  assert.deepEqual(value.driver_opts ?? {}, {});
  assert.deepEqual(value.labels ?? {}, {});
  const ipam = value.ipam ?? {};
  assert.equal(ipam.driver ?? 'default', 'default');
  assert.deepEqual(ipam.config ?? [], []);
  assert.deepEqual(ipam.options ?? {}, {});
  assert.ok(Object.keys(ipam).every(key => ['driver', 'config', 'options'].includes(key)));
  assert.ok(Object.keys(value).every(key => ['name', 'driver', 'internal', 'external', 'attachable', 'enable_ipv4', 'enable_ipv6', 'driver_opts', 'labels', 'ipam'].includes(key)));
}

/** ss skmem rb is the effective SO_RCVBUF, which Linux may double and kernel-cap. */
export function socketEvidence(text, rmemMax) {
  const number = value => /^\d+$/.test(value ?? '') ? Number(value) : null;
  return { requested_receive_buffer_bytes: 8388608, rmem_max: number(rmemMax.trim()),
    effective_so_rcvbuf: number(/(?:\(|,)rb(\d+)(?:,|\))/.exec(text)?.[1]),
    socket_drops: number(/(?:\(|,)d(\d+)\)/.exec(text)?.[1]) };
}

/** Numeric diagnostics only: raw Prometheus labels and text never leave this function. */
export function numericMetrics(text) {
  const names = ['buffer_events', 'buffer_byte_size', 'buffer_received_events_total', 'buffer_sent_events_total', 'buffer_discarded_events_total', 'buffer_discarded_bytes_total', 'buffer_send_duration_seconds_sum', 'buffer_send_duration_seconds_count', 'component_send_latency_seconds_sum', 'component_send_latency_seconds_count', 'component_errors_total', 'component_discarded_events_total', 'component_received_events_total', 'component_sent_events_total', 'component_received_event_bytes_total', 'component_sent_event_bytes_total', 'utilization'];
  const result = Object.fromEntries(names.map(name => [name, null]));
  for (const line of text.split('\n')) {
    const match = /^(?:vector_)?([a-z_]+)(?:\{[^}]*\})?\s+([0-9.eE+-]+)(?:\s|$)/.exec(line);
    if (!match || !Object.hasOwn(result, match[1])) continue;
    const value = Number(match[2]);
    if (Number.isFinite(value) && value >= 0) result[match[1]] = (result[match[1]] ?? 0) + value;
  }
  return result;
}

/** Fixed-code control totals count occurrences, not reduced output rows. */
export function diagnosticCounts(events) {
  const result = { warn: 0, unclassified: 0, error: 0, dependency_error: 0, total: 0 };
  for (const event of events) {
    if (!Number.isSafeInteger(event?.event_count) || event.event_count <= 0) continue;
    if (event.event === 'node_warning' || event.event === 'node_error') result.total += event.event_count;
    if (event.event === 'node_warning' && event.event_code === 'link_bind_invalid') result.warn += event.event_count;
    if (event.event === 'node_warning' && event.event_code === 'unclassified') result.unclassified += event.event_count;
    if (event.event === 'node_error' && event.event_code === 'share_native_kv_put_failed') result.error += event.event_count;
    if (event.event === 'node_error' && event.event_code === 'unclassified') result.dependency_error += event.event_count;
  }
  return result;
}

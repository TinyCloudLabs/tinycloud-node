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
  for (const event of events) if (event?.event === 'node_request' && event.status === 200
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

/**
 * Host network namespace UDP counters (TC-3741). The Docker daemon sends GELF to the published 127.0.0.1:12201,
 * which on a default daemon is a host-side docker-proxy socket in front of Vector's. Counting drops on every host
 * socket bound to the port, plus the kernel-wide Udp counters, locates loss that Vector's own socket cannot see.
 */
export function hostUdpEvidence(snmpText, udpTables, port) {
  const lines = snmpText.split('\n').filter(line => line.startsWith('Udp: '));
  const header = lines[0]?.split(/\s+/).slice(1) ?? [];
  const values = lines[1]?.split(/\s+/).slice(1) ?? [];
  const counter = name => {
    const value = values[header.indexOf(name)];
    return header.includes(name) && /^\d+$/.test(value ?? '') ? Number(value) : null;
  };
  const portHex = `:${port.toString(16).toUpperCase().padStart(4, '0')}`;
  let sockets = 0;
  let drops = 0;
  for (const table of udpTables) for (const line of table.split('\n').slice(1)) {
    const fields = line.trim().split(/\s+/);
    if (!fields[1]?.endsWith(portHex) || !/^\d+$/.test(fields.at(-1) ?? '')) continue;
    sockets++;
    drops += Number(fields.at(-1));
  }
  return { in_datagrams: counter('InDatagrams'), in_errors: counter('InErrors'), rcvbuf_errors: counter('RcvbufErrors'), sndbuf_errors: counter('SndbufErrors'),
    port_sockets: sockets, port_drops: sockets ? drops : null };
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

/**
 * The threshold member compose (TC-2224): `threshold-shares` mounts only in
 * `tinycloud` at the `threshold_share_dir` path, no ssh-gateway service
 * exists, and production declares and mounts no `threshold-shares` volume.
 */
export function assertThresholdMemberCompose(member, production, profilesOutput) {
  const share = 'threshold-shares';
  const target = '/var/lib/tinycloud/threshold';
  const memberServices = member.services ?? {};
  assert.equal(memberServices['ssh-gateway'], undefined, 'member_ssh_gateway_forbidden');
  assert.equal(profilesOutput.trim(), '', 'member_profiles_forbidden');
  assert.deepEqual(Object.keys(memberServices).sort(), ['postgres', 'tinycloud'], 'member_service_allowlist');
  const volumeEnds = (volume) => {
    if (typeof volume === 'string') {
      const [source, target] = volume.split(':');
      return { source, target };
    }
    return { type: volume?.type, source: volume?.source, target: volume?.target };
  };
  for (const service of Object.values(memberServices)) {
    assert.equal(service.profiles, undefined, 'member_profiles_forbidden');
  }
  const tinycloud = (memberServices.tinycloud?.volumes ?? []).map(volumeEnds).filter(ends => ends.target === target);
  assert.equal(tinycloud.length, 1, 'member_share_volume_mounted_once');
  assert.equal(tinycloud[0].type, 'volume', 'member_share_mount_must_be_a_named_volume');
  assert.equal(tinycloud[0].source, share, 'member_share_mount_source');
  assert.ok(Object.keys(member.volumes ?? {}).includes(share), 'member_share_volume_declared');
  // The render is --no-interpolate, so `$` survives into names and mount
  // paths: two names that differ literally can still resolve to the same
  // Docker volume at deploy. Refuse interpolation outright (TC-2224).
  for (const [name, service] of Object.entries(memberServices)) {
    const interpolated = (service.volumes ?? []).map(volumeEnds).find(ends => (ends.source ?? '').includes('$') || (ends.target ?? '').includes('$'));
    assert.equal(interpolated, undefined, `member_mount_interpolated_${name}`);
  }
  for (const [name, service] of Object.entries(memberServices)) {
    if (name === 'tinycloud') continue;
    // A non-tinycloud service may carry only the keys the reviewed postgres
    // render uses; every other key is refused, allowed or not (TC-2224).
    for (const key of Object.keys(service)) {
      assert.ok(['environment', 'healthcheck', 'image', 'networks', 'volumes'].includes(key), `member_key_not_allowed_in_${name}_${key}`);
    }
    const volumes = (service.volumes ?? []).map(volumeEnds);
    assert.equal(volumes.filter(ends => ends.source === share || ends.target === target).length, 0, `member_share_volume_mounted_in_${name}`);
    const socketMount = volumes.find(ends => ['bind', 'volume', undefined].includes(ends.type) && (ends.source === 'dstack.sock' || ends.target === 'dstack.sock' || ends.source === 'tappd.sock' || ends.target === 'tappd.sock'
      || (ends.source ?? '').endsWith('/dstack.sock') || (ends.target ?? '').endsWith('/dstack.sock')
      || (ends.source ?? '').endsWith('/tappd.sock') || (ends.target ?? '').endsWith('/tappd.sock')
      || ['/', '/var', '/run', '/var/run'].includes((ends.source ?? '').replace(/\/+$/, '') || '/')));
    assert.equal(socketMount, undefined, `member_dstack_socket_only_in_tinycloud_${name}`);
    const hostBind = volumes.find(ends => ends.type === 'bind' || /^(\/|\.|~)/.test(ends.source ?? ''));
    assert.equal(hostBind, undefined, `member_host_bind_mount_in_${name}`);
  }
  assert.deepEqual((memberServices.postgres?.volumes ?? []).map(volumeEnds), [{ type: 'volume', source: 'pgdata', target: '/var/lib/postgresql/data' }], 'member_postgres_volumes_allowlist');
  const dockerNames = Object.entries(member.volumes ?? {}).map(([key, definition]) => definition?.name ?? key);
  assert.equal(new Set(dockerNames).size, dockerNames.length, 'member_duplicate_volume_name');
  for (const [name, definition] of Object.entries(member.volumes ?? {})) {
    assert.ok(['pgdata', 'threshold-shares'].includes(name), `member_volumes_allowlist_${name}`);
    assert.equal(definition?.driver, undefined, `member_volume_option_forbidden_${name}`);
    assert.equal(definition?.driver_opts, undefined, `member_volume_option_forbidden_${name}`);
    assert.equal((definition?.name ?? '').includes('$'), false, `member_volume_name_interpolated_${name}`);
    assert.equal(definition?.external, undefined, `member_volume_option_forbidden_${name}`);
  }
  // D2-P3-1: only the render's own default network may exist or be used; an
  // external or driver-bridged network could carry member traffic off-CVM.
  for (const [name, definition] of Object.entries(member.networks ?? {})) {
    assert.equal(name, 'default', `member_networks_allowlist_${name}`);
    // Compose names the default network "<project>_default" from the
    // render's top-level `name`; pin it exactly and refuse any `$` or a
    // missing project name, so it can't alias an operator network.
    assert.ok(!`${member.name ?? ''}`.includes('$') && member.name && definition?.name === `${member.name}_default`, `member_network_name_forbidden_${name}`);
    assert.equal(definition?.external, undefined, `member_external_network_${name}`);
    assert.equal(definition?.driver, undefined, `member_network_option_forbidden_${name}`);
    assert.equal(definition?.driver_opts, undefined, `member_network_option_forbidden_${name}`);
  }
  for (const [name, service] of Object.entries(memberServices)) {
    const nets = service.networks ?? {};
    for (const net of (Array.isArray(nets) ? nets : Object.keys(nets))) {
      assert.equal(net, 'default', `member_network_not_allowed_in_${name}_${net}`);
    }
  }
  // `host` mode would publish the unauthenticated metrics port off-CVM.
  assert.equal(memberServices.tinycloud.network_mode, undefined, 'member_network_mode_forbidden_in_tinycloud');
  assert.ok(!Object.keys(production.volumes ?? {}).includes(share), 'production_share_volume_forbidden');
  for (const [name, service] of Object.entries(production.services ?? {})) {
    assert.equal((service?.volumes ?? []).map(volumeEnds).filter(ends => ends.source === share || ends.target === target).length, 0, `production_share_volume_mounted_in_${name}`);
  }
  assert.equal(memberServices.tinycloud.environment?.TINYCLOUD_ENCRYPTION_NETWORK__THRESHOLD_SHARE_DIR, target, 'member_threshold_share_dir_unset');
}

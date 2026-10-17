import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';
import { vectorTests, requestProfileTests } from '../log-shipper/cases.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const load = name => JSON.parse(readFileSync(resolve(root, 'log-shipper', name), 'utf8'));
export const nodeImage = 'ghcr.io/tinycloudlabs/tinycloud-node@sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f';
export const ingressImage = 'ghcr.io/tinycloudlabs/tinycloud-node-ingress@sha256:63c1c44e2ded5b73a5f174807b91ca677826974df0f9ab3045f6ec87865a5744';
export const vectorImage = 'timberio/vector:0.59.0-alpine@sha256:0e36bc2a290039e9b6a5e92f04bd2f133223506f72d09682c1df16c015172b7a';
const remap = (inputs, source, options = {}) => ({ type: 'remap', inputs, source, drop_on_error: true, drop_on_abort: true, ...options });
const aliases = {
  '/attestation?<nonce>': '/attestation',
  '/.well-known/encryption/network/<name>?<query..>': '/.well-known/encryption/network/<name>',
  '/hooks/events?<ticket>': '/hooks/events',
  '/hooks/webhooks?<query..>': '/hooks/webhooks',
  '/public/<space_id>/kv?<prefix>': '/public/<space_id>/kv',
};

/**
 * Compile each typed diagnostic into straight-line VRL: an exact (target,
 * message) match, its fixed level, then one check per declared field taken
 * from the schema. Any failure aborts the record; nothing undeclared is copied.
 */
function typedDiagnostics(diagnostics, fields) {
  const codes = fields.event_code.values;
  const untyped = new Set([...Object.keys(diagnostics.exact), ...Object.values(diagnostics.exact), ...Object.values(diagnostics.prefix)]);
  return Object.entries(diagnostics.typed).map(([message, { target, level, fields: names }]) => {
    if (!/^[a-z_]+$/.test(message) || !codes.includes(message) || untyped.has(message)) throw new TypeError(`typed diagnostic ${message} must be a distinct schema event code`);
    if (!/^tinycloud(_core)?(::[a-z_]+)*$/.test(target) || !['warn', 'error'].includes(level)) throw new TypeError(`typed diagnostic ${message} has an invalid target or level`);
    if (new Set(names).size !== names.length) throw new TypeError(`typed diagnostic ${message} repeats a field`);
    const checks = names.map(name => {
      const spec = fields[name];
      if (!/^[a-z_]+$/.test(name) || !spec) throw new TypeError(`typed diagnostic field ${name} is not in the schema`);
      const read = `v = get(f, [${JSON.stringify(name)}]) ?? null`;
      if (spec.type === 'integer' && Number.isSafeInteger(spec.min) && Number.isSafeInteger(spec.max)) {
        return `${read}\nif !is_integer(v) { abort }\nn = int!(v)\nif n < ${spec.min} || n > ${spec.max} { abort }\nout.${name} = n`;
      }
      if (spec.type === 'enum' && spec.values.every(value => /^[a-z_]+$/.test(value))) {
        return `${read}\nif !is_string(v) || !includes(${JSON.stringify(spec.values)}, v) { abort }\nout.${name} = string!(v)`;
      }
      if (spec.type === 'string' && /^\^[^'\\]*\$$/.test(spec.regex) && Number.isSafeInteger(spec.max_len)) {
        return `${read}\nif !is_string(v) { abort }\ns = string!(v)\nif length(s) > ${spec.max_len} || !match(s, r'${spec.regex}') { abort }\nout.${name} = s`;
      }
      throw new TypeError(`typed diagnostic field ${name} has no closed type`);
    });
    return [
      `if target == ${JSON.stringify(target)} && msg == ${JSON.stringify(message)} {`,
      '  typed = true',
      `  if level != ${JSON.stringify(level)} { abort }`,
      `  out = {"event": event, "svc": "api", "level": level, "event_code": ${JSON.stringify(message)}, "event_count": 1}`,
      ...checks.join('\n').split('\n').map(line => `  ${line}`),
      '}',
    ].join('\n');
  }).join('\n');
}

/** Compile one boundary for native tests, hosted Docker proof, and compose. */
export function buildConfig({ sinkUri = 'https://s2795437.us-west-2a.betterstackdata.com/', dataDir = '/var/lib/vector', sourceAddress = '0.0.0.0:12201', token, profile = 'errors_slow', slowThresholdUs = 1000000, runtimeProfile = false } = {}) {
  if (!['errors_slow', 'all_requests'].includes(profile)) throw new TypeError('invalid logship profile');
  if (!Number.isSafeInteger(slowThresholdUs) || slowThresholdUs < 0) throw new TypeError('invalid logship slow threshold');
  if (typeof runtimeProfile !== 'boolean') throw new TypeError('invalid runtime profile choice');
  const profileExpression = runtimeProfile ? '"${TINYCLOUD_LOGSHIP_PROFILE}"' : JSON.stringify(profile);
  const schema = load('fields.json').services['tinycloud-node'];
  const diagnostics = load('diagnostics.json');
  const typedCodes = JSON.stringify(Object.keys(diagnostics.typed));
  const typedSource = typedDiagnostics(diagnostics, schema.fields);
  // Function replacements: VRL regex literals contain `$'`, a replacement pattern.
  let sanitize = readFileSync(resolve(root, 'log-shipper/sanitize.vrl'), 'utf8')
    .replaceAll('__METHODS__', JSON.stringify(schema.fields.method.values))
    .replaceAll('__ROUTES__', JSON.stringify(schema.fields.route.values))
    .replace('__ROUTE_ALIASES__', JSON.stringify(aliases))
    .replace('__TYPED_DIAGNOSTICS__', () => typedSource)
    .replace('__DIAGNOSTICS__', JSON.stringify(diagnostics.exact))
    .replace('__PREFIX_DIAGNOSTICS__', Object.entries(diagnostics.prefix).sort(([a], [b]) => a.length - b.length).map(([prefix, code]) => `if starts_with(msg, ${JSON.stringify(prefix)}) { code = ${JSON.stringify(code)} }`).join('\n'));
  const config = {
    data_dir: dataDir,
    sources: { gelf_in: {
      type: 'socket', mode: 'udp', address: sourceAddress, max_length: 262144, receive_buffer_bytes: 8388608,
      framing: { method: 'chunked_gelf', chunked_gelf: { decompression: 'Auto' } }, decoding: { codec: 'bytes' },
    } },
    transforms: {
      // Parse GELF ourselves: native decoder errors can echo malformed values.
      gelf_envelope: remap(['gelf_in'], `packet = string(.message) ?? ""
if length(packet) > 262144 {
  . = {"reason": "oversized"}
} else {
  outer, err = parse_json(packet)
  if err != null || !is_object(outer) || (outer.version != "1.1" && outer.version != "1.0") {
    . = {"reason": "malformed_envelope"}
  } else if exists(outer.partial_message) || exists(outer._partial_message) {
    . = {"reason": "partial"}
  } else {
    label = get(outer, ["_tc.logship"]) ?? null
    . = {"_tc.logship": label, "message": outer.short_message}
  }
}`),
      logship_gate: remap(['gelf_envelope'], `if exists(.reason) {
  . = {"reason": .reason}
} else {
label = string(get(., ["_tc.logship"]) ?? null) ?? ""
raw = .message
reason = ""
if label == "" { reason = "unlabelled" }
else if !includes(["tinycloud-node", "tinycloud-ingress"], label) { reason = "unexpected_label" }
else if exists(.partial_message) { reason = "partial" }
else if !is_string(raw) { reason = "malformed_envelope" }
else if length(string!(raw)) > 65536 { reason = "oversized" }
if reason != "" {
  . = {"reason": reason}
} else {
  parsed, err = parse_json(string!(raw))
  if err != null || !is_object(parsed) { . = {"reason": "non_json"} }
  else if exists(parsed.partial_message) { . = {"reason": "partial"} }
  else {
    target = string(parsed.target) ?? ""
    level = downcase(string(parsed.level) ?? "")
    if label == "tinycloud-node" && !includes(["warn", "error"], level) && target != "tinycloud" && !starts_with(target, "tinycloud::") && target != "tinycloud_core" && !starts_with(target, "tinycloud_core::") {
      . = {"reason": "unknown_target"}
    } else if label == "tinycloud-node" && !includes(["warn", "error"], level) && (target != "tinycloud::request" || level != "info") {
      . = {"reason": "filtered_level"}
    } else { . = {"label": label, "parsed": parsed} }
  }
}
}`),
      gate_route: { type: 'route', inputs: ['logship_gate'], route: { candidate: 'exists(.parsed)', rejected: 'exists(.reason)' } },
      allowlist: remap(['gate_route.candidate'], sanitize, { reroute_dropped: true }),
      gate_counts: remap(['gate_route.rejected', 'gate_route._unmatched', 'allowlist.dropped', 'event_route._unmatched'], `reason = .reason
if !includes(${JSON.stringify(schema.fields.reason.values)}, reason) { reason = "invalid_fields" }
. = {"reason": reason, "count": 1}`),
      gate_reduce: { type: 'reduce', inputs: ['gate_counts'], group_by: ['reason'], end_every_period_ms: 60000, expire_after_ms: 75000, flush_period_ms: 1000, merge_strategies: { count: 'sum' } },
      gate_output: remap(['gate_reduce'], `. = {"ts": format_timestamp!(now(), format: "%Y-%m-%dT%H:%M:%S%.3fZ"), "level": "warn", "event": "logship_gate_summary_total", "svc": "logship", "reason": .reason, "count": .count}`),
      request_profile: { type: 'filter', inputs: ['allowlist'], condition: `${profileExpression} == "all_requests" || includes(["node_warning", "node_error"], .event) || (int(.status) ?? 0) >= 400 || (.event == "node_request" && (int(.latency_us) ?? 0) > ${slowThresholdUs}) || (.event == "ingress_request" && (to_float(.request_time_seconds) ?? 0.0) > ${(slowThresholdUs / 1000000).toFixed(6)})` },
      // Typed diagnostics keep their per-occurrence fields; only untyped codes are counted by reduction.
      event_route: { type: 'route', inputs: ['request_profile'], route: { request: '.event == "node_request" || .event == "ingress_request"', diagnostic: `(.event == "node_warning" || .event == "node_error") && !includes(${typedCodes}, .event_code)`, typed_diagnostic: `(.event == "node_warning" || .event == "node_error") && includes(${typedCodes}, .event_code)` } },
      diagnostic_reduce: { type: 'reduce', inputs: ['event_route.diagnostic'], group_by: ['event', 'event_code', 'level', 'svc'], end_every_period_ms: 60000, expire_after_ms: 75000, flush_period_ms: 1000, merge_strategies: { event_count: 'sum', ts: 'discard' } },
      diagnostic_output: remap(['diagnostic_reduce'], `. = {"ts": format_timestamp!(now(), format: "%Y-%m-%dT%H:%M:%S%.3fZ"), "level": .level, "event": .event, "svc": "api", "event_code": .event_code, "event_count": .event_count}`),
    },
    sinks: { betterstack: {
      type: 'http', inputs: ['event_route.request', 'event_route.typed_diagnostic', 'diagnostic_output', 'gate_output'], method: 'post', uri: sinkUri,
      encoding: { codec: 'json' }, framing: { method: 'newline_delimited' }, compression: 'gzip',
      auth: { strategy: 'bearer', token: token ?? 'SECRET[bs.bs_token]' },
      batch: { max_bytes: 262144, timeout_secs: 1 },
      buffer: { type: 'memory', max_events: 1000, when_full: 'block' },
      request: { timeout_secs: 10, retry_max_duration_secs: 300 },
      healthcheck: { enabled: false },
    } },
  };
  if (token === undefined) config.secret = { bs: { type: 'directory', path: `${dataDir}/secrets`, remove_trailing_whitespace: true } };
  return config;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [command, output, option, profileOption] = process.argv.slice(2);
  if (!['render-vector', 'render-tests'].includes(command) || !output) throw new Error('usage: tc959-logship.mjs render-tests OUTPUT [PROFILE] | render-vector OUTPUT [LOCAL_SINK_URI] [PROFILE]');
  const profile = (command === 'render-tests' ? option : profileOption) ?? 'errors_slow';
  const sinkUri = command === 'render-vector' ? option : undefined;
  const config = buildConfig({ profile, ...(sinkUri ? { sinkUri, token: 'tc959-synthetic-only' } : {}) });
  if (command === 'render-tests') {
    delete config.secret;
    config.sinks = { discard: { type: 'blackhole', inputs: config.sinks.betterstack.inputs } };
    config.tests = [...vectorTests, ...requestProfileTests(profile)];
  }
  writeFileSync(output, JSON.stringify(config, null, 2) + '\n');
}

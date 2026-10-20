// Synthetic inputs only. Native Vector evaluates every assertion after the full boundary.
export const canary = 'TC959_SYNTHETIC_Bearer_eyJhbGciOiJub25lIn0.email@example.test.did:pkh:0xdeadbeef';
export const timestamp = '2026-10-16T12:00:00.000Z';
export const nodeRequest = (fields = {}) => ({ timestamp, level: 'INFO', target: 'tinycloud::request', fields: { message: 'request', method: 'POST', route: '/invoke', status: 200, latency_us: 1234, ...fields } });
export const ingressRequest = (fields = {}) => ({ time: timestamp, method: 'GET', route: '/healthz', status: 200, request_time: 0.012, bytes: 2, upstream_status: '200', ...fields });
export const envelope = (value, label = 'tinycloud-node') => ({ message: typeof value === 'string' ? value : JSON.stringify(value), '_tc.logship': label, host: canary, full_message: canary, container_id: canary });
const safe = '!contains(encode_json(.), "TC959_SYNTHETIC") && !exists(.message) && !exists(.target) && !exists(.host) && !exists(.request_id) && !exists(.request_id_replaced) && !exists(.account_hash) && !exists(.space_hash)';
// Vector test log_fields keys are paths; quote the literal dotted GELF label.
const logFields = input => Object.fromEntries(Object.entries(input).map(([key, value]) => [key === '_tc.logship' ? '."_tc.logship"' : key, value]));
const check = (name, input, assertion, insertAt = 'logship_gate') => ({ name, inputs: [{ insert_at: insertAt, type: 'log', log_fields: logFields(input) }], outputs: [{ extract_from: 'allowlist', conditions: [{ type: 'vrl', source: `assert!(${assertion})\nassert!(${safe})` }] }] });
// Constant messages emitted by tinycloud-core migration m20261020_000000_current_kv_key_c_index (TC-1274); production logs drop the `event` field, so the exact text is the only key.
const currentKvCIndexMessages = {
  "missing": "idx_current_kv_space_deleted_key_c is missing; the node keeps serving and KV list requests are slower until an operator builds it with CREATE INDEX CONCURRENTLY (docs/releasing.md, section idx_current_kv_space_deleted_key_c)",
  "invalid": "idx_current_kv_space_deleted_key_c is invalid or still being built; the node keeps serving and KV list requests are slower. If no CREATE INDEX CONCURRENTLY is running, run DROP INDEX CONCURRENTLY idx_current_kv_space_deleted_key_c; and then the CREATE INDEX CONCURRENTLY in docs/releasing.md, section idx_current_kv_space_deleted_key_c",
  "wrong_shape": "idx_current_kv_space_deleted_key_c exists with the wrong definition and is not used for KV lists; the node keeps serving and KV list requests are slower. Run DROP INDEX CONCURRENTLY idx_current_kv_space_deleted_key_c; and then the CREATE INDEX CONCURRENTLY in docs/releasing.md, section idx_current_kv_space_deleted_key_c"
};
// Like check(), but the output may carry the validated N2 correlation fields; nothing else may leak.
const unsafeCorrelated = '!contains(encode_json(.), "TC959_SYNTHETIC") && !exists(.message) && !exists(.target) && !exists(.host)';
const correlated = (name, input, assertion) => ({ name, inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(input) }], outputs: [{ extract_from: 'allowlist', conditions: [{ type: 'vrl', source: `assert!(${assertion})\nassert!(${unsafeCorrelated})` }] }] });
const goodId = 'a8098c1a-f86e-4b1f-92a7-4b50b53ec932';
const goodHash = 'a'.repeat(64);
const goodSpace = '0123456789abcdef'.repeat(4);
const reject = (name, input, insertAt = 'logship_gate') => ({ name, inputs: [{ insert_at: insertAt, type: 'log', log_fields: logFields(input) }], no_outputs_from: ['allowlist'], outputs: [{ extract_from: 'gate_counts', conditions: [{ type: 'vrl', source: 'assert!(.count == 1)\nassert!(!contains(encode_json(.), "TC959_SYNTHETIC"))' }] }] });
export const vectorTests = [
  check('INFO node request validates as a safe individual event', envelope(nodeRequest()), '.event == "node_request" && .svc == "api" && .method == "POST" && .route == "/invoke" && .status == 200 && .latency_us == 1234'),
  check('unmatched request keeps fixed sentinel', envelope(nodeRequest({ route: '<unmatched>', status: 404, latency_us: 0 })), '.event == "node_request" && .route == "<unmatched>" && .status == 404 && .latency_us == 0'),
  check('HEAD is not rewritten to GET', envelope(nodeRequest({ method: 'HEAD' })), '.method == "HEAD"'),
  check('Rocket query template is normalized without values', envelope(nodeRequest({ route: '/attestation?<nonce>' })), '.route == "/attestation"'),
  check('ingress 3xx is a per-request event', envelope(ingressRequest({ status: 304 }), 'tinycloud-ingress'), '.event == "ingress_request" && .status == 304 && .request_time_seconds == 0.012'),
  check('ingress other is a fixed sentinel', envelope(ingressRequest({ route: '<other>', method: '<other>' }), 'tinycloud-ingress'), '.route == "<unmatched>" && .method == "<other>"'),
  check('long latency is not dropped by byte budget', envelope(nodeRequest({ route: '/policy/v3/deliveries/authorize', latency_us: 9007199254740991 })), '.latency_us == 9007199254740991 && .event == "node_request"'),
  ...['TRACE', 'CONNECT'].map(method => check(`${method} request uses the bounded other method`, envelope(nodeRequest({ method, route: '<unmatched>', status: 404 })), '.event == "node_request" && .method == "<other>" && .status == 404')),
  check('unknown extras are discarded', envelope({ ...nodeRequest({ authorization: canary, nested: { sql: canary }, unexpected: canary }), span: { account: canary }, spans: [{ request_id: canary }] }), '.event == "node_request" && !exists(.authorization) && !exists(.nested) && !exists(.unexpected) && !exists(.span)'),
  // TC-1482: /admin/stats is its own route label; only the route template and status ship.
  check('node /admin/stats ships as route plus status only', envelope(nodeRequest({ method: 'GET', route: '/admin/stats', status: 401, authorization: `Bearer ${canary}`, query: canary, uri: `/admin/stats?token=${canary}`, body: canary, address: canary })), '.event == "node_request" && .method == "GET" && .route == "/admin/stats" && .status == 401 && keys!(.) == ["event", "latency_us", "level", "method", "route", "status", "svc", "ts"]'),
  check('ingress /admin/stats ships as route plus status only', envelope(ingressRequest({ method: 'GET', route: '/admin/stats', status: 503, authorization: `Bearer ${canary}`, query: canary, uri: `/admin/stats?token=${canary}`, upstream_status: canary, body: canary, address: canary }), 'tinycloud-ingress'), '.event == "ingress_request" && .method == "GET" && .route == "/admin/stats" && .status == 503 && keys!(.) == ["event", "level", "method", "request_time_seconds", "route", "status", "svc", "ts"]'),
  reject('a query string or address in the route is rejected, never shipped', envelope(nodeRequest({ method: 'GET', route: `/admin/stats?token=${canary}`, status: 401 }))),
  correlated('valid N2 correlation fields pass through exactly', envelope({ ...nodeRequest({ request_id: goodId, request_id_replaced: true, account_hash: goodHash, space_hash: goodSpace }), span: { account: canary }, spans: [{ request_id: canary }] }), `.event == "node_request" && .request_id == "${goodId}" && .request_id_replaced == true && .account_hash == "${goodHash}" && .space_hash == "${goodSpace}" && !exists(.span) && !exists(.spans)`),
  correlated('absent hashes (no space on the request) stay absent', envelope(nodeRequest({ request_id: goodId, request_id_replaced: false })), `.event == "node_request" && .request_id == "${goodId}" && .request_id_replaced == false && !exists(.account_hash) && !exists(.space_hash)`),
  correlated('malformed correlation values are dropped but the request ships', envelope(nodeRequest({ request_id: 'not-a-uuid-TC959_SYNTHETIC', request_id_replaced: 'yes', account_hash: 'A'.repeat(64), space_hash: 'a'.repeat(63) })), '.event == "node_request" && .route == "/invoke" && !exists(.request_id) && !exists(.request_id_replaced) && !exists(.account_hash) && !exists(.space_hash)'),
  correlated('raw identifiers in hash fields are dropped', envelope(nodeRequest({ request_id: goodId, account_hash: 'did:pkh:eip155:1:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef', space_hash: 'tinycloud:pkh:eip155:1:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:default' })), `.event == "node_request" && .request_id == "${goodId}" && !exists(.account_hash) && !exists(.space_hash)`),
  correlated('uppercase request id is dropped', envelope(nodeRequest({ request_id: goodId.toUpperCase() })), '.event == "node_request" && !exists(.request_id)'),
  correlated('wrong-variant request id is dropped', envelope(nodeRequest({ request_id: 'a8098c1a-f86e-4b1f-c2a7-4b50b53ec932' })), '.event == "node_request" && !exists(.request_id)'),
  correlated('version 9 request id is dropped', envelope(nodeRequest({ request_id: 'a8098c1a-f86e-9b1f-92a7-4b50b53ec932' })), '.event == "node_request" && !exists(.request_id)'),
  // Anchor tests: a valid UUID or hash embedded in a longer raw string must be dropped whole; they fail if ^ or $ is removed.
  ...[['request_id', `${goodId}TC959_SYNTHETIC`], ['request_id', `TC959_SYNTHETIC${goodId}`], ['request_id', `${goodId}\n`], ['request_id', `${goodId}-${goodId}`]].map(([key, value], i) => correlated(`${key} #${i}: with a valid UUID embedded in a longer string is dropped (${value.length} chars)`, envelope(nodeRequest({ [key]: value })), `.event == "node_request" && !exists(.${key})`)),
  ...[['account_hash', `${goodHash}TC959_SYNTHETIC`], ['account_hash', `TC959_SYNTHETIC${goodHash}`], ['space_hash', `${goodSpace}0`], ['space_hash', `0${goodSpace}`], ['space_hash', `${goodSpace}\n`], ['space_hash', `${goodSpace}${goodSpace}`]].map(([key, value], i) => correlated(`${key} #${i}: with a valid 64-hex digest embedded in a longer string is dropped (${value.length} chars)`, envelope(nodeRequest({ [key]: value })), `.event == "node_request" && !exists(.${key})`)),
  correlated('a diagnostic cannot carry correlation fields', envelope({ timestamp, level: 'WARN', target: 'tinycloud::runtime', fields: { message: 'invalid link bind address; LAN listener not started', request_id: goodId, account_hash: goodHash, space_hash: goodHash } }), '.event == "node_warning" && !exists(.request_id) && !exists(.account_hash) && !exists(.space_hash)'),
  correlated('ingress rows never carry correlation fields', envelope(ingressRequest({ request_id: goodId, account_hash: goodHash, space_hash: goodHash }), 'tinycloud-ingress'), '.event == "ingress_request" && !exists(.request_id) && !exists(.account_hash) && !exists(.space_hash)'),
  check('known warning strips all free text', envelope({ timestamp, level: 'WARN', target: 'tinycloud::runtime', fields: { message: 'invalid link bind address; LAN listener not started', err: canary, bind: canary } }), '.event == "node_warning" && .event_code == "link_bind_invalid" && .event_count == 1'),
  check('unmatched warning becomes typed unclassified', envelope({ timestamp, level: 'WARN', target: 'tinycloud::tunnel::connection', fields: { message: canary, remote: canary } }), '.event == "node_warning" && .event_code == "unclassified" && .event_count == 1'),
  check('application error remains typed without error value', envelope({ timestamp, level: 'ERROR', target: 'tinycloud::share_email', fields: { message: 'native share KV put failed', failure: canary } }), '.event == "node_error" && .event_code == "share_native_kv_put_failed" && .event_count == 1'),
  ...[['SQL busy: lock wait', 'sql_busy_lock_wait'], ['SQL busy: hydration', 'sql_busy_hydration'], ['SQL busy: artifact transfer', 'sql_busy_artifact_transfer']].map(([message, code]) => check(`SQL busy warning maps to ${code} without its fields`, envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::sql::service', fields: { message, service: 'sql', error_class: 'sql_busy', stage: canary, bound_ms: 30000, waited_ms: 30001 } }), `.event == "node_warning" && .event_code == "${code}" && .event_count == 1`)),
  ...[['Request deadline exceeded', 'request_timeout'], ['Request completed after its deadline', 'deadline_overrun']].map(([message, code]) => check(`request deadline warning maps to ${code} without its fields`, envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::request_cancel', fields: { message, error_class: canary, stage: canary, deadline_ms: 55000 } }), `.event == "node_warning" && .event_code == "${code}" && .event_count == 1`)),
  check('hydration timeout warning maps to sql_hydration_timeout without its fields', envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::sql::service', fields: { message: 'Database hydration gave up loading its artifact', service: 'sql', error_class: canary, bound_ms: 600000 } }), '.event == "node_warning" && .event_code == "sql_hydration_timeout" && .event_count == 1'),
  ...[['Read audit wait expired', 'read_audit_busy'], ['Read audit batch slow', 'read_audit_batch_slow'], ['Read audit batch failed', 'read_audit_batch_failed'], ['Read audit drain stalled', 'read_audit_drain_stalled']].map(([message, code]) => check(`read-audit warning maps to ${code} without its fields`, envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::read_audit', fields: { message, error_class: canary, count: 3, queue_depth: 1024, in_flight_batch_age_ms: 30001, abandoned: 7 } }), `.event == "node_warning" && .event_code == "${code}" && .event_count == 1`)),
  ...[['missing', 'WARN', 'node_warning', 'current_kv_c_index_missing'], ['invalid', 'WARN', 'node_warning', 'current_kv_c_index_invalid'], ['wrong_shape', 'ERROR', 'node_error', 'current_kv_c_index_wrong_shape']].map(([key, level, event, code]) => check(`current_kv C index ${key} message maps to ${code} with only the fixed diagnostic keys`, envelope({ timestamp, level, target: 'tinycloud_core::migrations::m20261020_000000_current_kv_key_c_index', fields: { message: currentKvCIndexMessages[key], event: canary, index: canary, reason: canary } }), `.event == "${event}" && .event_code == "${code}" && .event_count == 1 && .level == "${level.toLowerCase()}" && keys(.) == ["event", "event_code", "event_count", "level", "svc", "ts"]`)),
  check('dependency warning is a fixed unclassified diagnostic', envelope({ timestamp, level: 'WARN', target: 'hyper::proto', fields: { message: canary, error: canary } }), '.event == "node_warning" && .event_code == "unclassified" && .event_count == 1'),
  check('dependency error without a message still counts', envelope({ timestamp, level: 'ERROR', target: 'sqlx::pool', fields: { error: canary } }), '.event == "node_error" && .event_code == "unclassified" && .event_count == 1'),
  check('warning without a target or fields still counts', envelope({ timestamp, level: 'WARN' }), '.event == "node_warning" && .event_code == "unclassified" && .event_count == 1'),
  check('dependency cannot borrow an internal diagnostic code', envelope({ timestamp, level: 'ERROR', target: 'dependency', fields: { message: 'native share KV put failed' } }), '.event == "node_error" && .event_code == "unclassified" && .event_count == 1'),
  check('request-target warning is not discarded as an INFO request', envelope({ timestamp, level: 'WARN', target: 'tinycloud::request', fields: { message: canary } }), '.event == "node_warning" && .event_code == "unclassified" && .event_count == 1'),
  reject('raw URI in route is rejected', envelope(nodeRequest({ route: `/signed/kv/${canary}` }))),
  reject('query value is not a template', envelope(nodeRequest({ route: `/attestation?nonce=${canary}` }))),
  reject('forbidden method is rejected', envelope(nodeRequest({ method: canary }))),
  ...[-1, 1.5, '200', 600].map(status => reject(`invalid status ${status}`, envelope(nodeRequest({ status })))),
  ...[-1, 0.5, '1234', null].map(latency_us => reject(`invalid latency ${latency_us}`, envelope(nodeRequest({ latency_us })))),
  reject('non-JSON panic is counted not claimed fatal', envelope(`thread main panicked: ${canary}`)),
  reject('nested method cannot escape', envelope(nodeRequest({ method: { token: canary } }))),
  reject('unlabelled line is rejected', { message: JSON.stringify(nodeRequest()) }),
  reject('unexpected label is rejected', envelope(nodeRequest(), canary)),
  ...['ptx-dev', 'ptx-dev-worker', 'ptx-batch'].map(label => reject(`${label} cannot enter the node pipeline`, envelope(nodeRequest(), label))),
  reject('typed ptx JSON cannot enter through a node label', envelope({ event: 'ptx_realtime_request', level: 'info', stage: canary, request_id: 'a8098c1a-f86e-4b1f-92a7-4b50b53ec932' })),
  reject('partial line is rejected', { ...envelope(nodeRequest()), partial_message: true }),
  reject('oversized uncapped input is counted', envelope(JSON.stringify({ ...nodeRequest(), extra: canary.repeat(2000) }))),
  reject('forged request target is rejected', envelope({ ...nodeRequest(), target: canary })),
  reject('bad ingress timing is rejected', envelope(ingressRequest({ request_time: canary }), 'tinycloud-ingress')),
  check('wire GELF metadata is discarded before inner request parsing', { message: JSON.stringify({ version: '1.1', host: canary, level: canary, full_message: canary, short_message: JSON.stringify(nodeRequest()), '_tc.logship': 'tinycloud-node' }) }, '.event == "node_request" && .latency_us == 1234', 'gelf_envelope'),
  reject('malformed outer GELF JSON is counted without decoder free text', { message: `{"version":"1.1","short_message":"${canary}` }, 'gelf_envelope'),
  reject('nested GELF short message cannot escape', { message: JSON.stringify({ version: '1.1', short_message: { token: canary }, '_tc.logship': 'tinycloud-node' }) }, 'gelf_envelope'),
  {
    name: 'warning reduction conserves both occurrences without relaying text',
    inputs: [1, 2].map(() => ({ insert_at: 'diagnostic_reduce', type: 'log', log_fields: { ts: timestamp, level: 'warn', event: 'node_warning', svc: 'api', event_code: 'unclassified', event_count: 1 } })),
    outputs: [{ extract_from: 'diagnostic_output', conditions: [{ type: 'vrl', source: 'assert!(.event_count == 2)\nassert!(.event_code == "unclassified")\nassert!(length(keys(.)) == 6)' }] }],
  },
  {
    name: 'gate reduction conserves rejected occurrences by fixed reason',
    inputs: [1, 2].map(() => ({ insert_at: 'gate_reduce', type: 'log', log_fields: { reason: 'non_json', count: 1 } })),
    outputs: [{ extract_from: 'gate_output', conditions: [{ type: 'vrl', source: 'assert!(.count == 2)\nassert!(.reason == "non_json")\nassert!(length(keys(.)) == 6)' }] }],
  },
];

/** Exercise the actual routed boundary, not just pre-profile sanitization. */
export function requestProfileTests(profile) {
  const requestCase = (name, payload, label, eligible) => {
    const node = label === 'tinycloud-node';
    const status = node ? payload.fields.status : payload.status;
    const timing = node ? `.latency_us == ${payload.fields.latency_us}` : `.request_time_seconds == ${payload.request_time}`;
    const fixture = { name: `${profile}: ${name}`, inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(payload, label)) }] };
    return profile === 'all_requests' || eligible
      ? { ...fixture, outputs: [{ extract_from: 'event_route.request', conditions: [{ type: 'vrl', source: `assert!(.status == ${status} && ${timing})\nassert!(${safe})` }] }] }
      : { ...fixture, no_outputs_from: ['event_route.request'] };
  };
  return [
    ...[
      ['node fast success', 200, 999999, false],
      ['node exact one second', 200, 1000000, false],
      ['node above one second', 200, 1000001, true],
      ['node status399 fast', 399, 0, false],
      ['node status400 fast', 400, 0, true],
      ['node error at one second', 503, 1000000, true],
    ].map(([name, status, latency_us, eligible]) => requestCase(name, nodeRequest({ status, latency_us }), 'tinycloud-node', eligible)),
    ...[
      ['ingress fast success', 200, 0.999999, false],
      ['ingress exact one second', 200, 1.0, false],
      ['ingress above one second', 200, 1.000001, true],
      ['ingress status399 fast', 399, 0, false],
      ['ingress status400 fast', 400, 0, true],
      ['ingress error at one second', 503, 1.0, true],
    ].map(([name, status, request_time, eligible]) => requestCase(name, ingressRequest({ status, request_time }), 'tinycloud-ingress', eligible)),
    ...['WARN', 'ERROR'].map(level => ({
      name: `${profile}: dependency ${level} always eligible`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope({ timestamp, level, target: 'dependency', fields: { message: canary, status: 200, latency_us: 0 } })) }],
      outputs: [{ extract_from: 'event_route.diagnostic', conditions: [{ type: 'vrl', source: `assert!(.event_count == 1 && .event_code == "unclassified")\nassert!(${safe})` }] }],
    })),
  ];
}

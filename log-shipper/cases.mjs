// Synthetic inputs only. Native Vector evaluates every assertion after the full boundary.
import { CAPPED_CLASSES } from './budget.mjs';
import { LEDGER_EVENTS, LEDGER_ERROR_KINDS, LEDGER_TARGETS, LEDGER_START_EVENT, LEDGER_START_TARGET, LEDGER_START_MESSAGE, LEDGER_START_FAILED_MESSAGE, LEDGER_START_FILES } from './ledger.mjs';
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
// TC-1840: the node's 5xx diagnostic line (target, message and fields as emitted by tinycloud-node). It ships
// as an individual event with exactly eight fields; any deviation falls back to the unclassified count.
const dbMessage = 'database failure answered with a 5xx';
export const dbFailure = (fields = {}, extra = {}) => ({ timestamp, level: 'WARN', target: 'tinycloud::request', ...extra, fields: { message: dbMessage, status: 503, code: 'sql_busy', service: 'sql', route: '/invoke', elapsed_ms: 30001, failure_kind: 'lock_wait', write_may_have_applied: false, db_hash: goodHash, ...fields } });
const dbShipped = ['code', 'db_hash', 'elapsed_ms', 'event', 'event_code', 'failure_kind', 'level', 'route', 'service', 'status', 'svc', 'ts', 'write_may_have_applied'];
const keysAre = names => `keys(.) == ${JSON.stringify(names)}`;
const dbFallback = (name, fields, extra) => check(name, envelope(dbFailure(fields, extra)), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(['event', 'event_code', 'event_count', 'level', 'svc', 'ts'])}`);
const dbCodes = ['unavailable_retryable', 'outcome_unknown', 'internal', 'sql_busy', 'request_timeout', 'read_audit_busy'];
const dbServices = ['sql', 'duckdb', 'kv', 'other'];
const dbKinds = ['pool_timeout', 'pool_closed', 'io', 'statement_timeout', 'serialization', 'connection_lost', 'artifact_changed', 'lock_wait', 'hydration', 'artifact_transfer', 'request_timeout', 'read_audit_busy', 'other'];
const reject = (name, input, insertAt = 'logship_gate') => ({ name, inputs: [{ insert_at: insertAt, type: 'log', log_fields: logFields(input) }], no_outputs_from: ['allowlist'], outputs: [{ extract_from: 'gate_counts', conditions: [{ type: 'vrl', source: 'assert!(.count == 1)\nassert!(!contains(encode_json(.), "TC959_SYNTHETIC"))' }] }] });
// TC-2917: the node's disk headroom line, one per local store every 5 minutes (target, message and fields as emitted
// by tinycloud-node, free_bytes rounded down to 64 MiB). It ships as an individual info event with exactly `store` and
// `free_bytes`; any deviation drops it.
export const storageHeadroom = (fields = {}, extra = {}) => ({ timestamp, level: 'INFO', target: 'tinycloud::disk_headroom', ...extra, fields: { message: 'storage headroom', store: 'sql', free_bytes: 7516192768, ...fields } });
const headroomShipped = ['event', 'free_bytes', 'level', 'store', 'svc', 'ts'];
const bootReindexMessages = {
  complete: 'delegation mode boot reindex complete',
  incomplete: 'delegation mode boot reindex incomplete; skipped rows remain unmarked and derive on read',
  lock_timeout: 'delegation mode boot reindex incomplete (lock timeout); remaining rows derive on read',
};
const bootCounts = {
  scanned: 123, reindexed_terminal: 4, marked_attenuable: 116, marked_invalid: 1,
  skipped_locked_pages: 0, skipped_decrypt_failed: 2, elapsed_ms: 50,
};
const bootSummary = (result, fields = {}, extra = {}) => ({
  timestamp, level: 'INFO', target: 'tinycloud_core::models::delegation_mode', ...extra,
  fields: { message: bootReindexMessages[result], ...bootCounts, ...fields },
});
const bootSummaryKeys = ['event', 'event_code', 'level', 'svc', 'ts', ...Object.keys(bootCounts)].sort();
// TC-3284: the deletion ledger's error lines as tinycloud-node emits them (target, level and fields). The message is
// the canary so a case fails if it is ever copied.
export const ledgerError = (event, fields = {}, extra = {}) => ({ timestamp, level: 'ERROR', target: LEDGER_TARGETS[event], ...extra, fields: { message: `deletion ledger failed ${canary}`, event, error_kind: 'io', ...fields } });
const ledgerShipped = ['error_kind', 'event', 'level', 'svc', 'ts'];
const ledgerUnclassified = `.event == "node_error" && .event_code == "unclassified" && .event_count == 1 && !exists(.error_kind) && ${keysAre(['event', 'event_code', 'event_count', 'level', 'svc', 'ts'])}`;
// Like reject(), and the drop is counted under exactly `reason`.
const rejectFor = (name, input, reason) => ({ name, inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(input) }], no_outputs_from: ['allowlist'], outputs: [{ extract_from: 'gate_counts', conditions: [{ type: 'vrl', source: `assert!(.count == 1 && .reason == "${reason}")\nassert!(!contains(encode_json(.), "TC959_SYNTHETIC"))` }] }] });
// TC-4177: the node's deletion ledger start line (`log_deletion_ledger_start`, tinycloud-node-server/src/lib.rs) and its
// failure variant, as the node emits them. `ledger_file` is LedgerFileState::as_str(); `newest_deleted_at` is `none` or the
// latest intent instant as written. Nothing here is an id, key path or file path.
const ledgerStartCounts = { bytes: 4096, operations: 12, key_entries: 40, committed: 10, aborted: 1 };
const ledgerStartNewest = '2026-11-23T08:15:30.123456789Z';
export const ledgerStart = (fields = {}, extra = {}) => ({ timestamp, level: 'INFO', target: LEDGER_START_TARGET, ...extra, fields: { message: LEDGER_START_MESSAGE, event: LEDGER_START_EVENT, ledger_file: 'present', ...ledgerStartCounts, newest_deleted_at: ledgerStartNewest, ...fields } });
export const ledgerStartFailed = (fields = {}, extra = {}) => ({ timestamp, level: 'INFO', target: LEDGER_START_TARGET, ...extra, fields: { message: LEDGER_START_FAILED_MESSAGE, event: LEDGER_START_EVENT, error_kind: 'io', ...fields } });
const ledgerStartShipped = ['aborted', 'bytes', 'committed', 'event', 'key_entries', 'ledger_file', 'level', 'newest_deleted_at', 'operations', 'svc', 'ts'];
const ledgerStartFailedShipped = ['error_kind', 'event', 'level', 'svc', 'ts'];
// TC-1843: per-window caps. Each capped class has its own route and `lua` cap transform. Events are injected at
// event_route (the post-sanitize shape) so the route and the cap both run. A Vector test condition is met by any one
// event, so exact membership is pinned by expected_event_count plus one condition per sequence number.
const capShapes = {
  node_request_5xx: n => ({ level: 'info', ts: timestamp, event: 'node_request', svc: 'api', method: 'POST', route: '/invoke', status: 503, latency_us: n }),
  ingress_request_5xx: n => ({ level: 'info', ts: timestamp, event: 'ingress_request', svc: 'ingress', method: 'GET', route: '/healthz', status: 502, request_time_seconds: n + 0.5 }),
  db_failure_5xx: n => ({ level: 'warn', ts: timestamp, event: 'node_warning', svc: 'api', event_code: 'db_failure_5xx', status: 503, code: 'sql_busy', service: 'sql', route: '/invoke', elapsed_ms: n, failure_kind: 'lock_wait', write_may_have_applied: false }),
  node_request_4xx: n => ({ level: 'info', ts: timestamp, event: 'node_request', svc: 'api', method: 'POST', route: '/invoke', status: 404, latency_us: n }),
  ingress_request_4xx: n => ({ level: 'info', ts: timestamp, event: 'ingress_request', svc: 'ingress', method: 'GET', route: '/healthz', status: 429, request_time_seconds: n + 0.5 }),
};
const capSeq = { node_request_5xx: n => `.latency_us == ${n}`, ingress_request_5xx: n => `.request_time_seconds == ${n}.5`, db_failure_5xx: n => `.elapsed_ms == ${n}`, node_request_4xx: n => `.latency_us == ${n}`, ingress_request_4xx: n => `.request_time_seconds == ${n}.5` };
const capNames = Object.keys(CAPPED_CLASSES);
const capOf = name => CAPPED_CLASSES[name].capPerMinute;
const uncappedCount = 5 * Math.max(...capNames.map(capOf));
const capOutput = (name, kept) => ({ extract_from: `cap_${name}`, expected_event_count: kept, conditions: Array.from({ length: kept }, (_, index) => ({ type: 'vrl', source: `assert!(${capSeq[name](index + 1)})` })) });
const inject = (name, count) => Array.from({ length: count }, (_, index) => ({ insert_at: 'event_route', type: 'log', log_fields: capShapes[name](index + 1) }));
const capCases = [
  ...capNames.flatMap(name => [['a single event', 1, 1], ['exactly the cap', capOf(name), capOf(name)], ['one over the cap', capOf(name) + 1, capOf(name)], ['five over the cap', capOf(name) + 5, capOf(name)]].map(([label, sent, kept]) => ({
    name: `cap: ${name}, ${label}: ${kept} of ${sent} ship, in order, with the same fields`,
    inputs: inject(name, sent),
    outputs: [capOutput(name, kept)],
    no_outputs_from: [...capNames.filter(other => other !== name).map(other => `cap_${other}`), 'event_route.request', 'event_route.diagnostic'],
  }))),
  {
    name: 'cap: the five classes are counted independently',
    inputs: capNames.flatMap(name => inject(name, capOf(name) + 3)),
    outputs: capNames.map(name => capOutput(name, capOf(name))),
  },
  {
    name: 'cap: request events below status 400 are never capped',
    inputs: Array.from({ length: uncappedCount }, (_, index) => ({ insert_at: 'event_route', type: 'log', log_fields: index % 2
      ? { level: 'info', ts: timestamp, event: 'node_request', svc: 'api', method: 'POST', route: '/invoke', status: [100, 200, 301, 399][index % 4], latency_us: index }
      : { level: 'info', ts: timestamp, event: 'ingress_request', svc: 'ingress', method: 'GET', route: '/healthz', status: [100, 200, 301, 399][index % 4], request_time_seconds: index + 0.5 } })),
    outputs: [{ extract_from: 'event_route.request', expected_event_count: uncappedCount }],
    no_outputs_from: capNames.map(name => `cap_${name}`),
  },
  {
    name: 'cap: aggregated diagnostics are never capped',
    inputs: Array.from({ length: uncappedCount }, (_, index) => ({ insert_at: 'event_route', type: 'log', log_fields: { level: 'warn', ts: timestamp, event: index % 2 ? 'node_warning' : 'node_error', svc: 'api', event_code: 'unclassified', event_count: 1 } })),
    outputs: [{ extract_from: 'event_route.diagnostic', expected_event_count: uncappedCount }],
    no_outputs_from: capNames.map(name => `cap_${name}`),
  },
  ...[['node_request', 'api', 'latency_us', 'node_request_4xx', 'node_request_5xx'], ['ingress_request', 'ingress', 'request_time_seconds', 'ingress_request_4xx', 'ingress_request_5xx']].map(([event, svc, timing, name4, name5]) => ({
    name: `cap: ${event} status 399 stays on the uncapped route, 400 and 499 take the 4xx cap, 500 and 599 the 5xx cap`,
    inputs: [399, 400, 499, 500, 599].map(status => ({ insert_at: 'event_route', type: 'log', log_fields: { level: 'info', ts: timestamp, event, svc, method: 'GET', route: '/healthz', status, [timing]: 1 } })),
    outputs: [
      { extract_from: 'event_route.request', expected_event_count: 1, conditions: [{ type: 'vrl', source: 'assert!(.status == 399)' }] },
      { extract_from: `cap_${name4}`, expected_event_count: 2, conditions: [{ type: 'vrl', source: 'assert!(.status == 400)' }, { type: 'vrl', source: 'assert!(.status == 499)' }] },
      { extract_from: `cap_${name5}`, expected_event_count: 2, conditions: [{ type: 'vrl', source: 'assert!(.status == 500)' }, { type: 'vrl', source: 'assert!(.status == 599)' }] },
    ],
    no_outputs_from: capNames.filter(other => ![name4, name5].includes(other)).map(other => `cap_${other}`),
  })),
];
const unclassifiedKeys = ['event', 'event_code', 'event_count', 'level', 'svc', 'ts'];
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
  // test-ruling: TC-3739 log-shipper/cases.mjs new cases only (2026-11-22)
  check('node request DB accounting ships as numbers within bounds', envelope(nodeRequest({ pool_wait_ms: 0.004, query_time_ms: 12.5, query_count: 9 })), '.event == "node_request" && .pool_wait_ms == 0.004 && .query_time_ms == 12.5 && .query_count == 9'),
  check('integral DB timings and the schema maxima still ship', envelope(nodeRequest({ pool_wait_ms: 0, query_time_ms: 86400000, query_count: 9007199254740991 })), '.event == "node_request" && .pool_wait_ms == 0.0 && .query_time_ms == 86400000.0 && .query_count == 9007199254740991'),
  check('out-of-bounds or mistyped DB accounting is dropped but the request ships', envelope(nodeRequest({ pool_wait_ms: -0.5, query_time_ms: '12.5', query_count: 1.5 })), '.event == "node_request" && .route == "/invoke" && !exists(.pool_wait_ms) && !exists(.query_time_ms) && !exists(.query_count)'),
  check('DB timings above the canonical maximum are dropped', envelope(nodeRequest({ pool_wait_ms: 86400000.5, query_time_ms: 1e12, query_count: -1 })), '.event == "node_request" && !exists(.pool_wait_ms) && !exists(.query_time_ms) && !exists(.query_count)'),
  ...[399, 400, 404, 499, 500, 503, 599].map(status => check(`DB accounting ships on status ${status} only below 400`, envelope(nodeRequest({ status, pool_wait_ms: 0.004, query_time_ms: 12.5, query_count: 9 })), status < 400
    ? `.event == "node_request" && .status == ${status} && .pool_wait_ms == 0.004 && .query_time_ms == 12.5 && .query_count == 9`
    : `.event == "node_request" && .status == ${status} && !exists(.pool_wait_ms) && !exists(.query_time_ms) && !exists(.query_count)`)),
  // test-ruling: TC-3834 log-shipper/cases.mjs new cases only (2026-11-24)
  ...[['db_timeout', 503], ['storage_io', 500], ['cutover_fence', 503], ['internal', 599]].map(([code, status]) => check(`a 5xx node request ships its error_code ${code}`, envelope(nodeRequest({ status, error_code: code })), `.event == "node_request" && .status == ${status} && .error_code == "${code}"`)),
  ...[200, 399, 400, 404, 499].map(status => check(`error_code is dropped on status ${status}`, envelope(nodeRequest({ status, error_code: 'db_error' })), `.event == "node_request" && .status == ${status} && !exists(.error_code)`)),
  check('free-text or unknown error_code is dropped but the 5xx request ships', envelope(nodeRequest({ status: 500, error_code: `SELECT secret FROM t ${canary}` })), '.event == "node_request" && .status == 500 && .route == "/invoke" && !exists(.error_code)'),
  ...['DB_ERROR', 'db_error ', 'unknown_code', 7].map(value => check(`error_code ${JSON.stringify(value)} outside the closed set is dropped`, envelope(nodeRequest({ status: 503, error_code: value })), '.event == "node_request" && .status == 503 && !exists(.error_code)')),
  ...[
    ['rocket::config::config', 'found value for deprecated config key `log`', 'rocket_deprecated_log_config'],
    ['rocket::launch', `Rocket has launched from http://127.0.0.1:8000/${canary}`, 'rocket_launched'],
    ['rocket::server', 'Rocket has launched from http://127.0.0.1:8000', 'unclassified'],
    ['tinycloud_core::db', 'delegation mode boot backfill failed; unmarked rows derive on read', 'delegation_mode_boot_backfill_failed'],
    ['tinycloud_core::models::delegation_mode', 'delegation mode boot reindex skipped rows that failed decryption; leaving unmarked for read-time fail-closed handling', 'delegation_mode_boot_reindex_decrypt_failed'],
  ].map(([target, message, code]) => check(`boot warning on ${target} maps to ${code}`, envelope({ timestamp, target, level: 'WARN', fields: { message, error: canary } }), `.event == "node_warning" && .event_code == "${code}" && .event_count == 1 && ${keysAre(['event', 'event_code', 'event_count', 'level', 'svc', 'ts'])}`)),
  ...[
    ['a negative count', { scanned: -1 }],
    ['a string count', { scanned: '123' }],
    ['a fractional count', { marked_invalid: 0.5 }],
    ['an oversized count', { scanned: 9007199254740992 }],
    ['a missing count', { marked_invalid: undefined }],
    ['an unexpected DID field', { did: canary }],
    ['an unlisted message', { message: canary }],
  ].map(([label, fields]) => rejectFor(`boot reindex with ${label} is dropped`, envelope(bootSummary('complete', fields)), 'invalid_fields')),
  rejectFor('boot reindex from a different node target is dropped', envelope(bootSummary('complete', {}, { target: 'tinycloud_core::db' })), 'filtered_level'),
  check('known warning strips all free text', envelope({ timestamp, level: 'WARN', target: 'tinycloud::runtime', fields: { message: 'invalid link bind address; LAN listener not started', err: canary, bind: canary } }), '.event == "node_warning" && .event_code == "link_bind_invalid" && .event_count == 1'),
  check('unmatched warning becomes typed unclassified', envelope({ timestamp, level: 'WARN', target: 'tinycloud::tunnel::connection', fields: { message: canary, remote: canary } }), '.event == "node_warning" && .event_code == "unclassified" && .event_count == 1'),
  check('application error remains typed without error value', envelope({ timestamp, level: 'ERROR', target: 'tinycloud::share_email', fields: { message: 'native share KV put failed', failure: canary } }), '.event == "node_error" && .event_code == "share_native_kv_put_failed" && .event_count == 1'),
  ...[['SQL busy: lock wait', 'sql_busy_lock_wait'], ['SQL busy: hydration', 'sql_busy_hydration'], ['SQL busy: artifact transfer', 'sql_busy_artifact_transfer']].map(([message, code]) => check(`SQL busy warning maps to ${code} without its fields`, envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::sql::service', fields: { message, service: 'sql', error_class: 'sql_busy', stage: canary, bound_ms: 30000, waited_ms: 30001 } }), `.event == "node_warning" && .event_code == "${code}" && .event_count == 1`)),
  ...[['Request deadline exceeded', 'request_timeout'], ['Request completed after its deadline', 'deadline_overrun']].map(([message, code]) => check(`request deadline warning maps to ${code} without its fields`, envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::request_cancel', fields: { message, error_class: canary, stage: canary, deadline_ms: 55000 } }), `.event == "node_warning" && .event_code == "${code}" && .event_count == 1`)),
  check('hydration timeout warning maps to sql_hydration_timeout without its fields', envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::sql::service', fields: { message: 'Database hydration gave up loading its artifact', service: 'sql', error_class: canary, bound_ms: 600000 } }), '.event == "node_warning" && .event_code == "sql_hydration_timeout" && .event_count == 1'),
  ...[['Read audit wait expired', 'read_audit_busy'], ['Read audit batch slow', 'read_audit_batch_slow'], ['Read audit batch failed', 'read_audit_batch_failed'], ['Read audit drain stalled', 'read_audit_drain_stalled']].map(([message, code]) => check(`read-audit warning maps to ${code} without its fields`, envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::read_audit', fields: { message, error_class: canary, count: 3, queue_depth: 1024, in_flight_batch_age_ms: 30001, abandoned: 7 } }), `.event == "node_warning" && .event_code == "${code}" && .event_count == 1`)),
  ...[['missing', 'WARN', 'node_warning', 'current_kv_c_index_missing'], ['invalid', 'WARN', 'node_warning', 'current_kv_c_index_invalid'], ['wrong_shape', 'ERROR', 'node_error', 'current_kv_c_index_wrong_shape']].map(([key, level, event, code]) => check(`current_kv C index ${key} message maps to ${code} with only the fixed diagnostic keys`, envelope({ timestamp, level, target: 'tinycloud_core::migrations::m20261020_000000_current_kv_key_c_index', fields: { message: currentKvCIndexMessages[key], event: canary, index: canary, reason: canary } }), `.event == "${event}" && .event_code == "${code}" && .event_count == 1 && .level == "${level.toLowerCase()}" && keys(.) == ["event", "event_code", "event_count", "level", "svc", "ts"]`)),
  // TC-2346: the node's operation-retry warnings (target tinycloud_core::db_pool). Like every classified diagnostic they ship the code and the count only; operation, error_class and the timings stay in the node's own log.
  ...[['retrying operation after a lost database connection', 'db_operation_retried'], ['not retrying operation: its first run took longer than the retry window to fail', 'db_operation_retry_skipped_slow']].map(([message, code]) => check(`operation retry warning maps to ${code} with only the fixed diagnostic keys`, envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::db_pool', fields: { message, operation: 'delegate', error_class: 'io', elapsed_ms: 10001, retry_window_ms: 10000, sql: canary } }), `.event == "node_warning" && .event_code == "${code}" && .event_count == 1 && .level == "warn" && keys(.) == ["event", "event_code", "event_count", "level", "svc", "ts"]`)),
  ...['retrying operation after a lost database connection: x', 'Retrying operation after a lost database connection', 'not retrying operation'].map(message => check(`operation retry warning near-miss "${message}" stays unclassified`, envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::db_pool', fields: { message, operation: 'delegate', error_class: 'io' } }), '.event == "node_warning" && .event_code == "unclassified" && .event_count == 1')),
  // TC-3284: every node warn/error message is mapped (coverage.test.mjs). A message-less line is named by its constant `event`
  // field only when diagnostics.json lists that event; its other fields and any unlisted event stay out.
  ...[['deletion ledger is locked by another process: waiting for it', 'WARN', 'node_warning', 'deletion_ledger_lock_wait'], ['Database artifact kept changing while it was read', 'WARN', 'node_warning', 'sql_artifact_changed_during_read'], ['purge ledger reconciliation failed; space traffic stays refused', 'ERROR', 'node_error', 'space_purge_reconcile_failed']].map(([message, level, event, code]) => check(`node message "${message}" maps to ${code} with only the fixed diagnostic keys`, envelope({ timestamp, level, target: 'tinycloud_core::x', fields: { message, event: canary, error: canary, lease_cid: canary } }), `.event == "${event}" && .event_code == "${code}" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`)),
  // TC-4190: the DuckDB cache cleanup warning (tinycloud-core/src/duckdb/database.rs) is named by its exact message and ships only the code.
  check('Database cache cleanup failed maps to duckdb_cache_cleanup_failed with only the fixed diagnostic keys', envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::duckdb::database', fields: { message: 'Database cache cleanup failed', event: 'duckdb_cache_cleanup_failed', path: canary } }), `.event == "node_warning" && .event_code == "duckdb_cache_cleanup_failed" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`),
  check('a near-miss of the DuckDB cache cleanup message stays unclassified', envelope({ timestamp, level: 'WARN', target: 'tinycloud_core::duckdb::database', fields: { message: 'Database cache cleanup failed: x', event: 'duckdb_cache_cleanup_failed' } }), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`),
  check('node format message maps by its constant prefix and drops the formatted value', envelope({ timestamp, level: 'WARN', target: 'tinycloud::node_control::key_provider', fields: { message: `created a new node identity at /data/${canary} (did:key:${canary})` } }), `.event == "node_warning" && .event_code == "node_identity_created" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`),
  ...['renewal_scheduler_lease_failed', 'session_retire_failed', 'did_resolution_refused'].map(name => check(`message-less node warning named by its listed event ${name} ships only the code`, envelope({ timestamp, level: 'WARN', target: 'tinycloud::renewal', fields: { event: name, lease_cid: canary, host: canary, reason: canary } }), `.event == "node_warning" && .event_code == "${name}" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`)),
  check('message-less node warning with an unlisted event stays unclassified', envelope({ timestamp, level: 'WARN', target: 'tinycloud::renewal', fields: { event: canary, lease_cid: canary } }), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`),
  check('a listed event does not name a line that has a message', envelope({ timestamp, level: 'WARN', target: 'tinycloud::renewal', fields: { message: canary, event: 'renewal_scheduler_lease_failed' } }), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`),
  check('a dependency cannot borrow a listed event name', envelope({ timestamp, level: 'WARN', target: 'dependency', fields: { event: 'session_retire_failed' } }), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`),
  check('node 5xx diagnostic ships exactly its eight fields as an individual event', envelope(dbFailure()), `.event == "node_warning" && .svc == "api" && .level == "warn" && .event_code == "db_failure_5xx" && .status == 503 && .code == "sql_busy" && .service == "sql" && .route == "/invoke" && .elapsed_ms == 30001 && .failure_kind == "lock_wait" && .write_may_have_applied == false && .db_hash == "${goodHash}" && !exists(.event_count) && ${keysAre(dbShipped)}`),
  check('node 5xx diagnostic without a database ships without db_hash', envelope(dbFailure({ db_hash: undefined, status: 500, code: 'internal', service: 'other', failure_kind: 'other' })), `.event_code == "db_failure_5xx" && .status == 500 && .code == "internal" && .service == "other" && .failure_kind == "other" && ${keysAre(dbShipped.filter(key => key !== 'db_hash'))}`),
  check('node 5xx diagnostic with an unknown outcome ships the write flag', envelope(dbFailure({ status: 500, code: 'outcome_unknown', write_may_have_applied: true })), `.event_code == "db_failure_5xx" && .status == 500 && .code == "outcome_unknown" && .write_may_have_applied == true && ${keysAre(dbShipped)}`),
  ...dbCodes.map(code => check(`node 5xx diagnostic ships code ${code}`, envelope(dbFailure({ code })), `.event_code == "db_failure_5xx" && .code == "${code}" && ${keysAre(dbShipped)}`)),
  ...dbServices.map(service => check(`node 5xx diagnostic ships service ${service}`, envelope(dbFailure({ service })), `.event_code == "db_failure_5xx" && .service == "${service}" && ${keysAre(dbShipped)}`)),
  ...dbKinds.map(failure_kind => check(`node 5xx diagnostic ships failure_kind ${failure_kind}`, envelope(dbFailure({ failure_kind })), `.event_code == "db_failure_5xx" && .failure_kind == "${failure_kind}" && ${keysAre(dbShipped)}`)),
  ...[[500, 0], [599, 9007199254740991]].map(([status, elapsed_ms]) => check(`node 5xx diagnostic ships status ${status} and elapsed_ms ${elapsed_ms}`, envelope(dbFailure({ status, elapsed_ms })), `.event_code == "db_failure_5xx" && .status == ${status} && .elapsed_ms == ${elapsed_ms} && ${keysAre(dbShipped)}`)),
  check('node 5xx diagnostic normalizes a Rocket query template like a request', envelope(dbFailure({ route: '/attestation?<nonce>' })), `.event_code == "db_failure_5xx" && .route == "/attestation" && ${keysAre(dbShipped)}`),
  check('node 5xx diagnostic ships a parameterized route template', envelope(dbFailure({ route: '/signed/kv/<ticket_id>' })), `.event_code == "db_failure_5xx" && .route == "/signed/kv/<ticket_id>" && ${keysAre(dbShipped)}`),
  check('node 5xx diagnostic discards span, spans and envelope extras', envelope({ ...dbFailure(), span: { account: canary, sql: canary }, spans: [{ request_id: canary }], filename: canary, thread_id: canary }), `.event_code == "db_failure_5xx" && ${keysAre(dbShipped)}`),
  dbFallback('node 5xx diagnostic with an unknown code falls back to unclassified', { code: 'sql_busy_but_new' }),
  dbFallback('node 5xx diagnostic with a free-text code falls back to unclassified', { code: canary }),
  dbFallback('node 5xx diagnostic with an uppercase code falls back to unclassified', { code: 'SQL_BUSY' }),
  dbFallback('node 5xx diagnostic with an unknown service falls back to unclassified', { service: 'postgres' }),
  dbFallback('node 5xx diagnostic with a free-text service falls back to unclassified', { service: canary }),
  dbFallback('node 5xx diagnostic with an unknown failure_kind falls back to unclassified', { failure_kind: 'lock_wait ' }),
  dbFallback('node 5xx diagnostic with a free-text failure_kind falls back to unclassified', { failure_kind: canary }),
  ...[['not a template', '/not-a-template'], ['raw URI', `/signed/kv/${canary}`], ['query value', `/invoke?token=${canary}`], ['empty', ''], ['over-long', `/${'x'.repeat(300)}`], ['not a string', null], ['object', { path: canary }]].map(([label, route]) => dbFallback(`node 5xx diagnostic with a route that is ${label} falls back to unclassified`, { route })),
  ...[['uppercase', 'A'.repeat(64)], ['63 chars', 'a'.repeat(63)], ['65 chars', 'a'.repeat(65)], ['trailing newline', `${goodHash}\n`], ['trailing text', `${goodHash}TC959_SYNTHETIC`], ['raw DID', 'did:pkh:eip155:1:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef'], ['raw database name', 'notes.db'], ['null', null], ['number', 7], ['boolean', true], ['object', { hash: goodHash }]].map(([label, db_hash]) => dbFallback(`node 5xx diagnostic with a db_hash that is ${label} falls back to unclassified`, { db_hash })),
  ...[['sql', canary], ['error', canary], ['space', 'tinycloud:pkh:eip155:1:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:default'], ['database', 'notes.db'], ['message_detail', canary], ['count', 3], ['empty', null]].map(([key, value]) => dbFallback(`node 5xx diagnostic with an extra ${key} field falls back to unclassified`, { [key]: value })),
  // Without db_hash the key count must be exactly eight: an extra key cannot ride along on the shorter line.
  ...[['sql', canary], ['space', 'tinycloud:pkh:eip155:1:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:default'], ['database', 'notes.db']].map(([key, value]) => dbFallback(`node 5xx diagnostic without db_hash and with an extra ${key} field falls back to unclassified`, { db_hash: undefined, [key]: value })),
  ...['status', 'code', 'service', 'route', 'elapsed_ms', 'failure_kind', 'write_may_have_applied'].map(key => dbFallback(`node 5xx diagnostic missing ${key} falls back to unclassified`, { [key]: undefined })),
  ...[['string', '503'], ['float', 503.5], ['below 5xx', 499], ['success', 200], ['above range', 600], ['null', null]].map(([label, status]) => dbFallback(`node 5xx diagnostic with a status that is ${label} falls back to unclassified`, { status })),
  ...[['negative', -1], ['string', '30001'], ['float', 1.5], ['above the safe integer range', 9007199254740992], ['null', null]].map(([label, elapsed_ms]) => dbFallback(`node 5xx diagnostic with an elapsed_ms that is ${label} falls back to unclassified`, { elapsed_ms })),
  ...[['string', 'false'], ['number', 0], ['null', null]].map(([label, write_may_have_applied]) => dbFallback(`node 5xx diagnostic with a write_may_have_applied that is ${label} falls back to unclassified`, { write_may_have_applied })),
  ...[['a suffix', `${dbMessage}: ${canary}`], ['a different case', dbMessage.toUpperCase()], ['free text', canary]].map(([label, message]) => dbFallback(`node 5xx diagnostic with a message that is ${label} falls back to unclassified`, { message })),
  dbFallback('node 5xx diagnostic on a dependency target falls back to unclassified', {}, { target: 'dependency' }),
  dbFallback('node 5xx diagnostic on another node target falls back to unclassified', {}, { target: 'tinycloud_core::request_cancel' }),
  check('node 5xx diagnostic at error level is a plain unclassified error', envelope(dbFailure({}, { level: 'ERROR' })), `.event == "node_error" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(['event', 'event_code', 'event_count', 'level', 'svc', 'ts'])}`),
  check('node 5xx diagnostic input with SQL, ids and message-like text in extra fields ships none of it', envelope({ ...dbFailure({ sql: `SELECT ${canary} FROM t`, error: canary, space_id: 'tinycloud:pkh:eip155:1:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef:default', db_name: 'notes.db', did: 'did:pkh:eip155:1:0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' }), span: { sql: canary } }), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(['event', 'event_code', 'event_count', 'level', 'svc', 'ts'])} && !contains(encode_json(.), "SELECT") && !contains(encode_json(.), "notes.db") && !contains(encode_json(.), "did:") && !contains(encode_json(.), "tinycloud:")`),
  reject('node 5xx diagnostic at info level is not an individual event', envelope(dbFailure({}, { level: 'INFO' }))),
  check('disk headroom ships exactly store and free_bytes as an individual info event', envelope(storageHeadroom()), `.event == "node_storage_headroom" && .svc == "api" && .level == "info" && .store == "sql" && .free_bytes == 7516192768 && ${keysAre(headroomShipped)}`),
  ...['sql', 'duckdb'].map(store => check(`disk headroom ships store ${store}`, envelope(storageHeadroom({ store })), `.event == "node_storage_headroom" && .store == "${store}" && ${keysAre(headroomShipped)}`)),
  ...[0, 67108864, 9007199187632128].map(free_bytes => check(`disk headroom ships free_bytes ${free_bytes}`, envelope(storageHeadroom({ free_bytes })), `.event == "node_storage_headroom" && .free_bytes == ${free_bytes} && ${keysAre(headroomShipped)}`)),
  check('disk headroom discards span, spans and envelope extras', envelope({ ...storageHeadroom(), span: { path: canary }, spans: [{ request_id: canary }], filename: canary, thread_id: canary }), `.event == "node_storage_headroom" && ${keysAre(headroomShipped)}`),
  ...[['an unknown store', { store: 'blocks' }], ['a free-text store', { store: canary }], ['a path as store', { store: '/app/data/sql' }], ['a missing store', { store: undefined }], ['negative free_bytes', { free_bytes: -1 }], ['free_bytes above the safe integer range', { free_bytes: 9007199254740992 }], ['free_bytes not a whole 64 MiB step', { free_bytes: 7516192769 }], ['the largest safe integer as free_bytes', { free_bytes: 9007199254740991 }], ['string free_bytes', { free_bytes: '7516192768' }], ['float free_bytes', { free_bytes: 1.5 }], ['missing free_bytes', { free_bytes: undefined }], ['an extra path field', { path: canary }], ['an extra error field', { error: canary }], ['a message with a suffix', { message: `storage headroom: ${canary}` }], ['a message in a different case', { message: 'Storage headroom' }]].map(([label, fields]) => rejectFor(`disk headroom with ${label} is dropped, never shipped`, envelope(storageHeadroom(fields)), 'invalid_fields')),
  ...['tinycloud::request', 'tinycloud::storage', 'tinycloud::disk_headroom_x', 'tinycloud::disk_headroom::sub', 'tinycloud::disk'].map(target => rejectFor(`disk headroom on target ${target} is dropped at the gate`, envelope(storageHeadroom({}, { target })), target === 'tinycloud::request' ? 'invalid_fields' : 'filtered_level')),
  rejectFor('an unrelated info line on the headroom target is dropped', envelope(storageHeadroom({ message: canary, store: undefined, free_bytes: undefined })), 'invalid_fields'),
  check('disk headroom at warn level is a plain unclassified warning', envelope(storageHeadroom({}, { level: 'WARN' })), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(['event', 'event_code', 'event_count', 'level', 'svc', 'ts'])}`),
  // TC-3284: the deletion ledger's error events.
  ...LEDGER_EVENTS.map(event => check(`${event} ships as an individual error with exactly its error_kind`, envelope(ledgerError(event)), `.event == "${event}" && .svc == "api" && .level == "error" && .error_kind == "io" && ${keysAre(ledgerShipped)}`)),
  ...LEDGER_EVENTS.flatMap(event => LEDGER_ERROR_KINDS.map(kind => check(`${event} ships error_kind ${kind}`, envelope(ledgerError(event, { error_kind: kind })), `.event == "${event}" && .error_kind == "${kind}" && ${keysAre(ledgerShipped)}`))),
  ...LEDGER_EVENTS.flatMap(event => [
    ['an unlisted kind', { error_kind: 'xyz' }], ['a lock_wait kind', { error_kind: 'lock_wait' }], ['a path as kind', { error_kind: '/app/data/deletion-ledger.jsonl' }],
    ['a free-text kind', { error_kind: canary }], ['an upper-case kind', { error_kind: 'IO' }], ['a numeric kind', { error_kind: 7 }], ['a missing kind', { error_kind: undefined }],
    ['an extra path field', { path: '/app/data/deletion-ledger.jsonl' }], ['an extra lock_wait field', { lock_wait: 60 }], ['a missing message', { message: undefined }],
  ].map(([label, fields]) => check(`${event} with ${label} is never shipped as a ledger event`, envelope(ledgerError(event, fields)), ledgerUnclassified))),
  ...LEDGER_EVENTS.map(event => check(`${event} at warn level is a plain unclassified warning`, envelope(ledgerError(event, {}, { level: 'WARN' })), `.event == "node_warning" && .event_code == "unclassified" && !exists(.error_kind) && ${keysAre(['event', 'event_code', 'event_count', 'level', 'svc', 'ts'])}`)),
  ...LEDGER_EVENTS.flatMap(event => ['tinycloud::request', 'tinycloud_core', 'tinycloud_core::encryption_network', LEDGER_TARGETS[event] === 'tinycloud' ? 'tinycloud_core::encryption_network::deletion_ledger' : 'tinycloud'].map(target => check(`${event} from target ${target} is never shipped as a ledger event`, envelope(ledgerError(event, {}, { target })), ledgerUnclassified))),
  check('a dependency cannot borrow a ledger event name', envelope(ledgerError('deletion_ledger_open_failed', {}, { target: 'dependency' })), ledgerUnclassified),
  // TC-4177: the deletion ledger's one line per start ships as an individual info event with its counts. Each case below
  // runs the node's own line (target `tinycloud`, message and fields as `log_deletion_ledger_start` emits them).
  ...LEDGER_START_FILES.map(file => check(`${LEDGER_START_EVENT} with a ${file} ledger file ships its file state, counts and newest instant`, envelope(ledgerStart({ ledger_file: file })), `.event == "${LEDGER_START_EVENT}" && .svc == "api" && .level == "info" && .ledger_file == "${file}" && ${Object.entries(ledgerStartCounts).map(([key, value]) => `.${key} == ${value}`).join(' && ')} && .newest_deleted_at == "${ledgerStartNewest}" && ${keysAre(ledgerStartShipped)}`)),
  check(`${LEDGER_START_EVENT} for an empty ledger ships zero counts and no newest instant`, envelope(ledgerStart({ ledger_file: 'empty', bytes: 0, operations: 0, key_entries: 0, committed: 0, aborted: 0, newest_deleted_at: 'none' })), `.event == "${LEDGER_START_EVENT}" && .ledger_file == "empty" && .bytes == 0 && .operations == 0 && .key_entries == 0 && .committed == 0 && .aborted == 0 && .newest_deleted_at == "none" && ${keysAre(ledgerStartShipped)}`),
  check(`${LEDGER_START_EVENT} ships the largest count the schema allows`, envelope(ledgerStart({ operations: 9007199254740991 })), `.event == "${LEDGER_START_EVENT}" && .operations == 9007199254740991 && ${keysAre(ledgerStartShipped)}`),
  ...['2026-11-23T08:15:30Z', '2026-11-23T08:15:30.5Z', '2026-11-23T08:15:30.123456789+01:00', '2026-11-23t08:15:30-05:30'].map(instant => check(`${LEDGER_START_EVENT} ships the newest instant ${instant} as written`, envelope(ledgerStart({ newest_deleted_at: instant })), `.event == "${LEDGER_START_EVENT}" && .newest_deleted_at == "${instant}" && ${keysAre(ledgerStartShipped)}`)),
  check(`${LEDGER_START_EVENT} failure variant ships only its fixed error_kind`, envelope(ledgerStartFailed()), `.event == "${LEDGER_START_EVENT}" && .svc == "api" && .level == "info" && .error_kind == "io" && ${keysAre(ledgerStartFailedShipped)}`),
  ...LEDGER_ERROR_KINDS.map(kind => check(`${LEDGER_START_EVENT} failure variant ships error_kind ${kind}`, envelope(ledgerStartFailed({ error_kind: kind })), `.event == "${LEDGER_START_EVENT}" && .error_kind == "${kind}" && ${keysAre(ledgerStartFailedShipped)}`)),
  ...[
    ['a negative count', { bytes: -1 }], ['a string count', { operations: '12' }], ['a fractional count', { key_entries: 0.5 }],
    ['an oversized count', { committed: 9007199254740992 }], ['a null count', { aborted: null }], ['a missing count', { aborted: undefined }],
    ['an unlisted file state', { ledger_file: 'lost' }], ['an upper-case file state', { ledger_file: 'PRESENT' }], ['a free-text file state', { ledger_file: canary }], ['a missing file state', { ledger_file: undefined }],
    ['a free-text newest instant', { newest_deleted_at: canary }], ['an empty newest instant', { newest_deleted_at: '' }], ['a date-only newest instant', { newest_deleted_at: '2026-11-23' }],
    ['a newest instant with trailing text', { newest_deleted_at: `2026-11-23T08:15:30Z ${canary}` }], ['a numeric newest instant', { newest_deleted_at: 20261123 }], ['a missing newest instant', { newest_deleted_at: undefined }],
    ['an extra path field', { path: '/var/lib/tinycloud/ledger/deletions.jsonl' }], ['an extra key field', { key: canary }], ['a torn_tail field', { torn_tail: false }],
    ['an unlisted message', { message: canary }], ['a missing message', { message: undefined }], ['the failure message with the counts', { message: LEDGER_START_FAILED_MESSAGE }],
    ['a different event name', { event: 'deletion_ledger_opened' }],
  ].map(([label, fields]) => rejectFor(`${LEDGER_START_EVENT} with ${label} is dropped`, envelope(ledgerStart(fields)), 'event' in fields ? 'filtered_level' : 'invalid_fields')),
  ...[
    ['an unlisted kind', { error_kind: 'xyz' }], ['a path as kind', { error_kind: '/var/lib/tinycloud/ledger/deletions.jsonl' }], ['a free-text kind', { error_kind: canary }],
    ['a missing kind', { error_kind: undefined }], ['an extra count field', { bytes: 4096 }], ['an unlisted message', { message: canary }], ['the success message', { message: LEDGER_START_MESSAGE }],
  ].map(([label, fields]) => rejectFor(`${LEDGER_START_EVENT} failure variant with ${label} is dropped`, envelope(ledgerStartFailed(fields)), 'invalid_fields')),
  ...[
    ['tinycloud::request', 'invalid_fields'], ['tinycloud::disk_headroom', 'invalid_fields'], ['tinycloud::runtime', 'filtered_level'], ['tinycloud_core', 'filtered_level'],
    ['tinycloud_core::encryption_network::deletion_ledger', 'filtered_level'], ['tinycloud_core::models::delegation_mode', 'invalid_fields'], ['dependency', 'unknown_target'],
  ].map(([target, reason]) => rejectFor(`${LEDGER_START_EVENT} from target ${target} is never shipped as the start event`, envelope(ledgerStart({}, { target })), reason)),
  ...[['an unrelated info line on the node target', { message: canary, event: undefined, ledger_file: undefined, bytes: undefined, operations: undefined, key_entries: undefined, committed: undefined, aborted: undefined, newest_deleted_at: undefined }], ['an info line naming another ledger event', { event: 'deletion_ledger_open_failed' }], ['an info line naming no event', { event: undefined }]]
    .map(([label, fields]) => rejectFor(`${label} on target tinycloud is dropped at the gate`, envelope(ledgerStart(fields)), 'filtered_level')),
  check(`${LEDGER_START_EVENT} at warn level is a plain unclassified warning`, envelope(ledgerStart({}, { level: 'WARN' })), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && !exists(.bytes) && !exists(.ledger_file) && ${keysAre(unclassifiedKeys)}`),
  check(`${LEDGER_START_EVENT} at error level is a plain unclassified error`, envelope(ledgerStart({}, { level: 'ERROR' })), `.event == "node_error" && .event_code == "unclassified" && .event_count == 1 && !exists(.bytes) && ${keysAre(unclassifiedKeys)}`),
  check(`a dependency cannot borrow the ${LEDGER_START_EVENT} event`, envelope(ledgerStart({}, { target: 'dependency', level: 'WARN' })), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`),
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
  ...capCases,
  // TC-1843: `errors_dropped` is built only by the cap transforms' timers from literals and a counter. No node log line,
  // request field or extra key can produce it or any of its fields.
  ...['errors_dropped', 'errors_dropped class=node_request_5xx dropped=7 window_s=60'].map(message => check(`node warning with the message "${message}" is an unclassified count, not a dropped-count event`, envelope({ timestamp, level: 'WARN', target: 'tinycloud::request', fields: { message } }), `.event == "node_warning" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(unclassifiedKeys)}`)),
  ...[['WARN', 'node_warning'], ['ERROR', 'node_error']].map(([level, event]) => check(`node ${level} line carrying errors_dropped fields ships none of them`, envelope({ timestamp, level, target: 'tinycloud::request', fields: { message: canary, event_code: 'errors_dropped', class: 'node_request_5xx', dropped: 7, window_s: 60 } }), `.event == "${event}" && .event_code == "unclassified" && .event_count == 1 && ${keysAre(unclassifiedKeys)} && !exists(.class) && !exists(.dropped) && !exists(.window_s)`)),
  check('node request carrying errors_dropped fields ships none of them', envelope(nodeRequest({ status: 503, event_code: 'errors_dropped', class: 'node_request_5xx', dropped: 7, window_s: 60 })), `.event == "node_request" && .status == 503 && ${keysAre(['event', 'latency_us', 'level', 'method', 'route', 'status', 'svc', 'ts'])}`),
  check('ingress request carrying errors_dropped fields ships none of them', envelope(ingressRequest({ status: 502, event_code: 'errors_dropped', class: 'ingress_request_5xx', dropped: 7, window_s: 60 }), 'tinycloud-ingress'), `.event == "ingress_request" && .status == 502 && ${keysAre(['event', 'level', 'method', 'request_time_seconds', 'route', 'status', 'svc', 'ts'])}`),
  ...[['dropped', 3], ['class', 'node_request_5xx'], ['window_s', 60]].map(([key, value]) => dbFallback(`node 5xx diagnostic with an extra ${key} field falls back to unclassified, never a dropped-count event`, { [key]: value })),
];

/** Exercise the actual routed boundary, not just pre-profile sanitization. */
export function requestProfileTests(profile) {
  const requestCase = (name, payload, label, eligible) => {
    const node = label === 'tinycloud-node';
    const status = node ? payload.fields.status : payload.status;
    const timing = node ? `.latency_us == ${payload.fields.latency_us}` : `.request_time_seconds == ${payload.request_time}`;
    const fixture = { name: `${profile}: ${name}`, inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(payload, label)) }] };
    // Status >= 500 and status 400-499 request events take their capped class route (TC-1843); lower statuses stay on `request`.
    const route = status >= 500 ? `event_route.${node ? 'node' : 'ingress'}_request_5xx` : status >= 400 ? `event_route.${node ? 'node' : 'ingress'}_request_4xx` : 'event_route.request';
    return profile === 'all_requests' || eligible
      ? { ...fixture, outputs: [{ extract_from: route, conditions: [{ type: 'vrl', source: `assert!(.status == ${status} && ${timing})\nassert!(${safe})` }] }] }
      : { ...fixture, no_outputs_from: [route] };
  };
  return [
    ...[
      ['node fast success', 200, 999999, false],
      ['node exact one second', 200, 1000000, false],
      ['node above one second', 200, 1000001, true],
      ['node status399 fast', 399, 0, false],
      ['node status400 fast', 400, 0, true],
      ['node error at one second', 503, 1000000, true],
      ['node slow client error', 404, 1000001, true],
    ].map(([name, status, latency_us, eligible]) => requestCase(name, nodeRequest({ status, latency_us }), 'tinycloud-node', eligible)),
    ...[
      ['ingress fast success', 200, 0.999999, false],
      ['ingress exact one second', 200, 1.0, false],
      ['ingress above one second', 200, 1.000001, true],
      ['ingress status399 fast', 399, 0, false],
      ['ingress status400 fast', 400, 0, true],
      ['ingress error at one second', 503, 1.0, true],
      ['ingress slow client error', 404, 1.000001, true],
    ].map(([name, status, request_time, eligible]) => requestCase(name, ingressRequest({ status, request_time }), 'tinycloud-ingress', eligible)),
    ...['WARN', 'ERROR'].map(level => ({
      name: `${profile}: dependency ${level} always eligible`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope({ timestamp, level, target: 'dependency', fields: { message: canary, status: 200, latency_us: 0 } })) }],
      outputs: [{ extract_from: 'event_route.diagnostic', conditions: [{ type: 'vrl', source: `assert!(.event_count == 1 && .event_code == "unclassified")\nassert!(${safe})` }] }],
    })),
    {
      name: `${profile}: node 5xx diagnostic routes as an individual event, never into the count reducer`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(dbFailure())) }],
      no_outputs_from: ['event_route.diagnostic', 'event_route.request', ...capNames.filter(name => name !== 'db_failure_5xx').map(name => `event_route.${name}`)],
      outputs: [{ extract_from: 'event_route.db_failure_5xx', conditions: [{ type: 'vrl', source: `assert!(.event_code == "db_failure_5xx" && .elapsed_ms == 30001 && .db_hash == "${goodHash}")\nassert!(${keysAre(dbShipped)})\nassert!(${safe})` }] }],
    },
    {
      name: `${profile}: invalid node 5xx diagnostic is counted as unclassified, never an individual event`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(dbFailure({ code: canary, sql: canary }))) }],
      no_outputs_from: ['event_route.db_failure_5xx', 'event_route.request'],
      outputs: [{ extract_from: 'event_route.diagnostic', conditions: [{ type: 'vrl', source: `assert!(.event_count == 1 && .event_code == "unclassified")\nassert!(${keysAre(['event', 'event_code', 'event_count', 'level', 'svc', 'ts'])})\nassert!(${safe})` }] }],
    },
    {
      name: `${profile}: disk headroom routes as an individual event, never into the count reducer or a cap`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(storageHeadroom({ store: 'duckdb' }))) }],
      no_outputs_from: ['event_route.diagnostic', 'event_route.request', ...capNames.map(name => `event_route.${name}`)],
      outputs: [{ extract_from: 'event_route.storage_headroom', expected_event_count: 1, conditions: [{ type: 'vrl', source: `assert!(.event == "node_storage_headroom" && .store == "duckdb" && .free_bytes == 7516192768)\nassert!(${keysAre(headroomShipped)})\nassert!(${safe})` }] }],
    },
    ...Object.keys(bootReindexMessages).map(result => ({
      name: `${profile}: delegation mode boot reindex ${result} reaches the sink with its seven counters`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(bootSummary(result))) }],
      no_outputs_from: ['event_route.diagnostic', 'event_route.request'],
      outputs: [{ extract_from: 'event_route.delegation_mode_boot_reindex', expected_event_count: 1, conditions: [{ type: 'vrl', source: `assert!(.event == "delegation_mode_boot_reindex" && .event_code == "delegation_mode_boot_reindex_${result}" && .level == "info" && .svc == "api" && ${Object.entries(bootCounts).map(([key, value]) => `.${key} == ${value}`).join(' && ')} && ${keysAre(bootSummaryKeys)})\nassert!(${safe})` }] }],
    })),
    ...LEDGER_EVENTS.map(event => ({
      name: `${profile}: ${event} routes as an individual event, never into the count reducer or a cap`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(ledgerError(event, { error_kind: 'lock_held' }))) }],
      no_outputs_from: ['event_route.diagnostic', 'event_route.request', 'event_route.storage_headroom', ...capNames.map(name => `event_route.${name}`)],
      outputs: [{ extract_from: 'event_route.deletion_ledger', expected_event_count: 1, conditions: [{ type: 'vrl', source: `assert!(.event == "${event}" && .error_kind == "lock_held")\nassert!(${keysAre(ledgerShipped)})\nassert!(${safe})` }] }],
    })),
    // TC-4177: the start line reaches the sink through its own route with every count, and never through the reducer, a cap or the error-event route.
    ...LEDGER_START_FILES.map(file => ({
      name: `${profile}: ${LEDGER_START_EVENT} with a ${file} ledger file reaches the sink with its file state and five counts`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(ledgerStart({ ledger_file: file }))) }],
      no_outputs_from: ['event_route.diagnostic', 'event_route.request', 'event_route.deletion_ledger', 'event_route.storage_headroom', 'event_route.delegation_mode_boot_reindex', ...capNames.map(name => `event_route.${name}`)],
      outputs: [{ extract_from: 'event_route.deletion_ledger_start', expected_event_count: 1, conditions: [{ type: 'vrl', source: `assert!(.event == "${LEDGER_START_EVENT}" && .level == "info" && .svc == "api" && .ledger_file == "${file}" && ${Object.entries(ledgerStartCounts).map(([key, value]) => `.${key} == ${value}`).join(' && ')} && .newest_deleted_at == "${ledgerStartNewest}" && ${keysAre(ledgerStartShipped)})\nassert!(${safe})` }] }],
    })),
    {
      name: `${profile}: ${LEDGER_START_EVENT} failure variant reaches the sink with only its error_kind`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(ledgerStartFailed({ error_kind: 'malformed' }))) }],
      no_outputs_from: ['event_route.diagnostic', 'event_route.request', 'event_route.deletion_ledger', ...capNames.map(name => `event_route.${name}`)],
      outputs: [{ extract_from: 'event_route.deletion_ledger_start', expected_event_count: 1, conditions: [{ type: 'vrl', source: `assert!(.event == "${LEDGER_START_EVENT}" && .error_kind == "malformed" && .level == "info")\nassert!(${keysAre(ledgerStartFailedShipped)})\nassert!(${safe})` }] }],
    },
    {
      name: `${profile}: ${LEDGER_START_EVENT} with a free-text file state never reaches the sink route`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(ledgerStart({ ledger_file: canary }))) }],
      no_outputs_from: ['event_route.deletion_ledger_start', 'event_route.deletion_ledger', 'event_route.diagnostic', 'event_route.request'],
    },
    {
      name: `${profile}: a ledger event with an unlisted error_kind is only a count, never an individual event`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(ledgerError('deletion_ledger_unrepaired', { error_kind: 'xyz' }))) }],
      no_outputs_from: ['event_route.deletion_ledger', 'event_route.request'],
      outputs: [{ extract_from: 'event_route.diagnostic', conditions: [{ type: 'vrl', source: `assert!(.event == "node_error" && .event_count == 1 && .event_code == "unclassified")\nassert!(${keysAre(['event', 'event_code', 'event_count', 'level', 'svc', 'ts'])})\nassert!(${safe})` }] }],
    },
    // TC-1843: the capped classes reach their cap transform from the raw envelope, with the same fields.
    ...[
      ['node request with status 503', 'node_request_5xx', envelope(nodeRequest({ status: 503 })), `.event == "node_request" && .status == 503 && .latency_us == 1234)\nassert!(${keysAre(['event', 'latency_us', 'level', 'method', 'route', 'status', 'svc', 'ts'])}`],
      ['ingress request with status 502', 'ingress_request_5xx', envelope(ingressRequest({ status: 502 }), 'tinycloud-ingress'), `.event == "ingress_request" && .status == 502 && .svc == "ingress")\nassert!(${keysAre(['event', 'level', 'method', 'request_time_seconds', 'route', 'status', 'svc', 'ts'])}`],
      ['node 5xx diagnostic', 'db_failure_5xx', envelope(dbFailure()), `.event_code == "db_failure_5xx" && .elapsed_ms == 30001)\nassert!(${keysAre(dbShipped)}`],
      ['node request with status 429', 'node_request_4xx', envelope(nodeRequest({ status: 429 })), `.event == "node_request" && .status == 429 && .latency_us == 1234)\nassert!(${keysAre(['event', 'latency_us', 'level', 'method', 'route', 'status', 'svc', 'ts'])}`],
      ['ingress request with status 404', 'ingress_request_4xx', envelope(ingressRequest({ status: 404 }), 'tinycloud-ingress'), `.event == "ingress_request" && .status == 404 && .svc == "ingress")\nassert!(${keysAre(['event', 'level', 'method', 'request_time_seconds', 'route', 'status', 'svc', 'ts'])}`],
    ].map(([label, name, input, assertion]) => ({
      name: `${profile}: ${label} reaches only the ${name} cap`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(input) }],
      no_outputs_from: ['event_route.request', ...capNames.filter(other => other !== name).map(other => `cap_${other}`)],
      outputs: [{ extract_from: `cap_${name}`, expected_event_count: 1, conditions: [{ type: 'vrl', source: `assert!(${assertion})\nassert!(${safe})` }] }],
    })),
    // Slow requests below status 400 are forwarded by errors_slow and are not capped.
    ...[['node', envelope(nodeRequest({ status: 200, latency_us: 1000001 })), 'latency_us == 1000001'], ['ingress', envelope(ingressRequest({ status: 301, request_time: 1.000001 }), 'tinycloud-ingress'), 'status == 301']].map(([side, input, condition]) => ({
      name: `${profile}: slow ${side} request with a status below 400 is not capped`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(input) }],
      no_outputs_from: capNames.map(name => `cap_${name}`),
      outputs: [{ extract_from: 'event_route.request', expected_event_count: 1, conditions: [{ type: 'vrl', source: `assert!(.${condition})` }] }],
    })),
  ];
}

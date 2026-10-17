import { readFileSync } from 'node:fs';
// Synthetic inputs only. Native Vector evaluates every assertion after the full boundary.
export const canary = 'TC959_SYNTHETIC_Bearer_eyJhbGciOiJub25lIn0.email@example.test.did:pkh:0xdeadbeef';
export const timestamp = '2026-10-16T12:00:00.000Z';
// The shipper cap per typed code per window (Sam, tc-959-f6-log-cap); fixtures derive from it.
const typedCap = JSON.parse(readFileSync(new URL('./diagnostics.json', import.meta.url), 'utf8')).typed_limit.records;
export const nodeRequest = (fields = {}) => ({ timestamp, level: 'INFO', target: 'tinycloud::request', fields: { message: 'request', method: 'POST', route: '/invoke', status: 200, latency_us: 1234, ...fields } });
export const ingressRequest = (fields = {}) => ({ time: timestamp, method: 'GET', route: '/healthz', status: 200, request_time: 0.012, bytes: 2, upstream_status: '200', ...fields });
export const envelope = (value, label = 'tinycloud-node') => ({ message: typeof value === 'string' ? value : JSON.stringify(value), '_tc.logship': label, host: canary, full_message: canary, container_id: canary });
const safe = '!contains(encode_json(.), "TC959_SYNTHETIC") && !exists(.message) && !exists(.target) && !exists(.host) && !exists(.request_id) && !exists(.request_id_replaced) && !exists(.account_hash) && !exists(.space_hash)';
// Vector test log_fields keys are paths; quote the literal dotted GELF label.
const logFields = input => Object.fromEntries(Object.entries(input).map(([key, value]) => [key === '_tc.logship' ? '."_tc.logship"' : key, value]));
const check = (name, input, assertion, insertAt = 'logship_gate') => ({ name, inputs: [{ insert_at: insertAt, type: 'log', log_fields: logFields(input) }], outputs: [{ extract_from: 'allowlist', conditions: [{ type: 'vrl', source: `assert!(${assertion})\nassert!(${safe})` }] }] });
// Like check(), but the output may carry the validated N2 correlation fields; nothing else may leak.
const unsafeCorrelated = '!contains(encode_json(.), "TC959_SYNTHETIC") && !exists(.message) && !exists(.target) && !exists(.host)';
const correlated = (name, input, assertion) => ({ name, inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(input) }], outputs: [{ extract_from: 'allowlist', conditions: [{ type: 'vrl', source: `assert!(${assertion})\nassert!(${unsafeCorrelated})` }] }] });
const goodId = 'a8098c1a-f86e-4b1f-92a7-4b50b53ec932';
const goodHash = 'a'.repeat(64);
const goodSpace = '0123456789abcdef'.repeat(4);
const reject = (name, input, insertAt = 'logship_gate') => ({ name, inputs: [{ insert_at: insertAt, type: 'log', log_fields: logFields(input) }], no_outputs_from: ['allowlist'], outputs: [{ extract_from: 'gate_counts', conditions: [{ type: 'vrl', source: 'assert!(.count == 1)\nassert!(!contains(encode_json(.), "TC959_SYNTHETIC"))' }] }] });

// TC-1274 F6 contention diagnostics, per Naomi's ruling: only these typed
// fields per event; space_hash/db_hash are keyed 64-lowercase-hex digests and
// no raw db, pool operation label, error or message text ever leaves.
export const spaceHash = '0123456789abcdef'.repeat(4);
export const dbHash = 'fedcba9876543210'.repeat(4);
export const f6Events = {
  sql_operation_lock_wait: { target: 'tinycloud_core::sql::service', level: 'WARN', fields: { op: 'execute', space_hash: spaceHash, db_hash: dbHash, waited_ms: 61000, ahead_approx: 2, suppressed_count: 0 } },
  sql_operation_lock_still_waiting: { target: 'tinycloud_core::sql::service', level: 'ERROR', fields: { op: 'execute_no_growth', space_hash: spaceHash, db_hash: dbHash, waited_ms: 30000, ahead_approx: 1, suppressed_count: 1 } },
  sql_operation_lock_held: { target: 'tinycloud_core::sql::service', level: 'WARN', fields: { op: 'publication', space_hash: spaceHash, db_hash: dbHash, held_ms: 61000, hydrate_ms: 10, execute_ms: 990, persist_ms: 60000, outcome: 'ok', suppressed_count: 0 } },
  sql_operation_still_running: { target: 'tinycloud_core::sql::service', level: 'ERROR', fields: { op: 'export', space_hash: spaceHash, db_hash: dbHash, phase: 'persist', held_ms: 30000, suppressed_count: 0 } },
  sql_actor_message_slow: { target: 'tinycloud_core::sql::database', level: 'WARN', fields: { kind: 'query', space_hash: spaceHash, db_hash: dbHash, elapsed_ms: 8000, outcome: 'parse_error', suppressed_count: 3 } },
  db_pool_acquire_timeout: { target: 'tinycloud_core::db_pool', level: 'WARN', fields: { elapsed_ms: 200, pool_size: 1, pool_idle: 0, pool_max: 1, suppressed_count: 0 } },
  db_connect_failed: { target: 'tinycloud_core::db_pool', level: 'WARN', fields: { class: 'refused', suppressed_count: 0 } },
};
/** A raw F6 tracing line; an override of `undefined` removes that field. */
export const f6Line = (name, overrides = {}, { target = f6Events[name].target, level = f6Events[name].level } = {}) => ({ timestamp, level, target, fields: { message: name, ...f6Events[name].fields, ...overrides } });
const vrl = value => JSON.stringify(value);
const f6Safe = '!contains(encode_json(.), "TC959_SYNTHETIC") && !exists(.message) && !exists(.target) && !exists(.host) && !exists(.db) && !exists(.operation) && !exists(.error) && !exists(.err) && !exists(.sql) && !exists(.nested) && !exists(.request_id) && !exists(.account_hash)';
/** The exact wire record for an admitted F6 occurrence: fixed envelope plus its typed fields, nothing else. */
export const f6Expected = name => {
  const { level, fields } = f6Events[name];
  const lower = level.toLowerCase();
  const event = lower === 'warn' ? 'node_warning' : 'node_error';
  const typed = Object.entries(fields).map(([key, value]) => `.${key} == ${vrl(value)}`);
  return [`.event == "${event}"`, '.svc == "api"', `.level == "${lower}"`, `.event_code == "${name}"`, '.event_count == 1', ...typed, `length(keys(.)) == ${6 + Object.keys(fields).length}`].join(' && ');
};
const f6Check = (name, input, assertion, extract = 'allowlist') => ({ name, inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(input)) }], outputs: [{ extract_from: extract, conditions: [{ type: 'vrl', source: `assert!(${assertion})\nassert!(${f6Safe})` }] }] });
const f6Reject = (name, input) => ({ name, inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(input)) }], no_outputs_from: ['allowlist'], outputs: [{ extract_from: 'gate_counts', conditions: [{ type: 'vrl', source: 'assert!(.count == 1 && .reason == "invalid_fields")\nassert!(!contains(encode_json(.), "TC959_SYNTHETIC"))' }] }] });
const hostileExtras = { db: 'v2n', operation: 'begin', error: canary, err: canary, sql: `SELECT '${canary}'`, nested: { space: canary }, space: canary, did: canary };
const integerFields = { waited_ms: 86_400_000, held_ms: 86_400_000, hydrate_ms: 86_400_000, execute_ms: 86_400_000, persist_ms: 86_400_000, elapsed_ms: 86_400_000, ahead_approx: 1_000_000, suppressed_count: 9_007_199_254_740_991, pool_size: 100_000, pool_idle: 100_000, pool_max: 100_000 };
/** An admitted F6 wire record, as the allowlist emits it. */
const f6Wire = name => {
  const { level, fields } = f6Events[name];
  const lower = level.toLowerCase();
  return { ts: timestamp, level: lower, event: lower === 'warn' ? 'node_warning' : 'node_error', svc: 'api', event_code: name, event_count: 1, ...fields };
};
const f6Tests = [
  ...Object.keys(f6Events).map(name => f6Check(`F6 ${name} keeps exactly its typed fields`, f6Line(name), f6Expected(name))),
  ...Object.keys(f6Events).map(name => f6Check(`F6 ${name} drops raw db, pool operation, error text and nested extras`, f6Line(name, hostileExtras), f6Expected(name))),
  f6Check('F6 field belonging to another event is not copied', f6Line('sql_operation_lock_wait', { phase: 'persist', kind: 'query', class: 'io', held_ms: 1 }), f6Expected('sql_operation_lock_wait')),
  ...Object.entries(f6Events).flatMap(([name, { fields }]) => Object.keys(fields).map(key => f6Reject(`F6 ${name} without ${key} is rejected`, f6Line(name, { [key]: undefined })))),
  ...Object.entries(f6Events).flatMap(([name, { fields }]) => Object.keys(fields).filter(key => key in integerFields).flatMap(key => [
    f6Check(`F6 ${name} ${key} accepts its bounds`, f6Line(name, { [key]: integerFields[key] }), `.${key} == ${integerFields[key]}`),
    ...[-1, integerFields[key] + 1, 1.5, '5000', true, null, { ms: 5000 }, [5000]].map(value => f6Reject(`F6 ${name} ${key}=${JSON.stringify(value)} is rejected`, f6Line(name, { [key]: value }))),
  ])),
  f6Reject('F6 float-overflowed counter is rejected', f6Line('sql_operation_lock_wait', { suppressed_count: 1e30 })),
  ...['space_hash', 'db_hash'].flatMap(key => [
    ['stale 16-hex shape', '0123456789abcdef'], ['uppercase', 'ABCDEF0123456789'.repeat(4)], ['63 hex', 'a'.repeat(63)], ['65 hex', 'a'.repeat(65)],
    ['non-hex', 'g'.repeat(64)], ['v2n', 'v2n'], ['v2d plus hex', `v2d${'a'.repeat(16)}`], ['legacy', `legacy-${'a'.repeat(16)}`],
    ['free text', canary], ['nested', { hash: spaceHash }], ['number', 1], ['padded', ` ${spaceHash}`],
  ].map(([label, value]) => f6Reject(`F6 ${key} ${label} is rejected`, f6Line('sql_operation_lock_held', { [key]: value })))),
  ...[
    ['op', ['EXECUTE', 'execute ', 'lock', canary, { op: 'execute' }, ['execute'], 1]],
    ['outcome', ['Sqlite', `sqlite error: ${canary}`, 'incomplete_', '', null]],
  ].flatMap(([key, values]) => values.map(value => f6Reject(`F6 lock_held ${key}=${JSON.stringify(value)} is rejected`, f6Line('sql_operation_lock_held', { [key]: value })))),
  ...['lock', 'Persist', canary].map(phase => f6Reject(`F6 still_running phase=${phase} is rejected`, f6Line('sql_operation_still_running', { phase }))),
  ...['drop', 'Query', canary, 1].map(kind => f6Reject(`F6 actor kind=${kind} is rejected`, f6Line('sql_actor_message_slow', { kind }))),
  ...['protocol', 'Refused', `connection refused: ${canary}`, { class: 'io' }].map(value => f6Reject(`F6 connect class=${JSON.stringify(value)} is rejected`, f6Line('db_connect_failed', { class: value }))),
  ...['ok', 'incomplete', 'sqlite', 'permission_denied', 'database_not_found', 'response_too_large', 'quota_exceeded', 'storage_would_grow', 'invalid_statement', 'schema_error', 'read_only_violation', 'parse_error', 'internal', 'unavailable', 'outcome_unknown'].map(outcome => f6Check(`F6 lock_held outcome ${outcome} is admitted`, f6Line('sql_operation_lock_held', { outcome }), `.outcome == "${outcome}"`)),
  ...['execute', 'execute_no_growth', 'publication', 'export'].map(op => f6Check(`F6 op ${op} is admitted`, f6Line('sql_operation_lock_wait', { op }), `.op == "${op}"`)),
  ...['hydrate', 'execute', 'persist'].map(phase => f6Check(`F6 phase ${phase} is admitted`, f6Line('sql_operation_still_running', { phase }), `.phase == "${phase}"`)),
  ...['query', 'execute', 'batch', 'execute_statement', 'export', 'publication', 'checkpoint', 'wal', 'shutdown'].map(kind => f6Check(`F6 kind ${kind} is admitted`, f6Line('sql_actor_message_slow', { kind }), `.kind == "${kind}"`)),
  ...['refused', 'io', 'tls', 'database_transient', 'database', 'after_connect', 'timed_out', 'other'].map(value => f6Check(`F6 class ${value} is admitted`, f6Line('db_connect_failed', { class: value }), `.class == "${value}"`)),
  ...Object.keys(f6Events).map(name => f6Reject(`F6 ${name} at the wrong level is rejected`, f6Line(name, {}, { level: f6Events[name].level === 'WARN' ? 'ERROR' : 'WARN' }))),
  ...[
    ['another F6 target', 'tinycloud_core::sql::database', 'sql_operation_lock_wait'],
    ['a child of the F6 target', 'tinycloud_core::sql::service::inner', 'sql_operation_lock_held'],
    ['a dependency', 'sqlx::pool', 'db_connect_failed'],
    ['an application target', 'tinycloud::request', 'db_pool_acquire_timeout'],
  ].map(([label, target, name]) => check(`F6 message from ${label} stays unclassified without fields`, envelope(f6Line(name, {}, { target })), `.event_code == "unclassified" && .event_count == 1 && length(keys(.)) == 6`)),
  f6Check('F6 occurrences bypass the diagnostic reduce', f6Line('sql_operation_lock_wait'), f6Expected('sql_operation_lock_wait'), 'event_route.typed_diagnostic'),
  {
    name: 'F6 occurrences are shipped one per line, never merged',
    inputs: [61000, 62000].map(waited_ms => ({ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(f6Line('sql_operation_lock_wait', { waited_ms }))) })),
    no_outputs_from: ['diagnostic_output'],
    outputs: [{ extract_from: 'event_route.typed_diagnostic', conditions: [{ type: 'vrl', source: `assert!(.event_count == 1 && (.waited_ms == 61000 || .waited_ms == 62000))\nassert!(${f6Safe})` }] }],
  },
  // Shipper-side cap (defence in depth over the node limiter): at most `typedCap` records per code per window.
  {
    name: 'typed cap passes up to its limit for each code unchanged and counts nothing',
    inputs: [...Array(typedCap).fill('sql_operation_lock_wait'), ...Array(typedCap).fill('db_connect_failed')].map(name => ({ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(f6Line(name))) })),
    no_outputs_from: ['typed_limit_route.throttled'],
    outputs: [{ extract_from: 'typed_limit_route.record', conditions: [{ type: 'vrl', source: `assert!(.event_count == 1 && ((.event_code == "sql_operation_lock_wait" && is_integer(.waited_ms) && .waited_ms == 61000 && length(keys(.)) == 12) || (.event_code == "db_connect_failed" && .class == "refused" && length(keys(.)) == 8)))\nassert!(${f6Safe})` }] }],
  },
  {
    name: 'typed cap drops the record past its limit and counts it without content',
    inputs: Array(typedCap + 1).fill('sql_operation_lock_wait').map(name => ({ insert_at: 'typed_limit', type: 'log', log_fields: f6Wire(name) })),
    outputs: [{ extract_from: 'typed_limit_route.throttled', conditions: [{ type: 'vrl', source: 'assert!(.reason == "typed_throttled" && .count == 1 && length(keys(.)) == 2)' }] }],
  },
  {
    name: 'typed cap drops surface in the gate summary as an exact count',
    inputs: Array(typedCap + 65).fill('sql_actor_message_slow').map(name => ({ insert_at: 'typed_limit', type: 'log', log_fields: f6Wire(name) })),
    outputs: [{ extract_from: 'gate_output', conditions: [{ type: 'vrl', source: 'assert!(.reason == "typed_throttled" && .count == 65 && .event == "logship_gate_summary_total" && length(keys(.)) == 6)' }] }],
  },
  {
    name: 'typed cap applies to raw node lines end to end',
    inputs: Array(typedCap + 1).fill('db_pool_acquire_timeout').map(name => ({ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(f6Line(name, { error: canary }))) })),
    outputs: [{ extract_from: 'gate_output', conditions: [{ type: 'vrl', source: 'assert!(.reason == "typed_throttled" && .count == 1)\nassert!(!contains(encode_json(.), "TC959_SYNTHETIC"))' }] }],
  },
];
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
  ...f6Tests,
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
    ...Object.keys(f6Events).map(name => ({
      name: `${profile}: F6 ${name} always eligible and never reduced`,
      inputs: [{ insert_at: 'logship_gate', type: 'log', log_fields: logFields(envelope(f6Line(name))) }],
      no_outputs_from: ['event_route.diagnostic', 'event_route.request'],
      outputs: [{ extract_from: 'event_route.typed_diagnostic', conditions: [{ type: 'vrl', source: `assert!(${f6Expected(name)})\nassert!(${f6Safe})` }] }],
    })),
  ];
}

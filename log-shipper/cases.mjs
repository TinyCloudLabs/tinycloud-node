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
  check('unknown extras and even valid N2 correlation fields are discarded', envelope({ ...nodeRequest({ authorization: canary, nested: { sql: canary }, request_id: 'a8098c1a-f86e-4b1f-92a7-4b50b53ec932', request_id_replaced: true, account_hash: 'a'.repeat(64), space_hash: '0'.repeat(64) }), span: { account: canary }, spans: [{ request_id: canary }] }), '.event == "node_request" && !exists(.authorization) && !exists(.nested) && !exists(.span)'),
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

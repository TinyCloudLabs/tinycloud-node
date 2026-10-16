const states = new Set(['connection_refused', 'connection_reset', 'timeout', 'dns', 'network', 'not_running']);

/** Classify an exception without copying its message, URL, headers or cause. */
export function classifyProbeError(error) {
  const code = error?.cause?.code ?? error?.code;
  if (error?.name === 'TimeoutError' || error?.name === 'AbortError' || code === 'ETIMEDOUT' || code === 'UND_ERR_CONNECT_TIMEOUT') return 'timeout';
  if (code === 'ECONNREFUSED') return 'connection_refused';
  if (code === 'ECONNRESET' || code === 'UND_ERR_SOCKET') return 'connection_reset';
  if (code === 'ENOTFOUND' || code === 'EAI_AGAIN') return 'dns';
  return 'network';
}

function sanitize(value) {
  if (Number.isInteger(value) && value >= 100 && value <= 599) return { state: 'http', status: value };
  if (value === true) return { state: 'ready' };
  if (value && states.has(value.state)) return { state: value.state };
  return { state: 'not_running' };
}

/** Keep only per-probe typed state. A failed probe never masks a passing one. */
export async function awaitReadiness(probe, { attempts = 90, intervalMs = 500 } = {}) {
  let diagnostics = {};
  for (let index = 0; index < attempts; index++) {
    const observed = await probe();
    diagnostics = Object.fromEntries(Object.entries(observed).map(([name, value]) => [name, sanitize(value)]));
    if (Object.values(diagnostics).every(value => value.state === 'ready' || (value.state === 'http' && value.status === 200))) return diagnostics;
    if (index + 1 < attempts && intervalMs > 0) await new Promise(resolve => setTimeout(resolve, intervalMs));
  }
  const error = new Error('readiness_timeout');
  error.diagnostics = diagnostics;
  throw error;
}

/** Synthetic fixture diagnostics only; never return a line or matched value. */
export function classifyStartupOutput(text) {
  const output = [];
  if (/failed to start tinycloud-node|panicked/i.test(text)) output.push('application_startup_failed');
  if (/invalid value|unknown variant|missing field|configuration error/i.test(text)) output.push('invalid_configuration');
  if (/permission denied|operation not permitted/i.test(text)) output.push('permission_denied');
  if (/nginx: \[emerg\]|configuration file.*test failed/i.test(text)) output.push('nginx_startup_failed');
  if (/connect\(\) failed.*upstream|connection refused/i.test(text)) output.push('upstream_connection_refused');
  if (/address already in use/i.test(text)) output.push('address_in_use');
  return output;
}

/** Linux socket-table readiness; a running process alone can still lose UDP. */
export function hasUdpListener(table, port) {
  const suffix = `:${port.toString(16).padStart(4, '0')}`.toUpperCase();
  return table.split('\n').some(line => {
    const fields = line.trim().split(/\s+/);
    return /^\d+:$/.test(fields[0]) && /^[0-9A-F]{8}:[0-9A-F]{4}$/i.test(fields[1] ?? '') && fields[1].toUpperCase().endsWith(suffix);
  });
}

/** Missing metrics stay unknown (null), never fabricated as zero. */
export function componentCounters(text, component) {
  const names = { component_received_events_total: 'received_events', component_sent_events_total: 'sent_events', component_errors_total: 'errors', component_discarded_events_total: 'discarded_events' };
  const counts = { received_events: null, sent_events: null, errors: null, discarded_events: null };
  for (const line of text.split('\n')) {
    const match = /^(?:vector_)?([a-z_]+)\{([^}]*)\}\s+([0-9.eE+-]+)(?:\s|$)/.exec(line);
    if (!match || !Object.hasOwn(names, match[1]) || !match[2].split(',').includes(`component_id="${component}"`)) continue;
    const value = Number(match[3]);
    if (!Number.isSafeInteger(value) || value < 0) continue;
    const name = names[match[1]];
    counts[name] = (counts[name] ?? 0) + value;
  }
  return counts;
}

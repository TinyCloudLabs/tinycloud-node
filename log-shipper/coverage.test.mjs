// test-ruling: TC-3284 log-shipper/coverage.test.mjs new test only (2026-11-23)
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { codeFor, formatPrefix, scanRepo, scanSource } from './coverage.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const diagnostics = JSON.parse(await readFile(new URL('./diagnostics.json', import.meta.url), 'utf8'));
const schema = JSON.parse(await readFile(new URL('./fields.json', import.meta.url), 'utf8')).services['tinycloud-node'];

// Lines that ship as their own event or are built at run time; each is named here with the reason.
const NOT_AGGREGATED = new Map([
  // TC-1840: an individual `db_failure_5xx` event, not a diagnostic count.
  ['database failure answered with a 5xx', 'individual'],
  // TC-3284: individual error events carrying `error_kind` (ledger.mjs).
  ['deletion ledger could not be opened: {}', 'individual'],
  ['deletion ledger replay failed: {}', 'individual'],
  ['a failed ledger append left bytes that could not be removed: later appends fail', 'individual'],
]);
// Messages built at run time from error text; they cannot be named without copying it, and stay unclassified.
const DYNAMIC = new Set(['tinycloud-core/src/sql/database.rs', 'tinycloud-node-server/src/tunnel/connection.rs']);

/** The code a scanned call ships as, or null when the shipper cannot name it. */
function shippedCode(call) {
  if (call.message !== null && !call.dynamic) return codeFor(diagnostics, call.message);
  if (call.message !== null) {
    const prefix = formatPrefix(call.message);
    const match = Object.keys(diagnostics.prefix).filter(p => prefix.startsWith(p)).sort((a, b) => b.length - a.length)[0];
    return match ? diagnostics.prefix[match] : null;
  }
  if (!call.dynamic && call.event !== null) return diagnostics.event[call.event] ?? null;
  return null;
}

test('every node warn/error line outside tests ships with a named event_code (TC-3284)', () => {
  const calls = scanRepo(root);
  assert.ok(calls.length > 100, `scanner found only ${calls.length} warn!/error! calls`);
  const unnamed = calls.filter(call => {
    if (NOT_AGGREGATED.has(call.message)) return false;
    if (call.dynamic && call.message === null && DYNAMIC.has(call.file)) return false;
    if (call.dynamic && call.message !== null && formatPrefix(call.message) === '' && DYNAMIC.has(call.file)) return false;
    const code = shippedCode(call);
    return code === null || code === diagnostics.fallback;
  });
  assert.deepEqual(unnamed.map(c => `${c.file}:${c.line} ${c.level} ${JSON.stringify(c.message ?? c.event)}`), [],
    'add each message to log-shipper/diagnostics.json (exact, prefix for a format message, or event for a message-less line) and its code to fields.json');
});

test('every mapped code is a schema event_code and every event entry names its own code (TC-3284)', () => {
  const codes = schema.fields.event_code.values;
  for (const code of [...Object.values(diagnostics.exact), ...Object.values(diagnostics.prefix), ...Object.values(diagnostics.event)]) {
    assert.ok(codes.includes(code), code);
    assert.match(code, /^[a-z][a-z0-9_]*$/);
  }
  for (const [event, code] of Object.entries(diagnostics.event)) assert.equal(event, code);
});

test('the scanner reads messages, constants, events and skips test code (TC-3284)', () => {
  const source = `
const MSG: &str = "from a constant";
fn live() {
    tracing::warn!(target: "tinycloud::x", event = "e_one", error_kind = kind, "plain \\"quoted\\" text");
    tracing::error!(%error, count = 3, MSG);
    warn!(event = "no_message", lease = %cid,);
    tracing::warn!("{MSG}");
    tracing::warn!("value {} here", x);
    tracing::warn!(%message);
    // tracing::warn!("in a comment");
    let s = "tracing::warn!(\\"in a string\\")";
}
#[cfg(test)]
mod tests {
    fn t() { tracing::warn!("test only"); }
}
`;
  const { calls } = scanSource(source);
  assert.deepEqual(calls.map(({ level, message, dynamic, event, target }) => ({ level, message, dynamic, event, target })), [
    { level: 'warn', message: 'plain "quoted" text', dynamic: false, event: 'e_one', target: 'tinycloud::x' },
    { level: 'error', message: 'from a constant', dynamic: false, event: null, target: null },
    { level: 'warn', message: null, dynamic: false, event: 'no_message', target: null },
    { level: 'warn', message: 'from a constant', dynamic: false, event: null, target: null },
    { level: 'warn', message: 'value {} here', dynamic: true, event: null, target: null },
    { level: 'warn', message: null, dynamic: true, event: null, target: null },
  ]);
});

test('boot-scoped diagnostics and reindex summaries use closed schema codes (TC-3973)', () => {
  const codes = [
    ...diagnostics.scoped.map(entry => entry.code),
    ...Object.values(diagnostics.boot_reindex),
  ];
  for (const code of codes) assert.ok(schema.fields.event_code.values.includes(code), code);
  assert.ok(schema.events.includes('delegation_mode_boot_reindex'));
});

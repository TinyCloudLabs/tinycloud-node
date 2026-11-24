// TC-4177: the deletion ledger start event ships its counts only if the canonical schema carries every field the
// shipper emits (the reducer-free route keeps fields, the schema is what the readers validate them against).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { LEDGER_START_EVENT, LEDGER_START_FILES, LEDGER_START_COUNTERS, LEDGER_ERROR_KINDS } from './ledger.mjs';
import { buildConfig } from '../scripts/tc959-logship.mjs';

const nodeSchema = JSON.parse(await readFile(new URL('./fields.json', import.meta.url), 'utf8')).services['tinycloud-node'];
const source = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');

test('the canonical schema declares the start event with every field it ships', () => {
  assert.ok(nodeSchema.events.includes(LEDGER_START_EVENT));
  assert.deepEqual(nodeSchema.fields.ledger_file, { type: 'enum', values: [...LEDGER_START_FILES] });
  for (const counter of LEDGER_START_COUNTERS) {
    assert.deepEqual(nodeSchema.fields[counter], { type: 'integer', min: 0, max: Number.MAX_SAFE_INTEGER }, counter);
  }
  const newest = nodeSchema.fields.newest_deleted_at;
  assert.equal(newest.type, 'string');
  assert.match('none', new RegExp(newest.regex));
  assert.match('2026-11-23T08:15:30.123456789Z', new RegExp(newest.regex));
  assert.doesNotMatch('2026-11-23T08:15:30Z extra', new RegExp(newest.regex));
  assert.deepEqual(nodeSchema.fields.error_kind.values, [...LEDGER_ERROR_KINDS]);
});

test('the start event has its own sink route, and the reducer and caps never see it', () => {
  const { sinks, transforms } = buildConfig();
  assert.ok(sinks.betterstack.inputs.includes('event_route.deletion_ledger_start'));
  assert.equal(transforms.event_route.route.deletion_ledger_start, `.event == "${LEDGER_START_EVENT}"`);
  const nodes = { ...transforms, ...sinks };
  assert.deepEqual(Object.keys(nodes).filter(id => nodes[id].inputs?.includes('event_route.deletion_ledger_start')), ['betterstack']);
  assert.ok(transforms.request_profile.condition.includes(`"${LEDGER_START_EVENT}"`));
});

test('the gate lets an info line through on target tinycloud only when it names the start event', () => {
  const gate = buildConfig().transforms.logship_gate.source;
  assert.match(gate, /target == "tinycloud" && gate_event == "deletion_ledger_start"/);
});

test('the DuckDB cache cleanup warning is a warn! carrying its event and a mapped message (TC-4190)', async () => {
  const database = await source('tinycloud-core/src/duckdb/database.rs');
  assert.match(database, /tracing::warn!\(\s*event = "duckdb_cache_cleanup_failed",\s*"Database cache cleanup failed"\s*\);/);
  const diagnostics = JSON.parse(await source('log-shipper/diagnostics.json'));
  assert.equal(diagnostics.exact['Database cache cleanup failed'], 'duckdb_cache_cleanup_failed');
  assert.ok(nodeSchema.fields.event_code.values.includes('duckdb_cache_cleanup_failed'));
});

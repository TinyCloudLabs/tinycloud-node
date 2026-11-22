// TC-3284: the deletion ledger events the shipper keeps are the node's, with exactly the node's fixed error kinds.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { LEDGER_EVENTS, LEDGER_ERROR_KINDS, LEDGER_TARGETS } from './ledger.mjs';
import { assertCapture } from '../scripts/tc959-docker.mjs';

const source = path => readFile(new URL(`../${path}`, import.meta.url), 'utf8');
const nodeSchema = JSON.parse(await readFile(new URL('./fields.json', import.meta.url), 'utf8')).services['tinycloud-node'];

test('the allowlisted error kinds are exactly DeletionLedgerError::kind(), in order', async () => {
  const ledger = await source('tinycloud-core/src/encryption_network/deletion_ledger.rs');
  const body = ledger.slice(ledger.indexOf('pub fn kind(&self) -> &\'static str {'));
  const arms = body.slice(0, body.indexOf('\n    }\n')).matchAll(/Self::\w+(?:\(_\))? => "([a-z0-9_]+)",/g);
  assert.deepEqual([...arms].map(([, kind]) => kind), [...LEDGER_ERROR_KINDS]);
});

test('every ledger event is declared by the canonical schema, and every kind fits its error_kind pattern', () => {
  for (const event of LEDGER_EVENTS) assert.ok(nodeSchema.events.includes(event), event);
  const pattern = new RegExp(nodeSchema.fields.error_kind.regex);
  for (const kind of LEDGER_ERROR_KINDS) {
    assert.match(kind, pattern);
    assert.ok(kind.length <= nodeSchema.fields.error_kind.max_len);
  }
});

test('each event is emitted, with error_kind, from the target the shipper expects', async () => {
  const files = { tinycloud: 'tinycloud-node-server/src/lib.rs', 'tinycloud_core::encryption_network::deletion_ledger': 'tinycloud-core/src/encryption_network/deletion_ledger.rs' };
  for (const event of LEDGER_EVENTS) {
    const text = await source(files[LEDGER_TARGETS[event]]);
    assert.match(text, new RegExp(`event = "${event}",\\s*error_kind = error\\.kind\\(\\),`), event);
  }
  // lib.rs is the `tinycloud` crate root: its events carry that target, not a module path.
  const manifest = await source('tinycloud-node-server/Cargo.toml');
  assert.match(manifest, /\[lib\][^[]*name = "tinycloud"/);
});

test('capture accepts a ledger event with exactly a fixed error_kind', () => {
  const base = { ts: '2026-10-16T12:00:00.000Z', level: 'error', svc: 'api' };
  for (const event of LEDGER_EVENTS) {
    for (const error_kind of LEDGER_ERROR_KINDS) assert.doesNotThrow(() => assertCapture([{ ...base, event, error_kind }]));
    for (const bad of [{ error_kind: 'xyz' }, { error_kind: 'lock_wait' }, { error_kind: '/app/data/deletion-ledger.jsonl' }, { error_kind: undefined }, { path: '/app' }, { message: 'x' }, { level: 'warn' }]) {
      const row = { ...base, event, error_kind: 'io', ...bad };
      if (bad.error_kind === undefined && 'error_kind' in bad) delete row.error_kind;
      assert.throws(() => assertCapture([row]), JSON.stringify(bad));
    }
  }
});

import assert from "node:assert/strict";
import { test } from "node:test";
import {
  describe,
  entryLine,
  headerLine,
  judge,
  nextId,
  parseLedger,
  valueFor,
  type Entry,
} from "./drill-core";

function ledgerOf(entries: Entry[]) {
  const text = [headerLine("r1"), ...entries.map(entryLine)].join("\n") + "\n";
  return parseLedger(text);
}

const ack = (id: number): Entry => ({ id, value: valueFor("r1", id), state: "ack" });
const intent = (id: number): Entry => ({ id, value: valueFor("r1", id), state: "intent" });
const rowsOf = (...ids: number[]) => new Map(ids.map((id) => [id, valueFor("r1", id)]));

test("every acknowledged write present with its value is ok", () => {
  const v = judge(ledgerOf([ack(1), ack(2), ack(3)]), rowsOf(1, 2, 3));
  assert.equal(v.ok, true);
  assert.equal(v.verified, 3);
});

test("an acknowledged write that is gone fails the drill", () => {
  const v = judge(ledgerOf([ack(1), ack(2), ack(3)]), rowsOf(1, 3));
  assert.equal(v.ok, false);
  assert.deepEqual(v.missing, [2]);
});

test("an acknowledged write read back with another value fails the drill", () => {
  const rows = rowsOf(1, 2);
  rows.set(2, "something else");
  const v = judge(ledgerOf([ack(1), ack(2)]), rows);
  assert.equal(v.ok, false);
  assert.deepEqual(v.wrong, [2]);
});

test("an unanswered write may be kept or lost; both pass", () => {
  const kept = judge(ledgerOf([ack(1), intent(2)]), rowsOf(1, 2));
  const lost = judge(ledgerOf([ack(1), intent(2)]), rowsOf(1));
  assert.equal(kept.ok, true);
  assert.equal(kept.unknownKept, 1);
  assert.equal(lost.ok, true);
  assert.equal(lost.unknownLost, 1);
});

test("a row nobody wrote fails the drill (a wrong database, or a replayed one)", () => {
  const v = judge(ledgerOf([ack(1)]), rowsOf(1, 99));
  assert.equal(v.ok, false);
  assert.deepEqual(v.extra, [99]);
});

test("an empty ledger cannot pass: nothing was proven", () => {
  assert.equal(judge(ledgerOf([]), new Map()).ok, false);
});

test("an intent followed by its ack counts as acknowledged, never the reverse", () => {
  const l = ledgerOf([intent(1), ack(1), ack(2), intent(2)]);
  assert.equal(l.entries.get(1)?.state, "ack");
  assert.equal(l.entries.get(2)?.state, "ack");
});

test("a ledger cut off in the middle of its last line drops that line only", () => {
  const text = [headerLine("r1"), entryLine(ack(1)), entryLine(ack(2)).slice(0, 12)].join("\n");
  const l = parseLedger(text);
  assert.equal(l.run, "r1");
  assert.deepEqual([...l.entries.keys()], [1]);
});

test("the next id continues after every entry, intents included", () => {
  assert.equal(nextId(ledgerOf([])), 1);
  assert.equal(nextId(ledgerOf([ack(1), ack(2), intent(3)])), 4);
});

test("the report names counts and at most ten ids, never a value", () => {
  const entries = Array.from({ length: 30 }, (_, i) => ack(i + 1));
  const v = judge(ledgerOf(entries), new Map());
  const text = describe(v);
  assert.match(text, /missing=30\(1,2,3,4,5,6,7,8,9,10\)/);
  assert.doesNotMatch(text, /r1-/);
  assert.match(text, /FAIL$/);
});

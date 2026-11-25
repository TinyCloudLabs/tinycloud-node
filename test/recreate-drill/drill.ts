// TC-1491 P4.2b part 1: the SQL client of the container-recreate drill.
//
//   tsx drill.ts write  <ledger> <count> [--until-failure]
//   tsx drill.ts verify <ledger>
//
// DRILL_KEY_FILE names a file holding a throwaway private key (the drill
// script creates it per run) and DRILL_HOST the node's URL. Every phase is a
// fresh process and signs in again, so a restart of the node never leaves a
// stale session behind.
//
// Exit codes: 0 ok, 1 failure (a write failed in `write`, or `verify` found a
// lost write), 2 harness fault (`--until-failure` ran to the end without the
// node ever failing: the kill did not happen).
import { randomBytes } from "node:crypto";
import { appendFileSync, closeSync, existsSync, fsyncSync, openSync, readFileSync, writeSync } from "node:fs";
import { TinyCloudNode } from "@tinycloud/node-sdk";
import { describe, entryLine, headerLine, judge, nextId, parseLedger, valueFor } from "./drill-core";

const PREFIX = "recreate-drill";
const TABLE = "CREATE TABLE IF NOT EXISTS drill (id INTEGER PRIMARY KEY, v TEXT NOT NULL)";
const USAGE = "usage: drill.ts write <ledger> <count> [--until-failure] | verify <ledger>";

type Result<T> = { ok: true; data: T } | { ok: false; error: unknown };

function unwrap<T>(result: Result<T>): T {
  if (!result.ok) throw result.error;
  return result.data;
}

// SDK errors can carry request headers or credentials: print a status, never
// the error.
function statusOf(error: unknown): string {
  const meta = error && typeof error === "object" && "meta" in error ? error.meta : undefined;
  return meta && typeof meta === "object" && "status" in meta && typeof meta.status === "number"
    ? ` HTTP ${meta.status}`
    : "";
}

// Durable on the runner: the ledger is the drill's memory of what was
// acknowledged, and the writer is the process that may be cut off.
function append(path: string, line: string): void {
  const fd = openSync(path, "a");
  try {
    writeSync(fd, `${line}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

async function connect(): Promise<TinyCloudNode> {
  const keyFile = process.env.DRILL_KEY_FILE;
  const host = process.env.DRILL_HOST;
  if (!keyFile || !host) throw new Error("DRILL_KEY_FILE and DRILL_HOST are required");
  const node = new TinyCloudNode({ privateKey: readFileSync(keyFile, "utf8").trim(), host, prefix: PREFIX });
  await node.signIn();
  await node.hostOwnedSpace(PREFIX);
  return node;
}

async function write(ledgerPath: string, count: number, untilFailure: boolean): Promise<number> {
  if (!existsSync(ledgerPath)) appendFileSync(ledgerPath, `${headerLine(randomBytes(6).toString("hex"))}\n`);
  const ledger = parseLedger(readFileSync(ledgerPath, "utf8"));
  const run = ledger.run;
  if (!run) throw new Error("the ledger has no run header");
  const node = await connect();
  unwrap(await node.sql.execute(TABLE));
  const first = nextId(ledger);
  for (let id = first; id < first + count; id += 1) {
    const value = valueFor(run, id);
    append(ledgerPath, entryLine({ id, value, state: "intent" }));
    // A refused answer and a dropped connection both leave the write unknown:
    // the intent stays in the ledger without an ack.
    let answer: Result<unknown>;
    try {
      answer = await node.sql.execute("INSERT INTO drill (id, v) VALUES (?, ?)", [id, value]);
    } catch (error) {
      answer = { ok: false, error };
    }
    if (!answer.ok) {
      console.log(`write ${id} not acknowledged${statusOf(answer.error)}`);
      return untilFailure ? 0 : 1;
    }
    append(ledgerPath, entryLine({ id, value, state: "ack" }));
  }
  console.log(`wrote ${count} acknowledged rows (ids ${first}..${first + count - 1})`);
  return untilFailure ? 2 : 0;
}

async function verify(ledgerPath: string): Promise<number> {
  const ledger = parseLedger(readFileSync(ledgerPath, "utf8"));
  const node = await connect();
  const data = unwrap(await node.sql.query<unknown>("SELECT id, v FROM drill ORDER BY id"));
  const rows = new Map<number, string>();
  for (const row of data.rows as unknown[][]) {
    if (typeof row[0] === "number" && typeof row[1] === "string") rows.set(row[0], row[1]);
  }
  const verdict = judge(ledger, rows);
  console.log(`verify ${describe(verdict)}`);
  return verdict.ok ? 0 : 1;
}

async function main(): Promise<number> {
  const [mode, ledgerPath, countArg, flag] = process.argv.slice(2);
  if (!ledgerPath) throw new Error(USAGE);
  if (mode === "verify") return verify(ledgerPath);
  const count = Number(countArg);
  if (mode === "write" && Number.isInteger(count) && count > 0) {
    return write(ledgerPath, count, flag === "--until-failure");
  }
  throw new Error(USAGE);
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (error: unknown) => {
    console.error(`drill client failed${statusOf(error)}`);
    process.exitCode = 1;
  },
);

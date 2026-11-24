// TC-1491 P4.2b: the drill's bookkeeping, with no network and no SDK, so it
// is unit-tested without Docker.
//
// The writer keeps a ledger, one JSON object per line. Before it sends a
// write it records an `intent`; when the node answers ok it records an `ack`.
// A write whose answer never came (the container was killed mid-request) stays
// an `intent`: the node may or may not have committed it, and the drill
// accepts either. A write that was ACKNOWLEDGED must be read back exactly.

export type State = "intent" | "ack";

export interface Entry {
  id: number;
  value: string;
  state: State;
}

export interface Ledger {
  run: string | undefined;
  entries: Map<number, Entry>;
}

export function headerLine(run: string): string {
  return JSON.stringify({ run });
}

export function entryLine(entry: Entry): string {
  return JSON.stringify(entry);
}

export function valueFor(run: string, id: number): string {
  return `${run}-${id}`;
}

/**
 * Parse a ledger. The last line may be cut off (the writer was killed while
 * appending); a line that does not parse is dropped, never guessed at. For one
 * id the strongest state wins: an `ack` is never undone by a later `intent`.
 */
export function parseLedger(text: string): Ledger {
  const ledger: Ledger = { run: undefined, entries: new Map() };
  for (const line of text.split("\n")) {
    if (line.trim() === "") continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      continue;
    }
    if (typeof parsed !== "object" || parsed === null) continue;
    const o = parsed as Record<string, unknown>;
    if (typeof o.run === "string" && o.id === undefined) {
      ledger.run ??= o.run;
      continue;
    }
    if (
      typeof o.id === "number" &&
      Number.isInteger(o.id) &&
      typeof o.value === "string" &&
      (o.state === "intent" || o.state === "ack")
    ) {
      const held = ledger.entries.get(o.id);
      if (held?.state === "ack" && o.state === "intent") continue;
      ledger.entries.set(o.id, { id: o.id, value: o.value, state: o.state });
    }
  }
  return ledger;
}

export function nextId(ledger: Ledger): number {
  let max = 0;
  for (const id of ledger.entries.keys()) max = Math.max(max, id);
  return max + 1;
}

export interface Verdict {
  ok: boolean;
  acked: number;
  /** acknowledged and read back with the exact value */
  verified: number;
  /** acknowledged but absent */
  missing: number[];
  /** acknowledged but read back with another value */
  wrong: number[];
  /** an intent without an ack that the node did commit */
  unknownKept: number;
  /** an intent without an ack that the node did not commit */
  unknownLost: number;
  /** rows the ledger never heard of */
  extra: number[];
}

/** Compare the ledger with what the database returned (`id -> value`). */
export function judge(ledger: Ledger, rows: Map<number, string>): Verdict {
  const v: Verdict = {
    ok: false,
    acked: 0,
    verified: 0,
    missing: [],
    wrong: [],
    unknownKept: 0,
    unknownLost: 0,
    extra: [],
  };
  for (const entry of ledger.entries.values()) {
    const got = rows.get(entry.id);
    if (entry.state === "ack") {
      v.acked += 1;
      if (got === undefined) v.missing.push(entry.id);
      else if (got !== entry.value) v.wrong.push(entry.id);
      else v.verified += 1;
    } else if (got === undefined) {
      v.unknownLost += 1;
    } else if (got === entry.value) {
      v.unknownKept += 1;
    } else {
      v.wrong.push(entry.id);
    }
  }
  for (const id of rows.keys()) {
    if (!ledger.entries.has(id)) v.extra.push(id);
  }
  v.ok = v.missing.length === 0 && v.wrong.length === 0 && v.extra.length === 0 && v.acked > 0;
  return v;
}

export function describe(v: Verdict): string {
  const ids = (list: number[]) => (list.length === 0 ? "none" : list.slice(0, 10).join(","));
  return [
    `acked=${v.acked}`,
    `verified=${v.verified}`,
    `missing=${v.missing.length}(${ids(v.missing)})`,
    `wrong=${v.wrong.length}(${ids(v.wrong)})`,
    `unknown_kept=${v.unknownKept}`,
    `unknown_lost=${v.unknownLost}`,
    `extra=${v.extra.length}(${ids(v.extra)})`,
    v.ok ? "OK" : "FAIL",
  ].join(" ");
}

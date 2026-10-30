import { describe, expect, test } from 'bun:test';
import { bytes, hex } from './protocol.ts';
import { dkgVerifyTranscript } from './dkg.ts';
import { reshareVerifyTranscript } from './reshare.ts';
import { verifierOf } from './transcripts.ts';
import { clone, inputOf, loadDoc, probes, verifyInput, type DocCase, type TranscriptInput } from './probes.ts';
import { draftsOf, flip, seal, type Draft } from './testkit.ts';

const docs = { dkg: loadDoc('dkg-genesis.json'), reshare: loadDoc('reshare.json') };
const cli = new URL('./cli.ts', import.meta.url).pathname;

for (const [kind, doc] of Object.entries(docs)) {
  describe(`${kind}: raw one-byte corruptions are rejected with the SPEC-ordered reason`, () => {
    for (const c of doc.cases) {
      test(c.name, () => {
        const base = inputOf(c), mismatches: string[] = [];
        for (const p of probes(c)) {
          const x = clone(base);
          p.apply(x);
          const observed = verifyInput(doc, x);
          if (observed !== p.expected) mismatches.push(`${p.record} ${p.field} @${p.offset}^${p.mask}: ${observed} != ${p.expected}`);
        }
        expect(mismatches).toEqual([]);
      }, 60000);
    }
  });
}

/** Re-signs every member envelope and re-closes every round after mutating drafts. */
function reseal(x: TranscriptInput, start: Uint8Array, digest: Uint8Array, mutate: (rounds: Draft[][]) => void): TranscriptInput {
  const rounds = x.records.map(draftsOf);
  mutate(rounds);
  return { ...x, records: seal(digest, start, rounds).records };
}
function payloadFlip(rounds: Draft[][], round: number, cohort: number, index: number, offset: (payload: Uint8Array) => number) {
  const d = rounds[round - 1]!.find(m => m.cohort === cohort && m.index === index)!;
  d.payload = flip(d.payload, offset(d.payload));
}
function startOf(c: DocCase) {
  return { digest: bytes(c.inputs.ceremony_digest), start: bytes(c.inputs.initial_transcript) };
}

describe('re-signed one-byte payload corruptions reach the rule-level reason', () => {
  const dkg = (name: string) => docs.dkg.cases.find(c => c.name === name)!;
  const reshare = (name: string) => docs.reshare.cases.find(c => c.name === name)!;
  test('resealing unmodified drafts reproduces every committed record byte for byte', () => {
    for (const c of [...docs.dkg.cases, ...docs.reshare.cases]) {
      const x = inputOf(c), { digest, start } = startOf(c);
      expect(reseal(x, start, digest, () => {}).records.map(r => hex(r.closure.signature))).toEqual(x.records.map(r => hex(r.closure.signature)));
    }
  });
  test('genesis: dealer 1 commitment byte → MalformedDeal; R2 version byte → no complaint; R4 byte → extraction fault needs R6', () => {
    const c = dkg('genesis_2of3'), x = inputOf(c), { digest, start } = startOf(c), verify = verifierOf(docs.dkg);
    const malformed = reseal(x, start, digest, r => payloadFlip(r, 1, 1, 1, () => 3 + 95));
    const out = dkgVerifyTranscript(docs.dkg.anchor, malformed.ceremony, malformed.records, verify);
    expect(out.disqualified).toEqual([{ member: 1, reason: 'MalformedDeal' }]);
    expect(out.qual).toEqual([2, 3]);
    if (!('outputs' in c)) throw new Error('genesis_2of3 is a success vector');
    const quiet = reseal(x, start, digest, r => payloadFlip(r, 2, 1, 2, () => 0));
    expect(hex(dkgVerifyTranscript(docs.dkg.anchor, quiet.ceremony, quiet.records, verify).mpk.toBytes())).toBe(c.outputs.mpk);
    expect(verifyInput(docs.dkg, reseal(x, start, digest, r => payloadFlip(r, 4, 1, 1, () => 3 + 95)))).toBe('InvalidRound');
  });
  test('genesis: corrupting the upheld R5 pair leaves nothing to reconstruct, so the R6 record is extra', () => {
    const c = dkg('genesis_2of3_selective_extraction'), x = inputOf(c), { digest, start } = startOf(c);
    expect(verifyInput(docs.dkg, reseal(x, start, digest, r => payloadFlip(r, 5, 1, 2, p => p.length - 1)))).toBe('InvalidRound');
  });
  test('reshare: B_0 byte → MalformedDeal; R3 value byte → InvalidAnswer; complaint version byte → MissingAnswer', () => {
    const verify = verifierOf(docs.reshare);
    const run = (x: TranscriptInput) => reshareVerifyTranscript(docs.reshare.anchor, x.ceremony, x.certificate!, x.records, verify);
    let c = reshare('reshare_2of3_to_3of4'), x = inputOf(c), s = startOf(c);
    let out = run(reseal(x, s.start, s.digest, r => payloadFlip(r, 1, 2, 1, () => 3 + 95)));
    expect([out.excluded, out.dealers]).toEqual([[{ member: 1, reason: 'MalformedDeal' }], [2, 3]]);
    c = reshare('refresh_2of3_answered_complaint'); x = inputOf(c); s = startOf(c);
    out = run(reseal(x, s.start, s.digest, r => payloadFlip(r, 3, 2, 1, () => 36)));
    expect([out.excluded, out.dealers]).toEqual([[{ member: 1, reason: 'InvalidAnswer' }], [2, 3]]);
    c = reshare('reshare_t_prime_complaints'); x = inputOf(c); s = startOf(c);
    out = run(reseal(x, s.start, s.digest, r => payloadFlip(r, 2, 1, 2, () => 0)));
    expect(out.excluded).toEqual([{ member: 3, reason: 'MissingAnswer' }]);
  });
  test('one appended byte over 4 MiB is LimitExceeded before any signature', () => {
    for (const doc of Object.values(docs)) {
      const x = inputOf(doc.cases[0]!);
      const size = x.records.reduce((n, r) => n + r.closure.body.length + r.closure.signature.length + r.messages.reduce((m, s) => m + s.body.length + s.signature.length, 0), 0);
      const pad = (total: number) => Array.from({ length: Math.ceil(total / 65536) }, (_, k) => ({ body: new Uint8Array(Math.min(65536, total - k * 65536)), signature: new Uint8Array(0) }));
      const over = clone(x); over.records[0]!.messages.push(...pad(4194304 - size + 1));
      const exact = clone(x); exact.records[0]!.messages.push(...pad(4194304 - size));
      expect(verifyInput(doc, over)).toBe('LimitExceeded');
      expect(verifyInput(doc, exact)).toBe('InvalidEncoding');
    }
  });
});

describe('real CLI reports the observed reason for a corrupted committed document', () => {
  for (const [kind, doc] of Object.entries(docs)) {
    test(kind, () => {
      const changed = structuredClone(doc), message = changed.cases[0]!.inputs.rounds[1]!.messages[0]!;
      message.signature = (message.signature[0] === '0' ? '1' : '0') + message.signature.slice(1);
      const result = Bun.spawnSync([process.execPath, cli, '/dev/stdin'], { env: process.env, stdin: Buffer.from(JSON.stringify(changed)), stdout: 'pipe', stderr: 'pipe', timeout: 30000 });
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(`${changed.cases[0]!.name}: computed error: observed "InvalidSignature"; expected null`);
    }, 30000);
  }
});

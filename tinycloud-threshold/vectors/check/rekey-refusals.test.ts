// The seven refusal cases of ../v1/dkg-rekey.json: owner-signed statements checked against inputs.current_certificate
// that must be refused at authorization, before any record is read. The expected codes below are written here, not read
// from the document; the checker recomputes them from the statement and certificate bytes.
import { describe, expect, test } from 'bun:test';
import { bytes, equal, hex, tagged } from './protocol.ts';
import { decodeCeremony, decodeCertificate } from './ceremony.ts';
import { inputOf, loadDoc, verifyInput, type TranscriptInput } from './probes.ts';
import { OWNER, sign } from './testkit.ts';
import { editDoc, hexFlip, loadJson, runCli, type Loose } from './cli-kit.ts';

const doc = loadDoc('dkg-rekey.json'), json = loadJson('dkg-rekey.json');
const EXPECTED: Record<string, string> = {
  rekey_3of3_outside_the_genesis_budget: 'UnsupportedFaultBudget',
  rekey_4of5_outside_the_genesis_budget: 'UnsupportedFaultBudget',
  rekey_names_another_current_certificate: 'InvalidCeremony',
  rekey_counter_not_incremented: 'InvalidCeremony',
  rekey_skips_an_epoch: 'InvalidCeremony',
  genesis_statement_presented_as_rekey: 'InvalidCeremony',
  rekey_transcript_under_another_generation: 'InvalidCeremony',
};
const names = Object.keys(EXPECTED);
const want = (name: string) => EXPECTED[name]!;
const refusal = (name: string) => doc.cases.find(c => c.name === name)!;
const index = (name: string) => doc.cases.findIndex(c => c.name === name);
const honest = doc.cases[0]!;

/** Byte offsets inside a ceremony body: 01 kind id:32 lp(network) lp(owner) option(current) t:u16 n:u16 rekey:u64 epoch:u64. */
function layout(body: Uint8Array) {
  const view = new DataView(body.buffer, body.byteOffset);
  let o = 34;
  o += 4 + view.getUint32(o);
  o += 4 + view.getUint32(o);
  const current = o + 1;
  o += body[o] === 1 ? 33 : 1;
  return { kind: 1, id: 2, current, t: o + 1, n: o + 3, rekey: o + 11, epoch: o + 19 };
}
/** The input with its ceremony statement edited and re-signed by the owner. */
function restated(x: TranscriptInput, change: (body: Uint8Array, at: ReturnType<typeof layout>) => void): TranscriptInput {
  const body = x.ceremony.body.slice();
  change(body, layout(body));
  return { ...x, ceremony: { body, signature: sign(OWNER, tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', body)) } };
}
const sameStatement = (a: TranscriptInput, b: TranscriptInput) => equal(a.ceremony.body, b.ceremony.body) && equal(a.ceremony.signature, b.ceremony.signature);

describe('the committed refusal cases', () => {
  test('are the seven cases after the original seven, each a typed refusal without outputs', () => {
    expect(doc.cases.length).toBe(14);
    expect(doc.cases.slice(7).map(c => c.name)).toEqual(names);
    for (const c of doc.cases.slice(7)) expect('outputs' in c).toBe(false);
  });
  test('every code is recomputed from the statement and the pinned certificate', () => {
    for (const name of names) expect([name, verifyInput(doc, inputOf(refusal(name)))]).toEqual([name, want(name)]);
  });
  test('each statement has the defect its name gives, read from the decoded bytes', () => {
    const view = (name: string) => {
      const x = inputOf(refusal(name));
      return { c: decodeCeremony(x.ceremony.body), cert: decodeCertificate(x.certificate!.body) };
    };
    for (const name of ['rekey_3of3_outside_the_genesis_budget', 'rekey_4of5_outside_the_genesis_budget']) {
      const { c, cert } = view(name);
      expect([c.kind, c.epoch, c.rekey, equal(c.current!, cert.digest)]).toEqual([4, cert.epoch + 1n, cert.rekey + 1n, true]);
    }
    expect([view(names[0]!).c.t, view(names[0]!).c.n, view(names[1]!).c.t, view(names[1]!).c.n]).toEqual([3, 3, 4, 5]);
    let v = view('rekey_names_another_current_certificate');
    expect([hex(v.c.current!), v.c.epoch, v.c.rekey]).toEqual(['07'.repeat(32), v.cert.epoch + 1n, v.cert.rekey + 1n]);
    v = view('rekey_counter_not_incremented');
    expect([equal(v.c.current!, v.cert.digest), v.c.epoch, v.c.rekey]).toEqual([true, v.cert.epoch + 1n, v.cert.rekey]);
    v = view('rekey_skips_an_epoch');
    expect([equal(v.c.current!, v.cert.digest), v.c.epoch, v.c.rekey]).toEqual([true, v.cert.epoch + 2n, v.cert.rekey + 1n]);
    v = view('genesis_statement_presented_as_rekey');
    expect([v.c.kind, v.c.current, v.c.epoch, v.c.rekey]).toEqual([1, undefined, 0n, 0n]);
    v = view('rekey_transcript_under_another_generation');
    // An honest re-key statement and transcript, checked against the later reshare certificate that the statement does not name.
    expect([v.c.kind, v.cert.epoch, v.cert.previousMpk === undefined, equal(v.cert.previous!, v.c.current!), equal(v.c.current!, decodeCertificate(inputOf(honest).certificate!.body).digest)])
      .toEqual([4, 1n, true, true, true]);
    expect(equal(inputOf(refusal('rekey_transcript_under_another_generation')).ceremony.body, inputOf(honest).ceremony.body)).toBe(true);
    // The two budget refusals carry no rounds; the other cases that name a pinned certificate carry the honest transcript.
    expect(doc.cases.slice(7).map(c => c.inputs.rounds.length)).toEqual([0, 0, 5, 5, 5, 0, 5]);
  });
});

describe('through the real CLI', () => {
  test('the committed document is accepted: every refusal is the expected one', () => {
    const r = runCli(json);
    expect(r.exitCode).toBe(0);
    for (const name of names) expect(r.stdout.toString()).toContain(`PASS ${name}`);
    expect(r.stdout.toString()).toContain('Re-key transcripts: 14/14');
  }, 60000);
  for (const name of names) {
    test(`${name} is refused with ${want(name)}: the CLI reports the computed code against a different declared one`, () => {
      const r = runCli(editDoc(json, d => { d.cases[index(name)]!.error = 'InvalidRound'; }));
      expect(r.exitCode).toBe(1);
      expect(r.stderr.toString()).toContain(`FAIL ${name}: computed error: observed "${want(name)}"; expected "InvalidRound"`);
    }, 60000);
  }
  test('an accepted result is never expected: declaring outputs for a refusal is a schema error, and dropping the error is one too', () => {
    for (const name of names) {
      const i = index(name);
      const r = runCli(editDoc(json, d => { delete d.cases[i]!.error; }));
      expect(r.exitCode).toBe(1);
      expect(r.stderr.toString()).toContain('FAIL schema:');
    }
  }, 60000);
});

describe('one-byte edits of each refusal case', () => {
  for (const name of names) {
    const i = index(name);
    const forCase = (change: (c: Loose['cases'][number]) => void) => runCli(editDoc(json, d => change(d.cases[i]!)));
    test(`${name}: statement (unsigned and re-signed), pinned certificate`, () => {
      // Statement body edited without the owner: the owner signature fails first, so the declared refusal no longer matches.
      let r = forCase(c => { c.inputs.ceremony.body = hexFlip(c.inputs.ceremony.body, 2); });
      expect(r.exitCode).toBe(1);
      expect(r.stderr.toString()).toContain(`FAIL ${name}: computed error: observed "InvalidSignature"; expected "${want(name)}"`);
      // Edited and re-signed by the owner: still refused for the same reason, but it is another statement, so the declared digests are stale.
      r = forCase(c => {
        const body = bytes(c.inputs.ceremony.body);
        body[2] = body[2]! ^ 1;
        c.inputs.ceremony = { body: hex(body), signature: hex(sign(OWNER, tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', body))) };
      });
      expect(r.exitCode).toBe(1);
      expect(r.stderr.toString()).toContain(`FAIL ${name}: ceremony digest:`);
      // Pinned certificate: a body byte (its signature no longer verifies) and a signature byte.
      for (const change of [
        (c: Loose['cases'][number]) => { const k = c.inputs.current_certificate; k.body = hexFlip(k.body, k.body.length / 2 - 40); },
        (c: Loose['cases'][number]) => { c.inputs.current_certificate.owner_signature = hexFlip(c.inputs.current_certificate.owner_signature); },
      ]) {
        r = forCase(change);
        expect(r.exitCode).toBe(1);
        expect(r.stderr.toString()).toContain(`FAIL ${name}: computed error: observed "`);
      }
    }, 120000);
  }
  test('an attached round is not read when authorization fails: any byte of any record leaves the refusal and its code unchanged', () => {
    for (const name of names) {
      const base = inputOf(refusal(name));
      for (const [k, r] of base.records.entries()) {
        for (const pick of [
          (x: TranscriptInput) => x.records[k]!.closure.body, (x: TranscriptInput) => x.records[k]!.closure.signature,
          (x: TranscriptInput) => x.records[k]!.messages[0]!.body, (x: TranscriptInput) => x.records[k]!.messages[r.messages.length - 1]!.signature,
        ]) {
          const x = inputOf(refusal(name));
          const target = pick(x);
          target[0] = target[0]! ^ 1;
          expect([name, k, verifyInput(doc, x)]).toEqual([name, k, want(name)]);
        }
      }
    }
  });
});

describe('repairing exactly the defect (and re-signing) reaches the next rule', () => {
  test('rekey_names_another_current_certificate, rekey_counter_not_incremented and rekey_skips_an_epoch become the honest statement; its transcript is then accepted', () => {
    const accepted = inputOf(honest);
    expect(verifyInput(doc, accepted)).toBe('ok');
    expect('outputs' in honest && 'qual' in honest.outputs ? honest.outputs.qual : undefined).toEqual([1, 2, 3]);
    const pinned = decodeCertificate(accepted.certificate!.body);
    const repairs: [string, (body: Uint8Array, at: ReturnType<typeof layout>) => void][] = [
      ['rekey_names_another_current_certificate', (b, at) => b.set(pinned.digest, at.current)],
      ['rekey_counter_not_incremented', (b, at) => { b[at.rekey] = 1; }],
      ['rekey_skips_an_epoch', (b, at) => { b[at.epoch] = 1; }],
    ];
    for (const [name, repair] of repairs) {
      const fixed = restated(inputOf(refusal(name)), repair);
      expect([name, sameStatement(fixed, accepted)]).toEqual([name, true]);
      expect([name, verifyInput(doc, fixed)]).toEqual([name, 'ok']);
      // With the defect repaired, one byte of an attached round now decides the outcome.
      const edited = restated(inputOf(refusal(name)), repair);
      edited.records[2]!.closure.signature[0] = edited.records[2]!.closure.signature[0]! ^ 1;
      expect([name, verifyInput(doc, edited)]).toEqual([name, 'InvalidSignature']);
    }
  });
  test('rekey_transcript_under_another_generation is accepted under the generation its statement names', () => {
    const x = inputOf(refusal('rekey_transcript_under_another_generation'));
    expect(verifyInput(doc, { ...x, certificate: inputOf(honest).certificate! })).toBe('ok');
  });
  test('the budget refusals pass the budget when t is lowered, and then need rounds', () => {
    const lowered: [string, number][] = [['rekey_3of3_outside_the_genesis_budget', 2], ['rekey_4of5_outside_the_genesis_budget', 3]];
    for (const [name, t] of lowered) {
      expect([name, verifyInput(doc, restated(inputOf(refusal(name)), (b, at) => { b[at.t] = t; }))]).toEqual([name, 'InvalidRound']);
    }
  });
  test('the genesis statement stays refused whatever one byte is repaired: its kind is the defect and it carries no pinned digest', () => {
    const x = inputOf(refusal('genesis_statement_presented_as_rekey'));
    expect(verifyInput(doc, restated(x, (b, at) => { b[at.kind] = 4; }))).toBe('InvalidCeremony');
    expect(verifyInput(doc, restated(x, (b, at) => { b[at.kind] = 2; }))).toBe('InvalidCeremony');
  });
});

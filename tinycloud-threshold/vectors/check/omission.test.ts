// TC-2226: the R6 reconstruction floor, R6 eligibility by own R4/R5 presence and the genesis/re-key activation budget.
// Transcripts and certificates are built from SPEC byte layouts in testkit.ts and signed by the fixture keys.
import { describe, expect, test } from 'bun:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { hex } from './protocol.ts';
import { dkgVerifyTranscript, type DkgOutput } from './dkg.ts';
import { decodeCertificate, type RoundRecord, type Statement } from './ceremony.ts';
import { verifyActivation, verifyCertificate, type SigningKeys, type VerifiedCertificate } from './certificates.ts';
import { activationFor, receiptFor } from './chain-kit.ts';
import { editDoc, loadJson, runCli, type Loose } from './cli-kit.ts';
import { checkTranscripts } from './transcripts.ts';
import {
  ANCHOR, G2_BASE, SEEDS, code, dkgSetup, expectedDkg, feldman, g2hex, msg, pair, pairs, poly, r6, replace, seal, signedCertificate, times, verify,
  type CertificateSpec, type DkgSetup, type Draft,
} from './testkit.ts';

const pin = signedCertificate({ t: 2, n: 3, coefficients: poly('omission-pin', 2) });
const rekey = (label: string, t: number, n: number) => dkgSetup(label, t, n, { kind: 4, current: pin.digest, epoch: 1n, rekey: 1n });
const KINDS = [['genesis', dkgSetup, undefined], ['re-key', rekey, pin]] as const;

function run(s: DkgSetup, rounds: Draft[][], pinned?: Statement): DkgOutput {
  return dkgVerifyTranscript(ANCHOR, s.ceremony, seal(s.digest, s.start, rounds).records, verify, pinned);
}
/** The sealed records with record k's owner closure signature zeroed (no longer authentic). */
function unsigned(s: DkgSetup, rounds: Draft[][], k: number): RoundRecord[] {
  return seal(s.digest, s.start, rounds).records.map((r, i) => i === k ? { ...r, closure: { ...r.closure, signature: new Uint8Array(64) } } : r);
}
function expectRecovered(out: DkgOutput, s: DkgSetup, reconstructed: number[]) {
  const all = s.dealers.map(d => d.index), e = expectedDkg(s.dealers, all, s.n);
  expect(out.qual).toEqual(all);
  expect(out.reconstructed).toEqual(reconstructed);
  expect(out.commitments.map(g2hex)).toEqual(e.commitments);
  expect(out.publicShares.map(g2hex)).toEqual(e.publicShares);
}

for (const [kind, setup, pinned] of KINDS) {
  describe(`${kind}: R6 floor (ExcessiveReconstruction)`, () => {
    test('3-of-5 at the floor: two reconstructed dealers leave t = 3 and are recovered', () => {
      const s = setup(`${kind}-floor-at`, 3, 5);
      expectRecovered(run(s, [...replace(replace(s, 4, 4), 4, 5), r6(s, [4, 5], [1, 2, 3])], pinned), s, [4, 5]);
    });
    test('3-of-5 below the floor: three reconstructed dealers abort after R5, with or without an R6 record', () => {
      const s = setup(`${kind}-floor-below`, 3, 5), rounds = replace(replace(replace(s, 4, 3), 4, 4), 4, 5);
      expect(code(() => run(s, rounds, pinned))).toBe('ExcessiveReconstruction');
      expect(code(() => run(s, [...rounds, r6(s, [3, 4, 5], [1, 2])], pinned))).toBe('ExcessiveReconstruction');
    });
    test('2-of-3: an upheld R5 complaint counts toward the floor like an extraction fault', () => {
      const s = setup(`${kind}-floor-upheld`, 2, 3), d3 = s.dealers[2]!;
      const wrong = replace(s, 4, 3, msg(3, feldman([d3.A[0]!, d3.A[1]!.add(G2_BASE)])));
      const upheld = replace(wrong, 5, 1, msg(1, pairs([[3, ...pair(d3, 1)]])));
      expectRecovered(run(s, [...upheld, r6(s, [3], [1, 2])], pinned), s, [3]);
      expect(code(() => run(s, replace(upheld, 4, 2), pinned))).toBe('ExcessiveReconstruction');
    });
    test('the floor counts QUAL, not n: a disqualified dealer lowers the margin', () => {
      const s = setup(`${kind}-floor-qual`, 3, 5), one = replace(replace(s, 1, 5), 4, 4);
      const out = run(s, [...one, r6(s, [4], [1, 2, 3])], pinned);
      expect(out.qual).toEqual([1, 2, 3, 4]);
      expect(out.reconstructed).toEqual([4]);
      expect(code(() => run(s, replace(one, 4, 3), pinned))).toBe('ExcessiveReconstruction');
    });
  });

  describe(`${kind}: fewer than t qualified dealers ends the transcript after R3`, () => {
    test('a later record, valid or not, is neither read nor authenticated: InsufficientQualified', () => {
      const s = setup(`${kind}-qual-after-r3`, 3, 5), alone = s.rounds.map((r, k) => k === 0 ? r.filter(d => d.index === 1) : r);
      const check = (records: RoundRecord[]) => code(() => dkgVerifyTranscript(ANCHOR, s.ceremony, records, verify, pinned));
      expect(code(() => run(s, alone.slice(0, 3), pinned))).toBe('InsufficientQualified');
      expect(code(() => run(s, alone.slice(0, 4), pinned))).toBe('InsufficientQualified');
      expect(check(unsigned(s, alone.slice(0, 4), 3))).toBe('InsufficientQualified');
      expect(code(() => run(s, [...alone, []], pinned))).toBe('InsufficientQualified');
      // R1–R3 are still authenticated: a bad R3 closure decides first.
      expect(check(unsigned(s, alone.slice(0, 4), 2))).toBe('InvalidSignature');
    });
  });

  describe(`${kind}: R6 values count only from senders with a unique R4 and R5`, () => {
    const s = setup(`${kind}-own-message`, 3, 5), d5 = s.dealers[4]!;
    const recovered = (rounds: Draft[][], senders: number[]) => run(s, [...rounds, r6(s, [5], senders)], pinned);
    const refused = (rounds: Draft[][], senders: number[]) => code(() => recovered(rounds, senders));
    /** The ineligible sender's Pedersen-valid R6 changes nothing with t eligible senders and cannot make up a missing t-th. */
    function ignored(rounds: Draft[][], eligible: number[], ineligible: number) {
      expectRecovered(recovered(rounds, eligible), s, [5]);
      expectRecovered(recovered(rounds, [...eligible, ineligible]), s, [5]);
      expect(refused(rounds, [...eligible.slice(0, 2), ineligible])).toBe('InsufficientRecovery');
    }
    test('an R6 from a member whose R4 is missing is ignored', () => {
      ignored(replace(s, 4, 5), [1, 2, 3], 5);
    });
    test('an R6 from a member whose R5 is missing is ignored', () => {
      ignored(replace(replace(s, 4, 5), 5, 4), [1, 2, 3], 4);
    });
    test('an R6 from a member with two different R4 is ignored', () => {
      ignored(replace(s, 4, 5, msg(5, feldman(d5.A)), msg(5, feldman([...d5.A].reverse()))), [1, 2, 3], 5);
    });
    test('an R6 from a member with two different R5 is ignored', () => {
      ignored(replace(replace(s, 4, 5), 5, 2, msg(2, pairs([])), msg(2, pairs([[1, ...pair(s.dealers[0]!, 2)]]))), [1, 3, 4], 2);
    });
    test('presence, not content: a byte-identical repeat is one envelope, and a malformed R4 is still present', () => {
      const repeated = replace(replace(s, 4, 5), 5, 1, msg(1, pairs([])), msg(1, pairs([])));
      expectRecovered(recovered(repeated, [1, 2, 3]), s, [5]);
      const malformed = replace(s, 4, 5, msg(5, feldman(d5.A.slice(0, 2))));
      expectRecovered(recovered(malformed, [1, 2, 5]), s, [5]);
    });
    test('only ineligible senders leave no values: InsufficientRecovery', () => {
      expect(refused(replace(s, 4, 5), [5])).toBe('InsufficientRecovery');
    });
    test('check order: a required R6 is authenticated before its values are read; a record after R6 is refused after reconstruction', () => {
      const rounds = replace(s, 4, 5);
      expect(code(() => run(s, rounds, pinned))).toBe('InvalidRound');
      expect(code(() => dkgVerifyTranscript(ANCHOR, s.ceremony, unsigned(s, [...rounds, r6(s, [5], [1, 2, 5])], 5), verify, pinned))).toBe('InvalidSignature');
      expect(code(() => run(s, [...rounds, r6(s, [5], [1, 2, 5]), []], pinned))).toBe('InsufficientRecovery');
      expect(code(() => run(s, [...rounds, r6(s, [5], [1, 2, 3]), []], pinned))).toBe('InvalidRound');
    });
    test('an R6 record that R5 does not require is not read: the floor or the round count decides', () => {
      const below = replace(replace(replace(s, 4, 3), 4, 4), 4, 5);
      expect(code(() => dkgVerifyTranscript(ANCHOR, s.ceremony, unsigned(s, [...below, r6(s, [3, 4, 5], [1, 2])], 5), verify, pinned))).toBe('ExcessiveReconstruction');
      expect(code(() => dkgVerifyTranscript(ANCHOR, s.ceremony, unsigned(s, [...s.rounds, r6(s, [5], [1, 2, 3])], 5), verify, pinned))).toBe('InvalidRound');
    });
  });
}

describe('activation budget of genesis and re-key candidates', () => {
  const keys: SigningKeys = new Map([...SEEDS].map(([did, seed]) => [did, ed25519.getPublicKey(seed)]));
  function certify(spec: CertificateSpec, previous?: VerifiedCertificate) {
    const c = signedCertificate(spec);
    return verifyCertificate(c.body, c.signature, ANCHOR, keys, previous);
  }
  /** verify_activation with receipts from `ready` and the owner's matching activation; 'ok' or the error code. */
  function activate(spec: CertificateSpec, cert: VerifiedCertificate, ready: number[], budget: number | null) {
    const receipts = ready.map(i => receiptFor(spec, { digest: cert.digest }, i));
    const activation = activationFor({ digest: cert.digest }, receipts);
    return code(() => verifyActivation(cert, receipts.map(r => ({ index: r.member, signature: r.signature })), budget, activation.signature, keys));
  }
  const all = (n: number) => Array.from({ length: n }, (_, k) => k + 1);
  const genesis35: CertificateSpec = { t: 3, n: 5, coefficients: poly('budget-genesis-3of5', 3) };
  const g35 = certify(genesis35);

  test('a 3-of-5 genesis needs b >= f = 2, even with every holder ready', () => {
    expect(activate(genesis35, g35, all(5), 1)).toBe('InvalidReadiness');
    expect(activate(genesis35, g35, all(5), 2)).toBe('ok');
    expect(activate(genesis35, g35, [1, 2, 4, 5], 2)).toBe('NotEnoughReady');
    expect(activate(genesis35, g35, all(5), null)).toBe('ok');
  });
  test('check order: receipts, then quorum and budget, then the ready count, then the activation statement', () => {
    const signed = all(5).map(i => receiptFor(genesis35, { digest: g35.digest }, i));
    const receipts = signed.map(r => ({ index: r.member, signature: r.signature }));
    const good = activationFor({ digest: g35.digest }, signed).signature;
    const run = (rs: typeof receipts, budget: number, signature: Uint8Array) => code(() => verifyActivation(g35, rs, budget, signature, keys));
    const forged = new Uint8Array(64);
    expect(run(receipts, 2, good)).toBe('ok');
    // A budget below f is refused before the ready count and before the activation signature.
    expect(run(receipts.slice(0, 3), 1, good)).toBe('InvalidReadiness');
    expect(run(receipts, 1, forged)).toBe('InvalidReadiness');
    expect(run(receipts, 2, forged)).toBe('InvalidSignature');
    // A bad receipt is refused before the ready count.
    expect(run([...receipts.slice(0, 2), receipts[1]!], 2, good)).toBe('InvalidReadiness');
    expect(run([receipts[0]!, { ...receipts[1]!, signature: forged }], 2, good)).toBe('InvalidReadiness');
    expect(run(receipts.slice(0, 4), 2, good)).toBe('NotEnoughReady');
  });
  test('3-of-4 has f = 1 and 2-of-3 has f = t − 1 = 1', () => {
    const genesis34: CertificateSpec = { t: 3, n: 4, coefficients: poly('budget-genesis-3of4', 3) };
    expect(activate(genesis34, certify(genesis34), all(4), 1)).toBe('ok');
    const genesis23: CertificateSpec = { t: 2, n: 3, coefficients: poly('budget-genesis-2of3', 2) };
    expect(activate(genesis23, certify(genesis23), all(3), 1)).toBe('ok');
  });
  test('a re-key candidate (previous master key present) needs b >= f; a reshare candidate does not', () => {
    const rekeyed: CertificateSpec = {
      t: 3, n: 5, coefficients: poly('budget-rekey-3of5', 3), epoch: 1n, rekey: 1n, previous: g35.digest, previousMpk: times(G2_BASE, genesis35.coefficients[0]!),
    };
    const r35 = certify(rekeyed, g35);
    expect(activate(rekeyed, r35, all(5), 1)).toBe('InvalidReadiness');
    expect(activate(rekeyed, r35, all(5), 2)).toBe('ok');
    const reshared: CertificateSpec = { t: 3, n: 5, coefficients: [genesis35.coefficients[0]!, ...poly('budget-reshare-3of5', 2)], epoch: 1n, previous: g35.digest };
    const s35 = certify(reshared, g35);
    expect(activate(reshared, s35, all(5), 1)).toBe('ok');
    expect(activate(reshared, s35, [1, 2, 3], 1)).toBe('NotEnoughReady');
  });
});

describe('dkg-omission.json', () => {
  const doc = loadJson('dkg-omission.json');
  // The committed fixture; its schema is enforced by checkTranscripts in the first test.
  const view = doc as Loose;

  test('every case is recomputed and agrees', () => {
    const report = checkTranscripts(doc);
    expect(report.kind).toBe('omission');
    expect(report.passed).toEqual(view.cases.map(c => c.name));
  });
  for (const kind of ['genesis', 'rekey']) {
    test(`${kind}: the chosen-key transcript verifies with nothing reconstructed, and its activation candidate carries that outcome`, () => {
      const chosen = view.cases.find(c => c.name === `${kind}_3of5_chosen_master_key`)!;
      expect(chosen.outputs.qual).toEqual([1, 2, 3, 4, 5]);
      expect(chosen.outputs.reconstructed).toEqual([]);
      for (const budget of [1, 2]) {
        const activation = view.cases.find(c => c.name === `${kind}_3of5_chosen_master_key_activation_budget_${budget}`)!;
        const cert = decodeCertificate(Buffer.from(activation.inputs.certificate.body, 'hex'));
        expect([cert.t, cert.n]).toEqual([3, 5]);
        expect(hex(cert.mpk.toBytes())).toBe(chosen.outputs.mpk);
        expect(cert.commitments.map(g2hex)).toEqual(chosen.outputs.commitments);
        expect(hex(cert.transcript)).toBe(chosen.outputs.transcript_hash);
        // LooseCase types `quorum` as the chain document's string; this document carries an object.
        expect<unknown>(activation.inputs.quorum).toEqual({ with_outage_budget: budget });
        expect(activation.inputs.receipts.map(r => r.member)).toEqual([1, 2, 4, 5]);
      }
    });
    test(`${kind}: an ignored R6 from a member without its R4 gives the outcome of the same transcript without that R6`, () => {
      const outputs = (name: string) => view.cases.find(c => c.name === `${kind}_3of5_${name}`)!.outputs;
      const late = outputs('r6_from_member_without_r4'), absent = outputs('member_without_r4_sends_no_r6');
      expect(late.reconstructed).toEqual([1]);
      expect({ ...late, transcript_hash: null }).toEqual({ ...absent, transcript_hash: null });
      expect(late.transcript_hash).not.toBe(absent.transcript_hash);
    });
  }
  test('the CLI reports a changed expected outcome instead of accepting it', () => {
    const edits = [
      ['genesis_3of5_reconstruction_floor', 'InvalidRound'], ['rekey_3of5_ineligible_r6_leaves_fewer_than_t_values', 'OwnMessageOmitted'],
      ['genesis_3of5_chosen_master_key_activation_budget_1', 'NotEnoughReady'],
    ];
    for (const [name, error] of edits) {
      const result = runCli(editDoc(doc, d => { d.cases.find(c => c.name === name)!.error = error; }));
      expect(result.exitCode).toBe(1);
      expect(result.stderr.toString()).toContain(`${name}: computed error`);
    }
  });
});

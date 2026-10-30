import { describe, expect, test } from 'bun:test';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { R, be, concat, type Bytes } from './protocol.ts';
import { reshareVerifyTranscript, type ReshareOutput } from './reshare.ts';
import type { RoundRecord, Statement } from './ceremony.ts';
import {
  ANCHOR, COHORT_DEALERS, COHORT_RECIPIENTS, G2_BASE, at, code, complaints, deal, did, expectedReshare, flip, g2hex,
  lagrange, reshareSetup, seal, signedCertificate, times, values, verify, type CeremonySpec, type Draft, type ReshareSetup,
} from './testkit.ts';

function run(s: ReshareSetup, rounds: Draft[][] = s.rounds, certificate: Statement = s.certificate): ReshareOutput {
  return reshareVerifyTranscript(ANCHOR, s.ceremony, certificate, seal(s.digest, s.start, rounds).records, verify);
}
const dealer = (index: number, payload: Bytes): Draft => ({ cohort: COHORT_DEALERS, index, payload });
const recipient = (index: number, payload: Bytes): Draft => ({ cohort: COHORT_RECIPIENTS, index, payload });
function replace(from: ReshareSetup | Draft[][], r: number, cohort: number, index: number, ...drafts: Draft[]): Draft[][] {
  return (Array.isArray(from) ? from : from.rounds).map((round, k) => k + 1 !== r ? round : [...round.filter(d => d.cohort !== cohort || d.index !== index), ...drafts]);
}
const recipients = (s: ReshareSetup) => Array.from({ length: s.n2 }, (_, k) => k + 1);
const commitmentsOf = (coefficients: readonly bigint[]) => coefficients.map(c => times(G2_BASE, c));
/** Replaces dealer i's polynomial and its R1 in place (R1 order decides D). */
function withDealing(s: ReshareSetup, i: number, coefficients: bigint[]): ReshareSetup {
  const dealings = s.dealings.map((d, k) => k + 1 === i ? coefficients : d);
  const payload = deal(commitmentsOf(coefficients), recipients(s), 32, i);
  return { ...s, dealings, rounds: s.rounds.map((r, k) => k !== 0 ? r : r.map(d => d.cohort === COHORT_DEALERS && d.index === i ? dealer(i, payload) : d)) };
}
function expectOutput(out: ReshareOutput, s: ReshareSetup, dealers: number[]) {
  const e = expectedReshare(s, dealers);
  expect(out.dealers).toEqual(dealers);
  expect(out.threshold).toBe(s.t2);
  expect(out.members).toBe(s.n2);
  expect(out.commitments.map(g2hex)).toEqual(e.commitments);
  expect(g2hex(out.mpk)).toBe(e.mpk);
  expect(out.publicShares.map(g2hex)).toEqual(e.publicShares);
}
const value = (s: ReshareSetup, i: number, j: number) => at(s.dealings[i - 1]!, j);

describe('honest redistribution', () => {
  test('2-of-3 → 3-of-4 keeps mpk; new shares match the scalar-domain expectation', () => {
    const s = reshareSetup('honest-reshare', 2, 3, 3, 4), out = run(s);
    expectOutput(out, s, [1, 2]);
    expect(out.excluded).toEqual([]);
    expect(out.transcriptHash).toEqual(seal(s.digest, s.start, s.rounds).hash);
  });
  test('refresh 2-of-3 → 2-of-3 keeps mpk', () => {
    const s = reshareSetup('honest-refresh', 2, 3, 2, 3, 3);
    expectOutput(run(s), s, [1, 2]);
  });
  test('D is the first t valid dealers in owner order of their first R1', () => {
    const s = reshareSetup('order', 2, 3, 3, 4);
    const reordered = s.rounds.map((r, k) => k === 0 ? [r[2]!, r[0]!, r[1]!, r[2]!] : r);
    expectOutput(run(s, reordered), s, [3, 1]);
  });
});

describe('exclusion reasons', () => {
  const s = reshareSetup('exclusions', 2, 3, 3, 4);
  test('MissingDeal and Equivocated round 1', () => {
    expect(run(s, replace(s, 1, COHORT_DEALERS, 1)).excluded).toEqual([{ member: 1, reason: 'MissingDeal' }]);
    const twice = replace(s, 1, COHORT_DEALERS, 1, dealer(1, deal(commitmentsOf(s.dealings[0]!), recipients(s), 32, 1)), dealer(1, deal(commitmentsOf(s.dealings[0]!), recipients(s), 32, 7)));
    const out = run(s, twice);
    expect(out.excluded).toEqual([{ member: 1, reason: 'Equivocated', round: 1 }]);
    expectOutput(out, s, [2, 3]);
  });
  const g = s.dealings[0]!;
  for (const [label, payload] of [
    ['B_0 is not pk_i', deal(commitmentsOf([(g[0]! + 1n) % R, g[1]!, g[2]!]), [1, 2, 3, 4])],
    ['t′+1 coefficients', deal(commitmentsOf([...g, 5n]), [1, 2, 3, 4])],
    ['identity top coefficient', deal(commitmentsOf([g[0]!, g[1]!, 0n]), [1, 2, 3, 4])],
    ['recipients 1..3', deal(commitmentsOf(g), [1, 2, 3])],
    ['trailing byte', concat(deal(commitmentsOf(g), [1, 2, 3, 4]), be(0n, 1))],
  ] as const) {
    test(`MalformedDeal: ${label}`, () => {
      expect(run(s, replace(s, 1, COHORT_DEALERS, 1, dealer(1, payload))).excluded).toEqual([{ member: 1, reason: 'MalformedDeal' }]);
    });
  }
  test('Equivocated round 3', () => {
    expect(run(s, replace(s, 3, COHORT_DEALERS, 2, dealer(2, values([])), dealer(2, values([[1, value(s, 2, 1)]])))).excluded)
      .toEqual([{ member: 2, reason: 'Equivocated', round: 3 }]);
  });
  test('t′ distinct complainers exclude, including the recipient whose index equals the dealer', () => {
    let rounds = s.rounds;
    for (const j of [1, 2, 3]) rounds = replace(rounds, 2, COHORT_RECIPIENTS, j, recipient(j, complaints([1])));
    expect(run(s, rounds).excluded).toEqual([{ member: 1, reason: 'Complaints' }]);
    let two = s.rounds;
    for (const j of [2, 3]) two = replace(two, 2, COHORT_RECIPIENTS, j, recipient(j, complaints([1])));
    expect(run(s, two).excluded).toEqual([{ member: 1, reason: 'MissingAnswer' }]);
  });
  test('valid answers replace; invalid answers exclude, required or not; omissions are MissingAnswer', () => {
    const complained = replace(s, 2, COHORT_RECIPIENTS, 2, recipient(2, complaints([1])));
    expectOutput(run(s, replace(complained, 3, COHORT_DEALERS, 1, dealer(1, values([[2, value(s, 1, 2)]])))), s, [1, 2]);
    expect(run(s, replace(complained, 3, COHORT_DEALERS, 1, dealer(1, values([[2, (value(s, 1, 2) + 1n) % R]])))).excluded).toEqual([{ member: 1, reason: 'InvalidAnswer' }]);
    expect(run(s, replace(s, 3, COHORT_DEALERS, 1, dealer(1, values([[3, 1n]])))).excluded).toEqual([{ member: 1, reason: 'InvalidAnswer' }]);
    expect(run(s, replace(complained, 3, COHORT_DEALERS, 1)).excluded).toEqual([{ member: 1, reason: 'MissingAnswer' }]);
    expect(run(s, replace(complained, 3, COHORT_DEALERS, 1, dealer(1, values([[2, value(s, 1, 2)], [5, 1n]])))).excluded).toEqual([{ member: 1, reason: 'MissingAnswer' }]);
  });
  test('R2 naming a dealer above the old n supplies no complaints', () => {
    expect(run(s, replace(s, 2, COHORT_RECIPIENTS, 2, recipient(2, complaints([1, 4])))).excluded).toEqual([]);
  });
  test('envelopes under the other cohort are authenticated but attribute nothing', () => {
    const r1AsRecipient = replace(s, 1, COHORT_DEALERS, 1, recipient(1, deal(commitmentsOf(g), recipients(s), 32, 1)));
    expect(run(s, r1AsRecipient).excluded).toEqual([{ member: 1, reason: 'MissingDeal' }]);
    let complaintsAsDealers = s.rounds;
    for (const i of [1, 2, 3]) complaintsAsDealers = replace(complaintsAsDealers, 2, COHORT_DEALERS, i, dealer(i, complaints([1])));
    expect(run(s, complaintsAsDealers).excluded).toEqual([]);
    expect(code(() => run(s, replace(s, 2, COHORT_DEALERS, 4, dealer(4, complaints([])))))).toBe('InvalidIndex');
  });
  test('rules 4–7 apply in order', () => {
    let three = s.rounds;
    for (const j of [1, 2, 3]) three = replace(three, 2, COHORT_RECIPIENTS, j, recipient(j, complaints([1])));
    expect(run(s, replace(three, 3, COHORT_DEALERS, 1, dealer(1, values([])), dealer(1, values([[2, value(s, 1, 2)]])))).excluded)
      .toEqual([{ member: 1, reason: 'Equivocated', round: 3 }]);
    expect(run(s, replace(three, 3, COHORT_DEALERS, 1, dealer(1, values([[2, 1n]])))).excluded).toEqual([{ member: 1, reason: 'Complaints' }]);
    const one = replace(s, 2, COHORT_RECIPIENTS, 2, recipient(2, complaints([1])));
    expect(run(s, replace(one, 3, COHORT_DEALERS, 1, dealer(1, values([[3, 1n]])))).excluded).toEqual([{ member: 1, reason: 'InvalidAnswer' }]);
  });
  test('fewer than t dealers is InsufficientQualified; record count must be 3', () => {
    const alone = s.rounds.map((r, k) => k === 0 ? r.filter(d => d.index === 1) : r);
    expect(code(() => run(s, alone))).toBe('InsufficientQualified');
    expect(code(() => run(s, s.rounds.slice(0, 2)))).toBe('InvalidRound');
    expect(code(() => run(s, [...s.rounds, []]))).toBe('InvalidRound');
  });
});

describe('entry checks', () => {
  test('ceremony kind, certificate binding, generation and refresh shape', () => {
    const base = reshareSetup('entry', 2, 3, 3, 4);
    const variant = (kind: number, spec: Partial<CeremonySpec>, t2 = 3, n2 = 4) => code(() => run(reshareSetup('entry', 2, 3, t2, n2, kind, spec)));
    expect(variant(1, { current: undefined, epoch: 0n })).toBe('InvalidCeremony');
    expect(variant(4, { rekey: 1n })).toBe('InvalidCeremony');
    expect(variant(2, { current: new Uint8Array(32) })).toBe('ContextMismatch');
    expect(variant(2, { current: undefined })).toBe('ContextMismatch');
    expect(variant(2, { epoch: 2n })).toBe('InvalidCeremony');
    expect(variant(2, { rekey: 1n })).toBe('InvalidCeremony');
    expect(variant(3, {}, 3, 3)).toBe('InvalidCeremony');
    expect(variant(3, { directory: [{ index: 1, did: did(1) }, { index: 2, did: did(2) }, { index: 3, did: did(9) }] }, 2, 3)).toBe('InvalidCeremony');
    expect(code(() => run(base, base.rounds, { ...base.certificate, signature: flip(base.certificate.signature, 5) }))).toBe('InvalidSignature');
    expect(code(() => run(base, base.rounds, { ...base.certificate, body: concat(base.certificate.body, be(0n, 1)) }))).toBe('InvalidEncoding');
    expect(code(() => run(base, base.rounds, signedCertificate({ t: 2, n: 3, coefficients: base.master, network: 'tinycloud:test:other' })))).toBe('InvalidCertificate');
  });
});

describe('identity rejections', () => {
  test('an identity new public share or top aggregate coefficient is IdentityPoint', () => {
    const s = reshareSetup('identity-reshare', 2, 3, 3, 4), Fr = bls.fields.Fr, D = [1, 2];
    const l1 = lagrange(1, D), l2 = lagrange(2, D), g1 = s.dealings[0]!, s2 = s.dealings[1]![0]!;
    const top = Fr.neg(Fr.mul(Fr.mul(l1, g1[2]!), Fr.inv(l2)));
    expect(code(() => run(withDealing(s, 2, [s2, s.dealings[1]![1]!, top])))).toBe('IdentityPoint');
    const target = Fr.neg(Fr.mul(Fr.mul(l1, at(g1, 4)), Fr.inv(l2))), c2 = s.dealings[1]![2]!;
    const c1 = Fr.mul(Fr.sub(Fr.sub(target, s2), Fr.mul(16n, c2)), Fr.inv(4n));
    const zeroShare = withDealing(s, 2, [s2, c1, c2]);
    expect(code(() => run(zeroShare))).toBe('IdentityPoint');
    expect(code(() => run(zeroShare, zeroShare.rounds.map((r, k) => k === 0 ? [r[1]!, r[2]!, r[0]!] : r)))).toBe('ok');
  });
});

describe('limits', () => {
  test('the 4 MiB bound precedes certificate and ceremony checks', () => {
    const s = reshareSetup('limits', 2, 3, 3, 4);
    const big: RoundRecord[] = Array.from({ length: 65 }, () => ({ closure: { body: new Uint8Array(98), signature: new Uint8Array(64) }, messages: [{ body: new Uint8Array(64374), signature: new Uint8Array(0) }] }));
    const bad: Statement = { body: new Uint8Array(1), signature: new Uint8Array(0) };
    expect(code(() => reshareVerifyTranscript(ANCHOR, bad, bad, big, verify))).toBe('LimitExceeded');
    expect(code(() => reshareVerifyTranscript(ANCHOR, s.ceremony, s.certificate, big.slice(0, 64), verify))).toBe('InvalidRound');
  });
});

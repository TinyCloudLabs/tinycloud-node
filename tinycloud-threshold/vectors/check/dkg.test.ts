import { describe, expect, test } from 'bun:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { R, be, concat, tagged, type Bytes } from './protocol.ts';
import { dkgVerifyTranscript, type DkgOutput } from './dkg.ts';
import { ed25519Verifier, type RoundRecord, type Statement } from './ceremony.ts';
import {
  ANCHOR, COHORT_DEALERS, COHORT_RECIPIENTS, G2_BASE, H, NETWORK, OWNER, SEEDS, alternateSignature, at, ceremonyBody, code,
  complaints, deal, did, dkgSetup, expectedDkg, feldman, flip, g2hex, nonCanonicalR, nonCanonicalS, pair, pairs, seal, sign,
  signedCeremony, times, verify, type DkgSetup, type Draft,
} from './testkit.ts';

function records(s: DkgSetup, rounds: Draft[][] = s.rounds): RoundRecord[] { return seal(s.digest, s.start, rounds).records; }
function run(s: DkgSetup, rounds: Draft[][] = s.rounds, ceremony: Statement = s.ceremony): DkgOutput {
  return dkgVerifyTranscript(ANCHOR, ceremony, records(s, rounds), verify);
}
const msg = (index: number, payload: Bytes): Draft => ({ cohort: COHORT_RECIPIENTS, index, payload });
/** Replaces sender `index`'s message(s) in round `r` (1-based) with the given drafts. */
function replace(from: DkgSetup | Draft[][], r: number, index: number, ...drafts: Draft[]): Draft[][] {
  return (Array.isArray(from) ? from : from.rounds).map((round, k) => k + 1 !== r ? round : [...round.filter(d => d.index !== index), ...drafts]);
}
function expectPublic(out: DkgOutput, s: DkgSetup, qual: number[]) {
  const e = expectedDkg(s.dealers, qual, s.n);
  expect(out.qual).toEqual(qual);
  expect(out.commitments.map(g2hex)).toEqual(e.commitments);
  expect(g2hex(out.mpk)).toBe(e.commitments[0]!);
  expect(out.publicShares.map(g2hex)).toEqual(e.publicShares);
}
/** Every member's R6 with its Pedersen-valid pair for each reconstructed dealer. */
function r6(s: DkgSetup, dealers: number[], senders = s.dealers.map(d => d.index)): Draft[] {
  return senders.map(j => msg(j, pairs(dealers.map(i => [i, ...pair(s.dealers[i - 1]!, j)] as const))));
}
/** Rebuilds dealer i with explicit coefficient vectors and regenerates its R1 and R4. */
function withDealer(s: DkgSetup, i: number, a: bigint[], b: bigint[]): DkgSetup {
  const d = { index: i, a, b, C: a.map((x, k) => times(G2_BASE, x).add(times(H, b[k]!))), A: a.map(x => times(G2_BASE, x)) };
  const dealers = s.dealers.map(x => x.index === i ? d : x), members = dealers.map(x => x.index);
  const next = { ...s, dealers };
  next.rounds = replace(next, 1, i, msg(i, deal(d.C, members, 64, i)));
  next.rounds = replace(next, 4, i, msg(i, feldman(d.A)));
  return next;
}

describe('honest genesis', () => {
  test('2-of-3 output matches scalar-domain expectation and the sealed transcript hash', () => {
    const s = dkgSetup('honest-2of3', 2, 3), out = run(s);
    expectPublic(out, s, [1, 2, 3]);
    expect(out.disqualified).toEqual([]);
    expect(out.reconstructed).toEqual([]);
    expect(out.transcriptHash).toEqual(seal(s.digest, s.start, s.rounds).hash);
  });
  test('byte-identical retransmissions and a second valid signature on one envelope are one message', () => {
    const s = dkgSetup('retransmit', 2, 3);
    const twice = s.rounds.map((round, k) => k === 1 ? [...round, round[1]!, { ...round[1]!, signature: (m: Bytes, signer: string) => alternateSignature(signer, m) }] : round);
    expectPublic(run(s, twice), s, [1, 2, 3]);
    expect(run(s, twice).disqualified).toEqual([]);
  });
  test('individual commitment coefficients may be the identity', () => {
    const base = dkgSetup('identity-coefficient', 2, 3), d = base.dealers[0]!;
    const s = withDealer(base, 1, [d.a[0]!, 0n], [d.b[0]!, 0n]);
    expectPublic(run(s), s, [1, 2, 3]);
  });
});

describe('R1–R3 and QUAL', () => {
  const s = dkgSetup('qual-2of3', 2, 3), members = [1, 2, 3];
  test('conflicting R1 disqualifies with round 1 and its R4 is ignored', () => {
    const out = run(s, replace(s, 1, 2, msg(2, deal(s.dealers[1]!.C, members, 64, 2)), msg(2, deal(s.dealers[1]!.C, members, 64, 9))));
    expect(out.disqualified).toEqual([{ member: 2, reason: 'Equivocated', round: 1 }]);
    expectPublic(out, s, [1, 3]);
  });
  test('missing R1 is MissingDeal', () => {
    expect(run(s, replace(s, 1, 3)).disqualified).toEqual([{ member: 3, reason: 'MissingDeal' }]);
  });
  for (const [label, payload] of [
    ['t+1 commitments', deal([...s.dealers[0]!.C, G2_BASE], members)],
    ['recipients 1..2', deal(s.dealers[0]!.C, [1, 2])],
    ['recipients 1..4', deal(s.dealers[0]!.C, [1, 2, 3, 4])],
    ['trailing byte', concat(deal(s.dealers[0]!.C, members), be(0n, 1))],
    ['version 2', flip(deal(s.dealers[0]!.C, members), 0, 3)],
    ['commitment off subgroup or curve', flip(deal(s.dealers[0]!.C, members), 3 + 95)],
    ['sealed dealing version 2', flip(deal(s.dealers[0]!.C, members), 3 + 2 * 96 + 2 + 2 + 4, 3)],
  ] as const) {
    test(`malformed R1 (${label}) is MalformedDeal`, () => {
      expect(run(s, replace(s, 1, 1, msg(1, payload))).disqualified).toEqual([{ member: 1, reason: 'MalformedDeal' }]);
    });
  }
  test('t distinct complainers disqualify even with valid answers', () => {
    const rounds = replace(replace(s, 2, 2, msg(2, complaints([1]))), 2, 3, msg(3, complaints([1])));
    const answered = rounds.map((r, k) => k === 2 ? [...r.filter(d => d.index !== 1), msg(1, pairs([[2, ...pair(s.dealers[0]!, 2)], [3, ...pair(s.dealers[0]!, 3)]]))] : r);
    expect(run(s, answered).disqualified).toEqual([{ member: 1, reason: 'Complaints' }]);
  });
  test('self-complaints are ignored', () => {
    expect(run(s, replace(s, 2, 1, msg(1, complaints([1])))).disqualified).toEqual([]);
  });
  test('a valid required answer keeps the dealer and the key', () => {
    const rounds = replace(replace(s, 2, 2, msg(2, complaints([1]))), 3, 1, msg(1, pairs([[2, ...pair(s.dealers[0]!, 2)]])));
    expectPublic(run(s, rounds), s, members);
  });
  test('an invalid answer is InvalidAnswer, required or not', () => {
    const [x, y] = pair(s.dealers[0]!, 2);
    const required = replace(replace(s, 2, 2, msg(2, complaints([1]))), 3, 1, msg(1, pairs([[2, (x + 1n) % R, y]])));
    expect(run(s, required).disqualified).toEqual([{ member: 1, reason: 'InvalidAnswer' }]);
    expect(run(s, replace(s, 3, 1, msg(1, pairs([[2, (x + 1n) % R, y]])))).disqualified).toEqual([{ member: 1, reason: 'InvalidAnswer' }]);
  });
  test('an unrequired valid answer is ignored', () => {
    expect(run(s, replace(s, 3, 1, msg(1, pairs([[2, ...pair(s.dealers[0]!, 2)]])))).disqualified).toEqual([]);
  });
  test('missing, omitted or malformed required answers are MissingAnswer', () => {
    const complained = replace(s, 2, 2, msg(2, complaints([1])));
    const variants: Draft[][][] = [
      complained.map((r, k) => k === 2 ? r.filter(d => d.index !== 1) : r),
      complained.map((r, k) => k === 2 ? [...r.filter(d => d.index !== 1), msg(1, pairs([[3, ...pair(s.dealers[0]!, 3)]]))] : r),
      complained.map((r, k) => k === 2 ? [...r.filter(d => d.index !== 1), msg(1, concat(pairs([[2, ...pair(s.dealers[0]!, 2)]]), be(0n, 1)))] : r),
      complained.map((r, k) => k === 2 ? [...r.filter(d => d.index !== 1), msg(1, pairs([[2, ...pair(s.dealers[0]!, 2)], [4, 1n, 1n]]))] : r),
    ];
    for (const rounds of variants) expect(run(s, rounds).disqualified).toEqual([{ member: 1, reason: 'MissingAnswer' }]);
  });
  test('an R3 naming a recipient above n is malformed, so its bad pair is not InvalidAnswer', () => {
    expect(run(s, replace(s, 3, 1, msg(1, pairs([[2, 1n, 1n], [4, 1n, 1n]])))).disqualified).toEqual([]);
  });
  test('R2 naming a dealer above n, or unsorted, supplies no complaints', () => {
    expect(run(s, replace(s, 2, 2, msg(2, complaints([1, 4])))).disqualified).toEqual([]);
    expect(run(s, replace(s, 2, 2, msg(2, concat(be(1n, 1), be(2n, 2), be(3n, 2), be(1n, 2))))).disqualified).toEqual([]);
  });
  test('conflicting R2 disqualifies its sender and supplies no complaints', () => {
    const out = run(s, replace(s, 2, 1, msg(1, complaints([])), msg(1, complaints([3]))));
    expect(out.disqualified).toEqual([{ member: 1, reason: 'Equivocated', round: 2 }]);
  });
  test('conflicting R3 is Equivocated round 3', () => {
    expect(run(s, replace(s, 3, 2, msg(2, pairs([])), msg(2, pairs([[1, ...pair(s.dealers[1]!, 1)]])))).disqualified)
      .toEqual([{ member: 2, reason: 'Equivocated', round: 3 }]);
  });
  test('the first applicable reason wins', () => {
    const malformedAndConflicting = replace(replace(s, 1, 1, msg(1, deal(s.dealers[0]!.C, [1, 2]))), 2, 1, msg(1, complaints([])), msg(1, complaints([2])));
    expect(run(s, malformedAndConflicting).disqualified).toEqual([{ member: 1, reason: 'MalformedDeal' }]);
    const conflictingAndComplained = replace(replace(replace(s, 2, 1, msg(1, complaints([])), msg(1, complaints([2]))), 2, 2, msg(2, complaints([1]))), 2, 3, msg(3, complaints([1])));
    expect(run(s, conflictingAndComplained).disqualified).toEqual([{ member: 1, reason: 'Equivocated', round: 2 }]);
  });
  test('fewer than t qualified dealers aborts only as the last record', () => {
    const alone = s.rounds.map((r, k) => k === 0 ? r.filter(d => d.index === 1) : r);
    expect(code(() => run(s, alone.slice(0, 3)))).toBe('InsufficientQualified');
    expect(code(() => run(s, alone))).toBe('InvalidRound');
    expect(code(() => run(s, alone.slice(0, 2)))).toBe('InvalidRound');
  });
  for (const length of [0, 15]) {
    test(`a ${length}-byte sealed ciphertext makes the deal malformed and changes QUAL`, () => {
      const out = run(s, replace(s, 1, 2, msg(2, deal(s.dealers[1]!.C, members, 64, 2, { 3: length }))));
      expect(out.disqualified).toEqual([{ member: 2, reason: 'MalformedDeal' }]);
      expectPublic(out, s, [1, 3]);
    });
  }
  test('a tag-only 16-byte sealed ciphertext is well formed', () => {
    expect(run(s, replace(s, 1, 2, msg(2, deal(s.dealers[1]!.C, members, 64, 2, { 3: 16 })))).disqualified).toEqual([]);
  });
  test('rules 5–8 apply in order', () => {
    const two = replace(replace(s, 2, 2, msg(2, complaints([1]))), 2, 3, msg(3, complaints([1])));
    expect(run(s, replace(two, 3, 1)).disqualified).toEqual([{ member: 1, reason: 'Complaints' }]);
    expect(run(s, replace(two, 3, 1, msg(1, pairs([[2, 1n, 1n]])))).disqualified).toEqual([{ member: 1, reason: 'Complaints' }]);
    expect(run(s, replace(two, 3, 1, msg(1, pairs([])), msg(1, pairs([[2, ...pair(s.dealers[0]!, 2)]])))).disqualified)
      .toEqual([{ member: 1, reason: 'Equivocated', round: 3 }]);
    const one = replace(s, 2, 2, msg(2, complaints([1])));
    expect(run(s, replace(one, 3, 1, msg(1, pairs([[3, 1n, 1n]])))).disqualified).toEqual([{ member: 1, reason: 'InvalidAnswer' }]);
  });
});

describe('R4–R6 extraction and reconstruction', () => {
  const s = dkgSetup('extract-2of3', 2, 3), members = [1, 2, 3];
  const faults: [string, Draft[]][] = [
    ['missing', []],
    ['conflicting', [msg(3, feldman(s.dealers[2]!.A)), msg(3, feldman([...s.dealers[2]!.A].reverse()))]],
    ['wrong count', [msg(3, feldman(s.dealers[2]!.A.slice(0, 1)))]],
    ['malformed', [msg(3, flip(feldman(s.dealers[2]!.A), 3 + 95))]],
  ];
  for (const [label, drafts] of faults) {
    test(`${label} R4 is an extraction fault recovered by R6; the dealer stays in QUAL`, () => {
      const faulted = replace(s, 4, 3, ...drafts);
      const out = run(s, [...faulted, r6(s, [3])]);
      expect(out.reconstructed).toEqual([3]);
      expectPublic(out, s, members);
      expect(code(() => run(s, faulted))).toBe('InvalidRound');
    });
  }
  test('an upheld R5 complaint forces reconstruction of the genuine contribution', () => {
    const wrong = [s.dealers[2]!.A[0]!, s.dealers[2]!.A[1]!.add(G2_BASE)];
    const rounds = replace(replace(s, 4, 3, msg(3, feldman(wrong))), 5, 1, msg(1, pairs([[3, ...pair(s.dealers[2]!, 1)]])));
    const out = run(s, [...rounds, r6(s, [3])]);
    expect(out.reconstructed).toEqual([3]);
    expectPublic(out, s, members);
  });
  test('R5 entries that are self-directed, Pedersen-invalid or against a Feldman-valid dealer are not upheld', () => {
    const wrong = replace(s, 4, 3, msg(3, feldman([s.dealers[2]!.A[0]!, s.dealers[2]!.A[1]!.add(G2_BASE)])));
    const [x, y] = pair(s.dealers[2]!, 1);
    for (const rounds of [
      replace(wrong, 5, 3, msg(3, pairs([[3, ...pair(s.dealers[2]!, 3)]]))),
      replace(wrong, 5, 1, msg(1, pairs([[3, x, (y + 1n) % R]]))),
      replace(s, 5, 1, msg(1, pairs([[3, x, y]]))),
    ]) {
      expect(run(s, rounds).reconstructed).toEqual([]);
      expect(code(() => run(s, [...rounds, r6(s, [3])]))).toBe('InvalidRound');
    }
  });
  test('fewer than t Pedersen-valid R6 values is InsufficientRecovery', () => {
    const faulted = replace(s, 4, 3);
    expect(code(() => run(s, [...faulted, r6(s, [3], [1])]))).toBe('InsufficientRecovery');
    const [x, y] = pair(s.dealers[2]!, 2);
    expect(code(() => run(s, [...faulted, [...r6(s, [3], [1]), msg(2, pairs([[3, x, (y + 1n) % R]]))]]))).toBe('InsufficientRecovery');
    const conflicting = [...r6(s, [3], [1, 2]), msg(2, pairs([]))];
    expect(code(() => run(s, [...faulted, conflicting]))).toBe('InsufficientRecovery');
    expectPublic(run(s, [...faulted, [...conflicting, ...r6(s, [3], [3])]]), s, members);
  });
  test('3-of-5 recovers from the lowest Pedersen-valid senders despite two silent members', () => {
    const big = dkgSetup('extract-3of5', 3, 5);
    const out = run(big, [...replace(big, 4, 5), r6(big, [5], [1, 2, 3])]);
    expect(out.reconstructed).toEqual([5]);
    expectPublic(out, big, [1, 2, 3, 4, 5]);
  });
});

describe('identity rejections', () => {
  const base = dkgSetup('identity-2of3', 2, 3), [d1, d2, d3] = base.dealers;
  test('identity mpk, top aggregate coefficient or public share is IdentityPoint', () => {
    const zeroMpk = withDealer(base, 3, [(2n * R - d1!.a[0]! - d2!.a[0]!) % R, d3!.a[1]!], d3!.b);
    const zeroTop = withDealer(base, 3, [d3!.a[0]!, (2n * R - d1!.a[1]! - d2!.a[1]!) % R], d3!.b);
    const zeroShare = withDealer(base, 3, [(3n * R - at(d1!.a, 1) - at(d2!.a, 1) - d3!.a[1]!) % R, d3!.a[1]!], d3!.b);
    for (const s of [zeroMpk, zeroTop, zeroShare]) expect(code(() => run(s))).toBe('IdentityPoint');
  });
});

describe('ceremony, round structure and limits', () => {
  const s = dkgSetup('structure-2of3', 2, 3);
  const verifyWith = (ceremony: Statement, rs: RoundRecord[]) => code(() => dkgVerifyTranscript(ANCHOR, ceremony, rs, verify));
  test('ceremony anchor, kind, budget, signature and encoding', () => {
    expect(verifyWith(signedCeremony({ kind: 1, t: 2, n: 3, network: 'tinycloud:test:other' }), [])).toBe('InvalidCeremony');
    expect(verifyWith(signedCeremony({ kind: 1, t: 2, n: 3, owner: did(1) }, did(1)), [])).toBe('InvalidCeremony');
    expect(verifyWith(signedCeremony({ kind: 2, t: 2, n: 3, current: new Uint8Array(32), epoch: 1n }), [])).toBe('InvalidCeremony');
    expect(verifyWith(signedCeremony({ kind: 1, t: 2, n: 3, epoch: 1n }), [])).toBe('InvalidCeremony');
    expect(verifyWith(signedCeremony({ kind: 1, t: 2, n: 3, rekey: 1n }), [])).toBe('InvalidCeremony');
    expect(verifyWith(signedCeremony({ kind: 1, t: 2, n: 3, current: new Uint8Array(32) }), [])).toBe('InvalidCeremony');
    expect(verifyWith(signedCeremony({ kind: 1, t: 3, n: 4 }), [])).toBe('UnsupportedFaultBudget');
    expect(verifyWith({ ...s.ceremony, signature: flip(s.ceremony.signature, 0) }, [])).toBe('InvalidSignature');
    expect(verifyWith({ ...s.ceremony, body: concat(s.ceremony.body, be(0n, 1)) }, [])).toBe('InvalidEncoding');
    expect(verifyWith(signedCeremony({ kind: 1, t: 2, n: 3, directory: [{ index: 1, did: did(1) }, { index: 2, did: did(1) }, { index: 3, did: did(3) }] }), [])).toBe('InvalidEncoding');
    expect(verifyWith(signedCeremony({ kind: 1, t: 2, n: 3, directory: [{ index: 1, did: did(1) }, { index: 2, did: did(2) }, { index: 4, did: did(4) }] }), [])).toBe('InvalidEncoding');
    const marker = ceremonyBody({ kind: 1, t: 2, n: 3 });
    marker[34 + 4 + NETWORK.length + 4 + OWNER.length] = 2;
    expect(verifyWith({ body: marker, signature: sign(OWNER, tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', marker)) }, [])).toBe('InvalidEncoding');
    expect(verifyWith({ ...s.ceremony, signature: new Uint8Array(513) }, [])).toBe('InvalidEncoding');
  });
  test('record count, closure binding and ordered-list commitment', () => {
    const rs = records(s);
    expect(code(() => run(s, [...s.rounds, r6(s, []), []]))).toBe('InvalidRound');
    expect(verifyWith(s.ceremony, rs.slice(0, 4))).toBe('InvalidRound');
    expect(code(() => dkgVerifyTranscript(ANCHOR, s.ceremony, seal(s.digest, new Uint8Array(32), s.rounds).records, verify))).toBe('InvalidRound');
    expect(verifyWith(s.ceremony, [rs[1]!, rs[0]!, ...rs.slice(2)])).toBe('InvalidRound');
    const swapped = { ...rs[1]!, messages: [rs[1]!.messages[1]!, rs[1]!.messages[0]!, rs[1]!.messages[2]!] };
    expect(verifyWith(s.ceremony, [rs[0]!, swapped, ...rs.slice(2)])).toBe('InvalidRound');
  });
  test('envelope binding, signer resolution and strict signatures', () => {
    const at2 = (d: Draft) => run(s, s.rounds.map((r, k) => k === 1 ? [...r, d] : r));
    expect(code(() => at2({ ...msg(1, complaints([])), round: 3 }))).toBe('InvalidRound');
    expect(code(() => at2({ ...msg(1, complaints([])), ceremony: new Uint8Array(32) }))).toBe('InvalidRound');
    expect(code(() => at2(msg(4, complaints([]))))).toBe('InvalidIndex');
    expect(code(() => at2(msg(0, complaints([]))))).toBe('InvalidIndex');
    expect(code(() => at2({ cohort: COHORT_DEALERS, index: 1, payload: complaints([]) }))).toBe('InvalidIndex');
    expect(code(() => at2({ ...msg(1, complaints([])), signer: did(2) }))).toBe('InvalidSignature');
    expect(code(() => at2({ ...msg(1, complaints([2])), signature: (m: Bytes, signer: string) => nonCanonicalS(alternateSignature(signer, m)) }))).toBe('InvalidSignature');
    const preimage = tagged('TC-THRESHOLD-V1-CEREMONY-MSG', new Uint8Array([1, 2, 3])), zip215Only = nonCanonicalR(did(1), preimage);
    expect(ed25519.verify(zip215Only, preimage, ed25519.getPublicKey(SEEDS.get(did(1))!), { zip215: true })).toBe(true);
    expect(verify(did(1), preimage, zip215Only)).toBe(false);
    expect(code(() => at2({ ...msg(1, complaints([2])), signature: (m: Bytes, signer: string) => nonCanonicalR(signer, m) }))).toBe('InvalidSignature');
    const identityKey = new Uint8Array(32); identityKey[0] = 1;
    const smallOrder = concat(ed25519.Point.BASE.multiply(5n).toBytes(), new Uint8Array([5, ...new Uint8Array(31)]));
    expect(ed25519.verify(smallOrder, preimage, identityKey, { zip215: true })).toBe(true);
    expect(ed25519Verifier(new Map([['small', identityKey]]))('small', preimage, smallOrder)).toBe(false);
  });
  test('per-message and signature caps', () => {
    expect(code(() => run(s, replace(s, 2, 1, msg(1, new Uint8Array(65536)))))).toBe('InvalidEncoding');
    expect(code(() => run(s, replace(s, 2, 1, { ...msg(1, complaints([])), signature: () => new Uint8Array(513) })))).toBe('InvalidEncoding');
    const rs = records(s);
    expect(code(() => dkgVerifyTranscript(ANCHOR, s.ceremony, [{ ...rs[0]!, closure: { ...rs[0]!.closure, signature: new Uint8Array(513) } }, ...rs.slice(1)], verify))).toBe('InvalidEncoding');
  });
  test('the 4 MiB transcript bound is checked before the ceremony and any signature', () => {
    const garbage = (size: number): RoundRecord => ({ closure: { body: new Uint8Array(98), signature: new Uint8Array(64) }, messages: [{ body: new Uint8Array(size), signature: new Uint8Array(0) }] });
    const fill = (total: number) => { const per = 65536, k = Math.floor((total - 162) / per); return [...Array.from({ length: k }, () => garbage(per - 162)), garbage(total - k * (per - 162 + 162) - 162)]; };
    const bad: Statement = { body: new Uint8Array(1), signature: new Uint8Array(0) };
    expect(verifyWith(bad, fill(4194305))).toBe('LimitExceeded');
    expect(verifyWith(bad, fill(4194304))).toBe('InvalidEncoding');
    expect(verifyWith(s.ceremony, fill(4194304))).toBe('InvalidRound');
  });
});

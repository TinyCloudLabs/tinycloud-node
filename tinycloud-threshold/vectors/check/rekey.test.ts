// Re-key DKG (S0.5 appendix): the S0.3 GJKR rules under an owner-authorized kind-4 ceremony pinned to
// the current certificate. Every adversarial input is built here, signed by the fixture owner, and
// sent through the same entry point as the honest transcripts.
import { describe, expect, test } from 'bun:test';
import { R, be, concat, equal, hex, tagged, type Bytes } from './protocol.ts';
import { dkgInitialTranscript, dkgVerifyTranscript, type DkgOutput } from './dkg.ts';
import { reshareVerifyTranscript } from './reshare.ts';
import { transcriptUpdate, verifyClosedRound, COHORT, type RoundRecord, type Statement } from './ceremony.ts';
import {
  ANCHOR, COHORT_DEALERS, G2_BASE, NETWORK, OWNER, at, code, complaints, did, dkgSetup, expectedDkg, feldman, flip, g2hex, msg, pair, pairs,
  poly, r6, replace, seal, sign, signedCeremony, signedCertificate, times, verify, withDealer, type CeremonySpec, type DkgSetup, type Draft,
} from './testkit.ts';

const PIN_COEFFICIENTS = poly('rekey-pin', 2);
const pin = signedCertificate({ t: 2, n: 3, coefficients: PIN_COEFFICIENTS });
/** Honest re-key under the genesis-level pin: epoch 1, re-key counter 1. */
function rekey(label: string, t: number, n: number, spec: Partial<CeremonySpec> = {}, current: { digest: Bytes } = pin): DkgSetup {
  return dkgSetup(label, t, n, { kind: 4, current: current.digest, epoch: 1n, rekey: 1n, ...spec });
}
function run(s: DkgSetup, rounds: Draft[][] = s.rounds, current: Statement | null = pin, ceremony: Statement = s.ceremony): DkgOutput {
  return dkgVerifyTranscript(ANCHOR, ceremony, seal(s.digest, s.start, rounds).records, verify, current ?? undefined);
}
const refuse = (s: DkgSetup, rounds: Draft[][] = s.rounds, current: Statement | null = pin, ceremony: Statement = s.ceremony) => code(() => run(s, rounds, current, ceremony));
function expectPublic(out: DkgOutput, s: DkgSetup, qual: number[]) {
  const e = expectedDkg(s.dealers, qual, s.n);
  expect(out.qual).toEqual(qual);
  expect(out.commitments.map(g2hex)).toEqual(e.commitments);
  expect(g2hex(out.mpk)).toBe(e.commitments[0]!);
  expect(out.publicShares.map(g2hex)).toEqual(e.publicShares);
}

describe('honest re-key', () => {
  for (const [t, n] of [[2, 3], [3, 4]] as const) {
    test(`${t}-of-${n} output matches the scalar-domain expectation and the sealed transcript hash`, () => {
      const s = rekey(`honest-${t}of${n}`, t, n), out = run(s);
      expectPublic(out, s, Array.from({ length: n }, (_, k) => k + 1));
      expect(out.disqualified).toEqual([]);
      expect(out.reconstructed).toEqual([]);
      expect(out.transcriptHash).toEqual(seal(s.digest, s.start, s.rounds).hash);
      expect(out.ceremony.kind).toBe(4);
      // Same H0 label as genesis.
      expect(hex(out.initialTranscript)).toBe(hex(tagged('TC-THRESHOLD-V1-DKG-START', s.digest)));
      expect(hex(dkgInitialTranscript(s.digest))).toBe(hex(s.start));
    });
  }
  test('the recipient directory is chosen freely: new members need not be members of the current certificate', () => {
    const s = rekey('fresh-members', 2, 3, { directory: [1, 2, 3].map(i => ({ index: i, did: did(i + 6) })) });
    const signed = s.rounds.map(r => r.map(d => ({ ...d, signer: did(d.index + 6) })));
    expectPublic(run(s, signed), s, [1, 2, 3]);
  });
  test('the pinned certificate may itself be a later generation; counters are checked against it', () => {
    const later = signedCertificate({ t: 3, n: 4, genesisT: 3, rekey: 2n, epoch: 4n, coefficients: poly('later', 3), previous: new Uint8Array(32).fill(9) });
    const s = rekey('later-pin', 2, 3, { epoch: 5n, rekey: 3n }, later);
    expectPublic(run(s, s.rounds, later), s, [1, 2, 3]);
    expect(refuse(rekey('later-stale', 2, 3, { epoch: 1n, rekey: 1n }, later), undefined, later)).toBe('InvalidCeremony');
  });
});

describe('F1: the genesis fault budget applies to the new threshold of a re-key', () => {
  const refused: [number, number][] = [[2, 2], [3, 3], [4, 4], [4, 5], [4, 6], [5, 8]];
  for (const [t, n] of refused) {
    test(`${t}-of-${n} is UnsupportedFaultBudget before any dealing, with and without honest records`, () => {
      const s = rekey(`f1-${t}of${n}`, t, n);
      expect(refuse(s)).toBe('UnsupportedFaultBudget');
      expect(refuse(s, [])).toBe('UnsupportedFaultBudget');
    });
  }
  test('shapes inside the budget pass the entry check and reach the round rules', () => {
    for (const [t, n] of [[2, 3], [3, 4], [2, 4], [3, 5], [4, 7], [5, 9]] as const) {
      expect(refuse(rekey(`f1-ok-${t}of${n}`, t, n), [])).toBe('InvalidRound');
    }
  });
  test('the budget is independent of the old threshold', () => {
    const old = signedCertificate({ t: 3, n: 4, coefficients: poly('old-3of4', 3) });
    expect(refuse(rekey('f1-from-3of4', 4, 5, {}, old), [], old)).toBe('UnsupportedFaultBudget');
    expect(refuse(rekey('f1-to-2of3', 2, 3, {}, old), [], old)).toBe('InvalidRound');
    const wide = signedCertificate({ t: 2, n: 8, coefficients: poly('old-2of8', 2) });
    expect(refuse(rekey('f1-from-2of8', 5, 8, {}, wide), [], wide)).toBe('UnsupportedFaultBudget');
  });
  test('3-of-4 and 2-of-3 re-keys are accepted with a faulty member', () => {
    const s = rekey('f1-3of4-faulty', 3, 4), d4 = s.dealers[3]!;
    const wrong = [d4.A[0]!, d4.A[1]!.add(G2_BASE), d4.A[2]!];
    const rounds = [...replace(replace(s, 4, 4, msg(4, feldman(wrong))), 5, 1, msg(1, pairs([[4, ...pair(d4, 1)]]))), r6(s, [4], [1, 2, 3])];
    const out = run(s, rounds);
    expect(out.reconstructed).toEqual([4]);
    expectPublic(out, s, [1, 2, 3, 4]);
  });
  test('3-of-5 with two corrupt members reconstructs the genuine master key', () => {
    const s = rekey('f1-3of5', 3, 5), [d4, d5] = [s.dealers[3]!, s.dealers[4]!], honest = [1, 2, 3];
    const bad = (d: typeof d4) => msg(d.index, feldman([d.A[0]!, d.A[1]!.add(G2_BASE), d.A[2]!]));
    // The corrupt dealers publish R4 vectors that fail every honest check and stay silent afterwards.
    let rounds = replace(replace(s, 4, 4, bad(d4)), 4, 5, bad(d5));
    rounds = [...rounds.slice(0, 4), rounds[4]!.map(m => honest.includes(m.index) ? msg(m.index, pairs([[4, ...pair(d4, m.index)], [5, ...pair(d5, m.index)]])) : msg(m.index, pairs([])))];
    const out = run(s, [...rounds, r6(s, [4, 5], honest)]);
    expect(out.reconstructed).toEqual([4, 5]);
    expect(out.disqualified).toEqual([]);
    expectPublic(out, s, [1, 2, 3, 4, 5]);
    const without = expectedDkg(s.dealers, [1, 2, 3], 5);
    expect(g2hex(out.mpk)).not.toBe(without.commitments[0]!);
    // Corrupt dealers that vanish after R1 (no R4, R5 or R6) are recovered the same way.
    const quiet = [s.rounds[0]!, s.rounds[1]!, s.rounds[2]!, s.rounds[3]!.filter(m => honest.includes(m.index)), s.rounds[4]!.filter(m => honest.includes(m.index)), r6(s, [4, 5], honest)];
    const silent = run(s, quiet);
    expect(silent.reconstructed).toEqual([4, 5]);
    expectPublic(silent, s, [1, 2, 3, 4, 5]);
    // With only two honest R6 senders there are fewer than t values.
    expect(refuse(s, [...quiet.slice(0, 5), r6(s, [4, 5], [1, 2])])).toBe('InsufficientRecovery');
  });
});

describe('F2: selective extraction under a re-key', () => {
  const s = rekey('f2-2of3', 2, 3), d3 = s.dealers[2]!;
  // Passes member 1's Feldman check (A_0 + A_1 is unchanged) but fails member 2's.
  const selective = [d3.A[0]!.add(G2_BASE), d3.A[1]!.subtract(G2_BASE)];
  const faulted = replace(replace(s, 4, 3, msg(3, feldman(selective))), 5, 2, msg(2, pairs([[3, ...pair(d3, 2)]])));
  test('the upheld R5 complaint forces R6; the dealer stays in QUAL and its genuine contribution is recovered', () => {
    const out = run(s, [...faulted, r6(s, [3])]);
    expect(out.reconstructed).toEqual([3]);
    expect(out.disqualified).toEqual([]);
    expectPublic(out, s, [1, 2, 3]);
  });
  test('barrier: nobody finishes before closed R5, and a required R6 cannot be skipped', () => {
    expect(refuse(s, faulted.slice(0, 4))).toBe('InvalidRound');
    expect(refuse(s, faulted)).toBe('InvalidRound');
    expect(refuse(s, [...faulted, r6(s, [3]), r6(s, [3])])).toBe('InvalidRound');
    expect(refuse(s, s.rounds.slice(0, 4))).toBe('InvalidRound');
  });
  test('a complaint that is not upheld leaves nothing to reconstruct, so an R6 record is extra', () => {
    expect(run(s, replace(s, 5, 2, msg(2, pairs([[3, ...pair(d3, 2)]])))).reconstructed).toEqual([]);
    expect(refuse(s, [...replace(s, 5, 2, msg(2, pairs([[3, ...pair(d3, 2)]]))), r6(s, [3])])).toBe('InvalidRound');
  });
  test('fewer than t Pedersen-valid R6 values is InsufficientRecovery', () => {
    expect(refuse(s, [...faulted, r6(s, [3], [1])])).toBe('InsufficientRecovery');
    expect(refuse(s, [...faulted, r6(s, [3], [])])).toBe('InsufficientRecovery');
  });
  test('without the selective R4 the same transcript needs no R6', () => {
    expectPublic(run(s), s, [1, 2, 3]);
  });
});

describe('F3: recipient keys are ceremony-scoped and bound into the ceremony digest', () => {
  const s = rekey('f3-3of4', 3, 4), digestOf = (c: Statement) => tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', c.body);
  const key = new Uint8Array(32).fill(0xee);
  const altered: [string, Statement][] = [
    ['HPKE key of member 2', signedCeremony({ kind: 4, t: 3, n: 4, id: sha(s), current: pin.digest, epoch: 1n, rekey: 1n, hpke: { 2: key } })],
    ['HPKE key of member 4', signedCeremony({ kind: 4, t: 3, n: 4, id: sha(s), current: pin.digest, epoch: 1n, rekey: 1n, hpke: { 4: key } })],
    ['swapped directory DIDs', signedCeremony({ kind: 4, t: 3, n: 4, id: sha(s), current: pin.digest, epoch: 1n, rekey: 1n, directory: [2, 1, 3, 4].map((d, k) => ({ index: k + 1, did: did(d) })) })],
  ];
  function sha(setup: DkgSetup): Bytes { return setup.ceremony.body.slice(2, 34); }
  for (const [label, ceremony] of altered) {
    test(`${label}: new digest; the owner signature does not carry over and every closed round names the old digest`, () => {
      const digest = digestOf(ceremony);
      expect(equal(digest, s.digest)).toBe(false);
      // Edited without re-signing: the owner signature fails.
      expect(refuse(s, s.rounds, pin, { body: ceremony.body, signature: s.ceremony.signature })).toBe('InvalidSignature');
      // Re-signed by the owner: a different ceremony, so the old transcript does not verify under it.
      expect(refuse(s, s.rounds, pin, ceremony)).toBe('InvalidRound');
      const records = seal(s.digest, s.start, s.rounds).records;
      let previous = s.start;
      for (const [k, record] of records.entries()) {
        expect(code(() => verifyClosedRound(digest, k + 1, previous, record, { [COHORT.recipients]: new Map([1, 2, 3, 4].map(i => [i, did(i)])) }, OWNER, verify))).toBe('InvalidRound');
        previous = transcriptUpdate(previous, record.closure);
      }
    });
  }
  test('an altered directory index is not canonical', () => {
    const gap = signedCeremony({ kind: 4, t: 3, n: 4, id: sha(s), current: pin.digest, epoch: 1n, rekey: 1n, directory: [1, 2, 3, 5].map(i => ({ index: i, did: did(i) })) });
    expect(refuse(s, s.rounds, pin, gap)).toBe('InvalidEncoding');
    // The index of the last directory entry: index:u16 || lp(did) || hpke:32.
    const lastIndexLow = s.ceremony.body.length - (2 + 4 + did(4).length + 32) + 1;
    expect(s.ceremony.body[lastIndexLow]).toBe(4);
    expect(refuse(s, s.rounds, pin, { body: flip(s.ceremony.body, lastIndexLow, 1), signature: s.ceremony.signature })).toBe('InvalidEncoding');
  });
  test('transcripts of two ceremonies that differ only in a recipient key never verify under each other', () => {
    const t = dkgSetup('f3-3of4', 3, 4, { kind: 4, current: pin.digest, epoch: 1n, rekey: 1n, hpke: { 3: key } });
    expect(equal(t.digest, s.digest)).toBe(false);
    expect(equal(t.start, s.start)).toBe(false);
    expect(run(t).qual).toEqual([1, 2, 3, 4]);
    expect(refuse(t, t.rounds, pin, s.ceremony)).toBe('InvalidRound');
    expect(refuse(s, s.rounds, pin, t.ceremony)).toBe('InvalidRound');
  });
  test('messages are accepted only from the directory of this ceremony, never from the current certificate', () => {
    const fresh = rekey('f3-fresh', 2, 3, { directory: [1, 2, 3].map(i => ({ index: i, did: did(i + 6) })) });
    // The members of the pinned certificate (fixtures 1-3) are not the recipients here; their signatures do not resolve.
    expect(refuse(fresh)).toBe('InvalidSignature');
    const outsider = replace(s, 1, 2, { cohort: 1, index: 2, payload: s.rounds[0]!.find(m => m.index === 2)!.payload, signer: did(9) });
    expect(refuse(s, outsider)).toBe('InvalidSignature');
  });
});

describe('F4: authorization precedes dealing', () => {
  const owned = (spec: Partial<CeremonySpec>): DkgSetup => rekey(`f4-${JSON.stringify(spec, (_, v) => typeof v === 'bigint' ? Number(v) : v)}`, 2, 3, spec);
  const other = signedCertificate({ t: 2, n: 3, coefficients: poly('f4-other', 2) });
  const foreign = signedCertificate({ t: 2, n: 3, coefficients: poly('rekey-pin', 2), network: `${NETWORK}:other` });
  const maxEpoch = signedCertificate({ t: 2, n: 3, genesisT: 2, rekey: 2n, epoch: (1n << 64n) - 1n, coefficients: poly('f4-max', 2), previous: new Uint8Array(32).fill(3) });
  const maxRekey = signedCertificate({ t: 2, n: 3, genesisT: 2, rekey: (1n << 64n) - 1n, epoch: (1n << 64n) - 1n, coefficients: poly('f4-max-rekey', 2), previous: new Uint8Array(32).fill(3), previousMpk: times(G2_BASE, 5n) });
  test('stale, absent or foreign current-certificate digests', () => {
    const stale = rekey('f4-stale', 2, 3, {}, other);
    expect(refuse(stale)).toBe('InvalidCeremony');
    expect(refuse(dkgSetup('f4-absent', 2, 3, { kind: 4, epoch: 1n, rekey: 1n }))).toBe('InvalidCeremony');
    expect(refuse(owned({ current: new Uint8Array(32).fill(0xab) }))).toBe('InvalidCeremony');
    expect(refuse(rekey('f4-foreign', 2, 3, {}, foreign))).toBe('InvalidCeremony');
    // Names the pinned certificate's digest of another network while the pinned certificate is its genuine one.
    expect(refuse(rekey('f4-newer', 2, 3, {}, pin), undefined, other)).toBe('InvalidCeremony');
  });
  test('unchanged, skipped or regressed re-key counter and epoch', () => {
    for (const spec of [{ rekey: 0n }, { rekey: 2n }, { rekey: 3n }, { epoch: 0n }, { epoch: 2n }, { epoch: 7n }, { epoch: 0n, rekey: 0n }, { epoch: 2n, rekey: 2n }]) {
      expect(refuse(owned(spec))).toBe('InvalidCeremony');
    }
    // Counters at u64 maximum cannot be incremented.
    expect(refuse(rekey('f4-max-epoch', 2, 3, { epoch: 0n, rekey: 3n }, maxEpoch), undefined, maxEpoch)).toBe('InvalidCeremony');
    expect(refuse(rekey('f4-max-rekey', 2, 3, { epoch: 0n, rekey: 0n }, maxRekey), undefined, maxRekey)).toBe('InvalidCeremony');
  });
  test('a genesis statement presented as a re-key, and the reverse', () => {
    const genesis = dkgSetup('f4-genesis', 2, 3);
    expect(refuse(genesis)).toBe('InvalidCeremony');
    expect(refuse(genesis, genesis.rounds, null)).toBe('ok');
    const asRekey = rekey('f4-rekey', 2, 3);
    expect(refuse(asRekey, asRekey.rounds, null)).toBe('InvalidCeremony');
    expect(refuse(asRekey)).toBe('ok');
    // A genesis statement that names the pinned certificate is not a genesis either.
    expect(refuse(dkgSetup('f4-genesis-current', 2, 3, { current: pin.digest }))).toBe('InvalidCeremony');
    expect(refuse(dkgSetup('f4-genesis-counters', 2, 3, { epoch: 1n, rekey: 1n }))).toBe('InvalidCeremony');
  });
  test('only the kind separates a re-key from a statement with re-key counters: kinds 1, 2 and 3 with a successor\'s fields are refused', () => {
    for (const kind of [1, 2, 3]) {
      const s = dkgSetup(`f4-successor-fields-${kind}`, 2, 3, { kind, current: pin.digest, epoch: 1n, rekey: 1n });
      expect(refuse(s)).toBe('InvalidCeremony');
    }
  });
  test('redistribution statements fed to the DKG verifier, with and without a pinned certificate', () => {
    for (const kind of [2, 3]) {
      const s = dkgSetup(`f4-kind-${kind}`, 2, 3, { kind, current: pin.digest, epoch: 1n });
      expect(refuse(s)).toBe('InvalidCeremony');
      expect(refuse(s, s.rounds, null)).toBe('InvalidCeremony');
    }
    // The reverse: a re-key statement fed to the redistribution verifier.
    const s = rekey('f4-to-reshare', 2, 3);
    expect(code(() => reshareVerifyTranscript(ANCHOR, s.ceremony, pin, seal(s.digest, s.start, s.rounds).records, verify))).toBe('InvalidCeremony');
  });
  test('recipients or threshold that differ from the signed statement', () => {
    const s = rekey('f4-signed', 3, 4);
    const base = { kind: 4, id: s.ceremony.body.slice(2, 34), current: pin.digest, epoch: 1n, rekey: 1n };
    // Re-signed variants are other ceremonies: the transcript names this statement's digest.
    expect(refuse(s, s.rounds, pin, signedCeremony({ ...base, t: 2, n: 4 }))).toBe('InvalidRound');
    expect(refuse(s, s.rounds, pin, signedCeremony({ ...base, t: 3, n: 5 }))).toBe('InvalidRound');
    expect(refuse(s, s.rounds, pin, signedCeremony({ ...base, t: 3, n: 4, directory: [1, 2, 3, 9].map(i => ({ index: [1, 2, 3, 4][[1, 2, 3, 9].indexOf(i)]!, did: did(i) })) }))).toBe('InvalidRound');
    // Edited without the owner: the signature fails.
    const edited = (offset: number) => ({ body: flip(s.ceremony.body, offset), signature: s.ceremony.signature });
    // t:u16 (low byte) follows option(current).
    const thresholdLow = 2 + 32 + 4 + NETWORK.length + 4 + OWNER.length + 1 + 32 + 1;
    expect(s.ceremony.body[thresholdLow]).toBe(3);
    expect(refuse(s, s.rounds, pin, edited(thresholdLow))).toBe('InvalidSignature');
    expect(refuse(s, s.rounds, pin, edited(s.ceremony.body.length - 1))).toBe('InvalidSignature');
  });
  test('a cohort-2 (dealer) envelope is refused: a re-key uses no old share', () => {
    const s = rekey('f4-cohort', 2, 3);
    const first = s.rounds[0]!;
    const asDealer: Draft[][] = [first.map(d => d.index === 1 ? { ...d, cohort: COHORT_DEALERS } : d), ...s.rounds.slice(1)];
    expect(refuse(s, asDealer)).toBe('InvalidIndex');
    // An additional, validly signed dealer-cohort envelope from a member of the pinned certificate is refused too.
    expect(refuse(s, replace(s, 3, 1, msg(1, pairs([])), { cohort: COHORT_DEALERS, index: 1, payload: pairs([]) }))).toBe('InvalidIndex');
  });
  test('the pinned certificate must itself verify under the anchor', () => {
    const impostor = signedCertificate({ t: 2, n: 3, coefficients: PIN_COEFFICIENTS, owner: did(1) }, did(1));
    const foreignNet = signedCertificate({ t: 2, n: 3, coefficients: PIN_COEFFICIENTS, network: `${NETWORK}:other` });
    const s = rekey('f4-pin', 2, 3);
    expect(refuse(s, s.rounds, impostor)).toBe('InvalidCertificate');
    expect(refuse(s, s.rounds, foreignNet)).toBe('InvalidCertificate');
    expect(refuse(s, s.rounds, { body: pin.body, signature: sign(did(1), tagged('TC-THRESHOLD-V1-CERT-STATEMENT', pin.digest)) })).toBe('InvalidSignature');
    expect(refuse(s, s.rounds, { body: pin.body, signature: flip(pin.signature, 0) })).toBe('InvalidSignature');
    expect(refuse(s, s.rounds, { body: flip(pin.body, pin.body.length - 34), signature: pin.signature })).toBe('InvalidSignature');
    expect(refuse(s, s.rounds, { body: concat(pin.body, be(0n, 1)), signature: pin.signature })).toBe('InvalidEncoding');
  });
});

describe('genesis and re-key never verify as one another', () => {
  const genesis = dkgSetup('mixup', 2, 3), asRekey = dkgSetup('mixup', 2, 3, { kind: 4, current: pin.digest, epoch: 1n, rekey: 1n });
  test('the ceremony digest binds the kind, so each transcript names the other\'s digest', () => {
    expect(equal(genesis.digest, asRekey.digest)).toBe(false);
    expect(equal(genesis.start, asRekey.start)).toBe(false);
    const genesisRecords: RoundRecord[] = seal(genesis.digest, genesis.start, genesis.rounds).records;
    const rekeyRecords: RoundRecord[] = seal(asRekey.digest, asRekey.start, asRekey.rounds).records;
    expect(code(() => dkgVerifyTranscript(ANCHOR, asRekey.ceremony, genesisRecords, verify, pin))).toBe('InvalidRound');
    expect(code(() => dkgVerifyTranscript(ANCHOR, genesis.ceremony, rekeyRecords, verify))).toBe('InvalidRound');
  });
  test('the initial link is the DKG label; the redistribution label does not start a re-key', () => {
    const wrong = tagged('TC-THRESHOLD-V1-RESHARE-START', asRekey.digest);
    expect(code(() => dkgVerifyTranscript(ANCHOR, asRekey.ceremony, seal(asRekey.digest, wrong, asRekey.rounds).records, verify, pin))).toBe('InvalidRound');
  });
});

describe('an output that keeps the pinned master key is not a re-key', () => {
  test('dealer constants summing to the pinned master scalar are refused; any other constant is accepted', () => {
    const s = rekey('same-mpk', 2, 3), [d1, d2, d3] = s.dealers;
    const same = withDealer(s, 3, [(PIN_COEFFICIENTS[0]! + 2n * R - d1!.a[0]! - d2!.a[0]!) % R, d3!.a[1]!], d3!.b);
    expect((d1!.a[0]! + d2!.a[0]! + same.dealers[2]!.a[0]!) % R).toBe(PIN_COEFFICIENTS[0]!);
    expect(refuse(same)).toBe('InvalidCeremony');
    expect(refuse(s)).toBe('ok');
  });
});

// Chain steps (S0.5 appendix): every generation is rebuilt from its raw ceremony transcript and the pinned
// predecessor. The chain below is built in the scalar domain by chain-kit.ts; each adversarial variant
// re-signs only the record it changes and regenerates the records that depend on it, so exactly one
// rule is violated per variant (and a control case shows the harness itself is clean).
import { describe, expect, test } from 'bun:test';
import { equal, hex } from './protocol.ts';
import { chainOrder, checkLineage, verifyChain, verifyChainStep, type ChainInput, type ChainOutput } from './chain.ts';
import { verifyCertificate } from './ceremony.ts';
import {
  activationFor, chainGenesis, chainInput, chainReshare, chainRekey, receiptFor, withCertificate, type Step, type StepInput,
} from './chain-kit.ts';
import {
  ANCHOR, COHORT_DEALERS, G2_BASE, NETWORK, at, code, did, flip, g2hex, seal, signedCeremony, signedCertificate, times, verify, type Draft,
} from './testkit.ts';

const g0 = chainGenesis('chain-g0', 2, 3);
const g1 = chainReshare(g0.gen, 'chain-r1', 3, 4);
const g2 = chainReshare(g1.gen, 'chain-r2', 2, 3);
const g3 = chainReshare(g2.gen, 'chain-f3', 2, 3, 3);
const g4 = chainRekey(g3.gen, 'chain-k4', 3, 4);
const g5 = chainReshare(g4.gen, 'chain-r5', 2, 3);
const g6 = chainRekey(g5.gen, 'chain-k6', 2, 3);
const g7 = chainReshare(g6.gen, 'chain-r7', 3, 4);
const steps = [g0, g1, g2, g3, g4, g5, g6, g7];

const run = (i: StepInput): ChainOutput => verifyChainStep(ANCHOR, chainInput(i), verify);
const refuse = (i: StepInput) => code(() => run(i));
const other32 = new Uint8Array(32).fill(0x42);
/** The built step with its certificate rebuilt from an edited spec (receipts and activation regenerated). */
const certified = (s: Step, change: (spec: Step['gen']['spec']) => Step['gen']['spec'], signer?: string) => withCertificate(s, change, signer);

describe('honest chain: genesis → reshare → reshare → refresh → re-key → reshare → re-key → reshare', () => {
  test('every generation matches the scalar-domain expectation', () => {
    const outputs = verifyChain(ANCHOR, steps.map(s => chainInput(s.input)), verify);
    for (const [k, s] of steps.entries()) {
      const o = outputs[k]!, c = s.gen.spec.coefficients, n = s.gen.n;
      expect(o.kind).toBe(s.kind);
      expect(o.commitments.map(g2hex)).toEqual(c.map(x => g2hex(times(G2_BASE, x))));
      expect(o.publicShares.map(g2hex)).toEqual(Array.from({ length: n }, (_, i) => g2hex(times(G2_BASE, at(c, i + 1)))));
      expect(g2hex(o.certificate.mpk)).toBe(g2hex(times(G2_BASE, c[0]!)));
      expect([o.certificate.epoch, o.certificate.rekey]).toEqual([BigInt(k), s.gen.rekey]);
      expect([o.certificate.genesisT, o.certificate.t, o.certificate.n]).toEqual([s.gen.genesisT, s.gen.t, s.gen.n]);
      expect(hex(o.certificate.digest)).toBe(hex(s.gen.certificate.digest));
      expect(hex(o.transcriptHash)).toBe(hex(s.gen.spec.transcript!));
      expect(hex(o.activation)).toBe(hex(s.input.activation.body));
    }
    expect(outputs.map(o => o.outcome)).toEqual([
      { qual: [1, 2, 3], reconstructed: [] }, { dealers: [1, 2] }, { dealers: [1, 2, 3] }, { dealers: [1, 2] },
      { qual: [1, 2, 3, 4], reconstructed: [] }, { dealers: [1, 2, 3] }, { qual: [1, 2, 3], reconstructed: [] }, { dealers: [1, 2] },
    ]);
  });
  test('lineage: reshare and refresh keep mpk, re-key counter and genesis t; a re-key changes mpk, adds 1 and resets genesis t', () => {
    const certs = verifyChain(ANCHOR, steps.map(s => chainInput(s.input)), verify).map(o => o.certificate);
    const mpk = certs.map(c => hex(c.mpk.toBytes()));
    expect([mpk[0] === mpk[1], mpk[1] === mpk[2], mpk[2] === mpk[3], mpk[3] === mpk[4], mpk[4] === mpk[5], mpk[5] === mpk[6], mpk[6] === mpk[7]])
      .toEqual([true, true, true, false, true, false, true]);
    expect(certs.map(c => c.rekey)).toEqual([0n, 0n, 0n, 0n, 1n, 1n, 2n, 2n]);
    expect(certs.map(c => c.genesisT)).toEqual([2, 2, 2, 2, 3, 3, 2, 2]);
    expect(certs[4]!.previousMpk!.equals(certs[3]!.mpk)).toBe(true);
    expect(certs[6]!.previousMpk!.equals(certs[5]!.mpk)).toBe(true);
    expect(certs.filter(c => c.previousMpk).length).toBe(2);
  });
  test('control: rebuilding a certificate from an unchanged spec reproduces the committed records', () => {
    for (const s of steps) {
      const again = certified(s, spec => spec);
      expect(again.certificate).toEqual(s.input.certificate);
      expect(again.receipts).toEqual(s.input.receipts);
      expect(again.activation).toEqual(s.input.activation);
    }
  });
});

describe('F5: the trust anchor is external, never taken from a certificate in the chain', () => {
  const foreign = (s: Step, change: Partial<{ owner: string; network: string }>) => {
    const signer = change.owner ?? did(0);
    return signedCertificate({ ...s.gen.spec, ...change }, signer);
  };
  test('a fully replaced, correctly self-signed previous certificate for another owner or network', () => {
    for (const [s, prev] of [[g1, g0], [g4, g3], [g3, g2]] as const) {
      for (const change of [{ owner: did(1) }, { owner: did(9) }, { network: `${NETWORK}:other` }]) {
        expect(refuse({ ...s.input, previous: foreign(prev, change) })).toBe('InvalidCertificate');
      }
    }
  });
  test('a fully replaced foreign ceremony pinned to a foreign certificate', () => {
    const cert = foreign(g0, { owner: did(1) });
    const ceremony = signedCeremony({ kind: 2, t: 3, n: 4, owner: did(1), current: cert.digest, epoch: 1n }, did(1));
    expect(refuse({ ...g1.input, ceremony, previous: cert })).toBe('InvalidCeremony');
    const netCert = foreign(g0, { network: `${NETWORK}:other` });
    const netCeremony = signedCeremony({ kind: 2, t: 3, n: 4, network: `${NETWORK}:other`, current: netCert.digest, epoch: 1n });
    expect(refuse({ ...g1.input, ceremony: netCeremony, previous: netCert })).toBe('InvalidCeremony');
    // Replacing only the ceremony is refused the same way.
    expect(refuse({ ...g1.input, ceremony: signedCeremony({ kind: 2, t: 3, n: 4, owner: did(1), current: g0.gen.certificate.digest, epoch: 1n }, did(1)) })).toBe('InvalidCeremony');
  });
  test('a fully replaced, correctly self-signed candidate certificate for another owner or network', () => {
    for (const s of steps) {
      for (const change of [{ owner: did(1) }, { network: `${NETWORK}:other` }]) {
        const signer = change.owner ?? did(0);
        expect(refuse(certified(s, spec => ({ ...spec, ...change }), signer))).toBe('InvalidCertificate');
      }
    }
  });
  test('a candidate for the right owner signed by another key is not the owner\'s certificate', () => {
    for (const s of [g0, g1, g4]) expect(refuse(certified(s, spec => spec, did(1)))).toBe('InvalidSignature');
  });
  test('a chain whose middle step pins a replaced predecessor is refused in the chain', () => {
    const swapped = steps.map(s => chainInput(s.input));
    swapped[2] = { ...swapped[2]!, previous: foreign(g1, { owner: did(1) }) };
    expect(code(() => verifyChain(ANCHOR, swapped, verify))).toBe('InvalidCertificate');
  });
});

describe('F6: the certificate is bound to the recomputed ceremony outcome and the pinned predecessor', () => {
  describe('re-key lineage', () => {
    const rekeyed = (s: Step, change: (spec: Step['gen']['spec']) => Step['gen']['spec']) => certified(s, change);
    test('a re-key certificate that keeps the old mpk', () => {
      for (const s of [g4, g6]) {
        const old = s === g4 ? g3 : g5;
        const keep = (spec: Step['gen']['spec']) => ({ ...spec, coefficients: [old.gen.spec.coefficients[0]!, ...spec.coefficients.slice(1)] });
        // Names the old mpk as previous and keeps it: previous mpk equals mpk.
        expect(refuse(rekeyed(s, keep))).toBe('InvalidEncoding');
        // Drops previous mpk: it is then a reshare-lineage certificate, which a re-key ceremony cannot produce.
        expect(refuse(rekeyed(s, spec => ({ ...keep(spec), previousMpk: undefined })))).toBe('InvalidCertificate');
        expect(refuse(rekeyed(s, spec => ({ ...spec, previousMpk: undefined })))).toBe('InvalidCertificate');
      }
    });
    test('a wrong previous mpk', () => {
      for (const s of [g4, g6]) expect(refuse(rekeyed(s, spec => ({ ...spec, previousMpk: times(G2_BASE, 123456789n) })))).toBe('InvalidCertificate');
      // The previous mpk of an older generation is not the pinned one.
      expect(refuse(rekeyed(g6, spec => ({ ...spec, previousMpk: times(G2_BASE, g3.gen.spec.coefficients[0]!) })))).toBe('InvalidCertificate');
    });
    test('the re-key counter is not incremented, skipped or decremented', () => {
      expect(refuse(rekeyed(g6, spec => ({ ...spec, rekey: 1n })))).toBe('InvalidCertificate');
      expect(refuse(rekeyed(g6, spec => ({ ...spec, rekey: 3n })))).toBe('InvalidCertificate');
      expect(refuse(rekeyed(g6, spec => ({ ...spec, rekey: 0n })))).toBe('InvalidEncoding');
      expect(refuse(rekeyed(g4, spec => ({ ...spec, rekey: 0n })))).toBe('InvalidEncoding');
      expect(refuse(rekeyed(g4, spec => ({ ...spec, rekey: 2n })))).toBe('InvalidCertificate');
    });
    test('genesis t is not reset to the new t', () => {
      expect(refuse(rekeyed(g4, spec => ({ ...spec, genesisT: g3.gen.genesisT })))).toBe('InvalidEncoding');
      expect(refuse(rekeyed(g6, spec => ({ ...spec, genesisT: g5.gen.genesisT })))).toBe('InvalidEncoding');
    });
    test('a different new master key still has to equal the recomputed ceremony output', () => {
      expect(refuse(rekeyed(g4, spec => ({ ...spec, coefficients: [777n, ...spec.coefficients.slice(1)] })))).toBe('InvalidCertificate');
    });
  });
  describe('reshare and refresh lineage', () => {
    test('a reshare or refresh certificate that changes mpk', () => {
      for (const s of [g1, g2, g3, g5, g7]) {
        expect(refuse(certified(s, spec => ({ ...spec, coefficients: [777n, ...spec.coefficients.slice(1)] })))).toBe('InvalidCertificate');
      }
    });
    test('a reshare or refresh certificate that changes the re-key counter or genesis t', () => {
      for (const s of [g1, g3, g5]) {
        expect(refuse(certified(s, spec => ({ ...spec, rekey: s.gen.rekey + 1n })))).toBe('InvalidCertificate');
        expect(refuse(certified(s, spec => ({ ...spec, genesisT: s.gen.genesisT + 1 })))).toBe('InvalidCertificate');
      }
    });
    test('a reshare certificate dressed as a re-key (previous mpk named, counter incremented, genesis t reset)', () => {
      for (const [s, prev] of [[g1, g0], [g5, g4]] as const) {
        const dress = (previousMpk: typeof prev.gen.spec.previousMpk) => certified(s, spec => ({ ...spec, rekey: spec.rekey! + 1n, genesisT: spec.t, previousMpk }));
        // Same master key named as previous: not a re-key certificate at all.
        expect(refuse(dress(times(G2_BASE, prev.gen.spec.coefficients[0]!)))).toBe('InvalidEncoding');
        // A different previous mpk makes it a well-formed re-key certificate that a reshare ceremony cannot have produced.
        expect(refuse(dress(times(G2_BASE, 99n)))).toBe('InvalidCertificate');
      }
    });
  });
  describe('generation, predecessor and ceremony outcome', () => {
    test('skipped, repeated or missing epoch and wrong or absent previous digest', () => {
      // A successor with epoch 0 is not a canonical certificate.
      expect(refuse(certified(g1, spec => ({ ...spec, epoch: 0n })))).toBe('InvalidEncoding');
      for (const s of [g1, g4, g7]) {
        expect(refuse(certified(s, spec => ({ ...spec, epoch: spec.epoch! + 1n })))).toBe('InvalidCertificate');
        expect(refuse(certified(s, spec => ({ ...spec, previous: other32 })))).toBe('InvalidCertificate');
        expect(refuse(certified(s, spec => ({ ...spec, previous: undefined, previousMpk: undefined })))).toBe('InvalidEncoding');
      }
    });
    test('a certificate whose transcript hash, commitments, mpk or shape differ from the recomputed outcome', () => {
      expect(refuse(certified(g0, spec => ({ ...spec, transcript: other32 })))).toBe('InvalidCertificate');
      expect(refuse(certified(g4, spec => ({ ...spec, transcript: other32 })))).toBe('InvalidCertificate');
      expect(refuse(certified(g0, spec => ({ ...spec, coefficients: [spec.coefficients[0]!, spec.coefficients[1]! + 1n] })))).toBe('InvalidCertificate');
      expect(refuse(certified(g0, spec => ({ ...spec, coefficients: [spec.coefficients[0]! + 1n, spec.coefficients[1]!] })))).toBe('InvalidCertificate');
      expect(refuse(certified(g1, spec => ({ ...spec, coefficients: [spec.coefficients[0]!, spec.coefficients[1]!, spec.coefficients[2]! + 1n] })))).toBe('InvalidCertificate');
      expect(refuse(certified(g0, spec => ({ ...spec, n: 4 })))).toBe('InvalidCertificate');
      expect(refuse(certified(g2, spec => ({ ...spec, n: 4 })))).toBe('InvalidCertificate');
    });
    test('a certificate of another ceremony on the same predecessor', () => {
      const branch = chainReshare(g0.gen, 'chain-branch', 3, 4);
      expect(refuse({ ...g1.input, certificate: branch.input.certificate, receipts: branch.input.receipts, activation: branch.input.activation })).toBe('InvalidCertificate');
      // The branch itself is a valid generation.
      expect(refuse(branch.input)).toBe('ok');
    });
    test('the outcome comes from the transcript: a changed dealing changes D, so the committed certificate no longer matches', () => {
      const edit = (s: Step, round: number, cohort: number, index: number) => {
        const rounds = s.rounds.map(r => r.map(d => ({ ...d }))) as Draft[][];
        const d = rounds[round - 1]!.find(m => m.cohort === cohort && m.index === index)!;
        d.payload = flip(d.payload, 3 + 95);
        return { ...s.input, records: seal(s.input.digest, s.input.start, rounds).records };
      };
      // Dealer 1's R1 commitment is malformed: it is excluded, so the outcome differs from the committed certificate.
      expect(refuse(edit(g1, 1, COHORT_DEALERS, 1))).toBe('InvalidCertificate');
      expect(refuse(edit(g0, 1, 1, 1))).toBe('InvalidCertificate');
      expect(refuse(edit(g4, 1, 1, 1))).toBe('InvalidCertificate');
    });
    test('a step that names its predecessor needs one, and a genesis names none', () => {
      expect(refuse({ ...g0.input, previous: g0.input.certificate })).toBe('InvalidCeremony');
      for (const s of [g1, g3, g4]) {
        const { previous: _, ...bare } = s.input;
        expect(refuse(bare)).toBe('InvalidCeremony');
      }
    });
  });
  describe('readiness receipts and activation', () => {
    const rebuilt = (s: Step, receipts: StepInput['receipts'], activation = activationFor(s.gen.certificate, receipts)): StepInput => ({ ...s.input, receipts, activation });
    const mine = (s: Step, signer: (i: number) => string = i => did(i), transcript?: Uint8Array) =>
      Array.from({ length: s.gen.n }, (_, k) => receiptFor(s.gen.spec, s.gen.certificate, k + 1, signer(k + 1), transcript));
    test('control: freshly built receipts and activation are accepted', () => {
      for (const s of steps) expect(refuse(rebuilt(s, mine(s)))).toBe('ok');
    });
    test('receipts signed for the previous candidate', () => {
      for (const [s, prev] of [[g3, g2], [g4, g3], [g6, g5]] as const) {
        const stale = Array.from({ length: s.gen.n }, (_, k) => receiptFor(s.gen.spec, prev.gen.certificate, k + 1));
        expect(refuse(rebuilt(s, stale))).toBe('InvalidReadiness');
      }
      // The previous generation's receipts and activation, verbatim.
      expect(refuse({ ...g3.input, receipts: g2.input.receipts })).toBe('InvalidReadiness');
      expect(refuse({ ...g3.input, activation: g2.input.activation })).toBe('InvalidReadiness');
    });
    test('receipts signed for another transcript, another member key or another member index', () => {
      for (const s of [g0, g1, g4]) {
        expect(refuse(rebuilt(s, mine(s, i => did(i), other32)))).toBe('InvalidReadiness');
        expect(refuse(rebuilt(s, mine(s, i => did(i % s.gen.n + 1))))).toBe('InvalidReadiness');
        expect(refuse(rebuilt(s, mine(s).map((r, k) => k === 0 ? { ...r, member: 2 } : r)))).toBe('InvalidReadiness');
        expect(refuse(rebuilt(s, mine(s).map((r, k) => k === 0 ? { ...r, signature: flip(r.signature, 0) } : r)))).toBe('InvalidReadiness');
      }
    });
    test('an activation over another receipt set, another candidate, or another key', () => {
      for (const s of [g0, g1, g4]) {
        const all = mine(s), before = steps[steps.indexOf(s) - 1];
        expect(refuse(rebuilt(s, all, activationFor(s.gen.certificate, all.slice(1))))).toBe('InvalidReadiness');
        expect(refuse(rebuilt(s, all, activationFor({ digest: other32 }, all)))).toBe('InvalidReadiness');
        if (before) expect(refuse(rebuilt(s, all, activationFor(before.gen.certificate, all)))).toBe('InvalidReadiness');
        expect(refuse(rebuilt(s, all, activationFor(s.gen.certificate, all, did(1))))).toBe('InvalidSignature');
        expect(refuse(rebuilt(s, all, { body: s.input.activation.body, signature: flip(s.input.activation.signature, 0) }))).toBe('InvalidSignature');
      }
    });
    test('fewer than n receipts under all_holders, including t′ alone', () => {
      for (const s of steps) {
        const all = mine(s);
        expect(refuse(rebuilt(s, all.slice(0, s.gen.n - 1)))).toBe('NotEnoughReady');
        expect(refuse(rebuilt(s, all.slice(0, s.gen.t)))).toBe('NotEnoughReady');
        expect(refuse(rebuilt(s, []))).toBe('NotEnoughReady');
      }
    });
    test('duplicate and non-member receipts add no vote and are refused', () => {
      for (const s of [g0, g1]) {
        const all = mine(s);
        expect(refuse(rebuilt(s, [all[0]!, ...all]))).toBe('InvalidReadiness');
        expect(refuse(rebuilt(s, [all[0]!, all[0]!, ...all.slice(2)]))).toBe('InvalidReadiness');
        expect(refuse(rebuilt(s, [...all, receiptFor(s.gen.spec, s.gen.certificate, s.gen.n + 1)]))).toBe('InvalidReadiness');
      }
    });
  });
});

describe('S0.2 lineage rules, applied to decoded candidates on their own', () => {
  const lineage = (s: Step, prev: Step | undefined, change: (spec: Step['gen']['spec']) => Step['gen']['spec']) => {
    const candidate = verifyCertificate(ANCHOR, certified(s, change).certificate, verify);
    const pinned = prev && verifyCertificate(ANCHOR, prev.input.certificate, verify);
    return code(() => checkLineage(s.kind, pinned, candidate));
  };
  test('every committed generation satisfies the rules of its kind; every other kind\'s rules refuse it', () => {
    for (const [k, s] of steps.entries()) expect(lineage(s, steps[k - 1], spec => spec)).toBe('ok');
    const c1 = verifyCertificate(ANCHOR, g1.input.certificate, verify), c4 = verifyCertificate(ANCHOR, g4.input.certificate, verify);
    expect(code(() => checkLineage(4, verifyCertificate(ANCHOR, g0.input.certificate, verify), c1))).toBe('InvalidCertificate');
    expect(code(() => checkLineage(2, verifyCertificate(ANCHOR, g3.input.certificate, verify), c4))).toBe('InvalidCertificate');
    expect(code(() => checkLineage(1, undefined, c1))).toBe('InvalidCertificate');
    expect(code(() => checkLineage(2, undefined, c1))).toBe('InvalidCertificate');
  });
  test('re-key: previous mpk, counter and epoch', () => {
    const bad: [Step, Step, (spec: Step['gen']['spec']) => Step['gen']['spec']][] = [
      [g4, g3, spec => ({ ...spec, previousMpk: times(G2_BASE, 123456789n) })],
      [g4, g3, spec => ({ ...spec, previousMpk: undefined })],
      [g4, g3, spec => ({ ...spec, rekey: 2n })],
      [g6, g5, spec => ({ ...spec, rekey: 1n })],
      [g6, g5, spec => ({ ...spec, rekey: 3n })],
      [g4, g3, spec => ({ ...spec, epoch: spec.epoch! + 1n })],
      [g4, g3, spec => ({ ...spec, previous: other32 })],
      [g6, g5, spec => ({ ...spec, previousMpk: times(G2_BASE, g3.gen.spec.coefficients[0]!) })],
    ];
    for (const [s, prev, change] of bad) expect(lineage(s, prev, change)).toBe('InvalidCertificate');
  });
  test('reshare and refresh: mpk, counter, genesis t, previous mpk and epoch', () => {
    const bad: [Step, Step, (spec: Step['gen']['spec']) => Step['gen']['spec']][] = [
      [g1, g0, spec => ({ ...spec, coefficients: [777n, ...spec.coefficients.slice(1)] })],
      [g3, g2, spec => ({ ...spec, coefficients: [777n, ...spec.coefficients.slice(1)] })],
      [g5, g4, spec => ({ ...spec, rekey: 2n })],
      [g1, g0, spec => ({ ...spec, genesisT: 3 })],
      [g5, g4, spec => ({ ...spec, genesisT: 2 })],
      [g1, g0, spec => ({ ...spec, rekey: 1n, genesisT: spec.t, previousMpk: times(G2_BASE, 99n) })],
      [g2, g1, spec => ({ ...spec, epoch: 4n })],
      [g2, g1, spec => ({ ...spec, previous: other32 })],
    ];
    for (const [s, prev, change] of bad) expect(lineage(s, prev, change)).toBe('InvalidCertificate');
  });
});

describe('chain order', () => {
  const inputs = steps.map(s => chainInput(s.input));
  const orderCode = (list: ChainInput[]) => code(() => verifyChain(ANCHOR, list, verify));
  test('the in-order chain is accepted', () => {
    expect(orderCode(inputs)).toBe('ok');
  });
  test('a skipped, repeated, swapped, reordered or truncated-front chain', () => {
    expect(orderCode([inputs[0]!, inputs[2]!, inputs[3]!])).toBe('InvalidCertificate');
    expect(orderCode([inputs[0]!, inputs[1]!, inputs[1]!])).toBe('InvalidCertificate');
    expect(orderCode([inputs[0]!, inputs[2]!, inputs[1]!])).toBe('InvalidCertificate');
    expect(orderCode([inputs[1]!, inputs[2]!])).toBe('InvalidCertificate');
    expect(orderCode([inputs[0]!, inputs[0]!])).toBe('InvalidCertificate');
    expect(orderCode([inputs[4]!])).toBe('InvalidCertificate');
  });
  test('an alternate branch is a valid generation of its own but not the predecessor of the next step', () => {
    const branch = chainReshare(g0.gen, 'order-branch', 3, 4);
    expect(code(() => verifyChainStep(ANCHOR, chainInput(branch.input), verify))).toBe('ok');
    expect(orderCode([inputs[0]!, chainInput(branch.input), inputs[2]!])).toBe('InvalidCertificate');
  });
  test('the pinned certificate is compared byte for byte, signature included', () => {
    const resigned = { ...inputs[2]!, previous: { body: g1.input.certificate.body, signature: g1.input.certificate.signature.map((b, i) => i === 0 ? b ^ 1 : b) } };
    expect(orderCode([inputs[0]!, inputs[1]!, resigned])).toBe('InvalidCertificate');
    expect(() => chainOrder(inputs[1], inputs[2]!)).not.toThrow();
    expect(equal(inputs[2]!.previous!.body, inputs[1]!.certificate.body)).toBe(true);
  });
});

describe('F1 and F2 reach the chain: the same ceremony rules decide the certificate', () => {
  test('re-key shapes outside the genesis budget are refused with an otherwise consistent certificate, receipts and activation', () => {
    for (const [t, n] of [[2, 2], [3, 3], [4, 4], [4, 5], [4, 6], [5, 8]] as const) {
      expect(refuse(chainRekey(g3.gen, `chain-budget-${t}-${n}`, t, n).input)).toBe('UnsupportedFaultBudget');
    }
    expect(refuse(chainRekey(g3.gen, 'chain-budget-2-3', 2, 3).input)).toBe('ok');
  });
  test('a re-key that needs extraction recovery is a valid generation only with the closed R5 barrier and R6', () => {
    expect(steps.map(s => s.input.records.length)).toEqual([5, 3, 3, 3, 5, 3, 5, 3]);
    const short = { ...g4.input, records: g4.input.records.slice(0, 4) };
    expect(refuse(short)).toBe('InvalidRound');
  });
  test('a cohort-2 envelope in a re-key step is refused', () => {
    const rounds = g4.rounds.map((r, k) => k === 0 ? r.map(d => d.index === 1 ? { ...d, cohort: COHORT_DEALERS } : d) : r);
    expect(refuse({ ...g4.input, records: seal(g4.input.digest, g4.input.start, rounds).records })).toBe('InvalidIndex');
  });
});

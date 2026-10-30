import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { DST, PEDERSEN_H_MESSAGE, ProtocolError, Reader, bytes, g2, scalar, tagged, type Bytes, type G2 } from './protocol.ts';
import {
  COHORT, KIND, TAG, authorizeCeremony, checkTranscriptSize, classify, evaluate, fail, listCount,
  memberIndex, mul, verifyChain, type Anchor, type Authenticated, type Ceremony, type Classified, type RoundRecord,
  type Statement, type Verifier,
} from './ceremony.ts';

const G2_BASE = bls.G2.Point.BASE, G2_ZERO = bls.G2.Point.ZERO;
/** SPEC §3.3 Pedersen generator h. */
export const PEDERSEN_H: G2 = bls.G2.hashToCurve(bytes(PEDERSEN_H_MESSAGE), { DST: DST.pedersen_h });

export interface Exclusion { member: number; reason: string; round?: number }

/** `01 || t:u16 || [P:96] || ...` coefficient vectors; individual coefficients may be the identity. */
function points(r: Reader): G2[] {
  return Array.from({ length: listCount(r) }, () => g2(r.take(96), true));
}
/** R1 deal (shared by genesis and redistribution): commitments and the recipient list. */
export function decodeDeal(payload: Bytes): { commitments: G2[]; recipients: number[] } {
  const r = new Reader(payload); r.version();
  const commitments = points(r);
  const recipients: number[] = [];
  for (let k = listCount(r), last = 0; k > 0; k--) {
    last = memberIndex(r, last);
    // §3.10 sealed dealing envelope: 01 || enc:32 || lp(ciphertext), decoded by layout only.
    const sealed = new Reader(r.field(65536)); sealed.version(); sealed.take(32); sealed.field(65536); sealed.end();
    recipients.push(last);
  }
  r.end();
  return { commitments, recipients };
}
/** R2 complaints. */
export function decodeComplaints(payload: Bytes): number[] {
  const r = new Reader(payload); r.version();
  const dealers: number[] = [];
  for (let k = listCount(r), last = 0; k > 0; k--) dealers.push(last = memberIndex(r, last));
  r.end();
  return dealers;
}
/** R3 answers, R5 extraction complaints and R6 values: indexed (s, s′) pairs. */
function decodePairs(payload: Bytes): Map<number, [bigint, bigint]> {
  const r = new Reader(payload); r.version();
  const pairs = new Map<number, [bigint, bigint]>();
  for (let k = listCount(r), last = 0; k > 0; k--) {
    last = memberIndex(r, last);
    pairs.set(last, [scalar(r.take(32)), scalar(r.take(32))]);
  }
  r.end();
  return pairs;
}
function decodeFeldman(payload: Bytes): G2[] {
  const r = new Reader(payload); r.version();
  const coefficients = points(r);
  r.end();
  return coefficients;
}
/** Decoded payload, or undefined when the payload is malformed. */
export function attempt<T>(decode: (b: Bytes) => T, payload: Bytes): T | undefined {
  try { return decode(payload); } catch (e) {
    if (e instanceof ProtocolError) return undefined;
    throw e;
  }
}

function pedersen(c: readonly G2[], j: number, [s, s2]: readonly [bigint, bigint]): boolean {
  return mul(G2_BASE, s).add(mul(PEDERSEN_H, s2)).equals(evaluate(c, j));
}
function feldman(a: readonly G2[], j: number, s: bigint): boolean {
  return mul(G2_BASE, s).equals(evaluate(a, j));
}
/** Coefficients of the degree t−1 polynomial through t points, mod r. */
export function interpolateCoefficients(points: readonly [number, bigint][]): bigint[] {
  const Fr = bls.fields.Fr, coefficients = points.map(() => 0n);
  for (const [xj, yj] of points) {
    let basis = [1n], denominator = 1n;
    for (const [xm] of points) {
      if (xm === xj) continue;
      const next = basis.map(() => 0n).concat(0n);
      for (const [k, b] of basis.entries()) { next[k + 1] = Fr.add(next[k + 1]!, b); next[k] = Fr.sub(next[k]!, Fr.mul(b, BigInt(xm))); }
      basis = next;
      denominator = Fr.mul(denominator, Fr.create(BigInt(xj - xm)));
    }
    const factor = Fr.mul(yj, Fr.inv(denominator));
    for (const [k, b] of basis.entries()) coefficients[k] = Fr.add(coefficients[k]!, Fr.mul(b, factor));
  }
  return coefficients;
}

export interface DkgOutput {
  qual: number[]; disqualified: Exclusion[]; reconstructed: number[];
  commitments: G2[]; mpk: G2; publicShares: G2[]; transcriptHash: Bytes; ceremony: Ceremony; initialTranscript: Bytes;
}
export function dkgInitialTranscript(ceremonyDigest: Bytes): Bytes { return tagged(TAG.dkgStart, ceremonyDigest); }

/** Genesis-only ceremony rules (S0.2 appendix and §3.0 budget). */
export function authorizeGenesis(anchor: Anchor, statement: Statement, verify: Verifier): Ceremony {
  const c = authorizeCeremony(anchor, statement, verify);
  if (c.kind !== KIND.genesis || c.current || c.rekey !== 0n || c.epoch !== 0n) fail('InvalidCeremony');
  if (c.n < 2 * c.t - 1) fail('UnsupportedFaultBudget');
  return c;
}

/** dkg_verify_transcript: SPEC §3.7 with the S0.3 appendix rules, from raw signed records only. */
export function dkgVerifyTranscript(anchor: Anchor, statement: Statement, records: readonly RoundRecord[], verify: Verifier): DkgOutput {
  checkTranscriptSize(records);
  const ceremony = authorizeGenesis(anchor, statement, verify);
  const { t, n } = ceremony, members = ceremony.directory.map(d => d.index);
  const initialTranscript = dkgInitialTranscript(ceremony.digest);
  const recipients = new Map(ceremony.directory.map(d => [d.index, d.did]));
  const { rounds, hash } = verifyChain(ceremony.digest, initialTranscript, records, 6, { [COHORT.recipients]: recipients }, anchor.owner, verify);
  if (rounds.length < 3) fail('InvalidRound');
  const sender = (round: Authenticated[], i: number): Classified => classify(round, COHORT.recipients, i);
  const [r1, r2, r3, r4, r5, r6] = rounds;

  const deals = new Map<number, G2[]>();
  const complainers = new Map<number, Set<number>>(members.map(i => [i, new Set()]));
  for (const j of members) {
    const m = sender(r2!, j);
    if (m.kind !== 'single') continue;
    const dealers = attempt(decodeComplaints, m.payload);
    if (!dealers || dealers.some(i => i > n)) continue;
    for (const i of dealers) if (i !== j) complainers.get(i)!.add(j);
  }
  const disqualified: Exclusion[] = [];
  for (const i of members) {
    const reason = ((): Exclusion | undefined => {
      const deal = sender(r1!, i);
      if (deal.kind === 'missing') return { member: i, reason: 'MissingDeal' };
      if (deal.kind === 'conflicting') return { member: i, reason: 'Equivocated', round: 1 };
      const decoded = attempt(decodeDeal, deal.payload);
      if (!decoded || decoded.commitments.length !== t || decoded.recipients.length !== n || decoded.recipients.some((x, k) => x !== k + 1)) return { member: i, reason: 'MalformedDeal' };
      if (sender(r2!, i).kind === 'conflicting') return { member: i, reason: 'Equivocated', round: 2 };
      const answer = sender(r3!, i);
      if (answer.kind === 'conflicting') return { member: i, reason: 'Equivocated', round: 3 };
      const required = complainers.get(i)!;
      if (required.size >= t) return { member: i, reason: 'Complaints' };
      const pairs = answer.kind === 'single' ? attempt(decodePairs, answer.payload) : undefined;
      const used = pairs && [...pairs.keys()].every(j => j <= n) ? pairs : undefined;
      if (used && [...used].some(([j, pair]) => !pedersen(decoded.commitments, j, pair))) return { member: i, reason: 'InvalidAnswer' };
      if ([...required].some(j => !used?.has(j))) return { member: i, reason: 'MissingAnswer' };
      deals.set(i, decoded.commitments);
      return undefined;
    })();
    if (reason) disqualified.push(reason);
  }
  const qual = [...deals.keys()];
  if (qual.length < t) {
    if (rounds.length !== 3) fail('InvalidRound');
    fail('InsufficientQualified');
  }
  if (rounds.length < 5) fail('InvalidRound');

  const extraction = new Map<number, G2[]>();
  for (const i of qual) {
    const m = sender(r4!, i);
    const coefficients = m.kind === 'single' ? attempt(decodeFeldman, m.payload) : undefined;
    if (coefficients && coefficients.length === t) extraction.set(i, coefficients);
  }
  const reconstruct = new Set(qual.filter(i => !extraction.has(i)));
  for (const j of members) {
    const m = sender(r5!, j);
    const entries = m.kind === 'single' ? attempt(decodePairs, m.payload) : undefined;
    for (const [i, pair] of entries ?? []) {
      const a = extraction.get(i);
      if (i !== j && a && pedersen(deals.get(i)!, j, pair) && !feldman(a, j, pair[0])) reconstruct.add(i);
    }
  }
  const reconstructed = qual.filter(i => reconstruct.has(i));
  if (rounds.length !== (reconstructed.length ? 6 : 5)) fail('InvalidRound');
  for (const i of reconstructed) {
    const values: [number, bigint][] = [];
    for (const j of members) {
      const m = sender(r6!, j);
      const pair = (m.kind === 'single' ? attempt(decodePairs, m.payload) : undefined)?.get(i);
      if (pair && pedersen(deals.get(i)!, j, pair)) values.push([j, pair[0]]);
    }
    if (values.length < t) fail('InsufficientRecovery');
    extraction.set(i, interpolateCoefficients(values.slice(0, t)).map(a => mul(G2_BASE, a)));
  }

  const commitments = Array.from({ length: t }, (_, k) => qual.reduce((acc, i) => acc.add(extraction.get(i)![k]!), G2_ZERO));
  const mpk = commitments[0]!;
  if (mpk.equals(G2_ZERO) || commitments[t - 1]!.equals(G2_ZERO)) fail('IdentityPoint');
  const publicShares = members.map(j => evaluate(commitments, j));
  if (publicShares.some(p => p.equals(G2_ZERO))) fail('IdentityPoint');
  return { qual, disqualified, reconstructed, commitments, mpk, publicShares, transcriptHash: hash, ceremony, initialTranscript };
}

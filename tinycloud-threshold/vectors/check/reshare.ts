import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { Reader, equal, scalar, tagged, type Bytes, type G2 } from './protocol.ts';
import {
  COHORT, DEFAULT_ERROR, KIND, TAG, authorizeCeremony, checkTranscriptSize, classify, evaluate, fail, listCount,
  memberIndex, mul, verifyCertificate, verifyChain, type Anchor, type Ceremony, type Certificate, type RoundRecord,
  type Statement, type Verifier,
} from './ceremony.ts';
import { attempt, decodeComplaints, decodeDeal, type Exclusion } from './dkg.ts';

const G2_BASE = bls.G2.Point.BASE, G2_ZERO = bls.G2.Point.ZERO, Fr = bls.fields.Fr;

/** Redistribution R3: `01 || count:u16 || [(recipient:u16 || value:32)]`. */
function decodeValues(payload: Bytes): Map<number, bigint> {
  const r = new Reader(payload); r.version();
  const values = new Map<number, bigint>();
  for (let k = listCount(r), last = 0; k > 0; k--) {
    last = memberIndex(r, last);
    values.set(last, scalar(r.take(32)));
  }
  r.end();
  return values;
}

export function reshareInitialTranscript(ceremonyDigest: Bytes): Bytes { return tagged(TAG.reshareStart, ceremonyDigest); }

/** S0.4 entry checks: kind, current-certificate binding, successor generation, refresh shape. */
export function authorizeRedistribution(anchor: Anchor, statement: Statement, certificate: Statement, verify: Verifier): { ceremony: Ceremony; current: Certificate } {
  const c = authorizeCeremony(anchor, statement, verify);
  if (c.kind !== KIND.reshare && c.kind !== KIND.refresh) fail('InvalidCeremony');
  const current = verifyCertificate(anchor, certificate, verify);
  if (!c.current) fail(DEFAULT_ERROR.absentCurrent);
  if (!equal(c.current, current.digest)) fail('ContextMismatch');
  if (current.epoch === 0xffffffffffffffffn || c.epoch !== current.epoch + 1n || c.rekey !== current.rekey) fail(DEFAULT_ERROR.successorGeneration);
  if (c.kind === KIND.refresh && (c.t !== current.t || c.n !== current.n || c.directory.some((d, k) => d.did !== current.members[k]!.did))) fail('InvalidCeremony');
  return { ceremony: c, current };
}

export interface ReshareOutput {
  threshold: number; members: number; dealers: number[]; excluded: Exclusion[];
  commitments: G2[]; mpk: G2; publicShares: G2[]; transcriptHash: Bytes; ceremony: Ceremony; initialTranscript: Bytes;
}

/** reshare_verify_transcript: SPEC §3.8 with the S0.4 appendix rules, from raw signed records only. */
export function reshareVerifyTranscript(anchor: Anchor, statement: Statement, certificate: Statement, records: readonly RoundRecord[], verify: Verifier): ReshareOutput {
  checkTranscriptSize(records);
  const { ceremony, current } = authorizeRedistribution(anchor, statement, certificate, verify);
  const t2 = ceremony.t, n2 = ceremony.n, oldMembers = current.members.map(m => m.index);
  const initialTranscript = reshareInitialTranscript(ceremony.digest);
  const cohorts = {
    [COHORT.recipients]: new Map(ceremony.directory.map(d => [d.index, d.did])),
    [COHORT.dealers]: new Map(current.members.map(m => [m.index, m.did])),
  };
  const { rounds, hash } = verifyChain(ceremony.digest, initialTranscript, records, 3, cohorts, anchor.owner, verify);
  if (rounds.length !== 3) fail('InvalidRound');
  const [r1, r2, r3] = rounds;

  const complainers = new Map<number, Set<number>>(oldMembers.map(i => [i, new Set()]));
  for (const d of ceremony.directory) {
    const m = classify(r2!, COHORT.recipients, d.index);
    const dealers = m.kind === 'single' ? attempt(decodeComplaints, m.payload) : undefined;
    if (!dealers || dealers.some(i => i > current.n)) continue;
    for (const i of dealers) complainers.get(i)!.add(d.index);
  }
  const excluded: Exclusion[] = [];
  const candidates: { index: number; position: number; commitments: G2[] }[] = [];
  for (const i of oldMembers) {
    const reason = ((): Exclusion | undefined => {
      const deal = classify(r1!, COHORT.dealers, i);
      if (deal.kind === 'missing') return { member: i, reason: 'MissingDeal' };
      if (deal.kind === 'conflicting') return { member: i, reason: 'Equivocated', round: 1 };
      const decoded = attempt(decodeDeal, deal.payload);
      const b = decoded?.commitments;
      if (!decoded || !b || b.length !== t2 || !b[0]!.equals(current.publicShares[i - 1]!) || b[t2 - 1]!.equals(G2_ZERO)
        || decoded.recipients.length !== n2 || decoded.recipients.some((x, k) => x !== k + 1)) return { member: i, reason: 'MalformedDeal' };
      const answer = classify(r3!, COHORT.dealers, i);
      if (answer.kind === 'conflicting') return { member: i, reason: 'Equivocated', round: 3 };
      const required = complainers.get(i)!;
      if (required.size >= t2) return { member: i, reason: 'Complaints' };
      const values = answer.kind === 'single' ? attempt(decodeValues, answer.payload) : undefined;
      const used = values && [...values.keys()].every(j => j <= n2) ? values : undefined;
      if (used && [...used].some(([j, g]) => !mul(G2_BASE, g).equals(evaluate(b, j)))) return { member: i, reason: 'InvalidAnswer' };
      if ([...required].some(j => !used?.has(j))) return { member: i, reason: 'MissingAnswer' };
      candidates.push({ index: i, position: deal.position, commitments: b });
      return undefined;
    })();
    if (reason) excluded.push(reason);
  }
  const selected = candidates.sort((a, b) => a.position - b.position).slice(0, current.t);
  if (selected.length < current.t) fail('InsufficientQualified');

  const dealers = selected.map(d => d.index);
  const commitments = Array.from({ length: t2 }, (_, k) => selected.reduce((acc, d) => {
    const lambda = dealers.reduce((l, j) => j === d.index ? l : Fr.mul(l, Fr.div(BigInt(j), Fr.create(BigInt(j - d.index)))), 1n);
    return acc.add(mul(d.commitments[k]!, lambda));
  }, G2_ZERO));
  if (!commitments[0]!.equals(current.mpk)) fail(DEFAULT_ERROR.reshareMpk);
  if (commitments[t2 - 1]!.equals(G2_ZERO)) fail('IdentityPoint');
  const publicShares = ceremony.directory.map(d => evaluate(commitments, d.index));
  if (publicShares.some(p => p.equals(G2_ZERO))) fail('IdentityPoint');
  return { threshold: t2, members: n2, dealers, excluded, commitments, mpk: commitments[0]!, publicShares, transcriptHash: hash, ceremony, initialTranscript };
}

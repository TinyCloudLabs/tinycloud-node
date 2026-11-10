import { be, concat, equal, lp, tagged, type Bytes, type G2 } from './protocol.ts';
import {
  DEFAULT_ERROR, KIND, LIMIT, TAG, checkTranscriptSize, decodeCeremony, fail, verifyCertificate,
  type Anchor, type Ceremony, type Certificate, type RoundRecord, type Statement, type Verifier,
} from './ceremony.ts';
import { dkgInitialTranscript, dkgVerifyTranscript } from './dkg.ts';
import { reshareInitialTranscript, reshareVerifyTranscript } from './reshare.ts';

const U64_MAX = 0xffffffffffffffffn;
const utf8 = new TextEncoder();

/** One `chain_step` case, decoded: every raw signed record, the pinned predecessor, the candidate and its activation. */
export interface ChainInput {
  ceremony: Statement; rounds: readonly RoundRecord[]; previous?: Statement;
  certificate: Statement; receipts: { member: number; signature: Bytes }[]; activation: Statement;
}
export type ChainOutcome = { qual: number[]; reconstructed: number[] } | { dealers: number[] };
export interface ChainOutput {
  kind: number; ceremony: Ceremony; initialTranscript: Bytes; outcome: ChainOutcome; certificate: Certificate;
  commitments: G2[]; publicShares: G2[]; transcriptHash: Bytes; activation: Bytes;
}

/** S0.2 canonical certificate body, rebuilt from the recomputed outcome and the pinned predecessor. */
function rebuiltBody(anchor: Anchor, ceremony: Ceremony, outcome: { mpk: G2; commitments: G2[]; transcriptHash: Bytes }, pinned: Certificate | undefined): Bytes {
  const rekey = !pinned ? 0n : ceremony.kind === KIND.rekey ? pinned.rekey + 1n : pinned.rekey;
  const genesisT = !pinned || ceremony.kind === KIND.rekey ? ceremony.t : pinned.genesisT;
  return concat(
    be(1n, 1), lp(utf8.encode(anchor.network)), lp(utf8.encode(anchor.owner)), be(rekey, 8), be(pinned ? pinned.epoch + 1n : 0n, 8),
    be(BigInt(genesisT), 2), be(BigInt(ceremony.t), 2), be(BigInt(ceremony.n), 2), be(BigInt(ceremony.directory.length), 2),
    ...ceremony.directory.flatMap(d => [be(BigInt(d.index), 2), lp(utf8.encode(d.did))]),
    outcome.mpk.toBytes(), be(BigInt(outcome.commitments.length), 2), ...outcome.commitments.map(c => c.toBytes()),
    outcome.transcriptHash,
    pinned ? concat(be(1n, 1), pinned.digest) : be(0n, 1),
    pinned && ceremony.kind === KIND.rekey ? concat(be(1n, 1), pinned.mpk.toBytes()) : be(0n, 1),
  );
}

/** S0.2 lineage of a verified candidate against its pinned predecessor, by the kind of the ceremony that produced it. */
export function checkLineage(kind: number, pinned: Certificate | undefined, c: Certificate) {
  const bad = () => fail(DEFAULT_ERROR.lineage);
  if (!pinned) {
    if (c.previous || c.previousMpk || c.epoch !== 0n || c.rekey !== 0n || c.genesisT !== c.t) bad();
    return;
  }
  if (c.owner !== pinned.owner || c.network !== pinned.network) bad();
  if (!c.previous || !equal(c.previous, pinned.digest) || pinned.epoch === U64_MAX || c.epoch !== pinned.epoch + 1n) bad();
  if (kind === KIND.rekey) {
    if (!c.previousMpk || !c.previousMpk.equals(pinned.mpk) || c.mpk.equals(pinned.mpk)) bad();
    if (pinned.rekey === U64_MAX || c.rekey !== pinned.rekey + 1n || c.genesisT !== c.t) bad();
  } else if (c.previousMpk || !c.mpk.equals(pinned.mpk) || c.rekey !== pinned.rekey || c.genesisT !== pinned.genesisT) bad();
}

/**
 * S0.5 readiness under the all-holders quorum: every receipt is a member's strict signature over the READY preimage,
 * all checked before counting or hashing; then the owner's activation over the sorted receipt hashes.
 */
function verifyReadiness(anchor: Anchor, c: Certificate, receipts: ChainInput['receipts'], activation: Statement, verify: Verifier): Bytes {
  const seen: Record<number, true> = {};
  for (const r of receipts) {
    const member = c.members.find(m => m.index === r.member);
    if (!member || seen[r.member] || r.signature.length > LIMIT.signature) fail('InvalidReadiness');
    seen[r.member] = true;
    const share = c.publicShares[r.member - 1]!;
    if (!verify(member.did, tagged(TAG.ready, concat(c.digest, c.transcript, be(BigInt(r.member), 2), share.toBytes())), r.signature)) fail('InvalidReadiness');
  }
  if (receipts.length < c.n) fail('NotEnoughReady');
  const hashes = receipts.map(r => tagged(TAG.ready, concat(be(1n, 1), be(BigInt(r.member), 2), lp(r.signature)))).sort((a, b) => Buffer.compare(a, b));
  const preimage = tagged(TAG.activate, concat(c.digest, ...hashes));
  if (!equal(activation.body, preimage)) fail('InvalidReadiness');
  if (activation.signature.length > LIMIT.signature || !verify(anchor.owner, preimage, activation.signature)) fail(DEFAULT_ERROR.signature);
  return preimage;
}

/**
 * One generation of the chain: recompute the ceremony outcome from the raw transcript (S0.3 for genesis and re-key,
 * S0.4 for reshare and refresh), rebuild the certificate body from that outcome and the pinned predecessor and require
 * it byte-for-byte, then the owner signature, lineage, every receipt and the activation. No output field is an input.
 */
export function verifyChainStep(anchor: Anchor, input: ChainInput, verify: Verifier): ChainOutput {
  checkTranscriptSize(input.rounds);
  const kind = decodeCeremony(input.ceremony.body).kind;
  if ((kind === KIND.genesis) === (input.previous !== undefined)) fail('InvalidCeremony');
  const records = [...input.rounds];
  let pinned: Certificate | undefined, outcome: ChainOutcome, ceremony: Ceremony, initialTranscript: Bytes;
  let shared: { mpk: G2; commitments: G2[]; publicShares: G2[]; transcriptHash: Bytes };
  if (kind === KIND.genesis || kind === KIND.rekey) {
    const out = dkgVerifyTranscript(anchor, input.ceremony, records, verify, input.previous);
    pinned = out.current; ceremony = out.ceremony; shared = out;
    outcome = { qual: out.qual, reconstructed: out.reconstructed };
    initialTranscript = dkgInitialTranscript(out.ceremony.digest);
  } else {
    const out = reshareVerifyTranscript(anchor, input.ceremony, input.previous!, records, verify);
    pinned = out.current; ceremony = out.ceremony; shared = out;
    outcome = { dealers: out.dealers };
    initialTranscript = reshareInitialTranscript(out.ceremony.digest);
  }
  const certificate = verifyCertificate(anchor, input.certificate, verify);
  checkLineage(kind, pinned, certificate);
  if (!equal(rebuiltBody(anchor, ceremony, shared, pinned), input.certificate.body)) fail(DEFAULT_ERROR.certificateOutcome);
  const activation = verifyReadiness(anchor, certificate, input.receipts, input.activation, verify);
  return { kind, ceremony, initialTranscript, outcome, certificate, commitments: shared.commitments, publicShares: shared.publicShares, transcriptHash: shared.transcriptHash, activation };
}

/** Chain order: the first step pins nothing; every later step pins exactly the previous step's certificate (body and owner signature). */
export function chainOrder(before: ChainInput | undefined, step: ChainInput) {
  if (!before) {
    if (step.previous) fail(DEFAULT_ERROR.chainOrder);
  } else if (!step.previous || !equal(step.previous.body, before.certificate.body) || !equal(step.previous.signature, before.certificate.signature)) fail(DEFAULT_ERROR.chainOrder);
}

export function verifyChain(anchor: Anchor, steps: readonly ChainInput[], verify: Verifier): ChainOutput[] {
  return steps.map((step, k) => {
    chainOrder(steps[k - 1], step);
    return verifyChainStep(anchor, step, verify);
  });
}

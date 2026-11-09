import { bytes, hex } from './protocol.ts';
import { KIND, TAG, type Anchor } from './ceremony.ts';
import { chainOrder, verifyChainStep, type ChainInput } from './chain.ts';
import { intField, invalid, literal, object, type Parsed, type Parser } from './schema.ts';
import {
  anchorShape, certificateShape, exactList, h32, h96, hexBytes, indexed, list, member, nullable, points, recordsOf, rounds, same, shares,
  sharedDst, signers, statement, statementOf, text, verifierOf,
} from './transcript-common.ts';

const counter = intField(0, Number.MAX_SAFE_INTEGER);
const KIND_NAME: Record<number, string> = { [KIND.genesis]: 'genesis', [KIND.reshare]: 'reshare', [KIND.refresh]: 'refresh', [KIND.rekey]: 'rekey' };
/** `qual` and `reconstructed` for genesis and re-key, `dealers` for reshare and refresh. */
const outcomeShape: Parser<{ qual: number[]; reconstructed: number[] } | { dealers: number[] }> = (v, p) => v && typeof v === 'object' && 'dealers' in v
  ? object({ dealers: list(member, 1, 16) })(v, p)
  : object({ qual: list(member, 1, 16), reconstructed: list(member, 0, 16) })(v, p);
const step = object({
  name: text, operation: literal('chain_step'), description: text,
  inputs: object({
    activation: object({ body: h32, signature: hexBytes }), ceremony: statement, ceremony_digest: h32, certificate: certificateShape,
    initial_transcript: h32, previous_certificate: nullable(certificateShape), quorum: literal('all_holders'),
    receipts: list(object({ member, signature: hexBytes }), 1, 16), rounds,
  }),
  outputs: object({
    activation: h32, ceremony: outcomeShape, certificate_digest: h32, commitments: list(h96, 1, 16), epoch: counter, genesis_t: member,
    kind: text, members: member, mpk: h96, public_shares: shares, rekey: counter, threshold: member, transcript_hash: h32,
  }),
});
const chainFile = object({
  format_version: literal(1),
  suite: literal('BLS12-381 G2 GJKR New-DKG, Feldman redistribution and re-key; owner certificates, readiness receipts and activation; Ed25519 test signatures'),
  encoding: literal('hex; statements are exact signed bytes; certificates are the canonical body plus the owner signature'),
  spec_sections: exactList(['3.7', '3.8', '3.9', '3.12', 'S0.5 re-key appendix', 'S0.5 chain appendix'] as const),
  dst: object({
    ...sharedDst, activate: literal(TAG.activate), cert_statement: literal(TAG.certStatement), dkg_start: literal(TAG.dkgStart),
    network_cert: literal(TAG.networkCert), ready: literal(TAG.ready), reshare_start: literal(TAG.reshareStart),
  }),
  anchor: anchorShape, seeds: object({ genesis: intField(0, 255), steps: list(intField(0, 255), 1) }), signers,
  cases: (v: unknown, p: string) => {
    const parsed = list(step, 1, 64)(v, p);
    if (new Set(parsed.map(c => c.name)).size !== parsed.length) invalid(`${p}: duplicate name`);
    return parsed;
  },
});
export type ChainFile = Parsed<typeof chainFile>;
export type ChainCase = ChainFile['cases'][number];
/** Schema-validated chain document. */
export function parseChainDocument(value: unknown): ChainFile { return chainFile(value, 'chain'); }

/** The decoded statements of a case, as the chain verifier takes them. */
export function chainInputOf(c: ChainCase): ChainInput {
  const signed = (s: { body: string; owner_signature: string }) => ({ body: bytes(s.body), signature: bytes(s.owner_signature) });
  const i = c.inputs;
  return {
    ceremony: statementOf(i.ceremony), rounds: recordsOf(i.rounds), ...(i.previous_certificate ? { previous: signed(i.previous_certificate) } : {}),
    certificate: signed(i.certificate), receipts: i.receipts.map(r => ({ member: r.member, signature: bytes(r.signature) })), activation: statementOf(i.activation),
  };
}

export interface ChainReport { kind: 'chain'; passed: string[] }
/**
 * Recomputes every generation from its raw transcript, in chain order, and compares the recomputed results with the
 * declared inputs and outputs. Declared fields are comparison values only; no decision reads them.
 */
export function checkChain(input: unknown): ChainReport {
  const file = chainFile(input, 'chain'), verify = verifierOf(file), anchor: Anchor = file.anchor, passed: string[] = [];
  let before: ChainInput | undefined;
  for (const c of file.cases) {
    try {
      const x = chainInputOf(c);
      chainOrder(before, x);
      const o = verifyChainStep(anchor, x, verify), cert = o.certificate;
      same('ceremony digest', hex(o.ceremony.digest), c.inputs.ceremony_digest);
      same('initial transcript', hex(o.initialTranscript), c.inputs.initial_transcript);
      same('kind', KIND_NAME[o.kind], c.outputs.kind);
      same('epoch', Number(cert.epoch), c.outputs.epoch);
      same('rekey', Number(cert.rekey), c.outputs.rekey);
      same('genesis t', cert.genesisT, c.outputs.genesis_t);
      same('threshold', cert.t, c.outputs.threshold);
      same('members', cert.n, c.outputs.members);
      same('mpk', hex(cert.mpk.toBytes()), c.outputs.mpk);
      same('commitments', points(o.commitments), c.outputs.commitments);
      same('public shares', indexed(o.publicShares), c.outputs.public_shares);
      same('transcript hash', hex(o.transcriptHash), c.outputs.transcript_hash);
      same('certificate digest', hex(cert.digest), c.outputs.certificate_digest);
      same('activation', hex(o.activation), c.outputs.activation);
      same('ceremony outcome', o.outcome, c.outputs.ceremony);
      before = x;
      passed.push(c.name);
    } catch (e) { throw new Error(`${c.name}: ${e instanceof Error ? e.message : String(e)}`); }
  }
  return { kind: 'chain', passed };
}

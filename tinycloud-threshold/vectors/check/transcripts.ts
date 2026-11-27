import { DST, bytes, hex, tagged } from './protocol.ts';
import { TAG, decodeCeremony, fail, type Anchor, type Statement, type Verifier } from './ceremony.ts';
import { verifyActivation, verifyCertificate as verifyCandidate, type SigningKeys } from './certificates.ts';
import { dkgInitialTranscript, dkgVerifyTranscript } from './dkg.ts';
import { reshareInitialTranscript, reshareVerifyTranscript } from './reshare.ts';
import { intField, invalid, literal, object, type Parsed, type Parser } from './schema.ts';
import { checkChain, parseChainDocument, type ChainFile } from './chain-vectors.ts';
import {
  anchorShape, caseOf, cases, ceremonySeeds, certificateShape, encoding, exactList, exclusion, exclusions, h32, h96, hexBytes, indexed, list, member,
  outcome, points, recordsOf, rounds, same, shares, sharedDst, signers, statement, statementOf, text, uniqueCases, verifierOf,
} from './transcript-common.ts';

export { recordsOf, statementOf, verifierOf } from './transcript-common.ts';

const dkgSuite = literal('BLS12-381 G2 Pedersen/Feldman GJKR New-DKG; RFC 9180 base mode DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305 dealings; Ed25519 test signatures');
const dkgDst = object({ ...sharedDst, dkg_start: literal(TAG.dkgStart), pedersen_h: literal(DST.pedersen_h), pedersen_h_message: literal('pedersen-h') });
const dkgInputs = { ceremony: statement, ceremony_digest: h32, initial_transcript: h32, members: member, threshold: member, rounds };
const dkgOutputs = object({
  commitments: list(h96, 1, 16), disqualified: list(exclusion, 0, 16), mpk: h96, public_shares: shares,
  qual: list(member, 1, 16), reconstructed: list(member, 0, 16), transcript_hash: h32,
});
const dkgFile = object({
  format_version: literal(1), suite: dkgSuite, encoding,
  spec_sections: exactList(['3.2', '3.3', '3.7', '3.10', 'S0.3 DKG appendix'] as const),
  dst: dkgDst, anchor: anchorShape, seeds: ceremonySeeds, signers,
  cases: cases('dkg_verify_transcript', object(dkgInputs), dkgOutputs),
});
/** A re-key is the same DKG under a kind-4 ceremony; every case also carries the signed pinned certificate. */
const rekeyInputs = object({ ...dkgInputs, current_certificate: certificateShape });
const rekeyFile = object({
  format_version: literal(1), suite: dkgSuite, encoding,
  spec_sections: exactList(['3.2', '3.3', '3.7', '3.9', '3.10', 'S0.3 DKG appendix', 'S0.5 re-key appendix'] as const),
  dst: dkgDst, anchor: anchorShape, seeds: ceremonySeeds, signers,
  cases: cases('dkg_verify_transcript', rekeyInputs, dkgOutputs),
});
/**
 * The omission document: genesis and re-key DKG transcripts (the R6 floor and the R6-sender presence rule) next to
 * `verify_activation` refusals of their candidates (the genesis/re-key outage budget). A case is re-key when it carries
 * the pinned current certificate, genesis otherwise.
 */
const activationInputs = {
  activation: object({ body: h32, signature: hexBytes }), certificate: certificateShape,
  quorum: object({ with_outage_budget: intField(0, 65535) }), receipts: list(object({ member, signature: hexBytes }), 0, 16),
};
const activationCase = <I>(inputs: Parser<I>) => object({ name: text, operation: literal('verify_activation'), description: text, inputs, error: text });
const omissionCases = {
  genesis: caseOf('dkg_verify_transcript', object(dkgInputs), dkgOutputs),
  rekey: caseOf('dkg_verify_transcript', rekeyInputs, dkgOutputs),
  genesisActivation: activationCase(object(activationInputs)),
  rekeyActivation: activationCase(object({ ...activationInputs, current_certificate: certificateShape })),
};
type OmissionCase = Parsed<(typeof omissionCases)[keyof typeof omissionCases]>;
const omissionCase: Parser<OmissionCase> = (v, p) => {
  const inputs = v && typeof v === 'object' && 'inputs' in v ? v.inputs : undefined;
  const pinned = !!inputs && typeof inputs === 'object' && 'current_certificate' in inputs;
  if (v && typeof v === 'object' && 'operation' in v && v.operation === 'verify_activation') return (pinned ? omissionCases.rekeyActivation : omissionCases.genesisActivation)(v, p);
  return (pinned ? omissionCases.rekey : omissionCases.genesis)(v, p);
};
const omissionFile = object({
  format_version: literal(1),
  suite: literal('BLS12-381 G2 Pedersen/Feldman GJKR New-DKG under genesis and re-key ceremonies: own-message presence, the R6 reconstruction floor and the genesis/re-key activation budget; Ed25519 test signatures'),
  encoding: literal('hex; statements are exact signed bytes; scalars 32-byte big-endian; G2 96-byte compressed; certificates are the canonical body plus the owner signature; re-key cases carry the pinned current certificate'),
  spec_sections: exactList(['3.7', '3.12', 'S0.2 activation appendix', 'S0.3 DKG appendix', 'S0.5 re-key appendix'] as const),
  dst: object({
    activate: literal(TAG.activate), ceremony_auth: literal(TAG.ceremonyAuth), ceremony_msg: literal(TAG.ceremonyMsg), cert_statement: literal(TAG.certStatement),
    dkg_start: literal(TAG.dkgStart), network_cert: literal(TAG.networkCert), ready: literal(TAG.ready), round_close: literal(TAG.roundClose), transcript: literal(TAG.transcript),
  }),
  anchor: anchorShape, seeds: ceremonySeeds, signers, cases: uniqueCases(omissionCase),
});
const reshareFile = object({
  format_version: literal(1),
  suite: literal('BLS12-381 G2 Feldman redistribution; RFC 9180 base mode DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305 dealings; Ed25519 test signatures'),
  encoding, spec_sections: exactList(['3.2', '3.3', '3.8', '3.10', 'S0.4 redistribution appendix'] as const),
  dst: object({ ...sharedDst, cert_statement: literal(TAG.certStatement), network_cert: literal(TAG.networkCert), reshare_start: literal(TAG.reshareStart) }),
  anchor: anchorShape, seeds: ceremonySeeds, signers,
  cases: cases('reshare_verify_transcript',
    object({ ceremony: statement, ceremony_digest: h32, current_certificate: certificateShape, initial_transcript: h32, rounds }),
    object({
      commitments: list(h96, 1, 16), dealers: list(member, 1, 16), excluded: list(exclusion, 0, 16), members: member,
      mpk: h96, public_shares: shares, threshold: member, transcript_hash: h32,
    })),
});
export type DkgFile = Parsed<typeof dkgFile>;
export type RekeyFile = Parsed<typeof rekeyFile>;
export type ReshareFile = Parsed<typeof reshareFile>;
export type OmissionFile = Parsed<typeof omissionFile>;
export type { ChainFile };
export type TranscriptKind = 'dkg' | 'rekey' | 'reshare' | 'chain' | 'omission';

/** Which transcript document this is, from its pinned SPEC section list; undefined for other documents. */
export function transcriptKind(value: unknown): TranscriptKind | undefined {
  if (!value || typeof value !== 'object' || !('spec_sections' in value) || !Array.isArray(value.spec_sections)) return undefined;
  // The chain, omission and re-key documents also name the S0.5 re-key appendix; their own markers decide first.
  if (value.spec_sections.includes('S0.5 chain appendix')) return 'chain';
  if (value.spec_sections.includes('S0.2 activation appendix')) return 'omission';
  if (value.spec_sections.includes('S0.5 re-key appendix')) return 'rekey';
  if (value.spec_sections.includes('S0.3 DKG appendix')) return 'dkg';
  if (value.spec_sections.includes('S0.4 redistribution appendix')) return 'reshare';
  return undefined;
}
/** Schema-validated DKG, re-key or redistribution transcript document. */
export function parseCeremonyDocument(value: unknown): DkgFile | RekeyFile | ReshareFile {
  const kind = transcriptKind(value);
  if (kind === 'dkg') return dkgFile(value, 'dkg');
  if (kind === 'rekey') return rekeyFile(value, 'rekey');
  if (kind === 'reshare') return reshareFile(value, 'reshare');
  return invalid('ceremony transcript document kind');
}
/** Schema-validated transcript document of any kind. */
export function parseTranscriptDocument(value: unknown): DkgFile | RekeyFile | ReshareFile | ChainFile | OmissionFile {
  const kind = transcriptKind(value);
  if (kind === 'chain') return parseChainDocument(value);
  if (kind === 'omission') return omissionFile(value, 'omission');
  return parseCeremonyDocument(value);
}

export interface TranscriptReport { kind: TranscriptKind; passed: string[] }
type DkgCase = DkgFile['cases'][number] | RekeyFile['cases'][number];
function checkDkgCase(c: DkgCase, anchor: Anchor, verify: Verifier) {
  const pinned: Statement | undefined = 'current_certificate' in c.inputs
    ? { body: bytes(c.inputs.current_certificate.body), signature: bytes(c.inputs.current_certificate.owner_signature) } : undefined;
  const result = outcome(() => dkgVerifyTranscript(anchor, statementOf(c.inputs.ceremony), recordsOf(c.inputs.rounds), verify, pinned));
  same('computed error', 'error' in result ? result.error : null, 'error' in c ? c.error : null);
  // The digest and H0 are functions of the statement bytes, so they are compared even when authorization fails.
  const digest = tagged(TAG.ceremonyAuth, bytes(c.inputs.ceremony.body));
  same('ceremony digest', hex(digest), c.inputs.ceremony_digest);
  same('initial transcript', hex(dkgInitialTranscript(digest)), c.inputs.initial_transcript);
  // Member count and threshold need the decoded statement; an undecodable one is already decided by the computed error.
  const ceremony = outcome(() => decodeCeremony(bytes(c.inputs.ceremony.body)));
  if ('value' in ceremony) {
    same('ceremony members', ceremony.value.n, c.inputs.members);
    same('ceremony threshold', ceremony.value.t, c.inputs.threshold);
  }
  if ('value' in result && 'outputs' in c) {
    const o = result.value;
    same('qual', o.qual, c.outputs.qual);
    same('disqualified', exclusions(o.disqualified), c.outputs.disqualified);
    same('reconstructed', o.reconstructed, c.outputs.reconstructed);
    same('commitments', points(o.commitments), c.outputs.commitments);
    same('mpk', hex(o.mpk.toBytes()), c.outputs.mpk);
    same('public shares', indexed(o.publicShares), c.outputs.public_shares);
    same('transcript hash', hex(o.transcriptHash), c.outputs.transcript_hash);
  }
}
function checkDkgCases(kind: 'dkg' | 'rekey', input: unknown): TranscriptReport {
  const file = kind === 'dkg' ? dkgFile(input, 'dkg') : rekeyFile(input, 'rekey'), verify = verifierOf(file), passed: string[] = [];
  const anchor: Anchor = file.anchor;
  for (const c of file.cases) {
    try {
      checkDkgCase(c, anchor, verify);
      passed.push(c.name);
    } catch (e) { throw new Error(`${c.name}: ${e instanceof Error ? e.message : String(e)}`); }
  }
  return { kind, passed };
}
export const checkDkg = (input: unknown) => checkDkgCases('dkg', input);
export const checkRekey = (input: unknown) => checkDkgCases('rekey', input);

type ActivationCase = Extract<OmissionCase, { operation: 'verify_activation' }>;
/**
 * verify_activation of a candidate certificate: the certificate under the anchor (a re-key candidate also against its
 * pinned current certificate), every receipt and the declared outage budget, then the owner's activation statement,
 * whose body must be the recomputed ACTIVATE preimage. Returns that preimage.
 */
export function activateCandidate(anchor: Anchor, keys: SigningKeys, i: ActivationCase['inputs']): Uint8Array {
  const previous = 'current_certificate' in i ? verifyCandidate(bytes(i.current_certificate.body), bytes(i.current_certificate.owner_signature), anchor, keys) : undefined;
  const candidate = verifyCandidate(bytes(i.certificate.body), bytes(i.certificate.owner_signature), anchor, keys, previous);
  const receipts = i.receipts.map(r => ({ index: r.member, signature: bytes(r.signature) }));
  const { preimage } = verifyActivation(candidate, receipts, i.quorum.with_outage_budget, bytes(i.activation.signature), keys);
  if (hex(preimage) !== i.activation.body) fail('InvalidReadiness');
  return preimage;
}
export function checkOmission(input: unknown): TranscriptReport {
  const file = omissionFile(input, 'omission'), verify = verifierOf(file), passed: string[] = [];
  const anchor: Anchor = file.anchor, keys: SigningKeys = new Map(file.signers.map(s => [s.did, bytes(s.ed25519_public_key)]));
  for (const c of file.cases) {
    try {
      if (c.operation === 'verify_activation') {
        const result = outcome(() => activateCandidate(anchor, keys, c.inputs));
        same('computed error', 'error' in result ? result.error : null, c.error);
      } else checkDkgCase(c, anchor, verify);
      passed.push(c.name);
    } catch (e) { throw new Error(`${c.name}: ${e instanceof Error ? e.message : String(e)}`); }
  }
  return { kind: 'omission', passed };
}
export function checkReshare(input: unknown): TranscriptReport {
  const file = reshareFile(input, 'reshare'), verify = verifierOf(file), passed: string[] = [];
  const anchor: Anchor = file.anchor;
  for (const c of file.cases) {
    try {
      const certificate: Statement = { body: bytes(c.inputs.current_certificate.body), signature: bytes(c.inputs.current_certificate.owner_signature) };
      const result = outcome(() => reshareVerifyTranscript(anchor, statementOf(c.inputs.ceremony), certificate, recordsOf(c.inputs.rounds), verify));
      same('computed error', 'error' in result ? result.error : null, 'error' in c ? c.error : null);
      const ceremony = decodeCeremony(bytes(c.inputs.ceremony.body));
      same('ceremony digest', hex(ceremony.digest), c.inputs.ceremony_digest);
      same('initial transcript', hex(reshareInitialTranscript(ceremony.digest)), c.inputs.initial_transcript);
      if ('value' in result && 'outputs' in c) {
        const o = result.value;
        same('threshold', o.threshold, c.outputs.threshold);
        same('members', o.members, c.outputs.members);
        same('dealers', o.dealers, c.outputs.dealers);
        same('excluded', exclusions(o.excluded), c.outputs.excluded);
        same('commitments', points(o.commitments), c.outputs.commitments);
        same('mpk', hex(o.mpk.toBytes()), c.outputs.mpk);
        same('public shares', indexed(o.publicShares), c.outputs.public_shares);
        same('transcript hash', hex(o.transcriptHash), c.outputs.transcript_hash);
      }
      passed.push(c.name);
    } catch (e) { throw new Error(`${c.name}: ${e instanceof Error ? e.message : String(e)}`); }
  }
  return { kind: 'reshare', passed };
}
export function checkTranscripts(input: unknown): TranscriptReport {
  const kind = transcriptKind(input);
  if (kind === 'dkg') return checkDkg(input);
  if (kind === 'rekey') return checkRekey(input);
  if (kind === 'reshare') return checkReshare(input);
  if (kind === 'chain') return checkChain(input);
  if (kind === 'omission') return checkOmission(input);
  return invalid('transcript document kind');
}

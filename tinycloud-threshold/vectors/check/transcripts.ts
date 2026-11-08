import { DST, bytes, hex } from './protocol.ts';
import { TAG, decodeCeremony, type Anchor, type Statement } from './ceremony.ts';
import { dkgInitialTranscript, dkgVerifyTranscript } from './dkg.ts';
import { reshareInitialTranscript, reshareVerifyTranscript } from './reshare.ts';
import { invalid, literal, object, type Parsed } from './schema.ts';
import { checkChain, parseChainDocument, type ChainFile } from './chain-vectors.ts';
import {
  anchorShape, cases, ceremonySeeds, certificateShape, encoding, exactList, exclusion, exclusions, h32, h96, indexed, list, member, outcome, points,
  recordsOf, rounds, same, shares, sharedDst, signers, statement, statementOf, verifierOf,
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
const rekeyFile = object({
  format_version: literal(1), suite: dkgSuite, encoding,
  spec_sections: exactList(['3.2', '3.3', '3.7', '3.9', '3.10', 'S0.3 DKG appendix', 'S0.5 re-key appendix'] as const),
  dst: dkgDst, anchor: anchorShape, seeds: ceremonySeeds, signers,
  cases: cases('dkg_verify_transcript', object({ ...dkgInputs, current_certificate: certificateShape }), dkgOutputs),
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
export type { ChainFile };
export type TranscriptKind = 'dkg' | 'rekey' | 'reshare' | 'chain';

/** Which transcript document this is, from its pinned SPEC section list; undefined for other documents. */
export function transcriptKind(value: unknown): TranscriptKind | undefined {
  if (!value || typeof value !== 'object' || !('spec_sections' in value) || !Array.isArray(value.spec_sections)) return undefined;
  // The chain and re-key documents also name the S0.5 re-key appendix; the chain document's own marker decides first.
  if (value.spec_sections.includes('S0.5 chain appendix')) return 'chain';
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
export function parseTranscriptDocument(value: unknown): DkgFile | RekeyFile | ReshareFile | ChainFile {
  return transcriptKind(value) === 'chain' ? parseChainDocument(value) : parseCeremonyDocument(value);
}

export interface TranscriptReport { kind: TranscriptKind; passed: string[] }
function checkDkgCases(kind: 'dkg' | 'rekey', input: unknown): TranscriptReport {
  const file = kind === 'dkg' ? dkgFile(input, 'dkg') : rekeyFile(input, 'rekey'), verify = verifierOf(file), passed: string[] = [];
  const anchor: Anchor = file.anchor;
  for (const c of file.cases) {
    try {
      const pinned: Statement | undefined = 'current_certificate' in c.inputs
        ? { body: bytes(c.inputs.current_certificate.body), signature: bytes(c.inputs.current_certificate.owner_signature) } : undefined;
      const result = outcome(() => dkgVerifyTranscript(anchor, statementOf(c.inputs.ceremony), recordsOf(c.inputs.rounds), verify, pinned));
      same('computed error', 'error' in result ? result.error : null, 'error' in c ? c.error : null);
      const ceremony = decodeCeremony(bytes(c.inputs.ceremony.body));
      same('ceremony digest', hex(ceremony.digest), c.inputs.ceremony_digest);
      same('initial transcript', hex(dkgInitialTranscript(ceremony.digest)), c.inputs.initial_transcript);
      same('ceremony members', ceremony.n, c.inputs.members);
      same('ceremony threshold', ceremony.t, c.inputs.threshold);
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
      passed.push(c.name);
    } catch (e) { throw new Error(`${c.name}: ${e instanceof Error ? e.message : String(e)}`); }
  }
  return { kind, passed };
}
export const checkDkg = (input: unknown) => checkDkgCases('dkg', input);
export const checkRekey = (input: unknown) => checkDkgCases('rekey', input);
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
  return invalid('transcript document kind');
}

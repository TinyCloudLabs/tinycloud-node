import { DST, ProtocolError, bytes, hex, type G2 } from './protocol.ts';
import { TAG, decodeCeremony, ed25519Verifier, type Anchor, type RoundRecord, type Statement, type Verifier } from './ceremony.ts';
import { dkgInitialTranscript, dkgVerifyTranscript, type Exclusion } from './dkg.ts';
import { reshareInitialTranscript, reshareVerifyTranscript } from './reshare.ts';
import { hexField, intField, invalid, literal, object, type Parsed, type Parser } from './schema.ts';

const hexBytes: Parser<string> = (v, p) => typeof v === 'string' && /^(?:[0-9a-f]{2})*$/.test(v) ? v : invalid(p);
const text: Parser<string> = (v, p) => typeof v === 'string' && v.length > 0 ? v : invalid(p);
function list<T>(parse: Parser<T>, min = 0, max = 0xffff): Parser<T[]> {
  return (v, p) => Array.isArray(v) && v.length >= min && v.length <= max ? v.map((x: unknown, i) => parse(x, `${p}[${i}]`)) : invalid(p);
}
function nullable<T>(parse: Parser<T>): Parser<T | null> { return (v, p) => v === null ? null : parse(v, p); }
const h32 = hexField(32), h96 = hexField(96), member = intField(1, 16);
const statement = object({ body: hexBytes, signature: hexBytes });
const rounds = list(object({ closure: statement, messages: list(statement) }));
const exclusion: Parser<Exclusion> = (v, p) => v && typeof v === 'object' && 'round' in v
  ? object({ member, reason: text, round: intField(1, 6) })(v, p)
  : object({ member, reason: text })(v, p);
const shares = list(object({ member, point: h96 }), 1, 16);
const signers = list(object({ did: text, ed25519_public_key: h32 }), 1, 64);
const anchor = object({ network: text, owner: text });
const ceremonySeeds = object({ ceremonies: list(intField(0, 255), 1) });
const sharedDst = {
  ceremony_auth: literal(TAG.ceremonyAuth), ceremony_msg: literal(TAG.ceremonyMsg), commitments: literal(TAG.commitments),
  dealing: literal(TAG.dealing), round_close: literal(TAG.roundClose), transcript: literal(TAG.transcript),
};
function exactList<const T extends readonly string[]>(expected: T): Parser<T> {
  return (v, p) => Array.isArray(v) && v.length === expected.length && v.every((x, i) => x === expected[i]) ? expected : invalid(p);
}
const encoding = literal('hex; statements are exact signed bytes; scalars 32-byte big-endian; G2 96-byte compressed');

/** Case records carry either `outputs` (success) or `error` (a typed refusal), never both; names are unique. */
function cases<O extends string, I, Out>(operation: O, inputs: Parser<I>, outputs: Parser<Out>) {
  const success = object({ name: text, operation: literal(operation), description: text, inputs, outputs });
  const failure = object({ name: text, operation: literal(operation), description: text, inputs, error: text });
  type Case = Parsed<typeof success> | Parsed<typeof failure>;
  const one: Parser<Case> = (v, p) => v && typeof v === 'object' && 'error' in v ? failure(v, p) : success(v, p);
  const all: Parser<Case[]> = (v, p) => {
    const parsed = list(one, 1, 256)(v, p);
    if (new Set(parsed.map(c => c.name)).size !== parsed.length) invalid(`${p}: duplicate name`);
    return parsed;
  };
  return all;
}
const dkgFile = object({
  format_version: literal(1),
  suite: literal('BLS12-381 G2 Pedersen/Feldman GJKR New-DKG; RFC 9180 base mode DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305 dealings; Ed25519 test signatures'),
  encoding, spec_sections: exactList(['3.2', '3.3', '3.7', '3.10', 'S0.3 DKG appendix'] as const),
  dst: object({ ...sharedDst, dkg_start: literal(TAG.dkgStart), pedersen_h: literal(DST.pedersen_h), pedersen_h_message: literal('pedersen-h') }),
  anchor, seeds: ceremonySeeds, signers,
  cases: cases('dkg_verify_transcript',
    object({ ceremony: statement, ceremony_digest: h32, initial_transcript: h32, members: member, threshold: member, rounds }),
    object({
      commitments: list(h96, 1, 16), disqualified: list(exclusion, 0, 16), mpk: h96, public_shares: shares,
      qual: list(member, 1, 16), reconstructed: list(member, 0, 16), transcript_hash: h32,
    })),
});
const reshareFile = object({
  format_version: literal(1),
  suite: literal('BLS12-381 G2 Feldman redistribution; RFC 9180 base mode DHKEM(X25519, HKDF-SHA256)/HKDF-SHA256/ChaCha20-Poly1305 dealings; Ed25519 test signatures'),
  encoding, spec_sections: exactList(['3.2', '3.3', '3.8', '3.10', 'S0.4 redistribution appendix'] as const),
  dst: object({ ...sharedDst, cert_statement: literal(TAG.certStatement), network_cert: literal(TAG.networkCert), reshare_start: literal(TAG.reshareStart) }),
  anchor, seeds: ceremonySeeds, signers,
  cases: cases('reshare_verify_transcript',
    object({ ceremony: statement, ceremony_digest: h32, current_certificate: object({ body: hexBytes, owner_signature: hexBytes }), initial_transcript: h32, rounds }),
    object({
      commitments: list(h96, 1, 16), dealers: list(member, 1, 16), excluded: list(exclusion, 0, 16), members: member,
      mpk: h96, public_shares: shares, threshold: member, transcript_hash: h32,
    })),
});
export type DkgFile = Parsed<typeof dkgFile>;
export type ReshareFile = Parsed<typeof reshareFile>;
/** Schema-validated DKG or redistribution transcript document. */
export function parseTranscriptDocument(value: unknown): DkgFile | ReshareFile {
  const kind = transcriptKind(value);
  if (kind === 'dkg') return dkgFile(value, 'dkg');
  if (kind === 'reshare') return reshareFile(value, 'reshare');
  return invalid('transcript document kind');
}
export type TranscriptKind = 'dkg' | 'reshare';

/** Which transcript document this is, from its pinned SPEC section list; undefined for other documents. */
export function transcriptKind(value: unknown): TranscriptKind | undefined {
  if (!value || typeof value !== 'object' || !('spec_sections' in value) || !Array.isArray(value.spec_sections)) return undefined;
  if (value.spec_sections.includes('S0.3 DKG appendix')) return 'dkg';
  if (value.spec_sections.includes('S0.4 redistribution appendix')) return 'reshare';
  return undefined;
}

function same(label: string, actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${label}: observed ${JSON.stringify(actual)}; expected ${JSON.stringify(expected)}`);
}
export function statementOf(s: { body: string; signature: string }): Statement { return { body: bytes(s.body), signature: bytes(s.signature) }; }
export function recordsOf(r: { closure: { body: string; signature: string }; messages: { body: string; signature: string }[] }[]): RoundRecord[] {
  return r.map(x => ({ closure: statementOf(x.closure), messages: x.messages.map(statementOf) }));
}
export function verifierOf(file: { signers: { did: string; ed25519_public_key: string }[] }): Verifier {
  return ed25519Verifier(new Map(file.signers.map(s => [s.did, bytes(s.ed25519_public_key)])));
}
/** Runs the operation and returns either its typed error code or its outputs. */
function outcome<T>(run: () => T): { error: string } | { value: T } {
  try { return { value: run() }; } catch (e) {
    if (e instanceof ProtocolError) return { error: e.code };
    throw e;
  }
}
const points = (p: G2[]) => p.map(x => hex(x.toBytes()));
const indexed = (p: G2[]) => p.map((x, k) => ({ member: k + 1, point: hex(x.toBytes()) }));
const exclusions = (e: Exclusion[]) => e.map(x => ({ member: x.member, reason: x.reason, ...(x.round === undefined ? {} : { round: x.round }) }));

export interface TranscriptReport { kind: TranscriptKind; passed: string[] }
export function checkDkg(input: unknown): TranscriptReport {
  const file = dkgFile(input, 'dkg'), verify = verifierOf(file), passed: string[] = [];
  const anchor: Anchor = file.anchor;
  for (const c of file.cases) {
    try {
      const result = outcome(() => dkgVerifyTranscript(anchor, statementOf(c.inputs.ceremony), recordsOf(c.inputs.rounds), verify));
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
  return { kind: 'dkg', passed };
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
  if (kind === 'reshare') return checkReshare(input);
  return invalid('transcript document kind');
}

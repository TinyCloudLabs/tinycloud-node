import { array, hexField, intField, invalid, literal, object, type Parsed, type Parser } from './schema.ts';
import { CERT_TAGS } from './certificates.ts';

const text: Parser<string> = (v, p) => typeof v === 'string' && new TextEncoder().encode(v).length >= 1 && new TextEncoder().encode(v).length <= 1024 ? v : invalid(p);
const h32 = hexField(32), h96 = hexField(96), index = intField(1, 16);
function hexBytes(max: number, min = 0): Parser<string> {
  return (v, p) => typeof v === 'string' && v.length >= min * 2 && v.length <= max * 2 && /^(?:[0-9a-f]{2})*$/.test(v) ? v : invalid(p);
}
function list<T>(parse: Parser<T>, min: number, max: number): Parser<T[]> {
  return (v, p) => {
    if (!Array.isArray(v) || v.length < min || v.length > max) return invalid(p);
    return v.map((entry: unknown, i) => parse(entry, `${p}[${i}]`));
  };
}
function nullable<T>(parse: Parser<T>): Parser<T | null> { return (v, p) => v === null ? null : parse(v, p); }
const body = hexBytes(65536, 1), signature = hexBytes(512), prior = nullable(h32);
const certificateInputs = object({ body, expected_owner: text, network: text, owner_signature: signature, pinned_predecessor: prior });
const ceremonyInputs = object({ body, expected_owner: text, network: text, signature, pinned_predecessor: prior });
const certificateOutput = object({
  commitments: list(h96, 2, 16), digest: h32, epoch: intField(0, Number.MAX_SAFE_INTEGER), genesis_t: intField(2, 16), members: intField(2, 16), mpk: h96, owner_statement: h32,
  public_shares: list(object({ index, point: h96 }), 2, 16), rekey: intField(0, Number.MAX_SAFE_INTEGER), threshold: intField(2, 16),
});
const receipt = object({ index, signature });
const receiptOutput = object({ encoding: hexBytes(519, 7), index, readiness_preimage: h32, receipt_hash: h32, signature });
const activationErrorInputs = object({ activation_preimage: h32, budget: nullable(intField(0, 65535)), candidate: h32, owner_signature: signature, receipts: list(receipt, 0, 16) });
const faultInputs = object({ certificate: h32, request: body, share: hexField(259), signature });
const cases = {
  'genesis-2of3': object({ name: literal('genesis-2of3'), operation: literal('verify_certificate'), inputs: certificateInputs, outputs: certificateOutput }),
  'reshare-3of4': object({ name: literal('reshare-3of4'), operation: literal('verify_certificate'), inputs: certificateInputs, outputs: certificateOutput }),
  'rekey-2of3': object({ name: literal('rekey-2of3'), operation: literal('verify_certificate'), inputs: certificateInputs, outputs: certificateOutput }),
  'ceremony-epoch-0': object({ name: literal('ceremony-epoch-0'), operation: literal('authorize_ceremony'), inputs: ceremonyInputs, outputs: object({ digest: h32, signing_preimage: h32 }) }),
  'ceremony-epoch-1': object({ name: literal('ceremony-epoch-1'), operation: literal('authorize_ceremony'), inputs: ceremonyInputs, outputs: object({ digest: h32, signing_preimage: h32 }) }),
  'ceremony-epoch-2': object({ name: literal('ceremony-epoch-2'), operation: literal('authorize_ceremony'), inputs: ceremonyInputs, outputs: object({ digest: h32, signing_preimage: h32 }) }),
  'closed-round-1': object({ name: literal('closed-round-1'), operation: literal('verify_closed_round'), inputs: object({ ceremony_digest: h32, closure: body, messages: list(object({ body, signature }), 0, 65535), owner_signature: signature, previous: h32, round: intField(0, 255) }), outputs: object({ owner_preimage: h32, transcript_hash: h32 }) }),
  'activate-all-2of3': object({ name: literal('activate-all-2of3'), operation: literal('verify_activation'), inputs: object({ candidate: h32, owner_signature: signature, quorum: literal('all'), receipts: list(receiptOutput, 0, 16) }), outputs: object({ accepted: (v: unknown, p: string) => v === true ? true : invalid(p), activation_preimage: h32 }) }),
  'duplicate-member-did': object({ name: literal('duplicate-member-did'), operation: literal('decode_certificate'), inputs: object({ body }), error: literal('InvalidEncoding') }),
  'trailing-certificate-byte': object({ name: literal('trailing-certificate-byte'), operation: literal('decode_certificate'), inputs: object({ body }), error: literal('InvalidEncoding') }),
  'stale-ceremony-predecessor': object({ name: literal('stale-ceremony-predecessor'), operation: literal('authorize_ceremony'), inputs: object({ body, pinned_predecessor: h32, signature }), error: literal('InvalidCeremony') }),
  'signed-valid-share': object({ name: literal('signed-valid-share'), operation: literal('verify_fault_proof'), inputs: faultInputs, outputs: object({ signing_preimage: h32, verdict: literal('NotAFault'), reason: literal('ValidShare') }) }),
  'signed-bad-share': object({ name: literal('signed-bad-share'), operation: literal('verify_fault_proof'), inputs: faultInputs, outputs: object({ signing_preimage: h32, verdict: literal('Fault'), member: index }) }),
  'genuine-old-response-after-rekey': object({ name: literal('genuine-old-response-after-rekey'), operation: literal('verify_fault_proof'), inputs: object({ certificate_body: body, owner_signature: signature, request: body, share: hexField(259), signature }), outputs: object({ verdict: literal('NotAFault'), reason: literal('ContextMismatch') }) }),
  'activation-under-quorum': object({ name: literal('activation-under-quorum'), operation: literal('verify_activation'), inputs: activationErrorInputs, error: literal('NotEnoughReady') }),
  'activation-zero-budget': object({ name: literal('activation-zero-budget'), operation: literal('verify_activation'), inputs: activationErrorInputs, error: literal('InvalidReadiness') }),
  'activation-budget-overflow': object({ name: literal('activation-budget-overflow'), operation: literal('verify_activation'), inputs: activationErrorInputs, error: literal('InvalidReadiness') }),
  'activation-duplicate-member': object({ name: literal('activation-duplicate-member'), operation: literal('verify_activation'), inputs: activationErrorInputs, error: literal('InvalidReadiness') }),
};
export type CertificateCase = Parsed<(typeof cases)[keyof typeof cases]>;
const parseCases: Parser<CertificateCase[]> = (v, p) => {
  if (!Array.isArray(v) || v.length !== Object.keys(cases).length) return invalid(p);
  const seen = new Set<string>();
  return v.map((entry: unknown, i) => {
    if (!entry || typeof entry !== 'object' || !('name' in entry) || typeof entry.name !== 'string' || !Object.hasOwn(cases, entry.name) || seen.has(entry.name)) return invalid(`${p}[${i}]`);
    seen.add(entry.name);
    return cases[entry.name as keyof typeof cases](entry, `${p}[${i}].${entry.name}`);
  });
};
const sections: Parser<string[]> = (v, p) => {
  const expected = ['3.0', '3.8', '3.9', '3.12', 'S0.1 amendment'];
  if (!Array.isArray(v) || v.length !== expected.length || v.some((entry, i) => entry !== expected[i])) return invalid(p);
  return expected;
};
const parseFile = object({
  cases: parseCases,
  dst: object({ activation: literal(CERT_TAGS.activation), ceremony: literal(CERT_TAGS.ceremony), certificate: literal(CERT_TAGS.certificate), closure: literal(CERT_TAGS.closure), message: literal(CERT_TAGS.message), readiness: literal(CERT_TAGS.readiness), statement: literal(CERT_TAGS.statement), transcript: literal(CERT_TAGS.transcript) }),
  encoding: literal('lowercase hex; unsigned integers big-endian; lp=u32be length followed by bytes'), format_version: literal(1),
  seeds: object({ ed25519: array(object({ did: text, public_key: h32, seed: h32 }), 17), test_dealer_genesis: intField(0, 255), test_dealer_rekey: intField(0, 255), test_dealer_reshare: intField(0, 255) }),
  spec_sections: sections, suite: literal('TC-THRESHOLD-V1'),
});
export type CertificateFile = Parsed<typeof parseFile>;
export function parseCertificateVectors(value: unknown): CertificateFile { return parseFile(value, 'certificates'); }
export function certificateCase<N extends CertificateCase['name']>(file: CertificateFile, name: N): Extract<CertificateCase, { name: N }> {
  const found = file.cases.find((entry): entry is Extract<CertificateCase, { name: N }> => entry.name === name);
  if (!found) return invalid(name);
  return found;
}

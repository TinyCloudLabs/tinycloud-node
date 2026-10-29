import { DST, PEDERSEN_H_MESSAGE } from './protocol.ts';

type Parser<T> = (value: unknown, path: string) => T;
type Parsed<P> = P extends Parser<infer T> ? T : never;
function invalid(path: string): never { throw new Error(`schema: ${path}`); }
function literal<const T extends string | number>(expected: T): Parser<T> {
  return (v, p) => v === expected ? expected : invalid(p);
}
function hexField(length: number): Parser<string> {
  return (v, p) => typeof v === 'string' && v.length === length * 2 && /^[0-9a-f]+$/.test(v) ? v : invalid(p);
}
function intField(min: number, max: number): Parser<number> {
  return (v, p) => typeof v === 'number' && Number.isInteger(v) && v >= min && v <= max ? v : invalid(p);
}
function object<S extends Record<string, Parser<unknown>>>(shape: S): Parser<{ [K in keyof S]: Parsed<S[K]> }> {
  return (v, p) => {
    if (!v || typeof v !== 'object' || Array.isArray(v)) return invalid(p);
    const input = v as Record<string, unknown>;
    if (Object.keys(input).length !== Object.keys(shape).length || Object.keys(input).some(k => !(k in shape))) return invalid(p);
    const result: Record<string, unknown> = {};
    for (const k of Object.keys(shape)) result[k] = shape[k]!(input[k], `${p}.${k}`);
    return result as { [K in keyof S]: Parsed<S[K]> };
  };
}
function array<T>(parse: Parser<T>, length: number): Parser<T[]> {
  return (v, p) => {
    if (!Array.isArray(v) || v.length !== length) return invalid(p);
    return v.map((x: unknown, i) => parse(x, `${p}[${i}]`));
  };
}
const h32 = hexField(32), h48 = hexField(48), h96 = hexField(96), member = intField(1, 16);
const shareOutput = object({ member, encoded: hexField(259), c1: h48, c2: h96, c3: h48, signing_preimage: h32 });
const thresholdInputs = object({
  context: hexField(79), context_digest: h32, certificate_digest: h32,
  threshold: literal(2), members: literal(3), master_scalar: h32, mpk: h96,
  public_shares: array(object({ member, point: h96 }), 3), scalar_shares: array(object({ member, scalar: h32 }), 3),
  transport_scalar: h32, transport_public: h48, identity: hexField(100), request: hexField(259), request_digest: h32,
});
const cases = {
  h1_custom_dst: object({ name: literal('h1_custom_dst'), operation: literal('hash_g1'), inputs: object({ message: hexField(100), dst: literal(DST.h1) }), outputs: object({ point: h48 }) }),
  pedersen_h: object({ name: literal('pedersen_h'), operation: literal('hash_g2'), inputs: object({ message: literal(PEDERSEN_H_MESSAGE), dst: literal(DST.pedersen_h) }), outputs: object({ point: h96 }) }),
  h3_scalar_r: object({ name: literal('h3_scalar_r'), operation: literal('h3'), inputs: object({ message: hexField(64) }), outputs: object({ scalar: h32 }) }),
  h2_gt: object({ name: literal('h2_gt'), operation: literal('h2'), inputs: object({ message: hexField(576) }), outputs: object({ bytes: h32 }) }),
  h4_sigma: object({ name: literal('h4_sigma'), operation: literal('h4'), inputs: object({ message: h32 }), outputs: object({ bytes: h32 }) }),
  pairing_generators: object({ name: literal('pairing_generators'), operation: literal('pairing'), inputs: object({ g1: h48, g2: h96 }), outputs: object({ gt: hexField(576) }) }),
  pairing_5_7: object({ name: literal('pairing_5_7'), operation: literal('pairing'), inputs: object({ g1: h48, g2: h96 }), outputs: object({ gt: hexField(576) }) }),
  fullident_wrap_unwrap: object({ name: literal('fullident_wrap_unwrap'), operation: literal('fullident'), inputs: object({ master_scalar: h32, mpk: h96, identity: hexField(100), message: h32, sigma: h32 }), outputs: object({ ciphertext: hexField(160), derived_key: h48, unwrapped: h32 }) }),
  threshold_2of3: object({ name: literal('threshold_2of3'), operation: literal('threshold'), inputs: thresholdInputs, outputs: object({ encrypted_shares: array(shareOutput, 3), selected_members: array(intField(0, 65535), 2), aggregate: object({ c1: h48, c2: h96, c3: h48 }), derived_key: h48 }) }),
  noncanonical_scalar: object({ name: literal('noncanonical_scalar'), operation: literal('decode_scalar'), inputs: object({ bytes: h32 }), error: literal('InvalidScalar') }),
  identity_transport: object({ name: literal('identity_transport'), operation: literal('decode_transport'), inputs: object({ bytes: h48 }), error: literal('IdentityPoint') }),
  identity_mpk: object({ name: literal('identity_mpk'), operation: literal('decode_mpk'), inputs: object({ bytes: h96 }), error: literal('IdentityPoint') }),
  share_c3_mutated: object({ name: literal('share_c3_mutated'), operation: literal('verify_share'), inputs: object({ reference: literal('threshold_2of3'), share: hexField(259) }), error: literal('Invalid'), member: literal(1) }),
  share_context_transplanted: object({ name: literal('share_context_transplanted'), operation: literal('verify_share'), inputs: object({ reference: literal('threshold_2of3'), share: hexField(259) }), error: literal('ContextMismatch') }),
  share_identity_transplanted: object({ name: literal('share_identity_transplanted'), operation: literal('verify_share'), inputs: object({ reference: literal('threshold_2of3'), share: hexField(259), request: hexField(258) }), error: literal('ContextMismatch') }),
  fullident_u_mutated: object({ name: literal('fullident_u_mutated'), operation: literal('unwrap'), inputs: object({ reference: literal('fullident_wrap_unwrap'), ciphertext: hexField(160) }), error: literal('InvalidCiphertext') }),
  fullident_v_mutated: object({ name: literal('fullident_v_mutated'), operation: literal('unwrap'), inputs: object({ reference: literal('fullident_wrap_unwrap'), ciphertext: hexField(160) }), error: literal('InvalidCiphertext') }),
  fullident_w_mutated: object({ name: literal('fullident_w_mutated'), operation: literal('unwrap'), inputs: object({ reference: literal('fullident_wrap_unwrap'), ciphertext: hexField(160) }), error: literal('InvalidCiphertext') }),
};
export type VectorCase = Parsed<(typeof cases)[keyof typeof cases]>;
const parseCases: Parser<VectorCase[]> = (v, p) => {
  if (!Array.isArray(v) || v.length !== Object.keys(cases).length) return invalid(p);
  const seen = new Set<string>();
  const result = v.map((entry: unknown, i) => {
    if (!entry || typeof entry !== 'object' || !('name' in entry) || typeof entry.name !== 'string' || !Object.hasOwn(cases, entry.name) || seen.has(entry.name)) return invalid(`${p}[${i}]`);
    seen.add(entry.name);
    return cases[entry.name as keyof typeof cases](entry, `${p}[${i}].${entry.name}`);
  });
  return result;
};
const sections: Parser<string[]> = (v, p) => {
  const expected = ['3.2', '3.3', '3.4', '3.5', '3.6 + request-digest amendment'];
  if (!Array.isArray(v) || v.length !== expected.length || v.some((x, i) => x !== expected[i])) return invalid(p);
  return expected;
};
const file = object({
  format_version: literal(1), suite: literal('BLS12-381 / RFC9380 SHA-256 SSWU_RO / FullIdent / encrypted threshold shares'),
  encoding: literal('hex; GT coefficients in SPEC 3.2 order'), spec_sections: sections,
  seeds: object({ dealer: h32, transport: h32, shares: h32, wrap: h32 }),
  dst: object({ h1: literal(DST.h1), h2: literal(DST.h2), h3: literal(DST.h3), h4: literal(DST.h4), pedersen_h: literal(DST.pedersen_h) }),
  cases: parseCases,
});
export type VectorFile = Parsed<typeof file>;
export function parseVectors(value: unknown): VectorFile { return file(value, 'vectors'); }
export function vector<N extends VectorCase['name']>(file: VectorFile, name: N): Extract<VectorCase, { name: N }> {
  const found = file.cases.find((c): c is Extract<VectorCase, { name: N }> => c.name === name);
  if (!found) return invalid(name);
  return found;
}

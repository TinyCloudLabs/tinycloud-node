import { ProtocolError, bytes, hex, type G2 } from './protocol.ts';
import { TAG, ed25519Verifier, type RoundRecord, type Statement, type Verifier } from './ceremony.ts';
import type { Exclusion } from './dkg.ts';
import { hexField, intField, invalid, literal, object, type Parsed, type Parser } from './schema.ts';

// Schema pieces and comparison helpers shared by every transcript-style vector document.
export const hexBytes: Parser<string> = (v, p) => typeof v === 'string' && /^(?:[0-9a-f]{2})*$/.test(v) ? v : invalid(p);
export const text: Parser<string> = (v, p) => typeof v === 'string' && v.length > 0 ? v : invalid(p);
export function list<T>(parse: Parser<T>, min = 0, max = 0xffff): Parser<T[]> {
  return (v, p) => Array.isArray(v) && v.length >= min && v.length <= max ? v.map((x: unknown, i) => parse(x, `${p}[${i}]`)) : invalid(p);
}
export function nullable<T>(parse: Parser<T>): Parser<T | null> { return (v, p) => v === null ? null : parse(v, p); }
export const h32 = hexField(32), h96 = hexField(96), member = intField(1, 16);
export const statement = object({ body: hexBytes, signature: hexBytes });
/** A signed certificate: the canonical body plus the owner signature. */
export const certificateShape = object({ body: hexBytes, owner_signature: hexBytes });
export const rounds = list(object({ closure: statement, messages: list(statement) }));
export const exclusion: Parser<Exclusion> = (v, p) => v && typeof v === 'object' && 'round' in v
  ? object({ member, reason: text, round: intField(1, 6) })(v, p)
  : object({ member, reason: text })(v, p);
export const shares = list(object({ member, point: h96 }), 1, 16);
export const signers = list(object({ did: text, ed25519_public_key: h32 }), 1, 64);
export const anchorShape = object({ network: text, owner: text });
export const ceremonySeeds = object({ ceremonies: list(intField(0, 255), 1) });
export const sharedDst = {
  ceremony_auth: literal(TAG.ceremonyAuth), ceremony_msg: literal(TAG.ceremonyMsg), commitments: literal(TAG.commitments),
  dealing: literal(TAG.dealing), round_close: literal(TAG.roundClose), transcript: literal(TAG.transcript),
};
export function exactList<const T extends readonly string[]>(expected: T): Parser<T> {
  return (v, p) => Array.isArray(v) && v.length === expected.length && v.every((x, i) => x === expected[i]) ? expected : invalid(p);
}
export const encoding = literal('hex; statements are exact signed bytes; scalars 32-byte big-endian; G2 96-byte compressed');

/** Case records carry either `outputs` (success) or `error` (a typed refusal), never both; names are unique. */
export function cases<O extends string, I, Out>(operation: O, inputs: Parser<I>, outputs: Parser<Out>) {
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

export function same(label: string, actual: unknown, expected: unknown) {
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
export function outcome<T>(run: () => T): { error: string } | { value: T } {
  try { return { value: run() }; } catch (e) {
    if (e instanceof ProtocolError) return { error: e.code };
    throw e;
  }
}
export const points = (p: G2[]) => p.map(x => hex(x.toBytes()));
export const indexed = (p: G2[]) => p.map((x, k) => ({ member: k + 1, point: hex(x.toBytes()) }));
export const exclusions = (e: Exclusion[]) => e.map(x => ({ member: x.member, reason: x.reason, ...(x.round === undefined ? {} : { round: x.round }) }));

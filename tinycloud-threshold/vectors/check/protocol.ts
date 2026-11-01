import { createHash } from 'node:crypto';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';

export type Bytes = Uint8Array;
export type G1 = typeof bls.G1.Point.BASE;
export type G2 = typeof bls.G2.Point.BASE;
export type GT = typeof bls.fields.Fp12.ONE;
export const R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;
export const DST = {
  h1: 'TC-THRESHOLD-V1-IBE-ID_BLS12381G1_XMD:SHA-256_SSWU_RO_',
  pedersen_h: 'TC-THRESHOLD-V1-PEDERSEN-H_BLS12381G2_XMD:SHA-256_SSWU_RO_',
  h2: 'TC-THRESHOLD-V1-IBE-H2', h3: 'TC-THRESHOLD-V1-IBE-H3', h4: 'TC-THRESHOLD-V1-IBE-H4',
};
export const PEDERSEN_H_MESSAGE = '706564657273656e2d68';
const PREFIX = 'TC-THRESHOLD-V1-IBE-ID-ENC';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export class ProtocolError extends Error {
  constructor(readonly code: string, readonly member?: number) { super(code); }
}
export function hex(b: Bytes): string { return Buffer.from(b).toString('hex'); }
export function bytes(s: string): Bytes {
  if (typeof s !== 'string' || !/^(?:[0-9a-f]{2})*$/.test(s)) throw new ProtocolError('InvalidEncoding');
  return new Uint8Array(Buffer.from(s, 'hex'));
}
export function concat(...parts: Bytes[]): Bytes {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) { out.set(p, offset); offset += p.length; }
  return out;
}
export function be(value: bigint, length: number): Bytes {
  if (value < 0n || value >= 1n << BigInt(8 * length)) throw new ProtocolError('InvalidEncoding');
  return bytes(value.toString(16).padStart(length * 2, '0'));
}
function integer(b: Bytes): bigint { return b.length ? BigInt(`0x${hex(b)}`) : 0n; }
export function lp(b: Bytes): Bytes { return concat(be(BigInt(b.length), 4), b); }
function equal(a: Bytes, b: Bytes): boolean { return a.length === b.length && a.every((v, i) => v === b[i]); }
function sha256(b: Bytes): Bytes { return new Uint8Array(createHash('sha256').update(b).digest()); }
export function tagged(tag: string, body: Bytes): Bytes { return sha256(concat(lp(encoder.encode(tag)), body)); }

export function xmd(message: Bytes, dst: string, length: number): Bytes {
  const tag = encoder.encode(dst);
  const count = Math.ceil(length / 32);
  if (tag.length > 255 || length < 1 || count > 255) throw new ProtocolError('InvalidEncoding');
  const suffix = concat(tag, be(BigInt(tag.length), 1));
  const b0 = sha256(concat(new Uint8Array(64), message, be(BigInt(length), 2), be(0n, 1), suffix));
  let previous = sha256(concat(b0, be(1n, 1), suffix));
  const blocks = [previous];
  for (let i = 2; i <= count; i++) {
    previous = sha256(concat(xor(b0, previous), be(BigInt(i), 1), suffix));
    blocks.push(previous);
  }
  return concat(...blocks).slice(0, length);
}
function xor(a: Bytes, b: Bytes): Bytes {
  if (a.length !== b.length) throw new ProtocolError('InvalidEncoding');
  return a.map((v, i) => v ^ b[i]!);
}
export function scalar(b: Bytes): bigint {
  if (b.length !== 32 || integer(b) >= R) throw new ProtocolError('InvalidScalar');
  return integer(b);
}
export function g1(b: Bytes, identityAllowed = false): G1 {
  let p: G1;
  try {
    if (b.length !== 48 || !(b[0]! & 0x80)) throw new Error();
    p = bls.G1.Point.fromBytes(b);
    p.assertValidity();
    if (!p.isTorsionFree() || !equal(p.toBytes(), b)) throw new Error();
  } catch { throw new ProtocolError('InvalidPoint'); }
  if (!identityAllowed && p.equals(bls.G1.Point.ZERO)) throw new ProtocolError('IdentityPoint');
  return p;
}
export function g2(b: Bytes, identityAllowed = false): G2 {
  let p: G2;
  try {
    if (b.length !== 96 || !(b[0]! & 0x80)) throw new Error();
    p = bls.G2.Point.fromBytes(b);
    p.assertValidity();
    if (!p.isTorsionFree() || !equal(p.toBytes(), b)) throw new Error();
  } catch { throw new ProtocolError('InvalidPoint'); }
  if (!identityAllowed && p.equals(bls.G2.Point.ZERO)) throw new ProtocolError('IdentityPoint');
  return p;
}
export function h1(identity: Bytes): G1 { return bls.G1.hashToCurve(identity, { DST: DST.h1 }); }
export function h3(message: Bytes): bigint { return integer(xmd(message, DST.h3, 48)) % R; }
export function pairing(a: G1, b: G2): GT {
  if (a.equals(bls.G1.Point.ZERO) || b.equals(bls.G2.Point.ZERO)) return bls.fields.Fp12.ONE;
  return bls.pairing(a, b, true);
}
export function encodeGT(gt: GT): Bytes {
  const coefficients: bigint[] = [];
  for (const a of [gt.c0, gt.c1]) for (const b of [a.c0, a.c1, a.c2]) coefficients.push(b.c0, b.c1);
  return concat(...coefficients.map(c => be(c, 48)));
}

export class Reader {
  private offset = 0;
  constructor(private readonly input: Bytes) {
    if (input.length > 65536) throw new ProtocolError('InvalidEncoding');
  }
  take(length: number): Bytes {
    if (length < 0 || length > this.input.length - this.offset) throw new ProtocolError('InvalidEncoding');
    const b = this.input.slice(this.offset, this.offset + length); this.offset += length; return b;
  }
  int(length: number): bigint { return integer(this.take(length)); }
  field(cap: number): Bytes {
    const length = Number(this.int(4));
    if (length > cap) throw new ProtocolError('InvalidEncoding');
    return this.take(length);
  }
  text(cap = 1024): string {
    const b = this.field(cap);
    if (b.length === 0) throw new ProtocolError('InvalidEncoding');
    try { return decoder.decode(b); } catch { throw new ProtocolError('InvalidEncoding'); }
  }
  version() { if (this.int(1) !== 1n) throw new ProtocolError('InvalidEncoding'); }
  end() { if (this.offset !== this.input.length) throw new ProtocolError('InvalidEncoding'); }
}
export interface Identity { mode: number; network: string; path: string; version: bigint; nonce?: Bytes }
export function encodeIdentity(id: Identity): Bytes {
  return concat(lp(encoder.encode(PREFIX)), be(1n, 1), be(BigInt(id.mode), 1), lp(encoder.encode(id.network)), lp(encoder.encode(id.path)), be(id.version, 8), id.mode === 1 ? (id.nonce ?? new Uint8Array()) : new Uint8Array());
}
export function decodeIdentity(b: Bytes): Identity {
  const r = new Reader(b);
  if (!equal(r.field(26), encoder.encode(PREFIX))) throw new ProtocolError('InvalidEncoding');
  r.version();
  const mode = Number(r.int(1));
  if (mode !== 1 && mode !== 2) throw new ProtocolError('InvalidEncoding');
  const id: Identity = { mode, network: r.text(), path: r.text(), version: r.int(8) };
  if (mode === 1) id.nonce = r.take(16);
  r.end(); return id;
}
export interface Context { network: string; rekey: bigint; epoch: bigint; certificate: Bytes; threshold: number; members: number }
export function encodeContext(c: Context): Bytes {
  return concat(be(1n, 1), lp(encoder.encode(c.network)), be(c.rekey, 8), be(c.epoch, 8), c.certificate, be(BigInt(c.threshold), 2), be(BigInt(c.members), 2));
}
export function decodeContext(b: Bytes): Context {
  const r = new Reader(b); r.version();
  const c = { network: r.text(), rekey: r.int(8), epoch: r.int(8), certificate: r.take(32), threshold: Number(r.int(2)), members: Number(r.int(2)) };
  r.end();
  if (c.threshold < 2 || c.threshold > c.members || c.members > 16) throw new ProtocolError('InvalidParameters');
  return c;
}
export function contextDigest(c: Context): Bytes { return tagged('TC-THRESHOLD-V1-KEY-CONTEXT', encodeContext(c)); }
export interface Request { context: Bytes; network: string; rekey: bigint; epoch: bigint; certificate: Bytes; identity: Bytes; tpk: Bytes }
export function encodeRequest(r: Request): Bytes {
  return concat(be(1n, 1), r.context, lp(encoder.encode(r.network)), be(r.rekey, 8), be(r.epoch, 8), r.certificate, lp(r.identity), r.tpk);
}
export function decodeRequest(b: Bytes): Request {
  const r = new Reader(b); r.version();
  const req = { context: r.take(32), network: r.text(), rekey: r.int(8), epoch: r.int(8), certificate: r.take(32), identity: r.field(4096), tpk: r.take(48) };
  r.end();
  if (decodeIdentity(req.identity).network !== req.network) throw new ProtocolError('ContextMismatch');
  g1(req.tpk); return req;
}
export function requestDigest(b: Bytes): Bytes { return tagged('TC-THRESHOLD-V1-DECRYPT-REQUEST', b); }
export interface Share { member: number; context: Bytes; request: Bytes; c1: Bytes; c2: Bytes; c3: Bytes }
export function encodeShare(s: Share): Bytes {
  return concat(be(1n, 1), be(BigInt(s.member), 2), s.context, s.request, s.c1, s.c2, s.c3);
}
export function decodeShare(b: Bytes): Share {
  const r = new Reader(b); r.version();
  const s = { member: Number(r.int(2)), context: r.take(32), request: r.take(32), c1: r.take(48), c2: r.take(96), c3: r.take(48) };
  r.end();
  if (s.member < 1 || s.member > 16) throw new ProtocolError('InvalidEncoding');
  g1(s.c1); g2(s.c2); g1(s.c3, true); return s;
}
export function signingPreimage(share: Bytes, request: Bytes, certificate: Bytes): Bytes {
  const s = decodeShare(share);
  if (request.length !== 32 || certificate.length !== 32 || !equal(s.request, request)) throw new ProtocolError('ContextMismatch');
  return tagged('TC-THRESHOLD-V1-DECRYPT-SHARE', concat(request, certificate, be(BigInt(s.member), 2), share));
}
export interface Keyset { context: Context; mpk: G2; publicShares: Map<number, G2> }
function boundRequest(keys: Keyset, encoded: Bytes): Request {
  const req = decodeRequest(encoded), c = keys.context;
  if (!equal(req.context, contextDigest(c)) || req.network !== c.network || req.rekey !== c.rekey || req.epoch !== c.epoch || !equal(req.certificate, c.certificate)) throw new ProtocolError('ContextMismatch');
  return req;
}
function boundShare(keys: Keyset, req: Request, digest: Bytes, s: Share): boolean {
  return equal(s.context, req.context) && equal(s.request, digest) && s.member <= keys.context.members && keys.publicShares.has(s.member);
}
function equations(keys: Keyset, req: Request, s: Share) {
  const c1 = g1(s.c1), c2 = g2(s.c2), c3 = g1(s.c3, true), fp = bls.fields.Fp12;
  const first = fp.eql(pairing(c1, bls.G2.Point.BASE), pairing(bls.G1.Point.BASE, c2));
  const second = fp.eql(pairing(c3, bls.G2.Point.BASE), fp.mul(pairing(h1(req.identity), keys.publicShares.get(s.member)!), pairing(g1(req.tpk), c2)));
  if (!first || !second) throw new ProtocolError('Invalid', s.member);
}
export function verifyShare(keys: Keyset, request: Bytes, share: Bytes): number {
  const req = boundRequest(keys, request), s = decodeShare(share);
  if (!boundShare(keys, req, requestDigest(request), s)) throw new ProtocolError('ContextMismatch');
  equations(keys, req, s); return s.member;
}
export function combine(keys: Keyset, request: Bytes, shares: Bytes[], transport: bigint): { key: Bytes; selected: number[]; aggregate: { c1: Bytes; c2: Bytes; c3: Bytes } } {
  const req = boundRequest(keys, request), digest = requestDigest(request);
  const decoded = shares.map(decodeShare);
  for (const s of decoded) if (!boundShare(keys, req, digest, s)) throw new ProtocolError('MixedContexts');
  for (const s of decoded) equations(keys, req, s);
  const distinct = new Map(decoded.map(s => [s.member, s]));
  if (distinct.size < keys.context.threshold) throw new ProtocolError('NotEnoughShares');
  const selected = [...distinct.keys()].sort((a, b) => a - b).slice(0, keys.context.threshold);
  let c1 = bls.G1.Point.ZERO, c2 = bls.G2.Point.ZERO, c3 = bls.G1.Point.ZERO;
  for (const i of selected) {
    let lambda = 1n;
    for (const j of selected) if (i !== j) lambda = bls.fields.Fr.mul(lambda, bls.fields.Fr.div(BigInt(j), bls.fields.Fr.create(BigInt(j - i))));
    const s = distinct.get(i)!;
    c1 = c1.add(g1(s.c1).multiply(lambda));
    c2 = c2.add(g2(s.c2).multiply(lambda));
    const p3 = g1(s.c3, true);
    c3 = c3.add(p3.equals(bls.G1.Point.ZERO) ? p3 : p3.multiply(lambda));
  }
  const k = c3.subtract(c1.equals(bls.G1.Point.ZERO) || transport === 0n ? bls.G1.Point.ZERO : c1.multiply(transport));
  if (k.equals(bls.G1.Point.ZERO) || !bls.fields.Fp12.eql(pairing(k, bls.G2.Point.BASE), pairing(h1(req.identity), keys.mpk))) throw new ProtocolError('InvalidDerivedKey');
  return { key: k.toBytes(), selected, aggregate: {
    c1: (c1.equals(bls.G1.Point.ZERO) ? bls.G1.Point.ZERO : c1).toBytes(),
    c2: (c2.equals(bls.G2.Point.ZERO) ? bls.G2.Point.ZERO : c2).toBytes(),
    c3: (c3.equals(bls.G1.Point.ZERO) ? bls.G1.Point.ZERO : c3).toBytes(),
  } };
}
export function wrap(mpk: G2, identity: Bytes, message: Bytes, sigma: Bytes): Bytes {
  decodeIdentity(identity);
  if (message.length !== 32 || sigma.length !== 32) throw new ProtocolError('InvalidEncoding');
  const rho = h3(concat(sigma, message));
  if (rho === 0n) throw new ProtocolError('DegenerateRandomness');
  const u = bls.G2.Point.BASE.multiply(rho).toBytes();
  const mask = xmd(encodeGT(pairing(h1(identity).multiply(rho), mpk)), DST.h2, 32);
  return concat(u, xor(sigma, mask), xor(message, xmd(sigma, DST.h4, 32)));
}
export function unwrap(key: Bytes, keyIdentity: Bytes, expectedIdentity: Bytes, ciphertext: Bytes): Bytes {
  if (!equal(keyIdentity, expectedIdentity)) throw new ProtocolError('WrongIdentity');
  if (ciphertext.length !== 160) throw new ProtocolError('InvalidCiphertext');
  let u: G2;
  try { u = g2(ciphertext.slice(0, 96)); } catch (e) {
    if (e instanceof ProtocolError) throw new ProtocolError('InvalidCiphertext');
    throw e;
  }
  const sigma = xor(ciphertext.slice(96, 128), xmd(encodeGT(pairing(g1(key), u)), DST.h2, 32));
  const message = xor(ciphertext.slice(128), xmd(sigma, DST.h4, 32));
  const rho = h3(concat(sigma, message));
  if (rho === 0n || !bls.G2.Point.BASE.multiply(rho).equals(u)) throw new ProtocolError('InvalidCiphertext');
  return message;
}

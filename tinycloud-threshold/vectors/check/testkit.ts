// Test-only transcript construction from SPEC byte layouts. Encoders here are written
// separately from the verifier's decoders; expected outputs are computed in the scalar
// domain (Σ coefficients, then ·g2) rather than through the verifier's point aggregation.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { DST, PEDERSEN_H_MESSAGE, R, ProtocolError, be, bytes, concat, hex, lp, tagged, type Bytes, type G2 } from './protocol.ts';
import { ed25519Verifier, type RoundRecord, type Statement } from './ceremony.ts';

const enc = new TextEncoder();
const sha = (alg: 'sha256' | 'sha512', ...parts: Bytes[]) => new Uint8Array(createHash(alg).update(concat(...parts)).digest());
const certCore: { seeds: { ed25519: { did: string; seed: string }[] } } = JSON.parse(readFileSync(new URL('../v1/cert-core.json', import.meta.url), 'utf8'));
/** Public test seeds published in cert-core.json; fixture-N signs with seed N. */
export const SEEDS = new Map(certCore.seeds.ed25519.map(s => [s.did, bytes(s.seed)]));
export const did = (n: number) => `did:key:tc2222-fixture-${n}`;
export const OWNER = did(0);
export const NETWORK = 'tinycloud:test:certificates';
export const ANCHOR = { owner: OWNER, network: NETWORK };
export const verify = ed25519Verifier(new Map([...SEEDS].map(([d, seed]) => [d, ed25519.getPublicKey(seed)])));
export function sign(signer: string, message: Bytes): Bytes {
  const seed = SEEDS.get(signer);
  if (!seed) throw new Error(`no test seed for ${signer}`);
  return ed25519.sign(message, seed);
}
/** RFC 8032 group order L. */
export const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const le = (b: Bytes) => BigInt(`0x${hex(b.slice().reverse()) || '0'}`);
const toLe = (v: bigint) => be(v, 32).reverse();
/** A second valid RFC 8032 signature with a different nonce: same signer, same message, different bytes. */
export function alternateSignature(signer: string, message: Bytes): Bytes {
  const h = sha('sha512', SEEDS.get(signer)!);
  const head = h.slice(0, 32); head[0]! &= 248; head[31]! &= 127; head[31]! |= 64;
  const a = le(head), A = ed25519.getPublicKey(SEEDS.get(signer)!);
  const r = le(sha('sha512', h.slice(32), message, new Uint8Array([1]))) % L;
  const Rb = ed25519.Point.BASE.multiply(r).toBytes();
  const k = le(sha('sha512', Rb, A, message)) % L;
  return concat(Rb, toLe((r + k * a) % L));
}
/** The same signature with S replaced by S + L (non-canonical; rejected by strict RFC 8032). */
export function nonCanonicalS(signature: Bytes): Bytes {
  return concat(signature.slice(0, 32), toLe(le(signature.slice(32)) + L));
}
/**
 * A signature valid under ZIP-215 but not strict RFC 8032: R is the identity point
 * encoded non-canonically (y = 1 + p) and S = k·a, so S·B = R + k·A holds exactly.
 */
export function nonCanonicalR(signer: string, message: Bytes): Bytes {
  const h = sha('sha512', SEEDS.get(signer)!);
  const head = h.slice(0, 32); head[0]! &= 248; head[31]! &= 127; head[31]! |= 64;
  const Rb = toLe((1n << 255n) - 18n), A = ed25519.getPublicKey(SEEDS.get(signer)!);
  const k = le(sha('sha512', Rb, A, message)) % L;
  return concat(Rb, toLe((k * le(head)) % L));
}

export function scalarOf(label: string): bigint {
  const v = BigInt(`0x${hex(sha('sha256', enc.encode(label)))}`) % R;
  return v === 0n ? 1n : v;
}
export function poly(label: string, degreePlusOne: number): bigint[] {
  return Array.from({ length: degreePlusOne }, (_, k) => scalarOf(`${label}/${k}`));
}
export function at(coefficients: readonly bigint[], x: number): bigint {
  return coefficients.reduceRight((acc, c) => (acc * BigInt(x) + c) % R, 0n);
}
export const G2_BASE = bls.G2.Point.BASE, G2_ZERO = bls.G2.Point.ZERO;
export const H: G2 = bls.G2.hashToCurve(bytes(PEDERSEN_H_MESSAGE), { DST: DST.pedersen_h });
export function times(p: G2, k: bigint): G2 { const s = ((k % R) + R) % R; return s === 0n ? G2_ZERO : p.multiply(s); }
export const g2hex = (p: G2) => hex(p.toBytes());
export function lagrange(i: number, set: readonly number[]): bigint {
  let num = 1n, den = 1n;
  for (const j of set) if (j !== i) { num = (num * BigInt(j)) % R; den = (den * (((BigInt(j - i)) % R) + R)) % R; }
  return (num * bls.fields.Fr.inv(den)) % R;
}

// --- S0.2 statements --------------------------------------------------------------
export interface CeremonySpec {
  kind: number; id?: Bytes; network?: string; owner?: string; current?: Bytes;
  t: number; n: number; rekey?: bigint; epoch?: bigint; directory?: { index: number; did: string }[];
}
export function ceremonyBody(c: CeremonySpec): Bytes {
  const directory = c.directory ?? Array.from({ length: c.n }, (_, k) => ({ index: k + 1, did: did(k + 1) }));
  return concat(
    be(1n, 1), be(BigInt(c.kind), 1), c.id ?? new Uint8Array(32).fill(0x5a), lp(enc.encode(c.network ?? NETWORK)), lp(enc.encode(c.owner ?? OWNER)),
    c.current ? concat(be(1n, 1), c.current) : be(0n, 1),
    be(BigInt(c.t), 2), be(BigInt(c.n), 2), be(c.rekey ?? 0n, 8), be(c.epoch ?? 0n, 8), be(BigInt(directory.length), 2),
    ...directory.map(d => concat(be(BigInt(d.index), 2), lp(enc.encode(d.did)), new Uint8Array(32).fill(d.index))),
  );
}
export function signedCeremony(c: CeremonySpec, signer = OWNER): Statement {
  const body = ceremonyBody(c);
  return { body, signature: sign(signer, tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', body)) };
}
export interface CertificateSpec {
  network?: string; owner?: string; rekey?: bigint; epoch?: bigint; genesisT?: number; t: number; n: number;
  coefficients: bigint[]; mpk?: G2; transcript?: Bytes; previous?: Bytes; previousMpk?: G2;
}
export function certificateBody(c: CertificateSpec): Bytes {
  const commitments = c.coefficients.map(a => times(G2_BASE, a));
  return concat(
    be(1n, 1), lp(enc.encode(c.network ?? NETWORK)), lp(enc.encode(c.owner ?? OWNER)), be(c.rekey ?? 0n, 8), be(c.epoch ?? 0n, 8),
    be(BigInt(c.genesisT ?? c.t), 2), be(BigInt(c.t), 2), be(BigInt(c.n), 2), be(BigInt(c.n), 2),
    ...Array.from({ length: c.n }, (_, k) => concat(be(BigInt(k + 1), 2), lp(enc.encode(did(k + 1))))),
    (c.mpk ?? commitments[0]!).toBytes(), be(BigInt(commitments.length), 2), ...commitments.map(p => p.toBytes()),
    c.transcript ?? new Uint8Array(32).fill(7),
    c.previous ? concat(be(1n, 1), c.previous) : be(0n, 1),
    c.previousMpk ? concat(be(1n, 1), c.previousMpk.toBytes()) : be(0n, 1),
  );
}
export function signedCertificate(c: CertificateSpec, signer = OWNER): Statement & { digest: Bytes } {
  const body = certificateBody(c), digest = tagged('TC-THRESHOLD-V1-NETWORK-CERT', body);
  return { body, signature: sign(signer, tagged('TC-THRESHOLD-V1-CERT-STATEMENT', digest)), digest };
}

// --- Payloads ------------------------------------------------------------------------
const sealed = (dealer: number, recipient: number, plaintext: number) =>
  concat(be(1n, 1), new Uint8Array(32).fill(dealer), lp(new Uint8Array(plaintext + 16).fill(recipient)));
export function deal(commitments: readonly G2[], recipients: readonly number[], plaintext = 64, dealer = 1): Bytes {
  return concat(be(1n, 1), be(BigInt(commitments.length), 2), ...commitments.map(p => p.toBytes()),
    be(BigInt(recipients.length), 2), ...recipients.map(j => concat(be(BigInt(j), 2), lp(sealed(dealer, j, plaintext)))));
}
export function complaints(dealers: readonly number[]): Bytes {
  return concat(be(1n, 1), be(BigInt(dealers.length), 2), ...dealers.map(i => be(BigInt(i), 2)));
}
export function pairs(entries: readonly (readonly [number, bigint, bigint])[]): Bytes {
  return concat(be(1n, 1), be(BigInt(entries.length), 2), ...entries.map(([i, s, s2]) => concat(be(BigInt(i), 2), be(s, 32), be(s2, 32))));
}
export function values(entries: readonly (readonly [number, bigint])[]): Bytes {
  return concat(be(1n, 1), be(BigInt(entries.length), 2), ...entries.map(([i, v]) => concat(be(BigInt(i), 2), be(v, 32))));
}
export function feldman(points: readonly G2[]): Bytes {
  return concat(be(1n, 1), be(BigInt(points.length), 2), ...points.map(p => p.toBytes()));
}

// --- Rounds ---------------------------------------------------------------------------
/** One member message before envelope/signature; overrides produce adversarial envelopes. */
export interface Draft {
  cohort: number; index: number; payload: Bytes;
  signer?: string; round?: number; ceremony?: Bytes; signature?: (envelope: Bytes, signer: string) => Bytes;
}
export function envelope(ceremony: Bytes, round: number, d: Draft): Bytes {
  return concat(be(1n, 1), d.ceremony ?? ceremony, be(BigInt(d.round ?? round), 1), be(BigInt(d.cohort), 1), be(BigInt(d.index), 2), lp(d.payload));
}
/** Signs envelopes and closes every round in order under the owner, chaining from `start`. */
export function seal(ceremonyDigest: Bytes, start: Bytes, rounds: readonly Draft[][]): { records: RoundRecord[]; hash: Bytes } {
  let previous = start;
  const records = rounds.map((drafts, k) => {
    const messages = drafts.map(d => {
      const body = envelope(ceremonyDigest, k + 1, d), signer = d.signer ?? did(d.index), preimage = tagged('TC-THRESHOLD-V1-CEREMONY-MSG', body);
      return { body, signature: d.signature ? d.signature(preimage, signer) : sign(signer, preimage) };
    });
    const list = concat(be(BigInt(messages.length), 2), ...messages.flatMap(m => [lp(m.body), lp(m.signature)]));
    const closure = concat(be(1n, 1), ceremonyDigest, be(BigInt(k + 1), 1), tagged('TC-THRESHOLD-V1-TRANSCRIPT', list), previous);
    const record = { closure: { body: closure, signature: sign(OWNER, tagged('TC-THRESHOLD-V1-ROUND-CLOSE', closure)) }, messages };
    previous = tagged('TC-THRESHOLD-V1-TRANSCRIPT', concat(previous, lp(record.closure.body), lp(record.closure.signature)));
    return record;
  });
  return { records, hash: previous };
}
/** Splits a signed record back into drafts (cohort, index, payload), keeping the signer mapping. */
export function draftsOf(record: RoundRecord): Draft[] {
  return record.messages.map(m => ({ cohort: m.body[34]!, index: (m.body[35]! << 8) | m.body[36]!, payload: m.body.slice(41) }));
}

// --- Honest scenarios -------------------------------------------------------------------
export const COHORT_RECIPIENTS = 1, COHORT_DEALERS = 2;
export interface DkgDealer { index: number; a: bigint[]; b: bigint[]; C: G2[]; A: G2[] }
export function dkgDealers(label: string, t: number, n: number): DkgDealer[] {
  return Array.from({ length: n }, (_, k) => {
    const a = poly(`${label}/a/${k + 1}`, t), b = poly(`${label}/b/${k + 1}`, t);
    return { index: k + 1, a, b, C: a.map((x, m) => times(G2_BASE, x).add(times(H, b[m]!))), A: a.map(x => times(G2_BASE, x)) };
  });
}
export const pair = (d: DkgDealer, j: number) => [at(d.a, j), at(d.b, j)] as const;
export interface DkgSetup { t: number; n: number; ceremony: Statement; digest: Bytes; start: Bytes; dealers: DkgDealer[]; rounds: Draft[][] }
/** Honest 5-round genesis: everybody deals, nobody complains, empty R5. */
export function dkgSetup(label: string, t: number, n: number, spec: Partial<CeremonySpec> = {}): DkgSetup {
  const ceremony = signedCeremony({ kind: 1, t, n, id: sha('sha256', enc.encode(label)), ...spec });
  const digest = tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', ceremony.body), start = tagged('TC-THRESHOLD-V1-DKG-START', digest);
  const dealers = dkgDealers(label, t, n), members = dealers.map(d => d.index);
  const each = (payload: (i: number) => Bytes): Draft[] => members.map(i => ({ cohort: COHORT_RECIPIENTS, index: i, payload: payload(i) }));
  const rounds = [
    each(i => deal(dealers[i - 1]!.C, members, 64, i)), each(() => complaints([])), each(() => pairs([])),
    each(i => feldman(dealers[i - 1]!.A)), each(() => pairs([])),
  ];
  return { t, n, ceremony, digest, start, dealers, rounds };
}
/** Expected public material for QUAL, computed from scalar sums. */
export function expectedDkg(dealers: readonly DkgDealer[], qual: readonly number[], n: number) {
  const used = dealers.filter(d => qual.includes(d.index)), t = used[0]!.a.length;
  const sum = (f: (d: DkgDealer) => bigint) => used.reduce((acc, d) => (acc + f(d)) % R, 0n);
  return {
    commitments: Array.from({ length: t }, (_, k) => g2hex(times(G2_BASE, sum(d => d.a[k]!)))),
    publicShares: Array.from({ length: n }, (_, k) => g2hex(times(G2_BASE, sum(d => at(d.a, k + 1))))),
  };
}

export interface ReshareSetup {
  t: number; n: number; t2: number; n2: number; ceremony: Statement; certificate: Statement & { digest: Bytes };
  digest: Bytes; start: Bytes; master: bigint[]; shares: bigint[]; dealings: bigint[][]; rounds: Draft[][];
}
/** Honest redistribution from a genesis (t, n) certificate to (t2, n2); dealer i deals g_i with g_i(0) = s_i. */
export function reshareSetup(label: string, t: number, n: number, t2: number, n2: number, kind = 2, spec: Partial<CeremonySpec> = {}): ReshareSetup {
  const master = poly(`${label}/master`, t), shares = Array.from({ length: n }, (_, k) => at(master, k + 1));
  const certificate = signedCertificate({ t, n, coefficients: master });
  const ceremony = signedCeremony({ kind, t: t2, n: n2, current: certificate.digest, epoch: 1n, id: sha('sha256', enc.encode(label)), ...spec });
  const digest = tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', ceremony.body), start = tagged('TC-THRESHOLD-V1-RESHARE-START', digest);
  const dealings = shares.map((s, k) => [s, ...poly(`${label}/g/${k + 1}`, t2 - 1)]);
  const recipients = Array.from({ length: n2 }, (_, k) => k + 1), dealersIdx = Array.from({ length: n }, (_, k) => k + 1);
  const rounds: Draft[][] = [
    dealersIdx.map(i => ({ cohort: COHORT_DEALERS, index: i, payload: deal(dealings[i - 1]!.map(c => times(G2_BASE, c)), recipients, 32, i) })),
    recipients.map(j => ({ cohort: COHORT_RECIPIENTS, index: j, payload: complaints([]) })),
    dealersIdx.map(i => ({ cohort: COHORT_DEALERS, index: i, payload: values([]) })),
  ];
  return { t, n, t2, n2, ceremony, certificate, digest, start, master, shares, dealings, rounds };
}
export function expectedReshare(s: ReshareSetup, dealers: readonly number[]) {
  const coefficient = (k: number) => dealers.reduce((acc, i) => (acc + lagrange(i, dealers) * s.dealings[i - 1]![k]!) % R, 0n);
  const coefficients = Array.from({ length: s.t2 }, (_, k) => coefficient(k));
  return {
    commitments: coefficients.map(c => g2hex(times(G2_BASE, c))),
    publicShares: Array.from({ length: s.n2 }, (_, k) => g2hex(times(G2_BASE, at(coefficients, k + 1)))),
    mpk: g2hex(times(G2_BASE, s.master[0]!)),
  };
}

/** Typed error code of a verifier call, or 'ok'. */
export function code(run: () => unknown): string {
  try { run(); return 'ok'; } catch (e) {
    if (e instanceof ProtocolError) return e.code;
    throw e;
  }
}
export function flip(b: Bytes, offset: number, mask = 1): Bytes {
  const out = b.slice(); out[offset] = out[offset]! ^ mask; return out;
}

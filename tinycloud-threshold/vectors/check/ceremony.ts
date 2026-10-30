import { ed25519 } from '@noble/curves/ed25519.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { ProtocolError, Reader, R, be, concat, equal, g2, lp, tagged, type Bytes, type G2 } from './protocol.ts';

/** SPEC §3.3 and the S0.3/S0.4 appendix start labels. */
export const TAG = {
  ceremonyAuth: 'TC-THRESHOLD-V1-CEREMONY-AUTH',
  ceremonyMsg: 'TC-THRESHOLD-V1-CEREMONY-MSG',
  roundClose: 'TC-THRESHOLD-V1-ROUND-CLOSE',
  transcript: 'TC-THRESHOLD-V1-TRANSCRIPT',
  networkCert: 'TC-THRESHOLD-V1-NETWORK-CERT',
  certStatement: 'TC-THRESHOLD-V1-CERT-STATEMENT',
  commitments: 'TC-THRESHOLD-V1-COMMITMENTS',
  dealing: 'TC-THRESHOLD-V1-DEALING',
  dkgStart: 'TC-THRESHOLD-V1-DKG-START',
  reshareStart: 'TC-THRESHOLD-V1-RESHARE-START',
} as const;

/** SPEC §3.2 caps and the S0.2 appendix ordered-input bound. */
export const LIMIT = { members: 16, did: 256, signature: 512, message: 65536, transcript: 4194304 } as const;

/**
 * Typed errors for conditions SPEC describes but does not name. Every entry is
 * a default ruled by Naomi on 2026-10-30 (TC-2223); SPEC- and vector-named
 * codes (LimitExceeded, InvalidRound for record counts, InvalidCeremony,
 * ContextMismatch, IdentityPoint, InsufficientQualified, InsufficientRecovery,
 * UnsupportedFaultBudget, InvalidEncoding for decoders) are used literally.
 */
export const DEFAULT_ERROR = {
  /** Owner or member signature fails strict RFC 8032 verification, or the DID has no key. */
  signature: 'InvalidSignature',
  /** Closure body non-canonical, or names another ceremony/round/previous hash/ordered list. */
  closure: 'InvalidRound',
  /** Member envelope names another ceremony or round. */
  envelopeBinding: 'InvalidRound',
  /** Envelope cohort/index does not resolve in the signed cohort. */
  signer: 'InvalidIndex',
  /** Ceremony owner/network differs from the anchor. */
  ceremonyAnchor: 'InvalidCeremony',
  /** Current certificate owner/network differs from the anchor. */
  certificateAnchor: 'InvalidCertificate',
  /** Reshare B′_0 differs from the current mpk. */
  reshareMpk: 'ContextMismatch',
} as const;

export function fail(code: string): never { throw new ProtocolError(code); }

export interface Anchor { owner: string; network: string }
export interface Statement { body: Bytes; signature: Bytes }
export interface RoundRecord { closure: Statement; messages: Statement[] }
/** The injected DID verifier: strict RFC 8032 Ed25519 over the allow-listed keys. */
export type Verifier = (did: string, message: Bytes, signature: Bytes) => boolean;

export function ed25519Verifier(keys: ReadonlyMap<string, Bytes>): Verifier {
  return (did, message, signature) => {
    const key = keys.get(did);
    if (!key || signature.length !== 64) return false;
    try { return ed25519.verify(signature, message, key, { zip215: false }); } catch { return false; }
  };
}

const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
function did(r: Reader): string {
  const b = r.field(LIMIT.did);
  if (b.length === 0) fail('InvalidEncoding');
  try { return utf8.decode(b); } catch { return fail('InvalidEncoding'); }
}
function option(r: Reader, length: number): Bytes | undefined {
  const marker = r.int(1);
  if (marker === 0n) return undefined;
  if (marker !== 1n) fail('InvalidEncoding');
  return r.take(length);
}
/** A u16 list count, at most 16, checked before allocation. */
export function listCount(r: Reader): number {
  const n = Number(r.int(2));
  if (n > LIMIT.members) fail('InvalidEncoding');
  return n;
}
/** S0.2 directory rules: contiguous 1..=n, strictly increasing, distinct DIDs, 2 <= t <= n <= 16. */
function checkDirectory(t: number, n: number, entries: { index: number; did: string }[]) {
  if (t < 2 || t > n || n > LIMIT.members || entries.length !== n) fail('InvalidEncoding');
  if (entries.some((e, k) => e.index !== k + 1)) fail('InvalidEncoding');
  if (new Set(entries.map(e => e.did)).size !== n) fail('InvalidEncoding');
}

export const KIND = { genesis: 1, reshare: 2, refresh: 3, rekey: 4 } as const;
export interface Ceremony {
  kind: number; id: Bytes; network: string; owner: string; current?: Bytes;
  t: number; n: number; rekey: bigint; epoch: bigint;
  directory: { index: number; did: string; hpke: Bytes }[];
  digest: Bytes;
}
export function decodeCeremony(body: Bytes): Ceremony {
  const r = new Reader(body); r.version();
  const kind = Number(r.int(1));
  if (kind < KIND.genesis || kind > KIND.rekey) fail('InvalidEncoding');
  const id = r.take(32), network = r.text(), owner = did(r), current = option(r, 32);
  const t = Number(r.int(2)), n = Number(r.int(2)), rekey = r.int(8), epoch = r.int(8);
  const entries = listCount(r);
  const directory = Array.from({ length: entries }, () => ({ index: Number(r.int(2)), did: did(r), hpke: r.take(32) }));
  r.end();
  checkDirectory(t, n, directory);
  return { kind, id, network, owner, ...(current ? { current } : {}), t, n, rekey, epoch, directory, digest: tagged(TAG.ceremonyAuth, body) };
}
/** Decode, anchor, owner signature. Kind-specific rules belong to the caller. */
export function authorizeCeremony(anchor: Anchor, statement: Statement, verify: Verifier): Ceremony {
  const c = decodeCeremony(statement.body);
  if (c.owner !== anchor.owner || c.network !== anchor.network) fail(DEFAULT_ERROR.ceremonyAnchor);
  if (statement.signature.length > LIMIT.signature) fail('InvalidEncoding');
  if (!verify(anchor.owner, c.digest, statement.signature)) fail(DEFAULT_ERROR.signature);
  return c;
}

const G2_ZERO = bls.G2.Point.ZERO;
/** k·P for any k mod r, including zero and the identity point. */
export function mul(p: G2, k: bigint): G2 {
  const s = ((k % R) + R) % R;
  return s === 0n || p.equals(G2_ZERO) ? G2_ZERO : p.multiply(s);
}
/** Σ_k x^k·C_k. */
export function evaluate(commitments: readonly G2[], x: number): G2 {
  let acc = G2_ZERO, power = 1n;
  for (const c of commitments) { acc = acc.add(mul(c, power)); power = (power * BigInt(x)) % R; }
  return acc;
}

export interface Certificate {
  network: string; owner: string; rekey: bigint; epoch: bigint; genesisT: number; t: number; n: number;
  members: { index: number; did: string }[]; mpk: G2; commitments: G2[]; transcript: Bytes;
  previous?: Bytes; previousMpk?: G2; publicShares: G2[]; digest: Bytes;
}
export function decodeCertificate(body: Bytes): Omit<Certificate, 'publicShares'> {
  const r = new Reader(body); r.version();
  const network = r.text(), owner = did(r), rekey = r.int(8), epoch = r.int(8);
  const genesisT = Number(r.int(2)), t = Number(r.int(2)), n = Number(r.int(2));
  const memberCount = listCount(r);
  const members = Array.from({ length: memberCount }, () => ({ index: Number(r.int(2)), did: did(r) }));
  const mpkBytes = r.take(96);
  const commitmentCount = listCount(r);
  const commitmentBytes = Array.from({ length: commitmentCount }, () => r.take(96));
  const transcript = r.take(32), previous = option(r, 32), previousMpkBytes = option(r, 96);
  r.end();
  checkDirectory(t, n, members);
  if (genesisT < 2 || genesisT > LIMIT.members || commitmentCount !== t) fail('InvalidEncoding');
  const mpk = g2(mpkBytes), commitments = commitmentBytes.map(b => g2(b, true));
  if (!commitments[0]!.equals(mpk)) fail('InvalidEncoding');
  if (commitments[t - 1]!.equals(G2_ZERO)) fail('IdentityPoint');
  const previousMpk = previousMpkBytes ? g2(previousMpkBytes) : undefined;
  // §3.9 field combinations: genesis has neither predecessor field and zero counters; re-key has both.
  if (!previous && (previousMpk || epoch !== 0n || rekey !== 0n)) fail('InvalidEncoding');
  return {
    network, owner, rekey, epoch, genesisT, t, n, members, mpk, commitments, transcript,
    ...(previous ? { previous } : {}), ...(previousMpk ? { previousMpk } : {}), digest: tagged(TAG.networkCert, body),
  };
}
export function verifyCertificate(anchor: Anchor, statement: Statement, verify: Verifier): Certificate {
  const c = decodeCertificate(statement.body);
  if (c.owner !== anchor.owner || c.network !== anchor.network) fail(DEFAULT_ERROR.certificateAnchor);
  if (statement.signature.length > LIMIT.signature) fail('InvalidEncoding');
  if (!verify(anchor.owner, tagged(TAG.certStatement, c.digest), statement.signature)) fail(DEFAULT_ERROR.signature);
  const publicShares = c.members.map(m => evaluate(c.commitments, m.index));
  if (publicShares.some(p => p.equals(G2_ZERO))) fail('IdentityPoint');
  return { ...c, publicShares };
}

/** S0.2 ordered member list and its commitment. */
export function orderedListHash(messages: readonly Statement[]): Bytes {
  if (messages.length > 0xffff) fail(DEFAULT_ERROR.closure);
  return tagged(TAG.transcript, concat(be(BigInt(messages.length), 2), ...messages.flatMap(m => [lp(m.body), lp(m.signature)])));
}
export function transcriptUpdate(previous: Bytes, closure: Statement): Bytes {
  return tagged(TAG.transcript, concat(previous, lp(closure.body), lp(closure.signature)));
}
export function encodeClosure(ceremony: Bytes, round: number, listHash: Bytes, previous: Bytes): Bytes {
  return concat(be(1n, 1), ceremony, be(BigInt(round), 1), listHash, previous);
}
export function encodeEnvelope(ceremony: Bytes, round: number, cohort: number, index: number, payload: Bytes): Bytes {
  return concat(be(1n, 1), ceremony, be(BigInt(round), 1), be(BigInt(cohort), 1), be(BigInt(index), 2), lp(payload));
}

export const COHORT = { recipients: 1, dealers: 2 } as const;
/** An authenticated message retained in owner order: the exact envelope plus its resolved signer. */
export interface Authenticated { envelope: Bytes; cohort: number; index: number; payload: Bytes }
/** Index → DID, per signed cohort. Genesis supplies only the recipient cohort. */
export type Cohorts = Partial<Record<number, ReadonlyMap<number, string>>>;

/**
 * Verifies one closed round. Order: closure decode and its ceremony/round/previous
 * binding, owner closure signature, then each member envelope (decode, ceremony/round,
 * signer resolution, signature), then the ordered-list commitment.
 */
export function verifyClosedRound(ceremony: Bytes, round: number, previous: Bytes, record: RoundRecord, cohorts: Cohorts, owner: string, verify: Verifier): Authenticated[] {
  const body = record.closure.body;
  if (body.length !== 98 || body[0] !== 1) fail(DEFAULT_ERROR.closure);
  if (!equal(body.slice(1, 33), ceremony) || body[33] !== round || !equal(body.slice(66, 98), previous)) fail(DEFAULT_ERROR.closure);
  if (record.closure.signature.length > LIMIT.signature) fail('InvalidEncoding');
  if (!verify(owner, tagged(TAG.roundClose, body), record.closure.signature)) fail(DEFAULT_ERROR.signature);
  const messages = record.messages.map(m => {
    const r = new Reader(m.body); r.version();
    const digest = r.take(32), envelopeRound = Number(r.int(1)), cohort = Number(r.int(1)), index = Number(r.int(2));
    const payload = r.field(LIMIT.message);
    r.end();
    if (m.signature.length > LIMIT.signature) fail('InvalidEncoding');
    if (!equal(digest, ceremony) || envelopeRound !== round) fail(DEFAULT_ERROR.envelopeBinding);
    const signer = cohorts[cohort]?.get(index);
    if (signer === undefined) fail(DEFAULT_ERROR.signer);
    if (!verify(signer, tagged(TAG.ceremonyMsg, m.body), m.signature)) fail(DEFAULT_ERROR.signature);
    return { envelope: m.body, cohort, index, payload };
  });
  if (!equal(orderedListHash(record.messages), body.slice(34, 66))) fail(DEFAULT_ERROR.closure);
  return messages;
}

/** The S0.2 transcript chain over every present record; record k must be round k ≤ maxRound. */
export function verifyChain(ceremony: Bytes, start: Bytes, records: readonly RoundRecord[], maxRound: number, cohorts: Cohorts, owner: string, verify: Verifier) {
  if (records.length > maxRound) fail('InvalidRound');
  let hash = start;
  const rounds = records.map((record, k) => {
    const messages = verifyClosedRound(ceremony, k + 1, hash, record, cohorts, owner, verify);
    hash = transcriptUpdate(hash, record.closure);
    return messages;
  });
  return { rounds, hash };
}

/** Byte-length sum checked before any signature (S0.3/S0.4 appendices). */
export function checkTranscriptSize(records: readonly RoundRecord[]) {
  let total = 0;
  for (const r of records) {
    total += r.closure.body.length + r.closure.signature.length;
    for (const m of r.messages) total += m.body.length + m.signature.length;
  }
  if (total > LIMIT.transcript) fail('LimitExceeded');
}

/** Per-sender classification within one cohort of a closed round. */
export type Classified = { kind: 'missing' } | { kind: 'conflicting' } | { kind: 'single'; payload: Bytes; position: number };
export function classify(messages: readonly Authenticated[], cohort: number, index: number): Classified {
  let found: { envelope: Bytes; payload: Bytes; position: number } | undefined;
  for (const [position, m] of messages.entries()) {
    if (m.cohort !== cohort || m.index !== index) continue;
    if (!found) found = { envelope: m.envelope, payload: m.payload, position };
    else if (!equal(found.envelope, m.envelope)) return { kind: 'conflicting' };
  }
  return found ? { kind: 'single', payload: found.payload, position: found.position } : { kind: 'missing' };
}

/** Strictly increasing member indices 1..=16 (payload index lists). */
export function memberIndex(r: Reader, previous: number): number {
  const index = Number(r.int(2));
  if (index < 1 || index > LIMIT.members || index <= previous) fail('InvalidEncoding');
  return index;
}

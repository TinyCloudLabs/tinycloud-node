import { ed25519 } from '@noble/curves/ed25519.js';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { Reader, ProtocolError, be, bytes, concat, hex, lp, tagged, g2, decodeRequest, decodeShare, contextDigest, requestDigest, signingPreimage, verifyShare, type Bytes, type G2, type Keyset } from './protocol.ts';

export const CERT_TAGS = {
  activation: 'TC-THRESHOLD-V1-ACTIVATE', ceremony: 'TC-THRESHOLD-V1-CEREMONY-AUTH',
  certificate: 'TC-THRESHOLD-V1-NETWORK-CERT', closure: 'TC-THRESHOLD-V1-ROUND-CLOSE',
  message: 'TC-THRESHOLD-V1-CEREMONY-MSG', readiness: 'TC-THRESHOLD-V1-READY',
  statement: 'TC-THRESHOLD-V1-CERT-STATEMENT', transcript: 'TC-THRESHOLD-V1-TRANSCRIPT',
} as const;
const utf8 = new TextEncoder();
const MAX_U64 = (1n << 64n) - 1n;
export interface SigningInput { did: string; seed: string; public_key: string }
export type SigningKeys = Map<string, Bytes>;
export interface Anchor { owner: string; network: string }
export interface Member { index: number; did: string }
export interface CertificateBody extends Anchor {
  rekey: bigint; epoch: bigint; genesisThreshold: number; threshold: number;
  members: Member[]; mpk: Bytes; commitments: Bytes[]; transcript: Bytes;
  previous?: Bytes; previousMpk?: Bytes;
}
export interface VerifiedCertificate {
  body: CertificateBody; encoded: Bytes; signature: Bytes; digest: Bytes; ownerPreimage: Bytes; anchor: Anchor; keyset: Keyset;
}
export interface Recipient extends Member { hpke: Bytes }
export interface CeremonyBody extends Anchor {
  kind: number; id: Bytes; current?: Bytes; threshold: number; rekey: bigint; epoch: bigint; recipients: Recipient[];
}
export interface VerifiedCeremony {
  body: CeremonyBody; encoded: Bytes; signature: Bytes; digest: Bytes; anchor: Anchor; previous?: VerifiedCertificate;
}
export interface SignedMessage { body: Bytes; signature: Bytes }
export interface Receipt { index: number; signature: Bytes }
export interface CheckedReceipt extends Receipt { encoding: Bytes; preimage: Bytes; hash: Bytes }
export interface FaultResult { verdict: 'Fault' | 'NotAFault'; reason?: string; member?: number; signing_preimage?: string }

function equal(a: Bytes, b: Bytes): boolean { return hex(a) === hex(b); }
function option(value: Bytes | undefined): Bytes { return value === undefined ? be(0n, 1) : concat(be(1n, 1), value); }
function readOption(r: Reader, width: number): Bytes | undefined {
  const flag = r.int(1);
  if (flag === 0n) return undefined;
  if (flag !== 1n) throw new ProtocolError('InvalidEncoding');
  return r.take(width);
}
function directory(members: Member[], threshold: number) {
  if (threshold < 2 || threshold > members.length || members.length > 16) throw new ProtocolError('InvalidEncoding');
  const seen = new Set<string>();
  for (const [i, m] of members.entries()) {
    const length = utf8.encode(m.did).length;
    if (m.index !== i + 1 || length < 1 || length > 256 || seen.has(m.did)) throw new ProtocolError('InvalidEncoding');
    seen.add(m.did);
  }
}
function signatureValid(keys: SigningKeys, did: string, signature: Bytes, preimage: Bytes): boolean {
  const key = keys.get(did);
  if (!key || signature.length !== 64) return false;
  try { return ed25519.verify(signature, preimage, key, { zip215: false }); } catch { return false; }
}
export function signingKeys(inputs: SigningInput[]): SigningKeys {
  const keys: SigningKeys = new Map();
  for (const input of inputs) {
    try {
      const secret = bytes(input.seed), publicKey = bytes(input.public_key), length = utf8.encode(input.did).length;
      if (length < 1 || length > 256 || keys.has(input.did) || secret.length !== 32 || publicKey.length !== 32 || !equal(ed25519.getPublicKey(secret), publicKey)) throw new Error();
      keys.set(input.did, publicKey);
    } catch { throw new ProtocolError('InvalidSigningKey'); }
  }
  return keys;
}
export function encodeCertificate(c: CertificateBody): Bytes {
  return concat(be(1n, 1), lp(utf8.encode(c.network)), lp(utf8.encode(c.owner)), be(c.rekey, 8), be(c.epoch, 8), be(BigInt(c.genesisThreshold), 2), be(BigInt(c.threshold), 2), be(BigInt(c.members.length), 2), be(BigInt(c.members.length), 2),
    ...c.members.flatMap(m => [be(BigInt(m.index), 2), lp(utf8.encode(m.did))]), c.mpk, be(BigInt(c.commitments.length), 2), ...c.commitments, c.transcript, option(c.previous), option(c.previousMpk));
}
function publicShares(c: CertificateBody): Map<number, G2> {
  const commitments = c.commitments.map(p => g2(p, true));
  const shares = new Map<number, G2>();
  for (const m of c.members) {
    let sum = bls.G2.Point.ZERO;
    for (const p of [...commitments].reverse()) sum = (sum.equals(bls.G2.Point.ZERO) ? bls.G2.Point.ZERO : sum.multiply(BigInt(m.index))).add(p);
    if (sum.equals(bls.G2.Point.ZERO)) throw new ProtocolError('InvalidEncoding');
    shares.set(m.index, sum);
  }
  return shares;
}
export function decodeCertificate(encoded: Bytes): CertificateBody {
  try {
    const r = new Reader(encoded); r.version();
    const network = r.text(), owner = r.text(256), rekey = r.int(8), epoch = r.int(8), genesisThreshold = Number(r.int(2)), threshold = Number(r.int(2)), n = Number(r.int(2)), count = Number(r.int(2));
    if (n > 16 || n < 2 || count !== n || threshold < 2 || threshold > n || genesisThreshold < 2 || genesisThreshold > 16) throw new ProtocolError('InvalidEncoding');
    const members = Array.from({ length: count }, () => ({ index: Number(r.int(2)), did: r.text(256) }));
    directory(members, threshold);
    const mpk = r.take(96), size = Number(r.int(2));
    if (size !== threshold) throw new ProtocolError('InvalidEncoding');
    const commitments = Array.from({ length: size }, () => r.take(96));
    const c: CertificateBody = { network, owner, rekey, epoch, genesisThreshold, threshold, members, mpk, commitments, transcript: r.take(32), previous: readOption(r, 32), previousMpk: readOption(r, 96) };
    r.end();
    g2(mpk); commitments.forEach(p => g2(p, true)); g2(commitments[threshold - 1]!);
    if (!equal(mpk, commitments[0]!) || (!c.previous && (c.previousMpk || epoch !== 0n || rekey !== 0n || genesisThreshold !== threshold || n < 2 * threshold - 1))) throw new ProtocolError('InvalidEncoding');
    publicShares(c);
    if (!equal(encodeCertificate(c), encoded)) throw new ProtocolError('InvalidEncoding');
    return c;
  } catch (e) {
    if (e instanceof ProtocolError) throw new ProtocolError('InvalidEncoding');
    throw e;
  }
}
export function verifyCertificate(encoded: Bytes, signature: Bytes, anchor: Anchor, keys: SigningKeys, previous?: VerifiedCertificate): VerifiedCertificate {
  const c = decodeCertificate(encoded), invalid = () => { throw new ProtocolError('InvalidCertificate'); };
  if (c.owner !== anchor.owner || c.network !== anchor.network) invalid();
  const digest = tagged(CERT_TAGS.certificate, encoded), ownerPreimage = tagged(CERT_TAGS.statement, digest);
  if (!signatureValid(keys, anchor.owner, signature, ownerPreimage)) throw new ProtocolError('InvalidSignature');
  if (!previous) {
    if (c.previous || c.previousMpk || c.rekey !== 0n || c.epoch !== 0n) invalid();
  } else {
    const p = previous.body;
    if (previous.anchor.owner !== anchor.owner || previous.anchor.network !== anchor.network || !c.previous || !equal(c.previous, previous.digest) || p.epoch === MAX_U64 || c.epoch !== p.epoch + 1n) invalid();
    if (c.previousMpk) {
      if (!equal(c.previousMpk, p.mpk) || equal(c.mpk, p.mpk) || p.rekey === MAX_U64 || c.rekey !== p.rekey + 1n || c.genesisThreshold !== c.threshold || c.members.length < 2 * c.threshold - 1) invalid();
    } else if (!equal(c.mpk, p.mpk) || c.rekey !== p.rekey || c.genesisThreshold !== p.genesisThreshold) invalid();
  }
  return { body: c, encoded, signature, digest, ownerPreimage, anchor: { ...anchor }, keyset: { mpk: g2(c.mpk), publicShares: publicShares(c), context: { network: c.network, rekey: c.rekey, epoch: c.epoch, certificate: digest, threshold: c.threshold, members: c.members.length } } };
}
export function encodeCeremony(c: CeremonyBody): Bytes {
  return concat(be(1n, 1), be(BigInt(c.kind), 1), c.id, lp(utf8.encode(c.network)), lp(utf8.encode(c.owner)), option(c.current), be(BigInt(c.threshold), 2), be(BigInt(c.recipients.length), 2), be(c.rekey, 8), be(c.epoch, 8), be(BigInt(c.recipients.length), 2), ...c.recipients.flatMap(m => [be(BigInt(m.index), 2), lp(utf8.encode(m.did)), m.hpke]));
}
export function decodeCeremony(encoded: Bytes): CeremonyBody {
  const r = new Reader(encoded); r.version();
  const kind = Number(r.int(1)), id = r.take(32), network = r.text(), owner = r.text(256), current = readOption(r, 32), threshold = Number(r.int(2)), n = Number(r.int(2)), rekey = r.int(8), epoch = r.int(8), count = Number(r.int(2));
  if (kind < 1 || kind > 4 || count !== n || n < 2 || n > 16) throw new ProtocolError('InvalidCeremony');
  const recipients = Array.from({ length: count }, () => ({ index: Number(r.int(2)), did: r.text(256), hpke: r.take(32) }));
  directory(recipients, threshold); r.end();
  const c = { kind, id, network, owner, current, threshold, rekey, epoch, recipients };
  if (!equal(encodeCeremony(c), encoded)) throw new ProtocolError('InvalidCeremony');
  return c;
}
export function authorizeCeremony(encoded: Bytes, signature: Bytes, anchor: Anchor, keys: SigningKeys, previous?: VerifiedCertificate): VerifiedCeremony {
  const c = decodeCeremony(encoded), invalid = () => { throw new ProtocolError('InvalidCeremony'); };
  if (c.owner !== anchor.owner || c.network !== anchor.network) invalid();
  if (c.kind === 1) {
    if (previous || c.current || c.epoch !== 0n || c.rekey !== 0n || c.recipients.length < 2 * c.threshold - 1) invalid();
  } else {
    if (!previous || !c.current || !equal(c.current, previous.digest) || previous.anchor.owner !== anchor.owner || previous.anchor.network !== anchor.network || previous.body.epoch === MAX_U64 || c.epoch !== previous.body.epoch + 1n) invalid();
    if (c.kind === 4) {
      if (previous!.body.rekey === MAX_U64 || c.rekey !== previous!.body.rekey + 1n || c.recipients.length < 2 * c.threshold - 1) invalid();
    } else if (c.rekey !== previous!.body.rekey) invalid();
  }
  const digest = tagged(CERT_TAGS.ceremony, encoded);
  if (!signatureValid(keys, anchor.owner, signature, digest)) throw new ProtocolError('InvalidSignature');
  return { body: c, encoded, signature, digest, anchor: { ...anchor }, previous };
}
export function verifyClosedRound(ceremony: VerifiedCeremony, closure: Bytes, ownerSignature: Bytes, round: number, previous: Bytes, messages: SignedMessage[], keys: SigningKeys): { ownerPreimage: Bytes; transcript: Bytes; messages: { body: Bytes; signature: Bytes; payload: Bytes }[] } {
  const r = new Reader(closure); r.version();
  const context = r.take(32), closedRound = Number(r.int(1)), listHash = r.take(32), prior = r.take(32); r.end();
  if (!equal(context, ceremony.digest) || closedRound !== round || !equal(prior, previous) || previous.length !== 32 || messages.length > 65535) throw new ProtocolError('InvalidCeremony');
  let total = 2;
  const authenticated = messages.map(message => {
    total += 8 + message.body.length + message.signature.length;
    if (total > 4194304 || message.signature.length > 512) throw new ProtocolError('InvalidEncoding');
    const m = new Reader(message.body); m.version();
    const digest = m.take(32), messageRound = Number(m.int(1)), cohort = Number(m.int(1)), index = Number(m.int(2)), payload = m.field(65536); m.end();
    if (!equal(digest, context) || messageRound !== round || (cohort !== 1 && cohort !== 2)) throw new ProtocolError('InvalidCeremony');
    const successor = ceremony.body.kind === 2 || ceremony.body.kind === 3;
    if ((!successor && cohort !== 1) || (successor && ((round === 1 || round === 3) ? cohort !== 2 : round === 2 && cohort !== 1))) throw new ProtocolError('InvalidCeremony');
    const members = cohort === 1 ? ceremony.body.recipients : ceremony.previous?.body.members;
    const member = members?.find(entry => entry.index === index);
    if (!member) throw new ProtocolError('InvalidCeremony');
    if (!signatureValid(keys, member.did, message.signature, tagged(CERT_TAGS.message, message.body))) throw new ProtocolError('InvalidSignature');
    return { ...message, payload };
  });
  const ordered = concat(be(BigInt(messages.length), 2), ...messages.flatMap(m => [lp(m.body), lp(m.signature)]));
  if (!equal(tagged(CERT_TAGS.transcript, ordered), listHash)) throw new ProtocolError('InvalidCeremony');
  const ownerPreimage = tagged(CERT_TAGS.closure, closure);
  if (!signatureValid(keys, ceremony.anchor.owner, ownerSignature, ownerPreimage)) throw new ProtocolError('InvalidSignature');
  const transcript = tagged(CERT_TAGS.transcript, concat(previous, lp(closure), lp(ownerSignature)));
  return { ownerPreimage, transcript, messages: authenticated };
}
export function verifyActivation(cert: VerifiedCertificate, receipts: Receipt[], budget: number | null, signature: Bytes, keys: SigningKeys): { preimage: Bytes; receipts: CheckedReceipt[] } {
  let quorum = cert.body.members.length;
  if (budget !== null) {
    quorum = cert.body.threshold + budget;
    if (!Number.isInteger(budget) || budget <= 0 || budget > 65535 || quorum > 65535 || quorum > cert.body.members.length) throw new ProtocolError('InvalidReadiness');
  }
  const seen = new Set<number>();
  const checked = receipts.map(receipt => {
    const member = cert.body.members.find(m => m.index === receipt.index);
    if (!member || seen.has(receipt.index) || receipt.signature.length > 512) throw new ProtocolError('InvalidReadiness');
    seen.add(receipt.index);
    const preimage = tagged(CERT_TAGS.readiness, concat(cert.digest, cert.body.transcript, be(BigInt(receipt.index), 2), cert.keyset.publicShares.get(receipt.index)!.toBytes()));
    if (!signatureValid(keys, member.did, receipt.signature, preimage)) throw new ProtocolError('InvalidReadiness');
    return { ...receipt, preimage };
  });
  if (checked.length < quorum) throw new ProtocolError('NotEnoughReady');
  const encoded = checked.map(r => {
    const encoding = concat(be(1n, 1), be(BigInt(r.index), 2), lp(r.signature));
    return { ...r, encoding, hash: tagged(CERT_TAGS.readiness, encoding) };
  });
  const sorted = encoded.map(r => r.hash).sort((a, b) => Buffer.compare(a, b));
  const preimage = tagged(CERT_TAGS.activation, concat(cert.digest, ...sorted));
  if (!signatureValid(keys, cert.anchor.owner, signature, preimage)) throw new ProtocolError('InvalidSignature');
  return { preimage, receipts: encoded };
}
export function verifyFaultProof(cert: VerifiedCertificate, request: Bytes, share: Bytes, signature: Bytes, keys: SigningKeys): FaultResult {
  let preimage: Bytes;
  try {
    const req = decodeRequest(request), s = decodeShare(share), c = cert.keyset.context;
    if (!equal(req.context, contextDigest(c)) || req.network !== c.network || req.rekey !== c.rekey || req.epoch !== c.epoch || !equal(req.certificate, cert.digest) || !equal(s.context, req.context) || !equal(s.request, requestDigest(request)) || !cert.keyset.publicShares.has(s.member)) throw new ProtocolError('ContextMismatch');
    preimage = signingPreimage(share, requestDigest(request), cert.digest);
    const member = cert.body.members.find(m => m.index === s.member)!;
    if (!signatureValid(keys, member.did, signature, preimage)) return { verdict: 'NotAFault', reason: 'InvalidSignature' };
  } catch (e) {
    if (e instanceof ProtocolError) return { verdict: 'NotAFault', reason: e.code };
    throw e;
  }
  try {
    verifyShare(cert.keyset, request, share);
    return { signing_preimage: hex(preimage), verdict: 'NotAFault', reason: 'ValidShare' };
  } catch (e) {
    if (e instanceof ProtocolError && e.code === 'Invalid') return { signing_preimage: hex(preimage), verdict: 'Fault', member: e.member };
    if (e instanceof ProtocolError) return { verdict: 'NotAFault', reason: e.code };
    throw e;
  }
}

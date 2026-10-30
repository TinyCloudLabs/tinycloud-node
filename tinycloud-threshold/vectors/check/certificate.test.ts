import { expect, test } from 'bun:test';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { ed25519 } from '@noble/curves/ed25519.js';
import { be, concat, hex, tagged, ProtocolError, encodeIdentity, encodeRequest, contextDigest, requestDigest, encodeShare, signingPreimage, h1 } from './protocol.ts';
import { signingKeys, encodeCertificate, decodeCertificate, verifyCertificate, encodeCeremony, authorizeCeremony, verifyClosedRound, verifyActivation, verifyFaultProof, type CertificateBody, type VerifiedCertificate } from './certificates.ts';

const seed = (n: number) => new Uint8Array(32).fill(n);
const directory = [21, 22, 23, 24, 25].map((n, i) => ({ did: `independent:${i}`, seed: hex(seed(n)), public_key: hex(ed25519.getPublicKey(seed(n))) }));
const keys = signingKeys(directory);
const anchor = { owner: 'independent:0', network: 'tinycloud:test:checker-independent' };
const base: CertificateBody = {
  ...anchor, rekey: 0n, epoch: 0n, genesisThreshold: 2, threshold: 2,
  members: [1, 2, 3].map(index => ({ index, did: `independent:${index}` })),
  mpk: bls.G2.Point.BASE.multiply(13n).toBytes(), commitments: [13n, 5n].map(n => bls.G2.Point.BASE.multiply(n).toBytes()), transcript: seed(77),
};
function signCertificate(body: CertificateBody, previous?: VerifiedCertificate) {
  const encoded = encodeCertificate(body);
  const digest = tagged('TC-THRESHOLD-V1-NETWORK-CERT', encoded);
  const signature = ed25519.sign(tagged('TC-THRESHOLD-V1-CERT-STATEMENT', digest), seed(21));
  return verifyCertificate(encoded, signature, anchor, keys, previous);
}
function errorCode(operation: () => unknown, code: string) {
  try { operation(); } catch (e) {
    expect(e).toBeInstanceOf(ProtocolError);
    expect((e as ProtocolError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}
const lp = (b: Uint8Array) => concat(be(BigInt(b.length), 4), b);

test('signing directory derives public keys and rejects duplicates or inconsistent mappings', () => {
  expect(hex(keys.get('independent:1')!)).toBe(directory[1]!.public_key);
  errorCode(() => signingKeys([...directory, directory[0]!]), 'InvalidSigningKey');
  errorCode(() => signingKeys([{ ...directory[0]!, public_key: directory[1]!.public_key }]), 'InvalidSigningKey');
});

test('canonical certificates evaluate shares and verify a pinned reshare/rekey chain', () => {
  const genesis = signCertificate(base);
  expect(hex(encodeCertificate(decodeCertificate(genesis.encoded)))).toBe(hex(genesis.encoded));
  expect([...genesis.keyset.publicShares.values()].map(p => hex(p.toBytes()))).toEqual([18n, 23n, 28n].map(n => hex(bls.G2.Point.BASE.multiply(n).toBytes())));
  const reshare = signCertificate({ ...base, epoch: 1n, previous: genesis.digest, threshold: 3, members: [...base.members, { index: 4, did: 'independent:4' }], commitments: [13n, 5n, 7n].map(n => bls.G2.Point.BASE.multiply(n).toBytes()) }, genesis);
  const rekey = signCertificate({ ...base, epoch: 2n, rekey: 1n, previous: reshare.digest, previousMpk: base.mpk, mpk: bls.G2.Point.BASE.multiply(19n).toBytes(), commitments: [19n, 3n].map(n => bls.G2.Point.BASE.multiply(n).toBytes()) }, reshare);
  expect(rekey.body.rekey).toBe(1n);
  expect(rekey.body.epoch).toBe(2n);
  errorCode(() => signCertificate({ ...base, epoch: 2n, previous: genesis.digest }, genesis), 'InvalidCertificate');
  errorCode(() => signCertificate({ ...base, epoch: 1n, previous: genesis.digest, mpk: rekey.body.mpk, commitments: rekey.body.commitments }, genesis), 'InvalidCertificate');
});

test('certificate anchors and signatures are checked independently of candidate fields', () => {
  const good = signCertificate(base);
  errorCode(() => verifyCertificate(good.encoded, good.signature, { ...anchor, owner: 'independent:1' }, keys), 'InvalidCertificate');
  errorCode(() => verifyCertificate(good.encoded, new Uint8Array(64), anchor, keys), 'InvalidSignature');
});

test('canonical certificate rules reject duplicate DIDs, trailing bytes, identity public shares and identity top coefficients', () => {
  errorCode(() => decodeCertificate(encodeCertificate({ ...base, members: [{ index: 1, did: 'same' }, { index: 2, did: 'same' }, { index: 3, did: 'other' }] })), 'InvalidEncoding');
  errorCode(() => decodeCertificate(concat(encodeCertificate(base), be(0n, 1))), 'InvalidEncoding');
  errorCode(() => decodeCertificate(encodeCertificate({ ...base, commitments: [base.mpk, bls.G2.Point.ZERO.toBytes()] })), 'InvalidEncoding');
  errorCode(() => decodeCertificate(encodeCertificate({ ...base, commitments: [base.mpk, bls.G2.Point.BASE.multiply(13n).negate().toBytes()] })), 'InvalidEncoding');
});

function ceremony(previous?: VerifiedCertificate, kind = 1) {
  const body = { ...anchor, kind, id: seed(31), current: previous?.digest, threshold: 2, rekey: kind === 4 ? 1n : 0n, epoch: previous ? previous.body.epoch + 1n : 0n, recipients: [1, 2, 3].map(index => ({ index, did: `independent:${index}`, hpke: seed(index + 90) })) };
  const encoded = encodeCeremony(body);
  const signature = ed25519.sign(tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', encoded), seed(21));
  return authorizeCeremony(encoded, signature, anchor, keys, previous);
}

test('ceremony authorization binds external anchor, current certificate and counters', () => {
  const genesis = signCertificate(base), authorized = ceremony(genesis, 2);
  expect(authorized.body.epoch).toBe(1n);
  errorCode(() => authorizeCeremony(authorized.encoded, authorized.signature, { ...anchor, network: 'other' }, keys, genesis), 'InvalidCeremony');
  const stale = { ...authorized.body, current: seed(19) }, encoded = encodeCeremony(stale);
  errorCode(() => authorizeCeremony(encoded, ed25519.sign(tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', encoded), seed(21)), anchor, keys, genesis), 'InvalidCeremony');
  const invalid = { ...ceremony().body, threshold: 3 };
  const invalidBytes = encodeCeremony(invalid);
  errorCode(() => authorizeCeremony(invalidBytes, ed25519.sign(tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', invalidBytes), seed(21)), anchor, keys), 'InvalidCeremony');
});

function closed(previousCertificate?: VerifiedCertificate, cohort = 1, signer = 22) {
  const auth = ceremony(previousCertificate, previousCertificate ? 2 : 1), previous = seed(0), round = 1;
  const payload = new Uint8Array([255, 0, 61]);
  const body = concat(be(1n, 1), auth.digest, be(BigInt(round), 1), be(BigInt(cohort), 1), be(1n, 2), lp(payload));
  const messages = [{ body, signature: ed25519.sign(tagged('TC-THRESHOLD-V1-CEREMONY-MSG', body), seed(signer)) }];
  const list = concat(be(1n, 2), ...messages.flatMap(m => [lp(m.body), lp(m.signature)]));
  const closure = concat(be(1n, 1), auth.digest, be(BigInt(round), 1), tagged('TC-THRESHOLD-V1-TRANSCRIPT', list), previous);
  const signature = ed25519.sign(tagged('TC-THRESHOLD-V1-ROUND-CLOSE', closure), seed(21));
  return { auth, previous, round, messages, closure, signature, payload };
}

test('closed rounds authenticate exact envelopes and preserve raw payload bytes', () => {
  const round = closed();
  const result = verifyClosedRound(round.auth, round.closure, round.signature, round.round, round.previous, round.messages, keys);
  expect(hex(result.messages[0]!.payload)).toBe(hex(round.payload));
  expect(hex(result.transcript)).toBe(hex(tagged('TC-THRESHOLD-V1-TRANSCRIPT', concat(round.previous, lp(round.closure), lp(round.signature)))));
  errorCode(() => verifyClosedRound(round.auth, round.closure, round.signature, 2, round.previous, round.messages, keys), 'InvalidCeremony');
  errorCode(() => verifyClosedRound(round.auth, round.closure, round.signature, round.round, seed(9), round.messages, keys), 'InvalidCeremony');
  errorCode(() => verifyClosedRound(round.auth, round.closure, round.signature, round.round, round.previous, [{ ...round.messages[0]!, signature: new Uint8Array(64) }], keys), 'InvalidSignature');
});

test('signed cohort selects its own directory with no recipient fallback', () => {
  const genesis = signCertificate(base), round = closed(genesis, 2);
  const swapped = { ...round.auth.body, recipients: round.auth.body.recipients.map((r, i) => ({ ...r, did: `independent:${i === 0 ? 2 : i === 1 ? 1 : 3}` })) };
  const encoded = encodeCeremony(swapped);
  const auth = authorizeCeremony(encoded, ed25519.sign(tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', encoded), seed(21)), anchor, keys, genesis);
  const body = concat(be(1n, 1), auth.digest, be(1n, 1), be(2n, 1), be(1n, 2), lp(round.payload));
  const messages = [{ body, signature: ed25519.sign(tagged('TC-THRESHOLD-V1-CEREMONY-MSG', body), seed(23)) }];
  const list = concat(be(1n, 2), lp(body), lp(messages[0]!.signature));
  const closure = concat(be(1n, 1), auth.digest, be(1n, 1), tagged('TC-THRESHOLD-V1-TRANSCRIPT', list), round.previous);
  const signature = ed25519.sign(tagged('TC-THRESHOLD-V1-ROUND-CLOSE', closure), seed(21));
  errorCode(() => verifyClosedRound(auth, closure, signature, 1, round.previous, messages, keys), 'InvalidSignature');
});

function receipts(cert: VerifiedCertificate) {
  return cert.body.members.map(m => {
    const preimage = tagged('TC-THRESHOLD-V1-READY', concat(cert.digest, cert.body.transcript, be(BigInt(m.index), 2), cert.keyset.publicShares.get(m.index)!.toBytes()));
    return { index: m.index, signature: ed25519.sign(preimage, seed(21 + m.index)) };
  });
}
function activationSignature(cert: VerifiedCertificate, values: { index: number; signature: Uint8Array }[]) {
  const hashes = values.map(r => tagged('TC-THRESHOLD-V1-READY', concat(be(1n, 1), be(BigInt(r.index), 2), lp(r.signature)))).sort((a, b) => Buffer.compare(a, b));
  return ed25519.sign(tagged('TC-THRESHOLD-V1-ACTIVATE', concat(cert.digest, ...hashes)), seed(21));
}

test('activation canonical receipts and binary sorted hashes are independent of receipt order', () => {
  const cert = signCertificate(base), values = receipts(cert), signature = activationSignature(cert, values);
  const forward = verifyActivation(cert, values, null, signature, keys);
  const reverse = verifyActivation(cert, [...values].reverse(), null, signature, keys);
  expect(hex(forward.preimage)).toBe(hex(reverse.preimage));
  expect(hex(forward.receipts[0]!.encoding)).toBe(hex(concat(be(1n, 1), be(1n, 2), lp(values[0]!.signature))));
  errorCode(() => verifyActivation(cert, values.slice(0, 2), null, signature, keys), 'NotEnoughReady');
  errorCode(() => verifyActivation(cert, values, 0, signature, keys), 'InvalidReadiness');
  errorCode(() => verifyActivation(cert, values, 65535, signature, keys), 'InvalidReadiness');
  errorCode(() => verifyActivation(cert, [values[0]!, values[0]!, values[1]!], null, signature, keys), 'InvalidReadiness');
});

test('all receipt signatures are checked, including surplus and under-quorum inputs', () => {
  const cert = signCertificate({ ...base, members: [...base.members, { index: 4, did: 'independent:4' }] });
  const values = receipts(cert), signature = activationSignature(cert, values);
  values[3] = { ...values[3]!, signature: new Uint8Array(64) };
  errorCode(() => verifyActivation(cert, values, 1, signature, keys), 'InvalidReadiness');
  errorCode(() => verifyActivation(cert, [values[3]!], null, signature, keys), 'InvalidReadiness');
});

test('fault attribution follows context and member signature checks before equations', () => {
  const cert = signCertificate(base), identity = encodeIdentity({ mode: 2, network: anchor.network, path: 'independent/fault', version: 1n });
  const context = cert.keyset.context;
  const request = encodeRequest({ ...context, context: contextDigest(context), identity, tpk: bls.G1.Point.BASE.multiply(11n).toBytes() });
  const share = encodeShare({ member: 1, context: contextDigest(context), request: requestDigest(request), c1: bls.G1.Point.BASE.multiply(7n).toBytes(), c2: bls.G2.Point.BASE.multiply(7n).toBytes(), c3: h1(identity).multiply(18n).add(bls.G1.Point.BASE.multiply(77n)).toBytes() });
  const signature = ed25519.sign(signingPreimage(share, requestDigest(request), cert.digest), seed(22));
  expect(verifyFaultProof(cert, request, share, signature, keys).verdict).toBe('NotAFault');
  const bad = share.slice(); bad.set(bls.G1.Point.BASE.toBytes(), 211);
  const badSignature = ed25519.sign(signingPreimage(bad, requestDigest(request), cert.digest), seed(22));
  expect(verifyFaultProof(cert, request, bad, badSignature, keys).verdict).toBe('Fault');
  expect(verifyFaultProof(cert, request, bad, new Uint8Array(64), keys).reason).toBe('InvalidSignature');
  const mixed = bad.slice(); mixed[35] = mixed[35]! ^ 1;
  expect(verifyFaultProof(cert, request, mixed, badSignature, keys).reason).toBe('ContextMismatch');
});

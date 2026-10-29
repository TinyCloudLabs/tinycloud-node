import { describe, expect, test } from 'bun:test';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import {
  R, ProtocolError, bytes, hex, be, concat, scalar, g1, g2, h1, h3,
  encodeIdentity, decodeIdentity, encodeContext, decodeContext, contextDigest,
  encodeRequest, decodeRequest, requestDigest, encodeShare, decodeShare,
  signingPreimage, verifyShare, combine, wrap, unwrap,
} from './protocol.ts';

const G1 = bls.G1.Point.BASE;
const G2 = bls.G2.Point.BASE;
const identity = encodeIdentity({ mode: 1, network: 'tinycloud:test:independent', path: 'records/é', version: 9n, nonce: new Uint8Array(16).fill(17) });
const context = { network: 'tinycloud:test:independent', rekey: 2n, epoch: 7n, certificate: new Uint8Array(32).fill(41), threshold: 2, members: 3 };
const request = encodeRequest({ ...context, context: contextDigest(context), identity, tpk: G1.multiply(11n).toBytes() });
const keyset = { context, mpk: G2.multiply(13n), publicShares: new Map([1, 2, 3].map(i => [i, G2.multiply(13n + 5n * BigInt(i))])) };
function share(member: number, randomness = BigInt(member + 20)) {
  return encodeShare({ member, context: contextDigest(context), request: requestDigest(request), c1: G1.multiply(randomness).toBytes(), c2: G2.multiply(randomness).toBytes(), c3: h1(identity).multiply(13n + 5n * BigInt(member)).add(G1.multiply(11n * randomness)).toBytes() });
}
function expectError(f: () => unknown, code: string, member?: number) {
  try { f(); } catch (e) {
    expect(e).toBeInstanceOf(ProtocolError);
    expect((e as ProtocolError).code).toBe(code);
    if (member !== undefined) expect((e as ProtocolError).member).toBe(member);
    return;
  }
  throw new Error(`expected ${code}`);
}
function changed(input: Uint8Array, offset: number, value?: number) {
  const result = input.slice();
  result[offset] = value ?? (result[offset]! ^ 1);
  return result;
}

describe('canonical bytes and role decoders', () => {
  test('scalar accepts zero and r-1 but not r, overlong or short encodings', () => {
    expect(scalar(be(0n, 32))).toBe(0n);
    expect(scalar(be(R - 1n, 32))).toBe(R - 1n);
    for (const b of [be(R, 32), new Uint8Array(31), new Uint8Array(33)]) expectError(() => scalar(b), 'InvalidScalar');
  });
  test('hex consumes every character', () => {
    for (const value of ['0', '0g', 'aa ', '0x00', 'AA']) expectError(() => bytes(value), 'InvalidEncoding');
  });
  test('G1 and G2 reject lengths, flags, noncanonical coordinates and torsion', () => {
    for (const [decode, base, size] of [[g1, G1.toBytes(), 48], [g2, G2.toBytes(), 96]] as const) {
      expectError(() => decode(base.slice(1)), 'InvalidPoint');
      expectError(() => decode(changed(base, 0, base[0]! & 0x7f)), 'InvalidPoint');
      const noncanonical = new Uint8Array(size).fill(255); noncanonical[0] = 0x9f;
      expectError(() => decode(noncanonical), 'InvalidPoint');
    }
    const torsion = new Uint8Array(48); torsion[0] = 0x80;
    expectError(() => g1(torsion), 'InvalidPoint');
  });
  test('identity is allowed only when the field permits it', () => {
    expectError(() => g1(bls.G1.Point.ZERO.toBytes()), 'IdentityPoint');
    expectError(() => g2(bls.G2.Point.ZERO.toBytes()), 'IdentityPoint');
    expect(g1(bls.G1.Point.ZERO.toBytes(), true).equals(bls.G1.Point.ZERO)).toBe(true);
  });
  test('identity encoding preserves UTF-8, modes, lengths and split boundaries', () => {
    expect(hex(encodeIdentity(decodeIdentity(identity)))).toBe(hex(identity));
    const session = encodeIdentity({ mode: 2, network: 'a', path: '/b', version: 0n });
    expect(decodeIdentity(session).nonce).toBeUndefined();
    expect(hex(session)).not.toBe(hex(encodeIdentity({ mode: 2, network: 'a/', path: 'b', version: 0n })));
    for (const b of [identity.slice(0, -1), concat(identity, be(0n, 1)), changed(identity, 31, 3), changed(identity, 32, 255)]) expectError(() => decodeIdentity(b), 'InvalidEncoding');
  });
  test('context and request round-trip with their full bindings', () => {
    expect(hex(encodeContext(decodeContext(encodeContext(context))))).toBe(hex(encodeContext(context)));
    expect(hex(encodeRequest(decodeRequest(request)))).toBe(hex(request));
    expectError(() => decodeRequest(concat(request, be(0n, 1))), 'InvalidEncoding');
    const other = encodeIdentity({ ...decodeIdentity(identity), network: 'elsewhere' });
    expectError(() => decodeRequest(encodeRequest({ ...decodeRequest(request), identity: other })), 'ContextMismatch');
    expectError(() => decodeContext(encodeContext({ ...context, threshold: 1 })), 'InvalidParameters');
  });
});

describe('request-bound encrypted shares', () => {
  test('both pairing equations identify independently chosen member errors', () => {
    const good = share(2);
    expect(verifyShare(keyset, request, good)).toBe(2);
    const decoded = decodeShare(good);
    expectError(() => verifyShare(keyset, request, encodeShare({ ...decoded, c1: G1.multiply(31n).toBytes() })), 'Invalid', 2);
    expectError(() => verifyShare(keyset, request, encodeShare({ ...decoded, c2: G2.multiply(31n).toBytes() })), 'Invalid', 2);
    expectError(() => verifyShare(keyset, request, encodeShare({ ...decoded, c3: g1(decoded.c3, true).add(G1).toBytes() })), 'Invalid', 2);
  });
  test('identity c3 satisfies the second equation when its terms cancel', () => {
    const req = encodeRequest({ ...decodeRequest(request), tpk: h1(identity).multiply(R - 18n).toBytes() });
    const encoded = encodeShare({
      member: 1, context: contextDigest(context), request: requestDigest(req),
      c1: G1.toBytes(), c2: G2.toBytes(), c3: bls.G1.Point.ZERO.toBytes(),
    });
    expect(verifyShare(keyset, req, encoded)).toBe(1);
  });
  test('request and share binding precedes algebra and signing', () => {
    const good = share(1);
    for (const offset of [3, 35]) {
      const bad = changed(good, offset);
      bad.set(G1.multiply(3n).toBytes(), 67);
      expectError(() => verifyShare(keyset, request, bad), 'ContextMismatch');
    }
    for (const req of [encodeRequest({ ...decodeRequest(request), tpk: G1.multiply(17n).toBytes() }), encodeRequest({ ...decodeRequest(request), identity: encodeIdentity({ ...decodeIdentity(identity), path: 'other' }) }), encodeRequest({ ...decodeRequest(request), epoch: 8n }), encodeRequest({ ...decodeRequest(request), certificate: new Uint8Array(32) })]) {
      expectError(() => verifyShare(keyset, req, good), 'ContextMismatch');
    }
    expectError(() => signingPreimage(good, new Uint8Array(32), context.certificate), 'ContextMismatch');
    expectError(() => verifyShare(keyset, request, encodeShare({ ...decodeShare(good), member: 4 })), 'ContextMismatch');
  });
  test('combine checks every binding before verifying even an unselected share', () => {
    const invalidEquation = encodeShare({ ...decodeShare(share(1)), c2: G2.multiply(9n).toBytes() });
    const mixed = changed(share(3), 35);
    expectError(() => combine(keyset, request, [invalidEquation, share(2), mixed], 11n), 'MixedContexts');
  });
  test('all subsets derive the master key; duplicate indices count once', () => {
    const expected = hex(h1(identity).multiply(13n).toBytes());
    for (const pair of [[1, 2], [1, 3], [2, 3]]) expect(hex(combine(keyset, request, pair.map(i => share(i)), 11n).key)).toBe(expected);
    expectError(() => combine(keyset, request, [share(1), share(1)], 11n), 'NotEnoughShares');
    expect(combine(keyset, request, [share(3), share(2), share(1), share(2)], 11n).selected).toEqual([1, 2]);
    expectError(() => combine(keyset, request, [share(1), share(2)], 12n), 'InvalidDerivedKey');
  });
  test('zero aggregate randomness remains a valid combination', () => {
    const result = combine(keyset, request, [share(1, 1n), share(2, 2n)], 11n);
    expect(hex(result.aggregate.c1)).toBe(hex(bls.G1.Point.ZERO.toBytes()));
    expect(hex(result.key)).toBe(hex(h1(identity).multiply(13n).toBytes()));
  });
  test('amended share has 259 bytes and rejects trailing bytes and old layout', () => {
    const good = share(1);
    expect(good.byteLength).toBe(259);
    expect(hex(encodeShare(decodeShare(good)))).toBe(hex(good));
    expectError(() => decodeShare(concat(good, be(0n, 1))), 'InvalidEncoding');
    expectError(() => decodeShare(concat(good.slice(0, 35), good.slice(67))), 'InvalidEncoding');
  });
});

describe('FullIdent from independently chosen inputs', () => {
  const sigma = new Uint8Array(32).fill(83);
  const message = new Uint8Array(32).fill(149);
  const key = h1(identity).multiply(13n).toBytes();
  test('explicit sigma wraps and unwraps; H3 is a scalar-field value', () => {
    const ciphertext = wrap(G2.multiply(13n), identity, message, sigma);
    expect(hex(unwrap(key, identity, identity, ciphertext))).toBe(hex(message));
    expect(h3(concat(sigma, message))).toBeLessThan(R);
  });
  test('U, V and W mutations produce the same ciphertext error', () => {
    const ciphertext = wrap(G2.multiply(13n), identity, message, sigma);
    const u = ciphertext.slice(); u.set(G2.multiply(41n).toBytes(), 0);
    for (const bad of [u, changed(ciphertext, 99), changed(ciphertext, 147), ciphertext.slice(1)]) expectError(() => unwrap(key, identity, identity, bad), 'InvalidCiphertext');
  });
  test('identity association is checked before ciphertext parsing', () => {
    expectError(() => unwrap(key, identity, encodeIdentity({ ...decodeIdentity(identity), path: 'other' }), new Uint8Array()), 'WrongIdentity');
  });
});

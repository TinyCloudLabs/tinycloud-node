import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { parseVectors, vector, type VectorCase } from './schema.ts';
import {
  ProtocolError, DST, PEDERSEN_H_MESSAGE, bytes, hex, be, scalar, g1, g2, h1, h3, xmd, pairing, encodeGT,
  decodeIdentity, encodeIdentity, decodeContext, encodeContext, contextDigest,
  decodeRequest, encodeRequest, requestDigest, encodeShare, signingPreimage,
  verifyShare, combine, wrap, unwrap, type Keyset,
} from './protocol.ts';

export interface CheckReport { passed: string[]; combinations: number[][] }
function same(label: string, actual: unknown, expected: unknown) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error(`${label}: observed ${JSON.stringify(actual)}; expected ${JSON.stringify(expected)}`);
}
function checkThreshold(c: Extract<VectorCase, { operation: 'threshold' }>): number[][] {
  const i = c.inputs, o = c.outputs, context = decodeContext(bytes(i.context));
  same('context bytes', hex(encodeContext(context)), i.context);
  same('context digest', hex(contextDigest(context)), i.context_digest);
  same('certificate', hex(context.certificate), i.certificate_digest);
  same('threshold', context.threshold, i.threshold);
  same('members', context.members, i.members);
  const identity = bytes(i.identity), transport = scalar(bytes(i.transport_scalar)), master = scalar(bytes(i.master_scalar));
  same('identity bytes', hex(encodeIdentity(decodeIdentity(identity))), i.identity);
  same('mpk', hex(bls.G2.Point.BASE.multiply(master).toBytes()), i.mpk);
  same('transport', hex(bls.G1.Point.BASE.multiply(transport).toBytes()), i.transport_public);
  const request = bytes(i.request), req = decodeRequest(request);
  same('request bytes', hex(encodeRequest(req)), i.request);
  same('request context', hex(req.context), i.context_digest);
  same('request network', req.network, context.network);
  same('request rekey', req.rekey.toString(), context.rekey.toString());
  same('request epoch', req.epoch.toString(), context.epoch.toString());
  same('request certificate', hex(req.certificate), i.certificate_digest);
  same('request identity', hex(req.identity), i.identity);
  same('request transport', hex(req.tpk), i.transport_public);
  const digest = requestDigest(request);
  same('request digest', hex(digest), i.request_digest);
  const indices = Array.from({ length: context.members }, (_, n) => n + 1);
  same('scalar member order', i.scalar_shares.map(s => s.member), indices);
  same('public member order', i.public_shares.map(s => s.member), indices);
  same('encrypted member order', o.encrypted_shares.map(s => s.member), indices);
  const publicShares = new Map(i.scalar_shares.map(s => [s.member, bls.G2.Point.BASE.multiply(scalar(bytes(s.scalar)))]));
  for (const s of i.public_shares) same(`public share ${s.member}`, hex(publicShares.get(s.member)!.toBytes()), s.point);
  const keys: Keyset = { context, mpk: g2(bytes(i.mpk)), publicShares };
  const encrypted = o.encrypted_shares.map(s => {
    const c1 = g1(bytes(s.c1)), c2 = g2(bytes(s.c2));
    const si = scalar(bytes(i.scalar_shares.find(x => x.member === s.member)!.scalar));
    const c3 = h1(identity).multiply(si).add(c1.multiply(transport)).toBytes();
    same(`share ${s.member} c3`, hex(c3), s.c3);
    const encoded = encodeShare({ member: s.member, context: contextDigest(context), request: digest, c1: c1.toBytes(), c2: c2.toBytes(), c3 });
    same(`share ${s.member} encoded`, hex(encoded), s.encoded);
    same(`share ${s.member} signing preimage`, hex(signingPreimage(encoded, digest, context.certificate)), s.signing_preimage);
    verifyShare(keys, request, encoded);
    return encoded;
  });
  const expected = hex(h1(identity).multiply(master).toBytes());
  same('derived key', expected, o.derived_key);
  const combinations = [[1, 2], [1, 3], [2, 3]];
  for (const members of combinations) {
    const result = combine(keys, request, members.map(n => encrypted[n - 1]!), transport);
    same(`combine ${members.join(',')} key`, hex(result.key), expected);
    if (members[0] === 1 && members[1] === 2) {
      same('selected members', result.selected, o.selected_members);
      same('aggregate c1', hex(result.aggregate.c1), o.aggregate.c1);
      same('aggregate c2', hex(result.aggregate.c2), o.aggregate.c2);
      same('aggregate c3', hex(result.aggregate.c3), o.aggregate.c3);
    }
  }
  return combinations;
}
export function checkVectors(input: unknown): CheckReport {
  const file = parseVectors(input), passed: string[] = [];
  const full = vector(file, 'fullident_wrap_unwrap'), threshold = vector(file, 'threshold_2of3');
  const fi = full.inputs, ti = threshold.inputs;
  const keys: Keyset = {
    context: decodeContext(bytes(ti.context)), mpk: g2(bytes(ti.mpk)),
    publicShares: new Map(ti.public_shares.map(s => [s.member, g2(bytes(s.point))])),
  };
  const fullKey = h1(bytes(fi.identity)).multiply(scalar(bytes(fi.master_scalar))).toBytes();
  let combinations: number[][] = [];
  for (const c of file.cases) {
    try {
      switch (c.operation) {
        case 'hash_g1':
          same('H1', hex(h1(bytes(c.inputs.message)).toBytes()), c.outputs.point);
          break;
        case 'hash_g2':
          same('Pedersen h', hex(bls.G2.hashToCurve(bytes(PEDERSEN_H_MESSAGE), { DST: DST.pedersen_h }).toBytes()), c.outputs.point);
          break;
        case 'h3': same('H3', hex(be(h3(bytes(c.inputs.message)), 32)), c.outputs.scalar); break;
        case 'h2': same('H2', hex(xmd(bytes(c.inputs.message), DST.h2, 32)), c.outputs.bytes); break;
        case 'h4': same('H4', hex(xmd(bytes(c.inputs.message), DST.h4, 32)), c.outputs.bytes); break;
        case 'pairing': {
          const a = c.name === 'pairing_generators' ? bls.G1.Point.BASE : bls.G1.Point.BASE.multiply(5n);
          const b = c.name === 'pairing_generators' ? bls.G2.Point.BASE : bls.G2.Point.BASE.multiply(7n);
          same('pairing input G1', hex(a.toBytes()), c.inputs.g1);
          same('pairing input G2', hex(b.toBytes()), c.inputs.g2);
          same('reduced pairing GT', hex(encodeGT(pairing(a, b))), c.outputs.gt);
          break;
        }
        case 'fullident': {
          same('master public key', hex(bls.G2.Point.BASE.multiply(scalar(bytes(fi.master_scalar))).toBytes()), fi.mpk);
          const ciphertext = wrap(g2(bytes(fi.mpk)), bytes(fi.identity), bytes(fi.message), bytes(fi.sigma));
          same('FullIdent ciphertext', hex(ciphertext), c.outputs.ciphertext);
          same('FullIdent key', hex(fullKey), c.outputs.derived_key);
          const plaintext = unwrap(fullKey, bytes(fi.identity), bytes(fi.identity), bytes(c.outputs.ciphertext));
          same('FullIdent plaintext', hex(plaintext), fi.message);
          same('FullIdent unwrapped', hex(plaintext), c.outputs.unwrapped);
          break;
        }
        case 'threshold':
          same('shared identity', ti.identity, fi.identity);
          same('shared master', ti.master_scalar, fi.master_scalar);
          same('shared mpk', ti.mpk, fi.mpk);
          combinations = checkThreshold(c);
          for (const members of combinations) {
            const derived = combine(keys, bytes(ti.request), members.map(n => bytes(c.outputs.encrypted_shares[n - 1]!.encoded)), scalar(bytes(ti.transport_scalar)));
            same(`FullIdent from subset ${members}`, hex(unwrap(derived.key, bytes(ti.identity), bytes(fi.identity), bytes(full.outputs.ciphertext))), fi.message);
          }
          break;
        case 'decode_scalar': case 'decode_transport': case 'decode_mpk': case 'verify_share': case 'unwrap': {
          let observed: { code: string; member?: number } | undefined;
          try {
            switch (c.operation) {
              case 'decode_scalar': scalar(bytes(c.inputs.bytes)); break;
              case 'decode_transport': g1(bytes(c.inputs.bytes)); break;
              case 'decode_mpk': g2(bytes(c.inputs.bytes)); break;
              case 'verify_share':
                verifyShare(keys, bytes('request' in c.inputs ? c.inputs.request : ti.request), bytes(c.inputs.share)); break;
              case 'unwrap': unwrap(fullKey, bytes(fi.identity), bytes(fi.identity), bytes(c.inputs.ciphertext)); break;
            }
          } catch (e) {
            if (!(e instanceof ProtocolError)) throw e;
            observed = { code: e.code, ...(e.member === undefined ? {} : { member: e.member }) };
          }
          same('computed error', observed, { code: c.error, ...('member' in c ? { member: c.member } : {}) });
          break;
        }
        default: { const exhaustive: never = c; throw new Error(`unsupported case ${exhaustive}`); }
      }
      passed.push(c.name);
    } catch (e) {
      throw new Error(`${c.name}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  return { passed, combinations };
}

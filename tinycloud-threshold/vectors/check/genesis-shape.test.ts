import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { verifyCertificate } from './ceremony.ts';
import { authorizeGenesis } from './dkg.ts';
import { authorizeCeremony as legacyAuthorize, signingKeys, verifyCertificate as legacyVerify, type SigningInput, type VerifiedCertificate } from './certificates.ts';
import { ANCHOR, G2_BASE, code, signedCeremony, signedCertificate, times, verify } from './testkit.ts';

// Unchecked: committed vector document; signingKeys() validates every seed against its public key.
const certCore = JSON.parse(readFileSync(new URL('../v1/cert-core.json', import.meta.url), 'utf8')) as { seeds: { ed25519: SigningInput[] } };
const keys = signingKeys(certCore.seeds.ed25519);
const three = [11n, 13n, 17n];

/** The same signed certificate through both checker families: [transcript layer, certificate layer]. */
function both(spec: Parameters<typeof signedCertificate>[0], previous?: VerifiedCertificate): [string, string] {
  const s = signedCertificate(spec);
  return [code(() => verifyCertificate(ANCHOR, s, verify)), code(() => legacyVerify(s.body, s.signature, ANCHOR, keys, previous))];
}

describe('§3.0 genesis shape agrees across both checker families', () => {
  const genesis = signedCertificate({ t: 2, n: 3, coefficients: [11n, 13n] });
  const pinned = legacyVerify(genesis.body, genesis.signature, ANCHOR, keys);
  const rekey = (t: number, n: number, coefficients: bigint[]) =>
    both({ t, n, coefficients, epoch: 1n, rekey: 1n, previous: pinned.digest, previousMpk: times(G2_BASE, 11n) }, pinned);

  test('3-of-4 genesis and re-key certificates are accepted by both', () => {
    expect(both({ t: 3, n: 4, coefficients: three })).toEqual(['ok', 'ok']);
    expect(rekey(3, 4, [5n, 7n, 9n])).toEqual(['ok', 'ok']);
  });
  test('3-of-3 and 4-of-5 genesis and re-key certificates are refused by both', () => {
    expect(both({ t: 3, n: 3, coefficients: three })).toEqual(['UnsupportedFaultBudget', 'InvalidEncoding']);
    expect(both({ t: 4, n: 5, coefficients: [...three, 19n] })).toEqual(['UnsupportedFaultBudget', 'InvalidEncoding']);
    expect(rekey(3, 3, [5n, 7n, 9n])).toEqual(['UnsupportedFaultBudget', 'InvalidCertificate']);
    expect(rekey(4, 5, [5n, 7n, 9n, 19n])).toEqual(['UnsupportedFaultBudget', 'InvalidCertificate']);
  });
  test('genesis ceremonies: 3-of-4 accepted, 3-of-3 and 4-of-5 refused, by both', () => {
    const ceremony = (t: number, n: number) => {
      const s = signedCeremony({ kind: 1, t, n });
      return [code(() => authorizeGenesis(ANCHOR, s, verify)), code(() => legacyAuthorize(s.body, s.signature, ANCHOR, keys))];
    };
    expect(ceremony(3, 4)).toEqual(['ok', 'ok']);
    expect(ceremony(3, 3)).toEqual(['UnsupportedFaultBudget', 'InvalidCeremony']);
    expect(ceremony(4, 5)).toEqual(['UnsupportedFaultBudget', 'InvalidCeremony']);
  });
  test('certificate-layer re-key ceremonies: 3-of-4 accepted, 3-of-3 refused', () => {
    const rekeyCeremony = (t: number, n: number) => {
      const s = signedCeremony({ kind: 4, t, n, current: pinned.digest, epoch: 1n, rekey: 1n });
      return code(() => legacyAuthorize(s.body, s.signature, ANCHOR, keys, pinned));
    };
    expect(rekeyCeremony(3, 4)).toBe('ok');
    expect(rekeyCeremony(3, 3)).toBe('InvalidCeremony');
  });
});

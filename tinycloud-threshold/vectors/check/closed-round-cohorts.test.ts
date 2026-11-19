import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { reshareVerifyTranscript } from './reshare.ts';
import { authorizeCeremony, signingKeys, verifyCertificate, verifyClosedRound, type SigningInput } from './certificates.ts';
import { ANCHOR, COHORT_RECIPIENTS, code, complaints, did, reshareSetup, seal, verify, type Draft } from './testkit.ts';

// Unchecked: committed vector document; signingKeys() validates every seed against its public key.
const certCore = JSON.parse(readFileSync(new URL('../v1/cert-core.json', import.meta.url), 'utf8')) as { seeds: { ed25519: SigningInput[] } };
const keys = signingKeys(certCore.seeds.ed25519);
const s = reshareSetup('closed-round-cohorts', 2, 3, 3, 4);
const pinned = verifyCertificate(s.certificate.body, s.certificate.signature, ANCHOR, keys);
const ceremony = authorizeCeremony(s.ceremony.body, s.ceremony.signature, ANCHOR, keys, pinned);

/** The same 2-of-3 → 3-of-4 reshare with `extra` appended to closed R1: [transcript layer, certificate layer]. */
function both(extra: Draft): [string, string] {
  const rounds = s.rounds.map((round, k) => k === 0 ? [...round, extra] : round);
  const { records } = seal(s.digest, s.start, rounds);
  const legacy = () => records.reduce((previous, r, k) =>
    verifyClosedRound(ceremony, r.closure.body, r.closure.signature, k + 1, previous, r.messages, keys).transcript, s.start);
  return [code(() => reshareVerifyTranscript(ANCHOR, s.ceremony, s.certificate, records, verify)), code(legacy)];
}

describe('S0.4 opposite-cohort envelopes agree across both checker families', () => {
  test('an authorized, signed recipient-cohort R1 envelope is authenticated and ignored by both', () => {
    expect(both({ cohort: COHORT_RECIPIENTS, index: 4, payload: complaints([]) })).toEqual(['ok', 'ok']);
  });
  test('an extra envelope from outside the recipient directory is refused by both', () => {
    expect(both({ cohort: COHORT_RECIPIENTS, index: 5, payload: complaints([]) })).toEqual(['InvalidIndex', 'InvalidCeremony']);
  });
  test('an authorized index signed by another key is refused by both', () => {
    expect(both({ cohort: COHORT_RECIPIENTS, index: 4, signer: did(5), payload: complaints([]) })).toEqual(['InvalidSignature', 'InvalidSignature']);
  });
});

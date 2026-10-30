import { describe, expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { bytes, hex, tagged } from './protocol.ts';
import { authorizeCeremony, decodeCertificate, transcriptUpdate, verifyCertificate, verifyClosedRound } from './ceremony.ts';
import { ANCHOR, G2_BASE, code, did, flip, g2hex, signedCertificate, sign, times, verify, OWNER } from './testkit.ts';

/** cert-core.json S0.2 records exercised by the transcript layer: field names as committed. */
interface CertCase { name: string; operation: string; error?: string; inputs: Record<string, unknown>; outputs?: Record<string, unknown> }
const raw: unknown = JSON.parse(readFileSync(new URL('../v1/cert-core.json', import.meta.url), 'utf8'));
// Unchecked: committed vector document; every field read below is converted through bytes()/String() and compared.
const certCore = raw as { cases: CertCase[] };
const str = (v: unknown) => { if (typeof v !== 'string') throw new Error('expected string'); return v; };
const statement = (v: unknown) => {
  if (!v || typeof v !== 'object' || !('body' in v) || !('signature' in v)) throw new Error('expected statement');
  return { body: bytes(str(v.body)), signature: bytes(str(v.signature)) };
};
const byName = (name: string) => certCore.cases.find(c => c.name === name)!;

describe('cert-core S0.2 records agree with the transcript layer', () => {
  for (const name of ['genesis-2of3', 'reshare-3of4', 'rekey-2of3']) {
    test(`verify_certificate ${name}`, () => {
      const c = byName(name), o = c.outputs!;
      const cert = verifyCertificate({ owner: str(c.inputs.expected_owner), network: str(c.inputs.network) },
        { body: bytes(str(c.inputs.body)), signature: bytes(str(c.inputs.owner_signature)) }, verify);
      expect(hex(cert.digest)).toBe(str(o.digest));
      expect(hex(tagged('TC-THRESHOLD-V1-CERT-STATEMENT', cert.digest))).toBe(str(o.owner_statement));
      expect(g2hex(cert.mpk)).toBe(str(o.mpk));
      expect<unknown>(cert.commitments.map(g2hex)).toEqual(o.commitments);
      expect<unknown>(cert.publicShares.map((p, k) => ({ index: k + 1, point: g2hex(p) }))).toEqual(o.public_shares);
      expect<unknown>([Number(cert.epoch), Number(cert.rekey), cert.genesisT, cert.t, cert.n]).toEqual([o.epoch, o.rekey, o.genesis_t, o.threshold, o.members]);
      if (c.inputs.pinned_predecessor !== null) expect(hex(cert.previous!)).toBe(str(c.inputs.pinned_predecessor));
    });
  }
  test('decode_certificate refusals', () => {
    for (const name of ['duplicate-member-did', 'trailing-certificate-byte']) {
      const c = byName(name);
      expect(code(() => decodeCertificate(bytes(str(c.inputs.body))))).toBe(str(c.error));
    }
  });
  test('authorize_ceremony digests, signatures and pinned predecessors', () => {
    for (const name of ['ceremony-epoch-0', 'ceremony-epoch-1', 'ceremony-epoch-2']) {
      const c = byName(name);
      const ceremony = authorizeCeremony({ owner: str(c.inputs.expected_owner), network: str(c.inputs.network) },
        { body: bytes(str(c.inputs.body)), signature: bytes(str(c.inputs.signature)) }, verify);
      expect(hex(ceremony.digest)).toBe(str(c.outputs!.digest));
      expect(ceremony.current ? hex(ceremony.current) : null).toBe(c.inputs.pinned_predecessor === null ? null : str(c.inputs.pinned_predecessor));
    }
    const stale = byName('stale-ceremony-predecessor');
    const ceremony = authorizeCeremony(ANCHOR, { body: bytes(str(stale.inputs.body)), signature: bytes(str(stale.inputs.signature)) }, verify);
    expect(hex(ceremony.current!)).not.toBe(str(stale.inputs.pinned_predecessor));
  });
  test('verify_closed_round closure preimage and transcript update', () => {
    const c = byName('closed-round-1'), ceremony = byName('ceremony-epoch-0');
    const directory = authorizeCeremony(ANCHOR, { body: bytes(str(ceremony.inputs.body)), signature: bytes(str(ceremony.inputs.signature)) }, verify).directory;
    const listed: unknown = c.inputs.messages;
    if (!Array.isArray(listed)) throw new Error('expected messages');
    const messages = listed.map(statement);
    const closure = { body: bytes(str(c.inputs.closure)), signature: bytes(str(c.inputs.owner_signature)) };
    const previous = bytes(str(c.inputs.previous));
    const authenticated = verifyClosedRound(bytes(str(c.inputs.ceremony_digest)), Number(c.inputs.round), previous, { closure, messages },
      { 1: new Map(directory.map(d => [d.index, d.did])) }, OWNER, verify);
    expect(authenticated.length).toBe(messages.length);
    expect(hex(tagged('TC-THRESHOLD-V1-ROUND-CLOSE', closure.body))).toBe(str(c.outputs!.owner_preimage));
    expect(hex(transcriptUpdate(previous, closure))).toBe(str(c.outputs!.transcript_hash));
  });
});

describe('§3.9 decoded-certificate rules on synthetic certificates', () => {
  const coefficients = [11n, 13n];
  const verifyCert = (s: { body: Uint8Array; signature: Uint8Array }) => code(() => verifyCertificate(ANCHOR, s, verify));
  const resign = (body: Uint8Array) => ({ body, signature: sign(OWNER, tagged('TC-THRESHOLD-V1-CERT-STATEMENT', tagged('TC-THRESHOLD-V1-NETWORK-CERT', body))) });
  test('valid genesis, reshare successor and re-key certificates are accepted', () => {
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients }))).toBe('ok');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, epoch: 1n, previous: new Uint8Array(32).fill(1) }))).toBe('ok');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, epoch: 2n, rekey: 1n, previous: new Uint8Array(32).fill(1), previousMpk: times(G2_BASE, 5n) }))).toBe('ok');
  });
  test('constant, top coefficient and evaluated public shares', () => {
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, mpk: times(G2_BASE, 12n) }))).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients: [11n, 0n] }))).toBe('IdentityPoint');
    expect(verifyCert(signedCertificate({ t: 3, n: 3, coefficients: [11n, 13n, 0n] }))).toBe('IdentityPoint');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients: [11n, -11n] }))).toBe('IdentityPoint');
  });
  test('predecessor-field combinations, genesis t and option markers', () => {
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, previousMpk: times(G2_BASE, 5n) }))).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, epoch: 1n }))).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, rekey: 1n }))).toBe('InvalidEncoding');
    const successor = { epoch: 1n, previous: new Uint8Array(32).fill(1) };
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, genesisT: 1, ...successor }))).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, genesisT: 17, ...successor }))).toBe('InvalidEncoding');
    // Present predecessor digest with marker 02 instead of 01: the 32 digest bytes still follow, so only the marker rule rejects it.
    const body = signedCertificate({ t: 2, n: 3, coefficients, epoch: 1n, previous: new Uint8Array(32).fill(1) }).body;
    expect(body[body.length - 34]).toBe(1);
    expect(verifyCert(resign(flip(body, body.length - 34, 3)))).toBe('InvalidEncoding');
  });
  test('owner rulings: genesis genesis_t and budget; successor epoch and counter; re-key mpk and counter', () => {
    const previous = new Uint8Array(32).fill(1), rotated = times(G2_BASE, 5n);
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, genesisT: 3 }))).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 3, n: 4, coefficients: [11n, 13n, 17n] }))).toBe('UnsupportedFaultBudget');
    expect(verifyCert(signedCertificate({ t: 3, n: 4, coefficients: [11n, 13n, 17n], epoch: 1n, previous }))).toBe('ok');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, epoch: 0n, previous }))).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, epoch: 1n, rekey: 2n, previous }))).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, epoch: 2n, rekey: 2n, previous }))).toBe('ok');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, epoch: 1n, rekey: 1n, previous, previousMpk: times(G2_BASE, 11n) }))).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, epoch: 1n, rekey: 0n, previous, previousMpk: rotated }))).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, epoch: 1n, rekey: 1n, previous, previousMpk: rotated }))).toBe('ok');
  });
  test('anchor, signature cap and signer', () => {
    const good = signedCertificate({ t: 2, n: 3, coefficients });
    expect(verifyCert({ ...good, signature: new Uint8Array(513) })).toBe('InvalidEncoding');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients }, did(1)))).toBe('InvalidSignature');
    expect(verifyCert(signedCertificate({ t: 2, n: 3, coefficients, owner: did(1) }, did(1)))).toBe('InvalidCertificate');
  });
});

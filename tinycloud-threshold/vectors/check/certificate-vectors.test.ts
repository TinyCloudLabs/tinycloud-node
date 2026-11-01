import { expect, test } from 'bun:test';
import { bytes, hex, tagged, ProtocolError } from './protocol.ts';
import { CERT_TAGS } from './certificates.ts';
import { certificateCase } from './cert-schema.ts';
import { CertificateRegistry, checkCertificateVectors } from './cert-vectors.ts';
import { certificateFixture, runCertificateCli } from './certificate-test-input.ts';

function errorCode(f: () => unknown, code: string) {
  try { f(); } catch (e) {
    expect(e).toBeInstanceOf(ProtocolError);
    expect((e as ProtocolError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

test('all named certificate operations and public key mappings are computed', () => {
  const report = checkCertificateVectors(certificateFixture);
  expect(report.passed).toEqual(certificateFixture.cases.map(c => c.name));
  expect(report.signingKeys).toBe(17);
});

test('expected digest bytes never establish reference authority', () => {
  const file = structuredClone(certificateFixture);
  const certificate = certificateCase(file, 'genesis-2of3'), ceremony = certificateCase(file, 'ceremony-epoch-0');
  const certDigest = hex(tagged(CERT_TAGS.certificate, bytes(certificate.inputs.body)));
  const authDigest = hex(tagged(CERT_TAGS.ceremony, bytes(ceremony.inputs.body)));
  certificate.outputs.digest = '00'.repeat(32); ceremony.outputs.digest = '00'.repeat(32);
  const registry = new CertificateRegistry(file);
  expect(hex(registry.certificate(certDigest).digest)).toBe(certDigest);
  expect(hex(registry.ceremony(authDigest).digest)).toBe(authDigest);
  errorCode(() => registry.certificate('00'.repeat(32)), 'UnresolvedReference');
  errorCode(() => registry.ceremony('00'.repeat(32)), 'UnresolvedReference');
  expect(() => checkCertificateVectors(file)).toThrow('genesis-2of3');
});

test('unverified candidate signatures never become cached authority', () => {
  const file = structuredClone(certificateFixture), first = certificateCase(file, 'genesis-2of3');
  first.inputs.owner_signature = '00'.repeat(64);
  const registry = new CertificateRegistry(file), digest = hex(tagged(CERT_TAGS.certificate, bytes(first.inputs.body)));
  errorCode(() => registry.certificate(digest), 'InvalidSignature');
  errorCode(() => registry.certificate(digest), 'InvalidSignature');
});

test('duplicate certificate and ceremony input references are ambiguous even with differing expected outputs', () => {
  const certs = structuredClone(certificateFixture);
  const first = certificateCase(certs, 'genesis-2of3'), second = certificateCase(certs, 'reshare-3of4');
  second.inputs = structuredClone(first.inputs);
  const registry = new CertificateRegistry(certs);
  errorCode(() => registry.certificate(hex(tagged(CERT_TAGS.certificate, bytes(first.inputs.body)))), 'AmbiguousReference');
  const ceremonies = structuredClone(certificateFixture), auth = certificateCase(ceremonies, 'ceremony-epoch-0');
  certificateCase(ceremonies, 'ceremony-epoch-1').inputs = structuredClone(auth.inputs);
  errorCode(() => new CertificateRegistry(ceremonies).ceremony(hex(tagged(CERT_TAGS.ceremony, bytes(auth.inputs.body)))), 'AmbiguousReference');
});

test('cross-case verification is independent of case ordering', () => {
  const file = structuredClone(certificateFixture); file.cases.reverse();
  expect(checkCertificateVectors(file).passed).toEqual(file.cases.map(c => c.name));
});

test('all seventeen seed/public-key mappings are checked, not merely looked up', () => {
  for (let i = 0; i < certificateFixture.seeds.ed25519.length; i++) {
    const file = structuredClone(certificateFixture), key = file.seeds.ed25519[i]!;
    key.public_key = (key.public_key[0] === '0' ? '1' : '0') + key.public_key.slice(1);
    expect(() => checkCertificateVectors(file)).toThrow('InvalidSigningKey');
  }
});

test('schema refuses missing, duplicate and additional certificate records or fields', () => {
  const missing = structuredClone(certificateFixture); missing.cases.pop();
  expect(() => checkCertificateVectors(missing)).toThrow();
  const duplicate = structuredClone(certificateFixture); duplicate.cases[1] = duplicate.cases[0]!;
  expect(() => checkCertificateVectors(duplicate)).toThrow();
  const extra = structuredClone(certificateFixture); Reflect.set(extra.cases[0]!.inputs, 'anchor_fallback', true);
  expect(() => checkCertificateVectors(extra)).toThrow();
  const empty = structuredClone(certificateFixture); empty.cases = [];
  expect(runCertificateCli(empty).exitCode).toBe(1);
});

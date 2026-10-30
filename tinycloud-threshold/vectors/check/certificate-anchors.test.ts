import { expect, test } from 'bun:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytes, hex, tagged, ProtocolError } from './protocol.ts';
import { CERT_TAGS, decodeCertificate, encodeCertificate, verifyFaultProof } from './certificates.ts';
import { CertificateRegistry } from './cert-vectors.ts';
import { certificateCase } from './cert-schema.ts';
import { certificateFixture } from './certificate-test-input.ts';

function errorCode(f: () => unknown, code: string) {
  try { f(); } catch (e) {
    expect(e).toBeInstanceOf(ProtocolError);
    expect((e as ProtocolError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

test('stale ceremony inherits only the explicit pinned certificate anchor, never its encoded current digest', () => {
  const file = structuredClone(certificateFixture), row = certificateCase(file, 'stale-ceremony-predecessor');
  const registry = new CertificateRegistry(file), root = registry.certificate(row.inputs.pinned_predecessor);
  const inputs = certificateCase(file, 'genesis-2of3').inputs;
  expect(root.anchor).toEqual({ owner: inputs.expected_owner, network: inputs.network });
  errorCode(() => registry.ceremony(hex(tagged(CERT_TAGS.ceremony, bytes(row.inputs.body)))), 'InvalidCeremony');
  row.inputs.pinned_predecessor = '00'.repeat(32);
  errorCode(() => new CertificateRegistry(file).ceremony(hex(tagged(CERT_TAGS.ceremony, bytes(row.inputs.body)))), 'UnresolvedReference');
});

test('inline old-response certificate is verified as a successor under the resolved predecessor anchor', () => {
  const file = structuredClone(certificateFixture), row = certificateCase(file, 'genuine-old-response-after-rekey');
  const registry = new CertificateRegistry(file), body = decodeCertificate(bytes(row.inputs.certificate_body));
  const predecessor = registry.certificate(hex(body.previous!));
  const current = registry.certificate(hex(tagged(CERT_TAGS.certificate, bytes(row.inputs.certificate_body))));
  expect(current.anchor).toEqual(predecessor.anchor);
  expect(current.body.epoch).toBe(predecessor.body.epoch + 1n);
  const result = verifyFaultProof(current, bytes(row.inputs.request), bytes(row.inputs.share), bytes(row.inputs.signature), registry.keys);
  expect(result).toEqual({ verdict: 'NotAFault', reason: 'ContextMismatch' });
});

test('a self-signed inline owner replacement cannot choose its own external anchor', () => {
  const file = structuredClone(certificateFixture), row = certificateCase(file, 'genuine-old-response-after-rekey');
  const body = decodeCertificate(bytes(row.inputs.certificate_body));
  body.owner = file.seeds.ed25519[1]!.did;
  row.inputs.certificate_body = hex(encodeCertificate(body));
  const digest = tagged(CERT_TAGS.certificate, bytes(row.inputs.certificate_body));
  row.inputs.owner_signature = hex(ed25519.sign(tagged(CERT_TAGS.statement, digest), bytes(file.seeds.ed25519[1]!.seed)));
  errorCode(() => new CertificateRegistry(file).certificate(hex(digest)), 'InvalidCertificate');
});

test('inline certificate without a supplied or predecessor-rooted anchor has no fallback', () => {
  const file = structuredClone(certificateFixture), row = certificateCase(file, 'genuine-old-response-after-rekey');
  const root = decodeCertificate(bytes(certificateCase(file, 'genesis-2of3').inputs.body));
  root.owner = file.seeds.ed25519[1]!.did;
  row.inputs.certificate_body = hex(encodeCertificate(root));
  const digest = tagged(CERT_TAGS.certificate, bytes(row.inputs.certificate_body));
  row.inputs.owner_signature = hex(ed25519.sign(tagged(CERT_TAGS.statement, digest), bytes(file.seeds.ed25519[1]!.seed)));
  errorCode(() => new CertificateRegistry(file).certificate(hex(digest)), 'UnresolvedAnchor');
});

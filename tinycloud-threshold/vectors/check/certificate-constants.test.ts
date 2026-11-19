import { expect, test } from 'bun:test';
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytes, be, concat, hex, lp, tagged } from './protocol.ts';
import { certificateCase, type CertificateFile } from './cert-schema.ts';
import { certificateFixture, runCertificateCli } from './certificate-test-input.ts';
import { CertificateRegistry } from './cert-vectors.ts';

const tags = {
  activation: 'TC-THRESHOLD-V1-ACTIVATE', ceremony: 'TC-THRESHOLD-V1-CEREMONY-AUTH',
  certificate: 'TC-THRESHOLD-V1-NETWORK-CERT', closure: 'TC-THRESHOLD-V1-ROUND-CLOSE',
  message: 'TC-THRESHOLD-V1-CEREMONY-MSG', readiness: 'TC-THRESHOLD-V1-READY',
  statement: 'TC-THRESHOLD-V1-CERT-STATEMENT', transcript: 'TC-THRESHOLD-V1-TRANSCRIPT',
};
function sign(file: CertificateFile, index: number, preimage: Uint8Array): string {
  return hex(ed25519.sign(preimage, bytes(file.seeds.ed25519[index]!.seed)));
}
function rejects(file: CertificateFile, component: string) {
  const result = runCertificateCli(file);
  expect(result.exitCode).toBe(1);
  expect(result.stderr.toString()).toContain(component);
}

for (const key of Object.keys(tags) as (keyof typeof tags)[]) {
  test(`certificate metadata pins the ${key} domain`, () => {
    const file = structuredClone(certificateFixture);
    Reflect.set(file.dst, key, `${tags[key]}X`);
    rejects(file, `dst.${key}`);
  });
}
for (const field of ['suite', 'format_version', 'encoding', 'spec_sections'] as const) {
  test(`certificate format metadata ${field} is compiled`, () => {
    const file = structuredClone(certificateFixture);
    Reflect.set(file, field, field === 'format_version' ? 2 : field === 'spec_sections' ? ['other'] : 'other');
    rejects(file, field);
  });
}

for (const key of Object.keys(tags) as (keyof typeof tags)[]) {
  test(`certificate computation pins ${key} even with matching alternate-domain signatures or outputs`, () => {
    const file = structuredClone(certificateFixture), alternate = `${tags[key]}X`;
    if (key === 'certificate' || key === 'statement') {
      const row = certificateCase(file, 'genesis-2of3');
      const digest = tagged(key === 'certificate' ? alternate : tags.certificate, bytes(row.inputs.body));
      const preimage = tagged(key === 'statement' ? alternate : tags.statement, digest);
      row.inputs.owner_signature = sign(file, 0, preimage);
      row.outputs.digest = hex(digest); row.outputs.owner_statement = hex(preimage);
      rejects(file, 'genesis-2of3');
    } else if (key === 'ceremony') {
      const row = certificateCase(file, 'ceremony-epoch-0'), preimage = tagged(alternate, bytes(row.inputs.body));
      row.inputs.signature = sign(file, 0, preimage);
      row.outputs.digest = hex(preimage); row.outputs.signing_preimage = hex(preimage);
      rejects(file, 'ceremony-epoch-0');
    } else if (key === 'message' || key === 'closure' || key === 'transcript') {
      const row = certificateCase(file, 'closed-round-1');
      if (key === 'message') {
        const m = row.inputs.messages[0]!;
        m.signature = sign(file, 1, tagged(alternate, bytes(m.body)));
      }
      const list = concat(be(BigInt(row.inputs.messages.length), 2), ...row.inputs.messages.flatMap(m => [lp(bytes(m.body)), lp(bytes(m.signature))]));
      const closure = bytes(row.inputs.closure);
      closure.set(tagged(key === 'transcript' ? alternate : tags.transcript, list), 34);
      row.inputs.closure = hex(closure);
      const preimage = tagged(key === 'closure' ? alternate : tags.closure, closure);
      row.inputs.owner_signature = sign(file, 0, preimage);
      row.outputs.owner_preimage = hex(preimage);
      row.outputs.transcript_hash = hex(tagged(key === 'transcript' ? alternate : tags.transcript, concat(bytes(row.inputs.previous), lp(closure), lp(bytes(row.inputs.owner_signature)))));
      rejects(file, 'closed-round-1');
    } else {
      const row = certificateCase(file, 'activate-all-2of3');
      if (key === 'readiness') {
        const r = row.inputs.receipts[0]!, cert = new CertificateRegistry(file).certificate(row.inputs.candidate);
        const preimage = tagged(alternate, concat(cert.digest, cert.body.transcript, be(BigInt(r.index), 2), cert.keyset.publicShares.get(r.index)!.toBytes()));
        r.readiness_preimage = hex(preimage); r.signature = sign(file, 1, preimage);
        r.encoding = hex(concat(be(1n, 1), be(BigInt(r.index), 2), lp(bytes(r.signature))));
        r.receipt_hash = hex(tagged(tags.readiness, bytes(r.encoding)));
      }
      const sorted = row.inputs.receipts.map(r => bytes(r.receipt_hash)).sort((a, b) => Buffer.compare(a, b));
      const preimage = tagged(key === 'activation' ? alternate : tags.activation, concat(bytes(row.inputs.candidate), ...sorted));
      row.inputs.owner_signature = sign(file, 0, preimage); row.outputs.activation_preimage = hex(preimage);
      rejects(file, 'activate-all-2of3');
    }
  });
}

test('receipt hash independently pins READY in addition to the readiness signing preimage', () => {
  const file = structuredClone(certificateFixture), row = certificateCase(file, 'activate-all-2of3');
  row.inputs.receipts[0]!.receipt_hash = hex(tagged(`${tags.readiness}X`, bytes(row.inputs.receipts[0]!.encoding)));
  rejects(file, 'activate-all-2of3');
});

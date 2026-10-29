import { expect, test } from 'bun:test';
import { be, bytes, hex } from './protocol.ts';
import { certificateCase, type CertificateCase } from './cert-schema.ts';
import { certificateFixture, runCertificateCli } from './certificate-test-input.ts';

interface Probe {
  path: (string | number)[]; offset: number; mask: number; encoding: 'hex' | 'utf8' | 'u16';
  outcome: string; observed?: string; schema?: boolean;
}
const probes: Record<CertificateCase['name'], Probe> = {
  'genesis-2of3': { path: ['outputs', 'digest'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed genesis digest differs' },
  'reshare-3of4': { path: ['outputs', 'digest'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed reshare digest differs' },
  'rekey-2of3': { path: ['outputs', 'digest'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed rekey digest differs' },
  'ceremony-epoch-0': { path: ['outputs', 'digest'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed genesis authorization differs' },
  'ceremony-epoch-1': { path: ['outputs', 'digest'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed reshare authorization differs' },
  'ceremony-epoch-2': { path: ['outputs', 'digest'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed rekey authorization differs' },
  'closed-round-1': { path: ['outputs', 'transcript_hash'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed recursive transcript differs' },
  'activate-all-2of3': { path: ['inputs', 'receipts', 0, 'receipt_hash'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed receipt hash differs' },
  'duplicate-member-did': { path: ['inputs', 'body'], offset: -1, mask: 0, encoding: 'hex', outcome: 'duplicate DID byte restored, decoder succeeds', observed: 'undefined' },
  'trailing-certificate-byte': { path: ['error'], offset: 0, mask: 1, encoding: 'utf8', outcome: 'declared error label rejected by schema; valid-body semantic probe below', schema: true },
  'stale-ceremony-predecessor': { path: ['inputs', 'body'], offset: 0, mask: 1, encoding: 'hex', outcome: 'version changes actual result to InvalidEncoding', observed: 'InvalidEncoding' },
  'signed-valid-share': { path: ['outputs', 'signing_preimage'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed valid-share signing hash differs' },
  'signed-bad-share': { path: ['outputs', 'signing_preimage'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed bad-share signing hash differs' },
  'genuine-old-response-after-rekey': { path: ['inputs', 'owner_signature'], offset: 0, mask: 1, encoding: 'hex', outcome: 'invalid successor signature precedes stale context, NotAFault reason differs', observed: 'reason: observed "InvalidSignature"' },
  'activation-under-quorum': { path: ['inputs', 'receipts', 0, 'signature'], offset: 0, mask: 1, encoding: 'hex', outcome: 'invalid receipt precedes counting', observed: 'InvalidReadiness' },
  'activation-zero-budget': { path: ['inputs', 'budget'], offset: 1, mask: 1, encoding: 'u16', outcome: 'budget 0 becomes 1, valid all-member activation succeeds', observed: 'undefined' },
  'activation-budget-overflow': { path: ['inputs', 'candidate'], offset: 31, mask: 1, encoding: 'hex', outcome: 'candidate reference becomes unresolved before budget evaluation', observed: 'UnresolvedReference' },
  'activation-duplicate-member': { path: ['inputs', 'candidate'], offset: 31, mask: 1, encoding: 'hex', outcome: 'candidate reference becomes unresolved before duplicate evaluation', observed: 'UnresolvedReference' },
};

for (const original of certificateFixture.cases) {
  const probe = probes[original.name];
  test(`certificate one-byte CLI decision: ${original.name}: ${probe.outcome}`, () => {
    const file = structuredClone(certificateFixture);
    let target: object = certificateCase(file, original.name);
    for (const part of probe.path.slice(0, -1)) {
      const next: unknown = Reflect.get(target, part);
      if (!next || typeof next !== 'object') throw new Error('not a field container');
      target = next;
    }
    const field = probe.path.at(-1)!;
    const value: unknown = Reflect.get(target, field);
    if (probe.encoding === 'u16' ? typeof value !== 'number' : typeof value !== 'string') throw new Error('wrong probe field type');
    const before = typeof value === 'number' ? be(BigInt(value), 2) : Buffer.from(String(value), probe.encoding === 'u16' ? 'hex' : probe.encoding);
    const after = new Uint8Array(before);
    let offset = probe.offset, mask = probe.mask;
    if (original.name === 'duplicate-member-did') {
      const valid = bytes(certificateCase(file, 'genesis-2of3').inputs.body);
      expect(valid.length).toBe(before.length);
      const differences = [...before.keys()].filter(i => before[i] !== valid[i]);
      expect(differences.length).toBe(1);
      offset = differences[0]!; mask = before[offset]! ^ valid[offset]!;
    }
    if (offset < 0 || offset >= after.length) throw new Error('probe offset outside field');
    after[offset] = after[offset]! ^ mask;
    expect(after.length).toBe(before.length);
    expect(after.reduce((n, byte, i) => n + Number(byte !== before[i]), 0)).toBe(1);
    Reflect.set(target, field, probe.encoding === 'u16' ? Number(BigInt(`0x${hex(after)}`)) : Buffer.from(after).toString(probe.encoding));
    const result = runCertificateCli(file), error = result.stderr.toString();
    expect(result.exitCode).toBe(1);
    expect(error).toContain(original.name);
    if (probe.schema) expect(error).toContain('schema:');
    if (probe.observed) expect(error).toContain(probe.observed);
  }, 30000);
}

test('trailing-byte row compares the actual decoder outcome with a valid input', () => {
  const file = structuredClone(certificateFixture);
  certificateCase(file, 'trailing-certificate-byte').inputs.body = certificateCase(file, 'genesis-2of3').inputs.body;
  const result = runCertificateCli(file);
  expect(result.exitCode).toBe(1);
  expect(result.stderr.toString()).toContain('trailing-certificate-byte: computed error: observed undefined');
});

test('overflow row also compares semantic success after substituting a valid budget', () => {
  const file = structuredClone(certificateFixture);
  certificateCase(file, 'activation-budget-overflow').inputs.budget = 1;
  const result = runCertificateCli(file);
  expect(result.exitCode).toBe(1);
  expect(result.stderr.toString()).toContain('activation-budget-overflow: computed error: observed undefined');
});

test('duplicate row also compares semantic success after replacing the duplicate receipt', () => {
  const file = structuredClone(certificateFixture), values = certificateCase(file, 'activate-all-2of3').inputs.receipts;
  certificateCase(file, 'activation-duplicate-member').inputs.receipts = values.map(r => ({ index: r.index, signature: r.signature }));
  const result = runCertificateCli(file);
  expect(result.exitCode).toBe(1);
  expect(result.stderr.toString()).toContain('activation-duplicate-member: computed error: observed undefined');
});

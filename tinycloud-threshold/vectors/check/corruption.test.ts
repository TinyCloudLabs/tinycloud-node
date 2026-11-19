import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { parseVectors, vector, type VectorCase } from './schema.ts';

const input: unknown = JSON.parse(readFileSync(new URL('../v1/primitives.json', import.meta.url), 'utf8'));
const fixture = parseVectors(input);
const cli = new URL('./cli.ts', import.meta.url).pathname;

interface Corruption {
  path: (string | number)[];
  offset: number;
  mask: number;
  encoding: 'hex' | 'utf8';
  outcome: string;
  observed?: { code: string } | 'success' | 'schema';
}
const corruptions: Record<VectorCase['name'], Corruption> = {
  h1_custom_dst: { path: ['outputs', 'point'], offset: 47, mask: 1, encoding: 'hex', outcome: 'computed H1 bytes disagree' },
  pedersen_h: { path: ['outputs', 'point'], offset: 95, mask: 1, encoding: 'hex', outcome: 'computed Pedersen bytes disagree' },
  h3_scalar_r: { path: ['outputs', 'scalar'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed H3 scalar disagrees' },
  h2_gt: { path: ['outputs', 'bytes'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed H2 bytes disagree' },
  h4_sigma: { path: ['outputs', 'bytes'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed H4 bytes disagree' },
  pairing_generators: { path: ['outputs', 'gt'], offset: 575, mask: 1, encoding: 'hex', outcome: 'computed generator GT disagrees' },
  pairing_5_7: { path: ['outputs', 'gt'], offset: 575, mask: 1, encoding: 'hex', outcome: 'computed second GT disagrees' },
  fullident_wrap_unwrap: { path: ['outputs', 'ciphertext'], offset: 159, mask: 1, encoding: 'hex', outcome: 'computed FullIdent tuple disagrees' },
  threshold_2of3: { path: ['outputs', 'encrypted_shares', 0, 'signing_preimage'], offset: 31, mask: 1, encoding: 'hex', outcome: 'computed response signing preimage disagrees' },
  noncanonical_scalar: { path: ['inputs', 'bytes'], offset: 31, mask: 1, encoding: 'hex', outcome: 'r becomes r-1 and decodes successfully', observed: 'success' },
  identity_transport: { path: ['inputs', 'bytes'], offset: 0, mask: 128, encoding: 'hex', outcome: 'IdentityPoint becomes InvalidPoint', observed: { code: 'InvalidPoint' } },
  identity_mpk: { path: ['inputs', 'bytes'], offset: 0, mask: 128, encoding: 'hex', outcome: 'IdentityPoint becomes InvalidPoint', observed: { code: 'InvalidPoint' } },
  share_c3_mutated: { path: ['inputs', 'share'], offset: 35, mask: 1, encoding: 'hex', outcome: 'Invalid becomes ContextMismatch', observed: { code: 'ContextMismatch' } },
  share_context_transplanted: { path: ['inputs', 'share'], offset: 2, mask: 1, encoding: 'hex', outcome: 'member zero changes ContextMismatch to InvalidEncoding', observed: { code: 'InvalidEncoding' } },
  share_identity_transplanted: { path: ['inputs', 'request'], offset: 210, mask: 128, encoding: 'hex', outcome: 'transport flags change ContextMismatch to InvalidPoint', observed: { code: 'InvalidPoint' } },
  fullident_u_mutated: { path: ['error'], offset: 16, mask: 1, encoding: 'utf8', outcome: 'declared error label changes and fails schema; valid-tuple semantics checked separately', observed: 'schema' },
  fullident_v_mutated: { path: ['inputs', 'ciphertext'], offset: 96, mask: 1, encoding: 'hex', outcome: 'V restored, unwrap succeeds instead of InvalidCiphertext', observed: 'success' },
  fullident_w_mutated: { path: ['inputs', 'ciphertext'], offset: 128, mask: 1, encoding: 'hex', outcome: 'W restored, unwrap succeeds instead of InvalidCiphertext', observed: 'success' },
};

function runCli(value: unknown) {
  return Bun.spawnSync([process.execPath, cli, '/dev/stdin'], {
    env: process.env, stdin: Buffer.from(JSON.stringify(value)), stdout: 'pipe', stderr: 'pipe', timeout: 30000,
  });
}

test('real CLI accepts the unchanged vector document through memory input', () => {
  expect(runCli(fixture).exitCode).toBe(0);
});

for (const original of fixture.cases) {
  const mutation = corruptions[original.name];
  test(`one-byte CLI decision: ${original.name}: ${mutation.outcome}`, () => {
    const changed = structuredClone(fixture);
    let target: object = vector(changed, original.name);
    for (const component of mutation.path.slice(0, -1)) {
      const next: unknown = Reflect.get(target, component);
      if (!next || typeof next !== 'object') throw new Error(`not an object: ${component}`);
      target = next;
    }
    const field = mutation.path.at(-1)!;
    const value: unknown = Reflect.get(target, field);
    if (typeof value !== 'string') throw new Error(`not a byte field: ${String(field)}`);
    const before = Buffer.from(value, mutation.encoding);
    const after = Buffer.from(before);
    if (mutation.offset >= after.length) throw new Error('corruption offset outside field');
    after[mutation.offset] = after[mutation.offset]! ^ mutation.mask;
    expect(after.length).toBe(before.length);
    expect(after.reduce((count, byte, index) => count + Number(byte !== before[index]), 0)).toBe(1);
    Reflect.set(target, field, after.toString(mutation.encoding));
    const result = runCli(changed);
    expect(result.exitCode).toBe(1);
    expect(result.stderr.toString()).toContain(original.name);
    if (mutation.observed === 'schema') {
      expect(result.stderr.toString()).toContain('FAIL schema:');
    } else if (mutation.observed !== undefined) {
      const actual = mutation.observed === 'success' ? 'undefined' : JSON.stringify(mutation.observed);
      expect(result.stderr.toString()).toContain(`computed error: observed ${actual};`);
    }
  }, 30000);
}

test('U negative compares the actual unwrap outcome when given the valid tuple', () => {
  const changed = structuredClone(fixture);
  vector(changed, 'fullident_u_mutated').inputs.ciphertext = vector(changed, 'fullident_wrap_unwrap').outputs.ciphertext;
  const result = runCli(changed);
  expect(result.exitCode).toBe(1);
  expect(result.stderr.toString()).toContain('fullident_u_mutated: computed error: observed undefined');
});

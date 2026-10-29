import { expect, test } from 'bun:test';
import { readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { checkVectors } from './vectors.ts';
import { parseVectors, vector, type VectorFile } from './schema.ts';

const raw: unknown = JSON.parse(readFileSync(new URL('../v1/primitives.json', import.meta.url), 'utf8'));
const fixture = parseVectors(raw);
const clone = () => structuredClone(fixture);
function perturb(target: object, field: string) {
  const value: unknown = Reflect.get(target, field);
  if (typeof value !== 'string') throw new Error(`not a byte field: ${field}`);
  Reflect.set(target, field, (value[0] === '0' ? '1' : '0') + value.slice(1));
}

test('committed primitive vectors compute every named result', () => {
  const result = checkVectors(fixture);
  expect(result.passed).toEqual(fixture.cases.map((c: { name: string }) => c.name));
  expect(result.combinations).toEqual([[1, 2], [1, 3], [2, 3]]);
});

test('expected bytes and errors are compared with computation', () => {
  for (const [name, output] of [['h1_custom_dst', 'point'], ['pedersen_h', 'point'], ['h3_scalar_r', 'scalar'], ['h2_gt', 'bytes'], ['h4_sigma', 'bytes'], ['pairing_generators', 'gt'], ['pairing_5_7', 'gt'], ['fullident_wrap_unwrap', 'ciphertext']] as const) {
    const file = clone();
    perturb(vector(file, name).outputs, output);
    expect(() => checkVectors(file)).toThrow(name);
  }
  const validNegative = clone();
  const base = vector(validNegative, 'threshold_2of3');
  vector(validNegative, 'share_c3_mutated').inputs.share = base.outputs.encrypted_shares[0]!.encoded;
  expect(() => checkVectors(validNegative)).toThrow('share_c3_mutated');
  const validCiphertext = clone();
  vector(validCiphertext, 'fullident_v_mutated').inputs.ciphertext = vector(validCiphertext, 'fullident_wrap_unwrap').outputs.ciphertext;
  expect(() => checkVectors(validCiphertext)).toThrow('fullident_v_mutated');
}, 30000);

test('share encoded bytes, signing preimages and aggregates are computed', () => {
  for (const field of ['encoded', 'signing_preimage', 'c3']) {
    const file = clone();
    perturb(vector(file, 'threshold_2of3').outputs.encrypted_shares[1]!, field);
    expect(() => checkVectors(file)).toThrow('threshold_2of3');
  }
  for (const field of ['c1', 'c2', 'c3']) {
    const file = clone();
    perturb(vector(file, 'threshold_2of3').outputs.aggregate, field);
    expect(() => checkVectors(file)).toThrow('threshold_2of3');
  }
}, 30000);

test('schema refuses missing, duplicate, unknown and mistyped records', () => {
  for (const mutate of [
    (f: VectorFile) => { f.cases = []; },
    (f: VectorFile) => { f.cases.pop(); },
    (f: VectorFile) => { f.cases[1] = f.cases[0]!; },
    (f: VectorFile) => { Reflect.set(f.cases[0]!, 'operation', 'unknown'); },
    (f: VectorFile) => { Reflect.set(f.cases[0]!.inputs, 'extra', true); },
    (f: VectorFile) => { vector(f, 'h1_custom_dst').outputs.point = '00'; },
    (f: VectorFile) => { f.dst.h3 = 'other'; },
    (f: VectorFile) => { Reflect.set(f, 'format_version', 2); },
    (f: VectorFile) => { Reflect.set(f.cases[0]!, 'outputs', null); },
  ]) {
    const file = clone(); mutate(file);
    expect(() => checkVectors(file)).toThrow();
  }
});

test('real CLI accepts committed JSON and exits nonzero for a perturbed file', () => {
  const cli = new URL('./cli.ts', import.meta.url).pathname;
  const run = (...args: string[]) => Bun.spawnSync([process.execPath, cli, ...args], { env: process.env, stdout: 'pipe', stderr: 'pipe', timeout: 30000 });
  const good = run();
  expect(good.exitCode).toBe(0);
  const file = clone(); vector(file, 'h1_custom_dst').outputs.point = '00'.repeat(48);
  const path = `${process.env.HOME}/perturbed.json`;
  writeFileSync(path, JSON.stringify(file), { mode: 0o600 });
  try {
    const bad = run(path);
    expect(bad.exitCode).not.toBe(0);
    expect(bad.stderr.toString()).toContain('h1_custom_dst');
  } finally { unlinkSync(path); }
});

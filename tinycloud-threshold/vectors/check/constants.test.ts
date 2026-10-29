import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { bls12_381 as bls } from '@noble/curves/bls12-381.js';
import { parseVectors, vector, type VectorFile } from './schema.ts';
import { R, be, bytes, concat, encodeGT, h3, hex, scalar, tagged, xmd } from './protocol.ts';

const input: unknown = JSON.parse(readFileSync(new URL('../v1/primitives.json', import.meta.url), 'utf8'));
const fixture = parseVectors(input);
const cli = new URL('./cli.ts', import.meta.url).pathname;
function rejectDocument(file: VectorFile, component: string) {
  const result = Bun.spawnSync([process.execPath, cli, '/dev/stdin'], {
    env: process.env, stdin: Buffer.from(JSON.stringify(file)), stdout: 'pipe', stderr: 'pipe', timeout: 30000,
  });
  expect(result.exitCode).toBe(1);
  expect(result.stderr.toString()).toContain(component);
}

test('Pedersen message is pedersen-h even when another label has a matching point', () => {
  const file = structuredClone(fixture), row = vector(file, 'pedersen_h');
  const message = '706564657273656e2d69';
  Reflect.set(row.inputs, 'message', message);
  row.outputs.point = hex(bls.G2.hashToCurve(bytes(message), { DST: 'TC-THRESHOLD-V1-PEDERSEN-H_BLS12381G2_XMD:SHA-256_SSWU_RO_' }).toBytes());
  rejectDocument(file, 'pedersen_h');
});

const specDsts = {
  h1: 'TC-THRESHOLD-V1-IBE-ID_BLS12381G1_XMD:SHA-256_SSWU_RO_',
  pedersen_h: 'TC-THRESHOLD-V1-PEDERSEN-H_BLS12381G2_XMD:SHA-256_SSWU_RO_',
  h2: 'TC-THRESHOLD-V1-IBE-H2', h3: 'TC-THRESHOLD-V1-IBE-H3', h4: 'TC-THRESHOLD-V1-IBE-H4',
};
for (const key of ['h1', 'pedersen_h', 'h2', 'h3', 'h4'] as const) {
  test(`SPEC DST ${key} stays fixed with a matching alternate-domain output`, () => {
    const file = structuredClone(fixture), alternate = `${specDsts[key]}X`;
    file.dst[key] = alternate;
    switch (key) {
      case 'h1': {
        const row = vector(file, 'h1_custom_dst');
        row.inputs.dst = alternate;
        row.outputs.point = hex(bls.G1.hashToCurve(bytes(row.inputs.message), { DST: alternate }).toBytes());
        break;
      }
      case 'pedersen_h': {
        const row = vector(file, 'pedersen_h');
        row.inputs.dst = alternate;
        row.outputs.point = hex(bls.G2.hashToCurve(bytes(row.inputs.message), { DST: alternate }).toBytes());
        break;
      }
      case 'h2': {
        const row = vector(file, 'h2_gt');
        row.outputs.bytes = hex(xmd(bytes(row.inputs.message), alternate, 32));
        break;
      }
      case 'h3': {
        const row = vector(file, 'h3_scalar_r');
        row.outputs.scalar = hex(be(BigInt(`0x${hex(xmd(bytes(row.inputs.message), alternate, 48))}`) % R, 32));
        break;
      }
      case 'h4': {
        const row = vector(file, 'h4_sigma');
        row.outputs.bytes = hex(xmd(bytes(row.inputs.message), alternate, 32));
        break;
      }
    }
    rejectDocument(file, `dst.${key}`);
  });
}
for (const name of ['h1_custom_dst', 'pedersen_h'] as const) {
  test(`row-local ${name} DST is pinned independently of metadata`, () => {
    const file = structuredClone(fixture), row = vector(file, name);
    row.inputs.dst += 'X';
    row.outputs.point = hex((name === 'h1_custom_dst' ? bls.G1.hashToCurve(bytes(row.inputs.message), { DST: row.inputs.dst }) : bls.G2.hashToCurve(bytes(row.inputs.message), { DST: row.inputs.dst })).toBytes());
    rejectDocument(file, name);
  });
}

for (const name of ['pairing_generators', 'pairing_5_7'] as const) {
  for (const group of ['g1', 'g2'] as const) {
    test(`${name} ${group} is fixed even with a matching alternate pairing`, () => {
      const file = structuredClone(fixture), row = vector(file, name);
      const a = bls.G1.Point.BASE.multiply(name === 'pairing_generators' ? (group === 'g1' ? 2n : 1n) : (group === 'g1' ? 6n : 5n));
      const b = bls.G2.Point.BASE.multiply(name === 'pairing_generators' ? (group === 'g2' ? 2n : 1n) : (group === 'g2' ? 8n : 7n));
      row.inputs.g1 = hex(a.toBytes()); row.inputs.g2 = hex(b.toBytes());
      row.outputs.gt = hex(encodeGT(bls.pairing(a, b, true)));
      rejectDocument(file, name);
    });
  }
}

test('identity encoding prefix is fixed rather than selected by the document', () => {
  const file = structuredClone(fixture), row = vector(file, 'fullident_wrap_unwrap');
  const identity = bytes(row.inputs.identity);
  identity[29] = identity[29]! ^ 1;
  row.inputs.identity = hex(identity);
  const q = bls.G1.hashToCurve(identity, { DST: specDsts.h1 });
  const sigma = bytes(row.inputs.sigma), message = bytes(row.inputs.message), rho = h3(concat(sigma, message));
  const mask = xmd(encodeGT(bls.pairing(q.multiply(rho), bls.G2.Point.fromBytes(bytes(row.inputs.mpk)), true)), specDsts.h2, 32);
  const pad = xmd(sigma, specDsts.h4, 32);
  row.outputs.ciphertext = hex(concat(bls.G2.Point.BASE.multiply(rho).toBytes(), sigma.map((v, i) => v ^ mask[i]!), message.map((v, i) => v ^ pad[i]!)));
  row.outputs.derived_key = hex(q.multiply(scalar(bytes(row.inputs.master_scalar))).toBytes());
  rejectDocument(file, 'fullident_wrap_unwrap');
});

for (const tag of ['TC-THRESHOLD-V1-KEY-CONTEXT', 'TC-THRESHOLD-V1-DECRYPT-REQUEST', 'TC-THRESHOLD-V1-DECRYPT-SHARE'] as const) {
  test(`SPEC tagged-hash domain ${tag} is fixed`, () => {
    const file = structuredClone(fixture), row = vector(file, 'threshold_2of3');
    if (tag === 'TC-THRESHOLD-V1-KEY-CONTEXT') {
      row.inputs.context_digest = hex(tagged(`${tag}X`, bytes(row.inputs.context)));
      rejectDocument(file, 'threshold_2of3: context digest');
    } else if (tag === 'TC-THRESHOLD-V1-DECRYPT-REQUEST') {
      row.inputs.request_digest = hex(tagged(`${tag}X`, bytes(row.inputs.request)));
      rejectDocument(file, 'threshold_2of3: request digest');
    } else {
      const share = row.outputs.encrypted_shares[0]!;
      share.signing_preimage = hex(tagged(`${tag}X`, concat(bytes(row.inputs.request_digest), bytes(row.inputs.certificate_digest), be(BigInt(share.member), 2), bytes(share.encoded))));
      rejectDocument(file, 'threshold_2of3: share 1 signing preimage');
    }
  });
}

import { readFileSync } from 'node:fs';
import { checkVectors } from './vectors.ts';
import { checkCertificateVectors } from './cert-vectors.ts';

try {
  if (process.argv.length > 3) throw new Error('usage: bun cli.ts [vector-file]');
  const paths = process.argv[2] ? [process.argv[2]] : [new URL('../v1/primitives.json', import.meta.url), new URL('../v1/cert-core.json', import.meta.url)];
  for (const path of paths) {
    const input: unknown = JSON.parse(readFileSync(path, 'utf8'));
    if (input && typeof input === 'object' && 'suite' in input && input.suite === 'TC-THRESHOLD-V1') {
      const report = checkCertificateVectors(input);
      for (const name of report.passed) console.log(`PASS ${name}`);
      console.log(`Certificate vectors: ${report.passed.length}/${report.passed.length}; signing keys: ${report.signingKeys}`);
    } else {
      const report = checkVectors(input);
      for (const name of report.passed) console.log(`PASS ${name}`);
      console.log(`Primitive vectors: ${report.passed.length}/${report.passed.length}; combinations: ${report.combinations.map(m => m.join('+')).join(', ')}`);
    }
  }
} catch (e) {
  console.error(`FAIL ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 1;
}

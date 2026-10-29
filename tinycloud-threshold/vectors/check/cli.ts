import { readFileSync } from 'node:fs';
import { checkVectors } from './vectors.ts';

try {
  if (process.argv.length > 3) throw new Error('usage: bun cli.ts [primitive-vector-file]');
  const path = process.argv[2] ?? new URL('../v1/primitives.json', import.meta.url);
  const input: unknown = JSON.parse(readFileSync(path, 'utf8'));
  const report = checkVectors(input);
  for (const name of report.passed) console.log(`PASS ${name}`);
  console.log(`Primitive vectors: ${report.passed.length}/${report.passed.length}; combinations: ${report.combinations.map(m => m.join('+')).join(', ')}`);
} catch (e) {
  console.error(`FAIL ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 1;
}

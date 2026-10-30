import { readFileSync } from 'node:fs';
import { checkVectors } from './vectors.ts';
import { checkTranscripts, transcriptKind } from './transcripts.ts';

const defaults = ['../v1/primitives.json', '../v1/dkg-genesis.json', '../v1/reshare.json'].map(p => new URL(p, import.meta.url));

function check(input: unknown) {
  if (transcriptKind(input) !== undefined) {
    const report = checkTranscripts(input);
    for (const name of report.passed) console.log(`PASS ${name}`);
    console.log(`${report.kind === 'dkg' ? 'DKG' : 'Reshare'} transcripts: ${report.passed.length}/${report.passed.length}`);
    return;
  }
  const report = checkVectors(input);
  for (const name of report.passed) console.log(`PASS ${name}`);
  console.log(`Primitive vectors: ${report.passed.length}/${report.passed.length}; combinations: ${report.combinations.map(m => m.join('+')).join(', ')}`);
}

try {
  if (process.argv.length > 3) throw new Error('usage: bun cli.ts [vector-file]');
  const paths = process.argv[2] === undefined ? defaults : [process.argv[2]];
  for (const path of paths) check(JSON.parse(readFileSync(path, 'utf8')));
} catch (e) {
  console.error(`FAIL ${e instanceof Error ? e.message : String(e)}`);
  process.exitCode = 1;
}

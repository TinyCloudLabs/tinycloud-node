import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { checkTranscripts } from './transcripts.ts';

const load = (file: string): unknown => JSON.parse(readFileSync(new URL(`../v1/${file}`, import.meta.url), 'utf8'));
const dkg = load('dkg-genesis.json'), reshare = load('reshare.json');
const cli = new URL('./cli.ts', import.meta.url).pathname;
interface Outputs {
  mpk: string; transcript_hash: string; commitments: string[]; public_shares: { member: number; point: string }[];
  qual: number[]; disqualified: unknown[]; reconstructed: number[]; dealers: number[]; excluded: unknown[]; threshold: number; members: number;
}
interface DocView { cases: { name: string; inputs: Record<string, unknown>; outputs: Outputs; error?: string }[]; dst: Record<string, unknown> }
/** Clones a committed document and applies a targeted edit to it. */
function edit(doc: unknown, change: (d: DocView) => void): unknown {
  // Unchecked: the clone of a committed vector document; checkTranscripts re-validates the edited result.
  const view = structuredClone(doc) as DocView;
  change(view);
  return view;
}
const hexFlip = (v: unknown) => typeof v === 'string' ? (v[0] === '0' ? '1' : '0') + v.slice(1) : '';

test('committed transcript documents compute every named case', () => {
  expect(checkTranscripts(dkg).passed).toEqual([
    'genesis_2of3', 'genesis_2of3_selective_extraction', 'genesis_3of5_two_faulty',
    'genesis_3of5_answers_and_disqualification', 'insufficient_reconstruction_values', 'insufficient_qualified_dealers',
  ]);
  expect(checkTranscripts(reshare).passed).toEqual([
    'reshare_2of3_to_3of4', 'refresh_2of3_answered_complaint', 'reshare_wrong_constant', 'reshare_t_prime_complaints', 'reshare_insufficient_dealers',
  ]);
}, 30000);

test('every expected output and declared input digest is compared with computation', () => {
  const dkgFields: [string, (o: Outputs) => void][] = [
    ['mpk', o => { o.mpk = hexFlip(o.mpk); }],
    ['transcript hash', o => { o.transcript_hash = hexFlip(o.transcript_hash); }],
    ['commitments', o => { o.commitments[1] = hexFlip(o.commitments[1]); }],
    ['public shares', o => { o.public_shares[2]!.point = hexFlip(o.public_shares[2]!.point); }],
    ['qual', o => { o.qual = [1, 2]; }],
    ['disqualified', o => { o.disqualified = [{ member: 4, reason: 'MissingDeal' }]; }],
    ['reconstructed', o => { o.reconstructed = [2]; }],
  ];
  for (const [label, change] of dkgFields) {
    expect(() => checkTranscripts(edit(dkg, d => change(d.cases[1]!.outputs)))).toThrow(`genesis_2of3_selective_extraction: ${label}`);
  }
  const reshareFields: [string, (o: Outputs) => void][] = [
    ['dealers', o => { o.dealers = [1, 3]; }], ['excluded', o => { o.excluded = []; }],
    ['threshold', o => { o.threshold = 3; }], ['members', o => { o.members = 4; }],
  ];
  for (const [label, change] of reshareFields) {
    expect(() => checkTranscripts(edit(reshare, d => change(d.cases[2]!.outputs)))).toThrow(`reshare_wrong_constant: ${label}`);
  }
  expect(() => checkTranscripts(edit(dkg, d => { d.cases[4]!.error = 'InsufficientQualified'; }))).toThrow('insufficient_reconstruction_values: computed error');
  expect(() => checkTranscripts(edit(reshare, d => { d.cases[0]!.inputs.ceremony_digest = hexFlip(d.cases[0]!.inputs.ceremony_digest); }))).toThrow('reshare_2of3_to_3of4: ceremony digest');
  expect(() => checkTranscripts(edit(dkg, d => { d.cases[0]!.inputs.initial_transcript = hexFlip(d.cases[0]!.inputs.initial_transcript); }))).toThrow('genesis_2of3: initial transcript');
  expect(() => checkTranscripts(edit(dkg, d => { d.cases[0]!.inputs.threshold = 3; }))).toThrow('genesis_2of3: ceremony threshold');
}, 60000);

test('schema refuses mistyped, duplicate, ambiguous and alternate-domain documents', () => {
  for (const change of [
    (d: DocView) => { d.cases[1]!.name = d.cases[0]!.name; },
    (d: DocView) => { d.cases[0]!.error = 'InvalidRound'; },
    (d: DocView) => { d.cases[0]!.inputs.extra = 1; },
    (d: DocView) => { d.dst.transcript = 'TC-THRESHOLD-V1-TRANSCRIPTX'; },
    (d: DocView) => { d.cases[0]!.inputs.ceremony = { body: 'zz', signature: '' }; },
  ]) {
    expect(() => checkTranscripts(edit(dkg, change))).toThrow('schema:');
  }
  expect(() => checkTranscripts({})).toThrow('schema:');
});

test('real CLI checks all committed documents by default and a transcript document by path', () => {
  const run = (...args: string[]) => Bun.spawnSync([process.execPath, cli, ...args], { env: process.env, stdout: 'pipe', stderr: 'pipe', timeout: 60000 });
  const all = run();
  expect(all.exitCode).toBe(0);
  expect(all.stdout.toString()).toContain('Primitive vectors: 18/18');
  expect(all.stdout.toString()).toContain('DKG transcripts: 6/6');
  expect(all.stdout.toString()).toContain('Reshare transcripts: 5/5');
  const one = run(new URL('../v1/reshare.json', import.meta.url).pathname);
  expect(one.exitCode).toBe(0);
  expect(one.stdout.toString()).not.toContain('Primitive vectors');
}, 60000);

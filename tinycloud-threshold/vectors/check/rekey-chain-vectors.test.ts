// The committed ../v1/dkg-rekey.json and ../v1/chain.json: schema, dispatch, comparison of every declared
// field with computation, and one-byte corruptions of every record kind rejected by the checker and the real CLI.
import { describe, expect, test } from 'bun:test';
import { code } from './testkit.ts';
import { checkTranscripts, parseTranscriptDocument, transcriptKind } from './transcripts.ts';
import { checkChain, chainInputOf, parseChainDocument, type ChainFile } from './chain-vectors.ts';
import { chainOrder, verifyChainStep } from './chain.ts';
import { chainProbes, cloneChain } from './chain-probes.ts';
import { verifierOf } from './transcript-common.ts';
import { editDoc, hexFlip, loadJson, runCli, type Loose } from './cli-kit.ts';

const load = loadJson;
const rekey = load('dkg-rekey.json'), chain = load('chain.json'), genesis = load('dkg-genesis.json'), reshare = load('reshare.json');
const edit = editDoc;

describe('dispatch and schema', () => {
  test('transcriptKind separates the four transcript documents, the chain marker deciding first', () => {
    expect([genesis, rekey, reshare, chain].map(transcriptKind)).toEqual(['dkg', 'rekey', 'reshare', 'chain']);
    expect(transcriptKind({ spec_sections: ['S0.3 DKG appendix', 'S0.5 re-key appendix', 'S0.5 chain appendix'] })).toBe('chain');
    expect(transcriptKind({ spec_sections: ['3.2'] })).toBeUndefined();
    expect(transcriptKind({})).toBeUndefined();
    expect(parseTranscriptDocument(rekey).cases.length).toBe(14);
    expect(parseTranscriptDocument(chain).cases.length).toBe(8);
  });
  test('the re-key document is the genesis document plus the pinned certificate of every case', () => {
    expect(() => checkTranscripts(edit(rekey, d => { Reflect.deleteProperty(d.cases[0]!.inputs, 'current_certificate'); }))).toThrow('schema:');
    expect(() => checkTranscripts(edit(genesis, d => { d.cases[0]!.inputs.current_certificate = { body: 'aa', owner_signature: 'bb' }; }))).toThrow('schema:');
    // A re-key transcript under the genesis marker, and a genesis transcript under the re-key marker, are not either document.
    expect(() => checkTranscripts(edit(rekey, d => { d.spec_sections = ['3.2', '3.3', '3.7', '3.10', 'S0.3 DKG appendix']; }))).toThrow('schema:');
    expect(() => checkTranscripts(edit(genesis, d => { d.spec_sections = ['3.2', '3.3', '3.7', '3.9', '3.10', 'S0.3 DKG appendix', 'S0.5 re-key appendix']; }))).toThrow('schema:');
  });
  test('schema refuses mistyped, duplicate, ambiguous and alternate-domain re-key and chain documents', () => {
    for (const [doc, changes] of [
      [rekey, [
        (d: Loose) => { d.cases[1]!.name = d.cases[0]!.name; },
        (d: Loose) => { d.cases[0]!.error = 'InvalidRound'; },
        (d: Loose) => { d.cases[0]!.inputs.extra = 1; },
        (d: Loose) => { d.dst.transcript = 'TC-THRESHOLD-V1-TRANSCRIPTX'; },
        (d: Loose) => { d.cases[0]!.inputs.current_certificate = { body: 'zz', owner_signature: '' }; },
        (d: Loose) => { d.cases[0]!.inputs.current_certificate.extra = ''; },
      ]],
      [chain, [
        (d: Loose) => { d.cases[1]!.name = d.cases[0]!.name; },
        (d: Loose) => { d.cases[0]!.error = 'InvalidRound'; },
        (d: Loose) => { d.cases[0]!.inputs.extra = 1; },
        (d: Loose) => { d.cases[0]!.inputs.quorum = 'threshold'; },
        (d: Loose) => { Reflect.deleteProperty(d.cases[0]!.inputs, 'previous_certificate'); },
        (d: Loose) => { d.cases[0]!.inputs.activation.body = d.cases[0]!.inputs.activation.body + '00'; },
        (d: Loose) => { d.cases[0]!.inputs.receipts = []; },
        (d: Loose) => { d.cases[0]!.outputs.ceremony = { qual: [1] }; },
        (d: Loose) => { d.dst.ready = 'TC-THRESHOLD-V1-READYX'; },
        (d: Loose) => { d.dst.activate = 'TC-THRESHOLD-V1-ACTIVATEX'; },
        (d: Loose) => { d.spec_sections = [...d.spec_sections, 'S0.9']; },
        (d: Loose) => { d.cases[2]!.operation = 'dkg_verify_transcript'; },
      ]],
    ] as const) {
      for (const change of changes) expect(() => checkTranscripts(edit(doc, change))).toThrow('schema:');
    }
    expect(() => parseChainDocument(rekey)).toThrow('schema:');
  });
});

describe('committed documents compute every named case', () => {
  test('re-key and chain', () => {
    expect(checkTranscripts(rekey).passed).toEqual([
      'rekey_2of3', 'rekey_2of3_selective_extraction', 'rekey_3of5_two_faulty', 'rekey_3of5_answers_and_disqualification',
      'insufficient_reconstruction_values', 'insufficient_qualified_dealers', 'rekey_3of4_one_faulty',
      'rekey_3of3_outside_the_genesis_budget', 'rekey_4of5_outside_the_genesis_budget', 'rekey_names_another_current_certificate',
      'rekey_counter_not_incremented', 'rekey_skips_an_epoch', 'genesis_statement_presented_as_rekey', 'rekey_transcript_under_another_generation',
    ]);
    expect(checkTranscripts(chain).passed).toEqual([
      'chain_0_genesis_2of3', 'chain_1_reshare_3of4', 'chain_2_reshare_2of3', 'chain_3_refresh_2of3',
      'chain_4_rekey_3of4', 'chain_5_reshare_2of3', 'chain_6_rekey_2of3', 'chain_7_reshare_3of4',
    ]);
  }, 60000);
});

describe('every declared field is compared with computation', () => {
  test('re-key outputs and input digests', () => {
    const fields: [string, (o: Loose['cases'][number]['outputs']) => void][] = [
      ['mpk', o => { o.mpk = hexFlip(o.mpk); }],
      ['transcript hash', o => { o.transcript_hash = hexFlip(o.transcript_hash); }],
      ['commitments', o => { o.commitments[1] = hexFlip(o.commitments[1]); }],
      ['public shares', o => { o.public_shares[2]!.point = hexFlip(o.public_shares[2]!.point); }],
      ['qual', o => { o.qual = [1, 2]; }],
      ['disqualified', o => { o.disqualified = [{ member: 4, reason: 'MissingDeal' }]; }],
      ['reconstructed', o => { o.reconstructed = [2]; }],
    ];
    for (const [label, change] of fields) {
      expect(() => checkTranscripts(edit(rekey, d => change(d.cases[1]!.outputs)))).toThrow(`rekey_2of3_selective_extraction: ${label}`);
    }
    expect(() => checkTranscripts(edit(rekey, d => { d.cases[0]!.inputs.ceremony_digest = hexFlip(d.cases[0]!.inputs.ceremony_digest); }))).toThrow('rekey_2of3: ceremony digest');
    expect(() => checkTranscripts(edit(rekey, d => { d.cases[0]!.inputs.initial_transcript = hexFlip(d.cases[0]!.inputs.initial_transcript); }))).toThrow('rekey_2of3: initial transcript');
    expect(() => checkTranscripts(edit(rekey, d => { d.cases[0]!.inputs.threshold = 3; }))).toThrow('rekey_2of3: ceremony threshold');
    expect(() => checkTranscripts(edit(rekey, d => { d.cases[4]!.error = 'InsufficientQualified'; }))).toThrow('insufficient_reconstruction_values: computed error');
  }, 60000);
  test('chain outputs and input digests', () => {
    const fields: [string, number, (o: Loose['cases'][number]['outputs']) => void][] = [
      ['kind', 4, o => { o.kind = 'reshare'; }],
      ['epoch', 4, o => { o.epoch = 3; }],
      ['rekey', 4, o => { o.rekey = 0; }],
      ['genesis t', 4, o => { o.genesis_t = 2; }],
      ['threshold', 4, o => { o.threshold = 2; }],
      ['members', 4, o => { o.members = 3; }],
      ['mpk', 4, o => { o.mpk = hexFlip(o.mpk); }],
      ['commitments', 4, o => { o.commitments[1] = hexFlip(o.commitments[1]); }],
      ['public shares', 4, o => { o.public_shares[3]!.point = hexFlip(o.public_shares[3]!.point); }],
      ['transcript hash', 4, o => { o.transcript_hash = hexFlip(o.transcript_hash); }],
      ['certificate digest', 4, o => { o.certificate_digest = hexFlip(o.certificate_digest); }],
      ['activation', 4, o => { o.activation = hexFlip(o.activation, 31); }],
      ['ceremony outcome', 4, o => { o.ceremony = { qual: [1, 2, 3], reconstructed: [] }; }],
      ['ceremony outcome', 1, o => { o.ceremony = { dealers: [1, 3] }; }],
      ['ceremony outcome', 3, o => { o.ceremony = { dealers: [2, 1] }; }],
      ['ceremony outcome', 0, o => { o.ceremony = { qual: [1, 2, 3], reconstructed: [1] }; }],
    ];
    for (const [label, index, change] of fields) {
      const name = (chain as Loose).cases[index]!.name;
      expect(() => checkTranscripts(edit(chain, d => change(d.cases[index]!.outputs)))).toThrow(`${name}: ${label}`);
    }
    expect(() => checkChain(edit(chain, d => { d.cases[2]!.inputs.ceremony_digest = hexFlip(d.cases[2]!.inputs.ceremony_digest); }))).toThrow('chain_2_reshare_2of3: ceremony digest');
    expect(() => checkChain(edit(chain, d => { d.cases[3]!.inputs.initial_transcript = hexFlip(d.cases[3]!.inputs.initial_transcript); }))).toThrow('chain_3_refresh_2of3: initial transcript');
  }, 60000);
  test('chain order is part of the document: a reordered case list is refused', () => {
    expect(() => checkChain(edit(chain, d => { [d.cases[1], d.cases[2]] = [d.cases[2]!, d.cases[1]!]; }))).toThrow('chain_2_reshare_2of3: InvalidCertificate');
    expect(() => checkChain(edit(chain, d => { d.cases.splice(1, 1); }))).toThrow('chain_2_reshare_2of3: InvalidCertificate');
    expect(() => checkChain(edit(chain, d => { d.cases = d.cases.slice(1); }))).toThrow('chain_1_reshare_3of4: InvalidCertificate');
  }, 60000);
});

describe('one-byte corruptions of every record kind in every chain case are rejected', () => {
  const file: ChainFile = parseChainDocument(chain), verify = verifierOf(file);
  for (const [k, c] of file.cases.entries()) {
    test(c.name, () => {
      const base = chainInputOf(c), accepted: string[] = [], codes = new Set<string>();
      chainOrder(k === 0 ? undefined : chainInputOf(file.cases[k - 1]!), base);
      expect(code(() => verifyChainStep(file.anchor, base, verify))).toBe('ok');
      for (const p of chainProbes(base)) {
        const x = cloneChain(base);
        p.apply(x);
        const observed = code(() => verifyChainStep(file.anchor, x, verify));
        if (observed === 'ok') accepted.push(`${p.record} ${p.field}`);
        codes.add(observed);
      }
      expect(accepted).toEqual([]);
      // Several different checks fire (this is not one catch-all failure).
      expect(codes.size).toBeGreaterThan(3);
    }, 120000);
  }
});

describe('the real CLI exits nonzero for an edited committed vector', () => {
  const view = chain as Loose;
  test('control: the committed documents pass through /dev/stdin', () => {
    for (const doc of [rekey, chain]) {
      const r = runCli(doc);
      expect(r.exitCode).toBe(0);
    }
  }, 60000);
  const chainEdits: [string, number, (d: Loose) => void][] = [
    ['ceremony body byte', 1, d => { d.cases[1]!.inputs.ceremony.body = hexFlip(d.cases[1]!.inputs.ceremony.body, 5); }],
    ['closure body byte', 2, d => { d.cases[2]!.inputs.rounds[1]!.closure.body = hexFlip(d.cases[2]!.inputs.rounds[1]!.closure.body, 40); }],
    ['closure signature byte', 2, d => { d.cases[2]!.inputs.rounds[0]!.closure.signature = hexFlip(d.cases[2]!.inputs.rounds[0]!.closure.signature); }],
    ['member message body byte', 3, d => { const m = d.cases[3]!.inputs.rounds[2]!.messages[0]!; m.body = hexFlip(m.body, m.body.length / 2 - 1); }],
    ['member message signature byte', 4, d => { const m = d.cases[4]!.inputs.rounds[3]!.messages[1]!; m.signature = hexFlip(m.signature); }],
    ['certificate body byte', 4, d => { const c = d.cases[4]!.inputs.certificate; c.body = hexFlip(c.body, c.body.length / 2 - 40); }],
    ['certificate signature byte', 6, d => { d.cases[6]!.inputs.certificate.owner_signature = hexFlip(d.cases[6]!.inputs.certificate.owner_signature); }],
    ['previous certificate body byte', 5, d => { const c = d.cases[5]!.inputs.previous_certificate; c.body = hexFlip(c.body, c.body.length / 2 - 40); }],
    ['receipt signature byte', 7, d => { d.cases[7]!.inputs.receipts[2]!.signature = hexFlip(d.cases[7]!.inputs.receipts[2]!.signature); }],
    ['receipt member index', 0, d => { d.cases[0]!.inputs.receipts[0]!.member = 2; }],
    ['activation body byte', 6, d => { d.cases[6]!.inputs.activation.body = hexFlip(d.cases[6]!.inputs.activation.body, 31); }],
    ['activation signature byte', 4, d => { d.cases[4]!.inputs.activation.signature = hexFlip(d.cases[4]!.inputs.activation.signature); }],
    ['output mpk', 4, d => { d.cases[4]!.outputs.mpk = hexFlip(d.cases[4]!.outputs.mpk); }],
    ['output epoch', 1, d => { d.cases[1]!.outputs.epoch = 2; }],
    ['output ceremony outcome', 1, d => { d.cases[1]!.outputs.ceremony = { dealers: [2, 3] }; }],
  ];
  for (const [label, index, change] of chainEdits) {
    test(`chain.json: ${label}`, () => {
      const r = runCli(edit(chain, change));
      expect(r.exitCode).toBe(1);
      expect(r.stderr.toString()).toContain(`FAIL ${view.cases[index]!.name}:`);
    }, 60000);
  }
  const rekeyEdits: [string, number, (d: Loose) => void][] = [
    ['ceremony body byte', 0, d => { d.cases[0]!.inputs.ceremony.body = hexFlip(d.cases[0]!.inputs.ceremony.body, 3); }],
    ['pinned certificate body byte', 1, d => { const c = d.cases[1]!.inputs.current_certificate; c.body = hexFlip(c.body, c.body.length / 2 - 40); }],
    ['pinned certificate signature byte', 2, d => { d.cases[2]!.inputs.current_certificate.owner_signature = hexFlip(d.cases[2]!.inputs.current_certificate.owner_signature); }],
    ['closure body byte', 3, d => { d.cases[3]!.inputs.rounds[2]!.closure.body = hexFlip(d.cases[3]!.inputs.rounds[2]!.closure.body, 40); }],
    ['member message body byte', 1, d => { const m = d.cases[1]!.inputs.rounds[3]!.messages[0]!; m.body = hexFlip(m.body, m.body.length / 2 - 1); }],
    ['member message signature byte', 6, d => { d.cases[6]!.inputs.rounds[4]!.messages[3]!.signature = hexFlip(d.cases[6]!.inputs.rounds[4]!.messages[3]!.signature); }],
    ['output mpk', 0, d => { d.cases[0]!.outputs.mpk = hexFlip(d.cases[0]!.outputs.mpk); }],
    ['expected error', 4, d => { d.cases[4]!.error = 'InsufficientQualified'; }],
  ];
  for (const [label, index, change] of rekeyEdits) {
    test(`dkg-rekey.json: ${label}`, () => {
      const r = runCli(edit(rekey, change));
      expect(r.exitCode).toBe(1);
      expect(r.stderr.toString()).toContain(`FAIL ${(rekey as Loose).cases[index]!.name}:`);
    }, 60000);
  }
});

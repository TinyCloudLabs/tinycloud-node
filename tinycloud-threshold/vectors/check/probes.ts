// Test-only one-byte corruption probes over committed transcript vectors. Each probe flips
// exactly one byte of one signed record and names the typed reason the verifier must return.
import { readFileSync } from 'node:fs';
import { bytes, type Bytes } from './protocol.ts';
import { decodeCeremony, decodeCertificate, type RoundRecord, type Statement } from './ceremony.ts';
import { dkgVerifyTranscript } from './dkg.ts';
import { reshareVerifyTranscript } from './reshare.ts';
import { parseTranscriptDocument, recordsOf, statementOf, verifierOf, type DkgFile, type ReshareFile } from './transcripts.ts';
import { code } from './testkit.ts';

export interface TranscriptInput { ceremony: Statement; certificate?: Statement; records: RoundRecord[] }
export interface Probe { record: string; field: string; offset: number; mask: number; expected: string; apply: (x: TranscriptInput) => void }
export type Doc = DkgFile | ReshareFile;
export type DocCase = Doc['cases'][number];
export function loadDoc(file: string): Doc {
  return parseTranscriptDocument(JSON.parse(readFileSync(new URL(`../v1/${file}`, import.meta.url), 'utf8')));
}

export function inputOf(c: DocCase): TranscriptInput {
  const base = { ceremony: statementOf(c.inputs.ceremony), records: recordsOf(c.inputs.rounds) };
  if (!('current_certificate' in c.inputs)) return base;
  const cert = c.inputs.current_certificate;
  return { ...base, certificate: { body: bytes(cert.body), signature: bytes(cert.owner_signature) } };
}
export function clone(x: TranscriptInput): TranscriptInput {
  const s = (v: Statement) => ({ body: v.body.slice(), signature: v.signature.slice() });
  return { ceremony: s(x.ceremony), ...(x.certificate ? { certificate: s(x.certificate) } : {}), records: x.records.map(r => ({ closure: s(r.closure), messages: r.messages.map(s) })) };
}
export function verifyInput(doc: Doc, x: TranscriptInput): string {
  const verify = verifierOf(doc);
  return code(() => x.certificate
    ? reshareVerifyTranscript(doc.anchor, x.ceremony, x.certificate, x.records, verify)
    : dkgVerifyTranscript(doc.anchor, x.ceremony, x.records, verify));
}

function at(record: string, field: string, select: (x: TranscriptInput) => Bytes, offset: number, mask: number, expected: string): Probe {
  return { record, field, offset, mask, expected, apply: x => { const b = select(x); b[offset] = b[offset]! ^ mask; } };
}
/** The fixed probe set for one case: every field class of every record kind, first and last message of each round. */
export function probes(c: Doc['cases'][number]): Probe[] {
  const x = inputOf(c), out: Probe[] = [];
  const ceremony = decodeCeremony(x.ceremony.body);
  const cohortSize: Record<number, number> = { 1: ceremony.n, 2: x.certificate ? decodeCertificate(x.certificate.body).n : 0 };
  const cb = x.ceremony.body;
  out.push(
    at('ceremony', 'version', y => y.ceremony.body, 0, 1, 'InvalidEncoding'),
    at('ceremony', 'kind→0', y => y.ceremony.body, 1, cb[1]!, 'InvalidEncoding'),
    at('ceremony', 'ceremony id', y => y.ceremony.body, 2, 1, 'InvalidSignature'),
    at('ceremony', 'network', y => y.ceremony.body, 38, 1, 'InvalidCeremony'),
    at('ceremony', 'last HPKE key byte', y => y.ceremony.body, cb.length - 1, 1, 'InvalidSignature'),
    at('ceremony', 'signature R', y => y.ceremony.signature, 0, 1, 'InvalidSignature'),
    at('ceremony', 'signature S', y => y.ceremony.signature, 63, 1, 'InvalidSignature'),
  );
  if (x.certificate) {
    const len = x.certificate.body.length;
    if (x.certificate.body[len - 1] !== 0 || x.certificate.body[len - 2] !== 0) throw new Error('probe expects a certificate without predecessor fields');
    out.push(
      at('certificate', 'version', y => y.certificate!.body, 0, 1, 'InvalidEncoding'),
      at('certificate', 'network', y => y.certificate!.body, 5, 1, 'InvalidCertificate'),
      at('certificate', 'transcript hash', y => y.certificate!.body, len - 34, 1, 'InvalidSignature'),
      at('certificate', 'signature', y => y.certificate!.signature, 0, 1, 'InvalidSignature'),
    );
  }
  for (const [k, r] of x.records.entries()) {
    const name = `R${k + 1} closure`, closure = (y: TranscriptInput) => y.records[k]!.closure.body;
    out.push(
      at(name, 'version', closure, 0, 1, 'InvalidRound'),
      at(name, 'ceremony digest', closure, 1, 1, 'InvalidRound'),
      at(name, 'round', closure, 33, 1, 'InvalidRound'),
      at(name, 'ordered-list hash', closure, 34, 1, 'InvalidSignature'),
      at(name, 'previous hash', closure, 66, 1, 'InvalidRound'),
      at(name, 'previous hash end', closure, 97, 1, 'InvalidRound'),
      at(name, 'signature', y => y.records[k]!.closure.signature, 0, 1, 'InvalidSignature'),
    );
    for (const m of new Set([0, r.messages.length - 1])) {
      const env = r.messages[m]!.body, label = `R${k + 1} message ${m + 1}`, body = (y: TranscriptInput) => y.records[k]!.messages[m]!.body;
      const flipped = ((env[35]! << 8) | env[36]!) ^ 1;
      out.push(
        at(label, 'version', body, 0, 1, 'InvalidEncoding'),
        at(label, 'ceremony digest', body, 1, 1, 'InvalidRound'),
        at(label, 'round', body, 33, 1, 'InvalidRound'),
        at(label, 'cohort→0', body, 34, env[34]!, 'InvalidIndex'),
        at(label, 'index', body, 36, 1, flipped >= 1 && flipped <= cohortSize[env[34]!]! ? 'InvalidSignature' : 'InvalidIndex'),
        at(label, 'payload length', body, 37, 1, 'InvalidEncoding'),
        at(label, 'payload first byte', body, 41, 1, 'InvalidSignature'),
        at(label, 'payload last byte', body, env.length - 1, 1, 'InvalidSignature'),
        at(label, 'signature R', y => y.records[k]!.messages[m]!.signature, 0, 1, 'InvalidSignature'),
        at(label, 'signature S', y => y.records[k]!.messages[m]!.signature, 63, 1, 'InvalidSignature'),
      );
    }
  }
  return out;
}

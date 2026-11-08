// Test-only one-byte corruption probes over committed chain cases. Each probe flips exactly one byte of one
// signed record (or one receipt/activation field); every probe must make the chain verifier reject the case.
import type { Bytes } from './protocol.ts';
import type { Statement } from './ceremony.ts';
import type { ChainInput } from './chain.ts';

export interface ChainProbe { record: string; field: string; apply: (x: ChainInput) => void }

function at(record: string, field: string, select: (x: ChainInput) => Bytes, offset: number, mask = 1): ChainProbe {
  return { record, field, apply: x => { const b = select(x); b[offset] = b[offset]! ^ mask; } };
}
export function cloneChain(x: ChainInput): ChainInput {
  const s = (v: Statement) => ({ body: v.body.slice(), signature: v.signature.slice() });
  return {
    ceremony: s(x.ceremony), rounds: x.rounds.map(r => ({ closure: s(r.closure), messages: r.messages.map(s) })), ...(x.previous ? { previous: s(x.previous) } : {}),
    certificate: s(x.certificate), receipts: x.receipts.map(r => ({ member: r.member, signature: r.signature.slice() })), activation: s(x.activation),
  };
}
const certificateFields = (name: string, select: (x: ChainInput) => Statement, length: number): ChainProbe[] => [
  at(name, 'version', x => select(x).body, 0),
  at(name, 'network', x => select(x).body, 5),
  at(name, 'transcript hash', x => select(x).body, length - 34),
  at(name, 'option marker', x => select(x).body, length - 1),
  at(name, 'signature R', x => select(x).signature, 0),
  at(name, 'signature S', x => select(x).signature, 63),
];

/** The fixed probe set for one case: every record kind, first and last message of each round, every receipt. */
export function chainProbes(x: ChainInput): ChainProbe[] {
  const out: ChainProbe[] = [
    at('ceremony', 'version', y => y.ceremony.body, 0),
    at('ceremony', 'kind', y => y.ceremony.body, 1, 0x06),
    at('ceremony', 'id', y => y.ceremony.body, 2),
    at('ceremony', 'last HPKE key byte', y => y.ceremony.body, x.ceremony.body.length - 1),
    at('ceremony', 'signature', y => y.ceremony.signature, 0),
    ...certificateFields('certificate', y => y.certificate, x.certificate.body.length),
  ];
  if (x.previous) out.push(...certificateFields('previous certificate', y => y.previous!, x.previous.body.length));
  for (const [k, r] of x.rounds.entries()) {
    const closure = (y: ChainInput) => y.rounds[k]!.closure;
    out.push(
      at(`R${k + 1} closure`, 'ceremony digest', y => closure(y).body, 1),
      at(`R${k + 1} closure`, 'ordered-list hash', y => closure(y).body, 34),
      at(`R${k + 1} closure`, 'previous hash', y => closure(y).body, 97),
      at(`R${k + 1} closure`, 'signature', y => closure(y).signature, 0),
    );
    for (const m of new Set([0, r.messages.length - 1])) {
      const message = (y: ChainInput) => y.rounds[k]!.messages[m]!;
      out.push(
        at(`R${k + 1} message ${m + 1}`, 'payload first byte', y => message(y).body, 41),
        at(`R${k + 1} message ${m + 1}`, 'payload last byte', y => message(y).body, r.messages[m]!.body.length - 1),
        at(`R${k + 1} message ${m + 1}`, 'signature', y => message(y).signature, 0),
      );
    }
  }
  for (const [k] of x.receipts.entries()) {
    out.push(
      at(`receipt ${k + 1}`, 'signature R', y => y.receipts[k]!.signature, 0),
      at(`receipt ${k + 1}`, 'signature S', y => y.receipts[k]!.signature, 63),
      { record: `receipt ${k + 1}`, field: 'member index', apply: y => { y.receipts[k]!.member ^= 1; } },
    );
  }
  out.push(
    at('activation', 'body first byte', y => y.activation.body, 0),
    at('activation', 'body last byte', y => y.activation.body, 31),
    at('activation', 'signature R', y => y.activation.signature, 0),
    at('activation', 'signature S', y => y.activation.signature, 63),
  );
  return out;
}

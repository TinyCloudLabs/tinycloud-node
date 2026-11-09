// Test-only chain construction from SPEC byte layouts: whole generations (ceremony, certificate,
// readiness receipts, activation) built in the scalar domain, separately from the verifier.
// Adversarial variants edit a built step, re-sign the changed record and keep every other record
// consistent with it, so exactly one rule is violated per variant.
import { createHash } from 'node:crypto';
import { R, be, concat, lp, tagged, type Bytes } from './protocol.ts';
import type { RoundRecord, Statement } from './ceremony.ts';
import type { ChainInput } from './chain.ts';
import {
  COHORT_DEALERS, COHORT_RECIPIENTS, G2_BASE, OWNER, at, complaints, deal, did, dkgSetup, lagrange, poly, seal, sign, signedCeremony,
  signedCertificate, times, values, type CertificateSpec, type CeremonySpec, type Draft,
} from './testkit.ts';

const enc = new TextEncoder();
const READY = 'TC-THRESHOLD-V1-READY', ACTIVATE = 'TC-THRESHOLD-V1-ACTIVATE';

export interface Receipt { member: number; signature: Bytes }
export interface Generation {
  spec: CertificateSpec; certificate: Statement & { digest: Bytes };
  t: number; n: number; rekey: bigint; epoch: bigint; genesisT: number;
}
/** The inputs of one `chain_step` case, as decoded statements. */
export interface StepInput {
  ceremony: Statement; digest: Bytes; start: Bytes; records: RoundRecord[]; previous?: Statement;
  certificate: Statement; receipts: Receipt[]; activation: Statement;
}
export interface Step { kind: number; gen: Generation; input: StepInput; rounds: Draft[][] }

export const transcriptOf = (spec: CertificateSpec) => spec.transcript ?? new Uint8Array(32).fill(7);
export function receiptFor(spec: CertificateSpec, certificate: { digest: Bytes }, index: number, signer = did(index), transcript = transcriptOf(spec)): Receipt {
  const share = times(G2_BASE, at(spec.coefficients, index));
  return { member: index, signature: sign(signer, tagged(READY, concat(certificate.digest, transcript, be(BigInt(index), 2), share.toBytes()))) };
}
export const receiptHash = (r: Receipt) => tagged(READY, concat(be(1n, 1), be(BigInt(r.member), 2), lp(r.signature)));
/** The owner's activation statement: the body is the exact 32-byte activation preimage. */
export function activationFor(certificate: { digest: Bytes }, receipts: readonly Receipt[], signer = OWNER): Statement {
  const hashes = receipts.map(receiptHash).sort((a, b) => Buffer.compare(a, b));
  const body = tagged(ACTIVATE, concat(certificate.digest, ...hashes));
  return { body, signature: sign(signer, body) };
}

function generation(spec: CertificateSpec): Generation {
  return {
    spec, certificate: signedCertificate(spec), t: spec.t, n: spec.n,
    rekey: spec.rekey ?? 0n, epoch: spec.epoch ?? 0n, genesisT: spec.genesisT ?? spec.t,
  };
}
interface Ceremony { ceremony: Statement; digest: Bytes; start: Bytes }
function assemble(kind: number, c: Ceremony, rounds: Draft[][], previous: Generation | undefined, spec: (transcript: Bytes) => CertificateSpec): Step {
  const sealed = seal(c.digest, c.start, rounds), gen = generation(spec(sealed.hash));
  const receipts = Array.from({ length: gen.n }, (_, k) => receiptFor(gen.spec, gen.certificate, k + 1));
  const input: StepInput = {
    ceremony: c.ceremony, digest: c.digest, start: c.start, records: sealed.records,
    ...(previous ? { previous: previous.certificate } : {}), certificate: gen.certificate, receipts, activation: activationFor(gen.certificate, receipts),
  };
  return { kind, gen, input, rounds };
}
const summed = (polys: readonly (readonly bigint[])[], t: number) => Array.from({ length: t }, (_, k) => polys.reduce((acc, p) => (acc + p[k]!) % R, 0n));

/** Honest genesis: every member deals, nobody complains. */
export function chainGenesis(label: string, t: number, n: number, spec: Partial<CeremonySpec> = {}): Step {
  const s = dkgSetup(label, t, n, spec);
  return assemble(1, s, s.rounds, undefined, transcript => ({ t, n, coefficients: summed(s.dealers.map(d => d.a), t), transcript }));
}
/** Honest re-key from `prev`: a GJKR DKG under a kind-4 ceremony pinned to it; the certificate names the previous master key. */
export function chainRekey(prev: Generation, label: string, t: number, n: number, spec: Partial<CeremonySpec> = {}): Step {
  const s = dkgSetup(label, t, n, { kind: 4, current: prev.certificate.digest, epoch: prev.epoch + 1n, rekey: prev.rekey + 1n, ...spec });
  return assemble(4, s, s.rounds, prev, transcript => ({
    t, n, rekey: prev.rekey + 1n, epoch: prev.epoch + 1n, genesisT: t, coefficients: summed(s.dealers.map(d => d.a), t), transcript,
    previous: prev.certificate.digest, previousMpk: times(G2_BASE, prev.spec.coefficients[0]!),
  }));
}
/** Honest redistribution from `prev` (kind 2 reshare, 3 refresh): every old member deals g_i with g_i(0) = s_i; D = the first t old members. */
export function chainReshare(prev: Generation, label: string, t2: number, n2: number, kind = 2, spec: Partial<CeremonySpec> = {}): Step {
  const ceremony = signedCeremony({ kind, t: t2, n: n2, current: prev.certificate.digest, epoch: prev.epoch + 1n, rekey: prev.rekey, id: new Uint8Array(createHash('sha256').update(enc.encode(label)).digest()), ...spec });
  const digest = tagged('TC-THRESHOLD-V1-CEREMONY-AUTH', ceremony.body), start = tagged('TC-THRESHOLD-V1-RESHARE-START', digest);
  const old = Array.from({ length: prev.n }, (_, k) => k + 1), recipients = Array.from({ length: n2 }, (_, k) => k + 1);
  const dealings = old.map(i => [at(prev.spec.coefficients, i), ...poly(`${label}/g/${i}`, t2 - 1)]);
  const rounds: Draft[][] = [
    old.map(i => ({ cohort: COHORT_DEALERS, index: i, payload: deal(dealings[i - 1]!.map(c => times(G2_BASE, c)), recipients, 32, i) })),
    recipients.map(j => ({ cohort: COHORT_RECIPIENTS, index: j, payload: complaints([]) })),
    old.map(i => ({ cohort: COHORT_DEALERS, index: i, payload: values([]) })),
  ];
  const selected = old.slice(0, prev.t);
  const coefficients = Array.from({ length: t2 }, (_, k) => selected.reduce((acc, i) => (acc + lagrange(i, selected) * dealings[i - 1]![k]!) % R, 0n));
  return assemble(kind, { ceremony, digest, start }, rounds, prev, transcript => ({
    t: t2, n: n2, rekey: prev.rekey, epoch: prev.epoch + 1n, genesisT: prev.genesisT, coefficients, transcript, previous: prev.certificate.digest,
  }));
}

/** The step with its certificate replaced by one built from `change(spec)`, with receipts and activation regenerated for it. */
export function withCertificate(step: Step, change: (spec: CertificateSpec) => CertificateSpec, signer = OWNER): StepInput {
  const spec = change(step.gen.spec), certificate = signedCertificate(spec, signer);
  const receipts = Array.from({ length: spec.n }, (_, k) => receiptFor(spec, certificate, k + 1));
  return { ...step.input, certificate, receipts, activation: activationFor(certificate, receipts) };
}

/** The decoded statements of a built step, in the shape the chain verifier takes. */
export const chainInput = (i: StepInput): ChainInput => ({
  ceremony: i.ceremony, rounds: i.records, ...(i.previous ? { previous: i.previous } : {}),
  certificate: i.certificate, receipts: i.receipts, activation: i.activation,
});

// Test-only helpers: edit a clone of a committed JSON document and run the real CLI on it through /dev/stdin.
import { readFileSync } from 'node:fs';

/** An exact signed statement as it appears in a document. */
export interface LooseStatement { body: string; signature: string }
export interface LooseCertificate { body: string; owner_signature: string; [k: string]: unknown }
export interface LooseRound { closure: LooseStatement; messages: LooseStatement[] }
/**
 * The members every transcript-style document case may carry, typed without validation: edits navigate by property
 * and the checker re-validates the edited clone, so a member absent from a given document is simply never touched.
 */
export interface LooseCase {
  name: string; operation?: string; error?: string;
  inputs: {
    ceremony: LooseStatement; ceremony_digest: string; initial_transcript: string; members: number; threshold: number; rounds: LooseRound[];
    current_certificate: LooseCertificate; previous_certificate: LooseCertificate; certificate: LooseCertificate;
    receipts: { member: number; signature: string }[]; activation: LooseStatement; quorum: string; [k: string]: unknown;
  };
  outputs: {
    commitments: string[]; public_shares: { member: number; point: string }[]; mpk: string; transcript_hash: string; qual: number[];
    reconstructed: number[]; disqualified: unknown[]; kind: string; epoch: number; rekey: number; genesis_t: number; threshold: number;
    members: number; certificate_digest: string; activation: string; ceremony: unknown; dealers: number[]; [k: string]: unknown;
  };
}
export interface Loose { cases: LooseCase[]; dst: Record<string, unknown>; spec_sections: string[]; [k: string]: unknown }
export const loadJson = (file: string): unknown => JSON.parse(readFileSync(new URL(`../v1/${file}`, import.meta.url), 'utf8'));
export function editDoc(doc: unknown, change: (d: Loose) => void): unknown {
  const view = structuredClone(doc) as Loose;
  change(view);
  return view;
}
/** Flips the low bit of one byte of a lowercase hex string. */
export const hexFlip = (v: unknown, byte = 0) => typeof v === 'string' ? v.slice(0, byte * 2 + 1) + ((parseInt(v[byte * 2 + 1]!, 16) ^ 1).toString(16)) + v.slice(byte * 2 + 2) : '';
const cli = new URL('./cli.ts', import.meta.url).pathname;
export function runCli(doc: unknown) {
  return Bun.spawnSync([process.execPath, cli, '/dev/stdin'], { env: process.env, stdin: Buffer.from(JSON.stringify(doc)), stdout: 'pipe', stderr: 'pipe', timeout: 60000 });
}

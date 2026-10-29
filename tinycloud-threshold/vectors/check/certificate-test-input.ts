import { readFileSync } from 'node:fs';
import { parseCertificateVectors } from './cert-schema.ts';

const input: unknown = JSON.parse(readFileSync(new URL('../v1/cert-core.json', import.meta.url), 'utf8'));
export const certificateFixture = parseCertificateVectors(input);
export function runCertificateCli(value: unknown) {
  return Bun.spawnSync([process.execPath, new URL('./cli.ts', import.meta.url).pathname, '/dev/stdin'], {
    cwd: new URL('.', import.meta.url).pathname, env: process.env,
    stdin: Buffer.from(JSON.stringify(value)), stdout: 'pipe', stderr: 'pipe', timeout: 30000,
  });
}

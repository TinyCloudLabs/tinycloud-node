import { expect, test } from 'bun:test';

const cwd = new URL('.', import.meta.url).pathname;
const cli = new URL('./cli.ts', import.meta.url).pathname;
const input = new URL('../v1/cert-core.json', import.meta.url).pathname;

test('real CLI computes the supplied certificate-core document', () => {
  const result = Bun.spawnSync([process.execPath, cli, input], {
    cwd, env: process.env, stdout: 'pipe', stderr: 'pipe', timeout: 30000,
  });
  expect({ exit: result.exitCode, error: result.stderr.toString() }).toEqual({ exit: 0, error: '' });
});

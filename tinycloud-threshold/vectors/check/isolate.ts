import { afterAll } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';

const created = spawnSync('mktemp', ['-d', '-p', '/var/tmp', 'tc-2219-checker-test.XXXXXXXX'], { encoding: 'utf8' });
if (created.status !== 0) throw new Error('isolated tool home creation failed');
const root = created.stdout.trim();
if (!root.startsWith('/var/tmp/tc-2219-checker-test.')) throw new Error('unexpected tool home');
const homes: Record<string, string> = {
  HOME: 'home', COURIER_HOME: 'courier', TC_HOME: 'tc', TC_CONFIG_DIR: 'tc-config',
  TC_STATE_DIR: 'tc-state', TC_PROFILE_DIR: 'tc-profile', TC_SECRETS_STATE: 'tc-secrets',
  BUN_INSTALL_CACHE_DIR: 'bun-cache', XDG_CONFIG_HOME: 'config', XDG_CACHE_HOME: 'cache',
  XDG_DATA_HOME: 'data', XDG_STATE_HOME: 'state',
};
for (const [key, suffix] of Object.entries(homes)) process.env[key] = `${root}/${suffix}`;
if (Object.keys(homes).some(key => !process.env[key]?.startsWith(`${root}/`))) throw new Error('tool homes not isolated');
writeFileSync(`${root}/created-paths.txt`, `${root}\n`, { mode: 0o600 });
for (const key of Object.keys(homes)) mkdirSync(process.env[key]!, { mode: 0o700 });
afterAll(() => rmSync(root, { recursive: true }));

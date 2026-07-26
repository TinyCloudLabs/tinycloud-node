#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

import {
  buildTc268NodeConfigOverlay,
  buildTc268NodeLaunchSpec,
  expandTc268Matrix,
  readTc268Matrix,
  selectTc268MatrixRow,
  validateTc268BackendSnapshot,
} from './tc268.mjs';

function normalizeBaseUrl(url) {
  return url.replace(/\/$/, '');
}

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (code, signal) => {
      if (signal) {
        reject(new Error(`process exited via signal ${signal}`));
        return;
      }
      resolve(code ?? 1);
    });
  });
}

async function waitForControlManifest(pathname, child, timeoutMs = 120_000) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    try {
      const manifest = JSON.parse(await readFile(pathname, 'utf8'));
      if (manifest?.host && manifest?.port && manifest?.tokenPath) {
        return manifest;
      }
    } catch (error) {
      if (child.exitCode != null) {
        throw new Error(`node process exited before creating ${pathname}`);
      }
    }

    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  throw new Error(`timed out waiting for ${pathname}`);
}

async function readControlSource(controlJsonPath) {
  const manifest = JSON.parse(await readFile(controlJsonPath, 'utf8'));
  const controlUrl = `http://${manifest.host}:${manifest.port}`;
  const controlToken = (await readFile(manifest.tokenPath, 'utf8')).trim();
  return {
    controlUrl: normalizeBaseUrl(controlUrl),
    controlToken,
    manifest,
  };
}

async function validateRowBackend(row, controlJsonPath) {
  const { controlUrl, controlToken } = await readControlSource(controlJsonPath);
  const response = await fetch(`${controlUrl}/v1/config`, {
    headers: {
      Authorization: `Bearer ${controlToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(`failed to read TC-268 control config: ${response.status}`);
  }

  validateTc268BackendSnapshot(await response.json(), row);
  return {
    controlUrl,
    controlToken,
  };
}

async function startNodeForRow(row, rowIndex, env) {
  const workspace = await mkdtemp(path.join(tmpdir(), `tc268-row-${rowIndex}-`));
  const specEnv = {
    ...process.env,
    ...env,
    TC268_STORAGE_DATADIR: path.join(workspace, 'data'),
  };
  await mkdir(specEnv.TC268_STORAGE_DATADIR, { recursive: true });
  const spec = buildTc268NodeLaunchSpec(row, specEnv);
  const overlay = buildTc268NodeConfigOverlay(row, specEnv);
  await writeFile(spec.configPath, overlay, 'utf8');

  const child = spawn(spec.command, spec.args, {
    stdio: 'inherit',
    env: {
      ...process.env,
      ...env,
    },
  });

  const cleanup = async () => {
    if (child.exitCode == null && child.signalCode == null) {
      child.kill('SIGTERM');
      await Promise.race([
        waitForExit(child).catch(() => undefined),
        new Promise((resolve) => setTimeout(resolve, 1000)),
      ]);
      if (child.exitCode == null && child.signalCode == null) {
        child.kill('SIGKILL');
        await Promise.race([
          waitForExit(child).catch(() => undefined),
          new Promise((resolve) => setTimeout(resolve, 1000)),
        ]);
      }
    }
    await rm(workspace, { recursive: true, force: true });
  };

  return {
    child,
    cleanup,
    spec,
  };
}

async function runK6ForRow(script, scriptArgs, rowIndex, controlJsonPath, env) {
  const runnerPath = fileURLToPath(new URL('./tc268-runner.mjs', import.meta.url));
  const child = spawn(process.execPath, [runnerPath, script, ...scriptArgs], {
    stdio: 'inherit',
    env: {
      ...process.env,
      ...env,
      TC268_CONTROL_JSON: controlJsonPath,
      TC268_ROW_INDEX: String(rowIndex),
    },
  });

  return waitForExit(child);
}

async function runRow(row, rowIndex, script, scriptArgs, env) {
  const { child, cleanup, spec } = await startNodeForRow(row, rowIndex, env);
  try {
    await waitForControlManifest(spec.controlJsonPath, child);
    await validateRowBackend(row, spec.controlJsonPath);
    return await runK6ForRow(script, scriptArgs, rowIndex, spec.controlJsonPath, env);
  } finally {
    await cleanup();
  }
}

async function main() {
  const script = process.argv[2];
  if (!script) {
    throw new Error('usage: node tc268-matrix-runner.mjs <k6-script> [k6-args...]');
  }

  const rows = expandTc268Matrix(readTc268Matrix());
  const rowIndexes =
    process.env.TC268_ROW_INDEX == null
      ? rows.map((_, index) => index)
      : [Number.parseInt(process.env.TC268_ROW_INDEX, 10)];

  for (const rowIndex of rowIndexes) {
    const row = selectTc268MatrixRow(rows, rowIndex);
    await runRow(row, rowIndex, script, process.argv.slice(3), process.env);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});

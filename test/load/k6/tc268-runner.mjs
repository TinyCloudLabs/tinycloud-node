#!/usr/bin/env node

import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import process from 'node:process';

import {
  expandTc268Matrix,
  readTc268Matrix,
  selectTc268MatrixRow,
  validateTc268BackendSnapshot,
} from './tc268.mjs';

function normalizeBaseUrl(url) {
  return url.replace(/\/$/, '');
}

async function readControlSource() {
  const controlJsonPath = process.env.TC268_CONTROL_JSON || process.env.TINYCLOUD_CONTROL_JSON;
  if (controlJsonPath) {
    const manifest = JSON.parse(await readFile(controlJsonPath, 'utf8'));
    const controlUrl = `http://${manifest.host}:${manifest.port}`;
    const controlToken = (await readFile(manifest.tokenPath, 'utf8')).trim();
    return {
      controlUrl,
      controlToken,
    };
  }

  const controlUrl = process.env.TC268_CONTROL_URL || process.env.TINYCLOUD_CONTROL_URL;
  const controlToken = process.env.TC268_CONTROL_TOKEN || process.env.TINYCLOUD_CONTROL_TOKEN;

  if (!controlUrl || !controlToken) {
    throw new Error('TC268_CONTROL_JSON or TC268_CONTROL_URL/TC268_CONTROL_TOKEN is required');
  }

  return {
    controlUrl: normalizeBaseUrl(controlUrl),
    controlToken,
  };
}

async function validateRowBackend(row, controlUrl, controlToken) {
  const response = await fetch(`${controlUrl}/v1/config`, {
    headers: {
      Authorization: `Bearer ${controlToken}`,
    },
  });

  if (!response.ok) {
    throw new Error(`failed to read TC-268 control config: ${response.status}`);
  }

  validateTc268BackendSnapshot(await response.json(), row);
}

async function main() {
  const script = process.argv[2];
  if (!script) {
    throw new Error('usage: node tc268-runner.mjs <k6-script> [k6-args...]');
  }

  const matrixRows = expandTc268Matrix(readTc268Matrix());
  const rowIndex = Number.parseInt(process.env.TC268_ROW_INDEX || '0', 10);
  const row = selectTc268MatrixRow(matrixRows, rowIndex);
  const { controlUrl, controlToken } = await readControlSource();
  await validateRowBackend(row, controlUrl, controlToken);

  const k6Bin = process.env.K6_BIN || 'k6';
  const env = {
    ...process.env,
    TC268_CONTROL_URL: controlUrl,
    TC268_CONTROL_TOKEN: controlToken,
  };
  const child = spawn(k6Bin, ['run', script, ...process.argv.slice(3)], {
    stdio: 'inherit',
    env,
  });

  child.on('error', (error) => {
    console.error(error);
    process.exit(1);
  });

  child.on('exit', (code, signal) => {
    if (signal) {
      process.exit(1);
    }
    process.exit(code ?? 1);
  });
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});

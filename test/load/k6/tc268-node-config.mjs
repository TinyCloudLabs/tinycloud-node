#!/usr/bin/env node

import process from 'node:process';

import {
  expandTc268Matrix,
  readTc268Matrix,
  selectTc268MatrixRow,
  buildTc268NodeConfigOverlay,
} from './tc268.mjs';

function parseRowIndex(argv, env) {
  const argIndex = argv.indexOf('--row-index');
  if (argIndex !== -1) {
    const value = argv[argIndex + 1];
    if (value == null) {
      throw new Error('usage: node tc268-node-config.mjs [--row-index <index>]');
    }
    return Number.parseInt(value, 10);
  }

  return Number.parseInt(env.TC268_ROW_INDEX || '0', 10);
}

function main() {
  const rowIndex = parseRowIndex(process.argv.slice(2), process.env);
  const rows = expandTc268Matrix(readTc268Matrix());
  const row = selectTc268MatrixRow(rows, rowIndex);
  process.stdout.write(buildTc268NodeConfigOverlay(row, process.env));
}

try {
  main();
} catch (error) {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
}

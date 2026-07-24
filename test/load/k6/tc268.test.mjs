import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import http from 'node:http';
import { access, chmod, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { tmpdir } from 'node:os';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  buildBootstrapUrls,
  buildInvocationBody,
  buildTc268Options,
  buildTc268NodeConfigOverlay,
  buildTc268NodeLaunchSpec,
  buildTc268SummaryArtifact,
  buildInvocationPlan,
  expectedTc268Backend,
  expandTc268Matrix,
  resolveTc268ExecutionRows,
  resolveTc268StorageDatadir,
  smokeTc268Matrix,
  selectTc268MatrixRow,
  validateTc268BackendSnapshot,
} from './tc268.mjs';

async function startControlServer(snapshot, token) {
  const requests = [];
  const server = http.createServer((request, response) => {
    requests.push({
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
    });

    if (request.url === '/v1/config' && request.headers.authorization === `Bearer ${token}`) {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify(snapshot));
      return;
    }

    response.writeHead(404, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ error: 'not found' }));
  });

  await new Promise((resolve) => {
    server.listen(0, '127.0.0.1', resolve);
  });

  const address = server.address();
  if (!address || typeof address === 'string') {
    throw new Error('failed to bind TC-268 test control server');
  }

  return {
    server,
    requests,
    controlUrl: `http://127.0.0.1:${address.port}`,
  };
}

async function runNodeProcess(script, args, env, cwd) {
  const child = spawn(process.execPath, [script, ...args], {
    cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });

  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    stdout += chunk;
  });
  child.stderr.on('data', (chunk) => {
    stderr += chunk;
  });

  const code = await new Promise((resolve, reject) => {
    child.once('error', reject);
    child.once('exit', (exitCode, signal) => {
      if (signal) {
        reject(new Error(`process exited via signal ${signal}`));
        return;
      }
      resolve(exitCode ?? 1);
    });
  });

  return {
    code,
    stdout,
    stderr,
  };
}

async function createFakeK6Executable(directory) {
  const executablePath = path.join(directory, 'fake-k6.mjs');
  const artifactPath = path.join(directory, 'tc268-json-put-summary.json');
  const invocationPath = path.join(directory, 'k6-invoked.json');
  await writeFile(
    executablePath,
    `#!/usr/bin/env node
import { writeFileSync } from 'node:fs';

const invocationPath = process.env.TC268_FAKE_K6_INVOCATION;
const artifactPath = process.env.TC268_FAKE_K6_ARTIFACT;

if (invocationPath) {
  writeFileSync(
    invocationPath,
    JSON.stringify({ argv: process.argv.slice(2), cwd: process.cwd() }, null, 2),
    'utf8'
  );
}

if (artifactPath) {
  writeFileSync(artifactPath, JSON.stringify({ accepted: true }, null, 2) + '\\n', 'utf8');
}

process.exit(0);
`,
    'utf8'
  );
  await chmod(executablePath, 0o755);
  return {
    executablePath,
    artifactPath,
    invocationPath,
  };
}

test('tc268 bootstrap uses the signer space_id route', () => {
  const urls = buildBootstrapUrls({
    tinycloud: 'http://127.0.0.1:8000',
    signer: 'http://127.0.0.1:3000',
    id: 7,
  });

  assert.equal(urls.spaceId, 'http://127.0.0.1:3000/space_id/7');
  assert.equal(urls.namespaceId, 'http://127.0.0.1:3000/namespace_id/7');
  assert.equal(urls.createSpace, 'http://127.0.0.1:3000/spaces/7');
  assert.equal(urls.peerId, 'http://127.0.0.1:8000/peer/generate/');
});

test('tc268 smoke matrix is deterministic and small', () => {
  const matrix = expandTc268Matrix(smokeTc268Matrix());

  assert.deepEqual(matrix, [
    {
      depth: 0,
      payloadBytes: 1024,
      concurrency: 1,
      database: 'sqlite',
      blockStore: 'local',
    },
  ]);
});

test('tc268 full matrix expansion covers the configured axes', () => {
  const matrix = expandTc268Matrix({
    depths: [0, 1, 4],
    payloadBytes: [1024, 64 * 1024, 8 * 1024 * 1024],
    concurrency: [1, 8, 32],
    database: ['sqlite', 'postgres'],
    blockStore: ['local', 's3'],
  });

  assert.equal(matrix.length, 108);
  assert.deepEqual(matrix[0], {
    depth: 0,
    payloadBytes: 1024,
    concurrency: 1,
    database: 'sqlite',
    blockStore: 'local',
  });
  assert.deepEqual(matrix.at(-1), {
    depth: 4,
    payloadBytes: 8 * 1024 * 1024,
    concurrency: 32,
    database: 'postgres',
    blockStore: 's3',
  });
});

test('tc268 backend expectation matches the selected row', () => {
  const row = {
    depth: 4,
    payloadBytes: 8 * 1024 * 1024,
    concurrency: 32,
    database: 'postgres',
    blockStore: 's3',
  };

  assert.deepEqual(expectedTc268Backend(row), {
    databaseBackendKind: 'postgres',
    blockStoreKind: 's3',
  });
});

test('tc268 backend validation rejects mislabeled live snapshots before load', () => {
  const row = {
    depth: 1,
    payloadBytes: 1024,
    concurrency: 8,
    database: 'sqlite',
    blockStore: 'local',
  };

  const liveConfig = {
    config: {
      storage: {
        database: { backendKind: 'postgres' },
        blocks: { kind: 's3' },
      },
    },
  };

  assert.throws(() => validateTc268BackendSnapshot(liveConfig, row), /backend mismatch/);
});

test('tc268 backend validation accepts the live backend for the row', () => {
  const row = {
    depth: 0,
    payloadBytes: 1024,
    concurrency: 1,
    database: 'sqlite',
    blockStore: 'local',
  };

  const liveConfig = {
    config: {
      storage: {
        database: { backendKind: 'sqlite' },
        blocks: { kind: 'local' },
      },
    },
  };

  assert.deepEqual(validateTc268BackendSnapshot(liveConfig, row), {
    expected: {
      databaseBackendKind: 'sqlite',
      blockStoreKind: 'local',
    },
    actual: {
      databaseBackendKind: 'sqlite',
      blockStoreKind: 'local',
    },
  });
});

test('tc268 runner exits before k6 launches when the live control snapshot is mislabeled', async () => {
  const workspace = await mkdtemp(path.join(tmpdir(), 'tc268-runner-e2e-'));
  const controlToken = 'tc268-test-token';
  const mislabeledSnapshot = {
    config: {
      storage: {
        database: { backendKind: 'postgres' },
        blocks: { kind: 's3' },
      },
    },
  };
  const { server, requests, controlUrl } = await startControlServer(mislabeledSnapshot, controlToken);
  const fakeK6 = await createFakeK6Executable(workspace);
  const controlJsonPath = path.join(workspace, 'runtime', 'control.json');
  const tokenPath = path.join(workspace, 'runtime', 'control.token');
  await mkdir(path.dirname(controlJsonPath), { recursive: true });
  await writeFile(
    controlJsonPath,
    JSON.stringify(
      {
        host: '127.0.0.1',
        port: Number(new URL(controlUrl).port),
        tokenPath,
      },
      null,
      2
    ),
    'utf8'
  );
  await writeFile(tokenPath, `${controlToken}\n`, 'utf8');

  const runnerPath = fileURLToPath(new URL('./tc268-runner.mjs', import.meta.url));
  const scriptPath = fileURLToPath(new URL('./json_put.js', import.meta.url));

  try {
    const result = await runNodeProcess(
      runnerPath,
      [scriptPath],
      {
        ...process.env,
        TC268_CONTROL_JSON: controlJsonPath,
        TC268_ROW_INDEX: '0',
        TC268_SMOKE: '1',
        K6_BIN: fakeK6.executablePath,
        TC268_FAKE_K6_INVOCATION: fakeK6.invocationPath,
        TC268_FAKE_K6_ARTIFACT: fakeK6.artifactPath,
      },
      workspace
    );

    assert.equal(result.code, 1);
    assert.match(result.stderr, /tc268 backend mismatch/);
    assert.equal(requests.length, 1);
    assert.equal(await fileExists(fakeK6.invocationPath), false);
    assert.equal(await fileExists(fakeK6.artifactPath), false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    await rm(workspace, { recursive: true, force: true });
  }
});

async function fileExists(filePath) {
  try {
    await access(filePath);
    return true;
  } catch {
    return false;
  }
}

test('tc268 row selection fails closed when the requested row is out of range', () => {
  const rows = expandTc268Matrix({
    depths: [0, 1],
    payloadBytes: [1024],
    concurrency: [1],
    database: ['sqlite'],
    blockStore: ['local'],
  });

  assert.throws(() => selectTc268MatrixRow(rows, -1), /out of range/);
  assert.throws(() => selectTc268MatrixRow(rows, 2), /out of range/);
  assert.throws(() => selectTc268MatrixRow(rows, Number.NaN), /must be an integer/);
});

test('tc268 execution rows expand to the full matrix unless a row is selected', () => {
  const rows = expandTc268Matrix({
    depths: [0, 4],
    payloadBytes: [1024],
    concurrency: [1],
    database: ['sqlite'],
    blockStore: ['local'],
  });

  assert.deepEqual(resolveTc268ExecutionRows(rows), rows);
  assert.deepEqual(resolveTc268ExecutionRows(rows, 1), [rows[1]]);
});

test('tc268 node config overlays pin the requested storage backends', () => {
  const row = {
    depth: 4,
    payloadBytes: 8 * 1024 * 1024,
    concurrency: 32,
    database: 'sqlite',
    blockStore: 'local',
  };

  const overlay = buildTc268NodeConfigOverlay(row, {
    TC268_STORAGE_DATADIR: '/tmp/tc268-row-4',
  });

  assert.match(overlay, /\[global\.storage\]/);
  assert.match(overlay, /datadir = "\/tmp\/tc268-row-4"/);
  assert.match(overlay, /database = "sqlite:\/tmp\/tc268-row-4\/caps\.db"/);
  assert.match(overlay, /\[global\.storage\.blocks\]/);
  assert.match(overlay, /type = "Local"/);
  assert.match(overlay, /path = "\/tmp\/tc268-row-4\/blocks"/);
});

test('tc268 node config overlays require the live backend inputs for postgres and s3 rows', () => {
  const row = {
    depth: 1,
    payloadBytes: 1024,
    concurrency: 8,
    database: 'postgres',
    blockStore: 's3',
  };

  assert.throws(
    () =>
      buildTc268NodeConfigOverlay(row, {
        TC268_STORAGE_DATADIR: '/tmp/tc268-row-1',
        TC268_POSTGRES_DATABASE_URL: 'postgres://user:password@db.example/share?sslmode=verify-full',
      }),
    /TC268_S3_BUCKET/
  );
});

test('tc268 node launch specs bind each row to a dedicated config and control snapshot path', () => {
  const row = {
    depth: 4,
    payloadBytes: 8 * 1024 * 1024,
    concurrency: 32,
    database: 'postgres',
    blockStore: 's3',
  };

  const spec = buildTc268NodeLaunchSpec(row, {
    TC268_STORAGE_DATADIR: '/tmp/tc268-row-7',
  });

  assert.equal(spec.datadir, '/tmp/tc268-row-7');
  assert.equal(spec.configPath, '/tmp/tc268-row-7/tc268-node.toml');
  assert.equal(spec.controlJsonPath, '/tmp/tc268-row-7/runtime/control.json');
  assert.equal(spec.controlTokenPath, '/tmp/tc268-row-7/runtime/control.token');
  assert.deepEqual(spec.command, 'cargo');
  assert.deepEqual(spec.args, [
    'run',
    '--manifest-path',
    'tinycloud-node-server/Cargo.toml',
    '--',
    'serve',
    '--config',
    '/tmp/tc268-row-7/tc268-node.toml',
  ]);
});

test('tc268 storage datadir resolution is stable per row unless overridden', () => {
  const row = {
    depth: 1,
    payloadBytes: 64 * 1024,
    concurrency: 8,
    database: 'sqlite',
    blockStore: 'local',
  };

  assert.equal(
    resolveTc268StorageDatadir(row, { TEMP: '/var/tmp' }),
    '/var/tmp/tc268-sqlite-local-1-65536-8'
  );
  assert.equal(
    resolveTc268StorageDatadir(row, {
      TC268_STORAGE_DATADIR: '/tmp/tc268-explicit',
      TEMP: '/var/tmp',
    }),
    '/tmp/tc268-explicit'
  );
});

test('tc268 k6 options run warm-up and measured phases with open-loop arrivals', () => {
  const options = buildTc268Options({
    rate: 11,
    warmupSeconds: 20,
    measureSeconds: 60,
    preAllocatedVUs: 64,
    minSamples: 250,
  });

  assert.equal(options.summaryTrendStats.includes('p(50)'), true);
  assert.equal(options.summaryTrendStats.includes('p(95)'), true);
  assert.equal(options.summaryTrendStats.includes('p(99)'), true);
  assert.equal(options.scenarios.warmup.executor, 'constant-arrival-rate');
  assert.equal(options.scenarios.measure.executor, 'constant-arrival-rate');
  assert.equal(options.scenarios.warmup.rate, 11);
  assert.equal(options.scenarios.measure.rate, 11);
  assert.equal(options.scenarios.warmup.preAllocatedVUs, 64);
  assert.equal(options.scenarios.measure.preAllocatedVUs, 64);
  assert.equal(options.scenarios.warmup.maxVUs > 64, true);
  assert.equal(options.scenarios.measure.maxVUs, options.scenarios.warmup.maxVUs);
  assert.equal(options.scenarios.measure.startTime, '20s');
  assert.equal(options.scenarios.measure.duration, '60s');
  assert.equal(options.minSamples, 250);
  assert.equal(options.thresholds.tc268_invoke_samples[0].threshold, 'count>=250');
  assert.equal(options.thresholds.tc268_invoke_samples[0].abortOnFail, true);
  assert.equal(options.scenarios.warmup.maxVUs, 256);
});

test('tc268 k6 options accept an explicit VU ceiling', () => {
  const options = buildTc268Options({
    rate: 11,
    warmupSeconds: 20,
    measureSeconds: 60,
    preAllocatedVUs: 64,
    maxVUs: 192,
    minSamples: 250,
  });

  assert.equal(options.scenarios.warmup.maxVUs, 192);
  assert.equal(options.scenarios.measure.maxVUs, 192);
});

test('tc268 summary artifacts are machine-readable and gate on minimum samples', () => {
  const artifact = buildTc268SummaryArtifact(
    {
      metrics: {
        tc268_invoke_samples: { values: { count: 300 } },
        tc268_invoke_errors: { values: { count: 2 } },
        tc268_invoke_latency: {
          values: {
            'p(50)': 12.5,
            'p(95)': 28.25,
            'p(99)': 41.75,
          },
        },
        checks: { values: { passes: 298, fails: 2, rate: 0.9933333333333333 } },
      },
    },
    {
      rate: 10,
      maxVUs: 192,
      warmupSeconds: 20,
      measureSeconds: 60,
      minSamples: 250,
      depth: 4,
      payloadBytes: 8 * 1024 * 1024,
      concurrency: 32,
      database: 'postgres',
      blockStore: 's3',
    }
  );

  assert.equal(artifact.meetsMinSamples, true);
  assert.equal(artifact.samples, 300);
  assert.equal(artifact.errors, 2);
  assert.equal(artifact.p50Ms, 12.5);
  assert.equal(artifact.p95Ms, 28.25);
  assert.equal(artifact.p99Ms, 41.75);
  assert.equal(artifact.throughputRps, 5);
  assert.equal(artifact.checkPassRate, 0.9933333333333333);
  assert.equal(artifact.rate, 10);
  assert.equal(artifact.maxVUs, 192);
  assert.equal(artifact.matrix.depth, 4);
  assert.equal(artifact.matrix.payloadBytes, 8 * 1024 * 1024);
  assert.equal(artifact.matrix.database, 'postgres');
});

test('tc268 invocation plans are unique and prepared ahead of the hot path', () => {
  const plan = buildInvocationPlan({
    count: 4,
    namespaceId: 3,
    action: 'put',
    depth: 1,
    payloadBytes: 1024,
  });

  assert.equal(plan.length, 4);
  assert.equal(new Set(plan.map((entry) => entry.invocationName)).size, 4);
  assert.deepEqual(plan[0], {
    invocationName: 'tc268-3-depth-1-put-0',
    namespaceId: 3,
    action: 'put',
    depth: 1,
    payloadBytes: 1024,
    preparedInSetup: true,
  });
});

test('tc268 invocation bodies are unique per seed and exact-length', () => {
  const bodyA = buildInvocationBody({
    action: 'put',
    payloadBytes: 8 * 1024 * 1024,
    seed: 'tc268-7-depth-4-put-0',
  });
  const bodyB = buildInvocationBody({
    action: 'put',
    payloadBytes: 8 * 1024 * 1024,
    seed: 'tc268-7-depth-4-put-1',
  });

  assert.equal(bodyA.length, 8 * 1024 * 1024);
  assert.equal(bodyB.length, 8 * 1024 * 1024);
  assert.notEqual(bodyA, bodyB);
  assert.match(bodyA.slice(0, 32), /^tc268:tc268-7-depth-4-put-0\|/);
  assert.match(bodyB.slice(0, 32), /^tc268:tc268-7-depth-4-put-1\|/);
});

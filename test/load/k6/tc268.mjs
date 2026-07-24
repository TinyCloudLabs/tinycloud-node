import path from 'node:path';

export function buildBootstrapUrls({ tinycloud, signer, id }) {
  const normalizedTinycloud = tinycloud.replace(/\/$/, '');
  const normalizedSigner = signer.replace(/\/$/, '');
  const suffix = encodeURIComponent(String(id));

  return {
    tinycloud: normalizedTinycloud,
    signer: normalizedSigner,
    id,
    peerId: `${normalizedTinycloud}/peer/generate/`,
    spaceId: `${normalizedSigner}/space_id/${suffix}`,
    namespaceId: `${normalizedSigner}/namespace_id/${suffix}`,
    createSpace: `${normalizedSigner}/spaces/${suffix}`,
    createSession: `${normalizedSigner}/sessions/${suffix}/create`,
    invokeSession: `${normalizedSigner}/sessions/${suffix}/invoke`,
  };
}

export function parseDelimitedList(value, fallback, parser = (item) => item) {
  if (value == null || value === '') {
    return fallback.slice();
  }

  return value
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean)
    .map(parser);
}

export function smokeTc268Matrix() {
  return {
    depths: [0],
    payloadBytes: [1024],
    concurrency: [1],
    database: ['sqlite'],
    blockStore: ['local'],
  };
}

export function fullTc268Matrix() {
  return {
    depths: [0, 1, 4],
    payloadBytes: [1024, 64 * 1024, 8 * 1024 * 1024],
    concurrency: [1, 8, 32],
    database: ['sqlite', 'postgres'],
    blockStore: ['local', 's3'],
  };
}

export function readTc268Matrix(env = globalThis.__ENV ?? {}) {
  const smoke = env.TC268_SMOKE === '1' || env.TC268_SMOKE === 'true';
  const defaults = smoke ? smokeTc268Matrix() : fullTc268Matrix();

  return {
    depths: parseDelimitedList(env.TC268_DEPTHS, defaults.depths, (value) =>
      Number.parseInt(value, 10)
    ),
    payloadBytes: parseDelimitedList(env.TC268_PAYLOAD_BYTES, defaults.payloadBytes, (value) =>
      Number.parseInt(value, 10)
    ),
    concurrency: parseDelimitedList(env.TC268_CONCURRENCY, defaults.concurrency, (value) =>
      Number.parseInt(value, 10)
    ),
    database: parseDelimitedList(env.TC268_DATABASES, defaults.database),
    blockStore: parseDelimitedList(env.TC268_BLOCK_STORES, defaults.blockStore),
  };
}

export function expandTc268Matrix(matrix) {
  const rows = [];
  for (const depth of matrix.depths) {
    for (const payloadBytes of matrix.payloadBytes) {
      for (const concurrency of matrix.concurrency) {
        for (const database of matrix.database) {
          for (const blockStore of matrix.blockStore) {
            rows.push({
              depth,
              payloadBytes,
              concurrency,
              database,
              blockStore,
            });
          }
        }
      }
    }
  }
  return rows;
}

export function selectTc268MatrixRow(rows, index) {
  if (!Number.isInteger(index)) {
    throw new RangeError(`tc268 matrix row index must be an integer, got ${index}`);
  }
  if (index < 0 || index >= rows.length) {
    throw new RangeError(`tc268 matrix row index ${index} is out of range for ${rows.length} rows`);
  }
  return rows[index];
}

export function resolveTc268ExecutionRows(rows, index) {
  if (index == null) {
    return rows.slice();
  }

  return [selectTc268MatrixRow(rows, index)];
}

function tomlString(value) {
  return JSON.stringify(String(value));
}

export function buildTc268NodeConfigOverlay(row, env = globalThis.__ENV ?? process.env) {
  const datadir = resolveTc268StorageDatadir(row, env);

  const lines = [
    '[global.storage]',
    `datadir = ${tomlString(datadir)}`,
  ];

  if (row.database === 'sqlite') {
    lines.push(`database = ${tomlString(`sqlite:${path.join(datadir, 'caps.db')}`)}`);
  } else if (row.database === 'postgres') {
    const databaseUrl = env.TC268_POSTGRES_DATABASE_URL;
    if (!databaseUrl) {
      throw new Error('TC268_POSTGRES_DATABASE_URL is required for postgres matrix rows');
    }
    lines.push(`database = ${tomlString(databaseUrl)}`);
  } else {
    throw new Error(`unsupported TC-268 database backend: ${row.database}`);
  }

  lines.push('', '[global.storage.blocks]');
  if (row.blockStore === 'local') {
    lines.push('type = "Local"', `path = ${tomlString(path.join(datadir, 'blocks'))}`);
  } else if (row.blockStore === 's3') {
    const bucket = env.TC268_S3_BUCKET;
    if (!bucket) {
      throw new Error('TC268_S3_BUCKET is required for s3 matrix rows');
    }
    lines.push('type = "S3"', `bucket = ${tomlString(bucket)}`);
    if (env.TC268_S3_ENDPOINT) {
      lines.push(`endpoint = ${tomlString(env.TC268_S3_ENDPOINT)}`);
    }
  } else {
    throw new Error(`unsupported TC-268 block store backend: ${row.blockStore}`);
  }

  return `${lines.join('\n')}\n`;
}

export function resolveTc268StorageDatadir(row, env = globalThis.__ENV ?? process.env) {
  return env.TC268_STORAGE_DATADIR || env.TC268_NODE_DATADIR || path.join(
    env.TEMP || env.TMPDIR || '/tmp',
    `tc268-${row.database}-${row.blockStore}-${row.depth}-${row.payloadBytes}-${row.concurrency}`
  );
}

export function buildTc268NodeLaunchSpec(row, env = globalThis.__ENV ?? process.env) {
  const datadir = resolveTc268StorageDatadir(row, env);
  const configPath = path.join(datadir, 'tc268-node.toml');

  return {
    datadir,
    configPath,
    controlJsonPath: path.join(datadir, 'runtime', 'control.json'),
    controlTokenPath: path.join(datadir, 'runtime', 'control.token'),
    command: 'cargo',
    args: [
      'run',
      '--manifest-path',
      'tinycloud-node-server/Cargo.toml',
      '--',
      'serve',
      '--config',
      configPath,
    ],
  };
}

export function expectedTc268Backend(row) {
  return {
    databaseBackendKind: row.database,
    blockStoreKind: row.blockStore,
  };
}

export function validateTc268BackendSnapshot(snapshot, row) {
  const expected = expectedTc268Backend(row);
  const actual = {
    databaseBackendKind: snapshot?.config?.storage?.database?.backendKind,
    blockStoreKind: snapshot?.config?.storage?.blocks?.kind,
  };

  if (
    actual.databaseBackendKind !== expected.databaseBackendKind ||
    actual.blockStoreKind !== expected.blockStoreKind
  ) {
    throw new Error(
      `tc268 backend mismatch for depth=${row.depth} payloadBytes=${row.payloadBytes} concurrency=${row.concurrency}: ` +
        `expected database=${expected.databaseBackendKind} blockStore=${expected.blockStoreKind}, ` +
        `got database=${actual.databaseBackendKind ?? 'unknown'} blockStore=${actual.blockStoreKind ?? 'unknown'}`
    );
  }

  return {
    expected,
    actual,
  };
}

export function buildTc268Options({
  rate,
  warmupSeconds,
  measureSeconds,
  preAllocatedVUs,
  maxVUs,
  minSamples = 0,
}) {
  const resolvedMaxVUs =
    maxVUs ?? Math.max(preAllocatedVUs * 4, preAllocatedVUs + rate * 4);
  return {
    scenarios: {
      warmup: {
        executor: 'constant-arrival-rate',
        rate,
        timeUnit: '1s',
        duration: `${warmupSeconds}s`,
        preAllocatedVUs,
        maxVUs: resolvedMaxVUs,
        maxDuration: `${warmupSeconds + measureSeconds}s`,
      },
      measure: {
        executor: 'constant-arrival-rate',
        rate,
        timeUnit: '1s',
        duration: `${measureSeconds}s`,
        startTime: `${warmupSeconds}s`,
        preAllocatedVUs,
        maxVUs: resolvedMaxVUs,
        maxDuration: `${warmupSeconds + measureSeconds}s`,
      },
    },
    summaryTrendStats: ['min', 'med', 'p(50)', 'p(95)', 'p(99)'],
    thresholds: {
      tc268_invoke_samples: [
        {
          threshold: `count>=${minSamples}`,
          abortOnFail: true,
        },
      ],
    },
    minSamples,
  };
}

export function buildInvocationPlan({
  count,
  namespaceId,
  action,
  depth,
  payloadBytes,
}) {
  const plan = [];
  for (let index = 0; index < count; index += 1) {
    plan.push({
      invocationName: `tc268-${namespaceId}-depth-${depth}-${action}-${index}`,
      namespaceId,
      action,
      depth,
      payloadBytes,
      preparedInSetup: true,
    });
  }
  return plan;
}

export function buildInvocationBody({ action, payloadBytes, seed = 0 }) {
  if (action !== 'put') {
    return '';
  }

  const seedText = String(seed);
  const prefix = `tc268:${seedText}|`;
  if (payloadBytes <= prefix.length) {
    return prefix.slice(0, payloadBytes);
  }

  const char = String.fromCharCode(97 + (seedText.length % 26));
  return prefix + char.repeat(payloadBytes - prefix.length);
}

export function buildPreparedInvocationBody(entry) {
  return buildInvocationBody({
    action: entry.action,
    payloadBytes: entry.payloadBytes,
    seed: entry.bodySeed ?? entry.invocationName,
  });
}

export function buildTc268SummaryArtifact(summary, config) {
  const samples = summary.metrics?.tc268_invoke_samples?.values?.count ?? 0;
  const errors = summary.metrics?.tc268_invoke_errors?.values?.count ?? 0;
  const latency = summary.metrics?.tc268_invoke_latency?.values ?? {};
  const checks = summary.metrics?.checks?.values ?? {};

  return {
    matrix: {
      depth: config.depth,
      payloadBytes: config.payloadBytes,
      concurrency: config.concurrency,
      database: config.database,
      blockStore: config.blockStore,
    },
    rate: config.rate,
    maxVUs: config.maxVUs,
    warmupSeconds: config.warmupSeconds,
    measureSeconds: config.measureSeconds,
    minSamples: config.minSamples,
    samples,
    meetsMinSamples: samples >= config.minSamples,
    errors,
    checkPasses: checks.passes ?? 0,
    checkFails: checks.fails ?? 0,
    checkPassRate: checks.rate ?? 0,
    p50Ms: latency['p(50)'] ?? latency.med ?? null,
    p95Ms: latency['p(95)'] ?? null,
    p99Ms: latency['p(99)'] ?? null,
    throughputRps: config.measureSeconds > 0 ? samples / config.measureSeconds : null,
  };
}

export function handleTc268Summary(summary, config, filename = 'tc268-baseline.json') {
  const artifact = buildTc268SummaryArtifact(summary, config);
  return {
    [filename]: `${JSON.stringify(artifact, null, 2)}\n`,
  };
}

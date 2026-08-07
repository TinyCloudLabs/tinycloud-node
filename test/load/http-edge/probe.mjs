#!/usr/bin/env node
// HTTP edge protocol probe: measures ALPN negotiation, HTTP/1.1 vs HTTP/2
// connection reuse, and latency against a single public, read-only endpoint.
//
// This tool never sends or logs Authorization headers, cookies, bodies, or
// credentials. It only ever issues unauthenticated GET requests against the
// `/healthz` path, which is the sole endpoint on the allowlist below. Output
// is a single JSON document written atomically at the end of the run; the
// process fails closed (non-zero exit, explicit `ok: false`) on any missing
// ALPN, protocol/status mismatch, incomplete samples, connection-accounting
// ambiguity, timeout, or truncation.

import { parseArgs } from 'node:util';
import { performance } from 'node:perf_hooks';
import https from 'node:https';
import http2 from 'node:http2';
import tls from 'node:tls';
import fs from 'node:fs';
import path from 'node:path';
import { randomBytes } from 'node:crypto';

// Only paths on this allowlist may be probed. `/healthz` is the only
// unauthenticated, side-effect-free GET endpoint exposed by tinycloud-node
// (see routes/mod.rs); every other route either requires an Authorization
// header or mutates state, and is out of scope for this diagnostic tool.
const SAFE_PATH_ALLOWLIST = new Set(['/healthz']);

const LIMITS = {
  maxConcurrency: 64,
  maxConcurrencyLevels: 6,
  maxRounds: 10,
  maxWarmupRounds: 3,
  maxResponseBytes: 1_048_576,
  maxRequestTimeoutMs: 30_000,
  maxConnectionLifetimeMs: 300_000,
};

const DEFAULTS = {
  concurrency: '1,8,32',
  rounds: 3,
  warmupRounds: 1,
  maxResponseBytes: 65_536,
  requestTimeoutMs: 5_000,
  connectionMaxLifetimeMs: 60_000,
  expectedStatus: 200,
};

class ProbeError extends Error {}

function parseCliArgs(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      origin: { type: 'string' },
      path: { type: 'string' },
      concurrency: { type: 'string', default: DEFAULTS.concurrency },
      rounds: { type: 'string', default: String(DEFAULTS.rounds) },
      'warmup-rounds': { type: 'string', default: String(DEFAULTS.warmupRounds) },
      'max-response-bytes': { type: 'string', default: String(DEFAULTS.maxResponseBytes) },
      'request-timeout-ms': { type: 'string', default: String(DEFAULTS.requestTimeoutMs) },
      'connection-max-lifetime-ms': { type: 'string', default: String(DEFAULTS.connectionMaxLifetimeMs) },
      'expected-status': { type: 'string', default: String(DEFAULTS.expectedStatus) },
      ca: { type: 'string' },
      out: { type: 'string' },
      help: { type: 'boolean', default: false },
    },
    allowPositionals: false,
    strict: true,
  });
  return values;
}

function requireHttpsOrigin(rawOrigin) {
  if (!rawOrigin) {
    throw new ProbeError('--origin is required and must be an https:// origin');
  }
  let url;
  try {
    url = new URL(rawOrigin);
  } catch {
    throw new ProbeError(`--origin is not a valid URL`);
  }
  if (url.protocol !== 'https:') {
    throw new ProbeError('--origin must use https:// (plaintext HTTP is not permitted)');
  }
  if (url.username || url.password) {
    throw new ProbeError('--origin must not contain credentials');
  }
  if (url.pathname !== '/' || url.search || url.hash) {
    throw new ProbeError('--origin must be a bare scheme+host[:port], use --path for the request path');
  }
  return `${url.protocol}//${url.host}`;
}

function requireSafePath(rawPath) {
  if (!rawPath || !SAFE_PATH_ALLOWLIST.has(rawPath)) {
    throw new ProbeError(
      `--path must be one of the allowlisted safe public paths: ${[...SAFE_PATH_ALLOWLIST].join(', ')}`,
    );
  }
  return rawPath;
}

// Requires a canonical decimal integer (no leading/trailing junk, no
// fractional or hex/octal forms) so malformed values like "1junk" or "5x"
// are rejected outright rather than silently truncated by parseInt.
const CANONICAL_INT = /^-?(0|[1-9]\d*)$/;

function boundedInt(name, raw, { min, max }) {
  const trimmed = typeof raw === 'string' ? raw.trim() : '';
  if (!CANONICAL_INT.test(trimmed)) {
    throw new ProbeError(`--${name} must be an integer between ${min} and ${max}`);
  }
  const n = Number(trimmed);
  if (!Number.isSafeInteger(n) || n < min || n > max) {
    throw new ProbeError(`--${name} must be an integer between ${min} and ${max}`);
  }
  return n;
}

function parseConcurrencyLevels(raw) {
  const parts = raw
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (parts.length === 0) {
    throw new ProbeError('--concurrency must list at least one level');
  }
  if (parts.length > LIMITS.maxConcurrencyLevels) {
    throw new ProbeError(`--concurrency must list at most ${LIMITS.maxConcurrencyLevels} levels`);
  }
  const levels = parts.map((s) => boundedInt('concurrency', s, { min: 1, max: LIMITS.maxConcurrency }));
  if (new Set(levels).size !== levels.length) {
    throw new ProbeError('--concurrency must not contain duplicate levels');
  }
  return levels;
}

function buildConfig(values) {
  const origin = requireHttpsOrigin(values.origin);
  const path = requireSafePath(values.path);
  const concurrencyLevels = parseConcurrencyLevels(values.concurrency);
  const rounds = boundedInt('rounds', values.rounds, { min: 1, max: LIMITS.maxRounds });
  const warmupRounds = boundedInt('warmup-rounds', values['warmup-rounds'], {
    min: 0,
    max: LIMITS.maxWarmupRounds,
  });
  const maxResponseBytes = boundedInt('max-response-bytes', values['max-response-bytes'], {
    min: 1,
    max: LIMITS.maxResponseBytes,
  });
  const requestTimeoutMs = boundedInt('request-timeout-ms', values['request-timeout-ms'], {
    min: 1,
    max: LIMITS.maxRequestTimeoutMs,
  });
  const connectionMaxLifetimeMs = boundedInt(
    'connection-max-lifetime-ms',
    values['connection-max-lifetime-ms'],
    { min: 1_000, max: LIMITS.maxConnectionLifetimeMs },
  );
  const expectedStatus = boundedInt('expected-status', values['expected-status'], { min: 100, max: 599 });
  let ca;
  if (values.ca) {
    ca = fs.readFileSync(values.ca);
  }
  return {
    origin,
    path,
    concurrencyLevels,
    rounds,
    warmupRounds,
    maxResponseBytes,
    requestTimeoutMs,
    connectionMaxLifetimeMs,
    expectedStatus,
    ca,
    out: values.out,
  };
}

function percentile(sortedValues, p) {
  if (sortedValues.length === 0) return null;
  const idx = Math.min(sortedValues.length - 1, Math.ceil((p / 100) * sortedValues.length) - 1);
  return sortedValues[Math.max(0, idx)];
}

function summarizeLatency(samples) {
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    samples: sorted.length,
    min: sorted.length ? sorted[0] : null,
    max: sorted.length ? sorted[sorted.length - 1] : null,
    p50: percentile(sorted, 50),
    p95: percentile(sorted, 95),
    p99: percentile(sorted, 99),
  };
}

// Only a fixed, non-sensitive classification of an error is ever recorded.
// Raw error messages are never included since Node error messages can echo
// back connection options.
function classifyError(err) {
  const code = typeof err?.code === 'string' ? err.code : 'ERR_UNKNOWN';
  if (err?.probeTimeout) return { code: 'ERR_PROBE_TIMEOUT', kind: 'timeout' };
  if (err?.probeTruncated) return { code: 'ERR_PROBE_TRUNCATED', kind: 'truncated' };
  if (code.startsWith('ERR_TLS') || code.includes('CERT')) return { code, kind: 'tls' };
  if (code === 'ECONNRESET' || code === 'ECONNREFUSED' || code === 'ETIMEDOUT') {
    return { code, kind: 'network' };
  }
  return { code, kind: 'other' };
}

function certSummary(socket) {
  const cert = typeof socket.getPeerCertificate === 'function' ? socket.getPeerCertificate() : null;
  if (!cert || !cert.subject) return { fingerprint256: null, subject: null };
  const subject = Object.entries(cert.subject)
    .map(([k, v]) => `${k}=${v}`)
    .join(', ');
  return { fingerprint256: cert.fingerprint256 ?? null, subject };
}

// Counts socket creation directly by wrapping the Agent's own connection
// factory rather than inferring counts from request completion.
class CountingHttpsAgent extends https.Agent {
  constructor(opts) {
    super(opts);
    this.socketsCreated = 0;
    this.handshakes = [];
    // Every socket's connection info is retained (not just the most recent)
    // so a mismatched or missing ALPN on an earlier socket cannot be lost.
    this.connectionInfos = [];
  }

  createConnection(options, callback) {
    const start = performance.now();
    const socket = super.createConnection({ ...options, ALPNProtocols: ['http/1.1'] }, callback);
    this.socketsCreated += 1;
    const timing = {};
    socket.once('lookup', () => {
      timing.dnsMs = performance.now() - start;
    });
    socket.once('connect', () => {
      timing.tcpMs = performance.now() - start;
    });
    socket.once('secureConnect', () => {
      timing.tlsMs = performance.now() - start;
      this.handshakes.push({ ...timing, totalMs: timing.tlsMs });
      this.connectionInfos.push({
        alpnProtocol: socket.alpnProtocol,
        remoteAddress: socket.remoteAddress,
        remotePort: socket.remotePort,
        ...certSummary(socket),
      });
    });
    return socket;
  }
}

function connectHttp2Session(origin, ca) {
  const counters = { connectionsCreated: 0, handshakes: [], connectionInfos: [] };
  const url = new URL(origin);
  const session = http2.connect(origin, {
    ca,
    createConnection: (authority, options) => {
      const start = performance.now();
      const socket = tls.connect({
        host: url.hostname,
        port: Number(url.port) || 443,
        servername: url.hostname,
        ALPNProtocols: ['h2'],
        ca,
        ...options,
      });
      counters.connectionsCreated += 1;
      const timing = {};
      socket.once('lookup', () => {
        timing.dnsMs = performance.now() - start;
      });
      socket.once('connect', () => {
        timing.tcpMs = performance.now() - start;
      });
      socket.once('secureConnect', () => {
        timing.tlsMs = performance.now() - start;
        counters.handshakes.push({ ...timing, totalMs: timing.tlsMs });
        counters.connectionInfos.push({
          alpnProtocol: socket.alpnProtocol,
          remoteAddress: socket.remoteAddress,
          remotePort: socket.remotePort,
          ...certSummary(socket),
        });
      });
      return socket;
    },
  });
  return { session, counters };
}

function doHttp1Request(agent, origin, requestPath, { timeoutMs, maxResponseBytes, expectedStatus }) {
  return new Promise((resolve) => {
    const start = performance.now();
    let bytes = 0;
    let settled = false;
    // `finish` resolves exactly once and is called directly from the
    // timeout/truncation branches instead of being deferred to a later
    // 'error' event, which never fires once the request/response has
    // already been destroyed with `settled` set — that gap previously left
    // the returned promise (and Promise.all in the caller) hanging forever.
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const req = https.request(
      `${origin}${requestPath}`,
      { agent, method: 'GET', timeout: timeoutMs },
      (res) => {
        res.on('data', (chunk) => {
          bytes += chunk.length;
          if (bytes > maxResponseBytes) {
            const err = new Error('response too large');
            err.probeTruncated = true;
            finish({ ok: false, error: classifyError(err) });
            res.destroy();
          }
        });
        res.on('end', () => {
          finish({
            ok: true,
            protocol: `http/${res.httpVersion}`,
            status: res.statusCode,
            statusOk: res.statusCode === expectedStatus,
            durationMs: performance.now() - start,
          });
        });
        res.on('error', (err) => {
          finish({ ok: false, error: classifyError(err) });
        });
      },
    );
    req.on('timeout', () => {
      const err = new Error('request timeout');
      err.probeTimeout = true;
      finish({ ok: false, error: classifyError(err) });
      req.destroy();
    });
    req.on('error', (err) => {
      finish({ ok: false, error: classifyError(err) });
    });
    req.end();
  });
}

function doHttp2Request(session, requestPath, { timeoutMs, maxResponseBytes, expectedStatus }) {
  return new Promise((resolve) => {
    const start = performance.now();
    let bytes = 0;
    let settled = false;
    let status = null;
    let streamId = null;
    const finish = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };
    const stream = session.request({ ':method': 'GET', ':path': requestPath });
    streamId = stream.id ?? null;
    stream.setTimeout(timeoutMs, () => {
      const err = new Error('stream timeout');
      err.probeTimeout = true;
      finish({ ok: false, error: classifyError(err), streamId: stream.id ?? streamId });
      stream.destroy(err);
    });
    stream.on('response', (headers) => {
      status = headers[':status'];
      streamId = stream.id ?? streamId;
    });
    stream.on('data', (chunk) => {
      bytes += chunk.length;
      if (bytes > maxResponseBytes) {
        const err = new Error('response too large');
        err.probeTruncated = true;
        finish({ ok: false, error: classifyError(err), streamId: stream.id ?? streamId });
        stream.close(http2.constants.NGHTTP2_CANCEL);
      }
    });
    stream.on('end', () => {
      finish({
        ok: true,
        protocol: 'h2',
        status,
        statusOk: status === expectedStatus,
        streamId,
        durationMs: performance.now() - start,
      });
    });
    stream.on('error', (err) => {
      finish({ ok: false, error: classifyError(err), streamId: stream.id ?? streamId });
    });
    stream.end();
  });
}

async function runRound({ protocol, concurrency, isWarmup, runner, config }) {
  const outcomes = await Promise.all(Array.from({ length: concurrency }, () => runner()));
  const succeeded = outcomes.filter((o) => o.ok && o.statusOk);
  const mismatched = outcomes.filter((o) => o.ok && !o.statusOk);
  const failed = outcomes.filter((o) => !o.ok);
  const timedOut = failed.filter((o) => o.error?.kind === 'timeout');
  const truncated = failed.filter((o) => o.error?.kind === 'truncated');
  // Compare against the protocol string each request path actually reports
  // (doHttp1Request reports "http/<version>", doHttp2Request always "h2"),
  // not against the round's short 'h1'/'h2' label, which would never match.
  const expectedProtocol = protocol === 'h1' ? 'http/1.1' : 'h2';
  const protocolMismatch = outcomes.filter((o) => o.ok && o.protocol !== expectedProtocol);
  return {
    protocol,
    concurrency,
    isWarmup,
    attempted: concurrency,
    succeeded: succeeded.length,
    statusMismatched: mismatched.length,
    failed: failed.length,
    timedOut: timedOut.length,
    truncated: truncated.length,
    protocolMismatched: protocolMismatch.length,
    latencies: isWarmup ? [] : succeeded.map((o) => o.durationMs),
    streamIds: protocol === 'h2' ? succeeded.map((o) => o.streamId).filter((id) => id !== null) : null,
    errors: failed.map((o) => o.error),
  };
}

function buildInterleavedPlan(rounds, warmupRounds) {
  const plan = [];
  const totalRounds = warmupRounds + rounds;
  for (let i = 0; i < totalRounds; i += 1) {
    const isWarmup = i < warmupRounds;
    plan.push({ protocol: 'h1', isWarmup, forced: true });
    plan.push({ protocol: 'h2', isWarmup, forced: true });
  }
  return plan;
}

function aggregateConcurrencyResults(roundResults, concurrency, protocol) {
  const measured = roundResults.filter(
    (r) => r.concurrency === concurrency && r.protocol === protocol && !r.isWarmup,
  );
  const latencies = measured.flatMap((r) => r.latencies);
  const totalAttempted = measured.reduce((a, r) => a + r.attempted, 0);
  const totalSucceeded = measured.reduce((a, r) => a + r.succeeded, 0);
  const totalFailed = measured.reduce((a, r) => a + r.failed, 0);
  const totalTimedOut = measured.reduce((a, r) => a + r.timedOut, 0);
  const totalTruncated = measured.reduce((a, r) => a + r.truncated, 0);
  const totalStatusMismatched = measured.reduce((a, r) => a + r.statusMismatched, 0);
  const totalProtocolMismatched = measured.reduce((a, r) => a + r.protocolMismatched, 0);
  const streamIds = protocol === 'h2' ? measured.flatMap((r) => r.streamIds ?? []) : null;
  const errors = measured.flatMap((r) => r.errors);
  return {
    protocol,
    concurrency,
    requests: {
      attempted: totalAttempted,
      succeeded: totalSucceeded,
      failed: totalFailed,
      timedOut: totalTimedOut,
      truncated: totalTruncated,
      statusMismatched: totalStatusMismatched,
      protocolMismatched: totalProtocolMismatched,
    },
    streamIds,
    latencyMs: summarizeLatency(latencies),
    errors,
  };
}

function verdictFor(entry, config, h2ConnectionsCreated, h2Settings) {
  const reasons = [];
  const { requests } = entry;
  if (requests.attempted === 0 || requests.succeeded !== requests.attempted) {
    reasons.push('incomplete samples: not all attempted requests succeeded');
  }
  if (requests.timedOut > 0) reasons.push('one or more requests timed out');
  if (requests.truncated > 0) reasons.push('one or more responses were truncated');
  if (requests.statusMismatched > 0) reasons.push('response status did not match expected status');
  if (requests.protocolMismatched > 0) {
    reasons.push('one or more responses reported an unexpected protocol version');
  }
  const connectionInfos = entry.connectionInfos ?? [];
  if (entry.protocol === 'h1') {
    if (connectionInfos.length === 0 || !connectionInfos.every((info) => info.alpnProtocol === 'http/1.1')) {
      reasons.push('missing or unexpected ALPN: forced HTTP/1.1 did not negotiate http/1.1 on every connection');
    }
  }
  if (entry.protocol === 'h2') {
    if (connectionInfos.length === 0 || !connectionInfos.every((info) => info.alpnProtocol === 'h2')) {
      reasons.push('missing or unexpected ALPN: HTTP/2 session did not negotiate h2 on every connection');
    }
  }
  if (entry.protocol === 'h2') {
    const distinct = new Set(entry.streamIds ?? []);
    if (distinct.size !== (entry.streamIds ?? []).length) {
      reasons.push('accounting ambiguity: duplicate HTTP/2 stream IDs observed');
    }
    if (entry.concurrency === 32) {
      // Multiple measured rounds legitimately accumulate more than 32
      // distinct stream IDs (rounds * concurrency); the requirement is a
      // floor of 32 per the acceptance criteria, not an exact match.
      if (distinct.size < 32) {
        reasons.push('concurrency-32 requires at least 32 distinct successful HTTP/2 streams');
      }
      if (h2ConnectionsCreated !== 1) {
        reasons.push('concurrency-32 requires exactly one client TLS connection for HTTP/2');
      }
      if (!h2Settings || !(h2Settings.maxConcurrentStreams >= 32)) {
        reasons.push('peer maxConcurrentStreams must be >= 32 for a valid concurrency-32 result');
      }
    }
  }
  return { ok: reasons.length === 0, reasons };
}

export {
  requireHttpsOrigin,
  requireSafePath,
  buildConfig,
  parseCliArgs,
  classifyError,
  verdictFor,
  buildInterleavedPlan,
  aggregateConcurrencyResults,
  summarizeLatency,
  SAFE_PATH_ALLOWLIST,
  ProbeError,
  doHttp1Request,
  doHttp2Request,
  withDeadline,
};

// Races `promise` against a deadline timer, always clearing the timer.
// Used to bound both the initial HTTP/2 handshake and every measured round
// under a single absolute connection-lifetime deadline, rather than only
// checking elapsed time between completed rounds.
function withDeadline(promise, ms, message) {
  if (!(ms > 0)) {
    return Promise.reject(new ProbeError(message));
  }
  let timer;
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new ProbeError(message)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

export async function runProbe(config) {
  const runStart = performance.now();
  const deadlineAt = runStart + config.connectionMaxLifetimeMs;
  const remainingMs = () => deadlineAt - performance.now();

  const h1Agent = new CountingHttpsAgent({
    keepAlive: true,
    maxSockets: Math.max(...config.concurrencyLevels),
    ca: config.ca,
    timeout: config.requestTimeoutMs,
  });
  const { session: h2Session, counters: h2Counters } = connectHttp2Session(config.origin, config.ca);

  try {
    let h2Settings = null;
    await withDeadline(
      new Promise((resolve, reject) => {
        h2Session.once('connect', () => {
          h2Settings = h2Session.remoteSettings ? { ...h2Session.remoteSettings } : null;
          resolve();
        });
        h2Session.once('error', reject);
      }),
      remainingMs(),
      'connection-max-lifetime-ms exceeded while establishing the HTTP/2 session',
    );

    const plan = buildInterleavedPlan(config.rounds, config.warmupRounds);
    // Snapshot connection counters right after each concurrency level's
    // rounds complete, so a level's report reflects sockets/sessions created
    // up to that point rather than the final total across the whole run.
    const levelSnapshots = new Map();
    const results = [];

    for (const concurrency of config.concurrencyLevels) {
      const roundResults = [];
      for (const step of plan) {
        const runner =
          step.protocol === 'h1'
            ? () =>
                doHttp1Request(h1Agent, config.origin, config.path, {
                  timeoutMs: config.requestTimeoutMs,
                  maxResponseBytes: config.maxResponseBytes,
                  expectedStatus: config.expectedStatus,
                })
            : () =>
                doHttp2Request(h2Session, config.path, {
                  timeoutMs: config.requestTimeoutMs,
                  maxResponseBytes: config.maxResponseBytes,
                  expectedStatus: config.expectedStatus,
                });
        // eslint-disable-next-line no-await-in-loop
        const result = await withDeadline(
          runRound({ ...step, concurrency, runner, config }),
          remainingMs(),
          'connection-max-lifetime-ms exceeded during run; aborting to bound connection age',
        );
        roundResults.push(result);
      }
      levelSnapshots.set(concurrency, {
        h1SocketsCreated: h1Agent.socketsCreated,
        h2ConnectionsCreated: h2Counters.connectionsCreated,
      });
      for (const protocol of ['h1', 'h2']) {
        const entry = aggregateConcurrencyResults(roundResults, concurrency, protocol);
        const snapshot = levelSnapshots.get(concurrency);
        entry.connectionInfos =
          protocol === 'h1' ? h1Agent.connectionInfos.slice() : h2Counters.connectionInfos.slice();
        entry.connectionInfo = entry.connectionInfos.at(-1) ?? null;
        entry.connectionsCreated = protocol === 'h1' ? snapshot.h1SocketsCreated : snapshot.h2ConnectionsCreated;
        entry.handshakes = protocol === 'h1' ? h1Agent.handshakes : h2Counters.handshakes;
        entry.http2Settings = protocol === 'h2' ? h2Settings : null;
        entry.verdict = verdictFor(entry, config, snapshot.h2ConnectionsCreated, h2Settings);
        results.push(entry);
      }
    }

    const overallOk = results.every((r) => r.verdict.ok);
    return {
      tool: 'http-edge-probe',
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      environment: {
        node: process.version,
        platform: process.platform,
        arch: process.arch,
      },
      target: { origin: config.origin, path: config.path },
      config: {
        concurrencyLevels: config.concurrencyLevels,
        rounds: config.rounds,
        warmupRounds: config.warmupRounds,
        maxResponseBytes: config.maxResponseBytes,
        requestTimeoutMs: config.requestTimeoutMs,
        connectionMaxLifetimeMs: config.connectionMaxLifetimeMs,
        expectedStatus: config.expectedStatus,
      },
      results,
      ok: overallOk,
    };
  } finally {
    // Always torn down — including when the deadline aborts a round or the
    // HTTP/2 handshake itself fails — so no socket/session outlives the run.
    h2Session.destroy();
    h1Agent.destroy();
  }
}

function helpText() {
  return (
    [
      'Usage: node test/load/http-edge/probe.mjs --origin https://host --path /healthz [options]',
      '',
      'Required:',
      '  --origin <https-origin>   Target origin, e.g. https://node.tinycloud.xyz',
      '  --path <safe-path>        Must be an allowlisted safe path (currently: /healthz)',
      '',
      'Options:',
      '  --concurrency <list>      Comma-separated concurrency levels (default: 1,8,32)',
      '  --rounds <n>              Measured rounds per concurrency level (default: 3)',
      '  --warmup-rounds <n>       Warm-up rounds excluded from latency stats (default: 1)',
      '  --max-response-bytes <n> Response byte bound (default: 65536)',
      '  --request-timeout-ms <n>  Per-request timeout (default: 5000)',
      '  --connection-max-lifetime-ms <n>  Safety bound on total run duration (default: 60000)',
      '  --expected-status <code>  Expected HTTP status (default: 200)',
      '  --ca <path>               Additional trusted CA PEM file (does not disable verification)',
      '  --out <path>              Write JSON report to a file instead of stdout',
      '',
      'Never emits headers, bodies, cookies, credentials, or URLs containing user data.',
    ].join('\n') + '\n'
  );
}

// Waits for the write to be fully flushed through the stdout pipe before the
// caller proceeds, instead of racing an immediate process.exit() (which can
// truncate output still buffered in the pipe).
function writeStdout(text) {
  return new Promise((resolve, reject) => {
    process.stdout.write(text, (err) => (err ? reject(err) : resolve()));
  });
}

// Writes to a same-directory temp file, fsyncs it, then atomically renames
// it into place, so a reader never observes a partially written report.
function writeFileAtomic(targetPath, contents) {
  const dir = path.dirname(targetPath) || '.';
  const tmpPath = path.join(dir, `.${path.basename(targetPath)}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`);
  let fd;
  try {
    fd = fs.openSync(tmpPath, 'w');
    fs.writeSync(fd, contents);
    fs.fsyncSync(fd);
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmpPath, targetPath);
  } finally {
    if (fd !== undefined) {
      fs.closeSync(fd);
    }
    if (fs.existsSync(tmpPath)) {
      fs.rmSync(tmpPath, { force: true });
    }
  }
}

async function main() {
  const values = parseCliArgs(process.argv.slice(2));
  if (values.help) {
    await writeStdout(helpText());
    process.exitCode = 0;
    return;
  }
  const config = buildConfig(values);
  const report = await runProbe(config);
  const json = JSON.stringify(report, null, 2) + '\n';
  if (config.out) {
    writeFileAtomic(config.out, json);
  } else {
    await writeStdout(json);
  }
  process.exitCode = report.ok ? 0 : 1;
}

const isMain = process.argv[1] && import.meta.url === `file://${process.argv[1]}`;
if (isMain) {
  main().catch(async (err) => {
    // Fail closed with a minimal, sanitized error envelope. Never emit a
    // partial JSON document.
    const safe = {
      tool: 'http-edge-probe',
      schemaVersion: 1,
      ok: false,
      fatal: true,
      reason: err instanceof ProbeError ? err.message : classifyError(err).code,
    };
    await writeStdout(JSON.stringify(safe, null, 2) + '\n');
    process.exitCode = 1;
  });
}

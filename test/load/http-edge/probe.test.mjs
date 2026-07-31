import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, readFileSync, existsSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import https from 'node:https';
import http2 from 'node:http2';
import {
  requireHttpsOrigin,
  requireSafePath,
  buildConfig,
  classifyError,
  summarizeLatency,
  runProbe,
  doHttp1Request,
  doHttp2Request,
  withDeadline,
} from './probe.mjs';

const PROBE_PATH = new URL('./probe.mjs', import.meta.url).pathname;
const SENTINEL_SECRET = 'sk_test_sentinel_do_not_leak_9f3c2a';

function runProbeCli(args) {
  return new Promise((resolve, reject) => {
    execFile(process.execPath, [PROBE_PATH, ...args], { encoding: 'utf8' }, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
  });
}

// --- CLI validation -------------------------------------------------------

test('rejects a non-https origin', () => {
  assert.throws(() => requireHttpsOrigin('http://example.com'), /https:\/\//);
});

test('rejects an origin carrying credentials, and never echoes the secret', () => {
  try {
    requireHttpsOrigin(`https://user:${SENTINEL_SECRET}@example.com`);
    assert.fail('expected requireHttpsOrigin to throw');
  } catch (err) {
    assert.match(err.message, /credentials/);
    assert.doesNotMatch(err.message, new RegExp(SENTINEL_SECRET));
  }
});

test('rejects an origin with a path, query, or hash', () => {
  assert.throws(() => requireHttpsOrigin('https://example.com/foo'), /bare scheme\+host/);
  assert.throws(() => requireHttpsOrigin(`https://example.com/?token=${SENTINEL_SECRET}`), /bare scheme\+host/);
});

test('accepts a bare https origin', () => {
  assert.equal(requireHttpsOrigin('https://example.com'), 'https://example.com');
  assert.equal(requireHttpsOrigin('https://example.com:8443'), 'https://example.com:8443');
});

test('only /healthz is an allowlisted safe path', () => {
  assert.equal(requireSafePath('/healthz'), '/healthz');
  assert.throws(() => requireSafePath('/invoke'), /allowlisted/);
  assert.throws(() => requireSafePath('/delegate'), /allowlisted/);
  assert.throws(() => requireSafePath(`/healthz?x=${SENTINEL_SECRET}`), /allowlisted/);
});

test('buildConfig enforces bounds on concurrency, rounds, and timeouts', () => {
  const base = { origin: 'https://example.com', path: '/healthz', rounds: '3', 'warmup-rounds': '1',
    'max-response-bytes': '65536', 'request-timeout-ms': '5000', 'connection-max-lifetime-ms': '60000',
    'expected-status': '200' };
  assert.throws(() => buildConfig({ ...base, concurrency: '1,8,999' }), /concurrency/);
  assert.throws(() => buildConfig({ ...base, concurrency: '1,8,32', rounds: '999' }), /rounds/);
  assert.throws(() => buildConfig({ ...base, concurrency: '1,8,32', 'request-timeout-ms': '999999' }), /request-timeout-ms/);
  const ok = buildConfig({ ...base, concurrency: '1,8,32' });
  assert.deepEqual(ok.concurrencyLevels, [1, 8, 32]);
});

test('buildConfig rejects malformed numeric arguments instead of silently truncating them', () => {
  const base = { origin: 'https://example.com', path: '/healthz', rounds: '3', 'warmup-rounds': '1',
    'max-response-bytes': '65536', 'request-timeout-ms': '5000', 'connection-max-lifetime-ms': '60000',
    'expected-status': '200' };
  assert.throws(() => buildConfig({ ...base, concurrency: '1junk,8,32' }), /concurrency/);
  assert.throws(() => buildConfig({ ...base, concurrency: '1,2oops,32' }), /concurrency/);
  assert.throws(() => buildConfig({ ...base, concurrency: '1,8,32', rounds: '5x' }), /rounds/);
  assert.throws(() => buildConfig({ ...base, concurrency: '1,8,32', rounds: '3.5' }), /rounds/);
  assert.throws(() => buildConfig({ ...base, concurrency: '1,8,32', rounds: '0x3' }), /rounds/);
});

test('buildConfig rejects oversized or duplicate concurrency lists (bounded runtime/output)', () => {
  const base = { origin: 'https://example.com', path: '/healthz', rounds: '1', 'warmup-rounds': '0',
    'max-response-bytes': '65536', 'request-timeout-ms': '5000', 'connection-max-lifetime-ms': '60000',
    'expected-status': '200' };
  assert.throws(() => buildConfig({ ...base, concurrency: '1,2,3,4,5,6,7,8' }), /at most/);
  assert.throws(() => buildConfig({ ...base, concurrency: '1,8,8,32' }), /duplicate/);
});

// --- redaction --------------------------------------------------------

test('classifyError never surfaces the raw error message', () => {
  const err = new Error(`leaked ${SENTINEL_SECRET} in Authorization: Bearer abc`);
  err.code = 'ECONNRESET';
  const classified = classifyError(err);
  const serialized = JSON.stringify(classified);
  assert.doesNotMatch(serialized, new RegExp(SENTINEL_SECRET));
  assert.doesNotMatch(serialized, /Authorization/);
  assert.deepEqual(Object.keys(classified).sort(), ['code', 'kind']);
});

test('summarizeLatency never includes non-numeric or header-shaped data', () => {
  const summary = summarizeLatency([1, 2, 3, 4, 5]);
  assert.equal(summary.samples, 5);
  assert.ok(typeof summary.p50 === 'number');
});

// --- CLI-level sentinel redaction (spawned process) ------------------------

test('CLI output never contains injected sentinel secrets, even via env or CA path names', () => {
  const result = spawnSync(
    process.execPath,
    [PROBE_PATH, '--origin', `https://user:${SENTINEL_SECRET}@example.com`, '--path', '/healthz'],
    { encoding: 'utf8', env: { ...process.env, AUTHORIZATION: `Bearer ${SENTINEL_SECRET}` } },
  );
  const combined = `${result.stdout}${result.stderr}`;
  assert.doesNotMatch(combined, new RegExp(SENTINEL_SECRET));
  assert.notEqual(result.status, 0);
});

test('CLI rejects an unsafe path outright (fails closed) without contacting the network', () => {
  const result = spawnSync(
    process.execPath,
    [PROBE_PATH, '--origin', 'https://example.com', '--path', '/invoke'],
    { encoding: 'utf8' },
  );
  assert.notEqual(result.status, 0);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.ok, false);
  assert.equal(parsed.fatal, true);
});

// --- integration against a local HTTP/2+1.1 server -------------------------

let tmpDir;
let keyPath;
let certPath;
let server;
let serverOrigin;
// The '/slow' route intentionally never calls res.end(); each response
// object is tracked here so tests that hit it can force-destroy the
// server-side response immediately afterward instead of leaving it (and its
// stream/socket) dangling on the shared server for the rest of the file.
const pendingSlowResponses = new Set();

before(async () => {
  tmpDir = mkdtempSync(path.join(tmpdir(), 'http-edge-probe-'));
  keyPath = path.join(tmpDir, 'key.pem');
  certPath = path.join(tmpDir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-keyout', keyPath, '-out', certPath,
    '-days', '1', '-nodes', '-subj', '/CN=localhost',
    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
  ]);

  server = http2.createSecureServer({
    key: readFileSync(keyPath),
    cert: readFileSync(certPath),
    allowHTTP1: true,
  });
  // In compat mode (allowHTTP1: true) the 'request' event alone handles
  // both HTTP/1.1 and HTTP/2 streams; also registering 'stream' would
  // respond twice to the same HTTP/2 request.
  server.on('request', (req, res) => {
    if (req.url === '/healthz') {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    } else if (req.url === '/slow') {
      // Deliberately never responds, to deterministically exercise the
      // fail-closed timeout path without depending on real network flakiness.
      pendingSlowResponses.add(res);
      res.once('close', () => pendingSlowResponses.delete(res));
    } else if (req.url === '/big') {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(Buffer.alloc(200_000, 'a'));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  // Start listening here (rather than inside the first test) so every test
  // in this file can rely on `serverOrigin`/`certPath` regardless of order.
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  serverOrigin = `https://127.0.0.1:${port}`;
});

after(() => {
  for (const res of pendingSlowResponses) res.destroy();
  pendingSlowResponses.clear();
  server?.close();
  rmSync(tmpDir, { recursive: true, force: true });
});

test('probe negotiates http/1.1 and h2 against a local dual-protocol server', async () => {
  const config = buildConfig({
    origin: serverOrigin,
    path: '/healthz',
    concurrency: '1,2',
    rounds: '1',
    'warmup-rounds': '1',
    'max-response-bytes': '65536',
    'request-timeout-ms': '5000',
    'connection-max-lifetime-ms': '60000',
    'expected-status': '200',
    ca: certPath,
  });

  const report = await runProbe(config);

  assert.equal(report.tool, 'http-edge-probe');
  assert.equal(report.target.origin, serverOrigin);
  assert.equal(report.target.path, '/healthz');

  const h1Results = report.results.filter((r) => r.protocol === 'h1');
  const h2Results = report.results.filter((r) => r.protocol === 'h2');
  assert.equal(h1Results.length, 2);
  assert.equal(h2Results.length, 2);

  for (const r of h1Results) {
    assert.equal(r.connectionInfo.alpnProtocol, 'http/1.1');
    assert.ok(r.connectionInfos.length > 0);
    assert.ok(r.connectionInfos.every((info) => info.alpnProtocol === 'http/1.1'));
    assert.equal(r.requests.succeeded, r.requests.attempted);
    assert.equal(r.requests.failed, 0);
    assert.equal(r.requests.protocolMismatched, 0);
  }
  for (const r of h2Results) {
    assert.equal(r.connectionInfo.alpnProtocol, 'h2');
    assert.ok(r.connectionInfos.length > 0);
    assert.ok(r.connectionInfos.every((info) => info.alpnProtocol === 'h2'));
    assert.equal(r.requests.succeeded, r.requests.attempted);
    assert.equal(r.requests.protocolMismatched, 0);
    const distinctStreamIds = new Set(r.streamIds);
    assert.equal(distinctStreamIds.size, r.streamIds.length);
  }

  // Exactly one HTTP/2 TLS connection for the whole run, reused across
  // every concurrency level.
  assert.equal(h2Results[0].connectionsCreated, 1);
  assert.equal(h2Results[1].connectionsCreated, 1);

  const serialized = JSON.stringify(report);
  assert.doesNotMatch(serialized, /authorization/i);
  assert.doesNotMatch(serialized, /cookie/i);
  assert.equal(report.ok, true);
});

test('probe fails closed when the expected status is not met', async () => {
  const config = buildConfig({
    origin: serverOrigin,
    path: '/healthz',
    concurrency: '1',
    rounds: '1',
    'warmup-rounds': '0',
    'max-response-bytes': '65536',
    'request-timeout-ms': '5000',
    'connection-max-lifetime-ms': '60000',
    'expected-status': '204', // server always returns 200, so this must fail closed
    ca: certPath,
  });

  const report = await runProbe(config);
  assert.equal(report.ok, false);
  for (const r of report.results) {
    assert.equal(r.verdict.ok, false);
    assert.ok(r.verdict.reasons.length > 0);
  }
});

// --- fail-closed timeout/truncation must resolve, never hang --------------

test('doHttp1Request resolves a fail-closed timeout instead of hanging when the server never responds', async () => {
  const agent = new https.Agent({ ca: readFileSync(certPath), keepAlive: true });
  try {
    const result = await doHttp1Request(agent, serverOrigin, '/slow', {
      timeoutMs: 200,
      maxResponseBytes: 65_536,
      expectedStatus: 200,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, 'timeout');
  } finally {
    agent.destroy();
    for (const res of pendingSlowResponses) res.destroy();
    pendingSlowResponses.clear();
  }
});

test('doHttp1Request resolves a fail-closed truncation instead of hanging on an oversized response', async () => {
  const agent = new https.Agent({ ca: readFileSync(certPath), keepAlive: true });
  try {
    const result = await doHttp1Request(agent, serverOrigin, '/big', {
      timeoutMs: 5000,
      maxResponseBytes: 1024,
      expectedStatus: 200,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, 'truncated');
  } finally {
    agent.destroy();
  }
});

test('doHttp2Request resolves a fail-closed timeout instead of hanging when the server never responds', async () => {
  const session = http2.connect(serverOrigin, { ca: readFileSync(certPath) });
  try {
    await new Promise((resolve, reject) => {
      session.once('connect', resolve);
      session.once('error', reject);
    });
    const result = await doHttp2Request(session, '/slow', {
      timeoutMs: 200,
      maxResponseBytes: 65_536,
      expectedStatus: 200,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, 'timeout');
  } finally {
    session.destroy();
    for (const res of pendingSlowResponses) res.destroy();
    pendingSlowResponses.clear();
  }
});

test('doHttp2Request resolves a fail-closed truncation instead of hanging on an oversized response', async () => {
  const session = http2.connect(serverOrigin, { ca: readFileSync(certPath) });
  try {
    await new Promise((resolve, reject) => {
      session.once('connect', resolve);
      session.once('error', reject);
    });
    const result = await doHttp2Request(session, '/big', {
      timeoutMs: 5000,
      maxResponseBytes: 1024,
      expectedStatus: 200,
    });
    assert.equal(result.ok, false);
    assert.equal(result.error.kind, 'truncated');
  } finally {
    session.destroy();
  }
});

// --- connection-max-lifetime-ms is enforced end-to-end ---------------------

// withDeadline is the single mechanism runProbe uses to bound both the
// initial HTTP/2 handshake and every measured round under one absolute
// connection-lifetime deadline; test it directly and deterministically
// rather than via a real hung socket (flaky, and leaks OS-level state).
test('withDeadline rejects with the given message once the deadline elapses, for a promise that never settles', async () => {
  const neverSettles = new Promise(() => {});
  await assert.rejects(
    () => withDeadline(neverSettles, 30, 'connection-max-lifetime-ms exceeded (test)'),
    /connection-max-lifetime-ms exceeded \(test\)/,
  );
});

test('withDeadline rejects immediately when no time remains', async () => {
  await assert.rejects(
    () => withDeadline(new Promise(() => {}), 0, 'connection-max-lifetime-ms exceeded (no time left)'),
    /connection-max-lifetime-ms exceeded \(no time left\)/,
  );
});

test('withDeadline resolves normally when the promise settles before the deadline', async () => {
  const result = await withDeadline(Promise.resolve('fast'), 5000, 'should not fire');
  assert.equal(result, 'fast');
});

// --- atomic output -----------------------------------------------------

test('CLI --out writes a single complete JSON file with no leftover temp file', async () => {
  const outPath = path.join(tmpDir, 'report.json');
  await runProbeCli([
    '--origin', serverOrigin,
    '--path', '/healthz',
    '--concurrency', '1',
    '--rounds', '1',
    '--warmup-rounds', '0',
    '--ca', certPath,
    '--out', outPath,
  ]);
  assert.ok(existsSync(outPath));
  const parsed = JSON.parse(readFileSync(outPath, 'utf8'));
  assert.equal(parsed.ok, true);
  const leftoverTmp = readdirSync(tmpDir).filter((f) => f.includes('.tmp'));
  assert.deepEqual(leftoverTmp, []);
});

test('CLI stdout output is a single complete, parseable JSON document', async () => {
  const result = await runProbeCli([
    '--origin', serverOrigin,
    '--path', '/healthz',
    '--concurrency', '1',
    '--rounds', '1',
    '--warmup-rounds', '0',
    '--ca', certPath,
  ]);
  const parsed = JSON.parse(result.stdout);
  assert.equal(parsed.ok, true);
});

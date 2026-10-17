import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createSocket } from 'node:dgram';
import { createServer } from 'node:http';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gunzipSync } from 'node:zlib';
import { buildConfig } from '../scripts/tc959-logship.mjs';
import { assertCapture } from '../scripts/tc959-docker.mjs';
import { hasUdpListener } from '../scripts/tc959-readiness.mjs';
import { canary, nodeRequest, ingressRequest, f6Line, f6Events } from './cases.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

/** Real native Vector, UDP framing and HTTP capture; never production inputs. */
export async function checkNativeVector(vector, baseline) {
  const dir = await mkdtemp(join(tmpdir(), 'tc959-native-'));
  const events = [];
  let malformedHttp = false;
  const server = createServer(async (request, response) => {
    try {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      let body = Buffer.concat(chunks);
      if (request.headers['content-encoding'] === 'gzip') body = gunzipSync(body);
      for (const line of body.toString().split('\n').filter(Boolean)) events.push(JSON.parse(line));
      response.writeHead(200).end();
    } catch { malformedHttp = true; response.writeHead(400).end(); }
  });
  let child;
  let closed;
  let consoleText = '';
  let overflow = false;
  const udp = createSocket('udp4');
  try {
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    await new Promise(resolve => udp.bind(0, '127.0.0.1', resolve));
    const port = udp.address().port;
    await new Promise(resolve => udp.close(resolve));
    const config = baseline ? structuredClone(baseline) : buildConfig({ profile: 'all_requests' });
    delete config.secret;
    config.data_dir = dir;
    config.sources.gelf_in.address = `127.0.0.1:${port}`;
    config.sinks.betterstack.uri = `http://127.0.0.1:${server.address().port}/`;
    config.sinks.betterstack.auth = { strategy: 'bearer', token: 'tc959-synthetic-only' };
    const path = join(dir, 'vector.json');
    await writeFile(path, JSON.stringify(config));
    child = spawn(vector, ['--config', path], { env: {}, stdio: ['ignore', 'pipe', 'pipe'] });
    closed = once(child, 'close');
    const collect = chunk => {
      consoleText += chunk.toString();
      if (Buffer.byteLength(consoleText) > 524288) { overflow = true; consoleText = consoleText.slice(-524288); }
    };
    child.stdout.on('data', collect);
    child.stderr.on('data', collect);
    let bound = false;
    for (let attempt = 0; attempt < 250; attempt++) {
      if (child.exitCode !== null) break;
      bound = hasUdpListener(await readFile('/proc/net/udp', 'utf8'), port);
      if (bound) break;
      await sleep(20);
    }
    assert.equal(bound, true, 'native UDP listener did not become ready');
    const sender = createSocket('udp4');
    const send = packet => new Promise((resolve, reject) => sender.send(Buffer.from(packet), port, '127.0.0.1', error => error ? reject(error) : resolve()));
    const frame = (value, label = 'tinycloud-node', extras = {}) => JSON.stringify({ version: '1.1', host: canary, timestamp: Date.now() / 1000, level: 6, short_message: JSON.stringify(value), '_tc.logship': label, ...extras });
    try {
      for (const [route, method, status] of [['/healthz', 'GET', 200], ['/version', 'GET', 200], ['/invoke', 'POST', 401]]) {
        await send(frame(nodeRequest({ route, method, status, authorization: canary })));
      }
      await send(frame(ingressRequest(), 'tinycloud-ingress'));
      // Native GELF JSON decoding used to quote this value in its own console.
      await send(frame(nodeRequest({ route: '/healthz' }), 'tinycloud-node', { level: canary, full_message: canary }));
      await send(`{"version":"1.1","short_message":"${canary}`);
      // F6: one valid occurrence with hostile extras is shipped typed; the stale 16-hex shape is not.
      await send(frame(f6Line('sql_operation_lock_wait', { db: canary, operation: 'begin', error: canary })));
      await send(frame(f6Line('sql_operation_lock_wait', { space_hash: '0123456789abcdef', db: 'v2n', db_hash: undefined })));
    } finally { sender.close(); }
    const typed = () => events.filter(event => event.event_code === 'sql_operation_lock_wait');
    for (let attempt = 0; attempt < 100; attempt++) {
      if (events.filter(event => event.event === 'node_request' || event.event === 'ingress_request').length >= 5 && typed().length >= 1) break;
      await sleep(30);
    }
    child.kill('SIGTERM');
    await closed;
    child = undefined;
    let wireSafe = true;
    const schema = JSON.parse(await readFile(new URL('./fields.json', import.meta.url), 'utf8'));
    try { assertCapture(events, schema.services['tinycloud-node'].fields); } catch { wireSafe = false; }
    const requests = events.filter(event => event.event === 'node_request' || event.event === 'ingress_request').length;
    const f6 = typed();
    const expected = { level: 'warn', event: 'node_warning', svc: 'api', event_code: 'sql_operation_lock_wait', event_count: 1, ...f6Events.sql_operation_lock_wait.fields };
    const f6Exact = f6.length === 1 && Object.entries(expected).every(([key, value]) => f6[0][key] === value) && Object.keys(f6[0]).length === Object.keys(expected).length + 1;
    const consoleHits = consoleText.split(canary).length - 1;
    return { status: wireSafe && !malformedHttp && !overflow && requests === 5 && f6Exact && consoleHits === 0 ? 'passed' : 'failed', request_events: requests, f6_typed_events: f6.length, f6_exact: f6Exact, console_canary_hits: consoleHits, wire_safe: wireSafe, positive_controls: 6, console_overflow: overflow };
  } finally {
    if (child) { child.kill('SIGTERM'); await closed; }
    server.closeAllConnections();
    await new Promise(resolve => server.close(resolve));
    await rm(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!process.argv[2]) throw new Error('usage: native-check.mjs VECTOR_BINARY');
  checkNativeVector(resolve(process.argv[2])).then(result => {
    console.log(JSON.stringify(result));
    if (result.status !== 'passed') process.exitCode = 1;
  }).catch(() => { console.log(JSON.stringify({ status: 'failed', reason: 'native_runtime_check_failed' })); process.exitCode = 1; });
}

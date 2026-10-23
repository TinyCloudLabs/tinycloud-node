import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildConfig } from '../scripts/tc959-logship.mjs';
import { assertCapture } from '../scripts/tc959-docker.mjs';
import { CAPPED_CLASSES, CAP_WINDOW_SECONDS } from './budget.mjs';
import { nodeRequest, ingressRequest, dbFailure } from './cases.mjs';

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const capOf = name => CAPPED_CLASSES[name].capPerMinute;

/**
 * TC-1843: real Vector, the real compiled boundary and the real cap transforms; no sockets. GELF packets go in on
 * stdin (the only source substitution) and every sink input is printed by a console sink. The cap timers are wall-clock,
 * so the check lasts about two cap windows. Window 1 overflows all three classes by different amounts and sends
 * uncapped 4xx and slow requests; window 2 overflows one class and stays under the cap in the others.
 */
export async function checkCaps(vector) {
  const dir = await mkdtemp(join(tmpdir(), 'tc1843-cap-'));
  let child;
  let closed;
  try {
    const config = buildConfig({ profile: 'errors_slow', token: 'tc1843-synthetic-only', dataDir: dir });
    config.sources = { gelf_in: { type: 'stdin', framing: { method: 'newline_delimited' }, decoding: { codec: 'bytes' } } };
    config.sinks = { out: { type: 'console', inputs: [...config.sinks.betterstack.inputs], target: 'stdout', encoding: { codec: 'json' } } };
    const path = join(dir, 'vector.json');
    await writeFile(path, JSON.stringify(config));
    const events = [];
    let pending = '';
    child = spawn(vector, ['--config', path], { env: {}, stdio: ['pipe', 'pipe', 'ignore'] });
    closed = once(child, 'close');
    child.stdout.on('data', chunk => {
      pending += chunk.toString();
      const lines = pending.split('\n');
      pending = lines.pop();
      for (const line of lines.filter(Boolean)) events.push(JSON.parse(line));
    });
    const frame = (value, label = 'tinycloud-node') => `${JSON.stringify({ version: '1.1', short_message: JSON.stringify(value), '_tc.logship': label })}\n`;
    const send = lines => new Promise((resolveWrite, reject) => child.stdin.write(lines.join(''), error => error ? reject(error) : resolveWrite()));
    const waitFor = async (predicate, seconds) => {
      for (let attempt = 0; attempt < seconds * 10; attempt++) { if (predicate()) return; await sleep(100); }
      assert.fail('timed out waiting for the capped events');
    };
    const dropEvents = () => events.filter(event => event.event_code === 'errors_dropped');
    const kinds = {
      node_request_5xx: n => frame(nodeRequest({ status: 503, latency_us: n })),
      ingress_request_5xx: n => frame(ingressRequest({ status: 502, request_time: n / 1000 }), 'tinycloud-ingress'),
      db_failure_5xx: n => frame(dbFailure({ elapsed_ms: n })),
    };
    const shipped = name => events.filter(event => ({
      node_request_5xx: event.event === 'node_request' && event.status >= 500,
      ingress_request_5xx: event.event === 'ingress_request' && event.status >= 500,
      db_failure_5xx: event.event_code === 'db_failure_5xx',
    })[name]);
    const sequence = (name, event) => ({ node_request_5xx: event.latency_us, ingress_request_5xx: Math.round(event.request_time_seconds * 1000), db_failure_5xx: event.elapsed_ms })[name];

    // Window 1: every class over its cap by a different amount, plus requests the cap must not touch.
    const over = { db_failure_5xx: 3, node_request_5xx: 7, ingress_request_5xx: 12 };
    const uncapped = 3 * Math.max(...Object.keys(over).map(capOf));
    for (const [name, extra] of Object.entries(over)) await send(Array.from({ length: capOf(name) + extra }, (_, index) => kinds[name](index + 1)));
    await send([
      ...Array.from({ length: uncapped }, (_, index) => frame(nodeRequest({ status: 429, latency_us: 100 + index }))),
      ...Array.from({ length: uncapped }, (_, index) => frame(ingressRequest({ status: 404, request_time: 0.5 + index / 1000 }), 'tinycloud-ingress')),
      ...Array.from({ length: uncapped }, (_, index) => frame(nodeRequest({ status: 200, latency_us: 2000000 + index }))),
    ]);
    await waitFor(() => dropEvents().length >= 3, CAP_WINDOW_SECONDS + 30);
    const window1 = dropEvents().length;
    assert.equal(window1, 3, 'one dropped-count event per class in the first window');
    for (const [name, extra] of Object.entries(over)) {
      const row = dropEvents().filter(event => event.class === name);
      assert.equal(row.length, 1, `exactly one dropped-count event for ${name}`);
      assert.equal(row[0].dropped, extra, `dropped count for ${name}`);
      assert.equal(row[0].window_s, CAP_WINDOW_SECONDS);
      assert.deepEqual(Object.keys(row[0]).sort(), ['class', 'dropped', 'event', 'event_code', 'level', 'svc', 'ts', 'window_s']);
      assert.deepEqual(shipped(name).map(event => sequence(name, event)).sort((a, b) => a - b), Array.from({ length: capOf(name) }, (_, index) => index + 1), `first ${capOf(name)} ${name} events ship`);
    }
    // 4xx and slow requests are neither capped nor counted.
    assert.equal(events.filter(event => event.event === 'node_request' && event.status === 429).length, uncapped);
    assert.equal(events.filter(event => event.event === 'ingress_request' && event.status === 404).length, uncapped);
    assert.equal(events.filter(event => event.event === 'node_request' && event.status === 200).length, uncapped);

    // Window 2: counters reset; only the class that overflowed reports.
    await send(Array.from({ length: capOf('node_request_5xx') + 2 }, (_, index) => kinds.node_request_5xx(1000 + index + 1)));
    await send(Array.from({ length: capOf('db_failure_5xx') }, (_, index) => kinds.db_failure_5xx(1000 + index + 1)));
    await waitFor(() => dropEvents().length >= 4, CAP_WINDOW_SECONDS + 30);
    await sleep(3000);
    assert.equal(dropEvents().length, 4, 'only the overflowing class reports in the second window');
    const second = dropEvents()[3];
    assert.equal(second.class, 'node_request_5xx');
    assert.equal(second.dropped, 2);
    assert.equal(shipped('node_request_5xx').filter(event => event.latency_us > 1000).length, capOf('node_request_5xx'));
    assert.equal(shipped('db_failure_5xx').filter(event => event.elapsed_ms > 1000).length, capOf('db_failure_5xx'));

    const schema = JSON.parse(await readFile(new URL('./fields.json', import.meta.url), 'utf8'));
    assertCapture(events, schema.services['tinycloud-node'].fields);
    return { status: 'passed', window_s: CAP_WINDOW_SECONDS, caps: Object.fromEntries(Object.keys(CAPPED_CLASSES).map(name => [name, capOf(name)])), dropped_events: dropEvents().length, uncapped_events: 3 * uncapped };
  } finally {
    if (child) { child.stdin.end(); child.kill('SIGTERM'); await closed; }
    await rm(dir, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (!process.argv[2]) throw new Error('usage: cap-check.mjs VECTOR_BINARY');
  checkCaps(resolve(process.argv[2])).then(result => console.log(JSON.stringify(result))).catch(error => {
    console.log(JSON.stringify({ status: 'failed', reason: String(error?.message ?? error).slice(0, 300) }));
    process.exitCode = 1;
  });
}

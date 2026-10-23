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
 * so the check lasts about three cap windows. Window 1 overflows all five classes by different amounts and sends slow
 * requests below status 400 that no cap may touch; window 2 sends 500 events per class; window 3 overflows one 5xx
 * class and stays at the cap in two others.
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
      node_request_4xx: n => frame(nodeRequest({ status: 404, latency_us: n })),
      ingress_request_4xx: n => frame(ingressRequest({ status: 429, request_time: n / 1000 }), 'tinycloud-ingress'),
    };
    const inRange = (status, low) => status >= low && status < low + 100;
    const shipped = name => events.filter(event => ({
      node_request_5xx: event.event === 'node_request' && inRange(event.status, 500),
      ingress_request_5xx: event.event === 'ingress_request' && inRange(event.status, 500),
      db_failure_5xx: event.event_code === 'db_failure_5xx',
      node_request_4xx: event.event === 'node_request' && inRange(event.status, 400),
      ingress_request_4xx: event.event === 'ingress_request' && inRange(event.status, 400),
    })[name]);
    const sequence = (name, event) => ({
      node_request_5xx: event.latency_us, node_request_4xx: event.latency_us, db_failure_5xx: event.elapsed_ms,
      ingress_request_5xx: Math.round(event.request_time_seconds * 1000), ingress_request_4xx: Math.round(event.request_time_seconds * 1000),
    })[name];

    // Window 1: every class over its cap by a different amount, plus slow requests below status 400 that no cap may touch.
    const over = { db_failure_5xx: 3, node_request_5xx: 7, ingress_request_5xx: 12, node_request_4xx: 5, ingress_request_4xx: 9 };
    const uncapped = 3 * Math.max(...Object.keys(over).map(capOf));
    const highRate = 500;
    for (const [name, extra] of Object.entries(over)) await send(Array.from({ length: capOf(name) + extra }, (_, index) => kinds[name](index + 1)));
    await send([
      ...Array.from({ length: uncapped }, (_, index) => frame(nodeRequest({ status: 200, latency_us: 2000000 + index }))),
      ...Array.from({ length: uncapped }, (_, index) => frame(ingressRequest({ status: 301, request_time: 2 + index / 1000 }), 'tinycloud-ingress')),
    ]);
    await waitFor(() => dropEvents().length >= 5, CAP_WINDOW_SECONDS + 30);
    const window1 = dropEvents().length;
    assert.equal(window1, 5, 'one dropped-count event per class in the first window');
    for (const [name, extra] of Object.entries(over)) {
      const row = dropEvents().filter(event => event.class === name);
      assert.equal(row.length, 1, `exactly one dropped-count event for ${name}`);
      assert.equal(row[0].dropped, extra, `dropped count for ${name}`);
      assert.equal(row[0].window_s, CAP_WINDOW_SECONDS);
      assert.deepEqual(Object.keys(row[0]).sort(), ['class', 'dropped', 'event', 'event_code', 'level', 'svc', 'ts', 'window_s']);
      assert.deepEqual(shipped(name).map(event => sequence(name, event)).sort((a, b) => a - b), Array.from({ length: capOf(name) }, (_, index) => index + 1), `first ${capOf(name)} ${name} events ship`);
    }
    // Slow requests below status 400 are neither capped nor counted.
    assert.equal(events.filter(event => event.event === 'node_request' && event.status === 200).length, uncapped);
    assert.equal(events.filter(event => event.event === 'ingress_request' && event.status === 301).length, uncapped);

    // Window 2: a high-rate burst of 500 events per class. Exactly the first cap ship and one errors_dropped reports 500 - cap.
    await send(Object.keys(over).flatMap(name => Array.from({ length: highRate }, (_, index) => kinds[name](1000 + index + 1))));
    await waitFor(() => dropEvents().length >= 10, CAP_WINDOW_SECONDS + 30);
    await sleep(3000);
    assert.equal(dropEvents().length, 10, 'one dropped-count event per class in the second window');
    for (const name of Object.keys(over)) {
      const row = dropEvents().slice(5).filter(event => event.class === name);
      assert.equal(row.length, 1, `exactly one dropped-count event for ${name} in the high-rate window`);
      assert.equal(row[0].dropped, highRate - capOf(name), `dropped count for ${name} in the high-rate window`);
      const window2 = shipped(name).map(event => sequence(name, event)).filter(value => value > 1000 && value < 2000).sort((a, b) => a - b);
      assert.deepEqual(window2, Array.from({ length: capOf(name) }, (_, index) => 1000 + index + 1), `exactly the first ${capOf(name)} of ${highRate} ${name} events ship`);
    }

    // Window 3: counters reset again; the 4xx and db classes stay at their cap exactly, so only the overflowing 5xx class reports.
    await send(Array.from({ length: capOf('node_request_5xx') + 2 }, (_, index) => kinds.node_request_5xx(2000 + index + 1)));
    await send(Array.from({ length: capOf('db_failure_5xx') }, (_, index) => kinds.db_failure_5xx(2000 + index + 1)));
    await send(Array.from({ length: capOf('node_request_4xx') }, (_, index) => kinds.node_request_4xx(2000 + index + 1)));
    await waitFor(() => dropEvents().length >= 11, CAP_WINDOW_SECONDS + 30);
    await sleep(3000);
    assert.equal(dropEvents().length, 11, 'only the overflowing class reports in the third window');
    const third = dropEvents()[10];
    assert.equal(third.class, 'node_request_5xx');
    assert.equal(third.dropped, 2);
    for (const name of ['node_request_5xx', 'db_failure_5xx', 'node_request_4xx']) {
      assert.equal(shipped(name).filter(event => sequence(name, event) > 2000).length, capOf(name), `${name} ships its full cap again in the third window`);
    }

    const schema = JSON.parse(await readFile(new URL('./fields.json', import.meta.url), 'utf8'));
    assertCapture(events, schema.services['tinycloud-node'].fields);
    return { status: 'passed', window_s: CAP_WINDOW_SECONDS, caps: Object.fromEntries(Object.keys(CAPPED_CLASSES).map(name => [name, capOf(name)])), high_rate_events_per_class: highRate, dropped_events: dropEvents().length, uncapped_events: 2 * uncapped };
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

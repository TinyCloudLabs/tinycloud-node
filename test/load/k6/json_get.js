import { check } from 'k6';
import exec from 'k6/execution';
import http from 'k6/http';
import { Counter, Trend } from 'k6/metrics';

import {
    buildInvocationBody,
    buildTc268Options,
    expandTc268Matrix,
    handleTc268Summary,
    readTc268Matrix,
    selectTc268MatrixRow,
    validateTc268BackendSnapshot,
} from './tc268.mjs';
import { prepare_signed_invocations, setup_namespace, signer, tinycloud } from './utils.js';

const invokeSamples = new Counter('tc268_invoke_samples');
const invokeErrors = new Counter('tc268_invoke_errors');
const invokeLatency = new Trend('tc268_invoke_latency');

const rate = Number.parseInt(__ENV.TC268_RATE || '10', 10);
const warmupSeconds = Number.parseInt(__ENV.TC268_WARMUP_SECONDS || '20', 10);
const measureSeconds = Number.parseInt(__ENV.TC268_MEASURE_SECONDS || '60', 10);
const minSamples = Number.parseInt(__ENV.TC268_MIN_SAMPLES || '250', 10);
const parsedMaxVUs = __ENV.TC268_MAX_VUS ? Number.parseInt(__ENV.TC268_MAX_VUS, 10) : undefined;
const maxVUs = Number.isFinite(parsedMaxVUs) ? parsedMaxVUs : undefined;
const matrixIndex = Number.parseInt(__ENV.TC268_ROW_INDEX || '0', 10);
const matrixRows = expandTc268Matrix(readTc268Matrix());
const matrix = selectTc268MatrixRow(matrixRows, matrixIndex);
const preAllocatedVUs = matrix.concurrency;
const keyName = `tc268-get-${matrix.depth}-${matrix.payloadBytes}`;
const controlUrl = __ENV.TC268_CONTROL_URL || __ENV.TINYCLOUD_CONTROL_URL;
const controlToken = __ENV.TC268_CONTROL_TOKEN || __ENV.TINYCLOUD_CONTROL_TOKEN;

export const options = buildTc268Options({
    rate,
    warmupSeconds,
    measureSeconds,
    preAllocatedVUs,
    maxVUs,
    minSamples,
});

function isMeasurePhase() {
    return exec.scenario.name === 'measure';
}

function validateBackendBeforeLoad() {
    if (!controlUrl || !controlToken) {
        throw new Error('TC268_CONTROL_URL and TC268_CONTROL_TOKEN are required before load begins');
    }

    const res = http.get(`${controlUrl.replace(/\/$/, '')}/v1/config`, {
        headers: {
            Authorization: `Bearer ${controlToken}`,
        },
    });
    check(res, {
        'control config request succeeds': (r) => r.status === 200,
    });
    if (res.status !== 200) {
        throw new Error(`failed to read TC-268 control config: ${res.status}`);
    }
    validateTc268BackendSnapshot(res.json(), matrix);
}

export function setup() {
    validateBackendBeforeLoad();
    setup_namespace(tinycloud, signer, 0, matrix.depth);

    const seed = prepare_signed_invocations({
        tinycloud,
        signer,
        sessionId: 0,
        action: 'put',
        count: 1,
        depth: matrix.depth,
        payloadBytes: matrix.payloadBytes,
        nameFactory: () => keyName,
    })[0];
    const seedBody = buildInvocationBody({
        action: seed.action,
        payloadBytes: seed.payloadBytes,
        seed: seed.bodySeed,
    });
    const seedRes = http.post(`${tinycloud}/invoke`, seedBody, {
        headers: seed.headers,
    });
    check(seedRes, {
        'seed write succeeds': (r) => r.status === 200,
    });

    const warmupPrepared = prepare_signed_invocations({
        tinycloud,
        signer,
        sessionId: 0,
        action: 'get',
        count: warmupSeconds * rate + 32,
        depth: matrix.depth,
        payloadBytes: matrix.payloadBytes,
        nameFactory: () => keyName,
    });
    const measurePrepared = prepare_signed_invocations({
        tinycloud,
        signer,
        sessionId: 0,
        action: 'get',
        count: measureSeconds * rate + 32,
        depth: matrix.depth,
        payloadBytes: matrix.payloadBytes,
        nameFactory: () => keyName,
    });

    return {
        warmupPrepared,
        measurePrepared,
        matrix,
        rate,
        warmupSeconds,
        measureSeconds,
        minSamples,
        keyName,
    };
}

export default function(data) {
    const prepared = (isMeasurePhase() ? data.measurePrepared : data.warmupPrepared)[
        exec.scenario.iterationInTest
    ];
    if (!prepared) {
        throw new Error(`missing prepared invocation for iteration ${exec.scenario.iterationInTest}`);
    }

    const body = buildInvocationBody({
        action: prepared.action,
        payloadBytes: prepared.payloadBytes,
        seed: prepared.bodySeed,
    });
    const res = http.post(`${tinycloud}/invoke`, body, {
        headers: prepared.headers,
    });
    const latencyMs = res.timings.duration;
    const ok = check(res, {
        'status is 200': (r) => r.status === 200,
        'response body matches payload size': (r) => r.body.length === matrix.payloadBytes,
    });

    if (isMeasurePhase()) {
        invokeSamples.add(1);
        invokeLatency.add(latencyMs);
        if (!ok) {
            invokeErrors.add(1);
        }
    }
}

export function teardown() {
    const del_invocation = http.post(`${signer}/sessions/0/invoke`,
        JSON.stringify({ name: keyName, action: "del" }),
        {
            headers: {
                'Content-Type': 'application/json',
            },
        }).json();
    del_invocation['Content-Type'] = 'application/json';
    const res = http.post(`${tinycloud}/invoke`,
        "",
        {
            headers: del_invocation
        }
    );
    check(res, {
        'teardown delete succeeds': (r) => r.status === 200,
    });
}

export function handleSummary(summary) {
    return handleTc268Summary(summary, {
        depth: matrix.depth,
        payloadBytes: matrix.payloadBytes,
        concurrency: preAllocatedVUs,
        database: matrix.database,
        blockStore: matrix.blockStore,
        rate,
        maxVUs: options.scenarios.warmup.maxVUs,
        warmupSeconds,
        measureSeconds,
        minSamples,
    }, 'tc268-json-get-summary.json');
}

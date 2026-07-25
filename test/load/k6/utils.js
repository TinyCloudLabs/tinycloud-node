import { check } from 'k6';
import http from 'k6/http';
import {
  buildBootstrapUrls,
  buildInvocationPlan,
} from './tc268.mjs';

export const tinycloud = __ENV.TINYCLOUD || "http://127.0.0.1:8000";
export const signer = __ENV.SIGNER || "http://127.0.0.1:3000";

export function bootstrap_urls(id) {
    return buildBootstrapUrls({ tinycloud, signer, id });
}

export function setup_namespace(tinycloud, signer, id, depth = 0) {
  const urls = buildBootstrapUrls({ tinycloud, signer, id });
  let namespace_id = http.get(urls.spaceId).body;
  let peer_id = http.get(`${tinycloud}/peer/generate/${encodeURIComponent(namespace_id)}`).body;
    let namespace_creation = http.post(urls.createSpace,
        JSON.stringify({ peer_id }),
        {
            headers: {
                'Content-Type': 'application/json',
            },
        }).json();
    let res = http.post(`${tinycloud}/delegate`,
        null,
        {
            headers: namespace_creation,
        });
    check(res, {
        'namespace creation is succesful': (r) => r.status === 200,
    });
    console.log(`[${id} CREATE NAMESPACE] (${res.headers["TinyCloud-Trace-Id"]}) -> ${res.status}`);
    let session_delegations = http.post(`${signer}/sessions/${id}/create`,
        JSON.stringify({ depth }),
        {
            headers: {
                'Content-Type': 'application/json',
            },
        }).json();
    if (!Array.isArray(session_delegations)) {
        session_delegations = [session_delegations];
    }
    for (const [index, session_delegation] of session_delegations.entries()) {
        res = http.post(`${tinycloud}/delegate`,
            null,
            {
                headers: session_delegation,
            });
        check(res, {
            [`session delegation ${index} is succesful`]: (r) => r.status === 200,
        });
        console.log(`[${id} SESSION DELEGATION ${index}] (${res.headers["TinyCloud-Trace-Id"]}) -> ${res.status}`);
    }
}

export function prepare_signed_invocations({
  tinycloud,
  signer,
  sessionId,
    action,
    count,
    depth,
    payloadBytes,
    nameFactory = (entry) => entry.invocationName,
}) {
    const plan = buildInvocationPlan({
        count,
        namespaceId: sessionId,
        action,
        depth,
        payloadBytes,
    });
    const prepared = plan.map((entry) => {
        const name = nameFactory(entry);
        const headers = http.post(`${signer}/sessions/${sessionId}/invoke`,
            JSON.stringify({ name, action, depth }),
            {
                headers: {
                    'Content-Type': 'application/json',
                },
            }).json();
        headers['Content-Type'] = action === 'put' ? 'application/octet-stream' : 'application/json';

        return {
            ...entry,
            headers,
            bodySeed: entry.invocationName,
        };
    });

    return prepared;
}

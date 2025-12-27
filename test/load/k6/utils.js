import { check } from 'k6';
import http from 'k6/http';

export const tinycloud = __ENV.TINYCLOUD || "http://127.0.0.1:8000";
export const signer = __ENV.SIGNER || "http://127.0.0.1:3000";

export function setup_namespace(tinycloud, signer, id) {
    let namespace_id = http.get(`${signer}/namespace_id/${id}`).body;
    let peer_id = http.get(`${tinycloud}/peer/generate/${encodeURIComponent(namespace_id)}`).body;
    let namespace_creation = http.post(`${signer}/namespaces/${id}`,
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
    let session_delegation = http.post(`${signer}/sessions/${id}/create`).json();
    res = http.post(`${tinycloud}/delegate`,
        null,
        {
            headers: session_delegation,
        });
    check(res, {
        'session delegation is succesful': (r) => r.status === 200,
    });

    console.log(`[${id} SESSION DELEGATION] (${res.headers["TinyCloud-Trace-Id"]}) -> ${res.status}`);
}

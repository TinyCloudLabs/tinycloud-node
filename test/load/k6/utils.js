import { check } from 'k6';
import http from 'k6/http';

export const tinycloud = __ENV.TINYCLOUD || "http://127.0.0.1:8000";
export const signer = __ENV.SIGNER || "http://127.0.0.1:3000";

export function setup_orbit(tinycloud, signer, id) {
    let orbit_id = http.get(`${signer}/orbit_id/${id}`).body;
    let peer_id = http.get(`${tinycloud}/peer/generate/${encodeURIComponent(orbit_id)}`).body;
    let orbit_creation = http.post(`${signer}/orbits/${id}`,
        JSON.stringify({ peer_id }),
        {
            headers: {
                'Content-Type': 'application/json',
            },
        }).json();
    let res = http.post(`${tinycloud}/delegate`,
        null,
        {
            headers: orbit_creation,
        });
    check(res, {
        'orbit creation is succesful': (r) => r.status === 200,
    });
    console.log(`[${id} CREATE ORBIT] (${res.headers["TinyCloud-Trace-Id"]}) -> ${res.status}`);
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

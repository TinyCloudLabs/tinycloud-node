# TC-313: Synthetic write probe

A small, self-contained probe that drives a **real, signed, end-to-end write**
against the live TinyCloud node and fails when any stage is too slow. It runs on
a schedule from GitHub Actions (`.github/workflows/write-probe.yml`).

## Why (the "healthz is blind to writes" rationale)

During the 2026-07-27/28 write-degradation incident, `/healthz` returned 200 in
~300ms while `kv.put` took 46s and `/delegate` blew past Cloudflare's 100s
ceiling. `/healthz` and `/version` never touch the database or the write path,
so uptime monitoring stayed green while writes were effectively down. This probe
exercises the write path a real client uses, so degradation shows up as a failed
job (the alert) instead of a silent outage.

## What it measures

Each stage is timed independently and checked against its own threshold:

| Stage       | Threshold | Why |
|-------------|-----------|-----|
| `signIn`    | 15s       | SIWE sign-in + delegation activation — the `/delegate` path worst-hit in the incident. Healthy ~1-3s; 15s is far under the 100s CF wall but clearly degraded. |
| `kv.put`    | 5s        | The write. Healthy sub-second; 5s = write path degrading before a hard failure. |
| `kv.get`    | 5s        | Read-back verification (also asserts the bytes round-trip). |
| `kv.delete` | 5s        | Cleanup; also exercises the write path so the probe space never accumulates data. |

Any breach — or any error (network, auth, readback mismatch) — exits non-zero
and fails the job. There is no graceful fallback by design: a silent pass would
recreate the exact blind spot this probe exists to remove.

Thresholds are overridable via env: `PROBE_THRESHOLD_SIGNIN_MS`,
`PROBE_THRESHOLD_PUT_MS`, `PROBE_THRESHOLD_GET_MS`, `PROBE_THRESHOLD_DELETE_MS`.

## Approach: SDK, not the `tc` CLI

The probe uses the published `@tinycloud/node-sdk` (`TinyCloudNode`) — the
canonical programmatic client path (`signIn()` → `kv.put/get/delete`). This is
far less code and infra than the alternatives evaluated:

- The `tc` CLI would require building the whole Rust node binary in CI.
- The `test/load/k6/` path (TC-268) needs a long-running Rust **signer** sidecar
  server plus k6 — heavyweight for a 15-minute cron.

The SDK path installs one npm package and drives the identical end-to-end write
a real user would.

## Operator setup

Set **one** GitHub Actions secret on the repository (Settings → Secrets and
variables → Actions):

- **`PROBE_PRIVATE_KEY`** — a hex private key (with or without `0x`) for a
  **throwaway** identity used only by the probe. It operates in its own isolated
  space (prefix `tc313-write-probe`), so it never touches user data. Do **not**
  reuse a real user or prod key.

Optional secret/vars: `PROBE_HOST` (defaults to `https://node.tinycloud.xyz`),
`PROBE_PREFIX`, and the threshold overrides above.

Generate a throwaway key, e.g.:

```bash
node -e "console.log('0x'+require('crypto').randomBytes(32).toString('hex'))"
```

## Reading a failure

A red scheduled run means the write path crossed a threshold (or errored). The
job log prints one line per stage, e.g.:

```
[probe] signIn     1820ms (threshold 15000ms) ok
[probe] put         410ms (threshold 5000ms) ok
[probe] get         205ms (threshold 5000ms) ok
[probe] delete      190ms (threshold 5000ms) ok
[probe] PASS: all stages within thresholds
```

On failure the offending stage is flagged `SLOW` and a `FAIL:` summary names
the stage(s) and measured latency. Match the slow stage to the incident
playbook: `signIn` slowness points at `/delegate`; `put`/`delete` slowness
points at the DB write path.

## Running locally

```bash
cd test/probe
npm install
PROBE_PRIVATE_KEY=0x... npm run probe
# type-check only:
npm run typecheck
```

## Wiring failure alerts to Slack (optional, later)

A failed scheduled job already emails watchers via GitHub's notification
settings — no extra infra. If/when the repo adopts a Slack-notify pattern, add a
final step to the job guarded by `if: failure()` that posts to a
`SLACK_WEBHOOK_URL` secret, e.g. `slackapi/slack-github-action`. Keep it as a
separate `if: failure()` step so a Slack outage never masks the probe verdict.

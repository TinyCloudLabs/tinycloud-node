# Write Probe (TC-313, TC-1176)

A small, self-contained probe that drives **real, signed, end-to-end reads and
writes** against the live TinyCloud node. It runs from GitHub Actions
(`.github/workflows/write-probe.yml`, workflow name **Write Probe**) every 5
minutes, and in a dense **promote watch** after every Phala deploy.

## Why

`/healthz` and `/version` never touch the database, the read path or the write
path, so uptime monitoring stays green while users are broken:

- **2026-07-27/28 (TC-313):** `/healthz` returned 200 in ~300ms while `kv.put`
  took 46s and `/delegate` blew past Cloudflare's 100s ceiling.
- **2026-10-14 (TC-1176):** signed-in KV reads and SQL returned 504 after ~62s
  for every account from ~23:35 to 23:53 UTC, while `/healthz`, `/version`,
  401s and writes stayed green. This probe failed at 23:36 and 23:50, but a red
  scheduled run only e-mails whoever last edited the cron line, so nobody was
  paged.

## What it does

### Normal mode (every scheduled run)

**Read half — the paging signal.** Each stage has a hard **20s** client
deadline (`STAGE_DEADLINE_MS`):

| Stage    | What                                                                  |
|----------|-----------------------------------------------------------------------|
| `signin` | SIWE sign-in + delegation activation                                  |
| `space`  | ensure the probe's own space exists (idempotent)                      |
| `kv`     | signed-in `kv.get` of the fixed key `read-probe/fixed`                |
| `sql`    | signed-in `SELECT v FROM read_probe WHERE id = 1` (default database)  |

The fixed key and row are written once by the probe itself the first time they
are missing; after that they are only read.

- **Good read** of both KV and SQL: ping the Better Stack heartbeat **Node
  authorized reads (Write Probe)**. A ping also resolves an open heartbeat
  incident.
- **Failed read** (any stage over 20s or erroring): count it in a small state
  file (`.state/probe-state.json`, carried between runs in the Actions cache and
  shared with dense mode). KV and SQL are counted separately; a failed `signin`
  or `space` counts against both. The heartbeat is pinged only while **both**
  are at zero, so a healthy SQL read never hides a broken KV read. From the
  **2nd failure in a row** of either, the probe POSTs the heartbeat's `/fail`
  URL with one line, which pages team@:

  ```
  TC-1176 node read probe FAIL (2 in a row, normal): stage=kv outcome="timeout >=20s" duration_ms=20004 build=1.20.6 host=node.tinycloud.xyz at=2026-10-15T01:05:07Z
  ```

  `outcome` is one of `timeout >=20s`, `HTTP <code>`, `connection refused`,
  `DNS`, `connection reset`, `connect timeout`, `node /info not OK`,
  `error <SDK code>`, or `slow <s> ><threshold>` (dense mode). `build` is the
  node version from public `/version`, or `unknown(<why>)` if `/version` is
  unreachable. **Read it as:** a read stage timing out while `build` is known
  means a **read hang** (TC-1176; Amos's runbook: recovery restart); `signin`
  failing with `HTTP 5xx`, `connection refused`, `DNS` or `build=unknown(...)`
  means the **node is down** (rollback territory).

  While a failure streak lasts, `/fail` is re-sent at most every 4 minutes,
  counted from the last report Better Stack **accepted** (2xx): a rejected or
  undelivered report is retried on the next sample. One failure alone never
  pages: a ~60s node restart during a deploy is absorbed.
- **Heartbeat not accepted:** if a ping or `/fail` gets a non-2xx or no
  response, the job ends red (logged as `heartbeat ... NOT accepted`), so a
  broken heartbeat shows before it turns into a false "missed" page.

**Write half — TC-313's round-trip.** `put -> get -> delete` of a fresh key,
each with its latency threshold (default 5s, `PROBE_THRESHOLD_{PUT,GET,DELETE}_MS`)
and the same 20s deadline. A breach fails the job (GitHub e-mail) but does not
touch the heartbeat.

### Dense mode — promote watch

`workflow_dispatch` with `mode=dense`: one job that signs in once, then reads

- every **30s for 5 min** (10 samples, alternating KV and SQL so each sees at
  most one request per 30s), then
- every **5 min for 60 min** (12 samples, KV and SQL each).

A read over **5s** (`DENSE_SLOW_MS`) or failing counts; **2 in a row** of KV or
of SQL POST `/fail` with the same one-line body (`dense` instead of `normal`);
the heartbeat is pinged once both are healthy. The job summary tables every
sample's latency, and the job ends red if any sample failed or a heartbeat
report wasn't accepted.

**One owner of the heartbeat at a time.** A dense watch starts from the failure
state the last normal run saved and saves its own at the end, so a streak
carries across modes. Scheduled runs skip themselves while a dense watch is
queued or running, and the dense job waits for any normal run already in
progress to finish before its first sample. They use separate concurrency
groups, so a scheduled run can never cancel a pending dense watch. Both checks
fail closed: a scheduled run that can't look up runs (after 3 tries) skips
itself, and a dense watch without a confirmed handover within 10 min ends red
without sampling. Re-dispatch it in that case.

`docker.yml` dispatches it automatically after every Phala deploy attempt (job
`promote-watch`). To run it by hand (Amos, QA):

```bash
gh workflow run write-probe.yml -R TinyCloudLabs/tinycloud-node --ref main -f mode=dense
gh run list -R TinyCloudLabs/tinycloud-node --workflow write-probe.yml --limit 3 \
  --json databaseId,displayTitle,status,conclusion,createdAt
```

The dense run's title is `Write Probe (dense promote watch)`. Watch its
`status`/`conclusion` (`success` = every sample under 5s), the job summary
table, or the log lines below. No secrets are needed to trigger or observe it.

## Log format

One line per stage, per sample:

```
[probe] mode=dense sample=3 stage=kv ms=812 threshold_ms=5000 result=ok outcome="ok"
[probe] mode=normal sample=1 stage=kv ms=20004 threshold_ms=20000 result=fail outcome="timeout >=20s"
[probe] read verdict=fail failures_kv=2 failures_sql=0 heartbeat_action=fail
[probe] fail report body: TC-1176 node read probe FAIL (2 in a row, normal): stage=kv ...
[probe] heartbeat fail sent: HTTP 200
```

Raw error details are logged as `stage=<s> error: <message>` with the private
key and heartbeat URL redacted. The heartbeat URL itself is never logged.

## Alert timing

| Situation                               | Pages after                                   |
|-----------------------------------------|-----------------------------------------------|
| Reads hang or fail (normal mode)        | the 2nd failed run in a row (~5–15 min)        |
| Reads slow or fail after a promote      | the 2nd bad dense sample (~30s–5 min)          |
| GitHub stops running the probe at all   | 60 min without a ping (heartbeat period 5 min + grace 55 min) |

The long grace is deliberate: GitHub delays and drops scheduled runs under load.
On this workflow (cron `*/15`, 600 runs, 2026-10-06..14) the gap between runs
was p50 19 min, p99 48 min, max 54 min. Read failures don't wait for the grace;
they alert through `/fail`.

## No pause for deploys

Per Amos (TC-1176): the probe keeps running through and after node promotes. A
~60s restart is absorbed by the 2-in-a-row rule, and TC-1176 began ~40 min after
a promote. The only switch is a manual **emergency** one, recorded in TC-1176:

```bash
gh workflow disable "Write Probe" -R TinyCloudLabs/tinycloud-node   # stop probing
# and pause the heartbeat ("paused": true in tinycloud-dev ops/betterstack/uptime.json, then apply)
gh workflow enable "Write Probe" -R TinyCloudLabs/tinycloud-node    # undo
```

## Exercising the alert path

`force_failure=true` points the run at `https://read-probe-forced-failure.invalid`
(reserved TLD, fails at DNS). Two forced runs in a row really page team@:

```bash
gh workflow run write-probe.yml -R TinyCloudLabs/tinycloud-node --ref main -f force_failure=true
# wait for it to finish, then once more; the next good scheduled run resolves the incident
```

## Operator setup

GitHub Actions secrets on the repository:

- **`PROBE_PRIVATE_KEY`** — hex private key (with or without `0x`) of a
  **throwaway** identity used only by the probe, in its own space (prefix
  `tc313-write-probe`). Never a real user or prod key. Generate one with
  `node -e "console.log('0x'+require('crypto').randomBytes(32).toString('hex'))"`
  and pipe it into `gh secret set`, never through chat.
- **`BETTERSTACK_HEARTBEAT_URL`** — the heartbeat's secret URL. The heartbeat is
  managed as code in tinycloud-dev `ops/betterstack/uptime.json`; its README
  pipes the URL from `apply.ts --heartbeat-url` straight into `gh secret set`.
  Unset, the probe still runs and logs `heartbeat ... skipped`.

Optional secrets: `PROBE_HOST` (default `https://node.tinycloud.xyz`),
`PROBE_PREFIX`, and the write thresholds above.

## Approach: SDK, not the `tc` CLI

The probe uses the published `@tinycloud/node-sdk` (`TinyCloudNode`), the
canonical programmatic client path. The `tc` CLI would need building in CI, and
`test/load/k6/` needs a long-running Rust signer sidecar.

`probe-core.ts` holds everything that doesn't need the SDK (deadlines, outcome
classification, the failure rule, heartbeat reporting, the dense loop);
`write-probe.ts` wires it to `TinyCloudNode`.

## Running locally

```bash
cd test/probe
npm install
npm test                 # unit tests (stub client; no node, no secrets)
npm run typecheck
PROBE_PRIVATE_KEY=0x... npm run probe                  # normal mode
PROBE_PRIVATE_KEY=0x... PROBE_MODE=dense npm run probe # promote watch (~66 min)
```

Without `BETTERSTACK_HEARTBEAT_URL` nothing is reported to Better Stack.

## DB saturation probe (TC-1601)

`db-saturation-run.ts` checks each target in `db-saturation-targets.json` once
per run (`db-saturation-probe.yml`, every 5 min). It reads PlanetScale metrics
for that branch only and sends one Better Stack heartbeat decision per target.

- **CPU:** breach when at least 13 of the last 15 one-minute points of
  `planetscale_primary_pods_cpu_util_percentages` are above `cpu_pct` (85).
  Points newer than 90 s are ignored for ingestion lag.
- **Pool:** same counting on the target's `pool` rule. The shipped target pins
  direct Postgres, port 5432: active connections >= 15
  (`TINYCLOUD_DATABASE__MAX_CONNECTIONS`). `pool: null` is a config fault. A
  PgBouncer port (6432) would use `planetscale_pgbouncer_pools_client` waiting clients > 0.
- **Outcomes:** breach or config fault -> `/fail` with numeric counts. Healthy
  -> ping. Unknown (fewer than max(`min_points`, `min_breach_points`) valid points, or no series) or transient API error
  (429, 5xx, timeout) -> no call, so the missed-heartbeat alert fires.
- **Secrets:** each target reads the env names in its `token_secret` and
  `heartbeat_secret`. A target whose secrets are unset is skipped. The token is
  a PlanetScale service token (`ID:TOKEN`) with `read_branch` on that database.

Proof runs (default branch only): `gh workflow run db-saturation-probe.yml -f threshold_pct=1`
should send `/fail`; a run with no inputs should send a ping.

Local: `npm run probe:db` (skips when secrets are unset). Tests: `npm test`.

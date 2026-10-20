/**
 * TC-1601 runner: one heartbeat decision per target in db-saturation-targets.json.
 *
 *   tsx db-saturation-run.ts
 *
 * Env:
 *   DB_TARGET        optional target label; default runs every target
 *   THRESHOLD_PCT    optional manual CPU threshold (0-100). Proof runs only; the
 *                    label in the log and the /fail body says so.
 *   <token_secret>   PlanetScale token, ID:TOKEN, read_branch on that database only
 *   <heartbeat_secret> Better Stack heartbeat URL for that target
 *
 * Heartbeat: ok -> ping; breach or config fault -> /fail; unknown or transient
 * API error -> nothing (the missed-heartbeat alert handles it). A target whose
 * token or heartbeat env is unset is skipped, like write-probe. Logs never
 * contain the token, the heartbeat URL, or query text.
 */
import { readFileSync } from "node:fs";
import { classify, detail, heartbeatUrl, redact, report, type Delivery, type Fetch } from "./probe-core";
import { ConfigFault, evaluateTarget, loadTargets, metricsUrl, parseSeries, type Series, type Target, type Verdict } from "./db-saturation";

const TIMEOUT_MS = 10_000;
const TARGETS_FILE = new URL("./db-saturation-targets.json", import.meta.url);

async function fetchSeries(t: Target, token: string, fetchFn: Fetch): Promise<Series[]> {
  const res = await fetchFn(metricsUrl(t), {
    headers: { authorization: token, accept: "application/json" },
    signal: AbortSignal.timeout(TIMEOUT_MS),
  });
  // 429 and 5xx are transient: no heartbeat call, the missed-heartbeat alert covers it.
  if (res.status === 429 || res.status >= 500) throw new Error(`planetscale HTTP ${res.status}`);
  // Any other non-2xx is a token, scope or path fault and must page now.
  if (!res.ok) throw new ConfigFault(`planetscale HTTP ${res.status}`);
  return parseSeries(await res.json());
}

function parseOverride(raw: string | undefined): number | undefined {
  if (raw === undefined || raw.trim() === "") return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0 || n > 100) throw new ConfigFault(`THRESHOLD_PCT must be 0-100, got ${raw}`);
  return n;
}

function failBody(label: string, verdict: Verdict, now: Date): string {
  const at = now.toISOString().replace(/\.\d{3}Z$/, "Z");
  return `TC-1601 db saturation ${verdict.status}: target=${label} ${verdict.detail} at=${at}`;
}

async function main(): Promise<number> {
  const only = process.env.DB_TARGET?.trim() || undefined;
  const override = parseOverride(process.env.THRESHOLD_PCT);
  const targets = loadTargets(JSON.parse(readFileSync(TARGETS_FILE, "utf8")));
  const selected = only ? targets.filter((t) => t.label === only) : targets;
  if (selected.length === 0) throw new ConfigFault(`no target named ${only}`);

  let deliveryFailed = false;
  for (const target of selected) {
    const token = process.env[target.token_secret]?.trim();
    const heartbeatRaw = process.env[target.heartbeat_secret]?.trim();
    if (!token || !heartbeatRaw) {
      const missing = !token ? target.token_secret : target.heartbeat_secret;
      console.log(`${target.label}: skipped (${missing} not set)`);
      continue;
    }
    const heartbeat = heartbeatUrl(heartbeatRaw);
    const t = override === undefined ? target : { ...target, cpu_pct: override };
    const label = override === undefined ? target.label : `${target.label} (manual cpu threshold ${override}%)`;
    const now = new Date();

    let verdict: Verdict;
    try {
      verdict = evaluateTarget(t, await fetchSeries(t, token, fetch), Math.floor(now.getTime() / 1000));
    } catch (error) {
      if (!(error instanceof ConfigFault)) {
        console.log(`${label}: check skipped, no heartbeat: ${redact(classify(error), [token])}`);
        continue;
      }
      verdict = { status: "config", detail: error.message };
    }

    console.log(`${label}: ${verdict.status} ${redact(verdict.detail, [token], 600)}`);
    if (verdict.status === "unknown") continue;
    const action = verdict.status === "ok" ? "ping" : "fail";
    const body = action === "fail" ? redact(failBody(label, verdict, now), [token], 400) : undefined;
    const delivery: Delivery = await report(action, heartbeat, body, fetch);
    console.log(delivery.line);
    if (!delivery.ok) deliveryFailed = true;
  }
  return deliveryFailed ? 1 : 0;
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (err: unknown) => {
    const secrets = Object.entries(process.env)
      .filter(([k, v]) => /^(PLANETSCALE_METRICS_TOKEN|BETTERSTACK_HEARTBEAT_URL)_/.test(k) && v)
      .map(([, v]) => v as string);
    console.error(`[db-saturation] crashed: ${detail(err, secrets)}`);
    process.exitCode = 1;
  },
);

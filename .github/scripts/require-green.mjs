// Fail unless every required check passed on main for one commit.
//
// Usage: node require-green.mjs <repo> <sha> <workflow-path>=<check name> ...
// Example: node require-green.mjs TinyCloudLabs/tinycloud-node "$SHA" \
//            ".github/workflows/rust.yml=capabilities"
//
// Needs `gh` authenticated with checks:read and actions:read (GH_TOKEN).
// A check counts only if GitHub Actions ran it in a push-to-main run of the
// named workflow in this repository, so a same-named check from another
// workflow, a pull_request run or another GitHub App cannot satisfy it. Among
// those, the newest attempt (highest id) decides: a rerun that failed beats an
// older success, and an unfinished newer attempt leaves the check pending.
// Any API error or missing check fails closed.
import { execFileSync } from 'node:child_process';

const GITHUB_ACTIONS_APP_ID = 15368;
const [repo, sha, ...specs] = process.argv.slice(2);
if (!/^[\w.-]+\/[\w.-]+$/.test(repo ?? '') || !/^[0-9a-f]{40}$/.test(sha ?? '') || specs.length === 0) {
  console.error('Usage: require-green.mjs <owner/repo> <40-hex sha> <workflow-path>=<check name> ...');
  process.exit(2);
}
const required = specs.map((spec) => {
  const i = spec.indexOf('=');
  if (i <= 0 || i === spec.length - 1) {
    console.error(`Bad requirement '${spec}'; expected <workflow-path>=<check name>`);
    process.exit(2);
  }
  return { path: spec.slice(0, i), name: spec.slice(i + 1) };
});

function pages(endpoint, key) {
  const out = execFileSync('gh', ['api', '--paginate', '--slurp', endpoint], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  const parsed = JSON.parse(out);
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.some((page) =>
    !Array.isArray(page?.[key]) || !Number.isInteger(page.total_count) || page.total_count < 0
  )) {
    throw new Error(`Incomplete response from ${endpoint}`);
  }
  const items = parsed.flatMap((page) => page[key]);
  if (parsed.some((page) => items.length < page.total_count)) {
    throw new Error(`Incomplete response from ${endpoint}: fewer items than total_count`);
  }
  return items;
}

const runs = pages(`repos/${repo}/actions/runs?head_sha=${sha}&per_page=100`, 'workflow_runs');
const checks = pages(`repos/${repo}/commits/${sha}/check-runs?filter=all&per_page=100`, 'check_runs');

let failed = false;
for (const { path, name } of required) {
  // Check suites of push-to-main runs of this workflow on this commit.
  const suites = new Set(runs
    .filter((run) => run.path === path && run.event === 'push' && run.head_branch === 'main' &&
      run.head_sha === sha && run.repository?.full_name === repo &&
      run.head_repository?.full_name === repo)
    .map((run) => run.check_suite_id));
  const attempts = checks.filter((check) =>
    check.name === name && check.head_sha === sha && check.app?.id === GITHUB_ACTIONS_APP_ID &&
    suites.has(check.check_suite?.id)
  );
  let newest;
  for (const check of attempts) {
    if (!Number.isSafeInteger(check.id) || check.id <= 0) throw new Error(`Invalid check-run id: ${check.id}`);
    if (!newest || check.id > newest.id) newest = check;
  }
  let state;
  if (!newest) state = 'missing';
  else if (newest.status !== 'completed') state = `pending (${newest.status})`;
  else state = newest.conclusion;
  const where = newest ? ` ${newest.html_url}` : '';
  if (state === 'success') {
    console.log(`ok   ${name} [${path}]${where}`);
  } else {
    failed = true;
    console.log(`::error title=Required check not green::${name} [${path}] on ${sha} is ${state}${where}`);
  }
}
if (failed) {
  console.log(`::error::Refusing to ship ${sha}: every required check must have passed on main for this commit. Wait for main CI to finish, or fix and re-run it.`);
  process.exit(1);
}
console.log(`All ${required.length} required checks passed on main for ${sha}.`);

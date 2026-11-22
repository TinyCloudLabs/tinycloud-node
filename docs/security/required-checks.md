# Required checks and the main ruleset

This file is the spec for the pre-release security gate on `main` and for the
production secret move. Repository settings are applied by an org admin
(Amos), not by CI or agents. Every command below uses the read-only state
recorded on 2026-11-22; re-read it before applying.

## What gates a release today

| Gate | Where | Fails closed on |
| --- | --- | --- |
| `test (workspace, PostgreSQL-backed)` | `rust.yml` `test-gate` | any test leg not `success` |
| `capabilities` | `rust.yml` | generated capability artifacts, Policy/v3 probe contract, main-only deploy guard |
| `gitleaks` | `security.yml` | a secret in the PR's commits (PR), or anywhere in history not in `.gitleaksignore` (main) |
| `cargo-deny (workspace)` | `security.yml` | a RustSec advisory, banned version or unknown source not baselined in `deny.toml` |
| require-green | `docker.yml` `deploy-phala`, first step | any of the first three checks not `success` on main for the shipped commit |

`deploy-phala` runs `.github/scripts/require-green.mjs` before it touches a
deploy secret. A check counts only when GitHub Actions ran it in a push-to-main
run of the named workflow on that exact commit. The newest attempt decides, so
a failed rerun beats an older success. A missing, pending or failed check, or
an API error, refuses the deploy. A rollback (`rollback_image_revision`) must
have passed `test (workspace, PostgreSQL-backed)` and `capabilities` itself.
Its `gitleaks` is read on the dispatched main commit instead, because that run
scans the full history including the rollback revision; the next step,
`check-deploy-ref.sh`, proves the revision is in main's history.

The trivy image scan is intentionally not run on the node image. The runtime
stage is `FROM scratch`, so trivy finds 0 targets: no OS packages, and the
static binary carries no dependency list. `cargo-deny` covers the same crates
from `Cargo.lock`, with all features. Embedding the list with `cargo auditable
build` would let an image scanner see them; that is a possible later item.

## Baselines

- `.gitleaksignore`: fingerprints of the findings in full history at
  `ccc14ec4`, each file under a comment saying why it is not a live secret.
  `.gitleaks.toml` allowlists `did:key` identifiers, which are public keys.
  For a new finding in a PR: if it is a live credential, rotate it first and
  never baseline it. If it is a fixture or a public value, add its fingerprint
  (`gitleaks git --report-format json` prints it) under a comment with the
  reason, in a PR reviewed by security.
- `deny.toml`: every RustSec advisory open at `ccc14ec4`, each with a reason.
  An advisory not listed fails the job. Delete an entry when the upgrade that
  clears it lands; `cargo deny` warns `advisory-not-detected` for stale ones.
  Four IDs (RUSTSEC-2026-0349, -0382, -0381, -0258) are listed for their
  unfixable old lines (rustls 0.21, rustls-webpki 0.101, webpki-roots 0.25,
  h2 0.3). Their fixable lines are held at or above the fix by `[bans] deny`,
  because cargo-deny cannot ignore an advisory for a single version.

## Ruleset on main

Current state (`gh api repos/TinyCloudLabs/tinycloud-node/rules/branches/main`):

```json
[]
```

`gh api repos/TinyCloudLabs/tinycloud-node/branches/main/protection` returns
`404 Branch not protected`. The two repository rulesets target other refs:
24961493 (retired deploy branches, locked) and 25016290 (`refs/tags/v*`). So a
direct push to `main` runs no check first.

Apply a check as required only after it has passed once on `main`, as a
push-to-main run. `test (workspace, PostgreSQL-backed)` and `capabilities`
already have. `gitleaks` qualifies after this change merges and its first main
run is green. Add `cargo-deny (workspace)` only after the lockfile PR
(TinyCloudLabs/tinycloud-node#700, `deps: patch rustls, webpki, h2, url,
ctutils advisories`) has landed and `cargo-deny (workspace)` has passed on
main.

After (create; `integration_id` 15368 is GitHub Actions, so another app cannot
satisfy the check):

```sh
gh api -X POST repos/TinyCloudLabs/tinycloud-node/rulesets --input - <<'JSON'
{
  "name": "main: PR plus pre-release security checks",
  "target": "branch",
  "enforcement": "active",
  "conditions": { "ref_name": { "include": ["~DEFAULT_BRANCH"], "exclude": [] } },
  "bypass_actors": [],
  "rules": [
    { "type": "deletion" },
    { "type": "non_fast_forward" },
    {
      "type": "pull_request",
      "parameters": {
        "required_approving_review_count": 0,
        "dismiss_stale_reviews_on_push": false,
        "require_code_owner_review": false,
        "require_last_push_approval": false,
        "required_review_thread_resolution": false
      }
    },
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "test (workspace, PostgreSQL-backed)", "integration_id": 15368 },
          { "context": "capabilities", "integration_id": 15368 },
          { "context": "gitleaks", "integration_id": 15368 }
        ]
      }
    }
  ]
}
JSON
```

Later, once #700 has landed and `cargo-deny (workspace)` has passed on main,
append `{ "context": "cargo-deny (workspace)", "integration_id": 15368 }` with
`gh api -X PUT repos/TinyCloudLabs/tinycloud-node/rulesets/<id> --input -`,
sending the full ruleset.

Notes:
- No bypass actors, including org admins: a release goes through a PR like any
  other change. Nothing in this repository's workflows pushes to `main`;
  release-plz opens a release PR and pushes only `v*` tags (ruleset 25016290).
- 0 required approvals: the rule forces CI to run before a merge without adding
  a review queue. Raise it separately if wanted.
- Not strict (no up-to-date requirement), so a PR need not be rebased on every
  main commit. The push-to-main run is still what `deploy-phala` checks.

Verify: `gh api repos/TinyCloudLabs/tinycloud-node/rules/branches/main` lists
the four rule types above. A test PR shows the three checks as Required.

Undo: `gh api -X DELETE repos/TinyCloudLabs/tinycloud-node/rulesets/<id>`
(returns 204). Or set `"enforcement": "disabled"` with a PUT to keep it for
later.

## Production deploy secrets: repository level to the production environment

Ruling (Naomi, 2026-11-22 10:05Z): deploy tokens live only in the main-limited
`production` environment, and PR or branch runs get no deploy token. Today
these production values are repository secrets. Every workflow on any branch,
including a same-repository PR, can read them, even though every job that uses
them already declares `environment: production` (docker.yml `rollback-audit`
and `deploy-phala`, export-share-invitation-descriptor.yml, renewals-switch.yml).
An environment secret takes precedence over a repository secret of the same
name, so creating them in the environment changes nothing for those jobs; no
workflow edit is needed.

Before (`gh api repos/TinyCloudLabs/tinycloud-node/environments/production/secrets`):
`PHALA_CLOUD_API_KEY`, `PROD_TINYCLOUD_ADMIN_SECRET`,
`PROD_TINYCLOUD_BETTERSTACK_SOURCE_TOKEN`, `PROD_TINYCLOUD_DATABASE_URL`,
`PROD_TINYCLOUD_NODE_STATS_READ_TOKEN`. Branch policy: `main` and `v*` tags.

Repository-level production secrets used only by `environment: production` jobs:

| Secret | Used at | In `production` env today |
| --- | --- | --- |
| `PROD_TINYCLOUD_DATABASE_URL` | docker.yml rollback-audit, deploy-phala | yes (repo copy is a duplicate) |
| `PROD_TINYCLOUD_KEYS_SECRET` | export-share-invitation-descriptor.yml | **no**, despite the TC-971 comment there |
| `PROD_TINYCLOUD_AWS_ACCESS_KEY_ID`, `PROD_TINYCLOUD_AWS_SECRET_ACCESS_KEY`, `PROD_TINYCLOUD_AWS_REGION` | deploy-phala | no |
| `PROD_TINYCLOUD_S3_BUCKET`, `PROD_TINYCLOUD_S3_ENDPOINT` | deploy-phala | no |
| `PROD_TINYCLOUD_CLOUDFLARE_API_TOKEN`, `PROD_TINYCLOUD_CERTBOT_EMAIL`, `PROD_TINYCLOUD_DSTACK_GATEWAY_DOMAIN` | deploy-phala | no |
| `PROD_TINYCLOUD_QUOTA_URL` | deploy-phala | no |
| `PROD_TINYCLOUD_SHARE_TRUST_BUNDLE_BASE64` | deploy-phala | no |

Repository secrets no workflow references: `AWS_DEPLOY_ROLE_ARN`,
`GH_PACKAGE_PUSH_TOKEN`, `TINYCLOUD_AWS_ACCESS_KEY_ID`,
`TINYCLOUD_AWS_SECRET_ACCESS_KEY`.

After: those twelve `PROD_TINYCLOUD_*` names exist only in the `production`
environment. The four unreferenced secrets are deleted, or moved after their
owner confirms they are unused.

Steps (GitHub cannot read a secret value back, so each value comes from its
source of truth, never from this repository):

1. For each name in the table that is not yet in the environment:
   `gh secret set <NAME> --env production -R TinyCloudLabs/tinycloud-node`
   (value on stdin).
2. Run `docker.yml` once with `deploy_phala: false` to prove nothing changed
   for builds, then do the next production deploy as usual.
3. Delete the repository copies:
   `gh secret delete <NAME> -R TinyCloudLabs/tinycloud-node`.
4. Verify: `gh api repos/TinyCloudLabs/tinycloud-node/actions/secrets --jq '.secrets[].name'`
   lists no `PROD_` name.

Undo: `gh secret set <NAME> -R TinyCloudLabs/tinycloud-node` with the same
value from its source of truth. Jobs keep reading the environment copy, which
wins, so the undo only widens exposure again.

Out of scope for this ruling, listed for the owner: `RELEASE_PLZ_TOKEN`
(release-plz.yml, pushes tags and publishes crates) and `HOMEBREW_TAP_TOKEN`
(release.yml) are publish tokens at repository level. `PROBE_PRIVATE_KEY`,
`BETTERSTACK_HEARTBEAT_URL*` and `PLANETSCALE_METRICS_TOKEN_NODE_DB` are
monitoring credentials for scheduled probes.

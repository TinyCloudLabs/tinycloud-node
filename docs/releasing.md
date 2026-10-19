# Releasing tinycloud-node

**Version numbers in this repo are chosen by hand.** release-plz is configured
and runs on every push to `main`, but it structurally cannot bump the version —
see [Why the version bump is manual](#why-the-version-bump-is-manual). Do not
assume a green Release-plz run means anything was released.

The version in `tinycloud-node-server/Cargo.toml` is the single source of truth.
The git tag, the GitHub Release, the GHCR image tag and the deployed CVM all
have to agree with it. When they don't, "which build is prod running?" stops
having an answer — that is how prod ran 1.8.0 for weeks while the team debugged
a feature that was not in the deployed binary.

## Who owns what

| Step | Owner | Trigger |
| --- | --- | --- |
| Bump `Cargo.toml` + write the `CHANGELOG.md` entry | **a human, in a PR** | you decide to release |
| Create the `vX.Y.Z` git tag | `release-plz` (`release` job in `.github/workflows/release-plz.yml`) | the version-bump PR lands on `main` |
| Build binaries + create the GitHub Release | `cargo-dist` (`.github/workflows/release.yml`) | the `vX.Y.Z` tag |
| Build + push GHCR images | `.github/workflows/docker.yml` | the `vX.Y.Z` tag push |
| Deploy the dstack image to the Phala prod CVM | `docker.yml` `deploy-phala` job | **manual** `workflow_dispatch` with `deploy_phala`, on the `vX.Y.Z` tag or `main` only — see [Promoting to production](#promoting-to-production-main-only) |

The `release` job genuinely works: it reads the version out of `Cargo.toml` and
creates the matching tag. Everything downstream of the tag is automated except
the production promotion, which is a deliberate manual dispatch. Only
the version *number* is manual.

On `main` pushes, the ordinary GHCR image gets `main`, `edge`, and the
short commit SHA; the dstack image gets `dstack-main`, `dstack-edge`,
and its prefixed short SHA. Neither floating release tag (`latest` for the
ordinary image, `dstack` for the dstack image) moves on a main push.
A `v*` tag push or published GitHub Release on that tag publishes the
version tags and both floating release tags.
Both are mutable; pin production and self-hosted compose files to a verified
digest instead.

## Cutting a release

1. Land your feature PRs on `main` as usual. `main` stays at the previously
   released version in between releases; that is normal.
2. Open a `chore(release): X.Y.Z` PR that does exactly two things:
   - set `version` in `tinycloud-node-server/Cargo.toml` to the new version,
   - add the corresponding `CHANGELOG.md` section.
   Choose the number from the commits since the last tag
   (`git log --oneline "$(git describe --tags --abbrev=0)"..main`) using normal
   semver rules.
3. Merge it. The `release` job tags `vX.Y.Z` on that `main` commit and the
   tag drives `cargo-dist` and the image build. If the tag does not appear,
   the release owner tags the merge commit on `main` by hand — never a commit
   that is not on `main`.
4. Promote the tag's image to production and verify it — next section. Nothing
   deploys automatically.

Do **not** hand-edit a version onto an in-flight release branch, and do not type
a version into the `docker.yml` `image_version` input that `Cargo.toml` does not
already claim. Both have happened (`0b48da2`, and the image tagged `1.10.0`
built from a `1.9.0` tree); the `version-guard` job now blocks the second one.

## Promoting to production (main-only)

Production is built and promoted **only from `main`** (TC-940, 2026-10-13).
There is no release branch. Immutable digest promotions require
`refs/heads/main`; normal build dispatches may also use a `vX.Y.Z` tag in
main's history (`scripts/ci/check-deploy-ref.sh`, before builds and again
inside `deploy-phala`). Other refs fail `Deploy refused (main-only)`.

**Release order:** approved #310 must never merge alone. Land #310 and its
stacked recovery changes atomically as one lineage, preserving emergency
re-promotion and security rollback first. #309's sidecar compose then ships
on the unchanged 1.20.6 image under that lineage's exact raw-hash lock. The
later main release lands this template lock and the 95m ingress body cap,
and is promoted by one dispatch (see
[Main release with N0 log shipping](#main-release-with-n0-log-shipping-one-dispatch)).
These docs grant no merge or dispatch authority. Merging either workflow
change is a push, not a deployment dispatch.

### The `production` environment (TC-971)

The ref check above runs inside the workflow file of the dispatched ref, so it
only protects refs whose `docker.yml` already has it. `workflow_dispatch` runs
the workflow file at the selected ref, and repository or organization secrets
are readable by every ref. To close that, every job that reads production
secrets runs in GitHub's `production` environment. Most deploy secrets
exist only there; `PROD_TINYCLOUD_ADMIN_SECRET` is the approved repository-
scoped exception and is consumed only inside the deploy job.

| Workflow | Job | Production secrets |
| --- | --- | --- |
| `docker.yml` | `deploy-phala` | `PHALA_CLOUD_API_KEY` and the `PROD_TINYCLOUD_*` sealed config |
| `docker.yml` | `rollback-audit` | `PROD_TINYCLOUD_DATABASE_URL` |
| `export-share-invitation-descriptor.yml` | `export` | `PROD_TINYCLOUD_KEYS_SECRET` |

Environment settings (Settings → Environments → `production`):

- Deployment branches and tags: **Selected branches and tags**, with the branch
  rule `main` and the tag rule `v*`. GitHub rejects a job for any other ref
  before it starts.
- Required reviewers: none. Wait timer: none.
- Secrets: `PHALA_CLOUD_API_KEY`, `PROD_TINYCLOUD_DATABASE_URL`,
  `PROD_TINYCLOUD_S3_BUCKET`, `PROD_TINYCLOUD_S3_ENDPOINT`,
  `PROD_TINYCLOUD_AWS_ACCESS_KEY_ID`, `PROD_TINYCLOUD_AWS_SECRET_ACCESS_KEY`,
  `PROD_TINYCLOUD_AWS_REGION`, `PROD_TINYCLOUD_QUOTA_URL`,
  `PROD_TINYCLOUD_SHARE_TRUST_BUNDLE_BASE64`,
  `PROD_TINYCLOUD_CLOUDFLARE_API_TOKEN`, `PROD_TINYCLOUD_DSTACK_GATEWAY_DOMAIN`,
  `PROD_TINYCLOUD_CERTBOT_EMAIL`, `PROD_TINYCLOUD_KEYS_SECRET`,
  `PROD_TINYCLOUD_BETTERSTACK_SOURCE_TOKEN`.
- Except for the explicit node admin exception, none may also exist as a repository secret; this repository
  must not be selected for the organization secret `PHALA_CLOUD_API_KEY`. A
  same-named repository or organization secret is still readable by a job
  without `environment: production`.
- `NODE_STATS_READ_TOKEN` (TC-1482, read-only `GET /admin/stats`) is not in
  that list and is not passed to the CVM by `docker.yml` or the compose files,
  so the route is disabled (`404`) in a deployment until a reviewed change adds
  it: a `PROD_TINYCLOUD_NODE_STATS_READ_TOKEN` environment secret, the
  `PHALA_ENV_` pass-through and a compose `environment` line (which changes the
  reviewed compose hash). Its value must be at least 32 bytes (generate it with
  `openssl rand -hex 32`; a shorter value disables the route) and must differ from
  `PROD_TINYCLOUD_ADMIN_SECRET`; the node disables the route if they are equal.

What this blocks: a dispatch on an unlocked branch fails the environment's
branch policy, even if that branch edits `docker.yml` to name the environment.
A dispatch on an old tag or branch whose `docker.yml` predates this section
runs without the environment and gets empty secrets, so its deploy fails (in
current workflows, at `Missing required GitHub secret for Phala deploy`).

What it does not block: `v*` is a name filter, not a check on the tagged
commit. Anyone who can push a `v*` tag can tag a commit off `main` whose
`docker.yml` names `production` and drops `scripts/ci/check-deploy-ref.sh`.
Treat tag creators as production operators, and restrict creating, updating
and deleting `v*` tags to release automation and admins with a tag ruleset.
The organization `PHALA_CLOUD_API_KEY` is also shared with other repositories.
Deselecting this repository doesn't stop those repositories from using the
key. A production-only Phala key that is stored only in this environment
closes that gap.

`TC780_CUTOVER_READY` stays a repository variable: the build jobs, which have
no environment, read it too. `GITHUB_TOKEN` is the automatic token.

The quota steps send `PROD_TINYCLOUD_ADMIN_SECRET` to billing's
`/api/admin/storage-comp/:space_id` as well as to the node's admin API.
Billing's storage-comp guard checks the Worker secret
`TINYCLOUD_ADMIN_SECRET`, which is the node/billing shared admin value:
billing uses it for its own calls to the node's `/admin/*` routes, and a
rotation sets the GitHub secret and the `tinycloud-billing` Worker secret
to one new value. No separate billing runner secret exists; rotating the
shared value must update both holders together, or the quota steps fail
closed with `quota API rejected the request`. The value is never passed in
argv/logs and never added to the CVM env or `allowed_envs` under a billing
name. A missing credential or an incompatible billing URL fails before
compose/CVM mutation. `PROD_TINYCLOUD_QUOTA_URL` is billing's base URL (the
node's `TINYCLOUD_QUOTA_URL`, to which the node appends `/api/quota/<space>`):
a bare HTTPS origin. The preflight also accepts that origin with the
`/api/quota` path; any other path, `http`, credentials, a query or fragment,
or CR/LF fails it. The quota steps take only its host and port and
call billing's fixed `/api/admin/storage-comp/` path; no URL is printed.

Every `deploy_phala=true` command must explicitly include
**`-f authorize_quota_values=true`**. This authorizes the reviewed values
and authority in `ops/quota-overrides.json` for that one dispatch; it is
not N0-specific or permission to silently reuse old values. Missing
authorization or missing/unknown authority fails before any compose,
CVM or whitelist mutation.

`authority=billing` is current (TC-1162/TC-1164): billing is the quota
authority for both of Sam's spaces, and the reviewed limits are floors,
applications `5368709120` and secrets `1073741824` (internal D1
`quota_overrides`). Billing mode is read-only after the last restart and
required health: both exact spaces must exist once with positive usage in
authenticated `/admin/usage`, which lists every space on the node
unpaginated (~107 bytes a space); the script reads up to 16 MiB of it and
fails closed above that, while other quota bodies stay capped at 64 KiB.
It never PUTs/DELETEs a node override. Each
active absolute per-space `storage_limit_bytes` must cover its floor, and
node GET must show `override_bytes=null`. Missing, inactive or insufficient
comps fail `billing authority does not cover both reviewed quota floors`; a
non-null override fails `stale legacy override`. A cold node cache is not a
failure: billing is authoritative and the node fetches on the next write
(≤60 s TTL). Do not compare incremental account `comp_bytes` with absolute
space limits.

Ordering rule: the flip to `billing` is merged only after both spaces are
billing comps with their node overrides cleared, and before any further
`deploy_phala` dispatch. Merged before that migration, the next dispatch
restarts the node (wiping its in-memory overrides) and billing-mode
reconcile then fails without restoring them (no comp covers the floors).
Left unmerged after the migration, the next dispatch refuses in
node-override mode with `authority mismatch: flip to billing`.
Reverting to `authority=node-override` requires a
reviewed PR. In that legacy mode, before ANY PUT both billing storage-comp
reads must prove no active comp (404 logs only `billing storage-comp
unavailable`; valid `active:false` also permits the restore); an active comp
fails `authority mismatch: flip to billing`. Each PUT requires GET readback
of both override and effective values. In both modes, auth/5xx/transport/
malformed responses fail closed and never count as absence.
No raw response, identity list, credential or error body is logged.
Any attempted restart without verified reconciliation is fatal
**OVERRIDES UNVERIFIED**, requiring authorized operator/TC-1161 fallback.

If a job that names the environment ever runs before the environment exists,
GitHub creates `production` with no branch policy. Create the environment and
its branch policy before any workflow that names it runs.

1. **Get the digest.** The tag push runs `docker.yml`, whose `build-dstack`
   job pushes `ghcr.io/tinycloudlabs/tinycloud-node:X.Y.Z-dstack`. Copy the
   digest from that job's log, then confirm its labels from the registry
   (the mutable tag can race, so always promote by digest):

   ```sh
   docker buildx imagetools inspect ghcr.io/tinycloudlabs/tinycloud-node@sha256:<digest> \
     --format '{{ json .Image.Config.Labels }}'   # revision == tag commit, version == X.Y.Z-dstack
   ```

2. **Promote the recorded immutable digest from main:**

   ```sh
   gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref main \
     -f deploy_phala=true -f authorize_quota_values=true \
     -f image_version=X.Y.Z \
     -f deploy_image_digest=sha256:<recorded digest> \
     -f rollback_image_version=X.Y.Z \
     -f rollback_image_revision=<recorded 40-character OCI revision> \
     -f sql_identity_fence=false
   ```

   - `image_version` and recorded labels describe the immutable image,
     never an unrelated current crate version. The revision must be in
     main history. A future non-N0 digest uses this same contract.
   - The reviewed N0 compose is locked as a template: its raw bytes with
     the single node digest normalized. Only a recorded *released* main
     image may fill that pin; see
     [Main release with N0 log shipping](#main-release-with-n0-log-shipping-one-dispatch).
     Before #309 lands,
     the ordinary main `:dstack` compose supports forward image
     promotions without installing the sidecar.
   - `sql_identity_fence=false` is required. The input defaults to `true`,
     which re-fences SQL/DuckDB in production (503s).
   - The production ancestry guard still applies: the revision prod is running
     must be an ancestor of the dispatched commit. Every production revision is
     on `main`, so a normal release passes it. Do not set
     `allow_non_descendant` for a release.

3. **Verify.** The workflow itself polls `node.tinycloud.xyz/version` and the
   Policy/v3 routes. Then check by hand:

   - `/info` reports the new version and the expected feature set:

     ```sh
     curl -fsS https://tee.node.tinycloud.xyz/info | jq '{version, features, inTEE}'
     ```

     Compare `features` with the previous release (1.20.1 reports `kv`,
     `delegation`, `sharing`, `sql`, `hooks`, `signed-urls`, `encryption`,
     `kv-sync-v1`, `kv-sync-root`, `tee`).
   - Every PostgreSQL connection got its TCP keepalive options (TC-1054,
     1.20.5 on). The production logs are private, so this is read from
     `/info`, which carries two counts (no hosts or errors):

     ```sh
     curl -fsS https://tee.node.tinycloud.xyz/info \
       | jq -e '.postgres.sockets_configured >= .postgres.connections_opened
                and .postgres.connections_opened > 0'
     ```

     It must print `true`. `connections_opened` without matching
     `sockets_configured` means the pool connected to a target the vendored
     sqlx-core was not told about, so its connections run without keepalive.
   - Large headers still reach the node (TC-910 raised the ingress header
     buffers to `4 32k`). A ~30 KB `Authorization` header must get the node's
     own `401 Unauthorized` page, not an nginx `400 Request Header Or Cookie
     Too Large` or a reset connection:

     ```sh
     H="$(head -c 30000 /dev/zero | tr '\0' a)"
     curl -sS -o /dev/null -w '%{http_code}\n' -X POST -H "Authorization: ${H}" \
       https://tee.node.tinycloud.xyz/delegate   # expect 401
     ```
   - Login, KV and SQL work end to end with a throwaway key, not a real
     account: create a key-only `tc` profile (`tc init --key-only`), then
     `tc auth login --method local`, and do a KV put/get and a SQL query in
     that profile's space. This exercises `/delegate`, `/invoke` KV and SQL.
     Run it with stderr visible (no `2>/dev/null`), so a failing request shows
     its error rather than an empty result.
4. **Watch.** The `promote-watch` job then dispatches the Write Probe's dense
   promote watch (TC-1176): signed-in KV and SQL reads every 30 s for 5 min,
   then every 5 min for 60 min, paging team@ through Better Stack on 2 reads
   in a row over 5 s or failing. The 2026-10-14 read hang began ~40 min after
   a promote, which is why it runs for an hour. Check the run titled
   `Write Probe (dense promote watch)`; to start one by hand:
   `gh workflow run write-probe.yml -R TinyCloudLabs/tinycloud-node --ref main -f mode=dense`.
   Details: `test/probe/README.md`.

### Main release with N0 log shipping (one dispatch)

Ships a main release on #309's log sidecar compose. Before dispatching,
`main` must contain the combined workflow lineage, #309, the template-lock
change that also raises the ingress `CLIENT_MAX_BODY_SIZE` to `95m`, and the
merged `chore(release): 1.21.0` commit tagged `v1.21.0`. Take the digest and
labels of the tag build's `1.21.0-dstack` image as in step 1 above:

```sh
gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref main \
  -f deploy_phala=true \
  -f authorize_quota_values=true \
  -f image_version=1.21.0 \
  -f deploy_image_digest=sha256:<release-dstack-digest> \
  -f rollback_image_version=1.21.0 \
  -f rollback_image_revision=<release-commit-sha> \
  -f sql_identity_fence=false
```

`rollback_image_version` and `rollback_image_revision` name the image being
**deployed** (here the release), not an image to roll back to. Despite the
input names, they are the recorded labels of `deploy_image_digest`.

Before any CVM mutation the workflow requires:

- the main compose, with its one node digest replaced by 64 zeros, to hash
  to the reviewed N0 template
  **`7fabba70e71423faa2c8b61981d4a7c95ac7c2552074af81c0877af774d6b383`**
  (raw `1228d81927fc0a3fbba85745103e77b3112606f5d314d15974d400b222409350` normalized: the 1.21.0 compose
  `d95bfb707871c1d626c4a8f2b8d32d354103edbb5077847c6a21fe5f7f6cfa50`, template
  `51f8e9e9…`, with only the embedded Vector config regenerated for TC-1274's
  and TC-1317's warning codes; TC-1274 alone was template `00938226…`, raw
  `b25b8414…`. That compose is the #349 compose
  `c33c23021589163b62a71ef245b7194717711922027629f155bdd5cff806b8c7`, which
  keeps `TINYCLOUD_EPOCH_HEAD_BACKFILL__ENABLED: "false"`, with only
  `CLIENT_MAX_BODY_SIZE=32m` → `95m`). Ingress, socat, Vector and the log
  profile stay byte-exact;
- the deployed compose to differ from that template only by
  `deploy_image_digest`;
- OCI labels `1.21.0-dstack` / `<release-commit-sha>`, the `v1.21.0` tag on
  that commit, its `Cargo.toml` at `1.21.0`, and the commit in main history.
  An untagged, mislabelled, feature-variant or freshly built image is
  refused;
- the release revision to be a **strict descendant** of the revision running
  in production (read from the CVM's pinned image by the ancestry guard).
  A downgrade (for example 1.20.5 or 1.0.0), the same revision as running,
  or an unknown running revision is refused. The same ancestry rule makes
  the 12c same-image command refuse an image older than the running
  revision once 1.21.0 is live, so it cannot downgrade across migrations.
  The captured pre-N0 rollback is the only intentional downgrade route.

Sealed preflight, `BETTERSTACK_SOURCE_TOKEN` sealing with the
`allowed_envs` sync, and the general quota reconciliation run as on every
deploy. The template's comment naming 1.20.6 is reviewed text, not image
identity; `/version` and the labels report the release. Reproduce the
template hash from any ref:

```sh
git show main:docker-compose.dstack-postgres.yaml \
  | sed -E '/^    image: ghcr\.io\/tinycloudlabs\/tinycloud-node@sha256:/s/[0-9a-f]{64}$/0000000000000000000000000000000000000000000000000000000000000000/' \
  | sha256sum
```

Rolling this release back means a database snapshot restore (a separate
decision) plus the [captured pre-N0 rollback](#tc-1302-captured-pre-n0-rollback)
to 1.20.6 with Sam's explicit privacy mode.

## Rolling back

Keep the digest, actual OCI version and actual revision of every promoted
image. Sealed-runtime preflight is mandatory on recovery, rollback and
forward paths; an image that cannot validate config fails before restart.
The same general quota authority/reconciliation gate runs after the final
env operation plus version/ingress health, before ancillary Policy probes.
The downstream watcher cannot skip quota restoration.

### Emergency same-image recovery (12c)

After the combined workflow is reviewed/landed and a named operator has fresh
values authorization, this is the single copy-paste recovery command. It uses
the **current main compose**, whether the exact pre-N0 template or the exact
reviewed N0 bytes. It does not opt into an N0-only snapshot or change the
current logging policy. No command has been dispatched by this work.

```sh
gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref main \
  -f deploy_phala=true \
  -f authorize_quota_values=true \
  -f image_version=1.20.6 \
  -f deploy_image_digest=sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f \
  -f rollback_image_version=1.20.6 \
  -f rollback_image_revision=e18578ff9162986ddd813259c60f73866e3e60d1 \
  -f sql_identity_fence=false
```

The served/OCI identity remains **1.20.6-dstack / e18578ff9162986ddd813259c60f73866e3e60d1**.
With the template lock on main this redeploys exactly main's raw compose
`1228d81927fc0a3fbba85745103e77b3112606f5d314d15974d400b222409350`
(the 1.21.0 compose `d95bfb70…` with the TC-1274 and TC-1317 Vector config), whatever digest
main's template currently pins. It is not a rollback of a
later release across a schema migration. Current pre-N0 tag/pinned
equivalents are separately hash-checked; arbitrary same-image config
substitutions fail before mutation.

### TC-1302 captured pre-N0 rollback

This is a compose rollback, not merely a node digest selection. The source
`ops/rollback/pre-n0-compose.yaml` is byte-identical to Amos's capture:
raw SHA256 **`df239749ca0a9c09893a855ae2a8abb94090b8556515ad002105c58ac91f4c91`**.
Its provenance was reconstructed from the frozen public template with only
the immutable node pin; the private saved file's contents were not read.
The node/ingress images, app env, storage and ingress topology stay fixed.
Other paths, symlinks, source drift and edited variants fail before mutation.

**Privacy choice remains pending Sam's explicit card answer.** The default
is `unselected`, which refuses rollback. Amos records the approved choice in
repository variable `TC959_ROLLBACK_PRIVACY_MODE`; the chosen input must match.
Neither command below is authorization to choose that policy. Use exactly
the command matching Sam's answer; do not add an override/bypass flag.

If Sam explicitly selects **keep prior json-file logging**, retain the
captured 3×50 MB local logging policy:

```sh
gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref main \
  -f deploy_phala=true \
  -f authorize_quota_values=true \
  -f rollback_pre_n0=true \
  -f rollback_privacy_mode=keep-json-file \
  -f image_version=1.20.6 \
  -f deploy_image_digest=sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f \
  -f rollback_image_version=1.20.6 \
  -f rollback_image_revision=e18578ff9162986ddd813259c60f73866e3e60d1 \
  -f sql_identity_fence=false
```

If Sam explicitly selects **stop FUTURE local logs**, the reviewed derivative
sets only the node and ingress logging drivers to `none`:

```sh
gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref main \
  -f deploy_phala=true \
  -f authorize_quota_values=true \
  -f rollback_pre_n0=true \
  -f rollback_privacy_mode=stop-future-local-logs \
  -f image_version=1.20.6 \
  -f deploy_image_digest=sha256:4bdae4fc232d886bb56bfbce4ec62ed4b8fb4e1369a01f6afb73d06dd68c188f \
  -f rollback_image_version=1.20.6 \
  -f rollback_image_revision=e18578ff9162986ddd813259c60f73866e3e60d1 \
  -f sql_identity_fence=false
```

That derivative's raw SHA256 is
`315ceca54bf8bfefe2b395b4097fe38ed8ec847fa0688bc873220bd65efc99ec`.
Both the original capture and the selected derivative are fixed-path/hash
validated. **Stopping future logs does not delete existing files. There is
NO truncation/deletion path in this PR.** Any destructive action needs a
separate explicit authorization and reviewed procedure.

Never silently restore raw retention on forward/current-compose promotion:
the privacy input is rollback-only and mutually exclusive. Existing private
logs/private sysinfo flags remain; operator readback must preserve
logs/sysinfo/tcbinfo = false/false/true. Do not use retired branches or tags
for these digest commands. `allow_non_descendant` is not normally needed;
all recorded revisions must remain in main history. Binary rollback across
a database schema migration still needs a separate DB-safety decision.


## Why the version bump is manual

release-plz decides the next version by comparing the local crate against the
**cargo registry**, not against git tags. `publish = false` only skips
`cargo publish`; it does not stop the comparison. The crates.io name
`tinycloud-node` is a reserved `0.0.1` placeholder, so on every push to `main`
where `HEAD` is ahead of the newest `v*` tag, release-plz logs:

```
INFO tinycloud-node: local version (1.9.0) > registry version (0.0.1). Only changelog will be updated.
INFO the repository is already up-to-date
release_pr_output: {"prs":[]}
```

It concludes a human already bumped the version, never computes a next version,
and exits 0. Thirty-five consecutive post-tag runs reported success while doing
nothing, which is why nobody noticed: 1.8.0, 1.9.0 and 1.10.0 were all
hand-chosen. The `release-pr` job now writes a job summary and a warning
annotation saying it did not bump anything, so the no-op is visible on the run.

### What would fix it

`git_only = true`
([docs](https://release-plz.dev/docs/config#the-git_only-field)) tells
release-plz to resolve the last release from git tags instead of the registry.
It is the supported fix and it resolves the tag correctly here
(`Latest release of package tinycloud-node: tag v1.10.0 (version 1.10.0)`), but
it cannot be enabled yet: git-only mode runs
`cargo package --allow-dirty --workspace` in a worktree at the release tag, and
this workspace is not packageable.

1. `dependencies/{siwe,siwe-recap,cacao}/Cargo.toml` set
   `license-file = "../LICENSE.md"`, which does not exist — the license is at
   the repo root. Three-line fix.
2. **Blocking:** `siwe-recap` depends on `ucan-capabilities-object` and
   `tinycloud-auth` depends on `ssi`, both unpublished TinyCloud git forks.
   `cargo package` rejects any git or path dependency without a version
   requirement, so `cargo package --workspace` cannot succeed until those forks
   are published to crates.io or vendored into the tree.

Once (2) is resolved, set `git_only = true` on the `tinycloud-node` package in
`release-plz.toml`, delete the manual steps above, and release-plz will open
real release PRs.

## Manual image builds

`docker.yml` accepts a `workflow_dispatch` `image_version` input. The
`version-guard` job validates it — along with the release tag and any tag ref —
against `tinycloud-node-server/Cargo.toml` at the checked-out ref, and fails the
workflow if they disagree. You cannot label an image with a version the source
tree does not claim. To ship a new version, land the version-bump PR first.

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
There is no release branch. The `deploy-phala` job refuses to run unless the
dispatched ref is `refs/heads/main` or a `refs/tags/vX.Y.Z` tag whose commit is
an ancestor of `origin/main` (`scripts/ci/check-deploy-ref.sh`, run both in
`version-guard` before any build and again at the start of `deploy-phala`). A
dispatch from any other branch or tag fails with
`Deploy refused (main-only)`.

### The `production` environment (TC-971)

The ref check above runs inside the workflow file of the dispatched ref, so it
only protects refs whose `docker.yml` already has it. `workflow_dispatch` runs
the workflow file at the selected ref, and repository or organization secrets
are readable by every ref. To close that, every job that reads production
secrets runs in the GitHub `production` environment, and those secrets exist
only there:

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
  `PROD_TINYCLOUD_ADMIN_SECRET`, `PROD_TINYCLOUD_SHARE_TRUST_BUNDLE_BASE64`,
  `PROD_TINYCLOUD_CLOUDFLARE_API_TOKEN`, `PROD_TINYCLOUD_DSTACK_GATEWAY_DOMAIN`,
  `PROD_TINYCLOUD_CERTBOT_EMAIL`, `PROD_TINYCLOUD_KEYS_SECRET`.
- None of these may also exist as a repository secret, and this repository
  must not be selected for the organization secret `PHALA_CLOUD_API_KEY`. A
  same-named repository or organization secret is still readable by a job
  without `environment: production`.

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

2. **Promote from the tag:**

   ```sh
   gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref vX.Y.Z \
     -f deploy_phala=true -f image_version=X.Y.Z \
     -f deploy_image_digest=sha256:<digest> \
     -f sql_identity_fence=false
   ```

   - Dispatch on the **tag**, not `main`. The deploy requires the image's
     `org.opencontainers.image.revision` label to equal `HEAD` of the dispatched
     ref; the tag always points at the build commit, while `main` only does
     until the next merge. (`--ref main` works only while `main`'s tip is the
     tag commit.)
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

## Rolling back

Roll back by promoting an older **recorded** digest, dispatched on `main`.
Keep a record (digest, version, revision) of every digest you promote.

```sh
gh workflow run docker.yml -R TinyCloudLabs/tinycloud-node --ref main \
  -f deploy_phala=true \
  -f image_version=<version in main's Cargo.toml> \
  -f deploy_image_digest=sha256:<old digest> \
  -f rollback_image_version=<old version, e.g. 1.20.1> \
  -f rollback_image_revision=<old image's 40-char revision label> \
  -f sql_identity_fence=false
```

- The `rollback_image_*` inputs replace the "revision label equals HEAD"
  check with "labels equal these recorded values". The rollback revision must
  be an ancestor of `main`, which every production revision since TC-940 is.
- `allow_non_descendant` is **not** needed. The ancestry guard compares the
  revision prod is currently running with `main`, and that revision is on
  `main`. Keep `allow_non_descendant` as break-glass for when Phala or GHCR
  cannot be queried for the running revision; the main-only check still
  applies with it set.
- The compose file and the ingress image come from `main`, not from the old
  release; only the node binary rolls back. Check
  `tinycloud-core/src/migrations` between the two revisions first: a binary
  rollback across a schema migration is not DB-safe.
- The sealed-config preflight is skipped for rollbacks, and the post-deploy
  `/version` check expects `rollback_image_version`. Run the same manual
  verification as for a release.
- Rollback runs in the `production` environment like any other deploy, and
  `main` is admitted by its branch policy. No environment change is needed.
- Do not roll back by dispatching on an old tag or a retired branch. Old refs
  carry an older `docker.yml` without the main-only guard or the `production`
  environment, so they get no deploy secrets and fail. The retired deploy
  branches (`feat/tc-780-release-line`,
  `Codex/roman/rollback-meeting-node-20260915`) are also locked.

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

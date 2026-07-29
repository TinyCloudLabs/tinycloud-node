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
| Build + push GHCR images | `.github/workflows/docker.yml` | the GitHub Release, or manual dispatch |
| Deploy the dstack image to the Phala prod CVM | `docker.yml` `deploy-phala` job | the GitHub Release, or manual dispatch with `deploy_phala` |

The `release` job genuinely works: it reads the version out of `Cargo.toml` and
creates the matching tag. Everything downstream of the tag is automated. Only
the version *number* is manual.

## Cutting a release

1. Land your feature PRs on `main` as usual. `main` stays at the previously
   released version in between releases; that is normal.
2. Open a `chore(release): X.Y.Z` PR that does exactly two things:
   - set `version` in `tinycloud-node-server/Cargo.toml` to the new version,
   - add the corresponding `CHANGELOG.md` section.
   Choose the number from the commits since the last tag
   (`git log --oneline "$(git describe --tags --abbrev=0)"..main`) using normal
   semver rules.
3. Merge it. The `release` job tags `vX.Y.Z` and the tag drives `cargo-dist`
   and the image build.
4. Confirm the deployed image tag matches: the `version-guard` job in
   `docker.yml` fails the build if it doesn't, so a green deploy is a real
   signal here.

Do **not** hand-edit a version onto an in-flight release branch, and do not type
a version into the `docker.yml` `image_version` input that `Cargo.toml` does not
already claim. Both have happened (`0b48da2`, and the image tagged `1.10.0`
built from a `1.9.0` tree); the `version-guard` job now blocks the second one.

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

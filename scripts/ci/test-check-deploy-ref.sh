#!/usr/bin/env bash
# TC-940: regression test for scripts/ci/check-deploy-ref.sh. Builds a
# throwaway repo with a main line and a side branch, then asserts which
# dispatched refs the main-only deploy guard accepts and refuses.
set -euo pipefail

GUARD="$(cd "$(dirname "$0")" && pwd)/check-deploy-ref.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

export GIT_AUTHOR_NAME=ci GIT_AUTHOR_EMAIL=ci@example.invalid
export GIT_COMMITTER_NAME=ci GIT_COMMITTER_EMAIL=ci@example.invalid
cd "${WORK}"
git init -q -b main
git commit -q --allow-empty -m one
OLD="$(git rev-parse HEAD)"
git commit -q --allow-empty -m two
TIP="$(git rev-parse HEAD)"
git checkout -q -b side
git commit -q --allow-empty -m side
SIDE="$(git rev-parse HEAD)"
git update-ref refs/remotes/origin/main "${TIP}"

failures=0
check() {
  expected="$1" desc="$2" ref="$3" sha="$4" rollback="${5:-}" event="${6:-workflow_dispatch}"
  git checkout -q --detach "${sha}"
  if GITHUB_EVENT_NAME="${event}" GITHUB_REF="${ref}" GITHUB_SHA="${sha}" \
    ROLLBACK_REVISION="${rollback}" bash "${GUARD}" >/dev/null 2>&1; then
    actual=accept
  else
    actual=refuse
  fi
  if [ "${actual}" = "${expected}" ]; then
    echo "ok   ${expected} ${desc}"
  else
    echo "FAIL expected ${expected}, got ${actual}: ${desc}"
    failures=$((failures + 1))
  fi
}

check accept "main tip" refs/heads/main "${TIP}"
check accept "release tag on main's history" refs/tags/v1.0.0 "${OLD}"
check accept "rollback revision on main" refs/heads/main "${TIP}" "${OLD}"
check refuse "release tag off main" refs/tags/v1.0.1 "${SIDE}"
check refuse "retired release-line branch" refs/heads/feat/tc-780-release-line "${SIDE}"
check refuse "other branch at main's commit" refs/heads/feat/x "${TIP}"
check refuse "branch whose name starts with main" refs/heads/mainline "${TIP}"
check refuse "non-release tag name" refs/tags/v1.0.0-rc1 "${OLD}"
check refuse "non-v tag" refs/tags/1.0.0 "${OLD}"
check refuse "pull request ref" refs/pull/1/merge "${TIP}"
check refuse "rollback revision off main" refs/heads/main "${TIP}" "${SIDE}"
check refuse "malformed rollback revision" refs/heads/main "${TIP}" "not-a-sha"
check refuse "main ref with a commit not on main" refs/heads/main "${SIDE}"
check refuse "push event" refs/heads/main "${TIP}" "" push

# Checked-out HEAD must be the dispatched commit.
git checkout -q --detach "${OLD}"
if GITHUB_EVENT_NAME=workflow_dispatch GITHUB_REF=refs/heads/main GITHUB_SHA="${TIP}" \
  bash "${GUARD}" >/dev/null 2>&1; then
  echo "FAIL expected refuse, got accept: HEAD differs from GITHUB_SHA"
  failures=$((failures + 1))
else
  echo "ok   refuse HEAD differs from GITHUB_SHA"
fi

# Without origin/main the guard must refuse, not pass.
git update-ref -d refs/remotes/origin/main
check refuse "origin/main missing" refs/heads/main "${TIP}"

if [ "${failures}" -ne 0 ]; then
  echo "${failures} deploy-ref guard case(s) failed"
  exit 1
fi
echo "all deploy-ref guard cases passed"

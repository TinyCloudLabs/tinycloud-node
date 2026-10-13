#!/usr/bin/env bash
# TC-940: production is built and promoted only from main.
#
# A Phala deploy (docker.yml `deploy_phala`) must be dispatched on either
#   - refs/heads/main, or
#   - a refs/tags/vX.Y.Z tag whose commit is an ancestor of origin/main.
# An emergency rollback's recorded revision must also be in main's history.
#
# Inputs (environment):
#   GITHUB_EVENT_NAME, GITHUB_REF, GITHUB_SHA  set by Actions
#   ROLLBACK_REVISION                          optional 40-char revision
#   MAIN_REF                                   optional, default origin/main
#
# Requires a checkout with full history (or `git fetch --unshallow`) so
# `git merge-base --is-ancestor` can answer.
set -euo pipefail

MAIN_REF="${MAIN_REF:-origin/main}"
ROLLBACK_REVISION="${ROLLBACK_REVISION:-}"

refuse() {
  echo "::error title=Deploy refused (main-only)::$1 Production deploys must be dispatched on main or a vX.Y.Z tag on main's history — see docs/releasing.md."
  exit 1
}

if [ "${GITHUB_EVENT_NAME:-}" != "workflow_dispatch" ]; then
  refuse "Deploys only run from workflow_dispatch, not '${GITHUB_EVENT_NAME:-}'."
fi
if ! [[ "${GITHUB_SHA:-}" =~ ^[0-9a-f]{40}$ ]]; then
  refuse "GITHUB_SHA '${GITHUB_SHA:-}' is not a commit id."
fi
if ! git rev-parse --verify --quiet "${MAIN_REF}^{commit}" >/dev/null; then
  refuse "Cannot resolve ${MAIN_REF}; fetch main with full history before this check."
fi
if [ "$(git rev-parse HEAD)" != "${GITHUB_SHA}" ]; then
  refuse "Checked-out HEAD $(git rev-parse HEAD) is not the dispatched commit ${GITHUB_SHA}."
fi

case "${GITHUB_REF:-}" in
  refs/heads/main)
    # GITHUB_SHA is main's tip at dispatch; main can only have moved forward.
    if ! git merge-base --is-ancestor "${GITHUB_SHA}" "${MAIN_REF}"; then
      refuse "Dispatched main commit ${GITHUB_SHA} is not in ${MAIN_REF}'s history (force-pushed main?)."
    fi
    ;;
  refs/tags/v*)
    TAG="${GITHUB_REF#refs/tags/}"
    if ! [[ "${TAG}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      refuse "Tag '${TAG}' is not a release tag of the form vX.Y.Z."
    fi
    if ! git merge-base --is-ancestor "${GITHUB_SHA}" "${MAIN_REF}"; then
      refuse "Tag ${TAG} points at ${GITHUB_SHA}, which is not an ancestor of ${MAIN_REF}. Release tags must be cut on main."
    fi
    ;;
  *)
    refuse "Ref '${GITHUB_REF:-}' is not main or a release tag."
    ;;
esac

if [ -n "${ROLLBACK_REVISION}" ]; then
  if ! [[ "${ROLLBACK_REVISION}" =~ ^[0-9a-f]{40}$ ]] \
    || ! git cat-file -e "${ROLLBACK_REVISION}^{commit}" 2>/dev/null \
    || ! git merge-base --is-ancestor "${ROLLBACK_REVISION}" "${MAIN_REF}"; then
    refuse "Rollback revision '${ROLLBACK_REVISION}' is not a commit in ${MAIN_REF}'s history."
  fi
  echo "Rollback revision ${ROLLBACK_REVISION} is in ${MAIN_REF}'s history."
fi

echo "Deploy source ${GITHUB_REF} (${GITHUB_SHA}) is on ${MAIN_REF}'s history."

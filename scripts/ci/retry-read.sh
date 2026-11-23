#!/usr/bin/env bash
# Run a READ-ONLY command and retry it once if it exits non-zero (TC-3881).
#
# Post-deploy verification reads (/info, `phala api` GETs) fail on one transient error, which then
# skips every later step of the deploy job. This reruns the command one more time after a short fixed
# pause. A second failure fails closed with the command's exit code.
#
# Usage:  retry-read.sh <command> [args...]   prints the command's stdout on success
# Env:    READ_RETRY_ATTEMPTS (default 2: one retry), READ_RETRY_PAUSE seconds (default 5)
#
# ONLY for reads. Never wrap a deploy, an override write or a restore: a rerun would repeat it.
# The command's stdout goes to a file and is copied out only after a successful run, so a failed attempt
# prints nothing. Its stderr is dropped. The log carries the attempt number and exit code, never a body.
set -euo pipefail

[ "$#" -gt 0 ] || { echo "usage: retry-read.sh <command> [args...]" >&2; exit 2; }
attempts="${READ_RETRY_ATTEMPTS:-2}"
pause="${READ_RETRY_PAUSE:-5}"

tmp="$(mktemp)"
trap 'rm -f "${tmp}"' EXIT
status=0
for attempt in $(seq 1 "${attempts}"); do
  status=0
  "$@" >"${tmp}" 2>/dev/null || status=$?
  if [ "${status}" = 0 ]; then
    cat "${tmp}"
    exit 0
  fi
  echo "::warning::read attempt ${attempt}/${attempts} failed with exit code ${status}" >&2
  if [ "${attempt}" -lt "${attempts}" ]; then
    sleep "${pause}"
  fi
done
echo "::error::read failed after ${attempts} attempts (last exit code ${status})" >&2
exit "${status}"

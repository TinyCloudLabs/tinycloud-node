#!/usr/bin/env bash
# Read `phala cvms get <cvm> --json` and retry transient bad reads.
#
# Phala sometimes exits 0 but prints a body that is not the CVM object: empty output, or
# non-JSON text. phala-os-guard.sh then fails with "Cannot read the OS of the CVM" (node
# 1.26.21: 2 of 3 runs). A read counts only when stdout is a JSON object with an `os`
# object. It is retried up to PHALA_READ_ATTEMPTS times (default 4) with a growing pause.
#
# Usage:  phala-cvm-json.sh <cvm-name>   prints the CVM JSON on stdout
# Env:    PHALA_READ_ATTEMPTS (default 4), PHALA_READ_PAUSE seconds (default 5; doubles)
#
# Never prints the response. On failure it logs only the attempt number, the byte count
# and whether the body was empty or not JSON, then exits 1.
set -euo pipefail

cvm_name="${1:?usage: phala-cvm-json.sh <cvm-name>}"
attempts="${PHALA_READ_ATTEMPTS:-4}"
pause="${PHALA_READ_PAUSE:-5}"

body=""
for attempt in $(seq 1 "${attempts}"); do
  status=0
  body="$(phala cvms get "${cvm_name}" --json 2>/dev/null)" || status=$?
  # jq -e on empty input exits 0 in some jq versions, so an empty body is refused explicitly.
  if [ "${status}" = 0 ] && [ -n "${body}" ] \
    && jq -e 'type == "object" and (.os | type) == "object"' >/dev/null 2>&1 <<<"${body}"; then
    printf '%s\n' "${body}"
    exit 0
  fi
  if [ "${status}" != 0 ]; then
    reason="phala exited ${status}"
  elif [ -z "${body}" ]; then
    reason="empty output"
  elif ! jq -e . >/dev/null 2>&1 <<<"${body}"; then
    reason="output is not JSON (${#body} bytes)"
  else
    reason="JSON without an os object (${#body} bytes)"
  fi
  echo "::warning::Phala CVM read ${attempt}/${attempts} failed: ${reason}" >&2
  if [ "${attempt}" -lt "${attempts}" ]; then
    sleep "${pause}"
    pause=$((pause * 2))
  fi
done
echo "::error::Cannot read the CVM ${cvm_name} from Phala after ${attempts} attempts" >&2
exit 1

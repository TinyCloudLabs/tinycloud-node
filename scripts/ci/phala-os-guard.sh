#!/usr/bin/env bash
# Phala deploy guard: refuse unless the CVM runs the pinned production OS image, or
# one dev OS image that is pinned in phala-dev-os-allowlist.txt and passes a fresh
# integrity check in this job.
#
# Usage:  phala-os-guard.sh < "$(phala cvms get <cvm> --json)"   (the CVM JSON on stdin)
# Env:    PHALA_OS_IMAGE, PHALA_OS_IMAGE_HASH   the production image name and hash (required)
#         DEV_OS_ALLOWLIST                      allowlist file (default: next to this script)
#
# Fails closed (exit 1) on an unknown dev hash, a missing or malformed field, a failed
# fetch, a hash mismatch, or any curl, tar or network error. It never changes the OS.
set -euo pipefail

fail() {
  echo "::error::$*"
  exit 1
}

: "${PHALA_OS_IMAGE:?PHALA_OS_IMAGE is not set}"
: "${PHALA_OS_IMAGE_HASH:?PHALA_OS_IMAGE_HASH is not set}"
allowlist="${DEV_OS_ALLOWLIST:-$(dirname "${BASH_SOURCE[0]}")/phala-dev-os-allowlist.txt}"
hash_re='^[0-9a-f]{64}$'

cvm="$(cat)"
os="$(jq -c '.os' <<<"${cvm}" 2>/dev/null)" || fail "Cannot read the OS of the CVM from the Phala output"
field() {
  jq -r --arg key "$1" --arg type "$2" \
    'if type == "object" and (.[$key] | type) == $type then .[$key] | tostring else "" end' <<<"${os}"
}
is_dev="$(field is_dev boolean)"
name="$(field name string)"
hash="$(field os_image_hash string)"
if [ -z "${is_dev}" ] || [ -z "${name}" ] || [ -z "${hash}" ]; then
  fail "The CVM OS is missing is_dev, name or os_image_hash. Found: ${os}"
fi

if [ "${is_dev}" = "false" ]; then
  if [ "${name}" != "${PHALA_OS_IMAGE}" ] || [ "${hash}" != "${PHALA_OS_IMAGE_HASH}" ]; then
    fail "The CVM is not on the production OS image ${PHALA_OS_IMAGE} (${PHALA_OS_IMAGE_HASH}). Found: ${os}"
  fi
  echo "The CVM runs the production OS image ${name}"
  exit 0
fi

# A dev image: pinned hash, then a fresh integrity check.
[[ "${hash}" =~ ${hash_re} ]] || fail "The dev OS hash is not 64 lowercase hex characters. Found: ${os}"
[ -f "${allowlist}" ] || fail "The dev OS allowlist ${allowlist} is missing"
pinned=0
while IFS= read -r line || [ -n "${line}" ]; do
  line="${line%%#*}"
  line="${line//[[:space:]]/}"
  [ -n "${line}" ] || continue
  [[ "${line}" =~ ${hash_re} ]] || fail "The dev OS allowlist ${allowlist} has a malformed entry"
  [ "${line}" != "${hash}" ] || pinned=1
done <"${allowlist}"
[ "${pinned}" = 1 ] || fail "The CVM runs the dev OS image ${name} (${hash}), which is not in the pinned allowlist. Found: ${os}"

url="https://download.dstack.org/os-images/mr_${hash}.tar.gz"
work="$(mktemp -d)" || fail "Cannot create a temporary directory"
trap 'rm -rf "${work}"' EXIT
status="$(curl -fsSI --max-time 120 -o /dev/null -w '%{http_code}' "${url}")" || fail "Cannot reach ${url}"
[ "${status}" = 200 ] || fail "${url} answered HTTP ${status}, not 200"
curl -fsS --max-time 120 --max-filesize 1073741824 -o "${work}/image.tar.gz" "${url}" || fail "Cannot download ${url}"
mkdir "${work}/image"
tar -xzf "${work}/image.tar.gz" -C "${work}/image" || fail "Cannot extract the image from ${url}"
[ -f "${work}/image/sha256sum.txt" ] || fail "The image from ${url} has no sha256sum.txt"
got="$(cd "${work}/image" && sha256sum sha256sum.txt)" || fail "Cannot hash sha256sum.txt"
got="${got%% *}"
[ "${got}" = "${hash}" ] || fail "sha256sum.txt of the image from ${url} hashes to ${got}, not ${hash}"
echo "The CVM runs the pinned dev OS image ${name} (${hash}); its integrity check passed"

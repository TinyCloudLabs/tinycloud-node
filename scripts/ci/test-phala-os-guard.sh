#!/usr/bin/env bash
# Tests phala-os-guard.sh with stubbed `phala` and `curl`: no network, no Phala account.
# Usage: test-phala-os-guard.sh   (from anywhere)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
guard="${here}/phala-os-guard.sh"
root="$(mktemp -d -p "${TMPDIR:-/var/tmp}")"
trap 'rm -rf "${root}"' EXIT
mkdir "${root}/bin" "${root}/tmp" "${root}/fixtures"

PROD_NAME=dstack-0.5.12
PROD_HASH=8db40cb23008d6213668b5816702d100b37b859a8a5bfd18d938ae3a1b3715bd
REAL_DEV_HASH=e866e987221db357129ebc3f066b6706ef955889ea95e5510acbdf3d3055186b

# The stubs print what the real tools would, driven by STUB_* variables.
cat >"${root}/bin/phala" <<'STUB'
#!/usr/bin/env bash
printf '%s\n' "${STUB_CVM_JSON}"
STUB
cat >"${root}/bin/curl" <<'STUB'
#!/usr/bin/env bash
echo "curl $*" >>"${STUB_LOG}"
out=""; head=0; timeout=0; prev=""
for arg in "$@"; do
  [ "${prev}" = "-o" ] && out="${arg}"
  [ "${prev}" = "--max-time" ] && timeout="${arg}"
  case "${arg}" in -*I*) head=1 ;; esac
  prev="${arg}"
done
[ "${timeout}" -gt 0 ] && [ "${timeout}" -le 120 ] || { echo "curl without a bounded --max-time" >&2; exit 2; }
if [ "${head}" = 1 ]; then
  [ "${STUB_HEAD}" != fail ] || exit 6
  printf '%s' "${STUB_HEAD}"
  exit 0
fi
[ "${STUB_GET}" != fail ] || exit 28
cp "${STUB_TARBALL}" "${out}"
STUB
chmod +x "${root}/bin/phala" "${root}/bin/curl"

# A fake image whose sha256sum.txt hashes to GOOD_HASH, and one that does not match it.
make_image() { # <dir> <content>
  mkdir "$1"
  printf '%s\n' "$2" >"$1/sha256sum.txt"
  echo kernel >"$1/bzImage"
  tar -czf "$1.tar.gz" -C "$1" sha256sum.txt bzImage
}
make_image "${root}/fixtures/good" "good image manifest"
make_image "${root}/fixtures/other" "tampered image manifest"
GOOD_HASH="$(sha256sum "${root}/fixtures/good/sha256sum.txt" | cut -d' ' -f1)"
printf '# test allowlist\n%s  # the fake dev image\n' "${GOOD_HASH}" >"${root}/allowlist.txt"
echo "not a tarball" >"${root}/fixtures/garbage.tar.gz"

os_json() { # <is_dev> <name> <hash>
  jq -nc --argjson dev "$1" --arg name "$2" --arg hash "$3" \
    '{name: "cvm", os: {is_dev: $dev, name: $name, os_image_hash: $hash}}'
}

failures=0
# run <cvm-json> [VAR=value ...]: sets $out and $code from the guard fed like the workflow feeds it.
run() {
  local cvm="$1"; shift
  : >"${root}/curl.log"
  set +e
  out="$(env -i PATH="${root}/bin:/usr/bin:/bin" TMPDIR="${root}/tmp" \
    PHALA_OS_IMAGE="${PROD_NAME}" PHALA_OS_IMAGE_HASH="${PROD_HASH}" DEV_OS_ALLOWLIST="${root}/allowlist.txt" \
    STUB_CVM_JSON="${cvm}" STUB_LOG="${root}/curl.log" STUB_HEAD=200 STUB_GET=ok STUB_TARBALL="${root}/fixtures/good.tar.gz" \
    "$@" bash -c 'phala cvms get cvm --json | bash "$0"' "${guard}" 2>&1)"
  code=$?
  set -e
}
expect() { # <name> <exit code> <output regex>
  if [ "${code}" != "$2" ] || ! grep -Eq -- "$3" <<<"${out}"; then
    echo "FAIL: $1 (exit ${code}, wanted $2 matching /$3/)"; echo "${out}" | sed 's/^/    /'
    failures=$((failures + 1))
  else
    echo "ok: $1"
  fi
}
no_curl() { [ ! -s "${root}/curl.log" ] || { echo "FAIL: $1 called curl"; failures=$((failures + 1)); }; }
no_leftovers() { [ -z "$(ls -A "${root}/tmp")" ] || { echo "FAIL: $1 left a temp dir"; failures=$((failures + 1)); }; }

run "$(os_json false "${PROD_NAME}" "${PROD_HASH}")"
expect "production image passes" 0 "runs the production OS image"; no_curl "production image"

run "$(os_json false "${PROD_NAME}" "$(printf 'a%.0s' {1..64})")"
expect "a non-pinned production image is refused" 1 "not on the production OS image"

run "$(os_json true "dstack-dev-0.5.12" "${GOOD_HASH}")"
expect "pinned dev image with a good pre-check passes" 0 "integrity check passed"
grep -q "mr_${GOOD_HASH}.tar.gz" "${root}/curl.log" || { echo "FAIL: pre-check URL"; failures=$((failures + 1)); }
no_leftovers "good pre-check"

run "$(os_json true "dstack-dev-0.5.12" "${GOOD_HASH}")" STUB_TARBALL="${root}/fixtures/other.tar.gz"
expect "pinned dev image with a bad sha is refused" 1 "hashes to [0-9a-f]{64}, not ${GOOD_HASH}"; no_leftovers "bad sha"

run "$(os_json true "dstack-dev-0.5.12" "$(printf 'b%.0s' {1..64})")"
expect "an unknown dev hash is refused" 1 "not in the pinned allowlist"; no_curl "unknown dev hash"

run "$(os_json true "dstack-dev-0.5.12" "${GOOD_HASH}")" STUB_HEAD=fail
expect "a failed HEAD request is refused" 1 "Cannot reach"; no_leftovers "failed HEAD"

run "$(os_json true "dstack-dev-0.5.12" "${GOOD_HASH}")" STUB_HEAD=302
expect "a non-200 answer is refused" 1 "answered HTTP 302"

run "$(os_json true "dstack-dev-0.5.12" "${GOOD_HASH}")" STUB_GET=fail
expect "a failed download is refused" 1 "Cannot download"; no_leftovers "failed download"

run "$(os_json true "dstack-dev-0.5.12" "${GOOD_HASH}")" STUB_TARBALL="${root}/fixtures/garbage.tar.gz"
expect "an archive that does not extract is refused" 1 "Cannot extract"; no_leftovers "bad archive"

run "$(os_json true "dstack-dev-0.5.12" "${REAL_DEV_HASH}")" DEV_OS_ALLOWLIST="${here}/phala-dev-os-allowlist.txt"
expect "the repo allowlist pins the dev image, then the pre-check refuses a mismatch" 1 "hashes to [0-9a-f]{64}, not ${REAL_DEV_HASH}"

run "$(os_json true "dstack-dev-0.5.12" "${GOOD_HASH}")" DEV_OS_ALLOWLIST="${root}/missing.txt"
expect "a missing allowlist is refused" 1 "allowlist .* is missing"; no_curl "missing allowlist"

echo "not-a-hash" >"${root}/bad-allowlist.txt"
run "$(os_json true "dstack-dev-0.5.12" "${GOOD_HASH}")" DEV_OS_ALLOWLIST="${root}/bad-allowlist.txt"
expect "a malformed allowlist is refused" 1 "malformed entry"; no_curl "malformed allowlist"

run "$(os_json true "dstack-dev-0.5.12" "UPPERCASE-OR-SHORT")"
expect "a malformed dev hash is refused" 1 "not 64 lowercase hex"; no_curl "malformed dev hash"

run '{"name":"cvm","os":{"name":"dstack-dev-0.5.12","os_image_hash":"'"${GOOD_HASH}"'"}}'
expect "a missing is_dev is refused" 1 "missing is_dev"; no_curl "missing is_dev"

run '{"name":"cvm","os":{"is_dev":true,"name":"dstack-dev-0.5.12"}}'
expect "a missing os_image_hash is refused" 1 "missing is_dev, name or os_image_hash"; no_curl "missing hash"

run '{"name":"cvm"}'
expect "a missing os object is refused" 1 "missing is_dev"

run '{"name":"cvm","os":{"is_dev":"false","name":"'"${PROD_NAME}"'","os_image_hash":"'"${PROD_HASH}"'"}}'
expect "a string is_dev is refused" 1 "missing is_dev"

run 'not json'
expect "unparsable Phala output is refused" 1 "Cannot read the OS"

run ''
expect "empty Phala output is refused" 1 "missing is_dev"

[ "${failures}" = 0 ] || { echo "${failures} failure(s)"; exit 1; }
echo "all phala-os-guard tests passed"

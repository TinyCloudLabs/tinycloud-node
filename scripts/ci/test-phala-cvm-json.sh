#!/usr/bin/env bash
# Tests phala-cvm-json.sh with a stubbed `phala` that plays a script of responses: no network.
# Usage: test-phala-cvm-json.sh   (from anywhere)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
reader="${here}/phala-cvm-json.sh"
root="$(mktemp -d -p "${TMPDIR:-/var/tmp}")"
trap 'rm -rf "${root}"' EXIT
mkdir "${root}/bin"

# Each call prints the next line of ${STUB_SCRIPT}: "ok", "empty", "text", "noos" or "exit".
cat >"${root}/bin/phala" <<'STUB'
#!/usr/bin/env bash
n=$(( $(cat "${STUB_COUNT}") + 1 )); echo "${n}" >"${STUB_COUNT}"
case "$(sed -n "${n}p" "${STUB_SCRIPT}")" in
  ok) printf '%s\n' '{"name":"cvm","os":{"is_dev":false,"name":"x","os_image_hash":"y"}}' ;;
  empty) ;;
  text) echo "Secret-looking notice that must never be echoed" ;;
  noos) echo '{"name":"cvm"}' ;;
  exit) echo '{"os":{}}'; exit 3 ;;
  *) echo "stub called too often" >&2; exit 9 ;;
esac
STUB
chmod +x "${root}/bin/phala"

failures=0
# run <responses...>: sets $out, $err, $code and $calls.
run() {
  printf '%s\n' "$@" >"${root}/script"
  echo 0 >"${root}/count"
  set +e
  out="$(env -i PATH="${root}/bin:/usr/bin:/bin" STUB_SCRIPT="${root}/script" STUB_COUNT="${root}/count" \
    PHALA_READ_PAUSE=0 bash "${reader}" tinycloud-node 2>"${root}/err")"
  code=$?
  set -e
  err="$(cat "${root}/err")"
  calls="$(cat "${root}/count")"
}
expect() { # <label> <code> <calls> [<stderr-regex>]
  local ok=1
  [ "${code}" = "$2" ] || ok=0
  [ "${calls}" = "$3" ] || ok=0
  [ -z "${4:-}" ] || grep -Eq "$4" <<<"${err}" || ok=0
  ! grep -q "Secret-looking" <<<"${out}${err}" || ok=0
  if [ "${ok}" = 1 ]; then echo "ok   $1"; else echo "FAIL $1 (code ${code}, calls ${calls}): ${err}"; failures=$((failures + 1)); fi
}

run ok
expect "a good first read is returned" 0 1
jq -e '.os.name == "x"' >/dev/null <<<"${out}" || { echo "FAIL the CVM JSON is passed through"; failures=$((failures + 1)); }

run text ok
expect "non-JSON output is retried" 0 2 "1/4 failed: output is not JSON"

run empty empty ok
expect "empty output is retried" 0 3 "empty output"

run noos exit ok
expect "JSON without os and a failed exit are retried" 0 3 "without an os object.*|phala exited 3"

run text empty noos exit
expect "four bad reads fail closed without echoing the body" 1 4 "after 4 attempts"

[ "${failures}" = 0 ] || { echo "${failures} failure(s)"; exit 1; }
echo "all phala-cvm-json tests passed"

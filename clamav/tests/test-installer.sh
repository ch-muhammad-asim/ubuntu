#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAMAV_DIR="$(cd "${TEST_DIR}/.." && pwd)"
INSTALLER="${CLAMAV_DIR}/setup-clamav-ubuntu.sh"
TEMP_DIR="$(mktemp -d)"
TESTS_RUN=0

cleanup() {
  rm -rf "${TEMP_DIR}"
}
trap cleanup EXIT

fail() {
  printf 'not ok - %s\n' "$*" >&2
  exit 1
}

pass() {
  TESTS_RUN=$((TESTS_RUN + 1))
  printf 'ok %d - %s\n' "${TESTS_RUN}" "$*"
}

assert_contains() {
  local file="$1"
  local expected="$2"

  grep -Fq -- "${expected}" "${file}" || fail "Expected ${file} to contain: ${expected}"
}

assert_not_contains() {
  local file="$1"
  local unexpected="$2"

  if grep -Fq -- "${unexpected}" "${file}"; then
    fail "Expected ${file} not to contain: ${unexpected}"
  fi
}

assert_rejected() {
  local expected="$1"
  shift
  local output_file="${TEMP_DIR}/rejected-${TESTS_RUN}.log"

  if bash "${INSTALLER}" "$@" >"${output_file}" 2>&1; then
    fail "Expected arguments to be rejected: $*"
  fi
  assert_contains "${output_file}" "${expected}"
}

extract_heredoc() {
  local marker="$1"
  local destination="$2"

  awk -v marker="${marker}" '
    index($0, "<<" marker) || index($0, "<<\047" marker "\047") { capture = 1; next }
    capture && $0 == marker { exit }
    capture { print }
  ' "${INSTALLER}" >"${destination}"
}

bash -n "${INSTALLER}"
pass "installer has valid Bash syntax"

HELP_OUTPUT="${TEMP_DIR}/help.txt"
bash "${INSTALLER}" --help >"${HELP_OUTPUT}"
assert_contains "${HELP_OUTPUT}" "--max-threads THREADS"
assert_contains "${HELP_OUTPUT}" '--scan-path PATH'
pass "help documents supported tuning options"

assert_rejected "--max-threads must be a positive integer" --max-threads 0
assert_rejected "--max-threads must be a positive integer" --max-threads invalid
assert_rejected "--max-threads must not exceed 48" --max-threads 49
pass "invalid worker counts are rejected before installation"

SCAN_HEAD="${TEMP_DIR}/scan-head.sh"
SCAN_BODY="${TEMP_DIR}/scan-body.sh"
GENERATED_SCAN="${TEMP_DIR}/clamav-daily-scan"
SCAN_ROOT="${TEMP_DIR}/scan path"
MISSING_ROOT="${TEMP_DIR}/missing path"
MOCK_BIN="${TEMP_DIR}/bin"
CAPTURE_FILE="${TEMP_DIR}/clamdscan.args"
SCAN_LOG="${TEMP_DIR}/daily-scan.log"

mkdir -p "${SCAN_ROOT}" "${MOCK_BIN}"
extract_heredoc SCAN_HEAD "${SCAN_HEAD}"
extract_heredoc SCAN_BODY "${SCAN_BODY}"
{
  cat "${SCAN_HEAD}"
  printf '  %q\n' "${SCAN_ROOT}" "${MISSING_ROOT}"
  cat "${SCAN_BODY}"
} >"${GENERATED_SCAN}"

sed -i \
  -e "s|^LOG_FILE=.*|LOG_FILE=$(printf '%q' "${SCAN_LOG}")|" \
  -e 's|/usr/bin/clamdscan|clamdscan|' \
  "${GENERATED_SCAN}"
chmod 0755 "${GENERATED_SCAN}"
bash -n "${GENERATED_SCAN}"
pass "generated daily scanner has valid Bash syntax"

cat >"${MOCK_BIN}/systemctl" <<'MOCK_SYSTEMCTL'
#!/usr/bin/env bash
exit 0
MOCK_SYSTEMCTL
cat >"${MOCK_BIN}/clamdscan" <<'MOCK_CLAMDSCAN'
#!/usr/bin/env bash
printf '%s\n' "$@" >"${CAPTURE_FILE}"
exit "${MOCK_SCAN_STATUS:-0}"
MOCK_CLAMDSCAN
chmod 0755 "${MOCK_BIN}/systemctl" "${MOCK_BIN}/clamdscan"

PATH="${MOCK_BIN}:${PATH}" CAPTURE_FILE="${CAPTURE_FILE}" MOCK_SCAN_STATUS=0 bash "${GENERATED_SCAN}"
assert_contains "${CAPTURE_FILE}" "--multiscan"
assert_contains "${CAPTURE_FILE}" "--fdpass"
assert_contains "${CAPTURE_FILE}" "${SCAN_ROOT}"
assert_not_contains "${CAPTURE_FILE}" "${MISSING_ROOT}"
assert_contains "${SCAN_LOG}" "configured path no longer exists: ${MISSING_ROOT}"
assert_contains "${SCAN_LOG}" "Scan completed: no threats found"
pass "daily scanner uses parallel fd passing and skips stale paths"

set +e
PATH="${MOCK_BIN}:${PATH}" CAPTURE_FILE="${CAPTURE_FILE}" MOCK_SCAN_STATUS=1 bash "${GENERATED_SCAN}"
SCAN_STATUS=$?
set -e
[[ "${SCAN_STATUS}" -eq 1 ]] || fail "Expected threat status 1, got ${SCAN_STATUS}"
assert_contains "${SCAN_LOG}" "Scan completed: threats found"
pass "daily scanner preserves ClamAV threat status"

if command -v clamd >/dev/null 2>&1; then
  CLAMD_TEMPLATE="${TEMP_DIR}/clamd.conf.template"
  CLAMD_CONFIG="${TEMP_DIR}/clamd.conf"
  CLAMD_OUTPUT="${TEMP_DIR}/clamd.output"

  extract_heredoc CLAMD "${CLAMD_TEMPLATE}"
  sed \
    -e "s/\${MAX_THREADS}/4/g" \
    -e "s/\${MAX_QUEUE}/100/g" \
    -e "s/\${ONACCESS_MAX_THREADS}/2/g" \
    "${CLAMD_TEMPLATE}" >"${CLAMD_CONFIG}"

  set +e
  timeout 5 clamd --foreground --config-file="${CLAMD_CONFIG}" >"${CLAMD_OUTPUT}" 2>&1
  set -e
  if grep -Eiq 'parse error|unknown option|malformed' "${CLAMD_OUTPUT}"; then
    cat "${CLAMD_OUTPUT}" >&2
    fail "Generated clamd.conf was rejected by the installed ClamAV parser"
  fi
  pass "generated clamd.conf is accepted by the installed ClamAV parser"
else
  printf '# clamd is not installed; parser compatibility check skipped locally\n'
fi

printf '1..%d\n' "${TESTS_RUN}"

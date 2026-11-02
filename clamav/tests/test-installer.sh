#!/usr/bin/env bash
# SC2016: assertions match literal installer source text. SC2317/SC2034: helpers used by sourced installer functions.
# SC1090/SC2030/SC2031: extracted helper files are sourced in subshells with a subshell-local mock PATH.
# shellcheck disable=SC2016,SC2317,SC2034,SC1090,SC2030,SC2031
set -euo pipefail

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAMAV_DIR="$(cd "${TEST_DIR}/.." && pwd)"
INSTALLER="${CLAMAV_DIR}/setup-clamav-ubuntu.sh"
TEMP_DIR="$(mktemp -d)"
TESTS_RUN=0

cleanup() {
  # The real-client test writes EICAR files under /var/tmp; never leave them behind, even after a failure.
  if [[ -n "${REAL_ROOT:-}" && -d "${REAL_ROOT}" ]]; then chmod -R u+rwX "${REAL_ROOT}"; rm -rf "${REAL_ROOT}"; fi
  chmod -R u+rwX "${TEMP_DIR}" 2>/dev/null || true
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
assert_contains "${HELP_OUTPUT}" '--watch-path PATH'
assert_contains "${HELP_OUTPUT}" 'Repeat for several users'
assert_contains "${HELP_OUTPUT}" '--verify'
assert_contains "${HELP_OUTPUT}" '--prevention'
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

SCAN_CLAMD_CONF="${TEMP_DIR}/scan-clamd.conf"
LISTED_FILE="${TEMP_DIR}/clamdscan.listed"
SCAN_TMP="${TEMP_DIR}/scan-tmp"
ODD_NAME="${SCAN_ROOT}/keep/new"$'\n'"line"
FF_NAME="${SCAN_ROOT}/keep/bad-"$'\xff'"-byte"
CR_NAME="${SCAN_ROOT}/keep/carriage-return"$'\r'
LONG_DIR="${SCAN_ROOT}/keep"
for part in d e f g h; do LONG_DIR="${LONG_DIR}/$(printf "${part}%.0s" {1..200})"; done
LONG_NAME="${LONG_DIR}/$(printf 'i%.0s' {1..200})"

mkdir -p "${SCAN_ROOT}/keep" "${SCAN_ROOT}/skipme/deep" "${SCAN_ROOT}/skipme-not" "${MOCK_BIN}" "${SCAN_TMP}" "${LONG_DIR}"
touch "${SCAN_ROOT}/keep/a" "${SCAN_ROOT}/keep/b" "${SCAN_ROOT}/skipme/c" "${SCAN_ROOT}/skipme/deep/d" \
  "${SCAN_ROOT}/skipme-not/e" "${SCAN_ROOT}/keep/vanish-me" "${ODD_NAME}" "${FF_NAME}" "${CR_NAME}" "${LONG_NAME}"
[[ "${#LONG_NAME}" -gt 1024 ]] || fail "test setup: long path is only ${#LONG_NAME} bytes"
ln -s "${SCAN_ROOT}/keep/a" "${SCAN_ROOT}/keep/link-to-a"
mkfifo "${SCAN_ROOT}/keep/fifo" "${SCAN_ROOT}/skipme/fifo"
EXPECTED_SPECIAL=1
if command -v python3 >/dev/null 2>&1; then
  (cd "${SCAN_ROOT}/keep" && python3 -I -c 'import socket; socket.socket(socket.AF_UNIX).bind("app.sock")')
  EXPECTED_SPECIAL=2
fi
printf 'LogTime true\nMaxThreads 2\nExcludePath /skipme(/|$)\nExcludePath\t/nothing-here(/|$)\n' >"${SCAN_CLAMD_CONF}"
extract_heredoc SCAN_HEAD "${SCAN_HEAD}"
extract_heredoc SCAN_BODY "${SCAN_BODY}"
{
  cat "${SCAN_HEAD}"
  printf '  %q\n' "${SCAN_ROOT}" "${MISSING_ROOT}"
  cat "${SCAN_BODY}"
} >"${GENERATED_SCAN}"

sed -i \
  -e "s|^LOG_FILE=.*|LOG_FILE=$(printf '%q' "${SCAN_LOG}")|" \
  -e "s|^CLAMD_CONF=.*|CLAMD_CONF=$(printf '%q' "${SCAN_CLAMD_CONF}")|" \
  -e "s|^LOG_LOCK=.*|LOG_LOCK=$(printf '%q' "${TEMP_DIR}/scan.lock")|" \
  -e 's|/usr/bin/clamdscan|clamdscan|' \
  "${GENERATED_SCAN}"
chmod 0755 "${GENERATED_SCAN}"
bash -n "${GENERATED_SCAN}"
pass "generated daily scanner has valid Bash syntax"

cat >"${MOCK_BIN}/systemctl" <<'MOCK_SYSTEMCTL'
#!/usr/bin/env bash
exit 0
MOCK_SYSTEMCTL
# Mock clamdscan: records its arguments and the files it was given, "scans" them like clamdscan --infected
# --no-summary on stdout/stderr (vanish-me disappears before the scan, *threat* is a detection, MOCK_SLEEP keeps the
# client busy after a detection, a batch with a *fail-batch* file exits 2 without output, MOCK_SCAN_STATUS=2 makes
# every batch do that).
cat >"${MOCK_BIN}/clamdscan" <<'MOCK_CLAMDSCAN'
#!/usr/bin/env bash
declare -a paths=()
for arg in "$@"; do
  case "${arg}" in
    --*) ;;
    *) paths+=("${arg}") ;;
  esac
done
printf '%s\n' "$@" >>"${CAPTURE_FILE}"
printf '%s\0' "${paths[@]}" >>"${LISTED_FILE}"
if [[ "${MOCK_SCAN_STATUS:-0}" -eq 2 ]]; then exit 2; fi
for p in "${paths[@]}"; do [[ "${p}" != *fail-batch* ]] || exit 2; done
infected=0; errors=0
for p in "${paths[@]}"; do
  case "${p}" in
    *vanish-me) rm -f -- "${p}"; echo "ERROR: Can't access file ${p}" >&2; errors=$((errors + 1)) ;;
    *threat*)
      echo "${p}: Eicar-Test-Signature FOUND"; infected=$((infected + 1))
      if [[ -n "${MOCK_SLEEP:-}" ]]; then exec sleep "${MOCK_SLEEP}"; fi ;;
  esac
done
if [[ "${infected}" -gt 0 ]]; then exit 1; elif [[ "${errors}" -gt 0 ]]; then exit 2; fi
exit 0
MOCK_CLAMDSCAN
chmod 0755 "${MOCK_BIN}/systemctl" "${MOCK_BIN}/clamdscan"

listed() {  # listed PATH: PATH was handed to clamdscan byte for byte (names may contain any byte but NUL)
  local LC_ALL=C rec
  while IFS= read -r -d '' rec; do [[ "${rec}" == "$1" ]] && return 0; done <"${LISTED_FILE}"
  return 1
}
run_scan() {  # run_scan [VAR=value...]: run the generated scanner with the mocks; sets SCAN_STATUS
  : >"${CAPTURE_FILE}"; : >"${LISTED_FILE}"
  set +e
  env PATH="${SCAN_PATH_PREFIX:-}${MOCK_BIN}:${PATH}" CAPTURE_FILE="${CAPTURE_FILE}" LISTED_FILE="${LISTED_FILE}" \
    TMPDIR="${SCAN_TMP}" "$@" bash "${SCAN_SCRIPT:-${GENERATED_SCAN}}" >/dev/null 2>&1
  SCAN_STATUS=$?
  set -e
}
log_since() { : >"${SCAN_LOG}"; }  # each scenario starts from an empty log

log_since; run_scan
[[ "${SCAN_STATUS}" -eq 0 ]] || fail "clean scan exited ${SCAN_STATUS}: $(cat "${SCAN_LOG}")"
assert_not_contains "${CAPTURE_FILE}" "--multiscan"
assert_not_contains "${CAPTURE_FILE}" "--file-list"
assert_not_contains "${CAPTURE_FILE}" "--log"
assert_contains "${CAPTURE_FILE}" "--fdpass"
assert_contains "${INSTALLER}" 'xargs -0 -r -n "${BATCH_SIZE}" -P "${JOBS}" -a "${WORK_DIR}/files.0" bash -c '"'"'run_batch "$@"'"'"' run_batch'
assert_not_contains "${INSTALLER}" 'clamdscan --fdpass --infected --no-summary --log'
for f in keep/a keep/b skipme-not/e keep/vanish-me; do listed "${SCAN_ROOT}/${f}" || fail "regular file not handed to clamdscan: ${f}"; done
listed "${ODD_NAME}" || fail "file name with a newline not handed to clamdscan unchanged"
listed "${FF_NAME}" || fail "file name with byte 0xff not handed to clamdscan unchanged"
listed "${CR_NAME}" || fail "file name with a trailing carriage return not handed to clamdscan unchanged"
listed "${LONG_NAME}" || fail "path longer than 1024 bytes not handed to clamdscan unchanged"
for f in skipme/c skipme/deep/d keep/fifo skipme/fifo keep/app.sock keep/link-to-a; do
  if listed "${SCAN_ROOT}/${f}"; then fail "handed to clamdscan but must not be: ${f}"; fi
done
if grep -zqF -- "${MISSING_ROOT}" "${LISTED_FILE}"; then fail "missing scan path was listed"; fi
assert_contains "${SCAN_LOG}" "configured path no longer exists: ${MISSING_ROOT}"
assert_contains "${SCAN_LOG}" "Files to scan: 8"
assert_contains "${SCAN_LOG}" "Special files skipped: ${EXPECTED_SPECIAL}"
assert_contains "${SCAN_LOG}" "Vanished before scan: 1"
assert_contains "${SCAN_LOG}" "Total errors: 0"
assert_contains "${SCAN_LOG}" "Scan completed: no threats found"
[[ -z "$(ls -A "${SCAN_TMP}")" ]] || fail "daily scanner left its work directory behind"
[[ "$(stat -c %a "${SCAN_LOG}")" == 640 ]] || fail "Expected daily-scan.log mode 640, got $(stat -c %a "${SCAN_LOG}")"
pass "daily scanner hands every regular file to clamdscan byte for byte (0xff, CR, newline, >1024-byte path), honours ExcludePath, counts sockets/FIFOs as skipped, reports vanished files"

touch "${SCAN_ROOT}/keep/threat.txt"
log_since; run_scan
[[ "${SCAN_STATUS}" -eq 1 ]] || fail "Expected threat status 1, got ${SCAN_STATUS}"
assert_contains "${SCAN_LOG}" "${SCAN_ROOT}/keep/threat.txt: Eicar-Test-Signature FOUND"
assert_contains "${SCAN_LOG}" "Infected files: 1"
assert_contains "${SCAN_LOG}" "Scan completed: threats found"

# SIGTERM mid-scan (for example the unit's 6 h timeout): the detection already made stays in the permanent log and
# the run is recorded as incomplete.
log_since
: >"${CAPTURE_FILE}"; : >"${LISTED_FILE}"
env PATH="${MOCK_BIN}:${PATH}" CAPTURE_FILE="${CAPTURE_FILE}" LISTED_FILE="${LISTED_FILE}" TMPDIR="${SCAN_TMP}" \
  MOCK_SLEEP=67.25 bash "${GENERATED_SCAN}" >/dev/null 2>&1 &
SCAN_PID=$!
# Wait until the busy batch has reported the detection in its own output file (not yet in the permanent log).
for _ in $(seq 100); do grep -rqs 'threat.txt: Eicar-Test-Signature FOUND' "${SCAN_TMP}" && break; sleep 0.1; done
grep -rqs 'threat.txt: Eicar-Test-Signature FOUND' "${SCAN_TMP}" || fail "mock batch did not report the detection"
assert_not_contains "${SCAN_LOG}" "threat.txt: Eicar-Test-Signature FOUND"
kill -TERM "${SCAN_PID}"
set +e; wait "${SCAN_PID}"; SCAN_STATUS=$?; set -e
[[ "${SCAN_STATUS}" -eq 2 ]] || fail "Expected status 2 after SIGTERM, got ${SCAN_STATUS}"
assert_contains "${SCAN_LOG}" "${SCAN_ROOT}/keep/threat.txt: Eicar-Test-Signature FOUND"
assert_contains "${SCAN_LOG}" "Infected files: 1"
assert_contains "${SCAN_LOG}" "Scan incomplete: interrupted by SIGTERM"
[[ -z "$(ls -A "${SCAN_TMP}")" ]] || fail "work directory left behind after SIGTERM"
sleep 0.3
if pgrep -fx "sleep 67.25" >/dev/null; then pkill -fx "sleep 67.25"; fail "a clamdscan worker survived SIGTERM"; fi
rm -f "${SCAN_ROOT}/keep/threat.txt"

log_since; run_scan MOCK_SCAN_STATUS=2
[[ "${SCAN_STATUS}" -eq 2 ]] || fail "Expected status 2 when a batch fails silently, got ${SCAN_STATUS}"
assert_contains "${SCAN_LOG}" "Scan incomplete: 1 of 1 clamdscan batches failed"
assert_contains "${SCAN_LOG}" "Files scanned: 0 of 7"

# One file per batch: a detection in one batch must not hide another batch's failure.
GENERATED_SCAN_B1="${TEMP_DIR}/clamav-daily-scan-batch1"
sed 's/^BATCH_SIZE=.*/BATCH_SIZE=1/' "${GENERATED_SCAN}" >"${GENERATED_SCAN_B1}"
touch "${SCAN_ROOT}/keep/threat.txt" "${SCAN_ROOT}/keep/fail-batch"
log_since; SCAN_SCRIPT="${GENERATED_SCAN_B1}" run_scan
[[ "${SCAN_STATUS}" -eq 2 ]] || fail "Expected status 2 for a detection plus a failed batch, got ${SCAN_STATUS}"
assert_contains "${SCAN_LOG}" "${SCAN_ROOT}/keep/threat.txt: Eicar-Test-Signature FOUND"
assert_contains "${SCAN_LOG}" "Infected files: 1"
assert_contains "${SCAN_LOG}" "Failed batches: 1"
assert_contains "${SCAN_LOG}" "Scan incomplete: 1 of 9 clamdscan batches failed"
rm -f "${SCAN_ROOT}/keep/threat.txt" "${SCAN_ROOT}/keep/fail-batch"
pass "daily scanner: threat status 1; SIGTERM keeps detections and records an incomplete scan (2); a failed batch is status 2 even next to a detection in another batch"

# Preparation failures abort with status 2 before anything is scanned.
REAL_GREP="$(command -v grep)"
FAIL_BIN="${TEMP_DIR}/fail-bin"
mkdir -p "${FAIL_BIN}"
cat >"${FAIL_BIN}/grep" <<MOCK_GREP
#!/usr/bin/env bash
for arg in "\$@"; do [[ "\${arg}" == -azEv ]] && exit 2; done
exec ${REAL_GREP} "\$@"
MOCK_GREP
chmod 0755 "${FAIL_BIN}/grep"
log_since; SCAN_PATH_PREFIX="${FAIL_BIN}:" run_scan
[[ "${SCAN_STATUS}" -eq 2 ]] || fail "Expected status 2 when the path filter fails, got ${SCAN_STATUS}"
assert_contains "${SCAN_LOG}" "Scan aborted: cannot prepare the scan list (path filter failed (grep exit 2))"
[[ ! -s "${CAPTURE_FILE}" ]] || fail "clamdscan ran although the scan list could not be prepared"
assert_not_contains "${SCAN_LOG}" "Scan completed"
log_since
set +e
env PATH="${MOCK_BIN}:${PATH}" CAPTURE_FILE="${CAPTURE_FILE}" LISTED_FILE="${LISTED_FILE}" TMPDIR="${TEMP_DIR}/no-such-dir" \
  bash "${GENERATED_SCAN}" >/dev/null 2>&1
SCAN_STATUS=$?
set -e
[[ "${SCAN_STATUS}" -eq 2 ]] || fail "Expected status 2 when the work directory cannot be created, got ${SCAN_STATUS}"
assert_contains "${SCAN_LOG}" "Scan aborted: cannot prepare the scan list (mktemp failed)"

# Traversal failure: the readable files are still scanned, but the run is incomplete and exits 2.
if [[ "${EUID}" -ne 0 ]]; then
  mkdir -p "${SCAN_ROOT}/locked"
  touch "${SCAN_ROOT}/locked/hidden"
  chmod 000 "${SCAN_ROOT}/locked"
  log_since; run_scan
  chmod 700 "${SCAN_ROOT}/locked"
  [[ "${SCAN_STATUS}" -eq 2 ]] || fail "Expected status 2 on traversal failure, got ${SCAN_STATUS}"
  assert_contains "${SCAN_LOG}" "Traversal incomplete: find exit 1"
  assert_contains "${SCAN_LOG}" "Scan incomplete: traversal failed (find exit 1)"
  listed "${SCAN_ROOT}/keep/a" || fail "readable files were not scanned after a traversal failure"
  rm -f "${SCAN_ROOT}/locked/hidden"; rmdir "${SCAN_ROOT}/locked"
fi
assert_contains "${INSTALLER}" 'check FAIL "daily scan coverage"'
pass "daily scanner: preparation failures (path filter, work directory) abort with status 2 before scanning; traversal failure exits 2 and fails coverage"

# Real clamdscan clients in parallel against the running clamd (unprivileged; skipped when clamd is not reachable).
# One file per batch, two EICAR files in two batches, two clients at a time, and one batch that really fails (a file
# clamdscan cannot open). /var/tmp, not /tmp: /tmp is watched on access and would quarantine the EICAR files.
if command -v clamdscan >/dev/null 2>&1 && clamdscan --ping 1 >/dev/null 2>&1 && [[ "${EUID}" -ne 0 ]]; then
  REAL_ROOT="$(mktemp -d /var/tmp/clamav-installer-test.XXXXXX)"
  REAL_LOG="${TEMP_DIR}/real-scan.log"
  REAL_CONF="${TEMP_DIR}/real-clamd.conf"
  REAL_SCAN="${TEMP_DIR}/real-daily-scan"
  REAL_TMP="${TEMP_DIR}/real-tmp"
  mkdir -p "${REAL_ROOT}/one" "${REAL_ROOT}/two" "${REAL_TMP}"
  REAL_EICAR="$(sed -n "s/^EICAR='\\(.*\\)'\$/\\1/p" "${INSTALLER}")"
  [[ "${REAL_EICAR}" == *EICAR-STANDARD-ANTIVIRUS-TEST-FILE* ]] || fail "could not read the EICAR string from the installer"
  printf '%s' "${REAL_EICAR}" | tee "${REAL_ROOT}/one/eicar-one.txt" >"${REAL_ROOT}/two/eicar-two.txt"
  for i in 1 2 3 4; do printf 'clean %s\n' "${i}" >"${REAL_ROOT}/clean-${i}.txt"; done
  printf 'MaxThreads 2\n' >"${REAL_CONF}"
  {
    cat "${SCAN_HEAD}"
    printf '  %q\n' "${REAL_ROOT}"
    cat "${SCAN_BODY}"
  } | sed -e "s|^LOG_FILE=.*|LOG_FILE=$(printf '%q' "${REAL_LOG}")|" \
      -e "s|^CLAMD_CONF=.*|CLAMD_CONF=$(printf '%q' "${REAL_CONF}")|" \
      -e "s|^LOG_LOCK=.*|LOG_LOCK=$(printf '%q' "${TEMP_DIR}/real.lock")|" \
      -e 's/^BATCH_SIZE=.*/BATCH_SIZE=1/' >"${REAL_SCAN}"
  real_scan() {
    : >"${REAL_LOG}"
    set +e; TMPDIR="${REAL_TMP}" bash "${REAL_SCAN}" >/dev/null 2>&1; REAL_STATUS=$?; set -e
  }
  real_scan
  [[ "${REAL_STATUS}" -eq 1 ]] || fail "real clients: expected status 1, got ${REAL_STATUS}: $(cat "${REAL_LOG}")"
  assert_contains "${REAL_LOG}" "${REAL_ROOT}/one/eicar-one.txt: Eicar-Test-Signature FOUND"
  assert_contains "${REAL_LOG}" "${REAL_ROOT}/two/eicar-two.txt: Eicar-Test-Signature FOUND"
  assert_contains "${REAL_LOG}" "Files scanned: 6 of 6"
  assert_contains "${REAL_LOG}" "Infected files: 2"
  assert_contains "${REAL_LOG}" "Failed batches: 0"
  assert_contains "${REAL_LOG}" "Scan completed: threats found"
  assert_not_contains "${REAL_LOG}" "lock"
  # Regression: the permanent log is copytruncated after every batch (as logrotate may do during a 2 h scan, here even
  # without the log lock). The totals come from the batch records, so both detections still count.
  ROT_SHIM="${TEMP_DIR}/clamdscan-then-rotate"
  cat >"${ROT_SHIM}" <<'ROT_SHIM'
#!/usr/bin/env bash
/usr/bin/clamdscan "$@"
rc=$?
cat "${ROT_LOG}" >>"${ROT_LOG}.1" && : >"${ROT_LOG}"
exit "${rc}"
ROT_SHIM
  chmod 0755 "${ROT_SHIM}"
  sed "s|/usr/bin/clamdscan|${ROT_SHIM}|" "${REAL_SCAN}" >"${REAL_SCAN}.rotate"
  : >"${REAL_LOG}"; : >"${REAL_LOG}.1"
  set +e; ROT_LOG="${REAL_LOG}" TMPDIR="${REAL_TMP}" bash "${REAL_SCAN}.rotate" >/dev/null 2>&1; REAL_STATUS=$?; set -e
  [[ "${REAL_STATUS}" -eq 1 ]] || fail "rotation during the scan: expected status 1, got ${REAL_STATUS}: $(cat "${REAL_LOG}.1" "${REAL_LOG}")"
  cat "${REAL_LOG}.1" "${REAL_LOG}" >"${REAL_LOG}.all"
  assert_contains "${REAL_LOG}" "Infected files: 2"
  assert_contains "${REAL_LOG}" "Files scanned: 6 of 6"
  assert_contains "${REAL_LOG}" "Scan completed: threats found"
  assert_contains "${REAL_LOG}.all" "eicar-one.txt: Eicar-Test-Signature FOUND"
  assert_contains "${REAL_LOG}.all" "eicar-two.txt: Eicar-Test-Signature FOUND"
  printf 'unreadable\n' >"${REAL_ROOT}/locked.txt"
  chmod 000 "${REAL_ROOT}/locked.txt"
  real_scan
  chmod 600 "${REAL_ROOT}/locked.txt"
  [[ "${REAL_STATUS}" -eq 2 ]] || fail "real clients: a failed batch must give status 2, got ${REAL_STATUS}"
  assert_contains "${REAL_LOG}" "eicar-one.txt: Eicar-Test-Signature FOUND"
  assert_contains "${REAL_LOG}" "eicar-two.txt: Eicar-Test-Signature FOUND"
  assert_contains "${REAL_LOG}" "${REAL_ROOT}/locked.txt: Failed to open file"
  assert_contains "${REAL_LOG}" "Total errors: 1"
  assert_contains "${REAL_LOG}" "Infected files: 2"
  assert_contains "${REAL_LOG}" "Files scanned: 6 of 7"
  assert_contains "${REAL_LOG}" "Scan incomplete: 1 of 7 clamdscan batches failed"
  [[ -z "$(ls -A "${REAL_TMP}")" ]] || fail "real clients: work directory left behind"
  rm -f "${REAL_ROOT}/one/eicar-one.txt" "${REAL_ROOT}/two/eicar-two.txt" "${REAL_ROOT}/locked.txt" "${REAL_ROOT}"/clean-*.txt
  rmdir "${REAL_ROOT}/one" "${REAL_ROOT}/two" "${REAL_ROOT}"
  pass "real clamdscan clients in parallel: both EICAR batches detected, no log-lock failures; totals survive a copytruncate of the log mid-run; a really failing batch gives status 2 and keeps the detections"
else
  printf '# clamd not reachable (or running as root); real-client concurrency test skipped\n'
fi

SERVICE_UNIT="${TEMP_DIR}/clamav-daily-scan.service"
extract_heredoc SERVICE "${SERVICE_UNIT}"
for option in PrivateTmp ProtectSystem ProtectHome ProtectKernelTunables ProtectKernelModules ProtectControlGroups; do
  assert_not_contains "${SERVICE_UNIT}" "${option}="
done
assert_contains "${SERVICE_UNIT}" "NoNewPrivileges=true"
assert_contains "${SERVICE_UNIT}" "TimeoutStartSec="
pass "daily scan unit avoids mount namespaces that break --fdpass with AppArmor"

LOGROTATE_RULES="${TEMP_DIR}/clamav-local"
extract_heredoc LOGROTATE "${LOGROTATE_RULES}"
assert_contains "${LOGROTATE_RULES}" "/var/log/clamav/clamonacc.log"
assert_contains "${LOGROTATE_RULES}" "/var/log/clamav/daily-scan.log"
assert_contains "${LOGROTATE_RULES}" "maxsize 50M"
assert_contains "${LOGROTATE_RULES}" "copytruncate"
assert_contains "${LOGROTATE_RULES}" "su root adm"
LR_TIMER="${TEMP_DIR}/clamav-logrotate.timer"
extract_heredoc LRTIMER "${LR_TIMER}"
assert_contains "${LR_TIMER}" "OnCalendar=hourly"
assert_contains "${INSTALLER}" "/etc/clamav/logrotate.conf"
pass "logrotate covers the on-access and daily-scan logs hourly, with copytruncate"

OVERRIDE_UNIT="${TEMP_DIR}/override.conf"
extract_heredoc OVERRIDE "${OVERRIDE_UNIT}"
assert_contains "${OVERRIDE_UNIT}" "UMask=0027"
assert_contains "${INSTALLER}" 'logrotate -f -s /var/lib/logrotate/clamav.status /etc/clamav/logrotate.conf'
assert_not_contains "${INSTALLER}" 'truncate -s 0'
assert_contains "${INSTALLER}" "trap 'cleanup || exit 1' EXIT"
assert_contains "${INSTALLER}" "trap 'cleanup; exit 130' INT"
assert_contains "${INSTALLER}" "sh -c 'set -C; umask 077; cat > \"\$1\"'"
assert_not_contains "${INSTALLER}" 'cat >> "$1"'
# noclobber must refuse an existing file (O_EXCL), so a test file can never overwrite user data
EXISTING="${TEMP_DIR}/existing.txt"
printf 'keep\n' >"${EXISTING}"
if printf 'x' | sh -c 'set -C; cat > "$1"' sh "${EXISTING}" 2>/dev/null; then fail "noclobber did not refuse an existing file"; fi
[[ "$(cat "${EXISTING}")" == keep ]] || fail "existing file was modified"
pass "clamonacc log is private, oversized logs are rotated by logrotate (no manual truncation), EICAR writes are exclusive"

WRITE_FILE_FN="${TEMP_DIR}/write_file.sh"
awk '/^write_file\(\) \{/ { capture = 1 } capture { print } capture && /^\}/ { exit }' "${INSTALLER}" >"${WRITE_FILE_FN}"
WF_TARGET="${TEMP_DIR}/wf-target.conf"
printf 'same\n' >"${WF_TARGET}"
chmod 0600 "${WF_TARGET}"
(
  log() { :; }
  TS=19700101000000
  # shellcheck disable=SC1090
  . "${WRITE_FILE_FN}"
  printf 'same\n' | write_file "${WF_TARGET}" 0644 "$(id -un):$(id -gn)"
)
[[ "$(stat -c %a "${WF_TARGET}")" == 644 ]] || fail "write_file did not repair the mode of an unchanged file"
compgen -G "${WF_TARGET}.*.bak" >/dev/null && fail "write_file backed up an unchanged file"
(
  log() { :; }
  TS=19700101000000
  # shellcheck disable=SC1090
  . "${WRITE_FILE_FN}"
  printf 'new\n' | write_file "${WF_TARGET}" 0644 "$(id -un):$(id -gn)"
)
[[ -f "${WF_TARGET}.19700101000000.bak" ]] || fail "write_file did not back up a changed file as <file>.<timestamp>.bak"
pass "write_file enforces owner and mode, and backs up only changed files"

# Order: hold the rotation timer -> stop writers -> forced rotation -> verification -> release the timer.
hold_line="$(grep -n '^  if lr_hold; then$' "${INSTALLER}" | cut -d: -f1)"
stop_line="$(grep -n '^    stop_writers$' "${INSTALLER}" | cut -d: -f1)"
rotate_line="$(grep -n 'elif logrotate -f -s /var/lib/logrotate/clamav.status /etc/clamav/logrotate.conf; then' "${INSTALLER}" | cut -d: -f1)"
verify_line="$(grep -n '^section "Verification"$' "${INSTALLER}" | cut -d: -f1)"
final_line="$(grep -n 'lr_release final || check FAIL' "${INSTALLER}" | cut -d: -f1)"
if [[ -z "${hold_line}" || -z "${stop_line}" || -z "${rotate_line}" || -z "${verify_line}" || -z "${final_line}" ]]; then
  fail "log preservation steps not found"
fi
(( hold_line < stop_line && stop_line < rotate_line && rotate_line < verify_line && verify_line < final_line )) \
  || fail "hold -> stop -> rotate -> verify -> release order is broken"
assert_not_contains "${INSTALLER}" "enable --now clamav-daily-scan.timer clamav-logrotate.timer"
assert_not_contains "${INSTALLER}" "rm -rf"
assert_contains "${INSTALLER}" 'ExecStart=/usr/bin/flock /run/clamav-daily-scan.lock /usr/sbin/logrotate -s /var/lib/logrotate/clamav.status /etc/clamav/logrotate.conf'
assert_contains "${INSTALLER}" 'LOG_LOCK="/run/clamav-daily-scan.lock"'
# The log lock must be in a root-only directory: both users of it (scan and logrotate) name the same path, and that
# path is not under a world-writable directory where another user could create it first.
SCAN_LOCK_PATH="$(sed -n 's/^LOG_LOCK="\(.*\)"$/\1/p' "${INSTALLER}")"
ROTATE_LOCK_PATH="$(sed -n 's|^ExecStart=/usr/bin/flock \([^ ]*\) /usr/sbin/logrotate .*|\1|p' "${INSTALLER}")"
[[ -n "${SCAN_LOCK_PATH}" && "${SCAN_LOCK_PATH}" == "${ROTATE_LOCK_PATH}" ]] \
  || fail "scan and logrotate must share one lock path (scan '${SCAN_LOCK_PATH}', logrotate '${ROTATE_LOCK_PATH}')"
case "${SCAN_LOCK_PATH}" in
  /run/lock/*|/var/lock/*|/tmp/*|/var/tmp/*|/dev/shm/*) fail "log lock in a world-writable directory: ${SCAN_LOCK_PATH}" ;;
esac
[[ "$(dirname "${SCAN_LOCK_PATH}")" == /run ]] || fail "log lock must be directly in /run: ${SCAN_LOCK_PATH}"
assert_contains "${INSTALLER}" "WRITER_UNITS=(clamav-logrotate.timer clamav-logrotate.service clamav-daily-scan.timer clamav-daily-scan.service clamav-clamonacc.service)"
# clamconf diagnostics are anchored: option names such as OnAccessDenyOnError must not count as errors
if printf 'OnAccessDenyOnError disabled\nOnErrorExecute disabled\n' | grep -E '^(ERROR|LibClamAV Error)|[Pp]arse error|[Uu]nknown option'; then
  fail "clamconf error pattern matches option names"
fi
assert_contains "${INSTALLER}" "grep -E '^(ERROR|LibClamAV Error)|[Pp]arse error|[Uu]nknown option'"
pass "the rotation timer is held from the start until after verification; no recursive deletes; clamconf matched precisely"

# Mock systemctl shared by the writer and timer tests; every call is logged to MOCK_CALLS.
MOCK_SYSTEMD="${TEMP_DIR}/mock-systemd"
mkdir -p "${MOCK_SYSTEMD}"
cat >"${MOCK_SYSTEMD}/systemctl" <<'MOCK_UNITS'
#!/usr/bin/env bash
[[ -n "${MOCK_CALLS:-}" ]] && printf '%s\n' "$*" >>"${MOCK_CALLS}"
state_file="${MOCK_STATE_FILE:-/dev/null}"
current_state() { if [[ -s "${state_file}" ]]; then cat "${state_file}"; else echo "${MOCK_STATE:-inactive}"; fi; }
case "$1" in
  show)
    [[ "${MOCK_SHOW_RC:-0}" -eq 0 ]] || exit "${MOCK_SHOW_RC}"
    if [[ "$*" == *--value* ]]; then
      case "$3" in
        LoadState) echo "${MOCK_LOAD:-loaded}" ;;
        ActiveState) current_state ;;
        UnitFileState) echo "${MOCK_ENABLED:-enabled}" ;;
      esac
    else
      printf 'LoadState=%s\nUnitFileState=%s\nActiveState=%s\n' "${MOCK_LOAD:-loaded}" "${MOCK_ENABLED:-enabled}" "$(current_state)"
    fi ;;
  stop) [[ "${MOCK_STOP_RC:-0}" -eq 0 ]] || exit "${MOCK_STOP_RC}"; [[ "${state_file}" == /dev/null ]] || echo inactive >"${state_file}" ;;
  start) [[ "${MOCK_START_RC:-0}" -eq 0 ]] || exit "${MOCK_START_RC}"; [[ "${state_file}" == /dev/null ]] || echo active >"${state_file}" ;;
  mask) exit "${MOCK_MASK_RC:-0}" ;;
  unmask) exit "${MOCK_UNMASK_RC:-0}" ;;
  *) exit 0 ;;
esac
MOCK_UNITS
chmod 0755 "${MOCK_SYSTEMD}/systemctl"

# Writer confirmation is FAIL-CLOSED.
WRITER_FNS="${TEMP_DIR}/writer-fns.sh"
awk '/^WRITER_UNITS=\(/ { capture = 1 } /^db_age_hours\(\) \{/ { exit } capture { print }' "${INSTALLER}" >"${WRITER_FNS}"
grep -q '^may_rotate() {' "${WRITER_FNS}" || fail "writer helper functions not found"
WRITER_LOG="${TEMP_DIR}/writer.log"
printf 'old\n' >"${WRITER_LOG}"
writer_case() {  # writer_case EXPECT(allow|block) REASON_SUBSTRING ENV...
  local expect="$1" reason="$2"
  shift 2
  env "$@" PATH="${MOCK_SYSTEMD}:${PATH}" WRITER_FNS="${WRITER_FNS}" WRITER_LOG="${WRITER_LOG}" \
    EXPECT="${expect}" REASON="${reason}" bash -c '
      . "${WRITER_FNS}"
      stop_writers
      if may_rotate "${WRITER_LOG}"; then got=allow; else got=block; fi
      [[ "${got}" == "${EXPECT}" ]] || { echo "expected ${EXPECT}, got ${got}: ${SKIP_REASON}" >&2; exit 1; }
      [[ -z "${REASON}" || "${SKIP_REASON}" == *"${REASON}"* ]] || { echo "reason: ${SKIP_REASON}" >&2; exit 1; }
    '
}
writer_case block "state query failed" MOCK_SHOW_RC=1 || fail "failed unit discovery must block rotation"
writer_case block "stop failed" MOCK_STOP_RC=1 || fail "a failed stop must block rotation"
writer_case block "hold: mask failed" LR_HOLD_PROBLEMS="mask failed" || fail "a failed timer hold must block rotation"
writer_case block "active" MOCK_STATE=active || fail "a unit that is still active must block rotation"
writer_case block "activating" MOCK_STATE=activating || fail "a unit that is activating must block rotation"
writer_case allow "" MOCK_LOAD=not-found || fail "units that do not exist must not block rotation"
writer_case allow "" || fail "rotation must be allowed once every writer is confirmed stopped"
( exec 3>>"${WRITER_LOG}"; sleep 30 ) &
WRITER_PID=$!
for _ in $(seq 50); do [[ "$(readlink "/proc/${WRITER_PID}/fd/3" 2>/dev/null)" == "${WRITER_LOG}" ]] && break; sleep 0.1; done
if ! writer_case block "still open by PID ${WRITER_PID}"; then
  kill "${WRITER_PID}" 2>/dev/null
  fail "an open writer must block rotation"
fi
kill "${WRITER_PID}" 2>/dev/null || true
wait "${WRITER_PID}" 2>/dev/null || true
pass "rotation is fail-closed: query/stop errors, a failed timer hold, active units and open writers all block it"

# The cleanup region: self-test cleanup, timer hold/release and the EXIT/INT/TERM traps.
CLEANUP_FN="${TEMP_DIR}/cleanup.sh"
awk '/^# Self-test cleanup never deletes recursively/ { capture = 1 } capture { print } capture && /^trap .cleanup; exit 143. TERM/ { exit }' "${INSTALLER}" >"${CLEANUP_FN}"
grep -q "^trap 'cleanup; exit 143' TERM" "${CLEANUP_FN}" || fail "cleanup region not found"
timer_run() {  # timer_run SCRIPT ENV...: run SCRIPT with the cleanup region and the mock systemctl
  local script="$1"
  shift
  : >"${TEMP_DIR}/calls"
  rm -f "${TEMP_DIR}/state"
  env "$@" PATH="${MOCK_SYSTEMD}:${PATH}" MOCK_CALLS="${TEMP_DIR}/calls" MOCK_STATE_FILE="${TEMP_DIR}/state" \
    REPORT_TMP="${TEMP_DIR}/report.tmp" EICAR='EICAR-TEST' bash -c ". '${CLEANUP_FN}'; ${script}"
}
calls_in_order() {  # calls_in_order PATTERN...: the patterns appear in the call log in this order
  local line=0 next pattern
  for pattern in "$@"; do
    next="$(grep -n -F -- "${pattern}" "${TEMP_DIR}/calls" | cut -d: -f1 | awk -v l="${line}" '$1 > l { print; exit }')"
    [[ -n "${next}" ]] || return 1
    line="${next}"
  done
}
# an early exit restores exactly the recorded state: active timer -> unmask + start
timer_run 'lr_hold || exit 9; exit 0' MOCK_STATE=active MOCK_ENABLED=enabled 2>/dev/null \
  || fail "EXIT after holding an active timer must succeed (status $?)"
calls_in_order "mask --runtime clamav-logrotate.timer" "stop clamav-logrotate.timer" \
  "unmask --runtime clamav-logrotate.timer" "start clamav-logrotate.timer" \
  || fail "EXIT did not restore the held timer (mask, stop, unmask, start): $(paste -sd'|' "${TEMP_DIR}/calls")"
# a timer that was inactive is unmasked but not started
timer_run 'lr_hold || exit 9; exit 0' MOCK_STATE=inactive MOCK_ENABLED=disabled 2>/dev/null \
  || fail "EXIT after holding an inactive timer must succeed (status $?)"
calls_in_order "unmask --runtime clamav-logrotate.timer" || fail "EXIT did not unmask the held timer"
if grep -q '^start clamav-logrotate.timer' "${TEMP_DIR}/calls"; then fail "EXIT started a timer that was inactive before"; fi
# restore errors are reported and make the exit status non-zero
set +e
restore_err="$(timer_run 'lr_hold || exit 9; exit 0' MOCK_STATE=active MOCK_UNMASK_RC=1 2>&1 >/dev/null)"
restore_status=$?
set -e
[[ "${restore_status}" -ne 0 ]] || fail "a failed timer restore must make the exit status non-zero"
[[ "${restore_err}" == *"could not restore clamav-logrotate.timer"*"unmask failed"* ]] || fail "a failed restore is not reported: ${restore_err}"
# INT/TERM also restore the timer
set +e
timer_run 'lr_hold || exit 9; kill -TERM $$; sleep 5' MOCK_STATE=active 2>/dev/null
term_status=$?
set -e
[[ "${term_status}" -eq 143 ]] || fail "TERM should exit 143, got ${term_status}"
calls_in_order "mask --runtime clamav-logrotate.timer" "unmask --runtime clamav-logrotate.timer" "start clamav-logrotate.timer" \
  || fail "TERM did not restore the held timer"
# a hold that cannot query systemd fails (fail-closed) and holds nothing
timer_run 'if lr_hold; then exit 1; fi; [[ "${LR_PROBLEMS}" == *"state query failed"* && "${LR_HELD}" -eq 0 ]]' MOCK_SHOW_RC=1 \
  || fail "a failed state query must make lr_hold fail without holding"
pass "the rotation timer state is recorded, held and restored exactly on EXIT/INT/TERM; restore errors are reported"

# EICAR self-tests: private directory created by the user; cleanup removes exact names only, never recursively.
SELFTEST_FNS="${TEMP_DIR}/selftest-fns.sh"
awk '/^# make_selftest_file USER DIR:/ { capture = 1 } /^# On-access: a protected user writes EICAR/ { exit } capture { print }' "${INSTALLER}" >"${SELFTEST_FNS}"
grep -q '^make_selftest_file() {' "${SELFTEST_FNS}" || fail "self-test helpers not found"
WATCHED="${TEMP_DIR}/watched"
QUAR="${TEMP_DIR}/quarantine"
DATA="${TEMP_DIR}/userdata"
mkdir -p "${WATCHED}" "${QUAR}" "${DATA}"
printf 'user data\n' >"${WATCHED}/notes.txt"
printf 'precious\n' >"${DATA}/precious.txt"
selftest_run() {  # selftest_run SCRIPT: helpers + cleanup region + traps, with a temp quarantine
  REPORT_TMP="${TEMP_DIR}/report.tmp" QUARANTINE_DIR="${QUAR}" EICAR='EICAR-TEST' WATCHED="${WATCHED}" DATA="${DATA}" \
    PATH="${MOCK_SYSTEMD}:${PATH}" bash -c ". '${CLEANUP_FN}'; . '${SELFTEST_FNS}'; $1"
}
no_selftest_left() { [[ -z "$(find "${WATCHED}" "${QUAR}" -name '.clamav-selftest.*' 2>/dev/null)" ]]; }
# success: private 700 directory; exact file and directory registered; cleanup removes only those
selftest_run 'make_selftest_file "$(id -un)" "${WATCHED}" || exit 1
  d="$(dirname "${SELFTEST_FILE}")"
  [[ "$(stat -c %a "${d}")" == 700 && "$(cat "${SELFTEST_FILE}")" == EICAR-TEST ]] || exit 2
  [[ "${#CLEANUP_USER_DIRS[@]}" -eq 1 && "${CLEANUP_USER_DIRS[0]}" == "$(id -un)"$'"'"'\t'"'"'"${d}" ]] || exit 3
  [[ "${#CLEANUP_USER_FILES[@]}" -eq 1 && "${CLEANUP_USER_FILES[0]}" == *$'"'"'\t'"'"'"${SELFTEST_FILE}" ]] || exit 4' \
  || fail "make_selftest_file did not create and register a private directory (status $?)"
no_selftest_left || fail "cleanup left the self-test directory behind"
[[ "$(cat "${WATCHED}/notes.txt")" == "user data" ]] || fail "cleanup touched a file it did not create"
# the private directory is replaced by a directory holding foreign data: nothing foreign is deleted
selftest_run 'make_selftest_file "$(id -un)" "${WATCHED}" || exit 1
  d="$(dirname "${SELFTEST_FILE}")"
  mv "${d}" "${d}.ours"
  mkdir "${d}"
  printf "foreign\n" >"${d}/foreign.txt"
  printf "%s" "${d}" >"${WATCHED}/.replaced-path"' \
  || fail "directory replacement scenario failed to run (status $?)"
replaced="$(cat "${WATCHED}/.replaced-path")"
[[ "$(cat "${replaced}/foreign.txt")" == foreign ]] || fail "cleanup deleted foreign data from a replaced directory"
rm -f "${replaced}/foreign.txt" "${WATCHED}/.replaced-path" "${replaced}.ours/"/.clamav-selftest.*.txt
rmdir "${replaced}" "${replaced}.ours"
# the private directory is replaced by a symlink to a data directory: the data directory is untouched
selftest_run 'make_selftest_file "$(id -un)" "${WATCHED}" || exit 1
  d="$(dirname "${SELFTEST_FILE}")"
  mv "${d}" "${d}.ours"
  ln -s "${DATA}" "${d}"
  printf "%s" "${d}" >"${WATCHED}/.replaced-path"' \
  || fail "symlink replacement scenario failed to run (status $?)"
replaced="$(cat "${WATCHED}/.replaced-path")"
[[ -L "${replaced}" && "$(cat "${DATA}/precious.txt")" == precious ]] || fail "cleanup followed a replaced symlink into user data"
rm -f "${replaced}" "${WATCHED}/.replaced-path" "${replaced}.ours/"/.clamav-selftest.*.txt
rmdir "${replaced}.ours"
# creation failure (folder not writable): nothing registered, nothing deleted
chmod 0500 "${WATCHED}"
selftest_run 'if make_selftest_file "$(id -un)" "${WATCHED}"; then exit 1; fi
  [[ "${#CLEANUP_USER_DIRS[@]}" -eq 0 && "${#CLEANUP_USER_FILES[@]}" -eq 0 && "${#CLEANUP_QUARANTINE[@]}" -eq 0 ]] || exit 2' \
  || fail "a failed directory creation must register nothing (status $?)"
chmod 0700 "${WATCHED}"
[[ "$(cat "${WATCHED}/notes.txt")" == "user data" ]] || fail "a failed creation touched user data"
# creation collisions with a deterministic name (mktemp stubbed)
printf 'foreign\n' >"${QUAR}/.clamav-selftest.FIXED.txt"
selftest_run 'mktemp() { mkdir -m 700 "${WATCHED}/.clamav-selftest.FIXED" && echo "${WATCHED}/.clamav-selftest.FIXED"; }
  make_selftest_file "$(id -un)" "${WATCHED}" || exit 1
  [[ "${#CLEANUP_QUARANTINE[@]}" -eq 0 ]] || exit 2' \
  || fail "an existing quarantine file must not be registered for cleanup (status $?)"
[[ "$(cat "${QUAR}/.clamav-selftest.FIXED.txt")" == foreign ]] || fail "cleanup deleted a quarantine file it did not create"
rm -f "${QUAR}/.clamav-selftest.FIXED.txt"
mkdir -m 700 "${WATCHED}/.clamav-selftest.FIXED"
printf 'foreign\n' >"${WATCHED}/.clamav-selftest.FIXED/own.txt"
selftest_run 'mktemp() { mkdir -m 700 "${WATCHED}/.clamav-selftest.FIXED" 2>/dev/null && echo "${WATCHED}/.clamav-selftest.FIXED"; }
  if make_selftest_file "$(id -un)" "${WATCHED}"; then exit 1; fi
  [[ "${#CLEANUP_USER_DIRS[@]}" -eq 0 && "${#CLEANUP_USER_FILES[@]}" -eq 0 ]] || exit 2' \
  || fail "a directory-name collision must fail and register nothing (status $?)"
[[ "$(cat "${WATCHED}/.clamav-selftest.FIXED/own.txt")" == foreign ]] || fail "a creation collision deleted foreign data"
rm -f "${WATCHED}/.clamav-selftest.FIXED/own.txt"
rmdir "${WATCHED}/.clamav-selftest.FIXED"
# a foreign file at the registered quarantine path (other inode, other content) is kept
selftest_run 'make_selftest_file "$(id -un)" "${WATCHED}" || exit 1
  printf "foreign quarantine\n" >"${QUARANTINE_DIR}/$(basename "${SELFTEST_FILE}")"'
leftover_q="$(find "${QUAR}" -name '.clamav-selftest.*' | head -n1)"
[[ -n "${leftover_q}" && "$(cat "${leftover_q}")" == "foreign quarantine" ]] || fail "cleanup deleted a quarantine file that is not our copy"
rm -f "${leftover_q}"
# write collision inside the private directory: noclobber refuses, the existing file is kept
selftest_run 'd="$(mktemp -d "${WATCHED}/.clamav-selftest.XXXXXXXXXX")"
  printf "keep" >"${d}/x.txt"
  if printf "EICAR" | sh -c "set -C; cat > \"\$1\"" sh "${d}/x.txt" 2>/dev/null; then exit 1; fi
  [[ "$(cat "${d}/x.txt")" == keep ]] || exit 2
  rm -f "${d}/x.txt"; rmdir "${d}"' \
  || fail "an exclusive write must not overwrite an existing file (status $?)"
# interrupted run (TERM) after clamonacc-style move into the quarantine: our copy (same inode) and dir removed
set +e
selftest_run 'make_selftest_file "$(id -un)" "${WATCHED}" || exit 1
  mv "${SELFTEST_FILE}" "${QUARANTINE_DIR}/$(basename "${SELFTEST_FILE}")"
  kill -TERM $$
  sleep 5'
INTERRUPT_STATUS=$?
set -e
[[ "${INTERRUPT_STATUS}" -eq 143 ]] || fail "interrupted run should exit 143, got ${INTERRUPT_STATUS}"
no_selftest_left || fail "interrupted run left self-test files behind"
[[ "$(cat "${WATCHED}/notes.txt")" == "user data" && "$(cat "${DATA}/precious.txt")" == precious ]] || fail "interrupted cleanup touched foreign files"
pass "EICAR self-tests: exact-name cleanup as the user, rmdir only, quarantine by owner+inode; replaced dirs and foreign files are never deleted"

CLAMD_RAW="${TEMP_DIR}/clamd.raw"
extract_heredoc CLAMD "${CLAMD_RAW}"
for option in "HeuristicAlerts true" "AlertBrokenExecutables true" '${EXCLUDE_PATH_LINES}' \
  'ConcurrentDatabaseReload ${CONCURRENT_RELOAD}' \
  "OnAccessExcludeUname clamav" "OnAccessExcludeRootUID true" "LocalSocketMode 660" \
  "TemporaryDirectory /var/lib/clamav/tmp" "OnAccessExtraScanning true" "OnAccessDenyOnError false"; do
  assert_contains "${CLAMD_RAW}" "${option}"
done
for option in AlgorithmicDetection ArchiveBlockEncrypted PhishingAlwaysBlock "PartitionIntersection false" OLE2BlockMacros; do
  if grep -Eq "^${option}" "${CLAMD_RAW}"; then fail "Deprecated clamd option still present: ${option}"; fi
done
pass "clamd.conf uses current option names and the hardening defaults"

extract_function() {  # extract_function NAME DEST: a top-level installer function, from "NAME() {" to "}"
  awk -v name="$1" 'index($0, name "() {") == 1 { capture = 1 } capture { print } capture && /^\}/ { exit }' \
    "${INSTALLER}" >"$2"
  [[ -s "$2" ]] || fail "installer function $1 not found"
}
FUNCS="${TEMP_DIR}/tuning-functions.sh"
: >"${FUNCS}"
for fn in default_max_threads regex_escape exclude_path_lines set_freshclam_checks clamconf_value unit_started_after; do
  extract_function "${fn}" "${TEMP_DIR}/fn-${fn}.sh"
  cat "${TEMP_DIR}/fn-${fn}.sh" >>"${FUNCS}"
done

(
  . "${FUNCS}"
  for pair in 1:1 2:1 3:1 4:2 5:2 7:3 8:4 9:4 16:4 64:4 0:1 x:1 "":1; do
    got="$(default_max_threads "${pair%%:*}")"
    [[ "${got}" == "${pair##*:}" ]] || fail "default_max_threads ${pair%%:*}: expected ${pair##*:}, got ${got}"
  done
)
assert_contains "${INSTALLER}" 'if [[ "${MAX_THREADS}" -eq 0 ]]; then MAX_THREADS="$(default_max_threads "${CPU_COUNT}")"; fi'
assert_not_contains "${INSTALLER}" 'CPUQuota'
pass "default worker count is half the CPUs rounded down, at least 1, at most 4; no hard CPU quota"

# excluded_by RULES_FILE PATH: true when any ExcludePath regex matches PATH (clamd uses POSIX extended regex search).
excluded_by() {
  local rules="$1" path="$2" rule
  while IFS= read -r rule; do
    if printf '%s\n' "${path}" | grep -Eq -- "${rule}"; then return 0; fi
  done < <(sed -n 's/^ExcludePath //p' "${rules}")
  return 1
}
expect_excluded() { excluded_by "$1" "$2" || fail "$3: expected excluded: $2"; }
expect_scanned() { if excluded_by "$1" "$2"; then fail "$3: expected scanned: $2"; fi; }
RULES_DEFAULT="${TEMP_DIR}/rules-default"
RULES_OPTIN="${TEMP_DIR}/rules-optin"
( . "${FUNCS}"; EXCLUDE_DEV_CACHES=0; exclude_path_lines /home/alice /home/odd.user/ ) >"${RULES_DEFAULT}"
( . "${FUNCS}"; EXCLUDE_DEV_CACHES=1; exclude_path_lines /home/alice /home/odd.user ) >"${RULES_OPTIN}"
( . "${FUNCS}"; EXCLUDE_DEV_CACHES=0; exclude_path_lines ) | grep -q '^ExcludePath ^/(proc|sys|dev|run)(/|\$)$' \
  || fail "system exclusions missing when no home is protected"
for f in "${RULES_DEFAULT}" "${RULES_OPTIN}"; do
  for p in /proc/1/maps /run /run/user/1000/bus /sys /var/lib/docker /var/lib/docker/overlay2/l/x \
    /home/alice/src/app/node_modules /home/alice/src/app/node_modules/x/index.js /home/alice/p/.git/objects/ab/cd \
    /home/alice/.local/share/containers/storage/x /home/alice/.cache/thumbnails/large/x.png \
    /home/odd.user/.cache/fontconfig/a.cache-8 /home/alice/.cache/mesa_shader_cache; do
    expect_excluded "${f}" "${p}" "$(basename "${f}")"
  done
  for p in /runner/x /home/alice/run/x /proc-notes/x /home/alice/Downloads/x/.m2/repository/payload.jar \
    /home/alice/.m2/repository/a/b.jar /home/alice/.local/share/flatpak/app/x/bin/x /home/alice/.rustup/toolchains/s/bin/rustc \
    /home/alice/.cargo/registry/src/x/lib.rs /home/alice/go/pkg/mod/example.com/x.go /home/alice/.gradle/caches/x.jar \
    /home/alice/Downloads/.cache/thumbnails/x /home/alice/Downloads/.cache/x.exe /home/oddXuser/.cache/fontconfig/a \
    /home/alice/p/.git/objects-backup/x /home/alice/node_modules_old/x /snap/bin/x \
    /home/alice/snap/x/y /home/alice/Downloads/x.exe /home/bob/.cache/thumbnails/x \
    /home/alice/.config/Code/CachedExtensionVSIXs/ms-python.python-2026.4.0-linux-x64 \
    /home/alice/.docker/desktop/vms/0/data/Docker.raw /home/alice/.docker/desktop/backend.sock \
    /home/alice/.config/herdr/herdr.sock; do
    expect_scanned "${f}" "${p}" "$(basename "${f}")"
  done
done
for p in /home/alice/.cache/pip/x.whl /home/alice/.npm/_cacache/content-v2/x /home/alice/.cargo/registry/cache/x.crate \
  /home/alice/go/pkg/mod/cache/download/x.zip /home/odd.user/.cache /home/alice/.cache/thumbnailsX/x \
  /home/alice/.cache/ibus/dbus-x /home/alice/.cache/zed/zed-crash-handler-1; do
  expect_scanned "${RULES_DEFAULT}" "${p}" "default"
  expect_excluded "${RULES_OPTIN}" "${p}" "opt-in"
done
grep -Ev '^ExcludePath [^ ]+$' "${RULES_OPTIN}" && fail "malformed ExcludePath line"
assert_contains "${INSTALLER}" '--exclude-dev-caches) EXCLUDE_DEV_CACHES=1'
pass "ExcludePath: (/|$) boundaries, home-anchored rules, executables and toolchains scanned, dev caches only opt-in"

# Path rules that were replaced: special files are skipped by type, VSIX false positives by exact hash.
for removed in DAILY_EXCLUDES EXCLUDE_REGEXES '\.sock' CachedExtensionVSIXs 'desktop/vms' ibus zed-crash-handler; do
  if grep -E '^[[:space:]]*(ExcludePath|.*ExcludePath ).*' "${INSTALLER}" | grep -qF -- "${removed}"; then
    fail "removed exclusion is back: ${removed}"
  fi
  if grep -qF -- "${removed}" "${RULES_OPTIN}"; then fail "removed exclusion generated: ${removed}"; fi
done
assert_not_contains "${INSTALLER}" "DAILY_EXCLUDES"
assert_not_contains "${INSTALLER}" ".ign2"
pass "no path rules for sockets, ibus, zed, Docker Desktop VMs or cached VSIX packages; no signature-name ignore list"

FP_RAW="${TEMP_DIR}/fp-allowlist.raw"
FP_DB="${TEMP_DIR}/local.sfp"
extract_heredoc FP_ALLOWLIST "${FP_RAW}"
assert_contains "${INSTALLER}" "grep -v -E '^[[:space:]]*(#|\$)' <<'FP_ALLOWLIST' | write_file /var/lib/clamav/local.sfp 0644 clamav:clamav"
grep -v -E '^[[:space:]]*(#|$)' "${FP_RAW}" >"${FP_DB}"
[[ "$(wc -l <"${FP_DB}")" -eq 2 ]] || fail "expected exactly 2 allowlisted hashes, got $(wc -l <"${FP_DB}")"
grep -Ev '^[0-9a-f]{64}:[0-9]+:[A-Za-z0-9._-]+$' "${FP_DB}" && fail "allowlist entry is not sha256:size:name"
assert_contains "${FP_DB}" "1d07e60d5eab257ea5d691b26def3fff642b4d2c04fab94424e8b8fe25baf656:17823311:ms-python.python-2026.4.0-linux-x64.vsix"
assert_contains "${FP_DB}" "7cea86fc649098a0c7037275d31fe6f6ae5446348f028587aa0fce7d9b73e35f:12859354:ms-python.vscode-python-envs-1.36.0-linux-x64.vsix"
grep -q 'Heuristics' "${FP_DB}" && fail "the allowlist must list file hashes, never a signature name"
assert_contains "${FP_RAW}" "marketplace.visualstudio.com"
if command -v clamscan >/dev/null 2>&1; then
  # Functional check with the installed engine: a file detected by a test signature is no longer reported once its
  # sha256 is in a .sfp next to it, a different file still is, and the generated local.sfp loads without errors.
  FP_ENGINE_DB="${TEMP_DIR}/fp-db"
  mkdir -p "${FP_ENGINE_DB}"
  printf 'allowlisted sample\n' >"${TEMP_DIR}/fp-sample"
  printf 'other sample\n' >"${TEMP_DIR}/fp-other"
  for f in fp-sample fp-other; do
    printf '%s:%s:Test.FP.%s\n' "$(md5sum <"${TEMP_DIR}/${f}" | cut -d' ' -f1)" "$(stat -c %s "${TEMP_DIR}/${f}")" "${f}"
  done >"${FP_ENGINE_DB}/test.hdb"
  cp "${FP_DB}" "${FP_ENGINE_DB}/local.sfp"
  printf '%s:%s:fp-sample\n' "$(sha256sum <"${TEMP_DIR}/fp-sample" | cut -d' ' -f1)" "$(stat -c %s "${TEMP_DIR}/fp-sample")" \
    >>"${FP_ENGINE_DB}/local.sfp"
  set +e
  FP_OUT="$(clamscan --no-summary -d "${FP_ENGINE_DB}" "${TEMP_DIR}/fp-sample" "${TEMP_DIR}/fp-other" 2>&1)"
  FP_RC=$?
  set -e
  [[ "${FP_RC}" -eq 1 ]] || fail "clamscan with the allowlist exited ${FP_RC}: ${FP_OUT}"
  [[ "${FP_OUT}" == *"fp-sample: OK"* && "${FP_OUT}" == *"fp-other: Test.FP.fp-other.UNOFFICIAL FOUND"* ]] \
    || fail "sha256 .sfp allowlist did not behave as expected: ${FP_OUT}"
fi
pass "false-positive allowlist: exactly the two official ms-python VSIX hashes (sha256:size:name, provenance in comments), installed as local.sfp"

SLICE_UNIT="${TEMP_DIR}/clamav.slice"
DAEMON_DROPIN="${TEMP_DIR}/desktop-limits.conf"
extract_heredoc SLICE "${SLICE_UNIT}"
extract_heredoc DAEMONLIMITS "${DAEMON_DROPIN}"
assert_contains "${SLICE_UNIT}" "[Slice]"
assert_contains "${SLICE_UNIT}" "CPUWeight=20"
assert_contains "${DAEMON_DROPIN}" "Slice=clamav.slice"
grep -Eq '^(Nice|CPUQuota|IOScheduling)' "${DAEMON_DROPIN}" && fail "clamd drop-in must only move clamd to the weighted slice"
assert_contains "${SERVICE_UNIT}" "Slice=clamav.slice"
assert_contains "${SERVICE_UNIT}" "Nice=10"
assert_contains "${INSTALLER}" 'CONCURRENT_RELOAD="yes"'
assert_contains "${INSTALLER}" '[[ "${LOW_MEMORY}" -eq 1 ]] && CONCURRENT_RELOAD="no"'
assert_contains "${HELP_OUTPUT}" "--exclude-dev-caches"
assert_contains "${HELP_OUTPUT}" "--low-memory"
pass "clamd runs in clamav.slice (CPUWeight=20, no quota); concurrent reload stays on unless --low-memory"

FC="${TEMP_DIR}/freshclam.conf"
printf '# Checks 24\nDatabaseMirror database.clamav.net\nChecks\t24\n  Checks 6\nNotifyClamd /etc/clamav/clamd.conf\nChecks 12\n' >"${FC}"
chmod 0640 "${FC}"
(
  log() { :; }
  . "${FUNCS}"
  TS=19700101000000; set_freshclam_checks "${FC}" 12
  [[ "$(cat "${FC}")" == $'# Checks 24\nDatabaseMirror database.clamav.net\nChecks 12\nNotifyClamd /etc/clamav/clamd.conf' ]] \
    || fail "freshclam Checks not normalized: $(cat -A "${FC}")"
  [[ -f "${FC}.19700101000000.bak" ]] || fail "changed freshclam.conf was not backed up"
  [[ "$(stat -c %a "${FC}")" == 640 ]] || fail "freshclam.conf mode not kept"
  TS=19700101000001; set_freshclam_checks "${FC}" 12
  [[ ! -e "${FC}.19700101000001.bak" ]] || fail "repeat run rewrote an already normalized freshclam.conf"
  printf 'DatabaseMirror x\n' >"${FC}"
  TS=19700101000002; set_freshclam_checks "${FC}" 12
  [[ "$(cat "${FC}")" == $'DatabaseMirror x\nChecks 12' ]] || fail "missing Checks was not added"
)
pass "freshclam Checks: tabs, indentation and duplicates normalized to one line, comments kept, repeat runs stable"

CLAMCONF_SAMPLE="${TEMP_DIR}/clamconf.out"
printf '%s\n' 'Config file: clamd.conf' '----------------------' 'MaxThreads = "4"' 'ConcurrentDatabaseReload disabled' \
  '' 'Config file: freshclam.conf' '--------------------------' 'MaxThreads = "99"' 'Checks = "12"' >"${CLAMCONF_SAMPLE}"
STAMP_FILE="${TEMP_DIR}/stamp.conf"
touch -d @1000 "${STAMP_FILE}"
cat >"${MOCK_BIN}/systemctl" <<'MOCK_SHOW_TS'
#!/usr/bin/env bash
printf '@%s\n' "${MOCK_START:-}"
MOCK_SHOW_TS
(
  . "${FUNCS}"
  [[ "$(clamconf_value clamd.conf MaxThreads <"${CLAMCONF_SAMPLE}")" == 4 ]] || fail "clamconf_value read the wrong MaxThreads"
  [[ "$(clamconf_value clamd.conf ConcurrentDatabaseReload <"${CLAMCONF_SAMPLE}")" == no ]] || fail "disabled boolean not read as no"
  [[ "$(clamconf_value freshclam.conf Checks <"${CLAMCONF_SAMPLE}")" == 12 ]] || fail "clamconf_value read the wrong Checks"
  PATH="${MOCK_BIN}:${PATH}"
  MOCK_START=2000 unit_started_after x.service "${STAMP_FILE}" || fail "unit started after the change was reported stale"
  if MOCK_START=500 unit_started_after x.service "${STAMP_FILE}"; then fail "unit started before the change was reported current"; fi
  if MOCK_START= unit_started_after x.service "${STAMP_FILE}"; then fail "unknown start time was reported current"; fi
)
for name in 'check PASS "clamd CPU weight (effective)"' 'check PASS "tuning (parsed by clamconf)"' \
  'check PASS "clamd runs the current config"' 'check PASS "freshclam runs the current config"'; do
  assert_contains "${INSTALLER}" "${name}"
done
pass "verification reports effective systemd limits, clamconf-parsed values and whether services run the current config"

# clamdscan exits 1 when it detects EICAR; under pipefail it must not be piped into grep.
if grep -Eq 'clamdscan [^|]*\| *grep' "${INSTALLER}"; then fail "clamdscan output must not be piped into grep under pipefail"; fi
assert_contains "${INSTALLER}" 'scan_rc=$?'
# The user-readable report must never contain raw log lines (file names).
if grep -Eq 'clamonacc\.log[^|]*\|[^#]*tee -a "\$\{REPORT_TMP\}"' "${INSTALLER}"; then fail "raw clamonacc.log lines reach the user report"; fi
SUMMARY_PROG="${TEMP_DIR}/summary.awk"
extract_heredoc SUMMARY_AWK "${SUMMARY_PROG}"
CRAFTED_LOG="${TEMP_DIR}/crafted-daily-scan.log"
cat >"${CRAFTED_LOG}" <<'CRAFTED'
[2026-11-01 02:00:01] Starting parallel ClamAV daily scan for: /home/alice
[2026-11-01 02:00:01] Files to scan: 99
Special files skipped: 98
Vanished before scan: 97
Total errors: 96
[2026-11-01 02:00:01] Traversal incomplete: find exit 1 (unreadable or vanished paths); the lists are a minimum
[2026-11-02 02:00:01] Starting parallel ClamAV daily scan for: /home/alice /home/bob
[2026-11-02 02:00:01] Files to scan: 1234
[2026-11-02 02:00:01] Special files skipped: 7
/home/bob/private/Scan completed confidential.txt: Eicar-Test-Signature FOUND
/home/bob/Total errors: 0 secret-plan.txt: Eicar-Test-Signature FOUND
Vanished before scan: /home/bob/.cache/tmp-file
----------- SCAN SUMMARY -----------
Infected files: 2
Total errors: 0
Vanished before scan: 1
Special files skipped: 7
Time: 42.000 sec (0 m 42 s)
[2026-11-02 02:00:44] Scan completed: threats found
CRAFTED
SUMMARY_OUT="$(awk -f "${SUMMARY_PROG}" "${CRAFTED_LOG}")"
[[ "${SUMMARY_OUT}" == "files=1234 skipped=7 vanished=1 infected=2 errors=0 time=42.000s traversal=complete result=Scan completed: threats found" ]] \
  || fail "Unexpected scan summary: ${SUMMARY_OUT}"
case "${SUMMARY_OUT}" in *confidential*|*secret*|*/home/*) fail "Scan summary leaks a file name: ${SUMMARY_OUT}" ;; esac
printf '[2026-11-02 02:00:01] Traversal incomplete: find exit 1 (unreadable or vanished paths); the listed files are still scanned\n[2026-11-02 02:00:50] Scan incomplete: traversal failed (find exit 1)\n' >>"${CRAFTED_LOG}"
[[ "$(awk -f "${SUMMARY_PROG}" "${CRAFTED_LOG}")" == *"result=Scan incomplete: traversal failed (find exit 1)" ]] || fail "incomplete result not reported"
[[ "$(awk -f "${SUMMARY_PROG}" "${CRAFTED_LOG}")" == *"traversal=incomplete"* ]] || fail "Incomplete traversal is not reported"
pass "verification handles clamdscan exit codes and keeps file names out of the report"

assert_contains "${INSTALLER}" 'REQUIRED_FOLDERS=(Desktop Downloads Documents)'
# shellcheck disable=SC2016  # literal source text
assert_contains "${INSTALLER}" 'check PASS "coverage ${label}"'
# shellcheck disable=SC2016  # literal source text
assert_contains "${INSTALLER}" 'onaccess_test "${TARGET_USERS[$i]}" "$(readlink -f "${dir}")" "~${TARGET_USERS[$i]}/${folder}"'
pass "Desktop, Downloads and Documents are required, coverage-checked and EICAR-tested for every user"

if command -v clamd >/dev/null 2>&1; then
  CLAMD_TEMPLATE="${TEMP_DIR}/clamd.conf.template"
  CLAMD_CONFIG="${TEMP_DIR}/clamd.conf"
  CLAMD_OUTPUT="${TEMP_DIR}/clamd.output"

  extract_heredoc CLAMD "${CLAMD_TEMPLATE}"
  sed \
    -e "s/\${MAX_THREADS}/4/g" \
    -e "s/\${MAX_QUEUE}/100/g" \
    -e "s/\${ONACCESS_MAX_THREADS}/2/g" \
    -e "s/\${PREVENTION_VALUE}/false/g" \
    -e "s/\${CONCURRENT_RELOAD}/yes/g" \
    "${CLAMD_TEMPLATE}" | awk -v rules="${RULES_OPTIN}" '
      $0 == "${EXCLUDE_PATH_LINES}" { while ((getline line < rules) > 0) print line; next }
      { print }' >"${CLAMD_CONFIG}"
  grep -q '\${' "${CLAMD_CONFIG}" && fail "unsubstituted placeholder in the generated clamd.conf"

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

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

mkdir -p "${SCAN_ROOT}" "${MOCK_BIN}" "${SCAN_ROOT}/skipme" "${SCAN_ROOT}/node_modules/pkg" "${SCAN_ROOT}/keep"
printf 'a\n' >"${SCAN_ROOT}/keep/a.txt"
printf 'b\n' >"${SCAN_ROOT}/skipme/b.txt"
printf 'c\n' >"${SCAN_ROOT}/node_modules/pkg/c.js"
printf 'd\n' >"${SCAN_ROOT}/d.txt"
# a REGULAR file named node_modules is not excluded by the regexes, so it must be counted (prune is for directories only)
printf 'e\n' >"${SCAN_ROOT}/keep/node_modules"
extract_heredoc SCAN_HEAD "${SCAN_HEAD}"
extract_heredoc SCAN_BODY "${SCAN_BODY}"
{
  cat "${SCAN_HEAD}"
  printf '  %q\n' "${SCAN_ROOT}" "${MISSING_ROOT}"
  printf ')\nEXCLUDE_REGEXES=(\n'
  printf '  %q\n' '/skipme/' '/node_modules/'
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
assert_contains "${SCAN_LOG}" "Files in scope (approx.): 3"
[[ "$(stat -c %a "${SCAN_LOG}")" == 640 ]] || fail "Expected daily-scan.log mode 640, got $(stat -c %a "${SCAN_LOG}")"
pass "daily scanner uses parallel fd passing, skips stale paths and keeps its log private"

set +e
PATH="${MOCK_BIN}:${PATH}" CAPTURE_FILE="${CAPTURE_FILE}" MOCK_SCAN_STATUS=1 bash "${GENERATED_SCAN}"
SCAN_STATUS=$?
set -e
[[ "${SCAN_STATUS}" -eq 1 ]] || fail "Expected threat status 1, got ${SCAN_STATUS}"
assert_contains "${SCAN_LOG}" "Scan completed: threats found"
pass "daily scanner preserves ClamAV threat status"

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
for option in "HeuristicAlerts true" "AlertBrokenExecutables true" '${CLAMD_EXCLUDES}' \
  "OnAccessExcludeUname clamav" "OnAccessExcludeRootUID true" "LocalSocketMode 660" \
  "TemporaryDirectory /var/lib/clamav/tmp" "OnAccessExtraScanning true" "OnAccessDenyOnError false"; do
  assert_contains "${CLAMD_RAW}" "${option}"
done
for option in AlgorithmicDetection ArchiveBlockEncrypted PhishingAlwaysBlock "PartitionIntersection false" OLE2BlockMacros; do
  if grep -Eq "^${option}" "${CLAMD_RAW}"; then fail "Deprecated clamd option still present: ${option}"; fi
done
# The real DAILY_EXCLUDES regexes (the single source for ExcludePath and the file count).
EXCLUDES_FILE="${TEMP_DIR}/daily-excludes.sh"
awk '/^DAILY_EXCLUDES=\(/ { capture = 1 } capture { print } capture && /^\)$/ { exit }' "${INSTALLER}" >"${EXCLUDES_FILE}"
EXCLUDE_PATTERNS="${TEMP_DIR}/daily-excludes.txt"
( . "${EXCLUDES_FILE}"; printf '%s\n' "${DAILY_EXCLUDES[@]}" ) >"${EXCLUDE_PATTERNS}"
[[ "$(grep -c . "${EXCLUDE_PATTERNS}")" -ge 9 ]] || fail "DAILY_EXCLUDES not found or incomplete"
excluded() { printf '%s\n' "$1" | grep -q -E -f "${EXCLUDE_PATTERNS}"; }
for p in /home/u/.config/herdr/herdr.sock /home/u/.config/herdr/herdr-client.sock /home/u/.local/share/zed/zed-stable.sock \
  /home/u/.codex/ipc/ipc.sock /home/u/.docker/desktop/backend.sock /home/u/.docker/desktop/vms/0/00000002.000007cf \
  /home/u/.config/Code/CachedExtensionVSIXs/ms-python.python-2026.4.0-linux-x64 \
  /home/u/.config/Code/CachedExtensionVSIXs/ms-python.vscode-python-envs-1.36.0-linux-x64 \
  /proc/1/status /home/u/src/app/node_modules/x/index.js /home/u/.cache/pip/x; do
  excluded "${p}" || fail "exclusion misses ${p}"
done
for p in /home/u/Downloads/evil.sock /home/u/Desktop/x.sock /home/u/Documents/report.pdf \
  /home/u/.local/share/Trash/files/evil.sock /home/u/.config/other/evil.sock /home/u/.config/herdr/sub/x.sock \
  /home/u/Documents/project/.docker/desktop/vms/data /home/u/Downloads/.docker/desktop/vms/x \
  /home/u/.config/Code/CachedExtensionVSIXs/other.extension-1.0 /home/u/.config/Code/User/settings.json \
  /home/u/Downloads/ms-python.python.vsix /home/u/.docker/config.json; do
  if excluded "${p}"; then fail "exclusion wrongly matches ${p}"; fi
done
assert_contains "${INSTALLER}" "CLAMD_EXCLUDES=\"\$(printf 'ExcludePath %s\\n' \"\${DAILY_EXCLUDES[@]}\")\""
assert_contains "${INSTALLER}" "printf '  %q\\n' \"\${DAILY_EXCLUDES[@]}\""
pass "clamd.conf uses current option names and the hardening defaults"

# clamdscan exits 1 when it detects EICAR; under pipefail it must not be piped into grep.
if grep -Eq 'clamdscan [^|]*\| *grep' "${INSTALLER}"; then fail "clamdscan output must not be piped into grep under pipefail"; fi
assert_contains "${INSTALLER}" 'scan_rc=$?'
# The user-readable report must never contain raw log lines (file names).
if grep -Eq 'clamonacc\.log[^|]*\|[^#]*tee -a "\$\{REPORT_TMP\}"' "${INSTALLER}"; then fail "raw clamonacc.log lines reach the user report"; fi
SUMMARY_PROG="${TEMP_DIR}/summary.awk"
extract_heredoc SUMMARY_AWK "${SUMMARY_PROG}"
CRAFTED_LOG="${TEMP_DIR}/crafted-daily-scan.log"
cat >"${CRAFTED_LOG}" <<'CRAFTED'
[2026-11-02 02:00:01] Starting parallel ClamAV daily scan for: /home/alice /home/bob
[2026-11-02 02:00:01] Files in scope (approx.): 1234
/home/bob/private/Scan completed confidential.txt: Eicar-Test-Signature FOUND
/home/bob/Total errors: 0 secret-plan.txt: Eicar-Test-Signature FOUND
Infected files: 2
Total errors: 0
Time: 42.500 sec (0 m 42 s)
[2026-11-02 02:00:44] Scan completed: threats found
CRAFTED
SUMMARY_OUT="$(awk -f "${SUMMARY_PROG}" "${CRAFTED_LOG}")"
[[ "${SUMMARY_OUT}" == "files~1234 infected=2 errors=0 time=42.500s traversal=complete result=Scan completed: threats found" ]] \
  || fail "Unexpected scan summary: ${SUMMARY_OUT}"
case "${SUMMARY_OUT}" in *confidential*|*secret*|*/home/*) fail "Scan summary leaks a file name: ${SUMMARY_OUT}" ;; esac
printf '[2026-11-02 02:00:01] Traversal incomplete: find exit 1 (unreadable or vanished paths); the count is a minimum\n' >>"${CRAFTED_LOG}"
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
    "${CLAMD_TEMPLATE}" >"${CLAMD_CONFIG}.partial"
  awk -v excludes="${EXCLUDE_PATTERNS}" '
    $0 == "${CLAMD_EXCLUDES}" { while ((getline line < excludes) > 0) print "ExcludePath " line; next }
    { print }' "${CLAMD_CONFIG}.partial" >"${CLAMD_CONFIG}"
  grep -q '^ExcludePath ^/home/\[^/\]+/\\.docker/desktop/vms/' "${CLAMD_CONFIG}" || fail "generated clamd.conf lacks the ExcludePath lines"

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

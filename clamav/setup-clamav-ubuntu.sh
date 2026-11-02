#!/usr/bin/env bash
# ClamAV for Ubuntu: install, configure, repair and verify (idempotent).
# Run with sudo. Every changed config file is backed up next to itself (<file>.<timestamp>.bak).
# A root-collected verification report (status and counters only, no file names) is written for the invoking user.
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
TS="$(date +%Y%m%d%H%M%S)"
TARGET_USERS=()
ENABLE_ON_ACCESS=1
ENABLE_PREVENTION=0
ENABLE_UNATTENDED_UPGRADES=1
WATCH_TMP=1
VERIFY_ONLY=0
RUN_FULL_SCAN=1
MAX_THREADS=0
SCAN_PATH_ARGS=()
WATCH_PATH_ARGS=()
REPORT_FILE=""
# shellcheck disable=SC2016  # literal EICAR test string
EICAR='X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

log() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<USAGE
Usage: sudo bash ${SCRIPT_NAME} [options]

Options:
  --user USER                  Desktop user to protect. Repeat for several users. Defaults to SUDO_USER.
  --scan-path PATH             Daily-scan path (repeatable). Replaces the default (each user's home).
                               Without --watch-path it is also watched on access (backwards compatible).
  --watch-path PATH            On-access watch path (repeatable). Replaces the default
                               (Downloads, Desktop, Documents, Public of each user, plus /tmp).
  --no-tmp-watch               Do not watch /tmp on access.
  --prevention                 Block access to files until scanned (OnAccessPrevention, global for all
                               watched paths). Off by default: it slows every open in watched folders.
  --max-threads THREADS        clamd worker threads. Defaults to a desktop-friendly automatic value.
  --skip-on-access             Install ClamAV without enabling clamonacc on-access scanning.
  --no-unattended-upgrades     Do not install or configure unattended-upgrades.
  --skip-full-scan             Do not run the real daily scan at the end (verification stays short).
  --verify                     Make no configuration changes. It still writes the report and root-only
                               diagnostics, runs EICAR self-tests (files removed afterwards) and, unless
                               --skip-full-scan is given, starts a real daily scan.
  --report FILE                Where to write the verification report
                               (default: ~SUDO_USER/clamav-report-<timestamp>.txt, mode 600).
  -h, --help                   Show this help.

Examples:
  sudo bash ${SCRIPT_NAME}
  sudo bash ${SCRIPT_NAME} --user alice --user bob
  sudo bash ${SCRIPT_NAME} --scan-path /srv/uploads --watch-path /srv/uploads
  sudo bash ${SCRIPT_NAME} --verify
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      [[ $# -ge 2 ]] || die "--user requires a value"
      TARGET_USERS+=("$2"); shift 2 ;;
    --scan-path)
      [[ $# -ge 2 ]] || die "--scan-path requires a value"
      SCAN_PATH_ARGS+=("$2"); shift 2 ;;
    --watch-path)
      [[ $# -ge 2 ]] || die "--watch-path requires a value"
      WATCH_PATH_ARGS+=("$2"); shift 2 ;;
    --max-threads)
      [[ $# -ge 2 ]] || die "--max-threads requires a value"
      [[ "$2" =~ ^[1-9][0-9]*$ ]] || die "--max-threads must be a positive integer"
      MAX_THREADS="$2"
      (( MAX_THREADS <= 48 )) || die "--max-threads must not exceed 48"
      shift 2 ;;
    --report)
      [[ $# -ge 2 ]] || die "--report requires a value"
      REPORT_FILE="$2"; shift 2 ;;
    --no-tmp-watch) WATCH_TMP=0; shift ;;
    --prevention) ENABLE_PREVENTION=1; shift ;;
    --skip-on-access) ENABLE_ON_ACCESS=0; shift ;;
    --no-unattended-upgrades) ENABLE_UNATTENDED_UPGRADES=0; shift ;;
    --skip-full-scan) RUN_FULL_SCAN=0; shift ;;
    --verify) VERIFY_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "Unknown option: $1" ;;
  esac
done

[[ "${EUID}" -eq 0 ]] || die "Run with sudo: sudo bash ${SCRIPT_NAME}"
[[ -r /etc/os-release ]] || die "Cannot identify operating system: /etc/os-release is missing"

# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "ubuntu" || "${ID_LIKE:-}" == *"ubuntu"* || "${ID_LIKE:-}" == *"debian"* ]] || die "This installer targets Ubuntu/Debian systems with apt and systemd"

command -v apt-get >/dev/null 2>&1 || die "apt-get is required"
command -v systemctl >/dev/null 2>&1 || die "systemd/systemctl is required"
[[ -d /run/systemd/system ]] || die "systemd is not running; this installer requires a systemd-based Ubuntu host"

if [[ "${MAX_THREADS}" -eq 0 ]]; then
  MAX_THREADS="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
  [[ "${MAX_THREADS}" =~ ^[1-9][0-9]*$ ]] || MAX_THREADS=1
  (( MAX_THREADS <= 2 )) || MAX_THREADS=$((MAX_THREADS - 1))
  (( MAX_THREADS <= 8 )) || MAX_THREADS=8
fi
MAX_QUEUE=$((MAX_THREADS * 2))
(( MAX_QUEUE >= 100 )) || MAX_QUEUE=100
ONACCESS_MAX_THREADS=$(((MAX_THREADS + 1) / 2))
(( ONACCESS_MAX_THREADS <= 4 )) || ONACCESS_MAX_THREADS=4
PREVENTION_VALUE="false"
[[ "${ENABLE_PREVENTION}" -eq 1 ]] && PREVENTION_VALUE="true"

# ---------------------------------------------------------------- users and paths
if [[ "${#TARGET_USERS[@]}" -eq 0 ]]; then
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    TARGET_USERS=("${SUDO_USER}")
  else
    candidate="$(logname 2>/dev/null || true)"
    if [[ -n "${candidate}" && "${candidate}" != "root" ]]; then TARGET_USERS=("${candidate}"); fi
  fi
fi

TARGET_HOMES=()
for user in "${TARGET_USERS[@]+"${TARGET_USERS[@]}"}"; do
  [[ "${user}" != "root" ]] || die "Do not pass root as a protected desktop user"
  getent passwd "${user}" >/dev/null || die "User does not exist: ${user}"
  home="$(getent passwd "${user}" | cut -d: -f6)"
  [[ -n "${home}" && -d "${home}" ]] || die "Home directory for ${user} was not found"
  TARGET_HOMES+=("${home}")
done
[[ "${#TARGET_USERS[@]}" -gt 0 ]] || warn "No non-root desktop user detected. User-specific paths and group membership will be skipped."

# Desktop, Downloads and Documents are always protected (on access and daily) for every user.
REQUIRED_FOLDERS=(Desktop Downloads Documents)
if [[ "${VERIFY_ONLY}" -eq 0 ]]; then
  for i in "${!TARGET_USERS[@]}"; do
    for folder in "${REQUIRED_FOLDERS[@]}"; do
      if [[ ! -d "${TARGET_HOMES[$i]}/${folder}" ]]; then
        install -d -m 0755 -o "${TARGET_USERS[$i]}" -g "$(id -gn "${TARGET_USERS[$i]}")" "${TARGET_HOMES[$i]}/${folder}"
        log "Created ${TARGET_HOMES[$i]}/${folder} for ${TARGET_USERS[$i]}"
      fi
    done
  done
fi

declare -a WATCH_CANDIDATES=() SCAN_CANDIDATES=()
if [[ "${#SCAN_PATH_ARGS[@]}" -gt 0 ]]; then
  SCAN_CANDIDATES=("${SCAN_PATH_ARGS[@]}")
elif [[ "${#TARGET_HOMES[@]}" -gt 0 ]]; then
  SCAN_CANDIDATES=("${TARGET_HOMES[@]}")
else
  SCAN_CANDIDATES=("/home")
fi

if [[ "${#WATCH_PATH_ARGS[@]}" -gt 0 ]]; then
  WATCH_CANDIDATES=("${WATCH_PATH_ARGS[@]}")
elif [[ "${#SCAN_PATH_ARGS[@]}" -gt 0 ]]; then
  WATCH_CANDIDATES=("${SCAN_PATH_ARGS[@]}")
elif [[ "${#TARGET_HOMES[@]}" -gt 0 ]]; then
  for home in "${TARGET_HOMES[@]}"; do
    WATCH_CANDIDATES+=("${home}/Downloads" "${home}/Desktop" "${home}/Documents" "${home}/Public")
  done
  if [[ "${WATCH_TMP}" -eq 1 ]]; then WATCH_CANDIDATES+=("/tmp"); fi
else
  ENABLE_ON_ACCESS=0
  warn "No desktop user and no --watch-path: on-access scanning stays disabled; daily scans cover /home."
fi

# canonicalize_paths OUTVAR path... : existing directories only, resolved and de-duplicated.
canonicalize_paths() {
  local -n out="$1"; shift
  local -A seen=()
  local path canonical
  out=()
  for path in "$@"; do
    if [[ -d "${path}" ]]; then
      canonical="$(readlink -f "${path}")"
      if [[ -z "${seen["${canonical}"]+set}" ]]; then
        out+=("${canonical}"); seen["${canonical}"]=1
      fi
    else
      warn "Skipping missing path: ${path}"
    fi
  done
}
declare -a WATCH_PATHS=() SCAN_PATHS=()

# Daily-scan exclusions: written as ExcludePath to clamd.conf (POSIX ERE, searched in the full path) and used by the
# daily scan's file count (grep -E, same semantics), so both always agree. One reason each:
DAILY_EXCLUDES=(
  '^/(proc|sys|dev)/'                 # pseudo filesystems, nothing to scan
  '/node_modules/'                    # registry packages, very many small files; check the supply chain with npm audit
  '/\.cache/'                         # regenerable caches (pip, npm, browsers); downloads land in ~/Downloads (scanned)
  '/\.git/objects/'                   # packed history; the checked-out working tree is scanned
  '/\.local/share/containers/'        # container image layers; scan images with an image scanner instead
  '^/var/lib/docker/'                 # container image layers; scan images with an image scanner instead
  '^/home/[^/]+/\.docker/desktop/vms/' # Docker Desktop VM disks (huge, guest filesystems not inspected) and vsock endpoints
  '^/home/[^/]+/\.config/Code/CachedExtensionVSIXs/ms-python\.' # cached ms-python VS Code extension packages: their
                                      # bundled binaries are reported as Heuristics.Broken.Executable (heuristic only)
  '^/home/[^/]+/(\.config/herdr|\.local/share/zed|\.codex/ipc|\.docker/desktop)/[^/]+\.sock$' # these apps' Unix
                                      # sockets: clamd cannot scan sockets ("Not supported file type" errors)
)
CLAMD_EXCLUDES="$(printf 'ExcludePath %s\n' "${DAILY_EXCLUDES[@]}")"
canonicalize_paths WATCH_PATHS "${WATCH_CANDIDATES[@]+"${WATCH_CANDIDATES[@]}"}"
canonicalize_paths SCAN_PATHS "${SCAN_CANDIDATES[@]}"
[[ "${#SCAN_PATHS[@]}" -gt 0 ]] || warn "No valid daily-scan paths; add them later in /usr/local/bin/clamav-daily-scan."

# ---------------------------------------------------------------- report helpers
REPORT_OWNER="${SUDO_USER:-root}"
if [[ -z "${REPORT_FILE}" ]]; then
  report_home="$(getent passwd "${REPORT_OWNER}" | cut -d: -f6)"
  REPORT_FILE="${report_home:-/root}/clamav-report-${TS}.txt"
fi
REPORT_TMP="$(mktemp)"
FAILS=0
WARNS=0
# Self-test cleanup never deletes recursively and never deletes anything this run did not create:
CLEANUP_USER_FILES=()   # "USER<TAB>PATH": exact files created by USER, removed as USER with rm -f --
CLEANUP_USER_DIRS=()    # "USER<TAB>PATH": private directories created by USER, removed as USER with rmdir --
CLEANUP_QUARANTINE=()   # "PATH<TAB>USER<TAB>INODE": quarantine copies, removed only if owner and inode/content match
CLEANUP_ROOT_FILES=()   # exact files created by root, rm -f --
CLEANUP_ROOT_DIRS=()    # directories created by root with mktemp -d, rmdir --
QUARANTINE_DIR="${QUARANTINE_DIR:-/var/lib/clamav/quarantine}"
LR_UNIT="clamav-logrotate.timer"
LR_HELD=0
LR_MASKED=0
LR_PREV_LOAD=""
LR_PREV_ENABLED=""
LR_PREV_ACTIVE=""
LR_PROBLEMS=""
LR_HOLD_PROBLEMS=""
as_user() {  # as_user USER CMD...: run CMD as USER (via runuser when root)
  local user="$1"
  shift
  if [[ "${EUID}" -eq 0 ]]; then runuser -u "${user}" -- "$@"; else "$@"; fi
}
cleanup_selftests() {
  local entry user path rest inode i
  for entry in "${CLEANUP_USER_FILES[@]+"${CLEANUP_USER_FILES[@]}"}"; do
    user="${entry%%$'\t'*}"; path="${entry#*$'\t'}"
    as_user "${user}" rm -f -- "${path}" 2>/dev/null || true
  done
  for entry in "${CLEANUP_QUARANTINE[@]+"${CLEANUP_QUARANTINE[@]}"}"; do
    path="${entry%%$'\t'*}"; rest="${entry#*$'\t'}"; user="${rest%%$'\t'*}"; inode="${rest#*$'\t'}"
    [[ -f "${path}" && ! -L "${path}" ]] || continue
    [[ "$(stat -c %U "${path}" 2>/dev/null)" == "${user}" ]] || continue
    if [[ -n "${inode}" && "$(stat -c %i "${path}" 2>/dev/null)" == "${inode}" ]] \
        || [[ "$(stat -c %s "${path}" 2>/dev/null)" == "${#EICAR}" && "$(cat -- "${path}" 2>/dev/null)" == "${EICAR}" ]]; then
      rm -f -- "${path}"
    fi
  done
  for (( i = ${#CLEANUP_USER_DIRS[@]} - 1; i >= 0; i-- )); do
    entry="${CLEANUP_USER_DIRS[$i]}"; user="${entry%%$'\t'*}"; path="${entry#*$'\t'}"
    as_user "${user}" rmdir -- "${path}" 2>/dev/null || true   # fails safely if anything else is inside
  done
  for path in "${CLEANUP_ROOT_FILES[@]+"${CLEANUP_ROOT_FILES[@]}"}"; do rm -f -- "${path}"; done
  for path in "${CLEANUP_ROOT_DIRS[@]+"${CLEANUP_ROOT_DIRS[@]}"}"; do rmdir -- "${path}" 2>/dev/null || true; done
  CLEANUP_USER_FILES=(); CLEANUP_USER_DIRS=(); CLEANUP_QUARANTINE=(); CLEANUP_ROOT_FILES=(); CLEANUP_ROOT_DIRS=()
}
# The hourly rotation timer is held (state recorded, masked at runtime, stopped) for the whole apply run and
# released into its final state only after verification. On an early exit the recorded state is restored.
lr_record_state() {  # fails if systemd cannot be queried
  local out
  out="$(systemctl show -p LoadState -p UnitFileState -p ActiveState "${LR_UNIT}" 2>/dev/null)" || return 1
  LR_PREV_LOAD="$(sed -n 's/^LoadState=//p' <<<"${out}")"
  LR_PREV_ENABLED="$(sed -n 's/^UnitFileState=//p' <<<"${out}")"
  LR_PREV_ACTIVE="$(sed -n 's/^ActiveState=//p' <<<"${out}")"
  [[ -n "${LR_PREV_LOAD}" ]]
}
lr_hold() {  # records the state, masks (runtime) and stops the timer; LR_PROBLEMS lists every error
  local active
  LR_PROBLEMS=""
  if ! lr_record_state; then LR_PROBLEMS="state query failed"; return 1; fi
  [[ "${LR_PREV_LOAD}" == not-found ]] && return 0   # not installed yet; it is created disabled and enabled at the end
  LR_HELD=1
  if [[ "${LR_PREV_LOAD}" != masked ]]; then
    if systemctl mask --runtime "${LR_UNIT}" >/dev/null 2>&1; then LR_MASKED=1; else LR_PROBLEMS+="mask failed; "; fi
  fi
  systemctl stop "${LR_UNIT}" >/dev/null 2>&1 || LR_PROBLEMS+="stop failed; "
  active="$(systemctl show -p ActiveState --value "${LR_UNIT}" 2>/dev/null)" || active="query failed"
  [[ "${active}" == inactive ]] || LR_PROBLEMS+="still ${active:-unknown}; "
  [[ -z "${LR_PROBLEMS}" ]]
}
lr_release() {  # lr_release restore|final: restore = the recorded state, final = enabled and active
  local mode="$1" active
  LR_PROBLEMS=""
  if [[ "${LR_MASKED}" -eq 1 ]]; then
    if systemctl unmask --runtime "${LR_UNIT}" >/dev/null 2>&1; then LR_MASKED=0; else LR_PROBLEMS+="unmask failed; "; fi
  fi
  if [[ "${mode}" == final ]]; then
    systemctl enable --now "${LR_UNIT}" >/dev/null 2>&1 || LR_PROBLEMS+="enable/start failed; "
  elif [[ "${LR_PREV_ACTIVE}" == active ]]; then
    systemctl start "${LR_UNIT}" >/dev/null 2>&1 || LR_PROBLEMS+="start failed; "
    active="$(systemctl show -p ActiveState --value "${LR_UNIT}" 2>/dev/null)" || active="query failed"
    [[ "${active}" == active ]] || LR_PROBLEMS+="not active after start (${active:-unknown}); "
  fi
  LR_HELD=0
  [[ -z "${LR_PROBLEMS}" ]]
}
cleanup() {
  local status=0
  cleanup_selftests
  rm -f "${REPORT_TMP}" "${REPORT_TMP}.lr"
  if [[ "${LR_HELD}" -eq 1 || "${LR_MASKED}" -eq 1 ]]; then
    if lr_release restore; then
      printf '[INFO] %s restored to its previous state (%s/%s)\n' "${LR_UNIT}" "${LR_PREV_ENABLED}" "${LR_PREV_ACTIVE}" >&2
    else
      printf '[ERROR] could not restore %s (%s); run: systemctl unmask --runtime %s; systemctl start %s\n' \
        "${LR_UNIT}" "${LR_PROBLEMS%; }" "${LR_UNIT}" "${LR_UNIT}" >&2
      status=1
    fi
  fi
  return "${status}"
}
trap 'cleanup || exit 1' EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

report() { printf '%s\n' "$*" | tee -a "${REPORT_TMP}"; }
section() { report ""; report "== $*"; }
check() {  # check STATUS NAME EVIDENCE
  report "$(printf '%-5s %-40s %s' "$1" "$2" "$3")"
  if [[ "$1" == "FAIL" ]]; then FAILS=$((FAILS + 1)); fi
  if [[ "$1" == "WARN" ]]; then WARNS=$((WARNS + 1)); fi
  return 0
}
# The user-readable report holds only fixed counters and status fields, never log lines with file names.
# Raw diagnostics (with paths) go to a root-only file under /var/log/clamav.
DIAG_FILE="/var/log/clamav/setup-diagnostics-${TS}.log"
# Summarize a daily-scan log: numbers and a fixed result phrase only, never a raw line (file names stay out).
SUMMARY_AWK_PROG="$(cat <<'SUMMARY_AWK'
/^\[[0-9-]+ [0-9:]+\] Files in scope \(approx\.\): [0-9]+$/ { n = split($0, a, ": "); files = a[n] }
/^Infected files: [0-9]+$/ { split($0, a, ": "); infected = a[2] }
/^Total errors: [0-9]+$/ { split($0, a, ": "); errors = a[2] }
/^Time: [0-9.]+ sec/ { split($0, a, " "); secs = a[2] }
/^\[[0-9-]+ [0-9:]+\] Scan completed(: no threats found|: threats found| with error code [0-9]+)$/ { sub(/^\[[^]]*\] /, ""); result = $0 }
/^\[[0-9-]+ [0-9:]+\] Traversal incomplete: find exit [0-9]+ / { traversal = "incomplete" }
END {
  printf "files~%s infected=%s errors=%s time=%ss traversal=%s result=%s\n", (files == "" ? "?" : files),
    (infected == "" ? "?" : infected), (errors == "" ? "?" : errors), (secs == "" ? "?" : secs),
    (traversal == "" ? "complete" : traversal), (result == "" ? "none" : result)
}
SUMMARY_AWK
)"
count_matches() {  # count_matches REGEX < input
  grep -a -c -E "$1" || true
}
# Units that write to or rotate /var/log/clamav/{clamonacc,daily-scan}.log.
WRITER_UNITS=(clamav-logrotate.timer clamav-logrotate.service clamav-daily-scan.timer clamav-daily-scan.service clamav-clamonacc.service)
unit_load_state() {  # prints the unit's LoadState; fails if systemd cannot be queried
  local state
  state="$(systemctl show -p LoadState --value "$1" 2>/dev/null)" || return 1
  [[ -n "${state}" ]] || return 1
  printf '%s\n' "${state}"
}
stop_writers() {  # FAIL-CLOSED: STOP_PROBLEMS lists every query/stop error and every unit not confirmed inactive
  local unit load active
  STOP_PROBLEMS=""
  # The rotation timer is held by lr_hold at the start of the run; any problem there blocks rotation too.
  if [[ -n "${LR_HOLD_PROBLEMS:-}" ]]; then STOP_PROBLEMS+="clamav-logrotate.timer hold: ${LR_HOLD_PROBLEMS}; "; fi
  for unit in "${WRITER_UNITS[@]}"; do
    if ! load="$(unit_load_state "${unit}")"; then STOP_PROBLEMS+="${unit} state query failed; "; continue; fi
    [[ "${load}" == not-found ]] && continue
    systemctl stop "${unit}" 2>/dev/null || STOP_PROBLEMS+="${unit} stop failed; "
    if ! active="$(systemctl show -p ActiveState --value "${unit}" 2>/dev/null)"; then
      STOP_PROBLEMS+="${unit} state query failed; "
      continue
    fi
    case "${active}" in
      inactive|failed) ;;
      *) STOP_PROBLEMS+="${unit} ${active:-unknown}; " ;;
    esac
  done
  return 0
}
log_writers() {  # log_writers FILE: PIDs that have FILE open (from /proc, no fuser/lsof needed)
  local fd target pid
  for fd in /proc/[0-9]*/fd/*; do
    target="$(readlink "${fd}" 2>/dev/null)" || continue
    if [[ "${target}" == "$1" || "${target}" == "$1 (deleted)" ]]; then
      pid="${fd#/proc/}"
      printf '%s\n' "${pid%%/*}"
    fi
  done | sort -u | paste -sd, || true
}
may_rotate() {  # may_rotate FILE...: true only when writers are confirmed stopped and no FILE is open; SKIP_REASON otherwise
  local f writers
  SKIP_REASON=""
  if [[ -n "${STOP_PROBLEMS}" ]]; then SKIP_REASON="writer units not confirmed stopped (${STOP_PROBLEMS%; })"; fi
  for f in "$@"; do
    writers="$(log_writers "${f}")"
    if [[ -n "${writers}" ]]; then SKIP_REASON+="${SKIP_REASON:+; }$(basename "${f}") still open by PID ${writers}"; fi
  done
  [[ -z "${SKIP_REASON}" ]]
}
db_age_hours() {  # hours since the daily database build, -1 if unknown
  local f build epoch
  f="$(compgen -G '/var/lib/clamav/daily.c[vl]d' | head -n1 || true)"
  if [[ -z "${f}" ]]; then echo "-1"; return; fi
  build="$(sigtool --info "${f}" 2>/dev/null | sed -n 's/^Build time: //p')"
  epoch="$(date -d "${build}" +%s 2>/dev/null || echo 0)"
  if [[ "${epoch}" -le 0 ]]; then echo "-1"; return; fi
  echo $(( ($(date +%s) - epoch) / 3600 ))
}

report "ClamAV report $(date '+%Y-%m-%d %H:%M:%S %Z') on $(hostname) (${PRETTY_NAME:-Linux}, kernel $(uname -r))"
report "Mode: $([[ "${VERIFY_ONLY}" -eq 1 ]] && echo verify-only || echo apply+verify); users: ${TARGET_USERS[*]:-none}"
report "No file names are included; raw diagnostics are root-only in ${DIAG_FILE}."

# ---------------------------------------------------------------- diagnostics (before any change)
section "Diagnostics before changes"
report "Packages: $(dpkg-query -W -f='${Package}=${Version} ' clamav clamav-daemon clamav-freshclam clamdscan 2>/dev/null || true)"
mkdir -p /var/log/clamav
install -m 0600 -o root -g root /dev/null "${DIAG_FILE}"
apparmor_lines="$( { journalctl -k -b --no-pager 2>/dev/null || true; cat /var/log/kern.log /var/log/kern.log.1 2>/dev/null || true; } \
  | grep -a -E 'apparmor="DENIED".*(clamd|clamdscan)' || true)"
report "AppArmor DENIED events for clamd (this boot + kern.log): $(printf '%s' "${apparmor_lines}" | count_matches .)"
{ echo "== AppArmor DENIED (last 20)"; printf '%s\n' "${apparmor_lines}" | tail -n 20; } >>"${DIAG_FILE}"
if [[ -f /var/log/clamav/daily-scan.log ]]; then
  report "Last daily-scan run: $(tail -n 200000 /var/log/clamav/daily-scan.log | awk "${SUMMARY_AWK_PROG}" || true)"
fi
if [[ -f /var/log/clamav/clamonacc.log ]]; then
  onacc_tail="$(mktemp)"
  tail -n 200000 /var/log/clamav/clamonacc.log >"${onacc_tail}" || true
  report "clamonacc.log: size $(du -h /var/log/clamav/clamonacc.log | cut -f1), last $(wc -l <"${onacc_tail}") lines:"
  report "  FOUND $(count_matches 'FOUND' <"${onacc_tail}"), 'Not a regular file' $(count_matches 'Not a regular file' <"${onacc_tail}"), permission/access denied $(count_matches '[Pp]ermission denied|[Aa]ccess denied' <"${onacc_tail}"), excluded $(count_matches '[Ee]xclud' <"${onacc_tail}"), connection/clamd errors $(count_matches '[Cc]onnect|clamd' <"${onacc_tail}"), watch/inotify $(count_matches 'inotif|[Ww]atch' <"${onacc_tail}"), other ERROR $(count_matches 'ERROR' <"${onacc_tail}"), WARNING $(count_matches 'WARNING' <"${onacc_tail}")"
  { echo "== clamonacc.log most frequent messages (digits as N)"
    sed -E 's/[0-9]+/N/g' "${onacc_tail}" | sort | uniq -c | sort -rn | head -n 20 || true; } >>"${DIAG_FILE}"
  rm -f "${onacc_tail}"
fi
report "Daily database age before changes: $(db_age_hours) h"

# ---------------------------------------------------------------- apply
# write_file PATH MODE OWNER:GROUP (content on stdin): replaces and backs up (<file>.<timestamp>.bak, ignored
# by APT, systemd and sysctl) only when the content differs; owner and mode are enforced either way.
write_file() {
  local path="$1" mode="$2" owner="$3" tmp
  tmp="$(mktemp)"
  cat >"${tmp}"
  if [[ -f "${path}" ]] && cmp -s "${tmp}" "${path}"; then
    rm -f "${tmp}"
    if [[ "$(stat -c '%a %U:%G' "${path}")" != "${mode#0} ${owner}" ]]; then
      chown "${owner}" "${path}"
      chmod "${mode}" "${path}"
      log "Fixed owner/mode of ${path}"
    fi
    return 0
  fi
  if [[ -f "${path}" ]]; then cp -a "${path}" "${path}.${TS}.bak"; fi
  install -m "${mode}" -o "${owner%%:*}" -g "${owner##*:}" "${tmp}" "${path}"
  rm -f "${tmp}"
  log "Updated ${path}"
}

write_daily_scan_script() {
  {
    cat <<'SCAN_HEAD'
#!/usr/bin/env bash
set -uo pipefail
umask 027

LOG_FILE="/var/log/clamav/daily-scan.log"
START_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
ACTIVE_SCAN_PATHS=(
SCAN_HEAD
    for path in "${SCAN_PATHS[@]+"${SCAN_PATHS[@]}"}"; do
      printf '  %q\n' "${path}"
    done
    printf ')\nEXCLUDE_REGEXES=(\n'
    printf '  %q\n' "${DAILY_EXCLUDES[@]}"
    cat <<'SCAN_BODY'
)

mkdir -p "$(dirname "${LOG_FILE}")"
touch "${LOG_FILE}"
chown root:adm "${LOG_FILE}" 2>/dev/null || true
chmod 0640 "${LOG_FILE}" 2>/dev/null || true

declare -a RUN_SCAN_PATHS=()
for path in "${ACTIVE_SCAN_PATHS[@]}"; do
  if [[ -d "${path}" ]]; then
    RUN_SCAN_PATHS+=("${path}")
  else
    END_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${END_STAMP}] Scan warning: configured path no longer exists: ${path}" >> "${LOG_FILE}"
  fi
done

if [[ "${#RUN_SCAN_PATHS[@]}" -eq 0 ]]; then
  END_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[${END_STAMP}] Scan aborted: no valid scan paths were configured" >> "${LOG_FILE}"
  exit 2
fi

echo "[${START_STAMP}] Starting parallel ClamAV daily scan for: ${RUN_SCAN_PATHS[*]}" >> "${LOG_FILE}"

if ! systemctl is-active --quiet clamav-daemon.service; then
  END_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
  echo "[${END_STAMP}] Scan aborted: clamav-daemon.service is not running" >> "${LOG_FILE}"
  exit 2
fi

# Approximate number of regular files in scope (same exclusions as ExcludePath in clamd.conf).
# Regular files in scope, filtered with the same regexes as ExcludePath in clamd.conf (grep -E searches like clamd).
# Sockets are not regular files. node_modules, .cache and .git/objects are pruned early for speed (also excluded).
FIND_RC=0
FILE_COUNT="$(find "${RUN_SCAN_PATHS[@]}" -xdev -type d \( -name node_modules -o -name .cache -o -path '*/.git/objects' \) -prune \
  -o -type f -print0 2>/dev/null \
  | { grep -z -E -v -f <(printf '%s\n' "${EXCLUDE_REGEXES[@]+"${EXCLUDE_REGEXES[@]}"}") || true; } \
  | tr -cd '\0' | wc -c; exit "${PIPESTATUS[0]}")" || FIND_RC=$?
echo "[${START_STAMP}] Files in scope (approx.): ${FILE_COUNT}" >> "${LOG_FILE}"
if [[ "${FIND_RC}" -ne 0 ]]; then
  echo "[${START_STAMP}] Traversal incomplete: find exit ${FIND_RC} (unreadable or vanished paths); the count is a minimum" >> "${LOG_FILE}"
fi

if /usr/bin/clamdscan --multiscan --fdpass --infected --log="${LOG_FILE}" "${RUN_SCAN_PATHS[@]}"; then
  STATUS=0
else
  STATUS=$?
fi

END_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"

if [[ "${STATUS}" -eq 0 ]]; then
  echo "[${END_STAMP}] Scan completed: no threats found" >> "${LOG_FILE}"
elif [[ "${STATUS}" -eq 1 ]]; then
  echo "[${END_STAMP}] Scan completed: threats found" >> "${LOG_FILE}"
else
  echo "[${END_STAMP}] Scan completed with error code ${STATUS}" >> "${LOG_FILE}"
fi

exit "${STATUS}"
SCAN_BODY
  } | write_file /usr/local/bin/clamav-daily-scan 0755 root:root
}

wait_for_databases() {
  local attempts=60
  while [[ "${attempts}" -gt 0 ]]; do
    if compgen -G '/var/lib/clamav/main.c[vl]d' >/dev/null && compgen -G '/var/lib/clamav/daily.c[vl]d' >/dev/null; then
      return 0
    fi
    sleep 3
    attempts=$((attempts - 1))
  done
  return 1
}

if [[ "${VERIFY_ONLY}" -eq 0 ]]; then
  section "Applying configuration"
  # Hold the hourly rotation timer before any log handling (whatever the log sizes) until after verification.
  if lr_hold; then
    check INFO "log rotation timer held" "was ${LR_PREV_ENABLED:-not installed}/${LR_PREV_ACTIVE:-inactive}; released after verification"
  else
    LR_HOLD_PROBLEMS="${LR_PROBLEMS%; }"
    warn "Could not hold ${LR_UNIT}: ${LR_HOLD_PROBLEMS}"
    check WARN "log rotation timer held" "failed (${LR_HOLD_PROBLEMS}); log rotation will be skipped"
  fi
  log "Installing ClamAV packages"
  apt-get update -qq
  PACKAGES=(clamav clamav-daemon clamdscan clamav-freshclam)
  if [[ "${ENABLE_UNATTENDED_UPGRADES}" -eq 1 ]]; then PACKAGES+=(unattended-upgrades); fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${PACKAGES[@]}"

  for user in "${TARGET_USERS[@]+"${TARGET_USERS[@]}"}"; do
    usermod -aG clamav "${user}"
  done

  if [[ "${ENABLE_UNATTENDED_UPGRADES}" -eq 1 ]]; then
    write_file /etc/apt/apt.conf.d/20auto-upgrades 0644 root:root <<'APT_AUTO'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT_AUTO
  fi

  mkdir -p /etc/clamav /etc/systemd/system/clamav-clamonacc.service.d /etc/systemd/system/clamav-freshclam.service.d \
    /var/lib/clamav/quarantine /var/log/clamav

  # ExcludePath lines come from DAILY_EXCLUDES (reasons listed there).
  write_file /etc/clamav/clamd.conf 0644 root:root <<CLAMD
# Managed by setup-clamav-ubuntu.sh
LocalSocket /var/run/clamav/clamd.ctl
FixStaleSocket true
LocalSocketGroup clamav
LocalSocketMode 660
User clamav
ScanMail true
ScanArchive true
AlertEncryptedArchive false
MaxDirectoryRecursion 15
FollowDirectorySymlinks false
FollowFileSymlinks false
ReadTimeout 180
MaxThreads ${MAX_THREADS}
MaxConnectionQueueLength 15
LogSyslog false
# logrotate (/etc/logrotate.d/clamav-daemon) is the single owner of log rotation.
LogRotate false
LogFacility LOG_LOCAL6
LogClean false
LogVerbose false
DatabaseDirectory /var/lib/clamav
# Not /tmp: /tmp is watched on access, and clamonacc must not watch clamd's own temporary directory.
TemporaryDirectory /var/lib/clamav/tmp
OfficialDatabaseOnly false
SelfCheck 3600
Foreground false
Debug false
ScanPE true
MaxEmbeddedPE 10M
ScanOLE2 true
ScanPDF true
ScanHTML true
MaxHTMLNormalize 10M
MaxHTMLNoTags 2M
MaxScriptNormalize 5M
MaxZipTypeRcg 1M
ScanSWF true
ExitOnOOM false
LeaveTemporaryFiles false
HeuristicAlerts true
AlertBrokenExecutables true
ScanELF true
IdleTimeout 30
CrossFilesystems false
PhishingSignatures true
PhishingScanURLs true
AlertPhishingSSLMismatch false
AlertPhishingCloak false
AlertPartitionIntersection false
# PUA detection stays off on desktops: admin and security tools cause many false positives.
DetectPUA false
ScanPartialMessages false
HeuristicScanPrecedence false
StructuredDataDetection false
CommandReadTimeout 30
SendBufTimeout 200
MaxQueue ${MAX_QUEUE}
ExtendedDetectionInfo true
AlertOLE2Macros false
AllowAllMatchScan true
ForceToDisk false
DisableCertCheck false
DisableCache false
MaxScanTime 120000
MaxScanSize 100M
MaxFileSize 25M
MaxRecursion 16
MaxFiles 10000
MaxPartitions 50
MaxIconsPE 100
PCREMatchLimit 10000
PCRERecMatchLimit 5000
PCREMaxFileSize 25M
ScanXMLDOCS true
ScanHWP3 true
MaxRecHWP3 16
StreamMaxLength 25M
LogFile /var/log/clamav/clamav.log
LogTime true
LogFileUnlock false
LogFileMaxSize 0
Bytecode true
BytecodeSecurity TrustSigned
BytecodeTimeout 60000
${CLAMD_EXCLUDES}
OnAccessMaxFileSize 25M
OnAccessMaxThreads ${ONACCESS_MAX_THREADS}
# clamd and root-owned system processes (package manager, backups, the daily scan) do not trigger
# on-access scans, which avoids scan loops. Files written or opened by users are scanned.
OnAccessExcludeUname clamav
OnAccessExcludeRootUID true
OnAccessPrevention ${PREVENTION_VALUE}
# Never block access because clamd failed (fail open; failures are logged).
OnAccessDenyOnError false
# Also scan files when they are closed after writing or moved into a watched folder (completed downloads).
OnAccessExtraScanning true
CLAMD

  if [[ "${#WATCH_PATHS[@]}" -gt 0 ]]; then
    printf '%s\n' "${WATCH_PATHS[@]}" | write_file /etc/clamav/onaccess.watch 0644 root:root
  else
    write_file /etc/clamav/onaccess.watch 0644 root:root </dev/null
  fi
  if [[ ! -f /etc/clamav/onaccess.exclude ]]; then : >/etc/clamav/onaccess.exclude; fi

  # clamonacc watches folders recursively with inotify; make sure the per-user watch limit has headroom.
  if [[ "${#WATCH_PATHS[@]}" -gt 0 ]]; then
    watch_find_rc=0
    watch_dots="$(find "${WATCH_PATHS[@]}" -xdev -type d -printf . 2>/dev/null)" || watch_find_rc=$?
    watch_dirs="${#watch_dots}"
    max_watches="$(sysctl -n fs.inotify.max_user_watches 2>/dev/null || echo 0)"
    if [[ "${watch_find_rc}" -ne 0 ]]; then
      warn "Watched-directory count incomplete (find exit ${watch_find_rc}): at least ${watch_dirs}"
      report "Watched directories: at least ${watch_dirs} (traversal incomplete, find exit ${watch_find_rc}); inotify limit raised to be safe"
    else
      log "Watched directories: ${watch_dirs} (inotify max_user_watches ${max_watches})"
    fi
    if [[ "${watch_find_rc}" -ne 0 ]] || [[ "${max_watches}" -gt 0 && $((watch_dirs * 2)) -gt "${max_watches}" ]]; then
      echo "fs.inotify.max_user_watches = 524288" | write_file /etc/sysctl.d/90-clamav-inotify.conf 0644 root:root
      sysctl -q -p /etc/sysctl.d/90-clamav-inotify.conf
    fi
  fi

  write_file /etc/systemd/system/clamav-clamonacc.service.d/override.conf 0644 root:root <<'OVERRIDE'
[Service]
ExecStart=
ExecStart=/usr/sbin/clamonacc -F --fdpass --log=/var/log/clamav/clamonacc.log --move=/var/lib/clamav/quarantine --watch-list=/etc/clamav/onaccess.watch --exclude-list=/etc/clamav/onaccess.exclude
ExecStop=
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=on-failure
RestartSec=10s
# The on-access log is created 640, never world-readable.
UMask=0027
OVERRIDE

  # freshclam can start before DNS works after boot; wait up to 60 s for the mirror name.
  write_file /etc/systemd/system/clamav-freshclam.service.d/wait-dns.conf 0644 root:root <<'WAITDNS'
[Service]
ExecStartPre=/bin/sh -c 'for i in $(seq 30); do getent hosts database.clamav.net >/dev/null && exit 0; sleep 2; done; exit 0'
WAITDNS

  write_daily_scan_script

  # No mount-namespace options (PrivateTmp, ProtectSystem, ProtectHome, ProtectKernel*, ProtectControlGroups):
  # clamdscan --fdpass hands file descriptors to the AppArmor-confined clamd, and descriptors opened in a
  # private mount namespace arrive as disconnected paths that AppArmor denies ("Not a regular file").
  write_file /etc/systemd/system/clamav-daily-scan.service 0644 root:root <<'SERVICE'
[Unit]
Description=Daily ClamAV scan
Wants=network-online.target
After=network-online.target clamav-daemon.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/clamav-daily-scan
SuccessExitStatus=1
TimeoutStartSec=6h
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
NoNewPrivileges=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
RestrictNamespaces=true
SystemCallArchitectures=native
MemoryDenyWriteExecute=true
SERVICE

  write_file /etc/systemd/system/clamav-daily-scan.timer 0644 root:root <<'TIMER'
[Unit]
Description=Run ClamAV daily scan once per day

[Timer]
OnCalendar=*-*-* 02:00:00
Persistent=true
RandomizedDelaySec=15m
Unit=clamav-daily-scan.service

[Install]
WantedBy=timers.target
TIMER

  # clamonacc.log and daily-scan.log are not covered by the packaged logrotate rules. They get their own rules,
  # outside /etc/logrotate.d, checked hourly by clamav-logrotate.timer so that maxsize is a real ceiling.
  # copytruncate for both: clamonacc keeps its log open, and a running scan appends (O_APPEND) to its log.
  write_file /etc/clamav/logrotate.conf 0644 root:root <<'LOGROTATE'
# Managed by setup-clamav-ubuntu.sh; run hourly by clamav-logrotate.timer
/var/log/clamav/clamonacc.log /var/log/clamav/daily-scan.log {
    daily
    maxsize 50M
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
    su root adm
}
LOGROTATE
  if [[ -f /etc/logrotate.d/clamav-local ]] && grep -q 'Managed by setup-clamav-ubuntu.sh' /etc/logrotate.d/clamav-local; then
    mv /etc/logrotate.d/clamav-local "/etc/clamav/logrotate.d-clamav-local.${TS}.bak"
  fi
  write_file /etc/systemd/system/clamav-logrotate.service 0644 root:root <<'LRSERVICE'
[Unit]
Description=Rotate the ClamAV on-access and daily-scan logs

[Service]
Type=oneshot
ExecStart=/usr/sbin/logrotate -s /var/lib/logrotate/clamav.status /etc/clamav/logrotate.conf
Nice=19
IOSchedulingClass=idle
LRSERVICE
  write_file /etc/systemd/system/clamav-logrotate.timer 0644 root:root <<'LRTIMER'
[Unit]
Description=Rotate the ClamAV on-access and daily-scan logs hourly

[Timer]
OnCalendar=hourly
Persistent=true
RandomizedDelaySec=5m

[Install]
WantedBy=timers.target
LRTIMER

  chown root:clamav /var/lib/clamav/quarantine
  chmod 0750 /var/lib/clamav/quarantine
  install -d -m 0750 -o clamav -g clamav /var/lib/clamav/tmp

  # Oversized logs (> 100 MB) are rotated once with logrotate -f on our own rules (full copy kept as .1,
  # copytruncate), FAIL-CLOSED: first the rotation timer is masked and every writer unit (clamonacc, the daily
  # scan, the rotation timer/service) is stopped and confirmed inactive, and no process may have a log open.
  # Any systemd query/mask/stop error or open writer => no rotation at all, reported as SKIPPED.
  systemctl daemon-reload
  oversized=()
  for f in /var/log/clamav/clamonacc.log /var/log/clamav/daily-scan.log; do
    if [[ -f "${f}" ]] && [[ "$(stat -c %s "${f}")" -gt $((100 * 1024 * 1024)) ]]; then oversized+=("${f}"); fi
  done
  if [[ "${#oversized[@]}" -gt 0 ]]; then
    stop_writers
    if ! may_rotate "${oversized[@]}"; then
      warn "Log rotation SKIPPED: ${SKIP_REASON}"
      check WARN "log preservation" "SKIPPED: writers not confirmed stopped (logs left untouched)"
    elif logrotate -f -s /var/lib/logrotate/clamav.status /etc/clamav/logrotate.conf; then
      log "Rotated oversized logs (full copies kept as <log>.1)"
      check INFO "log preservation" "rotated with logrotate -f, full copies kept"
    else
      check WARN "log preservation" "logrotate -f failed (logs left as they were)"
    fi
  fi

  log "Restarting services"
  systemctl daemon-reload
  systemctl enable --now clamav-freshclam.service
  # A restart makes freshclam check the mirrors right away.
  systemctl restart clamav-freshclam.service
  wait_for_databases || warn "ClamAV databases were not ready after waiting."
  systemctl enable clamav-daemon.service
  systemctl restart clamav-daemon.service
  for _ in $(seq 60); do [[ -S /run/clamav/clamd.ctl ]] && break; sleep 2; done

  if [[ "${ENABLE_ON_ACCESS}" -eq 1 && "${#WATCH_PATHS[@]}" -gt 0 ]]; then
    systemctl enable clamav-clamonacc.service
    systemctl restart clamav-clamonacc.service
  else
    systemctl disable --now clamav-clamonacc.service >/dev/null 2>&1 || true
    warn "On-access scanning is disabled because it was skipped or no valid watch paths exist."
  fi
  systemctl enable --now clamav-daily-scan.timer   # clamav-logrotate.timer stays held until after verification
  systemctl reset-failed clamav-daily-scan.service 2>/dev/null || true
  if [[ "${ENABLE_UNATTENDED_UPGRADES}" -eq 1 ]]; then systemctl enable --now unattended-upgrades.service; fi

  # No ClamAV log is world-readable.
  for f in /var/log/clamav/clamonacc.log /var/log/clamav/daily-scan.log; do
    if [[ -f "${f}" ]]; then chown root:adm "${f}"; chmod 0640 "${f}"; fi
  done
  find /var/log/clamav -maxdepth 1 -type f -exec chmod o-rwx {} +

  # Give freshclam time to fetch a newer daily database if one exists.
  for _ in $(seq 24); do
    age="$(db_age_hours)"
    if [[ "${age}" -ge 0 && "${age}" -lt 24 ]]; then break; fi
    sleep 5
  done
fi

# ---------------------------------------------------------------- verification
section "Verification"
for unit in clamav-daemon.service clamav-freshclam.service clamav-clamonacc.service clamav-daily-scan.timer; do
  en="$(systemctl is-enabled "${unit}" 2>/dev/null || true)"
  ac="$(systemctl is-active "${unit}" 2>/dev/null || true)"
  if [[ "${unit}" == clamav-clamonacc.service && "${ENABLE_ON_ACCESS}" -eq 0 ]]; then
    check INFO "${unit}" "on-access disabled by option (${en}/${ac})"
  elif [[ "${en}" == enabled && "${ac}" == active ]]; then
    check PASS "${unit}" "enabled, active"
  else
    check FAIL "${unit}" "enabled=${en} active=${ac}"
  fi
done

sock="$(stat -c '%a %U:%G' /run/clamav/clamd.ctl 2>/dev/null || echo missing)"
if [[ "${sock}" == "660 clamav:clamav" ]]; then check PASS "clamd socket" "${sock}"; else check FAIL "clamd socket" "${sock}"; fi
if ss -ltnp 2>/dev/null | grep -q -E ':3310\b'; then check FAIL "no TCP listener" "port 3310 open"; else check PASS "no TCP listener" "Unix socket only"; fi

age="$(db_age_hours)"
if [[ "${age}" -ge 0 && "${age}" -lt 24 ]]; then check PASS "signatures fresh" "daily database ${age} h old"
elif [[ "${age}" -ge 0 && "${age}" -lt 48 ]]; then check WARN "signatures fresh" "daily database ${age} h old"
else check FAIL "signatures fresh" "daily database age ${age} h"; fi
last_update="$(grep -a -o -E 'daily\.c[vl]d (updated|database is up-to-date) \(version: [0-9]+' /var/log/clamav/freshclam.log 2>/dev/null | tail -n1 || true)"
report "      freshclam last result: ${last_update:-none}"

clamconf_rc=0
clamconf_out="$(clamconf 2>&1)" || clamconf_rc=$?
config_errors="$(printf '%s\n' "${clamconf_out}" | grep -E '^(ERROR|LibClamAV Error)|[Pp]arse error|[Uu]nknown option' || true)"
config_warnings="$(printf '%s\n' "${clamconf_out}" | grep -E '^(WARNING|LibClamAV Warning)|[Dd]eprecated' || true)"
if [[ -n "${config_errors}${config_warnings}" || "${clamconf_rc}" -ne 0 ]]; then
  { echo "== clamconf (exit ${clamconf_rc})"; printf '%s\n%s\n' "${config_errors}" "${config_warnings}"; } >>"${DIAG_FILE}"
fi
if [[ "${clamconf_rc}" -ne 0 || -n "${config_errors}" ]]; then
  check FAIL "clamd.conf parses cleanly" "clamconf exit ${clamconf_rc}, $(printf '%s' "${config_errors}" | count_matches .) error(s), see the root-only diagnostics"
elif [[ -n "${config_warnings}" ]]; then
  check WARN "clamd.conf parses cleanly" "$(printf '%s' "${config_warnings}" | count_matches .) warning(s), see the root-only diagnostics"
else
  check PASS "clamd.conf parses cleanly" "clamconf exit 0, no errors or deprecated options"
fi
if grep -q '^OnAccessPrevention true' /etc/clamav/clamd.conf; then check INFO "on-access prevention" "on (files blocked until scanned)"
else check INFO "on-access prevention" "off (detect, log and quarantine)"; fi

selftest_dir="$(mktemp -d /var/tmp/clamav-selftest.XXXXXX)"
CLEANUP_ROOT_DIRS+=("${selftest_dir}")
CLEANUP_ROOT_FILES+=("${selftest_dir}/eicar.txt")
printf '%s' "${EICAR}" >"${selftest_dir}/eicar.txt"
scan_rc=0
scan_out="$(clamdscan --fdpass --no-summary "${selftest_dir}/eicar.txt" 2>&1)" || scan_rc=$?
if [[ "${scan_rc}" -eq 1 && "${scan_out}" == *"Eicar-Test-Signature FOUND"* ]]; then
  check PASS "clamdscan detects EICAR" "Eicar-Test-Signature FOUND (exit 1)"
else
  check FAIL "clamdscan detects EICAR" "exit ${scan_rc}"
fi
cleanup_selftests

# make_selftest_file USER DIR: creates a fresh private directory (mktemp -d, mode 700) as USER inside DIR and
# verifies it (real directory, not a symlink, owned by USER, mode 700, directly inside DIR). Registered for
# cleanup: that directory (rmdir as USER), the exact EICAR file name inside it (rm -f as USER) and, if no such
# file exists yet, the matching quarantine path (removed only if owner and inode or content match). EICAR goes
# into a new file through one exclusive open (noclobber -> O_EXCL). Sets SELFTEST_FILE.
make_selftest_file() {
  local user="$1" dir="$2" tdir name quarantine_registered=0
  SELFTEST_FILE=""
  tdir="$(as_user "${user}" mktemp -d "${dir}/.clamav-selftest.XXXXXXXXXX" 2>/dev/null)" || return 1
  if [[ -z "${tdir}" || -L "${tdir}" || ! -d "${tdir}" || "$(dirname "${tdir}")" != "${dir}" \
        || "$(stat -c '%U %a' "${tdir}")" != "${user} 700" ]]; then
    return 1
  fi
  name="$(basename "${tdir}").txt"
  CLEANUP_USER_DIRS+=("${user}"$'\t'"${tdir}")
  CLEANUP_USER_FILES+=("${user}"$'\t'"${tdir}/${name}")
  if [[ ! -e "${QUARANTINE_DIR}/${name}" ]]; then
    CLEANUP_QUARANTINE+=("${QUARANTINE_DIR}/${name}"$'\t'"${user}"$'\t')
    quarantine_registered=1
  fi
  # shellcheck disable=SC2016  # $1 expands in the inner shell, not here
  printf '%s' "${EICAR}" | as_user "${user}" sh -c 'set -C; umask 077; cat > "$1"' sh "${tdir}/${name}" || return 1
  if [[ "${quarantine_registered}" -eq 1 ]]; then
    CLEANUP_QUARANTINE+=("${QUARANTINE_DIR}/${name}"$'\t'"${user}"$'\t'"$(stat -c %i "${tdir}/${name}" 2>/dev/null || true)")
  fi
  SELFTEST_FILE="${tdir}/${name}"
}
# On-access: a protected user writes EICAR into a watched folder; clamonacc must move it to quarantine.
onaccess_test() {  # onaccess_test USER DIR LABEL
  local user="$1" dir="$2" label="$3" file name left quarantined logged attempt
  if ! make_selftest_file "${user}" "${dir}"; then
    check FAIL "on-access ${label}" "could not create a private test directory/file as ${user}"
    return 0
  fi
  file="${SELFTEST_FILE}"
  name="$(basename "${file}")"
  for attempt in 1 2 3; do
    sleep 2
    as_user "${user}" cat "${file}" >/dev/null 2>&1 || true   # an open by the user also triggers a scan
    for _ in $(seq 10); do
      [[ -e "${file}" ]] || break 2
      sleep 1
    done
    [[ "${attempt}" -lt 3 ]] || break
  done
  left="no"; quarantined="no"; logged="no"
  [[ -e "${file}" ]] && left="yes"
  [[ -e "${QUARANTINE_DIR}/${name}" ]] && quarantined="yes"
  grep -a -q "${name}.*FOUND" /var/log/clamav/clamonacc.log 2>/dev/null && logged="yes"
  if [[ "${left}" == no && "${quarantined}" == yes && "${logged}" == yes ]]; then
    check PASS "on-access ${label}" "quarantined and logged"
  else
    check FAIL "on-access ${label}" "file_left=${left} quarantined=${quarantined} logged=${logged}"
  fi
  cleanup_selftests
}
# Coverage: each required folder of each user exists, is watched on access and lies under a daily-scan path.
daily_paths="$(sed -n '/^ACTIVE_SCAN_PATHS=(/,/^)/p' /usr/local/bin/clamav-daily-scan 2>/dev/null | grep -v -E '^(ACTIVE|\))' | sed -e 's/^ *//' || true)"
for i in "${!TARGET_USERS[@]}"; do
  for folder in "${REQUIRED_FOLDERS[@]}"; do
    dir="${TARGET_HOMES[$i]}/${folder}"
    label="~${TARGET_USERS[$i]}/${folder}"
    if [[ ! -d "${dir}" ]]; then check FAIL "coverage ${label}" "folder missing"; continue; fi
    real="$(readlink -f "${dir}")"
    watched="no"; scanned="no"
    if grep -qxF "${real}" /etc/clamav/onaccess.watch 2>/dev/null; then watched="yes"; fi
    while IFS= read -r scan_path; do
      [[ -n "${scan_path}" ]] || continue
      scan_path="$(printf '%b' "${scan_path//\\ / }")"
      if [[ "${real}" == "${scan_path}" || "${real}" == "${scan_path%/}/"* ]]; then scanned="yes"; fi
    done <<<"${daily_paths}"
    if [[ "${watched}" == yes && "${scanned}" == yes ]] || [[ "${ENABLE_ON_ACCESS}" -eq 0 && "${scanned}" == yes ]]; then
      check PASS "coverage ${label}" "on-access=${watched} daily=${scanned}"
    else
      check FAIL "coverage ${label}" "on-access=${watched} daily=${scanned}"
    fi
  done
done

if [[ "${ENABLE_ON_ACCESS}" -eq 1 && "$(systemctl is-active clamav-clamonacc.service 2>/dev/null || true)" == active ]]; then
  sleep 5  # let clamonacc finish adding its watches after a restart
  for i in "${!TARGET_USERS[@]}"; do
    for folder in "${REQUIRED_FOLDERS[@]}"; do
      dir="${TARGET_HOMES[$i]}/${folder}"
      if [[ -d "${dir}" ]] && grep -qxF "$(readlink -f "${dir}")" /etc/clamav/onaccess.watch; then
        onaccess_test "${TARGET_USERS[$i]}" "$(readlink -f "${dir}")" "~${TARGET_USERS[$i]}/${folder}"
      fi
    done
  done
  if grep -qxF /tmp /etc/clamav/onaccess.watch && [[ "${#TARGET_USERS[@]}" -gt 0 ]]; then
    onaccess_test "${TARGET_USERS[0]}" /tmp "/tmp"
  fi
fi

if [[ "${RUN_FULL_SCAN}" -eq 1 ]]; then
  report "      running the real daily scan now (this can take a while)..."
  scan_start="$(date '+%Y-%m-%d %H:%M:%S')"
  log_lines_before="$(wc -l </var/log/clamav/daily-scan.log 2>/dev/null || echo 0)"
  systemctl start clamav-daily-scan.service || true
  result="$(systemctl show -p Result --value clamav-daily-scan.service)"
  status="$(systemctl show -p ExecMainStatus --value clamav-daily-scan.service)"
  summary="$(tail -n +"$((log_lines_before + 1))" /var/log/clamav/daily-scan.log 2>/dev/null | awk "${SUMMARY_AWK_PROG}" || true)"
  errors="$(printf '%s' "${summary}" | sed -n 's/.* errors=\([0-9]*\) .*/\1/p')"
  files="$(printf '%s' "${summary}" | sed -n 's/^files~\([0-9]*\) .*/\1/p')"
  if [[ "${result}" == success && "${status}" =~ ^[01]$ && "${errors}" == 0 && "${files:-0}" =~ ^[1-9][0-9]*$ \
        && "${summary}" == *"result=Scan completed"* ]]; then
    check PASS "daily scan run" "result=${result} exit=${status} errors=0 files~${files}"
  else
    check FAIL "daily scan run" "result=${result} exit=${status} errors=${errors:-missing} files~${files:-missing}"
  fi
  report "      ${summary}"
  if [[ "${summary}" == *"traversal=incomplete"* ]]; then
    check WARN "daily scan file count" "traversal incomplete (unreadable or vanished paths); count is a minimum"
  fi
  journal_rc=0
  journal_out="$(journalctl -k --since "${scan_start}" --no-pager -q 2>/dev/null)" || journal_rc=$?
  if [[ "${journal_rc}" -ne 0 ]]; then
    check FAIL "no AppArmor denials during scan" "kernel journal not readable (exit ${journal_rc})"
  else
    denied_after="$(printf '%s\n' "${journal_out}" | count_matches 'apparmor="DENIED".*clamd')"
    if [[ "${denied_after}" -eq 0 ]]; then check PASS "no AppArmor denials during scan" "0 (kernel journal read)"
    else check FAIL "no AppArmor denials during scan" "${denied_after}"; fi
  fi
fi
check INFO "daily scan timer" "$(systemctl list-timers --all clamav-daily-scan.timer --no-pager --no-legend 2>/dev/null | awk '{print "next run "$1" "$2" "$3}' | head -n1)"

if [[ "${VERIFY_ONLY}" -eq 0 ]]; then
  # Verification is done: release the held rotation timer into its final state (unmasked, enabled, active).
  lr_release final || check FAIL "log rotation timer release" "${LR_PROBLEMS%; }"
fi
lr_timer="$(systemctl is-enabled clamav-logrotate.timer 2>/dev/null || true)/$(systemctl is-active clamav-logrotate.timer 2>/dev/null || true)"
if [[ "${lr_timer}" == enabled/active ]]; then check PASS "log rotation timer (hourly)" "clamav-logrotate.timer enabled, active"
else check FAIL "log rotation timer (hourly)" "${lr_timer}"; fi
if logrotate -d -s /var/lib/logrotate/clamav.status /etc/clamav/logrotate.conf >/dev/null 2>"${REPORT_TMP}.lr" \
    && ! grep -q -i 'error' "${REPORT_TMP}.lr"; then
  check PASS "logrotate config (dry run)" "/etc/clamav/logrotate.conf"
else
  { echo "== logrotate -d errors"; grep -i error "${REPORT_TMP}.lr" || true; } >>"${DIAG_FILE}"
  check FAIL "logrotate config (dry run)" "$(grep -c -i error "${REPORT_TMP}.lr" || true) error(s), see the root-only diagnostics"
fi
world_readable="$(find /var/log/clamav -maxdepth 1 -type f -perm -o=r | wc -l)"
if [[ "${world_readable}" -eq 0 ]]; then check PASS "logs not world-readable" "0 files"
else check FAIL "logs not world-readable" "${world_readable} files"; fi
report "      log size: $(du -ch /var/log/clamav/*.log 2>/dev/null | tail -n1 | cut -f1) in /var/log/clamav/*.log"
q="$(stat -c '%a %U:%G' /var/lib/clamav/quarantine 2>/dev/null || echo missing)"
if [[ "${q}" == "750 root:clamav" ]]; then check PASS "quarantine permissions" "${q}"; else check FAIL "quarantine permissions" "${q}"; fi
report "      watched on access: $(grep -c . /etc/clamav/onaccess.watch 2>/dev/null || echo 0) paths (Desktop, Downloads, Documents, Public of each user$(grep -qxF /tmp /etc/clamav/onaccess.watch 2>/dev/null && echo ', /tmp'))"
report "      daily scan: $(printf '%s\n' "${daily_paths}" | count_matches .) paths (each protected user's home)"
report "      resources: $(ps -o comm=,rss= -C clamd,clamonacc,freshclam 2>/dev/null | awk '{printf "%s %d MB; ", $1, $2/1024}')$(free -h | awk '/^Mem:/ {print "RAM available " $7}')"

section "Summary"
report "Failures: ${FAILS}, warnings: ${WARNS}"
install -m 0600 -o "${REPORT_OWNER}" -g "$(id -gn "${REPORT_OWNER}")" "${REPORT_TMP}" "${REPORT_FILE}"
echo "Report written to ${REPORT_FILE}"
[[ "${FAILS}" -eq 0 ]]

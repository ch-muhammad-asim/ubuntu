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
EXCLUDE_DEV_CACHES=0
LOW_MEMORY=0
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
  --max-threads THREADS        clamd worker threads. Default: half the CPUs rounded down, at least 1, at most 4.
  --exclude-dev-caches         Also exclude disposable download caches in each user's home from the daily scan
                               (~/.cache, npm _cacache, cargo registry/cache, Go module download cache).
  --low-memory                 ConcurrentDatabaseReload no: reload signatures in place (about half the peak
                               memory); scans wait while a reload runs. Default keeps concurrent reload.
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
    --exclude-dev-caches) EXCLUDE_DEV_CACHES=1; shift ;;
    --low-memory) LOW_MEMORY=1; shift ;;
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

default_max_threads() {  # default_max_threads CPUS: half the CPUs rounded down, at least 1, at most 4
  local cpus="$1" threads
  [[ "${cpus}" =~ ^[1-9][0-9]*$ ]] || cpus=1
  threads=$((cpus / 2))
  (( threads >= 1 )) || threads=1
  (( threads <= 4 )) || threads=4
  printf '%s\n' "${threads}"
}

regex_escape() {  # regex_escape STRING: STRING as a literal POSIX extended regex
  printf '%s' "$1" | sed 's/[][\.*^$+?(){}|]/\\&/g'
}

# exclude_path_lines HOME...: the ExcludePath lines for clamd.conf (daily scan only; clamonacc has its own list).
# Every directory rule ends in (/|$) so it matches the directory itself and its contents, never a sibling
# that only shares the prefix (/run matches, /runner does not). Rules inside homes are anchored to each
# user's home, so the same folder name elsewhere (for example under ~/Downloads) is still scanned.
exclude_path_lines() {
  local home h
  printf '%s\n' 'ExcludePath ^/(proc|sys|dev|run)(/|$)' 'ExcludePath ^/var/lib/docker(/|$)' \
    'ExcludePath /node_modules(/|$)' 'ExcludePath /\.git/objects(/|$)'
  for home in "$@"; do
    h="$(regex_escape "${home%/}")"
    printf 'ExcludePath ^%s/\\.local/share/containers(/|$)\n' "${h}"
    printf 'ExcludePath ^%s/\\.cache/(thumbnails|fontconfig|mesa_shader_cache)(/|$)\n' "${h}"
    if [[ "${EXCLUDE_DEV_CACHES}" -eq 1 ]]; then
      printf 'ExcludePath ^%s/\\.cache(/|$)\n' "${h}"
      printf 'ExcludePath ^%s/\\.npm/_cacache(/|$)\n' "${h}"
      printf 'ExcludePath ^%s/\\.cargo/registry/cache(/|$)\n' "${h}"
      printf 'ExcludePath ^%s/go/pkg/mod/cache/download(/|$)\n' "${h}"
    fi
  done
}

CPU_COUNT="$(nproc 2>/dev/null || getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
if [[ "${MAX_THREADS}" -eq 0 ]]; then MAX_THREADS="$(default_max_threads "${CPU_COUNT}")"; fi
CONCURRENT_RELOAD="yes"
[[ "${LOW_MEMORY}" -eq 1 ]] && CONCURRENT_RELOAD="no"
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
# clamconf_value FILE OPTION < clamconf output: the value clamconf parsed for OPTION in that config file
# ("no" for a disabled boolean, empty when not shown).
clamconf_value() {
  awk -v file="$1" -v opt="$2" '
    /^Config file: / { in_file = ($3 == file); next }
    in_file && index($0, opt " = \"") == 1 { v = substr($0, length(opt) + 5); sub(/"$/, "", v); print v; exit }
    in_file && $0 == opt " disabled" { print "no"; exit }
  '
}
unit_started_after() {  # unit_started_after UNIT FILE...: the unit's main process started after every FILE changed
  local started f
  started="$(systemctl show -p ExecMainStartTimestamp --value --timestamp=unix "$1" 2>/dev/null)" || return 1
  started="${started#@}"
  [[ "${started}" =~ ^[0-9]+$ ]] || return 1
  shift
  for f in "$@"; do
    [[ ! -e "${f}" || "$(stat -c %Y "${f}")" -le "${started}" ]] || return 1
  done
}
# The user-readable report holds only fixed counters and status fields, never log lines with file names.
# Raw diagnostics (with paths) go to a root-only file under /var/log/clamav.
DIAG_FILE="/var/log/clamav/setup-diagnostics-${TS}.log"
# Summarize a daily-scan log: numbers and a fixed result phrase only, never a raw line (file names stay out).
SUMMARY_AWK_PROG="$(cat <<'SUMMARY_AWK'
/^\[[0-9-]+ [0-9:]+\] Starting / { files = ""; skipped = ""; vanished = ""; infected = ""; errors = ""; secs = ""; traversal = ""; result = "" }
/^\[[0-9-]+ [0-9:]+\] Files to scan: [0-9]+$/ { n = split($0, a, ": "); files = a[n] }
/^Special files skipped: [0-9]+$/ { split($0, a, ": "); skipped = a[2] }
/^Vanished before scan: [0-9]+$/ { split($0, a, ": "); vanished = a[2] }
/^Infected files: [0-9]+$/ { split($0, a, ": "); infected = a[2] }
/^Total errors: [0-9]+$/ { split($0, a, ": "); errors = a[2] }
/^Time: [0-9.]+ sec/ { split($0, a, " "); secs = a[2] }
/^\[[0-9-]+ [0-9:]+\] Scan (completed(: no threats found|: threats found| with error code [0-9]+)|incomplete: [a-z0-9][a-zA-Z0-9 ()/.-]*|aborted: [a-z0-9][a-zA-Z0-9 ()/.-]*)$/ { sub(/^\[[^]]*\] /, ""); result = $0 }
/^\[[0-9-]+ [0-9:]+\] Traversal incomplete: find exit [0-9]+ / { traversal = "incomplete" }
END {
  printf "files=%s skipped=%s vanished=%s infected=%s errors=%s time=%ss traversal=%s result=%s\n",
    (files == "" ? "?" : files), (skipped == "" ? "?" : skipped), (vanished == "" ? "?" : vanished),
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

# set_freshclam_checks FILE N: leaves exactly one active Checks directive, "Checks N", in place of the first one
# (any whitespace, tabs included); later duplicates are dropped, comments and other lines are kept. The file is
# backed up and rewritten only when this changes it, so repeated runs are stable. Owner and mode are kept.
set_freshclam_checks() {
  local file="$1" value="$2" tmp
  tmp="$(mktemp)"
  awk -v value="${value}" '
    /^[[:space:]]*Checks([[:space:]]|$)/ { if (!done) { print "Checks " value; done = 1 }; next }
    { print }
    END { if (!done) print "Checks " value }
  ' "${file}" >"${tmp}"
  if cmp -s "${tmp}" "${file}"; then rm -f "${tmp}"; return 0; fi
  cp -a "${file}" "${file}.${TS}.bak"
  cat "${tmp}" >"${file}"
  rm -f "${tmp}"
  log "Updated ${file} (Checks ${value})"
}

write_daily_scan_script() {
  {
    cat <<'SCAN_HEAD'
#!/usr/bin/env bash
set -uo pipefail
umask 027

LOG_FILE="/var/log/clamav/daily-scan.log"
CLAMD_CONF="/etc/clamav/clamd.conf"
# Every append to LOG_FILE holds this lock, and so does clamav-logrotate.service, so copytruncate never drops a line.
# Directly in /run (root-only, 755), never in a world-writable directory such as /run/lock or /tmp, where another
# local user could create it first and block the scan's reporting and the log rotation.
LOG_LOCK="/run/clamav-daily-scan.lock"
START_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
ACTIVE_SCAN_PATHS=(
SCAN_HEAD
    for path in "${SCAN_PATHS[@]+"${SCAN_PATHS[@]}"}"; do
      printf '  %q\n' "${path}"
    done
    cat <<'SCAN_BODY'
)

mkdir -p "$(dirname "${LOG_FILE}")"
touch "${LOG_FILE}"
chown root:adm "${LOG_FILE}" 2>/dev/null || true
chmod 0640 "${LOG_FILE}" 2>/dev/null || true

log_append() {  # log_append < TEXT: append TEXT to the permanent log while holding the log lock (unlocked if the
  # lock cannot be taken: the text is never dropped)
  flock "${LOG_LOCK}" sh -c 'cat >>"$1"' sh "${LOG_FILE}" || cat >> "${LOG_FILE}"
}
log_line() { printf '%s\n' "$*" | log_append; }

declare -a RUN_SCAN_PATHS=()
for path in "${ACTIVE_SCAN_PATHS[@]}"; do
  if [[ -d "${path}" ]]; then
    RUN_SCAN_PATHS+=("${path}")
  else
    END_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
    log_line "[${END_STAMP}] Scan warning: configured path no longer exists: ${path}"
  fi
done

if [[ "${#RUN_SCAN_PATHS[@]}" -eq 0 ]]; then
  END_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
  log_line "[${END_STAMP}] Scan aborted: no valid scan paths were configured"
  exit 2
fi

log_line "[${START_STAMP}] Starting parallel ClamAV daily scan for: ${RUN_SCAN_PATHS[*]}"

if ! systemctl is-active --quiet clamav-daemon.service; then
  END_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
  log_line "[${END_STAMP}] Scan aborted: clamav-daemon.service is not running"
  exit 2
fi

# Regular files only, byte-exact. Everything below runs in the C locale (bytes, not characters), and paths travel
# NUL-delimited from find to clamdscan's arguments (xargs -0), so no file name is changed or dropped: invalid UTF-8,
# carriage returns, newlines and long paths all reach clamd unchanged. One find pass sends special files (sockets,
# FIFOs, block and character devices) to a separate list that is only counted, and regular files through the
# ExcludePath rules of clamd.conf (grep -E searches each path as clamd does) into the one copy of the scan list.
# Symbolic links are not followed (as FollowFileSymlinks false).
export LC_ALL=C
START_EPOCH="$(date +%s)"
BATCH_SIZE=500
FIND_RC=0
XARGS_PID=""
XARGS_RC=0
INTERRUPTED=""
SPECIAL_COUNT="?"
FILE_COUNT=0

stamp() { date '+%Y-%m-%d %H:%M:%S'; }
abort_prep() {  # abort_prep REASON: the scan list could not be prepared, so nothing is scanned
  log_line "[$(stamp)] Scan aborted: cannot prepare the scan list (${1})"
  exit 2
}

WORK_DIR="$(mktemp -d "${TMPDIR:-/var/tmp}/clamav-daily-scan.XXXXXX")" || abort_prep "mktemp failed"
BATCHES="${WORK_DIR}/batches"
export WORK_DIR BATCHES LOG_FILE LOG_LOCK
cleanup_work() {  # exact names only, never recursive; by now every batch output is in the permanent log
  rm -f -- "${WORK_DIR}/files.0" "${WORK_DIR}/special.0" "${BATCHES}" "${WORK_DIR}"/batch.*
  rmdir -- "${WORK_DIR}" 2>/dev/null || true
}
trap cleanup_work EXIT

# run_batch FILE...: one clamdscan client for these files. clamdscan has no --log here (parallel clients cannot share
# one: it is locked exclusively); its output goes to a file of its own, which is appended to the permanent log under
# the log lock when the batch ends, together with one status record "STATUS FILES FOUND VANISHED ERRORS BATCHFILE".
# The totals of the run come only from these records, never from the permanent log, so a log rotation during the
# scan cannot change them. With --infected
# --no-summary clamdscan prints only detections and problems, so every other non-empty line is an error, except a
# vanished file: one that "Can't access file" names exactly as it was passed and that no longer exists. STATUS is
# 0 clean, 1 found, 2 failed (clamdscan exited above 2, reported an error, or exited non-zero without saying why).
run_batch() {
  local out rc=0 found errors=0 vanished=0 status line gone f
  out="$(mktemp "${WORK_DIR}/batch.XXXXXX")" || return 0
  /usr/bin/clamdscan --fdpass --infected --no-summary "$@" >"${out}" 2>&1 || rc=$?
  found="$(grep -a -c ' FOUND$' "${out}")"
  [[ "$?" -le 1 ]] || found=-1
  while IFS= read -r line; do
    if [[ "${line}" == "ERROR: Can't access file "* ]]; then
      gone="${line#"ERROR: Can't access file "}"
      if [[ ! -e "${gone}" && ! -L "${gone}" ]]; then
        for f in "$@"; do
          if [[ "${f}" == "${gone}" ]]; then vanished=$((vanished + 1)); continue 2; fi
        done
      fi
    fi
    errors=$((errors + 1))
  done < <(grep -a -v -e ' FOUND$' -e '^$' "${out}")
  if [[ "${found}" -lt 0 || "${rc}" -gt 2 || "${errors}" -gt 0 || ( "${rc}" -eq 2 && "${vanished}" -eq 0 ) \
        || ( "${rc}" -eq 1 && "${found}" -eq 0 ) ]]; then
    status=2
  elif [[ "${found}" -gt 0 ]]; then
    status=1
  else
    status=0
  fi
  flock "${LOG_LOCK}" sh -c 'cat -- "$1" >>"$2" && printf "%s %s %s %s %s %s\n" "$3" "$4" "$5" "$6" "$7" "${1##*/}" >>"$8" \
    && rm -f -- "$1"' sh "${out}" "${LOG_FILE}" "${status}" "$#" "${found}" "${vanished}" "${errors}" "${BATCHES}"
  return 0  # the outcome is in the status record; xargs must go on with the other batches
}
export -f run_batch

# finish: totals of this run from the batch records, then the summary, the result line and the exit status. Also runs
# on SIGTERM/SIGINT: a batch that had not finished has no record, so its detections are counted from its own output
# file, which is then appended to the permanent log; the run is marked incomplete.
finish() {
  local out n partial=0 counted=1 totals batches failed scanned found vanished errors infected result status secs summary
  trap - TERM INT
  : >>"${BATCHES}"
  for out in "${WORK_DIR}"/batch.*; do
    [[ -f "${out}" ]] || continue
    if ! awk -v name="${out##*/}" '$6 == name { seen = 1 } END { exit !seen }' "${BATCHES}"; then
      n="$(grep -a -c ' FOUND$' "${out}")"
      if [[ "$?" -le 1 ]]; then partial=$((partial + n)); else counted=0; fi
      log_append <"${out}"
    fi
    rm -f -- "${out}"
  done
  totals="$(awk '{ n++; if ($1 >= 2) failed++; else scanned += $2; if ($3 > 0) found += $3; vanished += $4; errors += $5 }
    END { printf "%d %d %d %d %d %d\n", n, failed, scanned, found, vanished, errors }' "${BATCHES}")" || counted=0
  read -r batches failed scanned found vanished errors <<<"${totals:-0 0 0 0 0 0}"
  infected="?"
  [[ "${counted}" -eq 0 ]] || infected=$((found + partial))
  if [[ -n "${INTERRUPTED}" ]]; then
    result="Scan incomplete: interrupted by ${INTERRUPTED}"; status=2
  elif [[ "${FIND_RC}" -ne 0 ]]; then
    result="Scan incomplete: traversal failed (find exit ${FIND_RC})"; status=2
  elif [[ "${XARGS_RC}" -ne 0 ]]; then
    result="Scan incomplete: clamdscan batches could not be run (xargs exit ${XARGS_RC})"; status=2
  elif [[ "${failed}" -gt 0 ]]; then
    result="Scan incomplete: ${failed} of ${batches} clamdscan batches failed"; status=2
  elif [[ "${scanned}" -ne "${FILE_COUNT}" ]]; then
    result="Scan incomplete: ${scanned} of ${FILE_COUNT} files scanned"; status=2
  elif [[ "${infected}" == "?" ]]; then
    result="Scan incomplete: cannot count the results"; status=2
  elif [[ "${infected}" -gt 0 ]]; then
    result="Scan completed: threats found"; status=1
  else
    result="Scan completed: no threats found"; status=0
  fi
  secs=$(( $(date +%s) - START_EPOCH ))
  summary="$(printf '\n%s\n' "----------- SCAN SUMMARY -----------"
    printf '%s\n' "Files scanned: ${scanned} of ${FILE_COUNT}" "Infected files: ${infected}" "Total errors: ${errors}" \
      "Failed batches: ${failed}" "Vanished before scan: ${vanished}" "Special files skipped: ${SPECIAL_COUNT}" \
      "Time: ${secs}.000 sec ($((secs / 60)) m $((secs % 60)) s)")"
  printf '%s\n' "${summary}"
  printf '%s\n[%s] %s\n' "${summary}" "$(stamp)" "${result}" | log_append
  exit "${status}"
}
on_signal() {  # on_signal NAME: stop xargs and every batch (workers first, then their clamdscan), then finish
  local pid i
  declare -a tree=()
  INTERRUPTED="$1"
  if [[ -n "${XARGS_PID}" ]]; then
    tree=("${XARGS_PID}")
    for (( i = 0; i < ${#tree[@]}; i++ )); do
      for pid in $(pgrep -P "${tree[$i]}"); do tree+=("${pid}"); done
    done
    kill -TERM "${tree[@]}" 2>/dev/null
    wait "${XARGS_PID}" 2>/dev/null
  fi
  finish
}
trap 'on_signal SIGTERM' TERM
trap 'on_signal SIGINT' INT

[[ -r "${CLAMD_CONF}" ]] || abort_prep "cannot read ${CLAMD_CONF}"
declare -a EXCLUDE_ARGS=(-e '^$')
while IFS= read -r rule; do
  EXCLUDE_ARGS+=(-e "${rule}")
done < <(sed -n 's/^ExcludePath[[:space:]]\{1,\}//p' "${CLAMD_CONF}")

# grep exit status: 0 = lines selected, 1 = none selected (an empty list is valid), 2 or more = failure.
find "${RUN_SCAN_PATHS[@]}" -xdev \( \( -type s -o -type p -o -type b -o -type c \) -fprint0 "${WORK_DIR}/special.0" \) \
  -o \( -type f -print0 \) 2>/dev/null | grep -azEv "${EXCLUDE_ARGS[@]}" >"${WORK_DIR}/files.0"
PIPE_RC=("${PIPESTATUS[@]}")
FIND_RC="${PIPE_RC[0]}"
[[ "${PIPE_RC[1]}" -le 1 ]] || abort_prep "path filter failed (grep exit ${PIPE_RC[1]})"
[[ -f "${WORK_DIR}/special.0" ]] || abort_prep "special-file list was not written"
SPECIAL_COUNT="$(grep -azEvc "${EXCLUDE_ARGS[@]}" "${WORK_DIR}/special.0")"
[[ "$?" -le 1 && "${SPECIAL_COUNT}" =~ ^[0-9]+$ ]] || abort_prep "special-file count failed"
rm -f -- "${WORK_DIR}/special.0"
FILE_COUNT="$(tr -cd '\0' <"${WORK_DIR}/files.0" | wc -c)" || abort_prep "file count failed"
[[ "${FILE_COUNT}" =~ ^[0-9]+$ ]] || abort_prep "file count failed"
log_line "[${START_STAMP}] Files to scan: ${FILE_COUNT}"
log_line "[${START_STAMP}] Special files skipped: ${SPECIAL_COUNT}"
if [[ "${FIND_RC}" -ne 0 ]]; then
  log_line "[${START_STAMP}] Traversal incomplete: find exit ${FIND_RC} (unreadable or vanished paths); the listed files are still scanned"
fi

# xargs runs batches of up to BATCH_SIZE files on as many parallel clamdscan clients as clamd has threads (MaxThreads).
JOBS="$(sed -n 's/^MaxThreads[[:space:]]\{1,\}\([1-9][0-9]*\)[[:space:]]*$/\1/p' "${CLAMD_CONF}" | tail -n 1)"
[[ "${JOBS}" =~ ^[1-9][0-9]*$ ]] || JOBS=1
xargs -0 -r -n "${BATCH_SIZE}" -P "${JOBS}" -a "${WORK_DIR}/files.0" bash -c 'run_batch "$@"' run_batch \
  >/dev/null 2>&1 &
XARGS_PID=$!
wait "${XARGS_PID}" || XARGS_RC=$?
XARGS_PID=""
finish
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
    /etc/systemd/system/clamav-daemon.service.d \
    /var/lib/clamav/quarantine /var/log/clamav

  # ExcludePath is the daily-scan policy (clamdscan applies it while walking the tree); see exclude_path_lines.
  # It does not filter on-access scans: clamonacc uses its own directory list, /etc/clamav/onaccess.exclude.
  EXCLUDE_PATH_LINES="$(exclude_path_lines "${TARGET_HOMES[@]+"${TARGET_HOMES[@]}"}")"
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
${EXCLUDE_PATH_LINES}
# yes: new signatures load next to the old set, so scanning never pauses (peak memory about twice the set).
# --low-memory sets no: reload in place, scans wait until the reload finishes.
ConcurrentDatabaseReload ${CONCURRENT_RELOAD}
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
  # On-access exclusions are a separate policy from ExcludePath: clamonacc --exclude-list takes explicit
  # directory paths (no regex). The installer creates the list empty and never changes an existing one.
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

  # False-positive allowlist by exact file hash (ClamAV .sfp format sha256:size:name, loaded by clamd with the
  # signatures). Only these exact files are exempt; the Heuristics.Broken.Executable heuristic and every signature
  # stay active for all other files. Comment lines are provenance and are stripped before installing.
  grep -v -E '^[[:space:]]*(#|$)' <<'FP_ALLOWLIST' | write_file /var/lib/clamav/local.sfp 0644 clamav:clamav
# Official VS Code Marketplace packages (targetPlatform=linux-x64), downloaded 2026-11-02 from
# https://marketplace.visualstudio.com/_apis/public/gallery/publishers/ms-python/vsextensions/<name>/<version>/vspackage
# and byte-identical to the copies VS Code caches in ~/.config/Code/CachedExtensionVSIXs/. Each bundles
# extension/python-env-tools/bin/pet (a 34-35 MB ELF, above MaxFileSize 25M), reported as Heuristics.Broken.Executable.
1d07e60d5eab257ea5d691b26def3fff642b4d2c04fab94424e8b8fe25baf656:17823311:ms-python.python-2026.4.0-linux-x64.vsix
7cea86fc649098a0c7037275d31fe6f6ae5446348f028587aa0fce7d9b73e35f:12859354:ms-python.vscode-python-envs-1.36.0-linux-x64.vsix
FP_ALLOWLIST

  # The daily-scan unit's Nice only affects the clamdscan client; the scanning work runs inside clamd.
  # clamd and the daily scan run in clamav.slice, a top-level slice with CPUWeight=20: when the CPU is
  # contended it gets 20 shares against 100 each for user.slice and system.slice, when it is idle it may use
  # every CPU. A weight, not a hard quota, so on-access scans are never capped on an idle machine.
  write_file /etc/systemd/system/clamav.slice 0644 root:root <<'SLICE'
# Managed by setup-clamav-ubuntu.sh
[Unit]
Description=ClamAV scanning (low CPU weight under contention)

[Slice]
CPUWeight=20
SLICE
  write_file /etc/systemd/system/clamav-daemon.service.d/desktop-limits.conf 0644 root:root <<'DAEMONLIMITS'
# Managed by setup-clamav-ubuntu.sh
[Service]
Slice=clamav.slice
DAEMONLIMITS

  # 12 signature checks a day (every 2 h) instead of 24. Set in debconf too so package upgrades keep it.
  echo "clamav-freshclam clamav-freshclam/update_interval string 12" | debconf-set-selections
  if [[ -f /etc/clamav/freshclam.conf ]]; then set_freshclam_checks /etc/clamav/freshclam.conf 12; fi

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
# Same low-weight slice as clamd; it runs one clamdscan worker per clamd thread (MaxThreads).
Slice=clamav.slice
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
# Same lock as the daily scan's appends to daily-scan.log: copytruncate never runs in the middle of an append.
ExecStart=/usr/bin/flock /run/clamav-daily-scan.lock /usr/sbin/logrotate -s /var/lib/logrotate/clamav.status /etc/clamav/logrotate.conf
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
fp_entries="$(grep -c -E '^[0-9a-f]{64}:[0-9]+:' /var/lib/clamav/local.sfp 2>/dev/null || true)"
check INFO "false-positive allowlist" "${fp_entries:-0} exact file hash(es) in /var/lib/clamav/local.sfp"

# Effective tuning: what systemd and the ClamAV parser actually load, and whether the running services
# started after the files changed. Files alone are never reported as deployed.
eff_slice="$(systemctl show -p Slice --value clamav-daemon.service 2>/dev/null || true)"
eff_weight="$(systemctl show -p CPUWeight --value clamav.slice 2>/dev/null || true)"
eff_reload="$(systemctl show -p NeedDaemonReload --value clamav-daemon.service 2>/dev/null || true)"
if [[ "${eff_slice}" == clamav.slice && "${eff_weight}" == 20 && "${eff_reload}" == no ]]; then
  check PASS "clamd CPU weight (effective)" "Slice=clamav.slice, CPUWeight=20"
else
  check FAIL "clamd CPU weight (effective)" "Slice=${eff_slice:-?} CPUWeight=${eff_weight:-?} NeedDaemonReload=${eff_reload:-?}"
fi
eff_threads="$(clamconf_value clamd.conf MaxThreads <<<"${clamconf_out}")"
eff_concurrent="$(clamconf_value clamd.conf ConcurrentDatabaseReload <<<"${clamconf_out}")"
eff_checks="$(clamconf_value freshclam.conf Checks <<<"${clamconf_out}")"
eff_evidence="MaxThreads=${eff_threads:-?} ConcurrentDatabaseReload=${eff_concurrent:-?} Checks=${eff_checks:-?}"
if [[ "${VERIFY_ONLY}" -eq 1 ]]; then
  check INFO "tuning (parsed by clamconf)" "${eff_evidence}"
elif [[ "${eff_threads}" == "${MAX_THREADS}" && "${eff_concurrent}" == "${CONCURRENT_RELOAD}" && "${eff_checks}" == 12 ]]; then
  check PASS "tuning (parsed by clamconf)" "${eff_evidence}"
else
  check FAIL "tuning (parsed by clamconf)" "${eff_evidence}; expected MaxThreads=${MAX_THREADS} ConcurrentDatabaseReload=${CONCURRENT_RELOAD} Checks=12"
fi
if unit_started_after clamav-daemon.service /etc/clamav/clamd.conf /etc/systemd/system/clamav.slice \
  /etc/systemd/system/clamav-daemon.service.d/desktop-limits.conf; then
  check PASS "clamd runs the current config" "started after the last change"
else
  check FAIL "clamd runs the current config" "clamd.conf or its unit changed after clamd started; restart clamav-daemon"
fi
if unit_started_after clamav-freshclam.service /etc/clamav/freshclam.conf; then
  check PASS "freshclam runs the current config" "started after the last change"
else
  check FAIL "freshclam runs the current config" "freshclam.conf changed after freshclam started; restart clamav-freshclam"
fi

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
  files="$(printf '%s' "${summary}" | sed -n 's/^files=\([0-9]*\) .*/\1/p')"
  if [[ "${result}" == success && "${status}" =~ ^[01]$ && "${errors}" == 0 && "${files:-0}" =~ ^[1-9][0-9]*$ \
        && "${summary}" == *"result=Scan completed"* ]]; then
    check PASS "daily scan run" "result=${result} exit=${status} errors=0 files=${files}"
  else
    check FAIL "daily scan run" "result=${result} exit=${status} errors=${errors:-missing} files=${files:-missing}"
  fi
  report "      ${summary}"
  if [[ "${summary}" == *"traversal=incomplete"* ]]; then
    check FAIL "daily scan coverage" "traversal incomplete (unreadable or vanished paths): not every file was listed"
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

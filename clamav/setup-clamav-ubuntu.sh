#!/usr/bin/env bash
set -euo pipefail

SCRIPT_NAME="$(basename "$0")"
TARGET_USER=""
ENABLE_ON_ACCESS=1
ENABLE_UNATTENDED_UPGRADES=1
MAX_THREADS=0
SCAN_PATH_ARGS=()

log() {
  printf '[INFO] %s\n' "$*"
}

warn() {
  printf '[WARN] %s\n' "$*" >&2
}

die() {
  printf '[ERROR] %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<USAGE
Usage: sudo bash ${SCRIPT_NAME} [options]

Options:
  --user USER                  Desktop user to protect. Defaults to SUDO_USER when available.
  --scan-path PATH             Add a scan/watch path. Can be provided more than once.
  --max-threads THREADS        clamd worker threads. Defaults to a desktop-friendly automatic value.
  --skip-on-access             Install ClamAV without enabling clamonacc on-access scanning.
  --no-unattended-upgrades     Do not install or configure unattended-upgrades.
  -h, --help                   Show this help.

Examples:
  sudo bash ${SCRIPT_NAME}
  sudo bash ${SCRIPT_NAME} --user alice
  sudo bash ${SCRIPT_NAME} --scan-path /srv/uploads --scan-path /home/alice/Downloads
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --user)
      [[ $# -ge 2 ]] || die "--user requires a value"
      TARGET_USER="$2"
      shift 2
      ;;
    --scan-path)
      [[ $# -ge 2 ]] || die "--scan-path requires a value"
      SCAN_PATH_ARGS+=("$2")
      shift 2
      ;;
    --max-threads)
      [[ $# -ge 2 ]] || die "--max-threads requires a value"
      [[ "$2" =~ ^[1-9][0-9]*$ ]] || die "--max-threads must be a positive integer"
      MAX_THREADS="$2"
      (( MAX_THREADS <= 48 )) || die "--max-threads must not exceed 48"
      shift 2
      ;;
    --skip-on-access)
      ENABLE_ON_ACCESS=0
      shift
      ;;
    --no-unattended-upgrades)
      ENABLE_UNATTENDED_UPGRADES=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "Unknown option: $1"
      ;;
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
  if command -v nproc >/dev/null 2>&1; then
    MAX_THREADS="$(nproc)"
  else
    MAX_THREADS="$(getconf _NPROCESSORS_ONLN 2>/dev/null || true)"
  fi
  [[ "${MAX_THREADS}" =~ ^[1-9][0-9]*$ ]] || MAX_THREADS=1
  (( MAX_THREADS <= 2 )) || MAX_THREADS=$((MAX_THREADS - 1))
  (( MAX_THREADS <= 8 )) || MAX_THREADS=8
fi

MAX_QUEUE=$((MAX_THREADS * 2))
(( MAX_QUEUE >= 100 )) || MAX_QUEUE=100
ONACCESS_MAX_THREADS=$(((MAX_THREADS + 1) / 2))
(( ONACCESS_MAX_THREADS <= 4 )) || ONACCESS_MAX_THREADS=4

if [[ -z "${TARGET_USER}" && -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
  TARGET_USER="${SUDO_USER}"
fi

if [[ -z "${TARGET_USER}" ]]; then
  TARGET_USER="$(logname 2>/dev/null || true)"
fi

if [[ -z "${TARGET_USER}" || "${TARGET_USER}" == "root" ]]; then
  TARGET_USER=""
  warn "No non-root desktop user detected. User-specific paths and group membership will be skipped."
fi

TARGET_HOME=""
if [[ -n "${TARGET_USER}" ]]; then
  getent passwd "${TARGET_USER}" >/dev/null || die "User does not exist: ${TARGET_USER}"
  TARGET_HOME="$(getent passwd "${TARGET_USER}" | cut -d: -f6)"
  [[ -n "${TARGET_HOME}" && -d "${TARGET_HOME}" ]] || die "Home directory for ${TARGET_USER} was not found"
fi

declare -a CANDIDATE_SCAN_PATHS=()
if [[ "${#SCAN_PATH_ARGS[@]}" -gt 0 ]]; then
  CANDIDATE_SCAN_PATHS=("${SCAN_PATH_ARGS[@]}")
elif [[ -n "${TARGET_HOME}" ]]; then
  CANDIDATE_SCAN_PATHS=(
    "${TARGET_HOME}/Downloads"
    "${TARGET_HOME}/Desktop"
    "${TARGET_HOME}/Documents"
    "${TARGET_HOME}/Public"
  )
else
  CANDIDATE_SCAN_PATHS=("/home")
  ENABLE_ON_ACCESS=0
  warn "Defaulting scheduled scans to /home and disabling on-access scanning. Use --scan-path to enable explicit server watch paths."
fi

declare -a ACTIVE_SCAN_PATHS=()
declare -A SEEN_SCAN_PATHS=()
for path in "${CANDIDATE_SCAN_PATHS[@]}"; do
  if [[ -d "${path}" ]]; then
    canonical_path="$(readlink -f "${path}")"
    if [[ -z "${SEEN_SCAN_PATHS["${canonical_path}"]+set}" ]]; then
      ACTIVE_SCAN_PATHS+=("${canonical_path}")
      SEEN_SCAN_PATHS["${canonical_path}"]=1
    fi
  else
    warn "Skipping missing scan path: ${path}"
  fi
done

if [[ "${#ACTIVE_SCAN_PATHS[@]}" -eq 0 ]]; then
  warn "No valid scan paths found. Creating daily scan with no active targets; add paths later in /usr/local/bin/clamav-daily-scan."
fi

backup_if_changed() {
  local file="$1"

  if [[ -f "${file}" ]]; then
    cp -a "${file}" "${file}.bak.$(date +%Y%m%d%H%M%S)"
  fi
}

write_daily_scan_script() {
  local script_path="/usr/local/bin/clamav-daily-scan"

  cat >"${script_path}" <<'SCAN_HEAD'
#!/usr/bin/env bash
set -uo pipefail

LOG_FILE="/var/log/clamav/daily-scan.log"
START_STAMP="$(date '+%Y-%m-%d %H:%M:%S')"
ACTIVE_SCAN_PATHS=(
SCAN_HEAD

  for path in "${ACTIVE_SCAN_PATHS[@]}"; do
    printf '  %q\n' "${path}" >>"${script_path}"
  done

  cat >>"${script_path}" <<'SCAN_BODY'
)

mkdir -p "$(dirname "${LOG_FILE}")"

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

  chmod 0755 "${script_path}"
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

log "Installing ClamAV packages"
apt-get update
PACKAGES=(clamav clamav-daemon clamdscan clamav-freshclam)
if [[ "${ENABLE_UNATTENDED_UPGRADES}" -eq 1 ]]; then
  PACKAGES+=(unattended-upgrades)
fi
apt-get install -y "${PACKAGES[@]}"

if [[ -n "${TARGET_USER}" ]]; then
  usermod -aG clamav "${TARGET_USER}"
fi

if [[ "${ENABLE_UNATTENDED_UPGRADES}" -eq 1 ]]; then
  cat >/etc/apt/apt.conf.d/20auto-upgrades <<'APT_AUTO'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
APT_AUTO
fi

mkdir -p /etc/clamav
mkdir -p /etc/systemd/system/clamav-clamonacc.service.d
mkdir -p /var/lib/clamav/quarantine
mkdir -p /var/log/clamav

backup_if_changed /etc/clamav/clamd.conf
cat >/etc/clamav/clamd.conf <<CLAMD
# Managed by setup-clamav-ubuntu.sh
LocalSocket /var/run/clamav/clamd.ctl
FixStaleSocket true
LocalSocketGroup clamav
LocalSocketMode 660
User clamav
ScanMail true
ScanArchive true
ArchiveBlockEncrypted false
MaxDirectoryRecursion 15
FollowDirectorySymlinks false
FollowFileSymlinks false
ReadTimeout 180
MaxThreads ${MAX_THREADS}
MaxConnectionQueueLength 15
LogSyslog false
LogRotate true
LogFacility LOG_LOCAL6
LogClean false
LogVerbose false
DatabaseDirectory /var/lib/clamav
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
AlgorithmicDetection true
ScanELF true
IdleTimeout 30
CrossFilesystems false
PhishingSignatures true
PhishingScanURLs true
PhishingAlwaysBlockSSLMismatch false
PhishingAlwaysBlockCloak false
PartitionIntersection false
DetectPUA false
ScanPartialMessages false
HeuristicScanPrecedence false
StructuredDataDetection false
CommandReadTimeout 30
SendBufTimeout 200
MaxQueue ${MAX_QUEUE}
ExtendedDetectionInfo true
OLE2BlockMacros false
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
OnAccessMaxFileSize 25M
OnAccessMaxThreads ${ONACCESS_MAX_THREADS}
OnAccessExcludeUname clamav
CLAMD

: >/etc/clamav/onaccess.watch
for path in "${ACTIVE_SCAN_PATHS[@]}"; do
  printf '%s\n' "${path}" >>/etc/clamav/onaccess.watch
done
: >/etc/clamav/onaccess.exclude

cat >/etc/systemd/system/clamav-clamonacc.service.d/override.conf <<'OVERRIDE'
[Service]
ExecStart=
ExecStart=/usr/sbin/clamonacc -F --fdpass --log=/var/log/clamav/clamonacc.log --move=/var/lib/clamav/quarantine --watch-list=/etc/clamav/onaccess.watch --exclude-list=/etc/clamav/onaccess.exclude
ExecStop=
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=on-failure
RestartSec=10s
OVERRIDE

write_daily_scan_script

cat >/etc/systemd/system/clamav-daily-scan.service <<'SERVICE'
[Unit]
Description=Daily ClamAV scan
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/clamav-daily-scan
SuccessExitStatus=1
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
SERVICE

cat >/etc/systemd/system/clamav-daily-scan.timer <<'TIMER'
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

chown root:clamav /var/lib/clamav/quarantine
chmod 0750 /var/lib/clamav/quarantine

log "Starting services"
systemctl daemon-reload
systemctl enable --now clamav-freshclam.service

if ! wait_for_databases; then
  warn "ClamAV databases were not ready after waiting. clamav-daemon may start after freshclam completes."
fi

systemctl enable clamav-daemon.service
systemctl restart clamav-daemon.service

if [[ "${ENABLE_ON_ACCESS}" -eq 1 && "${#ACTIVE_SCAN_PATHS[@]}" -gt 0 ]]; then
  systemctl enable clamav-clamonacc.service
  systemctl restart clamav-clamonacc.service
else
  systemctl disable --now clamav-clamonacc.service >/dev/null 2>&1 || true
  warn "On-access scanning is disabled because it was skipped or no valid watch paths exist."
fi

systemctl enable --now clamav-daily-scan.timer

if [[ "${ENABLE_UNATTENDED_UPGRADES}" -eq 1 ]]; then
  systemctl enable --now unattended-upgrades.service
fi

log "Validating installation"
clamscan --version
clamdscan --version
systemctl is-active --quiet clamav-daemon.service || die "clamav-daemon.service is not active"
systemctl is-active --quiet clamav-freshclam.service || die "clamav-freshclam.service is not active"
systemctl is-active --quiet clamav-daily-scan.timer || die "clamav-daily-scan.timer is not active"

if [[ "${ENABLE_ON_ACCESS}" -eq 1 && "${#ACTIVE_SCAN_PATHS[@]}" -gt 0 ]]; then
  systemctl is-active --quiet clamav-clamonacc.service || die "clamav-clamonacc.service is not active"
fi

if ! clamdscan --fdpass /etc/hosts >/dev/null; then
  die "clamdscan validation failed against /etc/hosts"
fi

echo
echo "ClamAV setup complete"
echo "clamd workers: ${MAX_THREADS} (queue: ${MAX_QUEUE}; on-access workers: ${ONACCESS_MAX_THREADS})"
if [[ -n "${TARGET_USER}" ]]; then
  echo "Protected user: ${TARGET_USER}"
  echo "Note: ${TARGET_USER} was added to the clamav group. Log out and back in before running clamdscan without sudo."
fi
echo
echo "Scan paths:"
if [[ "${#ACTIVE_SCAN_PATHS[@]}" -gt 0 ]]; then
  printf '  %s\n' "${ACTIVE_SCAN_PATHS[@]}"
else
  echo "  none configured"
fi
echo
echo "Check status:"
echo "  systemctl status clamav-daemon clamav-freshclam clamav-clamonacc clamav-daily-scan.timer unattended-upgrades --no-pager"
echo
echo "Check versions:"
echo "  clamscan --version"
echo "  apt-cache policy clamav clamav-daemon clamav-freshclam"
echo
echo "Check next run:"
echo "  systemctl list-timers --all clamav-daily-scan.timer --no-pager"
echo
echo "Run daily scan now:"
echo "  sudo systemctl start clamav-daily-scan.service"
echo
echo "Check logs:"
echo "  tail -n 80 /var/log/clamav/daily-scan.log"
echo "  sudo tail -n 80 /var/log/clamav/freshclam.log"
echo "  sudo tail -n 80 /var/log/clamav/clamav.log"
echo "  sudo tail -n 80 /var/log/clamav/clamonacc.log"

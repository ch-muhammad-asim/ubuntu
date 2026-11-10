#!/usr/bin/env bash
# Offline regression checks; no root, services, or installed xrdp required.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/ubuntu-rdp.sh"
testdir=$(mktemp -d)
trap 'rm -rf -- "$testdir"' EXIT

die() { echo "FAIL: $*" >&2; exit 1; }

# --- Session policy: single desktop, reattach, clean up abandoned desktops ---
cat > "$testdir/sesman.ini" <<'INI'
[Globals]
MaxSessions=99
[Sessions]
; keep this comment
MaxSessions=50
Policy=Separate
policy=UBDI
KillDisconnected=false
DisconnectedTimeLimit=0
IdleTimeLimit=120
X11DisplayOffset=10
[Xorg]
param=-config
param=xrdp/xorg.conf
INI
cp "$testdir/sesman.ini" "$testdir/original"
chmod 640 "$testdir/sesman.ini"
configure_session_policy "$testdir/sesman.ini" single
[[ $(session_setting "$testdir/sesman.ini" MaxSessions) == 1 ]] || die 'MaxSessions not set to 1'
[[ $(session_setting "$testdir/sesman.ini" Policy) == Default ]] || die 'Policy not set to Default'
[[ $(session_setting "$testdir/sesman.ini" KillDisconnected) == true ]] || die 'KillDisconnected not enabled'
[[ $(session_setting "$testdir/sesman.ini" DisconnectedTimeLimit) == 300 ]] || die 'DisconnectedTimeLimit not set'
[[ $(session_setting "$testdir/sesman.ini" IdleTimeLimit) == 0 ]] || die 'IdleTimeLimit not disabled'
[[ $(session_setting "$testdir/sesman.ini" X11DisplayOffset) == 10 ]] || die 'unrelated key changed'
[[ $(grep -ci '^policy=' "$testdir/sesman.ini") == 1 ]] || die 'duplicate Policy key left behind'
[[ $(stat -c %a "$testdir/sesman.ini") == 640 ]] || die 'permissions not preserved'
grep -q '^MaxSessions=99$' "$testdir/sesman.ini" || die '[Globals] MaxSessions changed'
grep -q '^; keep this comment$' "$testdir/sesman.ini" || die 'comment lost'
[[ $(grep -c '^param=' "$testdir/sesman.ini") == 2 ]] || die '[Xorg] params changed'
cmp "$testdir/original" "$(find "$testdir" -name 'sesman.ini.backup.*' -print -quit)" || die 'backup is not the original file'

cp "$testdir/sesman.ini" "$testdir/once"
configure_session_policy "$testdir/sesman.ini" single
cmp "$testdir/once" "$testdir/sesman.ini" || die 'second run changed the file'
[[ $(find "$testdir" -name 'sesman.ini.backup.*' | wc -l) == 1 ]] || die 'idempotent run added a backup'

# --- Session policy: one desktop per user keeps reattach and a bounded limit --
configure_session_policy "$testdir/sesman.ini" multi
[[ $(session_setting "$testdir/sesman.ini" MaxSessions) == "$RDP_MULTI_MAX_SESSIONS" ]] || die 'multi MaxSessions wrong'
[[ $(session_setting "$testdir/sesman.ini" Policy) == Default ]] || die 'multi Policy wrong'
[[ $(find "$testdir" -name 'sesman.ini.backup.*' | wc -l) == 2 ]] || die 'multi run did not back up'

# --- Session policy: damaged/awkward inputs --------------------------------
printf '[Sessions]\nPolicy=Separate\n[Xorg]\nparam=Xorg\n' > "$testdir/partial.ini"
configure_session_policy "$testdir/partial.ini" single
[[ $(session_setting "$testdir/partial.ini" MaxSessions) == 1 ]] || die 'partial section not completed'
printf '[Globals]\nEnableUserWindowManager=true\n' > "$testdir/no-section.ini"
configure_session_policy "$testdir/no-section.ini" single
[[ $(session_setting "$testdir/no-section.ini" Policy) == Default ]] || die '[Sessions] not appended'

printf '[Sessions]\nPolicy=Separate\n[Sessions]\nMaxSessions=50\n' > "$testdir/duplicate.ini"
cp "$testdir/duplicate.ini" "$testdir/duplicate-original"
if configure_session_policy "$testdir/duplicate.ini" single; then
    die 'duplicate section accepted'
fi
cmp "$testdir/duplicate-original" "$testdir/duplicate.ini" || die 'duplicate file was modified'
ln -s "$testdir/sesman.ini" "$testdir/link.ini"
if configure_session_policy "$testdir/link.ini" single; then
    die 'symlink accepted'
fi
if configure_session_policy "$testdir/sesman.ini" bogus 2>/dev/null; then
    die 'unknown mode accepted'
fi

# --- Session startup -------------------------------------------------------
configure_startwm "$testdir/startwm.sh"
[[ -x "$testdir/startwm.sh" ]] || die 'startwm.sh is not executable'
grep -q 'ubuntu-rdp.sh: managed xrdp session startup' "$testdir/startwm.sh" || die 'startwm marker missing'
grep -q 'dbus-run-session -- startxfce4' "$testdir/startwm.sh" || die 'startwm does not start Xfce'
grep -q 'unset DBUS_SESSION_BUS_ADDRESS' "$testdir/startwm.sh" || die 'startwm does not isolate the session bus'
sh -n "$testdir/startwm.sh" || die 'startwm.sh is not valid POSIX sh'
[[ $(find "$testdir" -name 'startwm.sh.backup.*' | wc -l) == 0 ]] || die 'fresh startwm.sh got a backup'

cp "$testdir/startwm.sh" "$testdir/startwm-once"
configure_startwm "$testdir/startwm.sh"
cmp "$testdir/startwm-once" "$testdir/startwm.sh" || die 'startwm second run changed the file'
[[ $(find "$testdir" -name 'startwm.sh.backup.*' | wc -l) == 0 ]] || die 'idempotent startwm run added a backup'

printf '#!/bin/sh\necho legacy\n' > "$testdir/legacy.sh"
configure_startwm "$testdir/legacy.sh"
grep -q 'echo legacy' "$(find "$testdir" -name 'legacy.sh.backup.*' -print -quit)" || die 'legacy startwm not backed up'
grep -q 'managed xrdp session startup' "$testdir/legacy.sh" || die 'legacy startwm not replaced'

ln -s "$testdir/startwm.sh" "$testdir/startwm-link.sh"
if configure_startwm "$testdir/startwm-link.sh" 2>/dev/null; then
    die 'symlinked startwm accepted'
fi

# --- Live-desktop counters -------------------------------------------------
loginctl() {
    if [[ "$1" == list-sessions ]]; then
        printf '1 1000 demo\n2 1000 demo\n3 1000 demo\n'
    elif [[ "$2" == 1 || "$2" == 2 ]]; then
        printf 'xrdp-sesman\n'
    else
        printf 'user@1000.service\n'
    fi
}
[[ $(rdp_session_count) == 2 ]] || die 'rdp_session_count wrong'
unset -f loginctl

pgrep() { printf '3\n'; }
[[ $(rdp_xorg_count) == 3 ]] || die 'rdp_xorg_count wrong'
pgrep() { return 1; }
[[ $(rdp_xorg_count) == 0 ]] || die 'rdp_xorg_count must report 0 without matches'
unset -f pgrep

is_positive_integer 1 || die 'is_positive_integer rejected 1'
is_positive_integer 0 && die 'is_positive_integer accepted 0'
is_positive_integer '' && die 'is_positive_integer accepted empty'
is_positive_integer 2x && die 'is_positive_integer accepted 2x'

# --- Verification must report every failed check, not exit on the first one --
export RDP_TEST_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/ubuntu-rdp.sh"
if bash -c '
    source "$RDP_TEST_SCRIPT"
    require_root() { :; }
    dpkg() { return 1; }
    dpkg-query() { return 1; }
    systemctl() { return 1; }
    ss() { return 0; }
    hostname() { printf "192.0.2.1\n"; }
    nc() { return 1; }
    loginctl() { return 1; }
    pgrep() { return 1; }
    ufw() { return 1; }
    journalctl() { return 0; }
    do_verify
' > "$testdir/verify.log" 2>&1; then
    die 'unhealthy verification returned success'
fi
grep -q 'Summary' "$testdir/verify.log" || die 'verification printed no summary'
grep -q 'check(s) failed' "$testdir/verify.log" || die 'verification counted no failures'
grep -q 'xrdp is NOT installed' "$testdir/verify.log" || die 'verification stopped before the package check'

echo 'PASS: policy modes, duplicate keys, unrelated sections, backups, permissions, idempotence, startup file, counters and failure safety'

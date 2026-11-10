#!/usr/bin/env bash
#
# ubuntu-rdp.sh — Install, configure, and verify xrdp on Ubuntu 22.04/24.04/26.04
#
# The script installs xrdp with a usable desktop session and one retained RDP
# desktop, so reconnecting returns to the same desktop instead of starting a new
# one next to it.
#
# Usage:
#   sudo ./ubuntu-rdp.sh              # Full install + verify (single desktop)
#   sudo ./ubuntu-rdp.sh install       # Install and configure only
#   sudo ./ubuntu-rdp.sh single-session # One RDP desktop for the whole server
#   sudo ./ubuntu-rdp.sh multi-session  # One RDP desktop per user (max 5)
#   sudo ./ubuntu-rdp.sh verify        # Verify existing setup only
#   sudo ./ubuntu-rdp.sh status        # Quick status check
#   sudo ./ubuntu-rdp.sh uninstall     # Remove xrdp completely

set -euo pipefail

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "  ${CYAN}[INFO]${NC} $1"; }
header() { echo -e "\n${CYAN}=== $1 ===${NC}"; }

ERRORS=0

# Seconds a client may stay disconnected before its desktop is cleaned up.
RDP_DISCONNECT_TIMEOUT=300
# Desktop limit for the multi-session mode.
RDP_MULTI_MAX_SESSIONS=5

# --- Root check ---
require_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: This script must be run as root (use sudo).${NC}"
        exit 1
    fi
}

# --- Detect the real user (not root) ---
get_real_user() {
    if [[ -n "${SUDO_USER:-}" ]]; then
        echo "$SUDO_USER"
    else
        echo "$USER"
    fi
}

# Backup name that never overwrites an earlier backup taken in the same second.
unique_backup_name() {
    local base candidate n=0
    base="${1}.backup.$(date +%Y%m%d%H%M%S)"
    candidate="$base"
    while [[ -e "$candidate" ]]; do
        n=$((n + 1))
        candidate="${base}.${n}"
    done
    printf '%s\n' "$candidate"
}

# Only modify [Sessions]; Xorg/Xvnc sections contain repeated param= keys.
session_setting() {
    awk -v wanted="$2" '
        /^[[:space:]]*\[/ { section=tolower($0); gsub(/[[:space:]]/, "", section) }
        section == "[sessions]" && $0 !~ /^[[:space:]]*[;#]/ {
            pos=index($0,"="); key=substr($0,1,pos-1); gsub(/[[:space:]]/,"",key)
            if (pos && tolower(key)==tolower(wanted)) {
                value=substr($0,pos+1); sub(/^[[:space:]]*/,"",value); sub(/[[:space:]]*$/,"",value)
                result=value
            }
        }
        END { print result }
    ' "$1"
}

# --- Session policy -------------------------------------------------------
# Policy=Default (xrdp's "UB") reattaches a client to the desktop it already
# owns for the same user and colour depth. Policy=Separate, which older guides
# recommend, starts a brand-new desktop on every connect and leaves the old one
# running, which is what produced several Xorg desktops on one account.
#
# KillDisconnected frees the slot again after RDP_DISCONNECT_TIMEOUT seconds so
# a crashed client cannot block the single desktop forever.
configure_session_policy() {
    local config="$1" mode="${2:-single}" temp backup maxsessions
    case "$mode" in
        single) maxsessions=1 ;;
        multi) maxsessions=$RDP_MULTI_MAX_SESSIONS ;;
        *) fail "Unknown session mode: $mode"; return 1 ;;
    esac
    [[ -f "$config" && ! -L "$config" ]] || { fail "Session config must be a regular file: $config"; return 1; }
    temp=$(mktemp "${config}.tmp.XXXXXX")
    if ! awk -v maxsessions="$maxsessions" -v timeout="$RDP_DISCONNECT_TIMEOUT" '
        BEGIN {
            keys[1]="MaxSessions"; keys[2]="Policy"; keys[3]="KillDisconnected"
            keys[4]="DisconnectedTimeLimit"; keys[5]="IdleTimeLimit"
            values[1]=maxsessions; values[2]="Default"; values[3]="true"
            values[4]=timeout; values[5]="0"
        }
        function missing( i) {
            for (i=1;i<=5;i++) if (!seen[i]) print keys[i] "=" values[i]
        }
        /^[[:space:]]*\[/ {
            if (inside) missing()
            section=tolower($0); gsub(/[[:space:]]/, "", section)
            inside=(section=="[sessions]")
            if (inside && ++sections>1) exit 2
        }
        inside && $0 !~ /^[[:space:]]*[;#]/ {
            pos=index($0,"="); key=substr($0,1,pos-1); gsub(/[[:space:]]/,"",key)
            matched=0
            for (i=1;i<=5;i++) if (pos && tolower(key)==tolower(keys[i])) {
                if (!seen[i]++) print keys[i] "=" values[i]
                matched=1; break
            }
            if (matched) next
        }
        { print }
        END {
            if (!sections) { print ""; print "[Sessions]"; missing() }
            else if (inside) missing()
        }
    ' "$config" > "$temp"; then
        rm -f -- "$temp"; fail "Could not update session policy (check duplicate [Sessions] sections)"; return 1
    fi
    if cmp -s -- "$config" "$temp"; then
        rm -f -- "$temp"; info "Session policy already configured ($mode)"; return 0
    fi
    backup=$(unique_backup_name "$config")
    if ! cp -p -- "$config" "$backup" || ! chmod --reference="$config" "$temp" ||
       ! chown --reference="$config" "$temp" || ! mv -- "$temp" "$config"; then
        rm -f -- "$temp"; fail "Could not install session policy; backup: $backup"; return 1
    fi
    if [[ "$mode" == single ]]; then
        pass "Configured one retained RDP desktop; backup: $backup"
    else
        pass "Configured one retained RDP desktop per user (max $maxsessions); backup: $backup"
    fi
}

# Kept for callers of the previous script version.
configure_single_session() {
    configure_session_policy "$1" single
}

# --- Session startup ------------------------------------------------------
# Written to /etc/xrdp/startwm.sh. It must stay POSIX sh: sesman runs it with
# /bin/sh and without the user's login shell.
startwm_content() {
    cat <<'STARTWM'
#!/bin/sh
# ubuntu-rdp.sh: managed xrdp session startup (rerun the script instead of editing)

if [ -r /etc/profile ]; then
    . /etc/profile
fi
if [ -r "$HOME/.profile" ]; then
    . "$HOME/.profile"
fi

# xrdp runs an X11 server. Drop the local console session's D-Bus address and
# Wayland socket: inheriting them makes desktop components attach to the console
# session or abort, and the RDP desktop then stays black.
unset DBUS_SESSION_BUS_ADDRESS SESSION_MANAGER WAYLAND_DISPLAY
export XDG_SESSION_TYPE=x11
export GDK_BACKEND=x11
export QT_QPA_PLATFORM=xcb

# GNOME has no X11 session on Ubuntu 25.10 and newer (GNOME 50 on 26.04), so
# gnome-session exits immediately under xrdp. Where the release still ships a
# GNOME X11 session keep the distribution default; otherwise start Xfce on a
# private D-Bus bus.
if [ ! -e /usr/share/xsessions/ubuntu.desktop ] &&
   [ ! -e /usr/share/xsessions/gnome.desktop ] &&
   [ ! -e /usr/share/xsessions/gnome-xorg.desktop ] &&
   command -v startxfce4 >/dev/null 2>&1; then
    export XDG_CURRENT_DESKTOP=XFCE
    export XDG_SESSION_DESKTOP=xfce
    export DESKTOP_SESSION=xfce
    exec dbus-run-session -- startxfce4
fi

# Distribution default: honours ~/.xsession, ~/.xsessionrc and the configured
# X session manager.
if [ -x /etc/X11/Xsession ]; then
    exec /etc/X11/Xsession
fi

exec dbus-run-session -- startxfce4
STARTWM
}

configure_startwm() {
    local target="${1:-/etc/xrdp/startwm.sh}" temp backup
    if [[ -L "$target" ]]; then
        fail "Session startup must not be a symlink: $target"; return 1
    fi
    if [[ -e "$target" && ! -f "$target" ]]; then
        fail "Session startup must be a regular file: $target"; return 1
    fi
    temp=$(mktemp "${target}.tmp.XXXXXX") || { fail "Could not write next to $target"; return 1; }
    startwm_content > "$temp"
    if [[ -f "$target" ]] && cmp -s -- "$target" "$temp"; then
        rm -f -- "$temp"
        chmod 0755 "$target" || return 1
        info "$target already configured"
        return 0
    fi
    backup="none"
    if [[ -f "$target" ]]; then
        backup=$(unique_backup_name "$target")
        if ! cp -p -- "$target" "$backup" ||
           ! chmod --reference="$target" "$temp" || ! chown --reference="$target" "$temp"; then
            rm -f -- "$temp"; fail "Could not install $target"; return 1
        fi
    else
        chmod 0755 "$temp" || { rm -f -- "$temp"; return 1; }
    fi
    if ! mv -- "$temp" "$target"; then
        rm -f -- "$temp"; fail "Could not install $target"; return 1
    fi
    pass "Configured $target (backup: $backup)"
}

# True when the release ships a GNOME X11 session; must match startwm_content.
gnome_x11_available() {
    [[ -e /usr/share/xsessions/ubuntu.desktop ||
       -e /usr/share/xsessions/gnome.desktop ||
       -e /usr/share/xsessions/gnome-xorg.desktop ]]
}

# GNOME 50 has no X11 session, so the RDP desktop has to come from Xfce.
ensure_desktop() {
    if gnome_x11_available; then
        info "GNOME X11 session available — keeping the distribution default"
        return 0
    fi
    if command -v startxfce4 >/dev/null 2>&1; then
        info "GNOME has no X11 session on this release — using Xfce"
        return 0
    fi
    info "GNOME has no X11 session on this release — installing Xfce..."
    apt-get install -y -qq xfce4 >/dev/null
    pass "Xfce installed"
}

# --- RDP desktop helpers --------------------------------------------------
rdp_session_count() {
    local sessions session service count=0
    sessions=$(loginctl list-sessions --no-legend 2>/dev/null) || return 1
    while read -r session _; do
        [[ -n "$session" ]] || continue
        service=$(loginctl show-session "$session" -p Service --value 2>/dev/null) || return 1
        [[ "$service" != xrdp-sesman ]] || count=$((count + 1))
    done <<< "$sessions"
    printf '%s\n' "$count"
}

# X servers started by xrdp. More X servers than logind sessions means desktops
# left behind by an earlier connect (the duplicate-desktop symptom).
rdp_xorg_count() {
    local count
    count=$(pgrep -c -f 'Xorg .*-config xrdp/xorg\.conf' 2>/dev/null) || count=0
    printf '%s\n' "$count"
}

is_positive_integer() {
    [[ "$1" =~ ^[0-9]+$ ]] && (( $1 > 0 ))
}

# --- Configure (no reinstall) --------------------------------------------
do_configure() {
    local mode="$1"
    require_root
    header "Configuring xrdp session"
    ensure_desktop
    configure_startwm /etc/xrdp/startwm.sh
    configure_session_policy /etc/xrdp/sesman.ini "$mode"
    if systemctl is-active --quiet xrdp-sesman; then
        # SIGHUP reloads sesman.ini and keeps existing desktops and their
        # session tracking intact; a restart would orphan them.
        systemctl reload xrdp-sesman
        pass "Reloaded xrdp-sesman without terminating desktops"
    else
        warn "xrdp-sesman is not running — start it with: systemctl start xrdp xrdp-sesman"
    fi
    info "Existing extra desktops are not killed: save work and log out of them from their own menu."
    info "Reconnect with the same account and colour depth to return to the retained desktop."
}

do_single_session() { do_configure single; }
do_multi_session() { do_configure multi; }

# --- Install ---
do_install() {
    require_root
    local REAL_USER
    REAL_USER=$(get_real_user)

    header "Installing xrdp"

    if dpkg -s xrdp >/dev/null 2>&1 && dpkg -s xorgxrdp >/dev/null 2>&1; then
        info "xrdp and xorgxrdp are already installed"
    else
        info "Updating package lists..."
        apt-get update -qq
        info "Installing xrdp and xorgxrdp..."
        apt-get install -y -qq xrdp xorgxrdp >/dev/null
        pass "xrdp and xorgxrdp installed"
    fi

    header "Configuring xrdp"

    # Add xrdp user to ssl-cert group
    if id -nG xrdp | grep -qw ssl-cert; then
        info "xrdp user already in ssl-cert group"
    else
        adduser xrdp ssl-cert
        pass "Added xrdp to ssl-cert group"
    fi

    # Desktop that xrdp can actually run on X11, plus the session startup file.
    ensure_desktop
    configure_startwm /etc/xrdp/startwm.sh

    # Create polkit rules to suppress auth dialogs over RDP
    local POLKIT_DIR="/etc/polkit-1/rules.d"
    if [[ -d "$POLKIT_DIR" ]]; then
        cat > "$POLKIT_DIR/02-allow-colord.rules" << 'POLKIT'
polkit.addRule(function(action, subject) {
    if ((action.id == "org.freedesktop.color-manager.create-device" ||
         action.id == "org.freedesktop.color-manager.create-profile" ||
         action.id == "org.freedesktop.color-manager.delete-device" ||
         action.id == "org.freedesktop.color-manager.delete-profile" ||
         action.id == "org.freedesktop.color-manager.modify-device" ||
         action.id == "org.freedesktop.color-manager.modify-profile") &&
        subject.isInGroup("users")) {
        return polkit.Result.YES;
    }
});
POLKIT
        pass "Created polkit rules for colord"
    else
        warn "Polkit rules.d directory not found — skipping colord rules"
    fi

    # Configure firewall if active
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw allow 3389/tcp
        pass "Firewall rule added for port 3389"
    else
        info "Firewall (ufw) is inactive — no rule needed"
    fi

    configure_session_policy /etc/xrdp/sesman.ini single

    # Enable and start xrdp
    systemctl enable xrdp --now
    systemctl enable xrdp-sesman --now
    systemctl reload xrdp-sesman
    pass "xrdp services enabled and started"

    header "Installation Complete"
    local IP
    IP=$(hostname -I | awk '{print $1}')
    info "Connect via RDP to ${GREEN}${IP}:3389${NC}"
    info "Username: ${GREEN}${REAL_USER}${NC}"
    echo ""
}

# --- Verify ---
do_verify() {
    require_root
    local REAL_USER
    REAL_USER=$(get_real_user)

    header "Verifying xrdp Setup"
    ERRORS=0

    # 1. Package installed
    header "1. Package Check"
    local pkg
    for pkg in xrdp xorgxrdp; do
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            pass "$pkg is installed (version: $(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null))"
        else
            fail "$pkg is NOT installed"
            ERRORS=$((ERRORS + 1))
        fi
    done

    # 2. Services running
    header "2. Service Status"
    for svc in xrdp xrdp-sesman; do
        if systemctl is-active --quiet "$svc"; then
            pass "$svc is running"
        else
            fail "$svc is NOT running"
            ERRORS=$((ERRORS + 1))
        fi
        if systemctl is-enabled --quiet "$svc"; then
            pass "$svc is enabled on boot"
        else
            fail "$svc is NOT enabled on boot"
            ERRORS=$((ERRORS + 1))
        fi
    done

    # 3. Port listening
    header "3. Network"
    if ss -tlnp | grep -q ':3389'; then
        pass "Port 3389 is listening"
    else
        fail "Port 3389 is NOT listening"
        ERRORS=$((ERRORS + 1))
    fi

    local IP
    IP=$(hostname -I | awk '{print $1}')
    info "Local IP: $IP"

    # 4. Firewall
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "Status: active"; then
        if ufw status | grep -q "3389"; then
            pass "Firewall allows port 3389"
        else
            fail "Firewall is active but port 3389 is NOT allowed"
            ERRORS=$((ERRORS + 1))
        fi
    else
        info "Firewall (ufw) is inactive — no restriction"
    fi

    # 5. SSL cert group
    header "4. Permissions"
    if id -nG xrdp 2>/dev/null | grep -qw ssl-cert; then
        pass "xrdp user is in ssl-cert group"
    else
        fail "xrdp user is NOT in ssl-cert group"
        ERRORS=$((ERRORS + 1))
    fi

    # 6. Session policy
    header "5. Session Configuration"
    local policy kill_disconnected disconnect_limit max_sessions
    policy=$(session_setting /etc/xrdp/sesman.ini Policy || true)
    kill_disconnected=$(session_setting /etc/xrdp/sesman.ini KillDisconnected || true)
    disconnect_limit=$(session_setting /etc/xrdp/sesman.ini DisconnectedTimeLimit || true)
    max_sessions=$(session_setting /etc/xrdp/sesman.ini MaxSessions || true)

    if [[ "${policy,,}" == "default" ]]; then
        pass "Session policy: Policy=$policy (reconnect reuses the desktop)"
    else
        fail "Session policy: expected Policy=Default, found '${policy:-unset}' (every connect creates a new desktop)"
        ERRORS=$((ERRORS + 1))
    fi
    if [[ "${kill_disconnected,,}" == "true" || "${kill_disconnected,,}" == "yes" || "$kill_disconnected" == "1" ]]; then
        pass "Session policy: KillDisconnected=$kill_disconnected"
    else
        fail "Session policy: expected KillDisconnected=true (abandoned desktops would never be cleaned up)"
        ERRORS=$((ERRORS + 1))
    fi
    if is_positive_integer "$disconnect_limit"; then
        pass "Session policy: DisconnectedTimeLimit=${disconnect_limit}s"
    else
        fail "Session policy: expected DisconnectedTimeLimit > 0"
        ERRORS=$((ERRORS + 1))
    fi
    if is_positive_integer "$max_sessions"; then
        if [[ "$max_sessions" == "1" ]]; then
            pass "Session policy: MaxSessions=1 (one RDP desktop for the server)"
        else
            pass "Session policy: MaxSessions=$max_sessions (one RDP desktop per user)"
        fi
    else
        fail "Session policy: expected MaxSessions >= 1"
        ERRORS=$((ERRORS + 1))
    fi

    # 7. Session startup and desktop
    local startup=/etc/xrdp/startwm.sh
    if [[ -x "$startup" ]]; then
        pass "$startup is executable"
        if grep -q 'ubuntu-rdp.sh: managed xrdp session startup' "$startup"; then
            pass "$startup is managed by this script"
        else
            warn "$startup was not written by this script — rerun single-session to normalise it"
        fi
    else
        fail "$startup is missing or not executable"
        ERRORS=$((ERRORS + 1))
    fi
    if gnome_x11_available; then
        info "GNOME X11 session present — distribution default desktop is used"
    elif command -v startxfce4 >/dev/null 2>&1; then
        pass "GNOME has no X11 session here; Xfce is available for RDP"
    else
        fail "No X11 desktop for RDP: GNOME has no X11 session and Xfce is not installed"
        ERRORS=$((ERRORS + 1))
    fi

    # 8. Live desktops
    local sessions xorgs
    if sessions=$(rdp_session_count); then
        if [[ "$sessions" == "0" ]]; then
            info "No RDP desktop is connected right now"
        elif is_positive_integer "$max_sessions" && (( sessions > max_sessions )); then
            fail "$sessions RDP desktops exist but MaxSessions=$max_sessions; save work and log out of the extra desktops"
            ERRORS=$((ERRORS + 1))
        else
            pass "RDP desktops: $sessions"
        fi
    else
        warn "Cannot count desktop sessions with loginctl"
    fi
    if xorgs=$(rdp_xorg_count); then
        if [[ "$sessions" =~ ^[0-9]+$ && "$xorgs" =~ ^[0-9]+$ ]]; then
            if (( xorgs > sessions )); then
                fail "$xorgs xrdp X servers but $sessions tracked desktop(s) — orphan desktop left by an earlier connect"
                ERRORS=$((ERRORS + 1))
            else
                pass "xrdp X servers: $xorgs"
            fi
        else
            warn "Cannot compare xrdp X servers with tracked desktops"
        fi
    else
        warn "Cannot count xrdp X servers"
    fi

    # 9. Polkit rules
    header "6. Polkit Rules"
    if [[ -f /etc/polkit-1/rules.d/02-allow-colord.rules ]]; then
        pass "Colord polkit rules are in place"
    elif [[ -f /etc/polkit-1/localauthority/50-local.d/45-allow-colord.pkla ]]; then
        pass "Colord polkit rules are in place (pkla format)"
    else
        warn "No colord polkit rules found — you may see auth dialogs on RDP"
    fi

    # 10. Connection test
    header "7. Connection Test"
    if command -v nc &>/dev/null; then
        if nc -z -w3 127.0.0.1 3389 2>/dev/null; then
            pass "TCP connection to localhost:3389 succeeded"
        else
            fail "TCP connection to localhost:3389 failed"
            ERRORS=$((ERRORS + 1))
        fi
    elif command -v bash &>/dev/null; then
        if (echo > /dev/tcp/127.0.0.1/3389) 2>/dev/null; then
            pass "TCP connection to localhost:3389 succeeded"
        else
            fail "TCP connection to localhost:3389 failed"
            ERRORS=$((ERRORS + 1))
        fi
    else
        warn "No connectivity tool available — skipping connection test"
    fi

    # 11. Recent logs
    header "8. Recent Logs"
    local LOG_ERRORS
    LOG_ERRORS=$(journalctl -u xrdp -u xrdp-sesman --since "10 min ago" --no-pager -p err 2>/dev/null | grep -v "^--" | tail -5 || true)
    if [[ -z "$LOG_ERRORS" ]]; then
        pass "No recent errors in xrdp logs"
    else
        warn "Recent errors in xrdp logs:"
        echo "$LOG_ERRORS" | while read -r line; do
            echo -e "        $line"
        done
    fi

    # Summary
    header "Summary"
    if [[ $ERRORS -eq 0 ]]; then
        echo -e "  ${GREEN}All checks passed!${NC}"
        echo ""
        info "RDP is ready. Connect to ${GREEN}${IP}:3389${NC} with user ${GREEN}${REAL_USER}${NC}"
    else
        echo -e "  ${RED}${ERRORS} check(s) failed.${NC}"
        echo ""
        info "Run '${CYAN}sudo $0 install${NC}' to fix issues"
    fi
    echo ""
    return $ERRORS
}

# --- Status (quick, no root needed) ---
do_status() {
    header "xrdp Quick Status"
    if systemctl is-active --quiet xrdp 2>/dev/null; then
        pass "xrdp: running"
    else
        fail "xrdp: not running"
    fi
    if systemctl is-active --quiet xrdp-sesman 2>/dev/null; then
        pass "xrdp-sesman: running"
    else
        fail "xrdp-sesman: not running"
    fi
    if ss -tlnp 2>/dev/null | grep -q ':3389'; then
        pass "Port 3389: listening"
    else
        fail "Port 3389: not listening"
    fi
    if [[ -r /etc/xrdp/sesman.ini ]]; then
        info "Policy: $(session_setting /etc/xrdp/sesman.ini Policy || true) | MaxSessions: $(session_setting /etc/xrdp/sesman.ini MaxSessions || true) | DisconnectedTimeLimit: $(session_setting /etc/xrdp/sesman.ini DisconnectedTimeLimit || true)s"
    fi
    local sessions xorgs
    if sessions=$(rdp_session_count); then
        info "RDP desktops: $sessions"
    fi
    if xorgs=$(rdp_xorg_count); then
        info "xrdp X servers: $xorgs"
    fi
    local IP
    IP=$(hostname -I 2>/dev/null | awk '{print $1}')
    info "IP: ${IP:-unknown}"
    echo ""
}

# --- Uninstall ---
do_uninstall() {
    require_root

    header "Uninstalling xrdp"

    systemctl stop xrdp xrdp-sesman 2>/dev/null || true
    systemctl disable xrdp xrdp-sesman 2>/dev/null || true
    apt-get remove --purge -y xrdp xorgxrdp 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true

    rm -f /etc/polkit-1/rules.d/02-allow-colord.rules
    rm -f /etc/polkit-1/localauthority/50-local.d/45-allow-colord.pkla 2>/dev/null

    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q "active"; then
        ufw delete allow 3389/tcp 2>/dev/null || true
    fi

    pass "xrdp has been completely removed"
    echo ""
}

# --- Main (guarded so regression checks can source the helpers) ---
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
ACTION="${1:-all}"

case "$ACTION" in
    single-session)
        do_single_session
        ;;
    multi-session)
        do_multi_session
        ;;
    install)
        do_install
        ;;
    verify)
        do_verify
        ;;
    status)
        do_status
        ;;
    uninstall)
        do_uninstall
        ;;
    all)
        do_install
        do_verify
        ;;
    *)
        echo "Usage: sudo $0 {install|single-session|multi-session|verify|status|uninstall|all}"
        exit 1
        ;;
esac
fi

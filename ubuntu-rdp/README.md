# Ubuntu RDP

One-script setup for xrdp on Ubuntu 22.04, 24.04 and 26.04 (GNOME or Xfce), with a
single retained RDP desktop that reconnects instead of stacking up new ones.

## Quick Start

```bash
git clone https://github.com/ch-muhammad-asim/ubuntu.git
cd ubuntu/ubuntu-rdp
sudo ./ubuntu-rdp.sh
```

This installs xrdp, configures the session startup and session policy, and verifies
everything is working.

## The two problems this fixes

**1. Every connect started a new desktop.** `Policy=Separate`, which several guides
recommend, gives each connection its own X server and desktop and leaves the previous
one running: reconnect a few times and the machine fills up with desktops on displays
`:10`, `:11`, `:12`, … each holding memory, and the same user ends up with several
`xfce4-session`/`gnome-session` trees fighting over the keyring and GSettings.

This script sets `Policy=Default` (xrdp's "UB"): a client reattaches to the desktop it
already owns for the same user and colour depth, no matter which client or window size
it uses.

**2. A second account got a black screen.** Ubuntu 22.04/24.04 ship a GNOME X11
session; Ubuntu 25.10 and newer (GNOME 50 on 26.04) do not. Users with no
`~/.xsession` were started through `/etc/X11/Xsession`, which runs
`x-session-manager` = `gnome-session`, and that exits immediately without a
Wayland compositor. xrdp then closes the connection or shows a black desktop.

The script writes `/etc/xrdp/startwm.sh` so every account gets the same working
session: the distribution default where a GNOME X11 session exists, otherwise Xfce
(installed if missing) on a private D-Bus bus. The private bus matters when someone is
also logged in locally: inheriting the console session's `DBUS_SESSION_BUS_ADDRESS`
makes desktop components attach to the console session or abort.

## Usage

```bash
sudo ./ubuntu-rdp.sh                 # Full install + verify (one retained desktop)
sudo ./ubuntu-rdp.sh install          # Install and configure only
sudo ./ubuntu-rdp.sh single-session   # One desktop for the whole server (default)
sudo ./ubuntu-rdp.sh multi-session    # One desktop per user (max 5)
sudo ./ubuntu-rdp.sh verify           # Verify existing setup
./ubuntu-rdp.sh status                # Quick status check (no root needed)
sudo ./ubuntu-rdp.sh uninstall        # Remove xrdp completely
```

## Session policy

`install` and `single-session` configure these keys in `/etc/xrdp/sesman.ini`:

```ini
[Sessions]
MaxSessions=1
Policy=Default
KillDisconnected=true
DisconnectedTimeLimit=300
IdleTimeLimit=0
```

`MaxSessions=1` is one RDP desktop **for the whole server**, including disconnected
desktops. `Policy=Default` matches by user and colour depth, so a reconnect returns to
the same desktop instead of creating a new one; a different user or colour depth cannot
start another desktop while the slot is occupied. `KillDisconnected` frees the slot
again 300 seconds after a client disappears, so a crashed or forgotten client cannot
block the desktop forever — reconnect within those 300 seconds to keep your open
applications.

`multi-session` keeps the same reattach behaviour but allows one desktop per user
(`MaxSessions=5`), for machines where several accounts connect at the same time.

Both modes reload `xrdp-sesman` with `SIGHUP`. The reload applies `sesman.ini` without
restarting the daemon, so connected desktops and their session tracking stay intact.
Changing the desktop limit while desktops are already open does not kill them: save
work and log out of the extra desktops from their own menu. Closing the RDP client only
disconnects and leaves that desktop running until `DisconnectedTimeLimit` expires.

Changed configuration and startup files are backed up beside the original as
`*.backup.YYYYMMDDHHMMSS` (never overwriting an earlier backup).

To undo a policy change, restore the backup to `/etc/xrdp/sesman.ini` (or
`/etc/xrdp/startwm.sh`) and run `sudo systemctl reload xrdp-sesman`.

## What it changes

| Path | Purpose |
|------|---------|
| `/etc/xrdp/sesman.ini` | `[Sessions]` policy: reattach, one desktop, cleanup timeout |
| `/etc/xrdp/startwm.sh` | Session startup: X11 environment, private D-Bus, GNOME or Xfce |
| `/etc/polkit-1/rules.d/02-allow-colord.rules` | Stops colord auth popups on RDP |
| `ufw` rule for 3389/tcp | Only when ufw is active |
| package `xfce4` | Only when the release has no GNOME X11 session |

`startwm.sh` is package-owned. A future `xrdp` upgrade can replace it; rerun
`sudo ./ubuntu-rdp.sh single-session` (or `multi-session`) after an upgrade. The script
does not use `~/.xsession` or `~/.xsessionrc`, so an old GNOME-era override cannot
silently break the session; leave such files alone, they are simply unused.

## Connecting

| Client | Command / App |
|--------|--------------|
| Windows | `mstsc` -> enter `<your-ip>:3389` |
| macOS | Microsoft Remote Desktop |
| Linux | Remmina or `xfreerdp /v:<your-ip> /u:<user>` |

Use your Ubuntu username and password. Select the Xorg session in the xrdp login
window (the default) and keep the colour depth stable — use 32-bit, because
`Policy=Default` also separates sessions by bits per pixel.

## Verify checks

`sudo ./ubuntu-rdp.sh verify` runs and reports every failure instead of stopping at the
first one:

1. **Packages** — `xrdp` and `xorgxrdp` installed
2. **Services** — xrdp and xrdp-sesman running and enabled
3. **Network** — port 3389 listening
4. **Firewall** — 3389 allowed when ufw is active
5. **Permissions** — xrdp user in ssl-cert group
6. **Session policy** — `Policy=Default`, `KillDisconnected` on, a cleanup timeout, and the desktop limit
7. **Session startup** — `/etc/xrdp/startwm.sh` executable and managed, Xfce available when GNOME has no X11 session
8. **Live desktops** — desktop count within the limit, and no X server left behind without a tracked session
9. **Polkit** — colord rules in place
10. **Connection** — TCP handshake to localhost:3389
11. **Logs** — no recent errors in journald (the connection probe's own handshake-failure lines are filtered out)

## Troubleshooting

**Black screen on connect:** the session started but no desktop came up. Check
`~/.xsession-errors` in the account's home and
`journalctl -u xrdp-sesman -b`. On 26.04 confirm Xfce is installed
(`command -v startxfce4`) and that `/etc/xrdp/startwm.sh` is the managed version.

**"Maximum number of sessions reached":** a disconnected desktop still holds the
single slot (a second user, or the 300-second cleanup has not expired). Either wait,
or use `single-session`/`multi-session` deliberately, or log out of the desktop that
is still connected. `./ubuntu-rdp.sh status` shows the live desktop count.

**Several desktops after a few reconnects:** the policy was set with an older script or
edited by hand. Rerun `sudo ./ubuntu-rdp.sh single-session` and check `Policy=Default`
in `/etc/xrdp/sesman.ini`. Existing extra desktops are not killed; save work and log
out of them.

**Authentication popups:** re-run `sudo ./ubuntu-rdp.sh install` to recreate the polkit
rules.

**Can't connect from a remote machine:** check that port 3389 is reachable (firewall,
network). `./ubuntu-rdp.sh status` is a quick check.

## Requirements

- Ubuntu 22.04, 24.04 or 26.04 LTS
- GNOME (22.04/24.04) or Xfce (25.10+) — the script installs `xfce4` when the release
  has no GNOME X11 session
- Root/sudo access

## Offline regression checks

```bash
bash ubuntu-rdp/test-session-policy.sh   # From the repository root; no sudo required
```

Covers both policy modes, duplicate and missing keys or sections, untouched unrelated
sections, permission and backup preservation, idempotent reruns, rejected symlinks,
the generated startup file (valid POSIX sh, private D-Bus, Xfce fallback), the live
desktop counters, and that `verify` counts every failure instead of exiting on the
first. These checks do not replace the interactive disconnect/reconnect test.

Session settings follow the upstream
[xrdp configuration](https://github.com/neutrinolabs/xrdp/blob/devel/sesman/sesman.ini.in).

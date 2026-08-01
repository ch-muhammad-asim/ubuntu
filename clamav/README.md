# ClamAV For Ubuntu

This directory provides a production-oriented ClamAV setup for Ubuntu systems using `apt` and `systemd`.

The maintained installer is:

- `setup-clamav-ubuntu.sh`

It supports desktop Ubuntu and headless Ubuntu hosts. On desktop systems it protects common user folders by default. On headless systems it still installs ClamAV, enables signature updates, configures the daemon, and schedules daily scans; on-access scanning is enabled only when explicit valid watch paths exist.

## What It Installs

- `clamav`
- `clamav-daemon`
- `clamdscan`
- `clamav-freshclam`
- `clamonacc`
- optional `unattended-upgrades`
- daily `systemd` scan timer
- optional on-access scanning with quarantine

## Current Verified Version

Verified on Ubuntu `24.04.4 LTS` on `2026-05-06`:

```text
ClamAV 1.4.4/27992/Tue May  5 11:26:41 2026
Installed: 1.4.4+dfsg-0ubuntu0.24.04.1
Candidate: 1.4.4+dfsg-0ubuntu0.24.04.1
```

Check your host:

```bash
clamscan --version
clamdscan --version
apt-cache policy clamav clamav-daemon clamav-freshclam
```

## Install

From this repository:

```bash
sudo bash clamav/setup-clamav-ubuntu.sh
```

Explicit desktop user:

```bash
sudo bash clamav/setup-clamav-ubuntu.sh --user alice
```

Custom scan/watch paths:

```bash
sudo bash clamav/setup-clamav-ubuntu.sh --scan-path /srv/uploads --scan-path /home/alice/Downloads
```

Override the desktop-friendly automatic worker count on a high-performance workstation:

```bash
sudo bash clamav/setup-clamav-ubuntu.sh --max-threads 24
```

Headless or scan-only install without on-access scanning:

```bash
sudo bash clamav/setup-clamav-ubuntu.sh --skip-on-access
```

Skip unattended APT upgrades:

```bash
sudo bash clamav/setup-clamav-ubuntu.sh --no-unattended-upgrades
```

Show all options:

```bash
bash clamav/setup-clamav-ubuntu.sh --help
```

## Installer Behavior

The installer:

- validates Ubuntu/Debian-like OS, `apt-get`, and running `systemd`
- installs required ClamAV packages
- optionally installs and enables `unattended-upgrades`
- detects the protected desktop user from `SUDO_USER`, or accepts `--user`
- accepts repeated `--scan-path` values for servers or custom workloads
- sizes the `clamd` worker pool for desktop responsiveness by reserving one logical CPU and capping the automatic value at 8 workers, with `--max-threads` available for explicit tuning
- defaults headless scheduled scans to `/home` while leaving on-access scanning disabled unless paths are explicit
- backs up an existing `/etc/clamav/clamd.conf` before replacing it
- configures a group-restricted daemon socket with `LocalSocketMode 660`
- adds the protected user to the `clamav` group when a user is configured
- creates `/etc/clamav/onaccess.watch` from valid scan paths
- enables `clamonacc` only when on-access scanning is requested and watch paths exist
- creates `/usr/local/bin/clamav-daily-scan`
- creates `clamav-daily-scan.service` and `clamav-daily-scan.timer`
- validates `clamscan`, `clamdscan`, active services, and a daemon scan of `/etc/hosts`

The installer intentionally resolves the protected user's home directory through `getent passwd` instead of `$HOME`. Under `sudo`, `$HOME` may be `/root`; using it would silently configure the wrong scan paths. All resolved paths are quoted, so home directories and custom paths containing spaces remain safe.

## Paths

Configuration:

- `/etc/clamav/clamd.conf`
- `/etc/clamav/freshclam.conf`
- `/etc/clamav/onaccess.watch`
- `/etc/clamav/onaccess.exclude`
- `/etc/apt/apt.conf.d/20auto-upgrades`
- `/etc/systemd/system/clamav-daily-scan.service`
- `/etc/systemd/system/clamav-daily-scan.timer`
- `/etc/systemd/system/clamav-clamonacc.service.d/override.conf`
- `/usr/local/bin/clamav-daily-scan`

Runtime and logs:

- signatures: `/var/lib/clamav`
- quarantine: `/var/lib/clamav/quarantine`
- daemon socket: `/var/run/clamav/clamd.ctl`
- daemon log: `/var/log/clamav/clamav.log`
- updater log: `/var/log/clamav/freshclam.log`
- on-access log: `/var/log/clamav/clamonacc.log`
- daily scan log: `/var/log/clamav/daily-scan.log`

## Health Checks

Service state:

```bash
systemctl status clamav-daemon clamav-freshclam clamav-clamonacc clamav-daily-scan.timer --no-pager
systemctl list-timers --all clamav-daily-scan.timer --no-pager
```

Scanner validation:

```bash
clamdscan --fdpass /etc/hosts
```

Expected result:

```text
/etc/hosts: OK
```

Recent logs:

```bash
tail -n 80 /var/log/clamav/daily-scan.log
sudo tail -n 80 /var/log/clamav/freshclam.log
sudo tail -n 80 /var/log/clamav/clamav.log
sudo tail -n 80 /var/log/clamav/clamonacc.log
```

## Updates And Upgrades

There are two separate update paths:

- Signature updates are handled by `clamav-freshclam.service`.
- Engine/package upgrades are handled by Ubuntu APT.

The installer enables this APT periodic configuration unless `--no-unattended-upgrades` is used:

```text
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
```

Manual package upgrade:

```bash
sudo apt update
apt-cache policy clamav clamav-daemon clamav-freshclam
sudo apt install --only-upgrade clamav clamav-daemon clamav-freshclam
sudo systemctl restart clamav-daemon clamav-freshclam clamav-clamonacc
```

Check automatic upgrade status:

```bash
systemctl status unattended-upgrades --no-pager
cat /etc/apt/apt.conf.d/20auto-upgrades
grep -E 'Allowed-Origins|security|updates' /etc/apt/apt.conf.d/50unattended-upgrades
```

For conservative desktops, keep automatic package upgrades limited to Ubuntu security updates. For systems where faster ClamAV engine updates matter more than change control, allow the Ubuntu updates pocket in `/etc/apt/apt.conf.d/50unattended-upgrades`.

## Daily Scan

The timer runs:

- daily at `02:00`
- with up to `15 minutes` randomized delay
- with `Persistent=true`, so missed runs can run after boot

Commands:

```bash
systemctl cat clamav-daily-scan.timer
systemctl list-timers --all clamav-daily-scan.timer --no-pager
sudo systemctl start clamav-daily-scan.service
systemctl status clamav-daily-scan.service --no-pager
tail -n 80 /var/log/clamav/daily-scan.log
```

The daily scan submits configured directories once with `clamdscan --multiscan --fdpass`. This lets `clamdscan` keep the daemon's worker pool busy while retaining descriptor-based access to protected user files, avoiding a process and socket round trip for every small batch. `CrossFilesystems false` keeps recursive scans on the configured filesystems.

## On-Access Scanning

On-access scanning uses `clamonacc`.

Default desktop paths:

- `~/Downloads`
- `~/Desktop`
- `~/Documents`
- `~/Public`

Detected files are moved to:

- `/var/lib/clamav/quarantine`

On-access scanning is disabled automatically when:

- `--skip-on-access` is used
- no valid scan/watch paths exist

To change watched paths:

```bash
sudoedit /etc/clamav/onaccess.watch
sudo systemctl restart clamav-clamonacc
```

## EICAR Test

Create the safe test file:

```bash
cat > ~/eicar.com.txt <<'EOF'
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
EOF
```

Manual scan:

```bash
clamscan ~/eicar.com.txt
clamdscan --fdpass ~/eicar.com.txt
```

On-access test:

```bash
cp ~/eicar.com.txt ~/Downloads/eicar.com.txt
sudo tail -n 40 /var/log/clamav/clamonacc.log
```

Expected result:

- manual scans report `Eicar-Signature FOUND`
- on-access scanning moves the file to `/var/lib/clamav/quarantine`

Clean up:

```bash
rm -f ~/eicar.com.txt ~/Downloads/eicar.com.txt
sudo rm -f /var/lib/clamav/quarantine/eicar.com.txt
```

## Troubleshooting

- If `clamdscan` reports socket permission errors for a normal user, log out and back in so the new `clamav` group membership applies.
- If `clamav-daemon` does not start immediately after a fresh install, check whether `freshclam` has finished downloading `main` and `daily` databases.
- If `clamonacc` uses too many resources, reduce paths in `/etc/clamav/onaccess.watch`.
- If a development tree is large, prefer scheduled scans over on-access monitoring for that tree.
- If logs are unreadable as a normal user, use `sudo`; ClamAV logs are commonly protected.

## Development Checks

Run the portable regression suite before publishing installer changes:

```bash
bash clamav/tests/test-installer.sh
shellcheck clamav/setup-clamav-ubuntu.sh clamav/tests/test-installer.sh
```

When ClamAV is installed locally, the suite also validates the generated `clamd.conf` with the packaged ClamAV parser.

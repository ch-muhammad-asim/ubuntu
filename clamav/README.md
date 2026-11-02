# ClamAV For Ubuntu

This directory provides a production-oriented ClamAV setup for Ubuntu systems using `apt` and `systemd`.

The maintained installer is `setup-clamav-ubuntu.sh`. It installs, configures, repairs and verifies ClamAV in one idempotent run: running it again changes only what differs, re-applies owner and mode of every managed file, backs up every config file it replaces (`<file>.<timestamp>.bak`, same folder; the `.bak` suffix is ignored by APT, systemd and sysctl) and ends with a verification report.

It supports desktop Ubuntu and headless Ubuntu hosts. On desktops it protects the common user folders of one or more users on access and scans their whole homes daily. On headless hosts it still installs ClamAV, keeps signatures updated and schedules daily scans; on-access scanning is enabled only when explicit watch paths exist.

## Components, one line each

| Component | What it does |
|---|---|
| `clamd` (`clamav-daemon`) | Scanning engine with the signatures loaded in memory; listens only on the Unix socket `/run/clamav/clamd.ctl` (mode 660, group `clamav`). |
| `freshclam` (`clamav-freshclam`) | Downloads signature updates 24 times a day and tells `clamd` to reload; a drop-in waits for DNS after boot. |
| `clamonacc` (`clamav-clamonacc`) | On-access scanner: watches the configured folders with fanotify and moves detected files to the quarantine. |
| `clamdscan` | Client that sends files to `clamd`; used by the daily scan and for manual scans. |
| `clamav-daily-scan.timer` / `.service` | Runs `/usr/local/bin/clamav-daily-scan` every night at 02:00 (±15 min, catches up after boot). |
| Quarantine | `/var/lib/clamav/quarantine` (`750 root:clamav`), where on-access detections are moved. |
| `clamav-logrotate.timer` / `.service` | Rotates `clamonacc.log` and `daily-scan.log` with `/etc/clamav/logrotate.conf`, checked hourly, so a log is rotated within about an hour of passing 50 MB (daily or at 50 MB, 14 kept, compressed, `copytruncate`, files stay `640 root:adm`). |
| `unattended-upgrades` (optional) | Installs Ubuntu security updates, including ClamAV engine updates. |

## Install or repair

```bash
sudo bash clamav/setup-clamav-ubuntu.sh                              # the invoking user
sudo bash clamav/setup-clamav-ubuntu.sh --user alice --user bob      # several users
sudo bash clamav/setup-clamav-ubuntu.sh --verify                     # no config changes; still runs self-tests and a scan
sudo bash clamav/setup-clamav-ubuntu.sh --skip-full-scan             # skip the real scan at the end
bash clamav/setup-clamav-ubuntu.sh --help                            # all options
```

Other options: `--scan-path PATH` and `--watch-path PATH` (repeatable, replace the defaults; without `--watch-path`, scan paths are also watched), `--no-tmp-watch`, `--prevention`, `--max-threads N`, `--skip-on-access`, `--no-unattended-upgrades`, `--report FILE`.

## What it protects by default

| Scope | Paths |
|---|---|
| On access (`clamonacc`) | `~/Desktop`, `~/Downloads`, `~/Documents` (always; created if missing) and `~/Public` of every `--user`, and `/tmp` |
| Daily scan (`clamdscan --multiscan --fdpass`) | The whole home of every `--user` |

**Exclusions** (`ExcludePath` in `clamd.conf`, applied by the daily scan), each with its reason:

| Excluded | Why |
|---|---|
| `^/(proc|sys|dev)/` | Pseudo filesystems, nothing to scan. |
| `/node_modules/` | Registry packages with very many small files; check the supply chain with `npm audit`. |
| `/.cache/` | Regenerable caches (pip, npm, browsers); real downloads land in `~/Downloads`, which is watched and scanned. |
| `/.git/objects/` | Packed history; the checked-out working tree is scanned. |
| `/.local/share/containers/`, `/var/lib/docker/` | Container image layers; scan images with an image scanner instead. |

**Prevention mode is off by default.** `OnAccessPrevention` is a single global switch for all watched paths: with it on, every open in `~/Desktop` or `~/Documents` waits for a scan, which slows git, builds and IDEs. Detected files are still logged and moved to the quarantine. Use `--prevention` on hosts where blocking is worth the delay.

**PUA detection is off** (`DetectPUA false`): admin and security tools cause many false positives on desktops.

## Configuration choices

- `HeuristicAlerts`, `AlertBrokenExecutables`: heuristic and malformed-executable detections are reported.
- Current option names only (`HeuristicAlerts`, `AlertEncryptedArchive`, `AlertOLE2Macros`, `AlertPhishing*`, `AlertPartitionIntersection`); `clamconf` reports no deprecated options.
- Scan limits: `MaxFileSize 25M`, `MaxScanSize 100M`, `StreamMaxLength 25M`, `MaxScanTime 120000` ms.
- `OnAccessExtraScanning true`: files are also scanned when they are closed after writing or moved into a watched folder, so a finished download is checked right away.
- `TemporaryDirectory /var/lib/clamav/tmp`: not `/tmp`, because `/tmp` is watched on access and `clamonacc` must not watch `clamd`'s own temporary directory.
- `OnAccessDenyOnError false`: if `clamd` fails, access is not blocked (fail open); the failure is logged.
- `clamonacc` runs with `UMask=0027`, so its log is created `640`.
- `OnAccessExcludeUname clamav` and `OnAccessExcludeRootUID true`: `clamd` and root-owned system processes (package manager, backups, the daily scan) do not trigger on-access scans, which avoids scan loops; files written or opened by users are scanned.
- Logging: `LogFile /var/log/clamav/clamav.log`, `LogTime true`; `LogRotate false` and `LogFileMaxSize 0` because logrotate is the single owner of rotation. No ClamAV log is world-readable.
- The daily-scan unit keeps `NoNewPrivileges`, `LockPersonality`, `RestrictRealtime`, `RestrictSUIDSGID`, `RestrictNamespaces`, `SystemCallArchitectures=native` and `MemoryDenyWriteExecute`, but **no mount-namespace options** (`PrivateTmp`, `ProtectSystem`, `ProtectHome`, `ProtectKernel*`, `ProtectControlGroups`). `clamdscan --fdpass` hands file descriptors to the AppArmor-confined `clamd`; descriptors opened inside a private mount namespace arrive as disconnected paths that AppArmor denies, and every file fails with `Not a regular file`.

## Paths

| Kind | Path |
|---|---|
| Daemon config | `/etc/clamav/clamd.conf` |
| Updater config | `/etc/clamav/freshclam.conf` (package default), drop-in `/etc/systemd/system/clamav-freshclam.service.d/wait-dns.conf` |
| On-access lists | `/etc/clamav/onaccess.watch`, `/etc/clamav/onaccess.exclude`, override `/etc/systemd/system/clamav-clamonacc.service.d/override.conf` |
| Daily scan | `/usr/local/bin/clamav-daily-scan`, `/etc/systemd/system/clamav-daily-scan.{service,timer}` |
| Log rotation | `/etc/clamav/logrotate.conf` with `clamav-logrotate.{service,timer}` (hourly), plus the packaged `clamav-daemon` and `clamav-freshclam` rules |
| Signatures | `/var/lib/clamav` |
| Logs | `/var/log/clamav/{clamav,freshclam,clamonacc,daily-scan}.log` |
| APT periodic | `/etc/apt/apt.conf.d/20auto-upgrades` |

## Verification report

Every run ends with checks written to `~SUDO_USER/clamav-report-<timestamp>.txt` (mode 600). The report holds only status fields and counters, never log lines or file names; raw diagnostics with paths stay root-only in `/var/log/clamav/setup-diagnostics-<timestamp>.log` (`600 root:root`). It contains:

- diagnostics from before the change: the number of AppArmor denials for `clamd`, the last daily-scan summary, `clamonacc.log` size and message counters by type, and the signature age;
- PASS/FAIL for services, the socket, no TCP listener, signature age (< 24 h), `clamconf` (fails on errors or a non-zero exit), EICAR through `clamdscan`, coverage of `~/Desktop`, `~/Downloads` and `~/Documents` for every user (watched on access and inside a daily-scan path), on-access EICAR in each of those three folders of every user and in `/tmp` (quarantined and logged, then removed), a real daily-scan run (it passes only with a complete summary, 0 errors and files in scope), no AppArmor denials (fails if the kernel journal cannot be read), the hourly rotation timer and a `logrotate -d` dry run, log and quarantine permissions, the number of watched and scanned paths, and resource use.

Each on-access EICAR test runs in a fresh private directory that the protected user creates inside the watched folder (`mktemp -d`, mode 700); the installer verifies it (real directory, owned by that user, mode 700, directly inside the folder). EICAR is written into a new file inside it in one exclusive open (`set -C`, i.e. `O_EXCL`). Cleanup (after each test and on `EXIT`/`INT`/`TERM`) never deletes recursively: it runs as that user, removes only the exact EICAR file name with `rm -f --` and then `rmdir`s the private directory, which fails safely if it was replaced or holds anything else. The quarantine copy is removed by its exact path only if its owner and inode (or exact EICAR content) match.

`--verify` makes no configuration changes, but it still writes the report and diagnostics, runs the EICAR self-tests and, unless `--skip-full-scan` is given, a real daily scan.

The hourly rotation timer (`clamav-logrotate.timer`) is held for the whole apply run: its state is recorded, it is masked at runtime and stopped before any log handling, whatever the log sizes, and it stays held until verification is finished; then it is unmasked, enabled and started. If the run exits early (error, `INT`, `TERM`), the `EXIT` trap restores exactly the recorded state (unmask, and start it if it was active); a failed restore is printed and makes the exit status non-zero. Logs above 100 MB are rotated once with `logrotate -f` on `/etc/clamav/logrotate.conf` (a full copy is kept as `<log>.1`, `copytruncate`); there is no manual truncation. This is fail-closed: every writer unit (`clamonacc`, the daily scan, the rotation timer and service) must be stopped and confirmed inactive, the timer hold must have succeeded, and no process may have a log open (checked through `/proc`). Any systemd query, mask or stop error, or an open writer, means no rotation at all, and the report shows `log preservation: SKIPPED`.

If the file count of a scan or the watched-directory count cannot traverse every folder, it is marked incomplete (`traversal=incomplete`, a WARN in the report) instead of being shown as exact.

The script exits non-zero if any check fails.

## Health checks

```bash
systemctl status clamav-daemon clamav-freshclam clamav-clamonacc clamav-daily-scan.timer --no-pager
systemctl list-timers --all clamav-daily-scan.timer --no-pager
clamdscan --fdpass /etc/hosts                     # expected: /etc/hosts: OK
sudo tail -n 40 /var/log/clamav/daily-scan.log
sudo tail -n 40 /var/log/clamav/clamonacc.log
sudo tail -n 20 /var/log/clamav/freshclam.log
sudo journalctl -k | grep 'apparmor="DENIED".*clamd'   # expected: no output
```

## Updates and upgrades

- Signatures: `clamav-freshclam.service`.
- Engine and packages: Ubuntu APT; the installer enables `APT::Periodic::Unattended-Upgrade "1"` unless `--no-unattended-upgrades` is used.

```bash
sudo apt update && sudo apt install --only-upgrade clamav clamav-daemon clamav-freshclam
sudo systemctl restart clamav-daemon clamav-freshclam clamav-clamonacc
```

## EICAR test (manual)

```bash
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/eicar.txt
clamdscan --fdpass ~/eicar.txt                    # Eicar-Test-Signature FOUND
cp ~/eicar.txt ~/Downloads/ && cat ~/Downloads/eicar.txt >/dev/null   # on access: moved to the quarantine within seconds
sudo grep eicar /var/log/clamav/clamonacc.log | tail -n 2
sudo rm -f /var/lib/clamav/quarantine/eicar.txt ~/eicar.txt ~/Downloads/eicar.txt
```

## Troubleshooting

- `clamdscan` socket permission errors as a normal user: log out and back in so the `clamav` group membership applies.
- Daily scan fails with thousands of `Not a regular file` errors: the unit runs in a private mount namespace; re-run the installer (it removes those options).
- `clamonacc` uses too many resources: reduce `/etc/clamav/onaccess.watch` or use `--no-tmp-watch`; large development trees are better covered by the daily scan.
- `clamav-daemon` not starting right after a fresh install: `freshclam` may still be downloading `main` and `daily`.

## Development checks

```bash
bash clamav/tests/test-installer.sh
shellcheck clamav/setup-clamav-ubuntu.sh clamav/tests/test-installer.sh
```

When ClamAV is installed locally, the suite also validates the generated `clamd.conf` with the packaged ClamAV parser.

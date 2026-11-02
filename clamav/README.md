# ClamAV For Ubuntu

This directory provides a production-oriented ClamAV setup for Ubuntu systems using `apt` and `systemd`.

The maintained installer is `setup-clamav-ubuntu.sh`. It installs, configures, repairs and verifies ClamAV in one idempotent run: running it again changes only what differs, re-applies owner and mode of every managed file, backs up every config file it replaces (`<file>.<timestamp>.bak`, same folder; the `.bak` suffix is ignored by APT, systemd and sysctl) and ends with a verification report.

It supports desktop Ubuntu and headless Ubuntu hosts. On desktops it protects the common user folders of one or more users on access and scans their whole homes daily. On headless hosts it still installs ClamAV, keeps signatures updated and schedules daily scans; on-access scanning is enabled only when explicit watch paths exist.

## Components, one line each

| Component | What it does |
|---|---|
| `clamd` (`clamav-daemon`) | Scanning engine with the signatures loaded in memory; listens only on the Unix socket `/run/clamav/clamd.ctl` (mode 660, group `clamav`). A drop-in moves it into `clamav.slice` (`CPUWeight=20`). |
| `freshclam` (`clamav-freshclam`) | Downloads signature updates 12 times a day (`Checks 12`, also set in debconf so package upgrades keep it) and tells `clamd` to reload; a drop-in waits for DNS after boot. |
| `clamonacc` (`clamav-clamonacc`) | On-access scanner: watches the configured folders with fanotify and moves detected files to the quarantine. |
| `clamdscan` | Client that passes file descriptors to `clamd`; used by the daily scan and for manual scans. |
| `clamav-daily-scan.timer` / `.service` | Runs `/usr/local/bin/clamav-daily-scan` every night at 02:00 (±15 min, catches up after boot), in `clamav.slice` at `Nice=10`: lists regular files with `find` (byte-exact, NUL-delimited, `ExcludePath` applied), passes them with `xargs -0` in batches to one `clamdscan --fdpass` client per `MaxThreads`; each batch writes its own output and status, appended to the log when the batch ends (or when the scan is stopped); sockets, FIFOs and devices are counted as skipped. |
| False-positive allowlist | `/var/lib/clamav/local.sfp`: exact SHA-256 hashes of verified official files that a heuristic flags (provenance in the installer); everything else, and that heuristic, stays active. |
| Quarantine | `/var/lib/clamav/quarantine` (`750 root:clamav`), where on-access detections are moved. |
| `clamav-logrotate.timer` / `.service` | Rotates `clamonacc.log` and `daily-scan.log` with `/etc/clamav/logrotate.conf` while holding the daily scan's log lock (`/run/clamav-daily-scan.lock`, so `copytruncate` never cuts an append; the scan's totals come from its own batch records, not from the log), checked hourly, so a log is rotated within about an hour of passing 50 MB (daily or at 50 MB, 14 kept, compressed, `copytruncate`, files stay `640 root:adm`). |
| `unattended-upgrades` (optional) | Installs Ubuntu security updates, including ClamAV engine updates. |

## Install or repair

```bash
sudo bash clamav/setup-clamav-ubuntu.sh                              # only the invoking (sudo) user
sudo bash clamav/setup-clamav-ubuntu.sh --user alice --user bob      # several users; name all of them on every run
sudo bash clamav/setup-clamav-ubuntu.sh --verify                     # no config changes; still runs self-tests and a scan
sudo bash clamav/setup-clamav-ubuntu.sh --skip-full-scan             # skip the real scan at the end
bash clamav/setup-clamav-ubuntu.sh --help                            # all options
```

Other options: `--scan-path PATH` and `--watch-path PATH` (repeatable, replace the defaults; without `--watch-path`, scan paths are also watched), `--no-tmp-watch`, `--prevention`, `--max-threads N`, `--exclude-dev-caches`, `--low-memory`, `--skip-on-access`, `--no-unattended-upgrades`, `--report FILE`.

## What it protects by default

| Scope | Paths |
|---|---|
| On access (`clamonacc`) | `~/Desktop`, `~/Downloads`, `~/Documents` (always; created if missing) and `~/Public` of every `--user`, and `/tmp` |
| Daily scan (`clamdscan --fdpass`, files as arguments) | Every regular file in the home of every `--user` |

**Daily-scan exclusions** (`ExcludePath` in `clamd.conf`). Every directory rule ends in `(/|$)`, so it matches the directory itself and its contents but not a sibling that only shares the prefix (`/run` is excluded, `/runner` is not). Rules inside a home are anchored to each protected user's home (`^/home/alice/...`), so the same folder name somewhere else, for example under `~/Downloads`, is still scanned. Toolchains, Flatpak runtimes, Maven/Gradle repositories and other executable content are scanned.

| Excluded | Why |
|---|---|
| `^/(proc|sys|dev|run)(/|$)` | Pseudo and runtime filesystems; nothing to scan. |
| `^/var/lib/docker(/|$)`, `^<home>/\.local/share/containers(/|$)` | Container image layers; scan images with an image scanner instead. |
| `/node_modules(/|$)` | Registry packages with very many small files; check the supply chain with `npm audit`. |
| `/\.git/objects(/|$)` | zlib-packed history; the checked-out working tree is scanned. |
| `^<home>/\.cache/(thumbnails|fontconfig|mesa_shader_cache)(/|$)` | Generated images, font and shader caches; no downloaded content. The rest of `~/.cache` (pip wheels, browser caches) is scanned. |

With `--exclude-dev-caches` (opt-in) these download caches are excluded as well: `^<home>/\.cache(/|$)`, `^<home>/\.npm/_cacache(/|$)`, `^<home>/\.cargo/registry/cache(/|$)`, `^<home>/go/pkg/mod/cache/download(/|$)`. The daily scan reads the deployed `ExcludePath` rules from `clamd.conf` when it builds its file list, so it always follows the policy in force. Special files (sockets, FIFOs, block and character devices) are skipped by type, never by path, and reported as a count; symbolic links are not followed.

**On-access exclusions are a separate policy.** `ExcludePath` does not filter `clamonacc`. `clamonacc --exclude-list=/etc/clamav/onaccess.exclude` takes explicit directory paths, one per line, not regular expressions. The installer creates that file empty and never changes an existing one, so add each on-access exclusion there deliberately (and restart `clamav-clamonacc`). `OnAccessExcludePath` (regex) is not used.

**Prevention mode is off by default.** `OnAccessPrevention` is a single global switch for all watched paths: with it on, every open in `~/Desktop` or `~/Documents` waits for a scan, which slows git, builds and IDEs. Detected files are still logged and moved to the quarantine. Use `--prevention` on hosts where blocking is worth the delay.

**PUA detection is off** (`DetectPUA false`): admin and security tools cause many false positives on desktops.

## Configuration choices

- `HeuristicAlerts`, `AlertBrokenExecutables`: heuristic and malformed-executable detections are reported.
- False positives are allowlisted only by exact file hash in `local.sfp` (`sha256:size:name`); signature names are never ignored. It holds the official VS Code Marketplace packages `ms-python.python` 2026.4.0 and `ms-python.vscode-python-envs` 1.36.0 (linux-x64), whose bundled 34–35 MB `pet` binary is above `MaxFileSize` and is reported as `Heuristics.Broken.Executable`.
- Current option names only (`HeuristicAlerts`, `AlertEncryptedArchive`, `AlertOLE2Macros`, `AlertPhishing*`, `AlertPartitionIntersection`); `clamconf` reports no deprecated options.
- Scan limits: `MaxFileSize 25M`, `MaxScanSize 100M`, `StreamMaxLength 25M`, `MaxScanTime 120000` ms, `MaxRecursion 16`, `MaxFiles 10000`, `MaxDirectoryRecursion 15`.
- Workers: `MaxThreads` defaults to half the CPUs rounded down, at least 1 and at most 4 (1 CPU: 1, 2–3: 1, 4–5: 2, 8 or more: 4); `--max-threads` overrides it. `OnAccessMaxThreads` is half of `MaxThreads` rounded up, at most 4. The daily scan runs one `clamdscan` worker per `MaxThreads` (each sends one file at a time), so its concurrency matches `clamd`'s.
- CPU sharing: the daily-scan unit's `Nice` only lowers the `clamdscan` client; the scanning work runs inside `clamd`. `clamav-daemon.service.d/desktop-limits.conf` therefore moves `clamd` into `clamav.slice`, a top-level slice with `CPUWeight=20` (the daily scan runs there too). Under contention it gets 20 shares against 100 each for `user.slice` and `system.slice`; on an idle machine it may use every CPU. It is a weight, not a hard quota, so on-access scans are never capped while the machine is idle. A weight on the service itself would only compete with other services inside `system.slice`, not with the desktop session.
- `ConcurrentDatabaseReload yes` (default): new signatures load next to the old set, so scanning never pauses during a reload; peak memory is about twice the signature set while it runs. `--low-memory` sets `no` for hosts short of RAM: about half the peak memory, but scans and on-access checks wait until the reload finishes (not benchmarked here; measure on the host before using it with `--prevention`).
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
| Daemon config | `/etc/clamav/clamd.conf`, drop-in `/etc/systemd/system/clamav-daemon.service.d/desktop-limits.conf`, slice `/etc/systemd/system/clamav.slice` |
| Updater config | `/etc/clamav/freshclam.conf` (package default except one `Checks 12`; other `Checks` lines, tab-separated or duplicated, are folded into it), drop-in `/etc/systemd/system/clamav-freshclam.service.d/wait-dns.conf` |
| On-access lists | `/etc/clamav/onaccess.watch`, `/etc/clamav/onaccess.exclude`, override `/etc/systemd/system/clamav-clamonacc.service.d/override.conf` |
| Daily scan | `/usr/local/bin/clamav-daily-scan`, `/etc/systemd/system/clamav-daily-scan.{service,timer}` |
| Log rotation | `/etc/clamav/logrotate.conf` with `clamav-logrotate.{service,timer}` (hourly), plus the packaged `clamav-daemon` and `clamav-freshclam` rules |
| Signatures | `/var/lib/clamav`, local allowlist `/var/lib/clamav/local.sfp` |
| Logs | `/var/log/clamav/{clamav,freshclam,clamonacc,daily-scan}.log` |
| APT periodic | `/etc/apt/apt.conf.d/20auto-upgrades` |

## Verification report

Every run ends with checks written to `~SUDO_USER/clamav-report-<timestamp>.txt` (mode 600). The report holds only status fields and counters, never log lines or file names; raw diagnostics with paths stay root-only in `/var/log/clamav/setup-diagnostics-<timestamp>.log` (`600 root:root`). It contains:

- diagnostics from before the change: the number of AppArmor denials for `clamd`, the last daily-scan summary, `clamonacc.log` size and message counters by type, and the signature age;
- PASS/FAIL for services, the socket, no TCP listener, signature age (< 24 h), effective tuning (`clamav-daemon` really in `clamav.slice` with `CPUWeight=20` and no pending daemon-reload; `MaxThreads`, `ConcurrentDatabaseReload` and `Checks` as parsed by `clamconf`; `clamd` and `freshclam` started after their config last changed), `clamconf` (fails on errors or a non-zero exit), EICAR through `clamdscan`, coverage of `~/Desktop`, `~/Downloads` and `~/Documents` for every user (watched on access and inside a daily-scan path), on-access EICAR in each of those three folders of every user and in `/tmp` (quarantined and logged, then removed), a real daily-scan run (it passes only with a complete summary, 0 errors and files in scope), no AppArmor denials (fails if the kernel journal cannot be read), the hourly rotation timer and a `logrotate -d` dry run, log and quarantine permissions, the number of watched and scanned paths, and resource use.

Each on-access EICAR test runs in a fresh private directory that the protected user creates inside the watched folder (`mktemp -d`, mode 700); the installer verifies it (real directory, owned by that user, mode 700, directly inside the folder). EICAR is written into a new file inside it in one exclusive open (`set -C`, i.e. `O_EXCL`). Cleanup (after each test and on `EXIT`/`INT`/`TERM`) never deletes recursively: it runs as that user, removes only the exact EICAR file name with `rm -f --` and then `rmdir`s the private directory, which fails safely if it was replaced or holds anything else. The quarantine copy is removed by its exact path only if its owner and inode (or exact EICAR content) match.

`--verify` makes no configuration changes, but it still writes the report and diagnostics, runs the EICAR self-tests and, unless `--skip-full-scan` is given, a real daily scan.

The hourly rotation timer (`clamav-logrotate.timer`) is held for the whole apply run: its state is recorded, it is masked at runtime and stopped before any log handling, whatever the log sizes, and it stays held until verification is finished; then it is unmasked, enabled and started. If the run exits early (error, `INT`, `TERM`), the `EXIT` trap restores exactly the recorded state (unmask, and start it if it was active); a failed restore is printed and makes the exit status non-zero. Logs above 100 MB are rotated once with `logrotate -f` on `/etc/clamav/logrotate.conf` (a full copy is kept as `<log>.1`, `copytruncate`); there is no manual truncation. This is fail-closed: every writer unit (`clamonacc`, the daily scan, the rotation timer and service) must be stopped and confirmed inactive, the timer hold must have succeeded, and no process may have a log open (checked through `/proc`). Any systemd query, mask or stop error, or an open writer, means no rotation at all, and the report shows `log preservation: SKIPPED`.

The daily-scan summary reports files scanned out of files listed, infected files, errors, failed batches, files that vanished between listing and scanning (not errors) and special files skipped, and ends with one result line. The scan exits 2 and its result reads `Scan incomplete: ...` when the traversal could not read every folder, any batch failed or was not run (detections from the other batches are still reported), or it was stopped (SIGTERM, for example the unit's 6 h timeout; detections found until then stay in the log); it reads `Scan aborted: ...` when the file list could not be prepared, and then nothing is scanned. The installer's verification fails in all these cases (`daily scan run`, and `daily scan coverage` for an incomplete traversal). The watched-directory count is marked incomplete (`traversal=incomplete`) when it cannot traverse every folder.

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

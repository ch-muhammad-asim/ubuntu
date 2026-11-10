# Ubuntu Security Setup

This repository contains practical Ubuntu-focused security setup material, starting with a ClamAV configuration that is usable on a fresh machine and easy to publish or reuse.

## Contents

- `clamav/README.md`
  Public guide for installing, configuring, and verifying ClamAV on Ubuntu
- `clamav/setup-clamav-ubuntu.sh`
  Standalone installer script for setting up the ClamAV configuration described in the guide
- `ubuntu-rdp/README.md`
  Public guide for installing, configuring, and verifying xrdp on Ubuntu (22.04, 24.04, 26.04)
- `ubuntu-rdp/ubuntu-rdp.sh`
  Standalone installer/repair script: one retained RDP desktop, reattach on reconnect, Xfce fallback where GNOME has no X11 session

## ClamAV

The ClamAV setup in this repository provides:

- automatic signature updates
- unattended Ubuntu security upgrades for ClamAV package updates
- a running `clamd` daemon for faster scans
- a daily scheduled scan of each protected user's home through `systemd`
- on-access scanning for the common folders of one or more users, plus `/tmp`
- quarantine-on-detection
- log rotation for every ClamAV log, none world-readable
- an idempotent installer that repairs drift and writes a verification report (`--verify` to only check), including EICAR tests

## Quick Start

Read the guide:

```bash
less clamav/README.md
```

Run the installer:

```bash
sudo bash clamav/setup-clamav-ubuntu.sh
```

Without `--user` it protects only the user who runs `sudo`. To protect several users, name each one, every time you run it (a run replaces the watched and scanned paths):

```bash
sudo bash clamav/setup-clamav-ubuntu.sh --user alice --user bob
```

## Suggested Repo Direction

This layout is intentionally simple:

- `clamav/`
  ClamAV-specific documentation and scripts

If you expand this repository later, a clean structure would be:

- `clamav/`
- `firewall/`
- `audit/`
- `hardening/`

## Status

Current focus:

- Ubuntu ClamAV setup and automation

Good next additions for the same repository:

- `ufw` baseline rules
- `fail2ban` setup
- log monitoring notes
- unattended upgrade alerting and reboot policy

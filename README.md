# security-hardening-checker

Read-only security audits for **Windows** (PowerShell) and **Linux** (bash).
Each check prints `PASS`, `WARN`, `FAIL` or `INFO`, followed by a summary score
and an exit code you can use in scripts or CI. **The scripts never change a
setting** - they only read configuration, the registry and command output.

| Script | Platform |
|--------|----------|
| `check-windows.ps1` | Windows 10/11, Server 2016+ (Windows PowerShell 5.1 or PowerShell 7+) |
| `check-linux.sh` | Debian/Ubuntu, RHEL/Fedora family and most other distros (bash 4+) |

## What is checked

### Windows (`check-windows.ps1`)

| Area | Check |
|------|-------|
| Firewall | Domain / Private / Public profiles enabled (`Get-NetFirewallProfile`, `netsh` fallback) |
| Defender | Antivirus + real-time protection on, signature age <= 7 days |
| UAC | `EnableLUA`, admin consent prompt, secure desktop |
| SMBv1 | SMB1 server protocol and SMB1 client driver disabled |
| Remote Desktop | RDP off, or on **with** Network Level Authentication |
| Accounts | Built-in Guest (SID -501) disabled; built-in Administrator (SID -500) status |
| Password policy | `net accounts`: minimum length (12+ PASS, 8-11 WARN), lockout threshold (1-10) |
| Windows Update | `wuauserv` not disabled; `NoAutoUpdate` policy not set |
| Risky services | Telnet, FTP, Remote Registry, SNMP, UPnP host (and INFO for SSDP / IIS) |
| BitLocker | System drive protection status (needs elevation) |

### Linux (`check-linux.sh`)

| Area | Check |
|------|-------|
| SSH | `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, `Protocol`, `Port`, `X11Forwarding`, `MaxAuthTries` (uses `sshd -T` when root, otherwise parses the config files in sshd's order and ignores `Match` blocks) |
| Firewall | UFW / firewalld / nftables service active, or nft / iptables input rules (root) |
| Permissions | `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`, `sshd_config`; `/tmp` sticky bit; world-writable files in system directories |
| SUID/SGID | Count of SUID/SGID files, and a WARN for any not on a list of common programs |
| Accounts | Only `root` has UID 0; no empty passwords (root); `PASS_MAX_DAYS` |
| Updates | `unattended-upgrades` installed and enabled (Debian/Ubuntu) or `dnf-automatic` timer (RHEL/Fedora) |
| Ports | Services listening on all interfaces (`ss`), WARN for commonly attacked ones (Telnet, SMB, databases, Redis, Docker API 2375, VNC...) |

### Scoring and exit codes

- Score = average of scored checks, with PASS = 100, WARN = 50, FAIL = 0. INFO lines are not scored.
- Exit code: `0` all PASS, `1` warnings only, `2` at least one FAIL, `3` usage error / wrong OS.

The score is a quick indicator for comparing a machine with itself over time,
not a compliance certification (for that, see the CIS Benchmarks).

## Requirements

- **Windows:** Windows PowerShell 5.1 or PowerShell 7+. Built-in modules only.
  Run **as Administrator** for the full audit (Defender, SMB, BitLocker).
- **Linux:** bash 4+, coreutils, findutils, awk. Optional: `ss`, `sshd`,
  `ufw`/`firewalld`/`nft`, `systemctl`, `dpkg`/`rpm`. Run with **sudo** for
  `/etc/shadow`, `sshd -T` and firewall rules.

## Usage

### Windows

```powershell
Get-Help .\check-windows.ps1 -Full

# Elevated PowerShell
.\check-windows.ps1
.\check-windows.ps1 -Quiet -ReportPath .\hardening.json     # JSON report
.\check-windows.ps1 -ReportPath .\hardening.txt             # text report
powershell -ExecutionPolicy Bypass -File .\check-windows.ps1
```

### Linux

```bash
chmod +x check-linux.sh
./check-linux.sh -h

sudo ./check-linux.sh                       # full audit
./check-linux.sh -q                         # only WARN/FAIL + summary
sudo ./check-linux.sh -o report.txt -n      # plain-text report file
./check-linux.sh -c /path/to/sshd_config    # audit another SSH config
```

## Example output

Real run of `check-linux.sh` on a Debian 13 test VM (not root), auditing the
deliberately weak SSH config in `tests/fixtures/` with `-q` (WARN/FAIL only).
The hostname is shortened to `test-vm`:

```
$ ./check-linux.sh -n -q -c tests/fixtures/sshd_config.insecure
Linux hardening audit - test-vm - 2026-11-14 13:55:13 +0100
Kernel: 6.12.113+   Running as: box (not root: some checks are limited)
[FAIL] SSH        PermitRootLogin yes - root can log in with a password
[WARN] SSH        PasswordAuthentication yes - exposed to password guessing; prefer keys
[FAIL] SSH        PermitEmptyPasswords yes
[FAIL] SSH        Protocol 2,1 - SSH protocol 1 is broken
[WARN] SSH        X11Forwarding yes - disable unless needed
[WARN] SSH        MaxAuthTries 10 - 3 or 4 is recommended
[WARN] Firewall   No active firewall service detected (run as root to inspect nft/iptables rules)
[WARN] Updates    unattended-upgrades is not installed
[WARN] Ports      tcp/2375 listens on ALL interfaces (commonly attacked service)

Summary: 8 PASS, 6 WARN, 3 FAIL, 20 INFO  ->  score 64/100
(Score: PASS = 100, WARN = 50, FAIL = 0 points, averaged; INFO lines are not scored.)
```

The same VM with the hardened fixture - the SSH section is all PASS:

```
== SSH server ==
[PASS] SSH        PermitRootLogin no
[PASS] SSH        PasswordAuthentication no (keys only)
[PASS] SSH        PermitEmptyPasswords no
[PASS] SSH        Protocol 2 (only protocol supported by OpenSSH 7.4+)
[INFO] SSH        Port 2222
[PASS] SSH        X11Forwarding no
[PASS] SSH        MaxAuthTries 3
```

`check-windows.ps1` prints the same `[LEVEL] Category Message` format, e.g.
`[PASS] Firewall   Public profile enabled (inbound default: Block)`.
It was not run on a real Windows machine for this repository (see Limitations).

## Tests

```bash
bash tests/run-tests.sh
```

- Runs `check-linux.sh` against the insecure and hardened SSH fixtures and checks
  the expected PASS/WARN/FAIL lines, exit codes and report file.
- Greps `check-linux.sh` for state-changing commands to keep it read-only.
- With `pwsh` installed: dot-sources `check-windows.ps1` in test mode to test the
  `net accounts` parser and score maths, and checks the non-Windows guard.

CI (GitHub Actions, Ubuntu) runs ShellCheck, PSScriptAnalyzer and these tests.

## Limitations

- `check-windows.ps1` was linted with PSScriptAnalyzer and its helpers were tested
  under PowerShell 7 on Linux, but the Windows-specific checks need a Windows
  machine to run. Please open an issue with the output if a check misbehaves.
- `net accounts` parsing expects English output; on other display languages the
  password-policy check reports INFO instead of guessing.
- Without root/admin some checks are skipped and reported as INFO.
- The SUID "common programs" list is a heuristic: a WARN means "look at this",
  not "this is malicious".

## Disclaimer

Run these audits only on systems you own or administer. They are a starting
point for hardening, not a replacement for a professional security assessment.

## License

[MIT](LICENSE) - Copyright (c) 2026 Arnold Rurangwa

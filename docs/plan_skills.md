# fogbot: Skill Library Reference

Skills live in `/etc/fogbot/skills-available/` and are enabled by symlinking into `/etc/fogbot/skills-enabled/` — identical to Apache2's `a2ensite` / `sites-enabled` pattern. fogbot ships with a set of prebuilt skill configs; the operator enables the ones relevant to their system.

---

## Filesystem Layout

```
/etc/fogbot/
├── skills-available/
│   ├── 100-ssh-monitor.yaml
│   ├── 200-suid-sweep.yaml
│   ├── 210-proc-exec.yaml
│   ├── 300-pkg-monitor.yaml
│   ├── 400-log-freshness.yaml
│   ├── 410-service-health.yaml
│   ├── 420-auditd-health.yaml
│   ├── 500-passwd-watch.yaml
│   ├── 510-port-tripwires.yaml
│   ├── 520-cron-watch.yaml
│   ├── 530-fs-anomaly.yaml
│   ├── 540-dir-watch.yaml
│   ├── 600-rkhunter.yaml
│   ├── 610-chkrootkit.yaml
│   ├── 700-kernel-mod.yaml
│   ├── 710-net-watch.yaml
│   ├── 715-net-discover.yaml
│   ├── 720-usb-monitor.yaml
│   ├── 800-bpftrace-exec.yaml
│   └── 900-resource-anomaly.yaml
└── skills-enabled/
    ├── 100-ssh-monitor.yaml -> ../skills-available/100-ssh-monitor.yaml
    └── 420-auditd-health.yaml -> ../skills-available/420-auditd-health.yaml
```

## Skill Numbering Groups

- **1xx** — auth monitoring
- **2xx** — process / execution
- **3xx** — package / system changes
- **4xx** — deadman / health checks
- **5xx** — file & filesystem (may require drop-ins)
- **6xx** — rootkit scanners (optional third-party tools)
- **7xx** — network / kernel
  - **715** — network discovery (added Phase 2 extension)
  - **720** — USB device monitor (added Phase 2 extension)
- **8xx** — advanced / bpftrace
- **9xx** — resource anomaly

---

## Skill YAML Format

Each skill YAML is both config and self-documentation. The operator edits the `config:` block; everything else is read-only reference.

```yaml
id: 100
name: ssh-monitor
description: >
  Monitors /var/log/auth.log for SSH authentication events.
  Detects brute force attempts, successful logins from new IPs,
  direct root logins, and sudo/su usage.
why: >
  SSH is the most common remote access vector on Linux systems.
  Brute force attempts are routine background noise on any
  internet-facing host, but a successful login from an IP that
  has never connected before — especially at an unusual hour —
  is a high-value indicator of compromise. Direct root login
  bypasses the sudo audit trail entirely.
requires:
  - auth.log read access
tags: [auth, ssh, brute-force]
severity_default: yellow   # brute force = yellow; new-IP login = red
config:
  brute_force_threshold: 5
  brute_force_window: 60s
  alert_new_ip_login: true
  quiet_hours_exempt: false
```

---

## CLI Commands

```
fogbot skill list                    # show all available skills, mark enabled ones
fogbot skill enable  <id-or-name>    # symlink into skills-enabled/, reload daemon, notify Telegram
fogbot skill disable <id-or-name>    # remove symlink, reload daemon, notify Telegram
fogbot skill info    <id-or-name>    # show full skill detail: description, why, config, drop-ins
fogbot skill edit    <id-or-name>    # open $EDITOR on skills-available/ file; reload on save
```

Tab completion is provided for `enable` and `disable` — `enable` completes from `skills-available/` (excluding already-enabled), `disable` completes from `skills-enabled/`.

---

## `fogbot skill list` Output

```
 ID   SKILL              STATUS    REQUIRES              DESCRIPTION
 ───  ─────────────────  ────────  ────────────────────  ──────────────────────────────────────
 100  ssh-monitor        enabled   auth.log              SSH brute force, new-IP logins, root login
 200  suid-sweep         disabled  auditd, root          Dual: auditd instant SUID/SGID chmod detection + periodic baseline sweep
 210  proc-exec          disabled  /proc                 Executables in /tmp, /dev/shm; process hiding
 300  pkg-monitor        disabled  dpkg.log              Package installs, removals, upgrades (dpkg)
 400  log-freshness      disabled  inotify               [DEADMAN] Logs not written within N minutes
 410  service-health     disabled  systemd               [DEADMAN] Configured services stopped
 420  auditd-health      enabled   auditd                [DEADMAN] auditd stopped or log gone stale
 500  passwd-watch       disabled  auditd, root          /etc/passwd, shadow, sudoers reads/writes
 510  port-tripwires     disabled  iptables, root        C2/malware port traffic (inbound + outbound)
 520  cron-watch         disabled  inotify               New crontab entries, systemd timers
 530  fs-anomaly         disabled  inotify, root         Hidden files, ld.so.preload, immutable flag
 540  dir-watch          disabled  inotify               Alert on new files/directories added to watched folders
 600  rkhunter           disabled  rkhunter              Parse rkhunter.log for warnings/infections
 610  chkrootkit         disabled  chkrootkit            Parse chkrootkit output for suspicious findings
 700  kernel-mod         disabled  root, dmesg           Kernel module load/unload, sysctl changes
 710  net-watch          disabled  /proc/net             Unexpected outbound connections by process
 715  net-discover       disabled  fping, root           Network discovery, new IP detection, baseline
 720  usb-monitor        disabled  udev or lsusb         USB device plug/unplug detection
 800  bpftrace-exec      disabled  bpftrace, root        Suspicious exec chains, ptrace, droppers
 900  resource-anomaly   disabled  /proc                 CPU/mem/IO spikes, crypto miner heuristics
```

Skills marked **[DEADMAN]** alert when expected activity *stops* rather than when unexpected activity *starts*.

---

## Detection Sensors ("OPs") — Detailed Descriptions

### 1. File Integrity Watcher (`auditd` + inotify)
**Skill ID:** 500 (passwd-watch)
**Analogy: Tripwire across a known trail**

Configures `auditd` rules at startup to watch specified files and directories. Reports on:
- Read/write/execute/attribute changes to sensitive files
- `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/hosts`
- SSH keys: `~/.ssh/authorized_keys`, `/etc/ssh/sshd_config`
- Crontabs: `/etc/cron*`, `/var/spool/cron`
- PAM config: `/etc/pam.d/`
- The daemon binary and config itself (tamper detection)

Reports: who touched it (uid, process, parent process), what they did, when.

---

### 2. File Permission Monitor (inotify + periodic stat)
**Skill ID:** 200 (suid-sweep)
**Analogy: Checking if the gate is still locked**

Periodically stats important files and alerts on unexpected permission changes:
- SUID/SGID bit appearing on a file that didn't have it
- World-writable flag appearing on sensitive files
- Owner/group changing on system binaries
- `/etc/passwd` suddenly world-writable
- New SUID binaries appearing anywhere in `$PATH`

Can do a full SUID/SGID sweep at configurable intervals — any new ones not in a known-good baseline get reported.

---

### 3. Port Tripwires (`iptables` + `nftables` logging)
**Skill ID:** 510 (port-tripwires)
**Analogy: Seismic sensor on the perimeter wire**

Configures iptables at startup to LOG (not drop) traffic on ports commonly used by malware/C2:
- **Lateral movement**: 135, 137-139, 445 (SMB/NetBIOS), 389/636 (LDAP)
- **C2 frameworks**: 4444, 4445 (Metasploit default), 8080, 8443, 1080 (SOCKS)
- **Crypto miners**: 3333, 4444, 5555, 7777, 14444 (Stratum protocol)
- **Backdoors**: 31337, 12345, 54321 (classic)
- **Data exfil**: Outbound on 25 (SMTP if not a mail server), DNS anomalies

Both inbound *and* outbound rules — outbound is often more interesting (something phoning home).

Reports: src/dst IP, port, protocol, which process triggered it (via `/proc/net/tcp` correlation).

---

### 4. Network Process Watcher (`bpftrace` / `ss` polling)
**Skill ID:** 710 (net-watch)
**Analogy: Watching the RF spectrum for unexpected transmitters**

Watches for processes establishing unexpected outbound connections:
- Processes that shouldn't be making network calls (e.g. `bash`, `python`, `perl` connecting out)
- New listeners appearing on unexpected ports
- Connections to known-bad IP ranges (configurable blocklist, can pull from threat intel feeds)
- DNS queries to unusual TLDs or high-entropy domains (DGA detection)
- `ss`/`/proc/net/tcp` polling at short intervals as a lightweight fallback if bpftrace unavailable

---

### 5. Process & Execution Monitor (`auditd` execve + `bpftrace`)
**Skill ID:** 800 (bpftrace-exec), 210 (proc-exec)
**Analogy: Movement on the objective — someone's up to something**

Watches for suspicious execution patterns:
- Shells spawned from unexpected parents (`apache2` → `bash`, `nginx` → `sh`)
- Interpreters running with `-c` flag (in-memory execution: `python3 -c ...`, `perl -e ...`)
- `curl`/`wget` → shell pipelines (classic dropper pattern)
- `chmod +x` followed immediately by execution of the same file
- Processes running from `/tmp`, `/dev/shm`, or `/run` — red flag
- Rapid process spawning (fork bombs, scanners)
- `ptrace` calls (debugger attachment / injection attempts)

---

### 6. User & Auth Monitor (`/var/log/auth.log` + PAM + auditd)
**Skill ID:** 100 (ssh-monitor)
**Analogy: Watching the gate for unknown personnel**

- SSH brute force detection (N failures in T seconds from same IP)
- Successful SSH login from new IP not seen before
- `su`/`sudo` usage, especially failures
- New user account created (`useradd`, direct `/etc/passwd` edit)
- User added to sudoers or wheel group
- Login at unusual hours (configurable quiet hours)
- Root login directly (not via sudo)

---

### 7. Kernel & Driver Monitor (`dmesg` / `auditd`)
**Skill ID:** 700 (kernel-mod)
**Analogy: Noticing the birds aren't singing — something disturbed them**

- Kernel module loaded (`insmod`/`modprobe`) — rootkit vector
- Unexpected module unloaded
- `dmesg` errors indicating unusual hardware or driver activity
- `ptrace_scope` or other kernel security knobs changing at runtime
- `/proc/sys/kernel` values changing (e.g. someone disabling ASLR)
- `LD_PRELOAD` set on any process (hooking indicator)

---

### 8. Filesystem Anomaly Monitor
**Skill ID:** 530 (fs-anomaly)
**Analogy: Noticing disturbed earth — something was buried here**

- New files appearing in `/tmp`, `/dev/shm`, `/run` that are executable
- Files with names that are all dots or whitespace (hiding in plain sight)
- Large files appearing in unusual places (data staging for exfil)
- Hidden directories (`.` prefixed) appearing in unusual locations
- Immutable flag (`chattr +i`) being set on files — ransomware technique
- `/etc/ld.so.preload` appearing or being modified

---

### 9. Directory Watch Monitor
**Skill ID:** 540 (dir-watch)
**Analogy: Guard post at the gate — alert when anything enters**

Uses inotify to watch one or more configured directories and alerts whenever a new file or subdirectory is created inside them. Designed for locations that should be static or change only during known maintenance windows:

- Operator configures a list of paths to watch in the skill YAML
- Alerts on `IN_CREATE` and `IN_MOVED_TO` events (new entries arriving, not modifications)
- Optional recursive mode — watch all subdirectories as well
- Optional filename glob filter — e.g. only alert on `*.sh`, `*.py`, or executables
- Optional whitelist: suppress alerts for expected filenames (e.g. lock files, PID files)
- Useful for: `/usr/local/bin/`, `/etc/cron.d/`, `/root/`, custom sensitive data dirs
- Pairs well with 520 (cron-watch) and 530 (fs-anomaly) for layered filesystem coverage

Reports: full path of new entry, whether it is a file or directory, permissions, owner, and whether it appears executable.

---

### 10. Scheduled Task Monitor (cron-watch)
**Skill ID:** 520 (cron-watch)
**Analogy: Checking for newly emplaced IEDs on a known route**

- New crontab entries for any user
- New systemd timers appearing
- New entries in `/etc/cron.d/`, `/etc/cron.daily/`, etc.
- At-jobs created
- Changes to `/etc/rc.local`, `/etc/profile.d/`, `/etc/bashrc`
- New systemd services appearing in `/etc/systemd/system/`

---

### 11. Resource Anomaly Monitor (proc polling)
**Skill ID:** 900 (resource-anomaly)
**Analogy: Noticing the comms traffic spike — something is active**

- CPU usage by a process spiking to near 100% persistently (crypto miner)
- Sudden high memory consumption by unexpected process
- High disk I/O from unexpected sources
- High network bandwidth from unexpected process
- Process hiding: PID visible in `/proc` but not in `ps` output (rootkit indicator)

---

### 12. Network Discovery Monitor (`fping` + baseline)
**Skill ID:** 715 (net-discover)
**Analogy: Spotting unfamiliar faces in a known area**

- Uses `fping` to sweep local network(s) every 5 minutes
- Maintains baseline of known IPs in `/var/lib/fogbot/net_baseline.json`
- Excludes own IP(s) from scanning to avoid self-detection
- Alerts on new IPs appearing on the network
- Configurable network ranges (CIDR notation)
- First run establishes baseline, operator approves via Telegram
- **Intel button** on alerts triggers active reconnaissance (nmap, arp-scan, DNS)

Reports: IP, MAC address, first-seen timestamp, reverse DNS if available.

---

### 13. USB Device Monitor (udev + lsusb)
**Skill ID:** 720 (usb-monitor)
**Analogy: Watching for unfamiliar equipment appearing on site**

- Monitors USB device plug/unplug events via udev (primary) or lsusb polling (fallback)
- Alerts on new USB storage devices, keyboards, network adapters
- Tracks vendor ID, product ID, serial number, device type
- Configurable whitelist for expected devices (suppress alerts for known equipment)
- **Intel button** provides detailed device info (lsusb -v output, kernel messages)

Reports: device type, vendor/product IDs, serial number, timestamp of connection.

---

### 14. Package Monitor
**Skill ID:** 300 (pkg-monitor)
**Analogy: Noticing new supplies have been delivered**

- Tails `/var/log/dpkg.log` for Debian-based systems
- Alerts on package installs, removals, upgrades
- Can be configured to alert only on unexpected packages (compare against baseline)
- Useful for detecting unauthorized software installation

---

### 14. Log Freshness Monitor (DEADMAN)
**Skill ID:** 400 (log-freshness)
**Analogy: Radio silence when you expect regular check-ins**

- Uses inotify + ticker to verify configured log files are being written
- Alerts if logs go stale (not modified within N minutes)
- Detects when logging infrastructure fails or is disabled
- Configurable per-log freshness thresholds

---

### 15. Service Health Monitor (DEADMAN)
**Skill ID:** 410 (service-health)
**Analogy: Checking if sentries are still at their posts**

- Polls systemd via D-Bus to verify configured services are running
- Alerts if critical services stop (e.g., auditd, sshd, fail2ban)
- Configurable service list per deployment
- Gracefully handles services not present on the system

---

### 16. auditd Health Monitor (DEADMAN)
**Skill ID:** 420 (auditd-health)
**Analogy: Verifying your surveillance system is still operational**

- Verifies auditd process is running
- Checks that audit.log is being written (freshness check)
- Dual-mode: both process check and log freshness
- Critical skill — if auditd is down, many other skills are blind

---

### 17. Rootkit Scanner Integration
**Skill IDs:** 600 (rkhunter), 610 (chkrootkit)
**Analogy: Calling in the experts for a detailed sweep**

- Integrates with existing rootkit detection tools
- Parses rkhunter and chkrootkit logs for warnings/infections
- Graceful no-op if tools not installed (won't break without them)
- Alerts on any suspicious findings from these scanners

---

## Alert Tagging

Every alert includes the skill ID and name that triggered it:

```
🔴 [CONTACT] #100 ssh-monitor
━━━━━━━━━━━━━━━━━━━━━
S: 1 source IP
A: 47 failed SSH attempts
L: targeting: root
U: src: 1.2.3.4
T: 2024-01-15 03:42:17 UTC
E: brute_force_threshold exceeded (47 > 5 in 60s)
━━━━━━━━━━━━━━━━━━━━━
Host: prod-web-01  |  skill #100 ssh-monitor
```

---

## Drop-in Config Management

fogbot never modifies files it doesn't own. All system tool configuration is done via drop-in files in dedicated directories:

| Tool | Drop-in location | Example file |
|------|-----------------|--------------|
| auditd | `/etc/audit/rules.d/` | `90-fogbot-passwd-watch.rules` |
| iptables | `/etc/iptables/rules.d/` | `90-fogbot-port-tripwires.rules` |
| rsyslog | `/etc/rsyslog.d/` | `90-fogbot.conf` |
| logrotate | `/etc/logrotate.d/` | `fogbot` |

Rules:
- All fogbot drop-ins are prefixed `90-fogbot-` for clear attribution
- fogbot never touches drop-in files it didn't create
- On `fogbot check disable <skill>`, the drop-in is removed (or moved to `.disabled`)
- Drop-in writes are always recorded in the ledger before the file is written

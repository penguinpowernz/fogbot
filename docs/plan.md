# fogbot: Linux Intrusion Detection via Telegram

> *"They don't fire unless compromised. They watch, they listen, they report."*

---

## Concept

A Go daemon that configures and monitors multiple detection subsystems on a Linux host, reporting anomalies as structured SALUTE-style alerts over Telegram. The operator configures what to watch; the daemon handles the instrumentation and stays out of the way.

---

## Current Status

**Phase 1 & 1.5: ✅ COMPLETE** (2026-03-08)

### What Works Now
- ✅ Full project structure with Debian packaging layout (etc/, usr/, var/)
- ✅ 17 detection skills defined (100-900 series) with complete YAML metadata
- ✅ Skill management CLI: `fogbot skill list|enable|disable|info`
- ✅ Configuration system with SIGHUP reload and environment overrides
- ✅ Telegram notifier with TOFU authentication (FOG-XXXX-XXXX codes)
- ✅ Improved auth flow: `/start` generates code on-demand, scans any message for code
- ✅ Command handlers: `/start`, `/help` (context-aware), `/reset` (deauthorize)
- ✅ SALUTE-formatted alerts (🔴 CONTACT, 🟡 MOVEMENT, 🟢 NOMINAL)
- ✅ Rate limiting (10 auth/60s, 3 unauth lifetime) and input sanitization
- ✅ HMAC-signed callback tokens for inline keyboards
- ✅ Drop-in file management with SHA256 ledger and dry-run mode
- ✅ Alert deduplication with windowed burst control
- ✅ Docker Compose test environment with proper capabilities
- ✅ Makefile: `make build|test|docker-up|docker-logs|package`

### Project Structure
```
fogbot/
├── cmd/fogbot/              # main.go, skill.go (CLI commands)
├── internal/
│   ├── auth/               # TOFU, rate limiting, input sanitization
│   ├── config/             # YAML config with env overrides
│   ├── dedup/              # Alert deduplication engine
│   ├── dropin/             # Drop-in file writer + ledger
│   ├── notifier/           # Interface + telegram/ implementation
│   └── skills/             # Skill interface, loader, registry
├── etc/fogbot/             # Config + skills (deployed to /etc)
│   ├── config.yaml
│   ├── skills-available/   # 17 prebuilt skill YAMLs
│   └── skills-enabled/     # Operator-created symlinks
├── usr/local/bin/          # fogbot binary (deployed)
├── usr/lib/systemd/system/ # fogbot.service
├── var/lib/fogbot/         # State, ledger, baselines
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── README.md
```

### What's Next
**Phase 2:** Implement actual skill watchers (ssh-monitor, suid-sweep, proc-exec, etc.)
**Phase 2.5:** Wire skills to Telegram alert pipeline, self-watch
**Phase 3:** Status reports with drill-down

---

## Detection Sensors ("OPs")

### 1. File Integrity Watcher (`auditd` + inotify)
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
**Analogy: Watching the RF spectrum for unexpected transmitters**

Watches for processes establishing unexpected outbound connections:
- Processes that shouldn't be making network calls (e.g. `bash`, `python`, `perl` connecting out)
- New listeners appearing on unexpected ports
- Connections to known-bad IP ranges (configurable blocklist, can pull from threat intel feeds)
- DNS queries to unusual TLDs or high-entropy domains (DGA detection)
- `ss`/`/proc/net/tcp` polling at short intervals as a lightweight fallback if bpftrace unavailable

---

### 5. Process & Execution Monitor (`auditd` execve + `bpftrace`)
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
**Analogy: Noticing the birds aren't singing — something disturbed them**

- Kernel module loaded (`insmod`/`modprobe`) — rootkit vector
- Unexpected module unloaded
- `dmesg` errors indicating unusual hardware or driver activity
- `ptrace_scope` or other kernel security knobs changing at runtime
- `/proc/sys/kernel` values changing (e.g. someone disabling ASLR)
- `LD_PRELOAD` set on any process (hooking indicator)

---

### 8. Filesystem Anomaly Monitor
**Analogy: Noticing disturbed earth — something was buried here**

- New files appearing in `/tmp`, `/dev/shm`, `/run` that are executable
- Files with names that are all dots or whitespace (hiding in plain sight)
- Large files appearing in unusual places (data staging for exfil)
- Hidden directories (`.` prefixed) appearing in unusual locations
- Immutable flag (`chattr +i`) being set on files — ransomware technique
- `/etc/ld.so.preload` appearing or being modified

---

### 9. Scheduled Task Monitor
**Analogy: Checking for newly emplaced IEDs on a known route**

- New crontab entries for any user
- New systemd timers appearing
- New entries in `/etc/cron.d/`, `/etc/cron.daily/`, etc.
- At-jobs created
- Changes to `/etc/rc.local`, `/etc/profile.d/`, `/etc/bashrc`
- New systemd services appearing in `/etc/systemd/system/`

---

### 10. Resource Anomaly Monitor (proc polling)
**Analogy: Noticing the comms traffic spike — something is active**

- CPU usage by a process spiking to near 100% persistently (crypto miner)
- Sudden high memory consumption by unexpected process
- High disk I/O from unexpected sources
- High network bandwidth from unexpected process
- Process hiding: PID visible in `/proc` but not in `ps` output (rootkit indicator)

---

## Alert Structure (SALUTE Format)

### RED — immediate, single event
```
🔴 [CONTACT] File Integrity
━━━━━━━━━━━━━━━━━━━━━
S: 1 process
A: WRITE to /etc/passwd
L: inode 12345 (/etc/passwd)
U: uid=1337 (unknown) → bash → sshd
T: 2024-01-15 03:42:17 UTC
E: auditd rule: watch-passwd
━━━━━━━━━━━━━━━━━━━━━
Host: prod-web-01
```

### YELLOW — rate-limited digest
```
🟡 [MOVEMENT] Auth: SSH Brute Force
━━━━━━━━━━━━━━━━━━━━━
47 failed attempts from 1.2.3.4
Targeting: root (32), admin (15)
Window: 60s
Last seen: 03:44:01 UTC
━━━━━━━━━━━━━━━━━━━━━
Host: prod-web-01
```

### GREEN — lifecycle
```
🟢 [NOMINAL] fogbot online
8 sensors active | baseline: approved
Host: prod-web-01 | 2024-01-15 03:40:00 UTC
```

Severity levels: 🔴 CONTACT / 🟡 MOVEMENT / 🟢 NOMINAL

---

## Command Interface Security

### Design Principles
- **Prefer structured input** — Telegram inline keyboards mean the operator clicks a button. fogbot receives a fixed callback token, never free text. No parsing surface, nothing to sanitize.
- **Commands are a closed enum** — handler is a `switch` on known verbs. Anything not in the switch is silently dropped. No dynamic dispatch.
- **No shell, ever** — nothing in the command handler touches `exec.Command`. Sensors configure system tools at startup only. The command interface flips internal state only.
- **Log everything inbound** — every message received, from any chat_id, authorised or not, logged to journald. Full audit trail.

### Command Surface (intentionally minimal)

| Input | Method | Free text? | Notes |
|-------|--------|------------|-------|
| Auth code | Free text | **Yes** | Only free text accepted. Validated against `^FOG-[A-Z0-9]{4}-[A-Z0-9]{4}$` exact match. Reject anything else with no explanation. |
| Approve SUID baseline | Inline keyboard | No | Button only, signed callback token |
| Acknowledge alert | Inline keyboard | No | Button only, signed callback token |
| `/status` | Telegram command | No | Args silently dropped |

That is the entire interface. There is no command that accepts meaningful free-text operator input beyond the one-time auth code.

### Callback Token Signing
Telegram inline keyboard callbacks are strings fogbot generates itself:
```
verb:noun:hmac
e.g. approve:baseline:a3f9c2...
```
HMAC keyed on the bot token. If verification fails → drop silently, log the attempt. Prevents replay or mutation of callback tokens by anyone who intercepts them.

### Input Sanitization (defence in depth)
Even though structured input is preferred, all inbound text goes through a sanitization pipeline before touching any internal logic:

```go
// Applied to ALL inbound text without exception
func sanitize(s string) string {
    s = strings.TrimSpace(s)
    s = strings.Map(func(r rune) rune {
        if r > unicode.MaxASCII { return -1 }   // drop non-ASCII
        if unicode.IsControl(r) { return -1 }    // drop control chars
        return r
    }, s)
    if len(s) > 64 { s = s[:64] }               // hard length cap
    return s
}
```

After sanitization, auth code input is validated against the exact regex and nothing else. Any mismatch → drop, log, no response.

### Rate Limiting (inbound)
- Max 10 commands per 60s from the authorised chat
- Exceed threshold → fogbot stops responding until window clears
- Unauth chat_ids: max 3 messages lifetime before permanently ignored (prevents probing)

---



### Challenge-Response (TOFU)
Proves the operator has shell access before the bot will talk to anyone.

```
1. fogbot starts
2. No auth code generated yet (waits for /start)
3. Bot ignores all unauthorized messages except /start, /help
4. /start → bot generates code: FOG-A3X9-K2M7
         → logs to stdout/journald: "*** AUTH CODE: FOG-A3X9-K2M7 ***"
         → marks chat as pending authorization
         → replies "Enter authorisation code"
5. Operator reads code from logs, pastes it in any message
6. Bot scans all messages from pending chats for valid codes
7. Code matches → chat_id saved to /var/lib/fogbot/state.json
                → chat_id also logged so operator can hardcode in config
                → code burned, never valid again
                → pending auth cleared
                → bot begins normal operation
8. /reset from authorized chat → deauthorize, clear code
9. Next /start generates fresh code
10. On restart: if state.json has an authorised chat_id, skip challenge entirely
```

- **No expiry** — code valid until used, operator can take their time
- **First to auth wins** — subsequent auth attempts silently dropped
- **One authorised chat only** — no ambiguity about who the operator is
- **Code format**: `FOG-XXXX-XXXX` (crypto/rand, uppercase alphanum)
- **Code generation**: Only on `/start` command, not on daemon startup or reset
- **Additional commands**: `/help` (context-aware), `/reset` (deauthorize current chat)

### Notifier Interface

Telegram is the first implementation but the interface is generic so Slack, WhatsApp, IRC can be added later. The interface must handle both directions — push (fogbot → operator) and pull (operator → fogbot commands).

```go
// Notifier handles outbound alerts and inbound commands
type Notifier interface {
    // Push an alert to the operator
    Send(ctx context.Context, alert Alert) error

    // Commands returns a channel of inbound operator commands
    // Each implementation handles its own polling/event loop
    Commands(ctx context.Context) (<-chan Command, error)

    // Name of this notifier implementation
    Name() string
}

type Command struct {
    Raw    string            // raw text from operator
    ChatID string            // implementation-specific sender ID
    Args   []string          // parsed tokens
}

// Known command verbs
const (
    CmdStart   = "start"    // initiate auth
    CmdApprove = "approve"  // approve pending SUID baseline
    CmdStatus  = "status"   // request status summary
)
```

Implementations: `telegram/`, `slack/` (future), `irc/` (future), `whatsapp/` (future) — each lives under `internal/notifier/`.

---

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Rule cleanup on shutdown | **Leave in place** | Protection persists through crashes; orphaned rules are preferable to a blind gap |
| Alert style | **Both, severity-dependent** | RED = immediate; YELLOW = rate-limited digest |
| SUID baseline approval | **Manual** | Operator signs off on what's "normal" before diffs are trusted |
| Startup/shutdown messages | **Yes** | Critical for knowing if the daemon crashed unexpectedly |
| Bot auth | **TOFU challenge-response** | Operator proves shell access by reading code from logs |
| Challenge code expiry | **None** | Valid until used; operator takes their time |
| Authorised chats | **One only, first wins** | No ambiguity; subsequent auth attempts silently dropped |
| chat_id persistence | **state.json + logged** | Survives restarts; operator can hardcode in config if preferred |
| Scheduled status reports | **Configurable** | Daily or weekly at operator-specified time; acts as heartbeat |
| Autonomous system modification | **Off by default** | Operator approves commands at enable time; startup repair is pre-approved; all commands logged to ledger |
| System config tagging | **Opaque per-machine tag** | HMAC-SHA256(machine-id, "fogbot"), base32 encoded — no "fogbot" string appears in iptables/auditd output |

### Alert Severity Model
- 🔴 **CONTACT** — immediate single alert (file integrity hit, new SUID, kernel module load, shell from unexpected parent)
- 🟡 **MOVEMENT** — rate-limited, digested (SSH brute force summary, port scan summary, resource anomaly)
- 🟢 **NOMINAL** — startup, shutdown, baseline approval prompts

### Baseline Workflow
On first run with `permissions` sensor enabled, fogbot performs a SUID/SGID sweep, writes findings to `/var/lib/fogbot/suid_baseline.pending.json`, sends a Telegram message listing every SUID binary found, and **waits for operator approval** (`/approve` command via Telegram) before the baseline is trusted. Until approved, any new SUID binary triggers a RED alert regardless.

---

## Architecture (Go)

```
fogbot/
├── cmd/
│   └── fogbot/
│       ├── main.go              # daemon entry point, signal handling
│       └── cli/                 # subcommand definitions (cobra)
│           ├── skill.go         # fogbot skill list|enable|disable|info|edit
│           ├── status.go        # fogbot status (query running daemon)
│           └── changes.go       # fogbot changes (show config change ledger)
├── internal/
│   ├── config/                  # yaml config parsing, SIGHUP reload
│   ├── notifier/
│   │   ├── notifier.go          # Notifier interface + Alert/Command types
│   │   └── telegram/            # Telegram implementation (long polling)
│   │   # future: slack/, irc/, whatsapp/
│   ├── auth/                    # TOFU challenge-response, state.json persistence
│   ├── skills/
│   │   ├── skill.go             # Skill interface + YAML schema (id, name, description, why, requires, config)
│   │   ├── loader.go            # read skills-enabled/ symlinks, parse YAMLs, build active set
│   │   ├── 100-ssh-monitor/     # Go impl: authlog parser
│   │   ├── 200-suid-sweep/      # Go impl: SUID/SGID baseline + sweep
│   │   ├── 210-proc-exec/       # Go impl: /proc polling
│   │   ├── 300-pkg-monitor/     # Go impl: dpkg.log tailer
│   │   ├── 400-log-freshness/   # Go impl: deadman log freshness
│   │   ├── 410-service-health/  # Go impl: deadman systemd service check
│   │   ├── 420-auditd-health/   # Go impl: deadman auditd check
│   │   ├── 500-passwd-watch/    # Go impl: auditd log tailer
│   │   ├── 510-port-tripwires/  # Go impl: iptables log parser
│   │   ├── 520-cron-watch/      # Go impl: inotify on cron paths
│   │   ├── 530-fs-anomaly/      # Go impl: inotify filesystem anomalies
│   │   ├── 600-rkhunter/        # Go impl: rkhunter log parser
│   │   ├── 610-chkrootkit/      # Go impl: chkrootkit log parser
│   │   ├── 700-kernel-mod/      # Go impl: dmesg watcher
│   │   ├── 710-net-watch/       # Go impl: ss+proc outbound watcher
│   │   ├── 800-bpftrace-exec/   # Go impl: bpftrace exec monitor
│   │   └── 900-resource-anomaly/ # Go impl: /proc resource polling
│   ├── dropin/                  # drop-in config writer + ledger
│   │   ├── dropin.go            # write/verify/remove drop-in files safely
│   │   └── ledger.go            # append-only change log → /var/lib/fogbot/changes.log
│   ├── selfwatch/               # inotify on fogbot binary, config, state dir, drop-ins
│   ├── baseline/                # known-good state snapshots + approval state machine
│   ├── metrics/                 # per-period counters for status reports
│   └── dedup/                   # alert deduplication / rate limiting
├── skills-available/            # prebuilt skill YAMLs — shipped with fogbot
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
│   ├── 600-rkhunter.yaml
│   ├── 610-chkrootkit.yaml
│   ├── 700-kernel-mod.yaml
│   ├── 710-net-watch.yaml
│   ├── 800-bpftrace-exec.yaml
│   └── 900-resource-anomaly.yaml
├── config.yaml.example
└── fogbot.service               # systemd unit

# On install, skills-available/ is copied to /etc/fogbot/skills-available/
# skills-enabled/ is created empty at /etc/fogbot/skills-enabled/
# fogbot skill enable 100-ssh-monitor creates:
#   /etc/fogbot/skills-enabled/100-ssh-monitor.yaml
#     -> /etc/fogbot/skills-available/100-ssh-monitor.yaml
```

### Core Interfaces

```go
// Skill is the unit of detection capability — self-describing, owns its config
type Skill interface {
    Name()        string     // machine name e.g. "port-tripwires"
    Description() string     // human summary
    Requires()    []string   // e.g. ["iptables", "root", "auditd"]
    DropIns()     []DropIn   // drop-in config files this skill manages
    Configure(cfg SkillConfig) error  // write drop-ins, record in ledger
    Watch(ctx context.Context) (<-chan Alert, error)
    Enabled()     bool
}

// Notifier handles outbound alerts and inbound operator commands
type Notifier interface {
    Send(ctx context.Context, alert Alert) error
    Commands(ctx context.Context) (<-chan Command, error)
    Name() string
}
```

Skills run concurrently, each pushing to a central alert channel. The dedup/rate-limiter prevents alert storms. On any skill enable/disable/configure, a 🟢 NOMINAL change alert is sent to Telegram and the change is recorded in the ledger.

---

## Config (YAML)

```yaml
telegram:
  token: "YOUR_BOT_TOKEN"
  chat_id: 123456789

host_label: "prod-web-01"

# Rules are left in place on shutdown — no teardown
# Change config and restart to update rules

quiet_hours:
  enabled: false
  start: "23:00"
  end: "06:00"
  # RED alerts always fire regardless of quiet hours

sensors:
  file_integrity:
    enabled: true
    watch:
      - /etc/passwd
      - /etc/shadow
      - /etc/sudoers
      - /etc/ssh/sshd_config
      - ~/.ssh/authorized_keys

  permissions:
    enabled: true
    suid_sweep_interval: 1h
    baseline_file: /var/lib/fogbot/suid_baseline.json
    # First run: sweeps, writes pending baseline, sends Telegram list,
    # waits for /approve command before trusting. Until approved,
    # every new SUID binary is a RED alert.

  port_tripwires:
    enabled: true
    watch_inbound: [135, 139, 445, 4444, 31337]
    watch_outbound: [4444, 1080, 25]

  process_watch:
    enabled: true
    suspicious_parents:
      - nginx
      - apache2
      - postgres
    suspicious_launchers:
      - /tmp
      - /dev/shm

  auth_monitor:
    enabled: true
    brute_force_threshold: 5   # failures
    brute_force_window: 60s
    alert_new_ip_login: true

  kernel_monitor:
    enabled: true
    watch_module_load: true

  resource_anomaly:
    enabled: true
    cpu_threshold_pct: 90
    cpu_sustained_seconds: 30

dedup:
  window: 300s   # suppress duplicate alerts for 5 min
  max_burst: 10  # max alerts per sensor per window
```

---

## Deployment

- Runs as a systemd service (provided unit file)
- Requires `root` or `CAP_NET_ADMIN + CAP_AUDIT_CONTROL + CAP_SYS_PTRACE`
- On startup: configures all enabled sensors (injects iptables rules, writes auditd rules, takes baselines), sends 🟢 **NOMINAL** online message to Telegram
- On shutdown (SIGTERM): sends 🟢 **NOMINAL** offline message to Telegram — **rules are left in place**
- State stored in `/var/lib/fogbot/`
- Logs to journald

---

## CLI Subcommands

fogbot is both a daemon and a management tool. The same binary is used for both.

```
fogbot daemon                          # start the daemon (used by systemd)
fogbot check list                      # list all skills with enabled/disabled status
fogbot check enable  <skill>           # enable a skill, write drop-ins, notify Telegram
fogbot check disable <skill>           # disable a skill, notify Telegram
fogbot check configure <skill>         # interactive prompt to configure a skill
fogbot check status                    # show running daemon status (via unix socket)
fogbot skill list                      # list all known skills with descriptions
fogbot skill info <skill>              # show full detail: what it watches, what it needs, drop-ins it manages
fogbot changes                         # print the config change ledger
fogbot changes --tail 20               # last 20 ledger entries
```

Interactive configuration example (`fogbot check configure port-tripwires`):
```
Configuring: port-tripwires
━━━━━━━━━━━━━━━━━━━━━
Watch inbound ports  [135 139 445 4444 31337]: 135 139 445 4444 31337 12345
Watch outbound ports [4444 1080 25]:           4444 1080 25

Writing drop-in: /etc/iptables/rules.d/fogbot-port-tripwires.rules  ✓
Ledger updated                                                        ✓
Sending Telegram notification                                         ✓

Reload fogbot to apply? [Y/n]: Y
Signalling daemon (SIGHUP)...                                         ✓
```

CLI talks to the running daemon via a Unix socket at `/run/fogbot/fogbot.sock` for live status queries. Config changes write directly to `config.yaml` and signal SIGHUP.

---

## Skill Library

Skills live in `/etc/fogbot/skills-available/` and are enabled by symlinking into `/etc/fogbot/skills-enabled/` — identical to Apache2's `a2ensite` / `sites-enabled` pattern. fogbot ships with a set of prebuilt skill configs; the operator enables the ones relevant to their system.

### Filesystem Layout

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
│   ├── 600-rkhunter.yaml
│   ├── 610-chkrootkit.yaml
│   ├── 700-kernel-mod.yaml
│   ├── 710-net-watch.yaml
│   ├── 800-bpftrace-exec.yaml
│   └── 900-resource-anomaly.yaml
└── skills-enabled/
    ├── 100-ssh-monitor.yaml -> ../skills-available/100-ssh-monitor.yaml
    └── 420-auditd-health.yaml -> ../skills-available/420-auditd-health.yaml
```

Numbering groups:
- **1xx** — auth monitoring
- **2xx** — process / execution
- **3xx** — package / system changes
- **4xx** — deadman / health checks
- **5xx** — file & filesystem (may require drop-ins)
- **6xx** — rootkit scanners (optional third-party tools)
- **7xx** — network / kernel
- **8xx** — advanced / bpftrace
- **9xx** — resource anomaly

### Skill YAML Format

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

### CLI Commands

```
fogbot skill list                    # show all available skills, mark enabled ones
fogbot skill enable  <id-or-name>    # symlink into skills-enabled/, reload daemon, notify Telegram
fogbot skill disable <id-or-name>    # remove symlink, reload daemon, notify Telegram
fogbot skill info    <id-or-name>    # show full skill detail: description, why, config, drop-ins
fogbot skill edit    <id-or-name>    # open $EDITOR on skills-available/ file; reload on save
```

Tab completion is provided for `enable` and `disable` — `enable` completes from `skills-available/` (excluding already-enabled), `disable` completes from `skills-enabled/`.

### `fogbot skill list` Output

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
 600  rkhunter           disabled  rkhunter              Parse rkhunter.log for warnings/infections
 610  chkrootkit         disabled  chkrootkit            Parse chkrootkit output for suspicious findings
 700  kernel-mod         disabled  root, dmesg           Kernel module load/unload, sysctl changes
 710  net-watch          disabled  /proc/net             Unexpected outbound connections by process
 800  bpftrace-exec      disabled  bpftrace, root        Suspicious exec chains, ptrace, droppers
 900  resource-anomaly   disabled  /proc                 CPU/mem/IO spikes, crypto miner heuristics
```

Skills marked **[DEADMAN]** alert when expected activity *stops* rather than when unexpected activity *starts*.

### Alert Tagging

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

---

## Config Change Ledger

Append-only log at `/var/lib/fogbot/changes.log`. Every config change fogbot makes — drop-in written, skill enabled/disabled, baseline approved — is recorded here.

```
2024-01-15T03:40:00Z  ENABLE   skill=passwd-watch       dropin=/etc/audit/rules.d/90-fogbot-passwd-watch.rules
2024-01-15T03:40:00Z  WRITE    file=/etc/audit/rules.d/90-fogbot-passwd-watch.rules  sha256=a3f9...
2024-01-15T09:12:33Z  DISABLE  skill=fs-anomaly          dropin=/etc/iptables/rules.d/90-fogbot-fs-anomaly.rules  (removed)
2024-01-15T11:04:01Z  APPROVE  baseline=suid             file=/var/lib/fogbot/suid_baseline.json
2024-01-16T08:00:00Z  CONFIG   skill=port-tripwires      changed=watch_inbound  old="135 139 445" new="135 139 445 12345"
```

SHA256 of every written file is recorded so tampering can be detected. `fogbot changes` pretty-prints the ledger.

---

## Self-Monitoring

fogbot watches its own files for unexpected modification — tamper detection for the watcher itself.

Watched paths:
- fogbot binary (`/usr/local/bin/fogbot` or wherever installed)
- `config.yaml`
- `/var/lib/fogbot/` (state dir)
- `/var/lib/fogbot/changes.log` (ledger — modification outside fogbot is suspicious)
- All active drop-in files fogbot has written

**Expected vs unexpected writes:** before fogbot writes any drop-in or ledger entry, it records the pending write in an internal whitelist. inotify events matching a whitelisted write are silently consumed. Anything else hitting these files from outside fogbot triggers a 🔴 CONTACT alert.

---



Acts as both an operational summary and a **heartbeat** — if the report doesn't arrive, something is wrong even if no alerts fired.

Two-tier design: a brief pushed summary you can read at a glance, with interactive drill-down into any section that has non-zero counts.

### Tier 1 — Summary (pushed on schedule)

Numbers only, fits on a phone screen without scrolling.

```
🟢 [STATUS] Daily — prod-web-01
━━━━━━━━━━━━━━━━━━━━━
2024-01-15 09:00 UTC  |  uptime 24h

ALERTS      2 🔴  1 🟡  0 suppressed
AUTH        SSH logins 3 ✓  |  failures 47 ✗  |  sudo 12
NETWORK     Outbound conns 1,204  |  tripwires hit 0
FILES       Watched files touched 2  |  SUID changes 0
PROCESSES   Suspicious exec 0  |  /tmp executables 0
SYSTEM      Modules loaded 0  |  cron changes 0
━━━━━━━━━━━━━━━━━━━━━
[🔍 Drill down ▾]
```

Drill-down button only appears for sections with non-zero counts — no point offering a modules drill-down if nothing loaded.

### Tier 2 — Drill down (on button tap)

Tapping `[🔍 Drill down ▾]` reveals an inline keyboard with one button per non-zero section. Tapping a section sends the detail view. Example for AUTH:

```
🔍 AUTH detail — last 24h
━━━━━━━━━━━━━━━━━━━━━
SSH logins (3):
  ✓ 03:12 UTC  192.168.1.5  →  alice
  ✓ 09:44 UTC  10.0.0.2     →  bob
  ✓ 11:30 UTC  10.0.0.2     →  bob

SSH failures (47):
  ✗ 1.2.3.4  —  47 attempts  targeting: root
    first: 03:40  last: 03:41 UTC  [brute force]

Sudo usage (12):
  alice  →  12x  all succeeded
  root direct login: 0
━━━━━━━━━━━━━━━━━━━━━
[◀ Back]
```

`[◀ Back]` returns to the summary inline keyboard. All navigation via buttons — no free text.

### Tracked Metrics per Section

| Section | Metrics |
|---------|---------|
| **Alerts** | RED count, YELLOW count, dedup-suppressed count, top offending IP |
| **Auth** | SSH logins (success/fail/IPs/users), sudo usage, su attempts, new accounts created, root direct logins |
| **Network** | Outbound connections by process, tripwire port hits, unique external IPs seen |
| **Files** | Watched file touches (who/when), permission changes, new SUID binaries |
| **Processes** | Suspicious parent→child execs, interpreter `-c` invocations, executions from `/tmp` `/dev/shm` |
| **System** | Kernel modules loaded, cron/systemd timer changes, `/proc/sys` changes |

### Schedule Config
```yaml
status_report:
  enabled: true
  schedule: daily        # daily | weekly
  time: "09:00"          # 24h
  day: monday            # weekly only — mon/tue/wed/thu/fri/sat/sun
  timezone: "Europe/London"  # IANA tz string
```

### Implementation
- Uses a ticker that wakes at the next scheduled time, then every interval — no cron dependency
- Metrics accumulated in an in-memory ring buffer per period, flushed on report
- If fogbot was down during a scheduled report time, sends catch-up on next startup: `"Note: fogbot was offline. Last report was 36h ago. Metrics incomplete for that period."`
- Timezone-aware via Go's `time.LoadLocation`
- Drill-down state tracked per Telegram message ID so multiple reports can be open simultaneously without confusion

---

## Phased Delivery

Architectural decisions (interfaces, package structure, config format) are established in Phase 1 and not revisited. Later phases add sensors and features without touching core.

---

### Phase 1 — Core Infrastructure (skeleton only) ✅ COMPLETE
*Goal: project compiles and runs. All interfaces defined. No Telegram, no skills, no auth — just the skeleton everything else hangs off.*

- [x] Project scaffold — `go.mod`, package structure, `fogbot.service`
- [x] `/etc/fogbot/skills-available/` — directory created on install, ships with all prebuilt skill YAMLs (17 skills: 100-900)
- [x] `/etc/fogbot/skills-enabled/` — empty on install, operator populates with symlinks
- [x] `internal/config/` — YAML parsing, validation, defaults, SIGHUP reload, environment variable overrides
- [x] `internal/notifier/notifier.go` — `Notifier` interface, `Alert` and `Command` types, severity constants
- [x] `internal/skills/skill.go` — `Skill` interface + YAML schema (`id`, `name`, `description`, `why`, `requires`, `config`)
- [x] `internal/skills/loader.go` — read symlinks from `skills-enabled/`, parse YAMLs, build active skill set, smart filename matching
- [x] `internal/dedup/` — dedup and rate-limiting engine with configurable window and burst limits
- [x] `internal/dropin/dropin.go` — drop-in file writer (safe write, verify, remove) with dry-run mode support
- [x] `internal/dropin/ledger.go` — append-only change ledger with SHA256 checksums
- [x] `cmd/fogbot/main.go` — daemon entry point, signal handling, SIGHUP config reload
- [x] `cmd/fogbot/cli/` — cobra subcommands: `skill list|enable|disable|info`, `version`
- [x] `config.yaml.example` with comprehensive documentation
- [x] **BONUS:** Makefile with build, test, docker, and package targets
- [x] **BONUS:** Docker Compose test environment with proper capabilities
- [x] **BONUS:** Dry-run mode via `FOGBOT_DRY_RUN` environment variable
- [x] **BONUS:** Debian package structure (etc/, usr/, var/) ready for ian
- [x] **BONUS:** .gitignore, .dockerignore, .ianignore for proper artifact management

**Exit criteria:** ✅ All met. `go build` succeeds. `fogbot daemon` starts, reads `skills-enabled/`, exits cleanly on SIGTERM. `fogbot skill list` prints the available/enabled table with all 17 skills. Ledger records all operations.

**Implementation notes:**
- Unix socket for CLI↔daemon comms deferred to Phase 2 (CLI currently direct-to-config)
- Shell completion scaffold deferred (cobra supports it, needs hookup)
- Environment variables added for all paths (`FOGBOT_CONFIG`, `FOGBOT_STATE_DIR`, `FOGBOT_SKILLS_*`) for testing flexibility
- Smart skill name matching handles numeric prefixes (e.g., "ssh-monitor" matches "100-ssh-monitor.yaml")

---

### Phase 1.5 — Telegram Auth & Ping ✅ COMPLETE
*Goal: prove the Telegram plumbing works end to end. First human interaction with the bot.*

- [x] `internal/notifier/telegram/` — Telegram implementation, long polling, message sending, inline keyboard support, SALUTE-formatted alerts
- [x] `internal/auth/` — TOFU challenge-response, `state.json` persistence, `FOG-XXXX-XXXX` code generation, inbound rate limiting (10 auth/60s, 3 unauth lifetime), unauth chat_id budget
- [x] Improved auth flow — code generated only on `/start` (not on daemon startup), pending auth state tracking, code scanning in any message after `/start`
- [x] Command handlers — `/start` (generate code + mark pending), `/help` (context-aware), `/reset` (deauthorize), `hi`/`hello` (ping)
- [x] Input sanitization pipeline — applied to all inbound text without exception (ASCII only, control chars stripped, 64 char limit)
- [x] Signed callback token generation and verification (HMAC-SHA256 keyed on bot token)
- [x] 🟢 Startup / shutdown Telegram messages with host label and version
- [x] Inline keyboard scaffolding (mechanism working, acknowledge buttons ready)

**Exit criteria:** ✅ All met. fogbot starts (no code generated), operator DMs `/start`, bot generates and logs code, operator pastes code in any message, bot confirms auth. Command handlers process `/start`, `/help`, `/reset`, `hi`, `hello`. SIGTERM sends offline message. Unauthorized chats are rate-limited and silently dropped.

**Implementation notes:**
- Alert formatting uses SALUTE structure (Size, Activity, Location, Unit, Time, Equipment)
- Emoji indicators: 🔴 CONTACT (red), 🟡 MOVEMENT (yellow), 🟢 NOMINAL (green)
- Rate limiter tracks both authorized (windowed) and unauthorized (lifetime budget) chats
- Callback verification prevents replay attacks on inline keyboard buttons
- Dry-run mode skips Telegram sends when `FOGBOT_DRY_RUN=true`
- Auth code generated on-demand via `/start`, not on daemon startup — improves security and reduces log noise
- Pending auth state allows flexible code input in any message after `/start`

---

### Phase 2 — First Skills (high value, low complexity)
*Goal: real detection using existing log files. No kernel instrumentation, no system config changes.*

- [ ] `internal/skills/100-ssh-monitor/` — parse `/var/log/auth.log`: SSH login success/fail, sudo, su, root direct login, brute force
- [ ] `internal/skills/210-proc-exec/` — `/proc` polling: executables in `/tmp`/`/dev/shm`, process hiding detection
- [ ] `internal/baseline/` — SUID sweep, `pending.json` state machine, Telegram approval flow with inline keyboard
- [ ] `internal/skills/200-suid-sweep/` — dual detection: auditd watches for chmod syscalls setting S_ISUID/S_ISGID (immediate, via `-k fogbot-200`), plus periodic sweep diffing filesystem state against approved baseline
- [ ] `internal/skills/300-pkg-monitor/` — tail `/var/log/dpkg.log`, alert on install/remove/upgrade events
- [ ] `internal/skills/400-log-freshness/` — [DEADMAN] inotify + ticker: alert if configured log files not written within N minutes
- [ ] `internal/skills/410-service-health/` — [DEADMAN] poll systemd via dbus: alert if configured services stop running
- [ ] `internal/skills/420-auditd-health/` — [DEADMAN] verify auditd process running + log is being written; alert on either going stale
- [ ] `fogbot skill list` — shows all registered skills with enabled/disabled status
- [ ] `fogbot skill enable/disable <skill>` — updates config.yaml, records in ledger, signals SIGHUP, notifies Telegram
- [ ] `fogbot skill info <skill>` — full detail view

**Exit criteria:** `fogbot skill list` shows all skills. Enable/disable works and Telegram is notified. fogbot detects SSH brute force, executables in `/tmp`, new dpkg installs, and a stopped service. Alerts print to stdout only — not yet Telegram.

---

### Phase 2.5 — Wire Skills to Telegram + Self-Watch
*Goal: alerts actually arrive on your phone — and fogbot immediately starts watching its own back.*

- [ ] Connect skill alert channel output to `Notifier.Send()` pipeline
- [ ] RED alert formatting — full SALUTE message, immediate send
- [ ] YELLOW alert formatting — rate-limited digest via dedup engine
- [ ] Alert acknowledge button — inline keyboard on each RED alert, signed callback token
- [ ] `internal/selfwatch/` — inotify on fogbot binary, `config.yaml`, `/var/lib/fogbot/` state dir, `changes.log`; whitelist own writes to avoid false positives
- [ ] End-to-end smoke test: trigger SSH brute force, receive 🔴 CONTACT on Telegram

**Exit criteria:** touching a watched file or triggering SSH failures produces a correctly formatted Telegram alert within seconds. Acknowledge button works. Unexpectedly modifying `config.yaml` or the fogbot binary from outside produces a 🔴 CONTACT alert.

---

### Phase 3 — Status Reports
*Goal: the daily/weekly heartbeat with interactive drill-down.*

- [ ] `internal/metrics/` — in-memory ring buffer accumulating per-section counts
- [ ] Scheduled report engine — timezone-aware ticker, catch-up report on restart
- [ ] Tier 1 summary message construction
- [ ] Tier 2 drill-down — inline keyboard per non-zero section, per-message-ID state, `[◀ Back]`
- [ ] `/status` command — on-demand report
- [ ] Quiet hours — suppress YELLOW during window, RED always fires

**Exit criteria:** daily report arrives on schedule, operator drills into AUTH and FILES, `/status` returns immediate summary.

---

### Phase 4 — System-Level Skills (require system config / drop-ins)
*Goal: expand coverage using auditd and iptables. fogbot now writes drop-in configs and tracks them in the ledger.*

- [ ] `internal/skills/500-passwd-watch/` — auditd drop-in: watch `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, SSH config, PAM
- [ ] `internal/skills/510-port-tripwires/` — iptables drop-in: LOG rules for C2/malware ports inbound + outbound, `/proc/net/tcp` correlation
- [ ] `internal/skills/520-cron-watch/` — inotify: `/etc/cron*`, `/var/spool/cron`, `/etc/systemd/system/`, rc.local
- [ ] `internal/skills/530-fs-anomaly/` — inotify: hidden files/dirs, `/etc/ld.so.preload`, immutable flag, large staging files
- [ ] `internal/skills/600-rkhunter/` — tail `/var/log/rkhunter.log`, alert on WARNING/infection lines; graceful no-op if rkhunter not installed
- [ ] `internal/skills/610-chkrootkit/` — parse chkrootkit output log, alert on INFECTED/suspicious findings; graceful no-op if not installed
- [ ] `fogbot skill configure <skill>` — interactive prompts, writes config.yaml, records in ledger
- [ ] `fogbot changes` — pretty-print ledger, `--tail N`
- [ ] Extend selfwatch (Phase 2.5) to also cover active drop-in files as they are written

- [ ] Approval prompt at `fogbot skill enable` — show all commands to be run, require `[y/N]` before execution (default `autonomous: false`)
- [ ] `--autonomous` flag and `autonomous: true` config option to skip prompts
- [ ] Startup rule verification for all active system-config skills — query actual state, diff, re-apply missing rules, log to ledger, alert if anything was missing
- [ ] `/var/lib/fogbot/skills/<id>.state.json` — persist expected rule state per skill at enable time

**Exit criteria:** `fogbot skill enable 500-passwd-watch` shows commands and prompts for approval before writing drop-in. On next startup with the drop-in deleted, fogbot detects it missing, re-applies it, logs the repair, and sends a 🟡 MOVEMENT alert. rkhunter/chkrootkit skills parse logs if tools are present, skip cleanly if not. Self-watch automatically extends to cover new drop-in files as each skill is enabled.

---

### Phase 5 — Advanced Skills (kernel-level)
*Goal: deep visibility via bpftrace and kernel monitoring.*

- [ ] `internal/skills/800-bpftrace-exec/` — suspicious exec chains, interpreter `-c`, dropper patterns, ptrace; graceful degradation if bpftrace absent
- [ ] `internal/skills/700-kernel-mod/` — dmesg: module load/unload, `/proc/sys/kernel` changes, `LD_PRELOAD`, ASLR knob
- [ ] `internal/skills/900-resource-anomaly/` — CPU/mem/IO anomaly, crypto miner heuristics
- [ ] `internal/skills/710-net-watch/` — `ss`/`/proc/net/tcp`: unexpected outbound by process, suspicious correlations

**Exit criteria:** fogbot detects shell spawned from nginx, kernel module load, and sustained high CPU from unexpected process.

---

### Phase 6 — Hardening & Polish
*Goal: production hardiness, notifier portability, and operator education.*

- [ ] `/why <id>` Telegram command — given a skill ID, sends the skill's `why:` field as a plain-language explanation of why the alert matters and what the operator should consider doing; uses the skill YAML directly, no LLM required
- [ ] Additional notifier implementations (Slack, IRC — interface already defined in Phase 1)
- [ ] Structured JSON logging to journald for SIEM ingestion
- [ ] Threat intel IP blocklist integration (configurable feed URLs)
- [ ] DGA / high-entropy DNS detection
- [ ] Comprehensive test suite
- [ ] Installation script / Makefile
- [ ] `fogbot skill edit <id>` — open `$EDITOR` on skill YAML, reload daemon on save, notify Telegram of config change

---

## Out of Scope (initially)

- Automated response / active countermeasures (LP/OP doctrine: observe and report only)
- Web UI
- Multi-host aggregation
- SIEM integration (though structured JSON logs could feed one)

# fogbot: Architecture & Design

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
│   │   ├── 500-file-watch/    # Go impl: auditd log tailer
│   │   ├── 510-port-tripwires/  # Go impl: iptables log parser
│   │   ├── 520-cron-watch/      # Go impl: inotify on cron paths
│   │   ├── 530-fs-anomaly/      # Go impl: inotify filesystem anomalies
│   │   ├── 600-rkhunter/        # Go impl: rkhunter log parser
│   │   ├── 610-chkrootkit/      # Go impl: chkrootkit log parser
│   │   ├── 700-kernel-mod/      # Go impl: dmesg watcher
│   │   ├── 710-net-watch/       # Go impl: ss+proc outbound watcher
│   │   ├── 715-net-discover/    # Go impl: fping network scanner
│   │   ├── 720-usb-monitor/     # Go impl: udev events + lsusb polling
│   │   ├── 800-bpftrace-exec/   # Go impl: bpftrace exec monitor
│   │   └── 900-resource-anomaly/ # Go impl: /proc resource polling
│   ├── dropin/                  # drop-in config writer + ledger
│   │   ├── dropin.go            # write/verify/remove drop-in files safely
│   │   └── ledger.go            # append-only change log → /var/lib/fogbot/changes.log
│   ├── selfwatch/               # inotify on fogbot binary, config, state dir, drop-ins
│   ├── baseline/                # known-good state snapshots + approval state machine
│   ├── metrics/                 # per-period counters for status reports
│   ├── contacts/                # contact report manager (incident tracking, anti-spam)
│   └── dedup/                   # alert deduplication / rate limiting
├── skills-available/            # prebuilt skill YAMLs — shipped with fogbot
│   ├── 100-ssh-monitor.yaml
│   ├── 200-suid-sweep.yaml
│   ├── 210-proc-exec.yaml
│   ├── 300-pkg-monitor.yaml
│   ├── 400-log-freshness.yaml
│   ├── 410-service-health.yaml
│   ├── 420-auditd-health.yaml
│   ├── 500-file-watch.yaml
│   ├── 510-port-tripwires.yaml
│   ├── 520-cron-watch.yaml
│   ├── 530-fs-anomaly.yaml
│   ├── 600-rkhunter.yaml
│   ├── 610-chkrootkit.yaml
│   ├── 700-kernel-mod.yaml
│   ├── 710-net-watch.yaml
│   ├── 715-net-discover.yaml
│   ├── 720-usb-monitor.yaml
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

---

## Core Interfaces

### Skill Interface

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

    // Phase 3: Intel gathering for contact reports
    GatherIntel(ctx context.Context, anomaly Anomaly) (Intel, error)
}
```

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

## Runtime Behavior

Skills run concurrently, each pushing to a central alert channel. The dedup/rate-limiter prevents alert storms. On any skill enable/disable/configure, a 🟢 NOMINAL change alert is sent to Telegram and the change is recorded in the ledger.

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

## Config Change Ledger

Append-only log at `/var/lib/fogbot/changes.log`. Every config change fogbot makes — drop-in written, skill enabled/disabled, baseline approved — is recorded here.

```
2024-01-15T03:40:00Z  ENABLE   skill=file-watch       dropin=/etc/audit/rules.d/90-fogbot-file-watch.rules
2024-01-15T03:40:00Z  WRITE    file=/etc/audit/rules.d/90-fogbot-file-watch.rules  sha256=a3f9...
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

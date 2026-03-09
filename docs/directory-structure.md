# Directory Structure

## Top-Level Layout

```
fogbot/
├── cmd/fogbot/              # Main application entry point
├── internal/                # Internal packages
├── etc/                     # Package files (deployed to /etc)
├── usr/                     # Package files (deployed to /usr)
├── var/                     # Package files (deployed to /var)
├── docs/                    # Documentation
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── README.md
└── QUICKSTART.md
```

## Key Directories

### cmd/fogbot/

Application entry points:

```
cmd/fogbot/
├── main.go       # Daemon entry, signal handling, skill registry
└── skill.go      # CLI commands: skill list|enable|disable|info
```

### internal/

Core implementation packages:

```
internal/
├── approval/              # Command approval tracking
│   └── tracker.go        # Stores approved commands to JSON
├── auth/                 # Telegram TOFU authentication
│   └── state.go          # FOG-XXXX-XXXX code generation
├── baseline/             # SUID baseline management
├── config/               # YAML config parsing, SIGHUP reload
│   ├── config.go
│   └── config_test.go
├── dedup/                # Alert deduplication engine
│   └── dedup.go
├── dropin/               # Drop-in config file management
│   ├── dropin.go         # Write/verify/remove drop-ins
│   └── ledger.go         # Append-only change log
├── notifier/
│   ├── notifier.go       # Notifier interface + Alert/Command types
│   └── telegram/         # Telegram implementation (long polling)
│       └── telegram.go
├── selfwatch/            # Monitor fogbot's own files
│   └── selfwatch.go
├── metrics/              # Per-period counters (future)
└── skills/
    ├── skill.go          # Skill interface + SystemCommand
    ├── enabler.go        # Approval workflow, system state checking
    ├── loader.go         # Load YAMLs from skills-enabled/
    ├── base.go           # Helper for legacy skills
    ├── porttripwires/    # Skill: iptables port monitoring
    │   └── porttripwires.go
    ├── sshmonitor/       # Skill: SSH auth log monitoring
    │   └── sshmonitor.go
    ├── suidsweep/        # Skill: SUID/SGID detection
    │   └── suidsweep.go
    ├── procexec/         # Skill: /proc monitoring
    │   └── procexec.go
    ├── pkgmonitor/       # Skill: package changes
    │   └── pkgmonitor.go
    ├── logfreshness/     # Skill: deadman log checking
    │   └── logfreshness.go
    ├── servicehealth/    # Skill: systemd service health
    │   └── servicehealth.go
    └── auditdhealth/     # Skill: auditd health check
        └── auditdhealth.go
```

### etc/fogbot/

Configuration and skill definitions (deployed to `/etc/fogbot/`):

```
etc/fogbot/
├── config.yaml           # Main config (Telegram token, etc.)
├── config.yaml.example   # Example config with comments
├── skills-available/     # 17 prebuilt skill YAMLs
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
└── skills-enabled/       # Symlinks to enabled skills (created by user)
```

### usr/

Binary and systemd service (deployed to `/usr/`):

```
usr/
├── local/bin/
│   └── fogbot            # Main binary (after make install)
└── lib/systemd/system/
    └── fogbot.service    # Systemd unit file
```

### var/

Runtime state and data (deployed to `/var/lib/fogbot/`):

```
var/lib/fogbot/
├── state.json                 # Telegram auth state (chat_id)
├── approved-commands.json     # User-approved system commands
├── changes.log                # Config change ledger
└── suid_baseline.json         # Known-good SUID binaries (future)
```

## Default Paths

Can be overridden with environment variables:

| Path | Default | Environment Variable |
|------|---------|---------------------|
| Config | `/etc/fogbot/config.yaml` | `FOGBOT_CONFIG` |
| State directory | `/var/lib/fogbot/` | `FOGBOT_STATE_DIR` |
| Skills available | `/etc/fogbot/skills-available/` | `FOGBOT_SKILLS_AVAILABLE` |
| Skills enabled | `/etc/fogbot/skills-enabled/` | `FOGBOT_SKILLS_ENABLED` |

## Testing Paths

For development/testing without touching system paths:

```bash
export FOGBOT_CONFIG=$PWD/etc/fogbot/config.yaml
export FOGBOT_STATE_DIR=/tmp/fogbot-test
export FOGBOT_SKILLS_AVAILABLE=$PWD/etc/fogbot/skills-available
export FOGBOT_SKILLS_ENABLED=$PWD/etc/fogbot/skills-enabled
```

# fogbot

> *"They don't fire unless compromised. They watch, they listen, they report."*

A Go daemon that configures and monitors multiple detection subsystems on a Linux
host, reporting anomalies as structured SALUTE-style alerts over Telegram.

Based on the doctrine of Forward Observers, a critical team in warfare responsible
for tracking enemy activity and reporting back to HQ using SALUTE reports.

As developers we are uniquely placed to be exploited by adversaries for the purposes
of espionage or access to customers systems. One of the biggest hacks in history, 
SolarWinds, started with the exploitation of a developers computer.

This is a tool for protecting the Linux machines of developers using intrusion detection
methods, with instant notifications going to Telegram by way of a Telegram bot.

## Quick Start

```bash
# Build
make build

# List available skills
./fogbot skill list

# Enable a skill
./fogbot skill enable ssh-monitor

# Run in Docker Compose for testing
make docker-up
make docker-logs
```

## Development

```bash
# Build and test
make build
make test-cli

# Run with dry-run mode (no system modifications)
FOGBOT_DRY_RUN=true ./fogbot daemon

# Build Debian package
make package
```

## Directory Structure

```
fogbot/
├── cmd/fogbot/           # Main application entry point
├── internal/             # Internal packages
│   ├── auth/            # TOFU authentication
│   ├── config/          # Configuration management
│   ├── dedup/           # Alert deduplication
│   ├── dropin/          # Drop-in file management
│   ├── notifier/        # Alert notification (Telegram, etc.)
│   └── skills/          # Skill management
├── etc/                 # Package files (deployed to /etc)
│   └── fogbot/
│       ├── config.yaml
│       ├── skills-available/
│       └── skills-enabled/
├── usr/                 # Package files (deployed to /usr)
│   ├── local/bin/
│   └── lib/systemd/system/
└── var/                 # Package files (deployed to /var)
    └── lib/fogbot/
```

## Configuration

Configuration via environment variables:

- `FOGBOT_CONFIG` - Path to config.yaml (default: /etc/fogbot/config.yaml)
- `FOGBOT_STATE_DIR` - State directory (default: /var/lib/fogbot)
- `FOGBOT_SKILLS_AVAILABLE` - Skills available directory
- `FOGBOT_SKILLS_ENABLED` - Skills enabled directory
- `FOGBOT_DRY_RUN` - Dry-run mode (true/false)

## Included Skills

| ID  | Skill Name        | Description                                          | Impl | Tested |
|-----|-------------------|------------------------------------------------------|------|--------|
| 100 | ssh-monitor       | SSH brute force, new-IP logins, root login           | ✅   |        |
| 200 | suid-sweep        | Monitor SUID/SGID binaries for changes               | ✅   |        |
| 210 | proc-exec         | Track process executions via auditd                  | ✅   |        |
| 300 | pkg-monitor       | Alert on package installs/removals                   | ✅   |        |
| 400 | log-freshness     | Detect stale/tampered log files                      | ✅   |        |
| 410 | service-health    | Monitor critical systemd services                    | ✅   | ✅     |
| 420 | auditd-health     | Ensure auditd is running                             | ✅   |        |
| 500 | file-watch        | Watch critical system files (passwd, shadow, etc)    | ❌   |        |
| 510 | port-tripwires    | Alert on connections to specific closed ports        | ✅   |        |
| 520 | cron-watch        | Monitor cron file changes                            | ❌   |        |
| 530 | fs-anomaly        | Filesystem integrity monitoring                      | ❌   |        |
| 540 | dir-watch         | Watch directories for new files                      | ✅   |  ✅    |
| 550 | systemd-watch     | Detect daemon-reload and unit changes via D-Bus      | ✅   |  ✅    |
| 600 | rkhunter          | Rootkit detection wrapper                            | ❌   |        |
| 610 | chkrootkit        | Rootkit detection wrapper                            | ❌   |        |
| 700 | kernel-mod        | Alert on kernel module loads                         | ❌   |        |
| 710 | net-watch         | Monitor network connections                          | ❌   |        |
| 715 | net-discover      | Detect new network interfaces                        | ❌   |        |
| 800 | bpftrace-exec     | eBPF-based execution monitoring                      | ❌   |        |
| 900 | resource-anomaly  | CPU/memory anomaly detection                         | ❌   |        |

## Phase 1 & 1.5 Complete

✅ Core infrastructure implemented:
- Project scaffold and package structure
- Skill system with 20 prebuilt skills (100-900 series)
- Configuration management with SIGHUP reload
- Notifier interface with Telegram implementation
- TOFU authentication with challenge-response
- Improved auth flow: `/start` generates code on-demand, scans any message for code
- Command handlers: `/start`, `/help` (context-aware), `/reset` (deauthorize)
- SALUTE-formatted alerts (🔴 CONTACT, 🟡 MOVEMENT, 🟢 NOMINAL)
- Deduplication and rate limiting (10 auth/60s, 3 unauth lifetime)
- Drop-in file management with SHA256 ledger
- CLI with skill management commands
- Docker Compose test environment with proper capabilities
- Dry-run mode for system modifications
- 10 skills fully implemented and ready to use

## Phase 2 & 2.5 - In Progress

🚧 Currently implementing skill watchers and testing:

**Phase 2 - Skill Implementation:**
- ✅ 10 skills with full implementations (ssh-monitor, suid-sweep, proc-exec, pkg-monitor, log-freshness, service-health, auditd-health, port-tripwires, dir-watch, systemd-watch)
- 🔄 Testing and debugging active skills
- 🔄 Implementing remaining skills (file-watch, cron-watch, fs-anomaly, kernel-mod, net-watch, etc.)
- 🔄 Integrating skills with Telegram alert pipeline
- ✅ Self-watch monitoring (fogbot monitors its own binary and config files)

**Phase 2.5 - Refinement:**
- ✅ Command approval workflow for system-modifying skills
- Skill configuration validation and error handling
- Enhanced logging and debugging for skill lifecycle
- Alert deduplication tuning
- Performance optimization for long-running watchers

## Pictures
<img width="381" height="268" alt="image" src="https://github.com/user-attachments/assets/c7876d8e-71f3-4924-a91a-d608b19203b5" />
<img width="347" height="225" alt="image" src="https://github.com/user-attachments/assets/17681de9-39fb-49df-8a98-0c62088577be" />
<img width="324" height="317" alt="image" src="https://github.com/user-attachments/assets/cf2f5f0e-7aa0-4c75-b689-c8757b45add3" />



## License

See plan.md for full specification.

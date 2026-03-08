# fogbot

> *"They don't fire unless compromised. They watch, they listen, they report."*

A Go daemon that configures and monitors multiple detection subsystems on a Linux host, reporting anomalies as structured SALUTE-style alerts over Telegram.

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

## Phase 1 & 1.5 Complete

✅ Core infrastructure implemented:
- Project scaffold and package structure
- Skill system with 17 prebuilt skills (100-900 series)
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

## License

See plan.md for full specification.

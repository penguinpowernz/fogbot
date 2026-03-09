# fogbot Quick Reference

## Build & Test

```bash
make build          # Compile
make test-cli       # Run CLI tests
make docker-up      # Start Docker Compose test env
make docker-logs    # View logs
make package        # Build Debian package
```

## Commands

```bash
./fogbot skill list            # List available skills
./fogbot skill enable <skill>  # Enable a skill
./fogbot daemon                # Run as daemon

# Dry-run mode (no system changes)
FOGBOT_DRY_RUN=true ./fogbot daemon
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FOGBOT_CONFIG` | `/etc/fogbot/config.yaml` | Config file path |
| `FOGBOT_STATE_DIR` | `/var/lib/fogbot` | State directory |
| `FOGBOT_SKILLS_AVAILABLE` | - | Skills available dir |
| `FOGBOT_SKILLS_ENABLED` | - | Skills enabled dir |
| `FOGBOT_DRY_RUN` | false | Dry-run mode |

## Alert Format

- **🔴 CONTACT** - Security anomaly detected
- **🟡 MOVEMENT** - Pending/investigating
- **🟢 NOMINAL** - All systems normal

## Telegram Commands

- `/start` - Begin authentication (generates code)
- `/help` - Context-aware help
- `/reset` - Deauthorize

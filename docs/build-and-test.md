# Build & Test Commands

## Build

```bash
# Build fogbot binary
make build

# Install to package structure (usr/local/bin/)
make install

# Clean build artifacts
make clean
```

## Testing

```bash
# Run Go tests
make test

# Test CLI with correct environment variables
make test-cli
```

## Docker Development (Recommended)

```bash
# Start fogbot in Docker Compose
make docker-up

# Follow logs
make docker-logs

# Open shell in container
make docker-shell

# Stop container
make docker-down
```

## Using fogbot in Docker Container

```bash
# Enable skill 510
docker-compose exec -T fogbot fogbot s e 510

# List skills
docker-compose exec -T fogbot fogbot s l

# Disable skill
docker-compose exec -T fogbot fogbot s d 510

# Show skill info
docker-compose exec -T fogbot fogbot skill info 510
```

## Packaging

```bash
# Build Debian package with ian
make package
```

## Environment Variables for Testing

Use these to avoid touching system paths during development:

```bash
export FOGBOT_CONFIG=$PWD/etc/fogbot/config.yaml
export FOGBOT_STATE_DIR=/tmp/fogbot-test
export FOGBOT_SKILLS_AVAILABLE=$PWD/etc/fogbot/skills-available
export FOGBOT_SKILLS_ENABLED=$PWD/etc/fogbot/skills-enabled
export FOGBOT_DRY_RUN=true  # Prevent actual system modifications
```

## Dry-Run Mode

Set `FOGBOT_DRY_RUN=true` to prevent system modifications:
- All detection logic runs normally
- Alerts formatted and logged
- No iptables/auditd rules written
- No actual system commands executed

Perfect for testing without root privileges or system changes.

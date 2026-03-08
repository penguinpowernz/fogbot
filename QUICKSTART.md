# fogbot Quick Start Guide

## Installation

### Build from Source

```bash
# Clone and build
cd fogbot
make build

# Install to package structure
make install
```

### Using Docker Compose (Recommended for Testing)

```bash
# Start fogbot in Docker
make docker-up

# View logs
make docker-logs

# Stop
make docker-down
```

## Configuration

### 1. Create Config File

```bash
cp etc/fogbot/config.yaml.example etc/fogbot/config.yaml
```

### 2. Get Telegram Bot Token

1. Message [@BotFather](https://t.me/botfather) on Telegram
2. Create new bot: `/newbot`
3. Copy the token
4. Add to `etc/fogbot/config.yaml`:

```yaml
telegram:
  token: "YOUR_BOT_TOKEN_HERE"
  chat_id: 0  # Will be set automatically after auth

host_label: "my-server"
```

## First Run

### Start the Daemon

```bash
# Using Docker
make docker-up
make docker-logs

# Or directly (requires root for some capabilities)
sudo ./fogbot daemon
```

### Authorize Your Telegram Chat

1. Watch the logs for the authorization code:
   ```
   Authorization code: FOG-A3X9-K2M7
   ```

2. Open Telegram and message your bot: `/start`

3. Bot will ask for the code - send it:
   ```
   FOG-A3X9-K2M7
   ```

4. Once authorized, the bot will respond to commands!

### Test It

Send to your bot:
- `hi` - Should get "fogbot online" response
- `/status` - Get status summary

## Enable Detection Skills

### List Available Skills

```bash
# Set environment for testing
export FOGBOT_SKILLS_AVAILABLE=$PWD/etc/fogbot/skills-available
export FOGBOT_SKILLS_ENABLED=$PWD/etc/fogbot/skills-enabled

# List all skills
./fogbot skill list
```

Output:
```
 ID   SKILL              STATUS    REQUIRES              DESCRIPTION
 ───  ─────────────────  ────────  ────────────────────  ──────────────────────────────────────
 100  ssh-monitor        disabled  auth.log read access  Monitors /var/log/auth.log for SSH...
 200  suid-sweep         disabled  auditd +1             Dual detection: auditd watches...
 ...
```

### Enable a Skill

```bash
./fogbot skill enable ssh-monitor

# Reload the daemon to activate
sudo systemctl reload fogbot
# or in Docker:
docker-compose restart
```

### Get Skill Details

```bash
./fogbot skill info ssh-monitor
```

## Environment Variables

For testing without modifying system paths:

```bash
export FOGBOT_CONFIG=$PWD/etc/fogbot/config.yaml
export FOGBOT_STATE_DIR=/tmp/fogbot-test
export FOGBOT_SKILLS_AVAILABLE=$PWD/etc/fogbot/skills-available
export FOGBOT_SKILLS_ENABLED=$PWD/etc/fogbot/skills-enabled
export FOGBOT_DRY_RUN=true  # Prevent actual system modifications
```

## Dry-Run Mode

Test without modifying your system:

```bash
FOGBOT_DRY_RUN=true ./fogbot daemon
```

In dry-run mode:
- ✅ All detection logic runs normally
- ✅ Alerts are formatted and logged
- ❌ No iptables rules written
- ❌ No auditd rules written
- ❌ No system files modified

## Skill Categories

- **1xx** - Auth monitoring (SSH, sudo, login events)
- **2xx** - Process/execution monitoring
- **3xx** - Package management monitoring
- **4xx** - Deadman/health checks (services, logs)
- **5xx** - File integrity & filesystem
- **6xx** - Rootkit scanners (rkhunter, chkrootkit)
- **7xx** - Kernel & network monitoring
- **8xx** - Advanced (bpftrace)
- **9xx** - Resource anomalies

## Alert Severity

- 🔴 **CONTACT** - Immediate, single event (file modified, new SUID, shell from nginx)
- 🟡 **MOVEMENT** - Rate-limited digest (SSH brute force, port scans)
- 🟢 **NOMINAL** - Lifecycle (startup, shutdown, baseline approvals)

## Common Commands

```bash
# Build
make build

# Test CLI
make test-cli

# Docker Compose
make docker-up      # Start container
make docker-logs    # View logs
make docker-shell   # Open shell in container
make docker-down    # Stop container

# Skill management
fogbot skill list
fogbot skill enable <name>
fogbot skill disable <name>
fogbot skill info <name>

# Version
fogbot version
```

## Troubleshooting

### Bot not responding?

1. Check logs: `make docker-logs` or `journalctl -u fogbot -f`
2. Verify token in config: `etc/fogbot/config.yaml`
3. Check authorization: Look for "Authorization code:" in logs
4. Test network: `docker-compose exec fogbot ping -c 3 api.telegram.org`

### Skills not loading?

1. Check symlinks: `ls -la etc/fogbot/skills-enabled/`
2. Reload daemon: `systemctl reload fogbot` or restart container
3. Check YAML syntax: `cat etc/fogbot/skills-available/100-ssh-monitor.yaml`

### Permission denied?

- fogbot requires root or specific capabilities (CAP_NET_ADMIN, CAP_AUDIT_CONTROL)
- Docker Compose sets these automatically
- For systemd, see `fogbot.service` for capability requirements

## Next Steps

1. **Phase 2**: Actual skill implementations (currently just skeleton)
2. **Enable skills**: Start with low-impact ones (400-log-freshness, 410-service-health)
3. **Tune alerts**: Adjust thresholds in skill YAML files
4. **Deploy**: Use `ian build` to create .deb package for production

## Learn More

- `plan.md` - Full specification and roadmap
- `README.md` - Overview and architecture
- Skill YAMLs in `etc/fogbot/skills-available/` - Each has "why:" explanation

# fogbot: Deployment & Configuration

## Deployment

- Runs as a systemd service (provided unit file)
- Requires `root` or `CAP_NET_ADMIN + CAP_AUDIT_CONTROL + CAP_SYS_PTRACE`
- On startup: configures all enabled sensors (injects iptables rules, writes auditd rules, takes baselines), sends 🟢 **NOMINAL** online message to Telegram
- On shutdown (SIGTERM): sends 🟢 **NOMINAL** offline message to Telegram — **rules are left in place**
- State stored in `/var/lib/fogbot/`
- Logs to journald

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

## Project Structure

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
│   ├── skills-available/   # 18 prebuilt skill YAMLs
│   └── skills-enabled/     # Operator-created symlinks
├── usr/local/bin/          # fogbot binary (deployed)
├── usr/lib/systemd/system/ # fogbot.service
├── var/lib/fogbot/         # State, ledger, baselines
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── README.md
```

---

## Environment Variables

For testing and non-standard deployments, fogbot respects these environment variables:

| Variable | Default | Purpose |
|----------|---------|---------|
| `FOGBOT_CONFIG` | `/etc/fogbot/config.yaml` | Path to main config file |
| `FOGBOT_STATE_DIR` | `/var/lib/fogbot` | State, baselines, ledger |
| `FOGBOT_SKILLS_AVAILABLE` | `/etc/fogbot/skills-available` | Skill YAML library |
| `FOGBOT_SKILLS_ENABLED` | `/etc/fogbot/skills-enabled` | Active skill symlinks |
| `FOGBOT_DRY_RUN` | `false` | If `true`, skip all writes (testing mode) |

---

## Systemd Service

```ini
[Unit]
Description=fogbot intrusion detection daemon
After=network.target auditd.service

[Service]
Type=simple
ExecStart=/usr/local/bin/fogbot daemon
Restart=always
RestartSec=10

# Capabilities for non-root operation (alternative to root)
# AmbientCapabilities=CAP_NET_ADMIN CAP_AUDIT_CONTROL CAP_SYS_PTRACE
# CapabilityBoundingSet=CAP_NET_ADMIN CAP_AUDIT_CONTROL CAP_SYS_PTRACE

# Or run as root
User=root
Group=root

# Security hardening (when not running as root)
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/fogbot /etc/fogbot/skills-enabled

[Install]
WantedBy=multi-user.target
```

---

## Docker Compose (Development)

```yaml
version: '3.8'
services:
  fogbot:
    build: .
    container_name: fogbot
    volumes:
      - ./etc/fogbot:/etc/fogbot
      - ./var/lib/fogbot:/var/lib/fogbot
    environment:
      - FOGBOT_DRY_RUN=false
      - TELEGRAM_TOKEN=${TELEGRAM_TOKEN}
    cap_add:
      - NET_ADMIN
      - AUDIT_CONTROL
      - SYS_PTRACE
    restart: unless-stopped
```

---

## Makefile Targets

```makefile
.PHONY: build test docker-up docker-logs docker-down package clean install

build:
	go build -o fogbot ./cmd/fogbot

test:
	go test -v ./...

install: build
	sudo cp fogbot /usr/local/bin/
	sudo mkdir -p /etc/fogbot /var/lib/fogbot
	sudo cp -r etc/fogbot/* /etc/fogbot/
	sudo cp usr/lib/systemd/system/fogbot.service /etc/systemd/system/
	sudo systemctl daemon-reload

docker-up:
	docker-compose up -d

docker-logs:
	docker-compose logs -f

docker-down:
	docker-compose down

package:
	# ian package build (Debian)
	ian build

clean:
	rm -f fogbot
	docker-compose down -v
```

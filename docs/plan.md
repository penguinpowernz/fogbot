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
- ✅ 19 detection skills defined (100-900 series) with complete YAML metadata
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

### What's Next
- **Phase 2:** Implement actual skill watchers (ssh-monitor, suid-sweep, proc-exec, etc.)
- **Phase 2.5:** Wire skills to Telegram alert pipeline, self-watch
- **Phase 3:** Status reports, presence system, startup/shutdown messages

---

## Documentation Index

This plan has been split into focused documents for easier navigation:

### Core Planning Documents
- **[plan_phases.md](plan_phases.md)** — Detailed phase-by-phase delivery plan (Phases 1-6)
- **[plan_skills.md](plan_skills.md)** — Complete skill library reference with all 18 detection skills
- **[plan_architecture.md](plan_architecture.md)** — System architecture, interfaces, and design decisions
- **[plan_alerts.md](plan_alerts.md)** — Alert structure (SALUTE format), status reports, presence system
- **[plan_security.md](plan_security.md)** — Authentication (TOFU), command interface security, rate limiting
- **[plan_deployment.md](plan_deployment.md)** — Deployment, configuration, systemd, Docker, Makefile

### Additional Documentation
- **[skills-architecture.md](skills-architecture.md)** — ⚠️ **READ THIS FIRST** when working with skills — Command deduction and approval workflow
- **[adding-new-skill.md](adding-new-skill.md)** — Step-by-step guide to implementing new detection skills
- **[build-and-test.md](build-and-test.md)** — How to build, test, and run fogbot in Docker
- **[directory-structure.md](directory-structure.md)** — Where everything lives in the codebase
- **[alerts-and-notifications.md](alerts-and-notifications.md)** — SALUTE format, Telegram auth, deduplication

---

## Quick Reference

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

### Key Concepts

**LP/OP Doctrine:** "They don't fire unless compromised. They watch, they listen, they report."

**Skills:** Self-contained detection modules (19 defined: 100-900 series)
- Enable via symlink: `/etc/fogbot/skills-enabled/` → `/etc/fogbot/skills-available/`
- Each skill has YAML metadata: id, name, description, why, requires, config
- Skills use **command deduction** — config is declarative, commands generated at enable time
- **User approval required** before any system modification (Phase 1.5 enhancement)

**Alert Severity:**
- 🔴 **CONTACT** — immediate single alert (file integrity, new SUID, shell from unexpected parent)
- 🟡 **MOVEMENT** — rate-limited digest (SSH brute force, port scan)
- 🟢 **NOMINAL** — lifecycle (startup, shutdown, baseline approval)

**TOFU Auth:** Operator proves shell access by reading code from logs before bot responds

---

## Development Workflow

```bash
# Build and test locally
make build && make install

# Run in Docker (recommended)
make docker-up
make docker-logs

# Enable a skill in docker
docker-compose exec -T fogbot fogbot skill enable 510

# Rebuild after code changes
make build && make install
docker-compose restart
```

---

## Design Principles

1. **Declarative over imperative** - Skills declare what to watch, not how
2. **User approval for system changes** - Never modify system without explicit approval
3. **Idempotent configuration** - Can re-apply configs safely
4. **Transparent operation** - All commands logged, approval tracked
5. **Non-obvious identifiers** - Use `fw-510-in` not `TRIPWIRE-IN` in system configs
6. **Startup repair** - Auto-fix missing configs using previously approved commands

---

## Out of Scope (initially)

- Automated response / active countermeasures (LP/OP doctrine: observe and report only)
- Web UI
- Multi-host aggregation
- SIEM integration (though structured JSON logs could feed one)

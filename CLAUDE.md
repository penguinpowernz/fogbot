# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**fogbot** is a Linux intrusion detection daemon that monitors multiple detection subsystems and reports anomalies via Telegram. It follows the LP/OP doctrine: "They don't fire unless compromised. They watch, they listen, they report."

**Current status:** Phase 1.5 complete - Core infrastructure, Telegram auth/notification, skill system, and command approval workflow all working.

## Quick Reference

### Essential Documentation

- **[Build & Test Commands](docs/build-and-test.md)** - How to build, test, and run fogbot in Docker
- **[Skills Architecture](docs/skills-architecture.md)** - **READ THIS FIRST** - Understanding the command deduction and approval workflow
- **[Adding New Skills](docs/adding-new-skill.md)** - Step-by-step guide to implementing new detection skills
- **[Directory Structure](docs/directory-structure.md)** - Where everything lives in the codebase
- **[Alerts & Notifications](docs/alerts-and-notifications.md)** - SALUTE format, Telegram auth, deduplication

### Additional Resources

- **[Full Specification](docs/plan.md)** - Complete project plan with all phases and sensor descriptions
- **[Troubleshooting Guide](docs/TROUBLESHOOTING.md)** - Common issues and solutions
- **[Bug Fixes Log](docs/BUGFIXES.md)** - History of bugs fixed during development
- **[Quick Start Guide](QUICKSTART.md)** - End-user guide to getting started with fogbot
- **[README](README.md)** - Project overview and high-level architecture

## Most Important Concept: Skills with Command Approval

⚠️ **Critical architectural change (Phase 1.5):**

Skills that modify the system (iptables, auditd) now use **command deduction** instead of hardcoded commands:

1. Skill YAML contains **only declarative config** (what to watch), NOT commands
2. Skill implementation **deduces commands** from config at enable time
3. User **must approve** before commands execute (colored CLI prompt)
4. Approved commands **tracked in JSON** for audit trail
5. On startup, fogbot **checks system state** and re-applies if needed

**Example:** Port tripwires skill (510) doesn't store iptables commands in YAML. It generates them from the port list when user enables it, shows them for approval, then executes.

See [docs/skills-architecture.md](docs/skills-architecture.md) for complete details.

## Quick Start Development

```bash
# Build and test locally
make build && make install

# Run in Docker (recommended)
make docker-up
make docker-logs

# Enable a skill in docker
docker-compose exec -T fogbot fogbot s e 510

# Rebuild after code changes
make build && make install
docker-compose restart
```

## Key Design Principles

1. **Declarative over imperative** - Skills declare what to watch, not how
2. **User approval for system changes** - Never modify system without explicit approval
3. **Idempotent configuration** - Can re-apply configs safely
4. **Transparent operation** - All commands logged, approval tracked
5. **Non-obvious identifiers** - Use `fw-510-in` not `TRIPWIRE-IN` in system configs
6. **Startup repair** - Auto-fix missing configs using previously approved commands

## Project Status: Phase 1.5 Complete

✅ **Working:**
- Full project structure with Debian packaging layout
- 17 detection skills defined (YAML only, most not implemented)
- Telegram TOFU auth with `/start` command
- SALUTE-formatted alerts
- Drop-in file management with ledger
- Alert deduplication
- **Command approval workflow with colored CLI**
- **Approval tracking and revocation**
- **System state checking and startup reapplication**

🚧 **Next (Phase 2):**
- Implement actual skill watchers (ssh-monitor, suid-sweep, proc-exec, etc.)
- Wire skills to Telegram alert pipeline
- Self-watch (fogbot monitors its own files)

## When Working on This Codebase

1. **Always read [docs/skills-architecture.md](docs/skills-architecture.md)** before adding/modifying skills
2. **Test in Docker** using `make docker-up` and `docker-compose exec`
3. **Use environment variables** to avoid touching system paths during development
4. **Follow the approval workflow pattern** for any skill that modifies system state
5. **Update skill registration** in both `cmd/fogbot/main.go` and `cmd/fogbot/skill.go`

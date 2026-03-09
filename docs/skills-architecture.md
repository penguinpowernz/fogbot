# Skills Architecture

## Overview

Skills are the core detection units in fogbot. Each skill monitors a specific aspect of the system and generates alerts.

## Skill Lifecycle & Command Approval Workflow

Skills that require system changes (iptables, auditd) follow this pattern:

1. **Declarative config** - Skill YAML contains only configuration (e.g., ports to watch), NOT hardcoded commands
2. **Command deduction** - Skill implementation's `DeduceCommands()` generates actual commands from config at enable time
3. **User approval** - Commands shown to user with colored formatting, approval required
4. **Approval tracking** - Approved commands stored in `/var/lib/fogbot/approved-commands.json`
5. **System state checking** - `CheckSystemState()` verifies if config already exists in system
6. **Startup reapplication** - If enabled skill's config missing from system, fogbot re-applies previously approved commands

## Example: Port Tripwires (Skill 510)

### Wrong Way (Old Pattern)

```yaml
# etc/fogbot/skills-available/510-port-tripwires.yaml
commands:
  - "iptables -A INPUT ... --log-prefix 'TRIPWIRE-IN: '"
config:
  watch_inbound: [135, 139, 445]
```

### Correct Way (New Pattern)

```yaml
# etc/fogbot/skills-available/510-port-tripwires.yaml
requires_approval: true
config:
  watch_inbound: [135, 139, 445, 4444, 31337, 12345]
  watch_outbound: [4444, 1080, 25, 3333, 5555, 7777, 14444]
```

The skill implementation deduces commands:

```go
// internal/skills/porttripwires/porttripwires.go
func (p *PortTripwires) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
    // Generates iptables commands with non-obvious prefixes like "fw-510-in:"
    // Built from config at runtime, not hardcoded
}

func (p *PortTripwires) CheckSystemState() (bool, error) {
    // Checks if iptables rules already exist by looking for rule identifiers
    // Returns true if already configured, false if commands need to run
}
```

## Skill Interface

All skills must implement:

```go
type Skill interface {
    ID() int
    Name() string
    Description() string
    Why() string              // Explanation of security value
    Requires() []string       // Dependencies (e.g., ["iptables", "root"])
    Tags() []string
    DropIns() []DropIn        // Config files this skill manages

    Configure(cfg map[string]interface{}) error

    // NEW: Command deduction and system state checking
    DeduceCommands(cfg map[string]interface{}) ([]SystemCommand, error)
    CheckSystemState() (bool, error)

    Watch(ctx context.Context) (<-chan notifier.Alert, error)
    Enabled() bool
    SetEnabled(enabled bool)
    Config() map[string]interface{}
}
```

## Legacy Skills (No System Changes Required)

Skills like ssh-monitor that only read log files don't need system changes. They have stub implementations:

```go
func (s *SSHMonitor) DeduceCommands(cfg map[string]interface{}) ([]SystemCommand, error) {
    return []SystemCommand{}, nil  // No commands needed
}

func (s *SSHMonitor) CheckSystemState() (bool, error) {
    return true, nil  // Always "configured"
}
```

## Command Approval Flow

When user runs `fogbot skill enable 510`:

1. Load skill config from `skills-available/510-port-tripwires.yaml`
2. Instantiate skill implementation
3. Check `CheckSystemState()` - if already configured, skip approval
4. If not configured:
   - Call `DeduceCommands()` to generate commands
   - Show colored approval prompt with:
     - Skill's "why" explanation
     - Each command with description
     - Note about startup reapplication
   - Wait for user approval (y/N)
5. If approved:
   - Record approval in `/var/lib/fogbot/approved-commands.json`
   - Execute commands
   - Create symlink in `skills-enabled/`

## Command Revocation

When user runs `fogbot skill disable 510`:

1. Remove symlink from `skills-enabled/`
2. **Revoke all approvals** for that skill from approved-commands.json
3. Next enable will require fresh approval

This ensures users must re-approve commands if they re-enable a skill.

## Startup Reapplication

On fogbot daemon startup, for each enabled skill with `requires_approval: true`:

1. Call `CheckSystemState()` to verify config exists
2. If missing:
   - Load approved commands from `/var/lib/fogbot/approved-commands.json`
   - Re-execute approved commands (no prompt needed)
   - Log the reapplication
   - Send alert about configuration repair

This ensures fogbot self-heals if iptables rules are flushed or system rebooted.

## Skill Registration

Skills must be registered in two places:

### 1. Daemon (cmd/fogbot/main.go)

```go
registry := skills.NewRegistry()
registry.Register(sshmonitor.New())
registry.Register(porttripwires.New(cfg))
```

### 2. CLI Enable Command (cmd/fogbot/skill.go)

```go
func instantiateSkill(cfg skills.SkillConfig) skills.Skill {
    switch cfg.ID {
    case 510:
        return porttripwires.New(cfg)
    case 100:
        return sshmonitor.New()
    // Add more as implemented
    default:
        return nil  // Falls back to old symlink-only method
    }
}
```

## Skills-Available vs Skills-Enabled

Similar to Apache's `sites-available` / `sites-enabled`:

- `skills-available/` - All skill YAML definitions (shipped with fogbot)
- `skills-enabled/` - Symlinks to enabled skills

Example:
```bash
# Enable creates symlink
fogbot skill enable ssh-monitor
→ /etc/fogbot/skills-enabled/100-ssh-monitor.yaml → ../skills-available/100-ssh-monitor.yaml

# CLI accepts short names or IDs
fogbot skill enable ssh-monitor
fogbot skill enable 100
```

## Skill Numbering Convention

- **1xx** - Auth monitoring (SSH, sudo, login)
- **2xx** - Process/execution monitoring
- **3xx** - Package management
- **4xx** - Deadman/health checks (services, logs)
- **5xx** - File integrity & filesystem (requires drop-ins)
- **6xx** - Rootkit scanners (optional tools)
- **7xx** - Kernel & network
- **8xx** - Advanced (bpftrace)
- **9xx** - Resource anomalies

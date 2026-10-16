# Adding a New Skill

This guide shows how to add a new skill with the command deduction and approval workflow.

Every skill has its own directory, `internal/skills/<skill>/`, holding its
README and its code. See [internal/skills/README.md](../internal/skills/README.md).

## Step 1: Create Skill YAML

Create `usr/share/fogbot/contrib/skills-available/520-cron-watch.yaml` with declarative config only:

```yaml
id: 520
name: cron-watch
description: >
  Monitors cron directories for new or modified entries.
  Detects scheduled task persistence via crontab modifications.
why: >
  Attackers frequently use cron for persistence. A new cron entry
  appearing outside of package management is a strong indicator
  of compromise.
requires:
  - inotify
  - /etc/cron.d/ read access
tags: [persistence, scheduled-tasks]
severity_default: red
requires_approval: false  # Only monitoring, no system changes
config:
  watch_paths:
    - /etc/cron.d/
    - /etc/cron.daily/
    - /etc/cron.hourly/
    - /var/spool/cron/
  ignore_packages: true  # Skip alerts for dpkg-installed cron files
```

**Important:**
- Don't include `commands:` field
- Set `requires_approval: true` if skill needs to run system commands (informational: the enabler always prompts before running any command `DeduceCommands()` returns)
- Only include declarative configuration in `config:` section

## Step 2: Write the README

Create `internal/skills/cronwatch/README.md`, following the existing ones
(e.g. [port-tripwires](../internal/skills/porttripwires/README.md)):

- **What it's for**: the attacker behaviour it catches and why that matters
- **How it works**: what it watches, any system commands it needs approved, and
  a table of the alerts it raises with their severity
- **Requirements**
- **Configuration**: where the YAML lives, the shipped `config:` block, and a
  table of every key with its default
- **Examples**: config for real situations, especially tripwire and canary uses
  ("watch port 3389 even if you don't run RDP")
- **Enabling**: the `fogbot skill enable` command

The directory is the skill's name without dashes (`cron-watch` → `cronwatch`).
Add the skill to the table in `internal/skills/README.md`. `layout_test.go`
fails if a shipped skill has no README.

## Step 3: Implement Skill Package

Create `internal/skills/cronwatch/cronwatch.go`:

```go
package cronwatch

import (
    "context"
    "github.com/penguinpowernz/fogbot/internal/notifier"
    "github.com/penguinpowernz/fogbot/internal/skills"
)

type CronWatch struct {
    id          int
    name        string
    description string
    why         string
    requires    []string
    tags        []string
    enabled     bool
    config      map[string]interface{}
}

func New(cfg skills.SkillConfig) *CronWatch {
    return &CronWatch{
        id:          cfg.ID,
        name:        cfg.Name,
        description: cfg.Description,
        why:         cfg.Why,
        requires:    cfg.Requires,
        tags:        cfg.Tags,
        config:      cfg.Config,
        enabled:     false,
    }
}

// Interface implementations
func (c *CronWatch) ID() int                         { return c.id }
func (c *CronWatch) Name() string                    { return c.name }
func (c *CronWatch) Description() string             { return c.description }
func (c *CronWatch) Why() string                     { return c.why }
func (c *CronWatch) Requires() []string              { return c.requires }
func (c *CronWatch) Tags() []string                  { return c.tags }
func (c *CronWatch) Enabled() bool                   { return c.enabled }
func (c *CronWatch) SetEnabled(enabled bool)         { c.enabled = enabled }
func (c *CronWatch) Config() map[string]interface{}  { return c.config }
func (c *CronWatch) DropIns() []skills.DropIn        { return nil }

func (c *CronWatch) Configure(cfg map[string]interface{}) error {
    c.config = cfg
    return nil
}

// DeduceCommands - this skill doesn't need system changes
func (c *CronWatch) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
    return []skills.SystemCommand{}, nil
}

// CheckSystemState - always ready (no setup needed)
func (c *CronWatch) CheckSystemState() (bool, error) {
    return true, nil
}

// Watch - actual detection logic
func (c *CronWatch) Watch(ctx context.Context) (<-chan notifier.Alert, error) {
    alerts := make(chan notifier.Alert)

    go func() {
        defer close(alerts)

        // TODO: Implement inotify watching of cron paths
        // When new file detected or modified, send alert

        <-ctx.Done()
    }()

    return alerts, nil
}
```

## Step 4: Register Skill in Daemon

Edit `cmd/fogbot/main.go`:

```go
import (
    // ... existing imports ...
    "github.com/penguinpowernz/fogbot/internal/skills/cronwatch"
)

func runDaemon(cmd *cobra.Command, args []string) {
    // ... existing code ...

    registry := skills.NewRegistry()
    registry.Register(sshmonitor.New())
    registry.Register(suidsweep.New(baselineManager))
    registry.Register(cronwatch.New())  // ADD THIS

    // ... rest of function ...
}
```

## Step 5: Register Skill in CLI

Every implemented skill needs a case here, even one that changes nothing on
the system, or `fogbot skill enable` reports it has no implementation.
`instantiate_test.go` fails for any skill directory with code but no case.

Edit `cmd/fogbot/skill.go`:

```go
import (
    // ... existing imports ...
    "github.com/penguinpowernz/fogbot/internal/skills/cronwatch"
)

func instantiateSkill(cfg skills.SkillConfig) skills.Skill {
    switch cfg.ID {
    case 510:
        return porttripwires.New(cfg)
    case 520:
        return cronwatch.New(cfg)  // ADD THIS
    // ... more cases ...
    default:
        return nil
    }
}
```

## Step 6: Test the Skill

```bash
# Build with new skill
make build

# In Docker container
docker-compose exec -T fogbot fogbot skill list
# Should see: 520  cron-watch  disabled  inotify  Monitors cron directories...

# Enable it
docker-compose exec -T fogbot fogbot skill enable 520
# No approval prompt since DeduceCommands() returns no commands

# Check it's enabled
docker-compose exec -T fogbot fogbot skill list
# Should see: 520  cron-watch  enabled  ...
```

## Example: Skill with System Commands

For skills that need to run system commands (like iptables), implement `DeduceCommands()`:

```go
func (s *SkillName) DeduceCommands(cfg map[string]interface{}) ([]skills.SystemCommand, error) {
    commands := []skills.SystemCommand{}

    // Extract config
    ports, _ := extractPorts(cfg, "watch_ports")

    // Generate command
    cmd := fmt.Sprintf("iptables -A INPUT -p tcp --dport %d -j LOG --log-prefix 'fw-%d: '",
        ports[0], s.id)

    commands = append(commands, skills.SystemCommand{
        Command:     cmd,
        Description: fmt.Sprintf("Monitor port %d", ports[0]),
        Metadata: map[string]string{
            "rule_id": fmt.Sprintf("fw-%d", s.id),
            "port":    fmt.Sprintf("%d", ports[0]),
        },
    })

    return commands, nil
}

func (s *SkillName) CheckSystemState() (bool, error) {
    // Check if iptables rule exists
    cmd := exec.Command("iptables", "-L", "-n")
    output, err := cmd.CombinedOutput()
    if err != nil {
        return false, err
    }

    // Look for our rule identifier
    ruleID := fmt.Sprintf("fw-%d", s.id)
    return strings.Contains(string(output), ruleID), nil
}
```

## Design Principles

1. **Declarative over imperative** - Skills declare what to watch, not how
2. **User approval for system changes** - Implement `DeduceCommands()`; the enabler always asks before running its commands
3. **Idempotent configuration** - `CheckSystemState()` should verify config exists
4. **Non-obvious identifiers** - Use `fw-520` not `CRON-WATCH` in system configs
5. **Clear explanations** - Write good `why:` field explaining security value

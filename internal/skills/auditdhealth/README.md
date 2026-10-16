# auditd-health (420)

**DEADMAN.** Checks that `auditd` is running and that its log is still being
written.

## What it's for

[file-watch](../filewatch/README.md) and [dir-watch](../dirwatch/README.md)
see nothing without auditd. An attacker who gets root and knows the box is
audited will stop auditd, or quietly break its logging, before doing anything
else. This skill is the alarm on the alarm.

## How it works

Every `poll_interval`:

| Condition | Alert | Severity |
|---|---|---|
| `systemctl is-active auditd` isn't `active` | [DEADMAN] auditd Stopped | CONTACT |
| `log_path` doesn't exist | [DEADMAN] audit.log Missing | CONTACT |
| `log_path` not modified within `log_freshness_threshold` | [DEADMAN] Stale audit.log | CONTACT |
| Any of the above clears | [DEADMAN] Recovered: ... | NOMINAL |

Each condition alerts once when it starts and once when it clears.

## Requirements

- auditd, running under systemd

## Configuration

Set in `/etc/fogbot/skills-available/420-auditd-health.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/420-auditd-health.yaml`).

```yaml
config:
  poll_interval: 30s
  log_path: /var/log/audit/audit.log
  log_freshness_threshold: 2m
```

| Key | Default | Meaning |
|---|---|---|
| `poll_interval` | `1m` | Time between checks |
| `log_path` | `/var/log/audit/audit.log` | auditd's log file |
| `log_freshness_threshold` | `5m` | How long the log may go unwritten |

## Examples

**A quiet machine.** With only a handful of audit rules loaded, an idle
workstation can go a few minutes without an audit event. If you get stale-log
alerts that recover by themselves, raise the threshold:

```yaml
config:
  log_freshness_threshold: 10m
```

## Enabling

```bash
sudo fogbot skill enable auditd-health
```

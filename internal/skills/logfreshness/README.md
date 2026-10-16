# log-freshness (400)

**DEADMAN.** Alerts when a log file that should always be growing stops being
written, or disappears.

## What it's for

This watches for the absence of something rather than its presence. A log
going quiet means the service writing it died, logging was misconfigured, or
an attacker turned it off to cover their tracks. Deleting or truncating logs is
standard clean-up after a break-in, and it leaves no event to alert on except
the silence that follows.

## How it works

Every minute it checks each configured file's modification time:

| Condition | Alert | Severity |
|---|---|---|
| File doesn't exist | [DEADMAN] Log File Missing | CONTACT |
| Not modified within its `threshold` | [DEADMAN] Stale Log File | CONTACT |
| Either condition clears | [DEADMAN] Recovered: ... | NOMINAL |

Each condition alerts once when it starts and once when it clears, not on every
check.

## Requirements

- Read access to the logs' directories

## Configuration

Set in `/etc/fogbot/skills-available/400-log-freshness.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/400-log-freshness.yaml`).

```yaml
config:
  watch_logs:
    - path: /var/log/auth.log
      threshold: 10m
    - path: /var/log/syslog
      threshold: 5m
```

| Key | Default | Meaning |
|---|---|---|
| `watch_logs` | syslog 10m, auth.log 30m | List of `path` + `threshold` (Go duration) |
| `poll_interval` | `1m` | Time between checks |

## Examples

**Pick logs that are never quiet.** The threshold has to be longer than the
log's longest normal silence or you will get alerts every night. `auth.log` on
a workstation can be silent for hours overnight; the journal and `audit.log`
are written constantly:

```yaml
config:
  watch_logs:
    - path: /var/log/syslog
      threshold: 15m
    - path: /var/log/audit/audit.log
      threshold: 5m
```

**Systems with only the journal.** Recent Debian and Ubuntu installs may not
run rsyslog, so `/var/log/syslog` and `/var/log/auth.log` never exist and both
alert as missing. Remove them from `watch_logs`, or install rsyslog.

**Your own application.** Anything with a heartbeat log line works:

```yaml
    - path: /var/log/myapp/app.log
      threshold: 2m
```

## Enabling

```bash
sudo fogbot skill enable log-freshness
```

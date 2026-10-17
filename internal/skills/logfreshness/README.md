# log-freshness (400)

**DEADMAN.** Alerts when a log file that should always be growing stops being
written, or disappears.

## What it's for

This watches for the absence of something rather than its presence. A log
going quiet means the service writing it died, logging was misconfigured, or
an attacker turned it off to cover their tracks. Stopping the logger leaves no
event to alert on except the silence that follows; deleting the log shows up
as missing.

## How it works

Every `poll_interval` it checks each configured file's modification time:

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
| `watch_logs` | auth.log 10m, syslog 5m (as above) | List of `path` + `threshold` (Go duration). If the key is absent: syslog 10m, auth.log 30m |
| `poll_interval` | `1m` | Time between checks |

## Examples

**Pick logs that are never quiet.** The threshold has to be longer than the
log's longest normal silence or you will get alerts every night. `auth.log` on
a workstation can be silent for an hour or more, so the shipped 10m will fire
on an idle machine. Raise it or drop `auth.log`:

```yaml
config:
  watch_logs:
    - path: /var/log/syslog
      threshold: 15m
    - path: /var/log/auth.log
      threshold: 2h
```

`audit.log` is covered by [auditd-health](../auditdhealth/README.md), so
don't list it here.

**Systems with only the journal.** Recent Debian and Ubuntu installs may not
run rsyslog, so `/var/log/syslog` and `/var/log/auth.log` never exist and both
alert as missing. Remove them from `watch_logs`.

**A local service of your own.** Anything you run that writes a heartbeat
log line works:

```yaml
    - path: /var/log/myapp/app.log
      threshold: 2m
```

## Enabling

```bash
sudo fogbot skill enable log-freshness
```

# chkrootkit (610)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design.

Reads chkrootkit's output and forwards `INFECTED` and suspicious findings as
alerts.

## What it's for

chkrootkit uses different checks from [rkhunter](../rkhunter/README.md), so
running both catches more. If chkrootkit isn't installed, the skill does
nothing.

## How it will work

Follows `log_path` and raises a CONTACT alert for each `INFECTED` line (with
`alert_on_infected`) and each suspicious finding (with `alert_on_suspicious`).

## Requirements

- chkrootkit, run on a schedule with its output written to `log_path`

## Configuration

Set in `/etc/fogbot/skills-available/610-chkrootkit.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/610-chkrootkit.yaml`).

```yaml
config:
  log_path: /var/log/chkrootkit.log
  alert_on_infected: true
  alert_on_suspicious: true
```

| Key | Meaning |
|---|---|
| `log_path` | File chkrootkit's output is written to |
| `alert_on_infected` | Alert on `INFECTED` results |
| `alert_on_suspicious` | Alert on suspicious files and processes |

## Examples

**Getting a log to read.** Debian's package runs chkrootkit daily but mails
the result rather than logging it. A cron job that writes it to a file works:

```
# /etc/cron.d/chkrootkit-log
30 3 * * * root /usr/sbin/chkrootkit -q > /var/log/chkrootkit.log 2>&1
```

## Enabling

Not yet available.

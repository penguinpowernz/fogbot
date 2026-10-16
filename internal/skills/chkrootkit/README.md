# chkrootkit (610)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design.

Reads chkrootkit's output and forwards `INFECTED` and `WARNING` findings as
alerts.

## What it's for

chkrootkit uses different checks from [rkhunter](../rkhunter/README.md), so
running both catches more. If chkrootkit isn't installed, the skill does
nothing.

## How it will work

Reads `log_path` each time chkrootkit rewrites it and raises a CONTACT alert
for each `INFECTED` line (with `alert_on_infected`) and each `WARNING` line
(with `alert_on_suspicious`).

## Requirements

- chkrootkit, run on a schedule. Debian's package does this daily
  (`chkrootkit.timer`) and writes the result to `/var/log/chkrootkit/log.today`.

## Configuration

Set in `/etc/fogbot/skills-available/610-chkrootkit.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/610-chkrootkit.yaml`).

```yaml
config:
  log_path: /var/log/chkrootkit/log.today
  alert_on_infected: true
  alert_on_suspicious: true
```

| Key | Meaning |
|---|---|
| `log_path` | File chkrootkit's output is written to |
| `alert_on_infected` | Alert on `INFECTED` results |
| `alert_on_suspicious` | Alert on `WARNING` results (suspicious files, processes, sniffers) |

## Examples

**Quiet the known warnings first.** chkrootkit flags some things on most
systems. Review the `WARNING` lines in the first `log.today`, and once you're
sure a finding is harmless, add a pattern matching just that line to
`/etc/chkrootkit/chkrootkit.ignore`. `log.today` is written after that filter,
so what reaches fogbot is new.

## Enabling

Not yet available.

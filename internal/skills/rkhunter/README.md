# rkhunter (600)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design.

Reads rkhunter's log and forwards its warnings and infection findings as
alerts.

## What it's for

rkhunter is a mature rootkit scanner with its own signatures and heuristics.
If you already run it, fogbot can put its findings on your phone instead of
leaving them in a log nobody reads. If rkhunter isn't installed, the skill
does nothing.

## How it will work

Follows `log_path` and raises a CONTACT alert for each `Warning:` line (with
`alert_on_warning`) and each infection found (with `alert_on_infection`).

## Requirements

- rkhunter, run on a schedule. Debian's package ships a daily cron job but
  leaves it off; set `CRON_DAILY_RUN="yes"` in `/etc/default/rkhunter`.

## Configuration

Set in `/etc/fogbot/skills-available/600-rkhunter.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/600-rkhunter.yaml`).

```yaml
config:
  log_path: /var/log/rkhunter.log
  alert_on_warning: true
  alert_on_infection: true
```

| Key | Meaning |
|---|---|
| `log_path` | rkhunter's log file |
| `alert_on_warning` | Alert on warnings |
| `alert_on_infection` | Alert on rootkits found |

## Examples

**Quiet the known warnings first.** rkhunter warns about some things on every
stock system (commands in `/usr/bin` that are scripts, hidden files in `/etc`).
Run `sudo rkhunter --propupd` on a known-clean system (and again after package
upgrades), and whitelist the remaining known warnings by exact path
(`SCRIPTWHITELIST`, `ALLOWHIDDENFILE`) in `/etc/rkhunter.conf`, so that what
reaches fogbot is new.

## Enabling

Not yet available.

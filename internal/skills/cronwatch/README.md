# cron-watch (520)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design. Until it lands, add the cron directories to
> [dir-watch](../dirwatch/README.md) (it watches `/etc/cron.d/` by default).

Watches the places cron and at jobs live and alerts when one is added or
changed.

## What it's for

Once in, an attacker wants to stay in, and a job that runs on a schedule is
the easiest way: a cron job that re-downloads the implant every hour, or an
`at` job that brings it back later. Every one of them is a file appearing or
changing in a short list of places.

Other persistence spots belong to other skills:

- systemd services and timers: [systemd-watch](../systemdwatch/README.md)
- `~/.config/autostart/`: [dir-watch](../dirwatch/README.md)
- `/etc/rc.local`, `/etc/profile.d/`, `~/.bashrc`, `~/.profile`: [file-watch](../filewatch/README.md) with `wa`

## How it will work

inotify watches on each path; a new or modified file raises a CONTACT alert
naming it.

## Requirements

- inotify

## Configuration

Set in `/etc/fogbot/skills-available/520-cron-watch.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/520-cron-watch.yaml`).

```yaml
config:
  watch_paths:
    - /etc/crontab
    - /etc/cron.d
    - /etc/cron.daily
    - /etc/cron.hourly
    - /etc/cron.monthly
    - /etc/cron.weekly
    - /var/spool/cron/crontabs
    - /var/spool/cron/atjobs
```

| Key | Meaning |
|---|---|
| `watch_paths` | Files and directories to watch |

## Examples

**Fedora/RHEL spool paths.** The defaults are Debian's. On Red Hat-family
systems user crontabs and at jobs live elsewhere:

```yaml
    - /var/spool/cron
    - /var/spool/at
```

**anacron.** If anacron is installed, add `/etc/anacrontab` too.

## Enabling

Not yet available.

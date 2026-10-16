# systemd-watch (550)

Listens to systemd on D-Bus and alerts when units are reloaded or unit files
change on disk.

## What it's for

A systemd service is the most common way to persist on a modern Linux box: drop
a unit file in `/etc/systemd/system`, `daemon-reload`, enable it, done. Both
steps show up as signals from systemd itself, so they can be seen as they
happen rather than found later.

## How it works

It connects to the system bus and subscribes to two signals from
`org.freedesktop.systemd1.Manager`, accepting them only when systemd itself is
the sender (any client could otherwise forge them):

| Signal | Alert | Severity |
|---|---|---|
| `Reloading` (start of `systemctl daemon-reload`) | systemd daemon-reload | MOVEMENT |
| `UnitFilesChanged` (enable, disable, mask, edit) | systemd unit files changed | MOVEMENT |

Package maintainer scripts reload systemd and enable units on every upgrade
that ships one. With `quiet_during_dpkg` on, signals that arrive while dpkg
holds its lock (`/var/lib/dpkg/lock` or `lock-frontend`, held by `apt`,
`unattended-upgrades` and PackageKit too) are logged and dropped.
[pkg-monitor](../pkgmonitor/README.md) reports the package change instead.

## Requirements

- systemd
- D-Bus system bus

## Configuration

Set in `/etc/fogbot/skills-available/550-systemd-watch.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/550-systemd-watch.yaml`).

```yaml
config:
  quiet_during_dpkg: true
```

| Key | Default | Meaning |
|---|---|---|
| `quiet_during_dpkg` | `true` | Drop signals while dpkg is running |

Only root can take the dpkg lock, so an unprivileged user can't use it to hide
a unit. Root can, by holding the lock while installing one; turn this off if
you would rather see every reload than trust that.

## Examples

**A reload you didn't cause.** With package runs filtered out, a daemon-reload
you didn't run yourself deserves a look at
`systemctl list-unit-files --state=enabled`.

**User units aren't covered.** This listens to the system instance only.
`systemctl --user` units in `~/.config/systemd/user/` need no root to install,
so watch that directory with [dir-watch](../dirwatch/README.md).

## Enabling

```bash
sudo fogbot skill enable systemd-watch
```

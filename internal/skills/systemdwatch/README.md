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

MOVEMENT alerts are batched into digests, so a package upgrade that reloads
systemd several times arrives as one message.

## Requirements

- systemd
- D-Bus system bus

## Configuration

Set in `/etc/fogbot/skills-available/550-systemd-watch.yaml` (shipped from
`usr/share/fogbot/contrib/skills-available/550-systemd-watch.yaml`).

It has no options:

```yaml
config: {}
```

## Examples

**Correlate with package changes.** `apt` reloads systemd whenever a package
ships a unit. A daemon-reload that arrives without a
[pkg-monitor](../pkgmonitor/README.md) alert next to it, and without you
running `systemctl`, deserves a look at
`systemctl list-unit-files --state=enabled`.

**User units aren't covered.** This listens to the system instance only.
`systemctl --user` units in `~/.config/systemd/user/` need no root to install,
so watch that directory with [dir-watch](../dirwatch/README.md).

## Enabling

```bash
sudo fogbot skill enable systemd-watch
```
